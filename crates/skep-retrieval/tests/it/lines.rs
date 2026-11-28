//! The line read (`Query::line_numbers`, `Query::line_numbers_masked`): the
//! line a position lies on, the position a line starts at and the line count,
//! each held to a count over the delivery RETRIEVEV serves the same reader;
//! the rule that counts a line and the end of a document; masking; the
//! refusals and their order; and the one walk a request costs.

use skep_address::{Address, Nat};
use skep_arrangement::{AsOf, Deposit, HasM5, Run, Shot, ShotRun, VPos, VSpec, Vstream};
use skep_kernel::Kernel;
use skep_namespace::PrincipalId;
use skep_retrieval::{DeliveryItem, Flagged, LineNumbers, LinesError, Query};

use crate::common::*;

/// The line break's byte.
const LINE_BREAK: u8 = 0x0A;

/// The bytes the model's inserts draw from: half of them line breaks.
const ALPHABET: &[u8] = b"\n\na\nb\r\nc";

fn flagged<T>(number: T, masked: bool) -> Flagged<T> {
    Flagged { number, masked }
}

/// What one reader counts in the delivery it is served, position by position.
///
/// The delivery is of a document's whole content: the oracle every answer is
/// held to.
struct Counted {
    /// Whether each content position's value is a line break, in V-order.
    ///
    /// A position of a withheld run is none.
    breaks: Vec<bool>,
    /// The first position of the first withheld run, counted from one.
    hidden_from: Option<usize>,
}

impl Counted {
    /// Counts `doc`'s delivery as the rule does.
    ///
    /// A line break is each `0x0A` byte of a `Bytes` item and each `Content`
    /// item that is exactly that one byte, and nothing of an atom or of a
    /// withheld run.
    fn of(q: &Query<'_, World>, doc: &Address, readable: &dyn Fn(&Address) -> bool) -> Counted {
        let whole = spec(doc.clone(), vspan(1, 1, 1 << 20));
        let delivery = ok_of(q.retrieve_v_masked(&[whole], readable));
        let (mut breaks, mut hidden_from) = (Vec::new(), None);
        for item in &delivery {
            match item {
                DeliveryItem::Bytes(bytes) => breaks.extend(bytes.iter().map(|&b| b == LINE_BREAK)),
                DeliveryItem::Content(value) => breaks.push(value.as_bytes() == [LINE_BREAK]),
                DeliveryItem::Withheld { width, .. } => {
                    hidden_from.get_or_insert(breaks.len() + 1);
                    let width = usize::try_from(width).expect("a test width fits a usize");
                    breaks.resize(breaks.len() + width, false);
                }
                DeliveryItem::Ref(_) => panic!("a content span delivers no link"),
            }
        }
        Counted {
            breaks,
            hidden_from,
        }
    }

    /// Whether a withheld run lies at or before `position`.
    fn masked_at(&self, position: usize) -> bool {
        self.hidden_from.is_some_and(|from| from <= position)
    }

    /// Returns how many lines the reader counts.
    ///
    /// They are the line breaks, and one more for the text after the last.
    fn count(&self) -> usize {
        let breaks = self.breaks.iter().filter(|is_break| **is_break).count();
        breaks + usize::from(self.breaks.last() == Some(&false))
    }

    /// The line `position` lies on, for any position up to one past the end.
    fn line_of(&self, position: usize) -> Flagged<Nat> {
        let below = self.breaks[..position - 1]
            .iter()
            .filter(|is_break| **is_break)
            .count();
        flagged(Nat::from(below + 1), self.masked_at(position))
    }

    /// The position `line` starts at, or `None` where it names no line.
    fn start_of(&self, line: usize) -> Option<Flagged<VPos>> {
        if line == 0 || line > self.count() {
            return None;
        }
        let start = match line {
            1 => 1,
            _ => {
                let nth_break = (0..self.breaks.len())
                    .filter(|&at| self.breaks[at])
                    .nth(line - 2)
                    .expect("a line at or below the count follows a line break");
                nth_break + 2 // the break's position is `nth_break + 1`
            }
        };
        let at = VPos::content(Nat::from(start));
        Some(flagged(at, self.masked_at(start)))
    }

    /// What the line read must answer when asked `positions` and `lines`.
    fn numbers(&self, positions: &[usize], lines: &[usize]) -> LineNumbers {
        LineNumbers {
            positions: positions.iter().map(|&at| self.line_of(at)).collect(),
            lines: lines.iter().map(|&line| self.start_of(line)).collect(),
            count: flagged(Nat::from(self.count()), self.hidden_from.is_some()),
        }
    }
}

/// Holds the line read of `doc` to the oracle's count.
///
/// One request asks every position the document admits and every line up to
/// two past its count.
#[track_caller]
fn assert_numbered_as_counted(
    q: &Query<'_, World>,
    doc: &Address,
    readable: &dyn Fn(&Address) -> bool,
) -> Counted {
    let counted = Counted::of(q, doc, readable);
    let positions: Vec<usize> = (1..=counted.breaks.len() + 1).collect();
    let lines: Vec<usize> = (0..=counted.count() + 2).collect();
    assert_eq!(
        ask(q, doc, &positions, &lines, readable),
        Ok(counted.numbers(&positions, &lines)),
        "{doc} numbers its lines as its delivery counts them"
    );
    counted
}

/// The line read of `doc`, its positions and lines given as machine counts.
fn ask(
    q: &Query<'_, World>,
    doc: &Address,
    positions: &[usize],
    lines: &[usize],
    readable: &dyn Fn(&Address) -> bool,
) -> Result<LineNumbers, LinesError> {
    let positions: Vec<VPos> = positions
        .iter()
        .map(|&at| VPos::content(Nat::from(at)))
        .collect();
    let lines: Vec<Nat> = lines.iter().map(|&line| Nat::from(line)).collect();
    q.line_numbers_masked(doc, &positions, &lines, readable)
}

/// One per-byte value for each byte of `text`.
fn bytes(text: &[u8]) -> Vec<skep_content::Val> {
    text.iter().map(|&b| val(&[b])).collect()
}

/// Inserts `values` into the draft `doc` at content ordinal `at`.
fn insert_at(k: &Kernel<World>, doc: &Address, at: u32, values: Vec<skep_content::Val>) {
    Vstream::new(k)
        .insert(
            P1,
            doc,
            vp(1, at),
            values,
            Deposit::Undeclared,
            AsOf::Typed(k.current_seq()),
        )
        .expect("insert commits");
}

/// Copies `width` positions of `source` from `from` into `doc` at `at`.
fn copy_at(k: &Kernel<World>, doc: &Address, at: u32, source: &Address, from: u32, width: u32) {
    let spec = VSpec {
        source: source.clone(),
        span: vspan(1, from, width),
    };
    Vstream::new(k)
        .copy(P1, doc, vp(1, at), &[spec], AsOf::Typed(k.current_seq()))
        .expect("copy commits");
}

#[test]
fn a_line_is_numbered_by_the_line_breaks_below_it_and_text_after_the_last_is_a_line() {
    // The rule, on the smallest document that shows each clause. Line 1
    // starts at position 1; line N starts one position past line break
    // N − 1; a document ending in a line break has no empty last line; and
    // the position one past the end, where an insert would land, is on the
    // line after the last where the document ends in a line break, and on
    // the last line where it does not.
    let k = mem_kernel();
    insert_at(&k, &doc1(), 1, bytes(b"a\nb\n"));
    {
        let s = k.snapshot();
        let q = Query::new(&s);
        assert_eq!(
            ask(&q, &doc1(), &[1, 2, 3, 4, 5], &[0, 1, 2, 3, 4], &|_| true),
            Ok(LineNumbers {
                positions: [1u32, 1, 2, 2, 3]
                    .map(|line| flagged(n(line), false))
                    .to_vec(),
                lines: vec![
                    None, // line 0 names no line
                    Some(flagged(vp(1, 1), false)),
                    Some(flagged(vp(1, 3), false)),
                    None, // the document ends in a line break: no empty line 3
                    None,
                ],
                count: flagged(n(2), false),
            }),
            "`a\\nb\\n` is two lines, and its end is on a third"
        );
    }
    insert_at(&k, &doc1(), 5, bytes(b"c"));
    let s = k.snapshot();
    let q = Query::new(&s);
    assert_eq!(
        ask(&q, &doc1(), &[5, 6], &[3, 4], &|_| true),
        Ok(LineNumbers {
            positions: vec![flagged(n(3), false), flagged(n(3), false)],
            lines: vec![Some(flagged(vp(1, 5), false)), None],
            count: flagged(n(3), false),
        }),
        "`a\\nb\\nc` is three lines, its end is on the last, and line 4 names none"
    );
    assert_numbered_as_counted(&q, &doc1(), &|_| true);
}

#[test]
fn only_the_single_byte_0x0a_at_its_own_position_is_a_line_break() {
    // The rule's other half: an atom is one position whose value is no
    // single byte, so it holds no line break whatever its bytes; and neither
    // `\r` nor U+2028 is one. The document is `a`, the atom `x\ny`, a line
    // break, the atom `\n\n`, `\r`, U+2028's three bytes, `b`: nine
    // positions and one line break, at the third.
    let k = mem_kernel();
    let mut values = vec![val(b"a"), val(b"x\ny"), val(b"\n"), val(b"\n\n")];
    values.extend(bytes("\r\u{2028}b".as_bytes()));
    insert_at(&k, &doc1(), 1, values);
    let s = k.snapshot();
    let q = Query::new(&s);
    let counted = assert_numbered_as_counted(&q, &doc1(), &|_| true);
    assert_eq!(counted.breaks.len(), 9, "the premise: nine positions");
    assert_eq!(
        ask(&q, &doc1(), &[2, 3, 4, 9], &[2, 3], &|_| true),
        Ok(LineNumbers {
            positions: [1u32, 1, 2, 2].map(|line| flagged(n(line), false)).to_vec(),
            lines: vec![Some(flagged(vp(1, 4), false)), None],
            count: flagged(n(2), false),
        }),
        "the one line break is the one-byte value at position 3"
    );
}

#[test]
fn an_empty_document_has_no_line_and_its_one_position_is_on_line_one() {
    // A registered document holding no content: no line, so every listed
    // line answers none; and position 1, where an insert would land, is on
    // line 1, the line it would begin. Nothing is withheld, so no flag.
    let k = mem_kernel();
    let s = k.snapshot();
    let q = Query::new(&s);
    assert_eq!(
        ask(&q, &doc2(), &[1], &[0, 1, 2], &|_| true),
        Ok(LineNumbers {
            positions: vec![flagged(n(1), false)],
            lines: vec![None, None, None],
            count: flagged(n(0), false),
        })
    );
    assert_eq!(
        ask(&q, &doc2(), &[1, 2], &[], &|_| true),
        Err(LinesError::RangeNotPresent { index: 1 }),
        "an empty document admits position 1 alone"
    );
}

#[test]
fn the_answers_come_back_in_request_order_a_repeat_answered_each_time() {
    // `LineNumbers`: both lists are answered entry for entry in the order
    // asked. The read sorts each list to meet it in one walk, so a request
    // out of order, with repeats, is the one that tells the answers' order
    // from the walk's.
    let k = mem_kernel();
    insert_at(&k, &doc1(), 1, bytes(b"a\nb\nc\nd"));
    let s = k.snapshot();
    let q = Query::new(&s);
    let counted = Counted::of(&q, &doc1(), &|_| true);
    let (positions, lines) = ([8, 3, 3, 1, 7, 2, 8], [4, 9, 2, 0, 2, 1, 4, 3]);
    let got = ok_of(ask(&q, &doc1(), &positions, &lines, &|_| true));
    assert_eq!(got, counted.numbers(&positions, &lines));
    assert_eq!(
        got.positions
            .iter()
            .map(|at| at.number.clone())
            .collect::<Vec<_>>(),
        [4u32, 2, 2, 1, 4, 1, 4].map(n),
        "the lines, in the order their positions were asked"
    );
    assert_eq!(
        got.lines
            .iter()
            .map(|line| line.as_ref().map(|start| start.number.clone()))
            .collect::<Vec<_>>(),
        [
            Some(7u32),
            None,
            Some(3),
            None,
            Some(3),
            Some(1),
            Some(7),
            Some(5)
        ]
        .map(|start| start.map(|at| vp(1, at))),
        "the starts, in the order their lines were asked"
    );
}

/// The next value of SplitMix64: the seed is the whole reproduction.
fn next(rng: &mut u64) -> u64 {
    *rng = rng.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *rng;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// A value below `bound`, which is at least one.
fn below(rng: &mut u64, bound: u32) -> u32 {
    u32::try_from(next(rng) % u64::from(bound)).expect("below a u32 bound")
}

#[test]
fn every_number_matches_a_count_over_the_delivered_text_under_random_edits() {
    // The model: random inserts of bytes and atoms, deletes, rearrangements
    // and transclusions — a document onto itself among them — over two
    // drafts, and after every edit each document's every position, every
    // line and its count held to a count over its delivered text. The line
    // read asks M4 two counts a run and never a value, so this is the check
    // that those counts, summed over an arrangement's runs, are the text's.
    for seed in 0..6u64 {
        let k = mem_kernel();
        let vs = Vstream::new(&k);
        let docs = [doc1(), doc2()];
        let mut rng = seed;
        for step in 0..120 {
            let doc = &docs[below(&mut rng, 2) as usize];
            let width = |d: &Address| {
                let count = k.snapshot().world().m5().content_count(d);
                u32::try_from(count).expect("a test document is small")
            };
            let held = width(doc);
            let typed = AsOf::Typed(k.current_seq());
            match below(&mut rng, 10) {
                // An insert of one to six values: bytes of an alphabet heavy
                // in line breaks, and an atom now and then, some holding the
                // line break's byte.
                0..=4 => {
                    let values = (0..=below(&mut rng, 6))
                        .map(|_| match below(&mut rng, 12) {
                            0 => val(b"x\ny"),
                            1 => val(b"\n\n"),
                            2 => val(b"atom"),
                            pick => val(&[ALPHABET[pick as usize % ALPHABET.len()]]),
                        })
                        .collect();
                    let at = vp(1, 1 + below(&mut rng, held + 1));
                    vs.insert(P1, doc, at, values, Deposit::Undeclared, typed)
                        .expect("insert commits");
                }
                5 | 6 if held > 0 => {
                    let from = 1 + below(&mut rng, held);
                    let count = 1 + below(&mut rng, (held - from + 1).min(4));
                    vs.delete(P1, doc, vp(1, from), n(count), typed)
                        .expect("delete commits");
                }
                // A pivot or a swap: three or four ascending boundaries.
                7 if held >= 3 => {
                    let mut cuts: Vec<u32> = (1..=held + 1).collect();
                    while cuts.len() > 3 + below(&mut rng, 2) as usize {
                        cuts.remove(below(&mut rng, cuts.len() as u32) as usize);
                    }
                    let cuts: Vec<VPos> = cuts.into_iter().map(|at| vp(1, at)).collect();
                    vs.rearrange(P1, doc, &cuts, typed)
                        .expect("rearrange commits");
                }
                // A transclusion of either draft's content, its own included.
                _ => {
                    let source = &docs[below(&mut rng, 2) as usize];
                    let source_held = width(source);
                    if source_held == 0 {
                        continue;
                    }
                    let from = 1 + below(&mut rng, source_held);
                    let count = 1 + below(&mut rng, (source_held - from + 1).min(5));
                    let spec = VSpec {
                        source: source.clone(),
                        span: vspan(1, from, count),
                    };
                    let at = vp(1, 1 + below(&mut rng, held + 1));
                    vs.copy(P1, doc, at, &[spec], typed).expect("copy commits");
                }
            }
            let s = k.snapshot();
            let q = Query::new(&s);
            for doc in &docs {
                let counted = Counted::of(&q, doc, &|_| true);
                let positions: Vec<usize> = (1..=counted.breaks.len() + 1).collect();
                let lines: Vec<usize> = (0..=counted.count() + 2).collect();
                assert_eq!(
                    ask(&q, doc, &positions, &lines, &|_| true),
                    Ok(counted.numbers(&positions, &lines)),
                    "seed {seed}, step {step}: {doc} numbers its lines as its delivery counts them"
                );
            }
        }
    }
}

/// Builds doc2 as a window onto doc1 between two runs of its own.
///
/// doc1 = `p\nq\n`; doc2 = `a\n`, then doc1's four positions transcluded,
/// then `b\nc`: three runs of origins doc2, doc1, doc2, nine positions. A
/// reader of everything counts four line breaks; one who may not read doc1
/// is served `a\n`, a withheld run of four, `b\nc`, and counts two.
fn a_window_onto_doc1(k: &Kernel<World>) {
    insert_at(k, &doc1(), 1, bytes(b"p\nq\n"));
    insert_at(k, &doc2(), 1, bytes(b"a\n"));
    copy_at(k, &doc2(), 3, &doc1(), 1, 4);
    insert_at(k, &doc2(), 7, bytes(b"b\nc"));
}

#[test]
fn a_withheld_run_counts_no_line_break_and_flags_every_number_at_or_past_it() {
    // PUB-6.41, as RETRIEVEV applies it: a run whose origin the reader may
    // not read is withheld, and here it counts zero line breaks, so the
    // numbers are the ones the reader counts in its own delivery. Each
    // number carries the flag where a withheld run lies at or before what
    // it numbers; the count carries it where one lies anywhere.
    let k = mem_kernel();
    a_window_onto_doc1(&k);
    let s = k.snapshot();
    let q = Query::new(&s);
    let not_doc1 = |d: &Address| *d != doc1();
    let positions: Vec<usize> = (1..=10).collect();
    assert_eq!(
        ask(&q, &doc2(), &positions, &[1, 2, 3, 4], &not_doc1),
        Ok(LineNumbers {
            positions: vec![
                flagged(n(1), false), // `a`
                flagged(n(1), false), // the line break before the withheld run
                // The withheld run's first position: flagged, since the run
                // lies at it, and on the line the run starts on.
                flagged(n(2), true),
                flagged(n(2), true),
                flagged(n(2), true),
                flagged(n(2), true),
                flagged(n(2), true), // `b`: the run's two line breaks count nothing
                flagged(n(2), true),
                flagged(n(3), true), // `c`
                flagged(n(3), true), // one past the end
            ],
            lines: vec![
                Some(flagged(vp(1, 1), false)),
                // Line 2 opens on the withheld run's first position.
                Some(flagged(vp(1, 3), true)),
                Some(flagged(vp(1, 9), true)),
                None,
            ],
            count: flagged(n(3), true),
        })
    );
    assert_numbered_as_counted(&q, &doc2(), &not_doc1);
    // A reader who may read the run counts its line breaks, and no number
    // is flagged.
    let whole = assert_numbered_as_counted(&q, &doc2(), &|_| true);
    assert_eq!((whole.count(), whole.hidden_from), (5, None));
    // The consult is on each run's origin, never on the document named:
    // masking doc2 withholds its own two runs and counts doc1's.
    let own_hidden = assert_numbered_as_counted(&q, &doc2(), &|d| *d != doc2());
    assert_eq!((own_hidden.count(), own_hidden.hidden_from), (3, Some(1)));
    assert_eq!(
        ask(&q, &doc2(), &[1], &[1], &|d| *d != doc2()),
        Ok(LineNumbers {
            positions: vec![flagged(n(1), true)],
            lines: vec![Some(flagged(vp(1, 1), true))],
            count: flagged(n(3), true),
        }),
        "a withheld first run flags line 1 and position 1"
    );
}

#[test]
fn a_run_of_an_unregistered_origin_is_withheld_with_the_predicate_unasked() {
    // PUB-6.37, RES-162: the predicate is contracted to registered documents,
    // so a run whose origin no registration names is withheld before it is
    // asked — and counts no line break, under every reader. pdoc's head is
    // `a\n`, two line breaks under a member never registered, then `c`.
    let k = mem_kernel();
    let vs = Vstream::new(&k);
    vs.insert(
        P1,
        &pdoc(),
        vp(1, 1),
        bytes(b"a\nc"),
        declared(),
        AsOf::Typed(k.current_seq()),
    )
    .expect("deposit commits");
    skep_content::write_stretch(&k, &unheld_ca(1), std::sync::Arc::from(&b"\n\n"[..]))
        .expect("M4's test-only stretch write commits");
    let shot_run = |start: Address, width: u32| ShotRun {
        origin: pdoc(),
        run: Run::new(start, n(width)).expect("a content run"),
    };
    let shot = Shot {
        base: None,
        draft: None,
        also: vec![],
        keep_base: false,
        runs: vec![
            shot_run(pca(1), 2),
            shot_run(unheld_ca(1), 2),
            shot_run(pca(3), 1),
        ],
        stretches: Vec::new(),
    };
    vs.publish(P1, &pdoc(), &shot, &|_: &World, _: &Address| true)
        .expect("the birth shot commits");
    let s = k.snapshot();
    let q = Query::new(&s);
    let registered_alone = |d: &Address| {
        assert_ne!(
            *d,
            unheld_member(),
            "the predicate is asked of an unregistered origin"
        );
        true
    };
    let counted = assert_numbered_as_counted(&q, &pdoc(), &registered_alone);
    assert_eq!((counted.count(), counted.hidden_from), (2, Some(3)));
    assert_eq!(
        q.line_numbers(&pdoc(), &[vp(1, 5)], &[n(2)]),
        Ok(LineNumbers {
            positions: vec![flagged(n(2), true)],
            lines: vec![Some(flagged(vp(1, 3), true))],
            count: flagged(n(2), true),
        }),
        "the door that reads for no principal withholds the same run"
    );
}

#[test]
fn a_position_is_refused_never_clipped_and_the_first_fault_in_request_order_speaks() {
    // `LinesError`: registration first; then each position in request order,
    // its subspace judged ahead of its range; and a listed line faults
    // nothing. A position is answered from 1 to one past the end, and
    // refused outside that — as SHOWORIGIN_V refuses a span it cannot wholly
    // resolve, where RETRIEVEV would clip.
    let k = mem_kernel();
    insert_at(&k, &doc1(), 1, bytes(b"a\nb"));
    let s = k.snapshot();
    let q = Query::new(&s);
    let ask_at = |doc: &Address, positions: &[VPos]| {
        q.line_numbers_masked(doc, positions, &[], &|_| {
            panic!("a refused request asks no reader")
        })
    };
    assert_eq!(
        ask_at(&unregistered(), &[]),
        Err(LinesError::DocNotRegistered)
    );
    assert_eq!(
        ask_at(&unregistered(), &[vp(2, 1), vp(1, 0)]),
        Err(LinesError::DocNotRegistered),
        "registration is judged ahead of every position"
    );
    // The link subspace has no lines, and a foreign numeral selects nothing.
    assert_eq!(
        ask_at(&doc1(), &[vp(1, 1), vp(2, 1)]),
        Err(LinesError::NotContentSubspace { index: 1 })
    );
    assert_eq!(
        ask_at(&doc1(), &[vp(3, 1)]),
        Err(LinesError::NotContentSubspace { index: 0 })
    );
    // Ordinal zero is no position; one past the end is the last admitted.
    assert_eq!(
        ask_at(&doc1(), &[vp(1, 0)]),
        Err(LinesError::RangeNotPresent { index: 0 })
    );
    assert_eq!(
        ask_at(&doc1(), &[vp(1, 4), vp(1, 5)]),
        Err(LinesError::RangeNotPresent { index: 1 }),
        "the document holds three positions: 4 is admitted and 5 is not"
    );
    // Within one position the subspace speaks ahead of the range; across
    // positions the first faulty one does, whatever its fault.
    assert_eq!(
        ask_at(&doc1(), &[vp(2, 0), vp(1, 9)]),
        Err(LinesError::NotContentSubspace { index: 0 })
    );
    assert_eq!(
        ask_at(&doc1(), &[vp(1, 1), vp(1, 9), vp(2, 1)]),
        Err(LinesError::RangeNotPresent { index: 1 })
    );
    // A line that names none is an answer, however far past the count.
    let far = Nat::from(u64::MAX) * Nat::from(u64::MAX);
    assert_eq!(
        q.line_numbers(&doc1(), &[], &[n(0), n(3), far]),
        Ok(LineNumbers {
            positions: vec![],
            lines: vec![None, None, None],
            count: flagged(n(2), false),
        })
    );
}

#[test]
fn a_published_address_numbers_its_trunk_heads_lines() {
    // Crate doc, *Which arrangement an operation answers from*: the line
    // read floats. pdoc's own arrangement is `a\nb`, two lines; its head
    // takes a deposit of `\nc` and holds three, and a position is a position
    // of the head, so pdoc's sixth is admitted where its own arrangement
    // ends at the third.
    let k = mem_kernel();
    let vs = Vstream::new(&k);
    vs.insert(
        P1,
        &pdoc(),
        vp(1, 1),
        bytes(b"a\nb"),
        declared(),
        AsOf::Typed(k.current_seq()),
    )
    .expect("deposit commits");
    let (head, _) = vs
        .version(PrincipalId(1), &pdoc(), None)
        .expect("the version commits");
    assert_eq!(head, vdoc(), "the trunk's first member, and so its head");
    vs.insert(
        P1,
        &head,
        vp(1, 4),
        bytes(b"\nc"),
        declared(),
        AsOf::Typed(k.current_seq()),
    )
    .expect("the head's deposit commits");
    let s = k.snapshot();
    let q = Query::new(&s);
    let of_the_head = LineNumbers {
        positions: vec![flagged(n(3), false)],
        lines: vec![Some(flagged(vp(1, 5), false))],
        count: flagged(n(3), false),
    };
    assert_eq!(
        q.line_numbers(&pdoc(), &[vp(1, 6)], &[n(3)]),
        Ok(of_the_head.clone())
    );
    assert_eq!(
        q.line_numbers(&vdoc(), &[vp(1, 6)], &[n(3)]),
        Ok(of_the_head)
    );
}

#[test]
fn a_request_at_both_list_caps_over_4096_runs_is_one_walk_and_is_answered() {
    // Crate doc, *What M6 refuses for size*: the line read walks its
    // document's runs once, whatever its lists hold, so its price is the
    // surface's run count. doc2 is 4096 one-position runs — `c`, a line
    // break, `a`, over and over, by reference to doc1 — and the request
    // lists 4096 positions and 4096 lines, the transport's cap on each. A
    // walk apiece would pull 8193 × 4096 runs, past the walk budget
    // of 2^24; one walk prices it at 4096, and every number matches the
    // delivery's count.
    let k = mem_kernel();
    insert_at(&k, &doc1(), 1, bytes(b"a\nc"));
    let specs: Vec<VSpec> = (0..4096u32)
        .map(|i| VSpec {
            source: doc1(),
            span: vspan(1, 3 - i % 3, 1),
        })
        .collect();
    Vstream::new(&k)
        .copy(P1, &doc2(), vp(1, 1), &specs, AsOf::Typed(k.current_seq()))
        .expect("copy commits");
    let s = k.snapshot();
    let q = Query::new(&s);
    assert_eq!(
        s.world().m5().content_run_count(&doc2()),
        4096,
        "the premise: no two of doc2's runs coalesce"
    );
    let counted = Counted::of(&q, &doc2(), &|_| true);
    let positions: Vec<usize> = (1..=4096).collect();
    let lines: Vec<usize> = (1..=4096).collect();
    assert_eq!(
        counted.count(),
        1366,
        "the premise: a line break at every third position"
    );
    assert_eq!(
        ask(&q, &doc2(), &positions, &lines, &|_| true),
        Ok(counted.numbers(&positions, &lines))
    );
}
