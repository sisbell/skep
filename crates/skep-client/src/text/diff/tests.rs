//! The unit suite of the diff by identity.
//!
//! A text is modelled as its bytes with the I-address each stands at
//! ([`Doc`]): typed text mints addresses, and a line picked out of a text
//! keeps its own, so a move, a copy and a re-typing are each what a board
//! would hold. The images are spelled as the board answers them and decoded
//! by the lent reader, and the plans are read as the rows a caller draws of
//! them ([`rows`]).

use std::ops::Range;

use serde_json::{json, Value};

use super::*;
use crate::board::whole_image;

/// The chains the modelled texts mint in: two drafts' content subspaces.
const CHAINS: [&str; 2] = ["1.0.1.0.64.0.1", "1.0.1.0.65.0.1"];

/// A text, each byte with the chain and the ordinal of its I-address.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct Doc(Vec<(usize, u64, u8)>);

impl Doc {
    /// Returns `text` typed afresh: minted in `chain` from the ordinal `first`.
    fn typed(chain: usize, first: u64, text: &str) -> Doc {
        Doc(text.bytes().enumerate().map(|(k, byte)| (chain, first + k as u64, byte)).collect())
    }

    /// Returns the text's bytes.
    fn text(&self) -> String {
        String::from_utf8(self.0.iter().map(|cell| cell.2).collect()).expect("text")
    }

    /// Returns the byte range of each line, its line break among them.
    fn line_ranges(&self) -> Vec<Range<usize>> {
        let (mut ranges, mut start) = (Vec::new(), 0);
        for (at, cell) in self.0.iter().enumerate() {
            if cell.2 == b'\n' {
                ranges.push(start..at + 1);
                start = at + 1;
            }
        }
        if start < self.0.len() {
            ranges.push(start..self.0.len());
        }
        ranges
    }

    /// Returns the lines numbered `lines`, from 1, one after another.
    ///
    /// Each byte keeps its address.
    fn pick(&self, lines: &[usize]) -> Doc {
        let ranges = self.line_ranges();
        Doc(lines.iter().flat_map(|line| self.0[ranges[line - 1].clone()].iter().copied()).collect())
    }

    /// Returns the text followed by `next`.
    fn then(mut self, next: &Doc) -> Doc {
        self.0.extend(next.0.iter().copied());
        self
    }

    /// Returns the image's runs as the board spells them.
    ///
    /// A run is ended at every `every` positions at most.
    fn runs(&self, every: usize) -> Value {
        let mut runs: Vec<(usize, u64, u64)> = Vec::new();
        for (chain, ordinal, _) in &self.0 {
            match runs.last_mut() {
                Some((in_chain, first, width)) if in_chain == chain && *first + *width == *ordinal && (*width as usize) < every => *width += 1,
                _ => runs.push((*chain, *ordinal, 1)),
            }
        }
        let runs: Vec<Value> = runs.into_iter().map(|(chain, first, width)| json!({"i_start": format!("{}.{first}", CHAINS[chain]), "width": width.to_string()})).collect();
        json!({"resp": "runs", "as_of": 9, "runs": runs})
    }

    /// Returns the text's image, its runs as long as they go on.
    fn image(&self) -> Image {
        whole_image(&self.runs(usize::MAX)).expect("an image")
    }

    /// Returns the text's line table.
    ///
    /// Each key is its line's bytes less the line break.
    fn lines(&self) -> Vec<Line<Vec<u8>>> {
        self.line_ranges()
            .into_iter()
            .map(|range| {
                let bytes: Vec<u8> = self.0[range.clone()].iter().map(|cell| cell.2).collect();
                let closed = bytes.last() == Some(&b'\n');
                let key = bytes[..bytes.len() - usize::from(closed)].to_vec();
                let solid = String::from_utf8_lossy(&key).chars().filter(|c| !c.is_whitespace()).count() as u64;
                Line { start: range.start as u64 + 1, len: range.len() as u64, key, closed, solid }
            })
            .collect()
    }
}

/// Returns the identity plan from `before` to `now`.
fn identity(before: &Doc, now: &Doc) -> Identity {
    Identity::of(&before.image(), &now.image()).expect("a plan within the bound")
}

/// Returns the line plan from `before` to `now`, two lines of context.
fn plan(before: &Doc, now: &Doc) -> Lines {
    identity(before, now).lines(&before.lines(), &now.lines(), 2)
}

/// Returns `plan` as the rows a caller draws of it.
///
/// Each hunk stands under its header; a line unchanged, new or moved here
/// carries its number in `now` and its text, a gone one its number in
/// `before`, and a run of lines that moved away is one row.
fn rows(plan: &Lines, before: &Doc, now: &Doc) -> Vec<String> {
    let text = |doc: &Doc, number: u64| {
        let range = doc.line_ranges()[number as usize - 1].clone();
        String::from_utf8(doc.0[range].iter().map(|cell| cell.2).filter(|byte| *byte != b'\n').collect()).expect("text")
    };
    let mut rows = Vec::new();
    for hunk in &plan.hunks {
        rows.push(format!("@@ -{},{} +{},{} @@", hunk.before.0, hunk.before.1, hunk.now.0, hunk.now.1));
        let ops = &plan.ops[hunk.ops.clone()];
        let mut k = 0;
        while k < ops.len() {
            match ops[k] {
                Op::Same { now: number, .. } => rows.push(format!(" {number}\t{}", text(now, number))),
                Op::New { now: number } => rows.push(format!("+{number}\t{}", text(now, number))),
                Op::MovedIn { now: number, .. } => rows.push(format!(">{number}\t{}", text(now, number))),
                Op::Gone { before: number } => rows.push(format!("-{number}\t{}", text(before, number))),
                Op::MovedOut { before: first, now: to } => {
                    let mut count = 1;
                    while ops.get(k + count as usize) == Some(&Op::MovedOut { before: first + count, now: to + count }) {
                        count += 1;
                    }
                    rows.push(format!("<{first}-{} to {to}-{}", first + count - 1, to + count - 1));
                    k += count as usize - 1;
                }
            }
            k += 1;
        }
    }
    rows
}

/// Returns the rows of the plan from `before` to `now`.
fn diffed(before: &Doc, now: &Doc) -> Vec<String> {
    rows(&plan(before, now), before, now)
}

/// Eight lines, each with a word a note counts: no two equal as text.
const EIGHT: &str = "alpha one\nbravo two\ncharlie three\ndelta four\necho five\nfoxtrot six\ngolf seven\nhotel eight\n";

// ── identity ─────────────────────────────────────────────────────────────

/// Pairs come of runs that overlap in one chain, wherever each is cut.
///
/// A run of one image that overlaps two runs of the other is cut at their
/// edges, and each overlap is a pair at its own offsets; runs of two chains
/// that share ordinals share nothing; and a run one image places twice
/// pairs once in place, its second place standing again (the mutant that
/// pairs by ordinals alone pairs the two chains).
#[test]
fn pairs_come_of_runs_that_overlap_in_one_chain() {
    let before = whole_image(&json!({"resp": "runs", "runs": [{"i_start": format!("{}.1", CHAINS[0]), "width": "10"}, {"i_start": format!("{}.1", CHAINS[1]), "width": "4"}]})).expect("an image");
    let now = whole_image(&json!({"resp": "runs", "runs": [
        {"i_start": format!("{}.3", CHAINS[0]), "width": "4"},
        {"i_start": format!("{}.50", CHAINS[0]), "width": "2"},
        {"i_start": format!("{}.7", CHAINS[0]), "width": "4"},
        {"i_start": format!("{}.3", CHAINS[0]), "width": "2"},
    ]}))
    .expect("an image");
    let plan = Identity::of(&before, &now).expect("a plan");
    assert_eq!(plan.stays(), [Pair { before: 3, now: 1, width: 4 }, Pair { before: 7, now: 7, width: 4 }], "each overlap at its own offsets, the staying pairs ascending in both");
    assert_eq!(plan.moved(), [], "nothing left to move");
    assert_eq!(plan.again(), [Pair { before: 3, now: 11, width: 2 }], "the positions 3 and 4 stand a second time");
    assert_eq!(
        plan.gone(),
        [Gone { before: 1, prefix: CHAINS[0].into(), first: 1, width: 2 }, Gone { before: 11, prefix: CHAINS[1].into(), first: 1, width: 4 }],
        "the other chain's ordinals pair nothing"
    );
    assert_eq!(plan.gone()[1].start(), format!("{}.1", CHAINS[1]));
    assert_eq!((plan.bytes(), plan.shared()), (Bytes { new: 2, gone: 6, moved: 2 }, 10));
    assert_eq!((plan.before_extent(), plan.now_extent(), plan.unchanged()), (14, 12, false));
    let told = |before, width, source| Stretch { before, width, source };
    assert_eq!(plan.sources(), [told(1, 2, Source::Gone(0)), told(3, 4, Source::Now(1)), told(7, 4, Source::Now(7)), told(11, 4, Source::Gone(1))]);
}

/// Returns a text's addresses: each position's chain and ordinal.
fn addresses(doc: &Doc) -> Vec<(usize, u64)> {
    doc.0.iter().map(|cell| (cell.0, cell.1)).collect()
}

/// Returns the length of the longest sequence two sequences share in order.
fn longest_common(a: &[(usize, u64)], b: &[(usize, u64)]) -> u64 {
    let mut row = vec![0u64; b.len() + 1];
    for x in a {
        let mut diagonal = 0;
        for (j, y) in b.iter().enumerate() {
            let above = row[j + 1];
            row[j + 1] = if x == y { diagonal + 1 } else { above.max(row[j]) };
            diagonal = above;
        }
    }
    row[b.len()]
}

/// A seeded generator of small naturals.
struct Seeded(u64);

impl Seeded {
    /// Returns the next natural below `below`.
    fn below(&mut self, below: usize) -> usize {
        self.0 = self.0.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
        ((self.0 >> 33) as usize) % below.max(1)
    }

    /// Returns a text made of `doc` by `changes` changes a board allows.
    ///
    /// Each is a stretch removed, moved or placed a second time by identity,
    /// or new bytes typed.
    fn changed(&mut self, doc: &Doc, changes: usize, mint: &mut u64) -> Doc {
        let mut cells = doc.0.clone();
        for _ in 0..changes {
            let (from, len) = (self.below(cells.len() + 1), self.below(5) + 1);
            let stretch: Vec<_> = cells.iter().skip(from).take(len).copied().collect();
            match self.below(4) {
                0 => drop(cells.drain(from..from + stretch.len())),
                1 => {
                    cells.drain(from..from + stretch.len());
                    let to = self.below(cells.len() + 1);
                    cells.splice(to..to, stretch);
                }
                2 => {
                    let to = self.below(cells.len() + 1);
                    cells.splice(to..to, stretch);
                }
                _ => {
                    let typed: Vec<_> = (0..len).map(|k| (1, *mint + k as u64, if self.below(4) == 0 { b'\n' } else { b'a' + self.below(3) as u8 })).collect();
                    *mint += len as u64;
                    cells.splice(from..from, typed);
                }
            }
        }
        Doc(cells)
    }
}

/// The staying set is the heaviest that keeps its order.
///
/// The plan's laws hold beside it.
/// Over seeded texts changed as a board allows — stretches removed, moved,
/// placed a second time and typed — the staying pairs weigh what the longest
/// sequence of addresses the two texts share in order weighs, found by a
/// plain table, ranges standing twice among them; they ascend in both texts
/// and overlap nowhere; every pair holds the same addresses at both its
/// places; the positions of each text are those the plan counts; the source
/// map tells every byte of the text before; and the plan is the same however
/// the board cuts the runs (the mutants that keep a set out of order, count
/// a piece left over as moved, or join pairs by their place in a sort break
/// a law).
#[test]
fn the_staying_set_is_the_heaviest_that_keeps_its_order_and_the_laws_hold() {
    let mut seeded = Seeded(0x9E37_79B9_7F4A_7C15);
    for case in 0..1500 {
        let mut mint = 1_000;
        let base = Doc::typed(0, 1, &"abc\nab\ncab\n".repeat(1 + seeded.below(2)));
        let (changes_before, changes_now) = (seeded.below(3), 1 + seeded.below(4));
        let before = seeded.changed(&base, changes_before, &mut mint);
        let now = seeded.changed(&before, changes_now, &mut mint);
        let plan = identity(&before, &now);
        let (was, is) = (addresses(&before), addresses(&now));
        let width = |pairs: &[Pair]| pairs.iter().map(|pair| pair.width).sum::<u64>();
        assert_eq!(width(plan.stays()), longest_common(&was, &is), "case {case}: the heaviest set that keeps its order");
        for pairs in plan.stays().windows(2) {
            assert!(pairs[0].before + pairs[0].width <= pairs[1].before && pairs[0].now + pairs[0].width <= pairs[1].now, "case {case}: ascending in both, none overlapping");
        }
        let (mut in_before, mut in_now) = (vec![0u8; was.len()], vec![0u8; is.len()]);
        for (pairs, counts_before) in [(plan.stays(), true), (plan.moved(), true), (plan.again(), false)] {
            for pair in pairs {
                for k in 0..pair.width as usize {
                    let (b, n) = (pair.before as usize - 1 + k, pair.now as usize - 1 + k);
                    assert_eq!(was[b], is[n], "case {case}: a pair holds one address at both its places");
                    in_now[n] += 1;
                    in_before[b] += u8::from(counts_before);
                }
            }
        }
        assert!(in_before.iter().chain(&in_now).all(|count| *count <= 1), "case {case}: no position in two pairs");
        let bytes = plan.bytes();
        assert_eq!(width(plan.stays()) + width(plan.moved()) + width(plan.again()) + bytes.new, is.len() as u64, "case {case}: the positions of now");
        assert_eq!(width(plan.stays()) + width(plan.moved()) + bytes.gone, was.len() as u64, "case {case}: the positions of before");
        assert_eq!((bytes.moved, plan.shared()), (width(plan.moved()) + width(plan.again()), is.len() as u64 - bytes.new), "case {case}");
        assert_eq!(in_now.iter().filter(|count| **count == 0).count() as u64, bytes.new, "case {case}");
        for (n, address) in is.iter().enumerate() {
            assert_eq!(in_now[n] == 0, !was.contains(address), "case {case}: a position is new where before holds its address nowhere");
        }
        // The source map tells every byte of before, in order.
        let mut told = Vec::new();
        for stretch in plan.sources() {
            assert_eq!(stretch.before as usize, told.len() + 1, "case {case}: the stretches tile before");
            match stretch.source {
                Source::Now(at) => told.extend_from_slice(&is[at as usize - 1..(at + stretch.width) as usize - 1]),
                Source::Gone(span) => {
                    let gone = &plan.gone()[span];
                    assert_eq!((gone.before, gone.width), (stretch.before, stretch.width), "case {case}: a gone span is one stretch");
                    let chain = CHAINS.iter().position(|chain| *chain == gone.prefix).expect("a chain");
                    assert!((0..gone.width).all(|k| !is.contains(&(chain, gone.first + k))), "case {case}: a span read by identity stands nowhere now");
                    told.extend((0..gone.width).map(|k| (chain, gone.first + k)));
                }
            }
        }
        assert_eq!(told, was, "case {case}: the source map tells before");
        assert_eq!(plan.unchanged(), was == is, "case {case}");
        // The board's cut of the runs changes nothing.
        let cut = Identity::of(&whole_image(&before.runs(1 + seeded.below(3))).expect("an image"), &whole_image(&now.runs(1 + seeded.below(3))).expect("an image")).expect("a plan");
        assert_eq!(cut, plan, "case {case}: the same plan however the runs are cut");
    }
}

/// A passage that stands twice is counted where it stands, never as moved.
///
/// Standing twice in both texts with nothing changed, every position stays
/// and the diff is unchanged; one of the two copies deleted is gone by its
/// width, its text told from the copy that stands, and nothing moved; a
/// passage placed a second time stands again, a moved byte by the counts and
/// a line placed twice by the notes; and a run half placed elsewhere stands
/// again by that half (the mutant that counts every pair past the staying
/// ones as moved answers moved bytes for a deletion and never unchanged).
#[test]
fn a_passage_that_stands_twice_is_counted_where_it_stands() {
    let once = Doc::typed(0, 1, EIGHT);
    let twice = once.pick(&[1, 2, 3, 2, 3, 4]);
    let same = identity(&twice, &twice);
    assert!(same.unchanged(), "nothing changed");
    assert_eq!((same.bytes(), same.moved(), same.again(), same.gone()), (Bytes::default(), &[][..], &[][..], &[][..]));
    assert!(diffed(&twice, &twice).is_empty());
    assert!(plan(&twice, &twice).notes.is_empty());

    // The second copy of lines 2 and 3 deleted.
    let one = twice.pick(&[1, 2, 3, 6]);
    let dropped = identity(&twice, &one);
    let copy = ("bravo two\ncharlie three\n".len()) as u64;
    assert_eq!(dropped.bytes(), Bytes { new: 0, gone: copy, moved: 0 }, "gone by its width, nothing moved");
    assert!(dropped.gone().is_empty(), "its values stand in the copy that stays, and no read by identity is owed");
    let first = ("alpha one\n".len()) as u64 + 1;
    let rest = copy + ("delta four\n".len()) as u64;
    assert_eq!(dropped.sources()[1], Stretch { before: first + copy, width: rest, source: Source::Now(first) }, "told from where the range stands, with the line that follows it there");
    assert_eq!(diffed(&twice, &one), ["@@ -2,5 +2,3 @@", " 2\tbravo two", " 3\tcharlie three", "-4\tbravo two", "-5\tcharlie three", " 4\tdelta four"]);
    let lines = plan(&twice, &one);
    assert_eq!((lines.counts, lines.notes), (LineCounts { added: 0, removed: 2, moved: 0 }, vec![]));

    // Lines 2 and 3 placed a second time, after line 5.
    let copied = once.pick(&[1, 2, 3, 4, 5, 2, 3, 6, 7, 8]);
    let placed = identity(&once, &copied);
    assert_eq!(placed.bytes(), Bytes { new: 0, gone: 0, moved: copy });
    assert_eq!(placed.again(), [Pair { before: first, now: ("alpha one\nbravo two\ncharlie three\ndelta four\necho five\n".len()) as u64 + 1, width: copy }]);
    assert!(placed.moved().is_empty(), "a second place is no move");
    assert_eq!(diffed(&once, &copied), ["@@ -4,4 +4,6 @@", " 4\tdelta four", " 5\techo five", ">6\tbravo two", ">7\tcharlie three", " 8\tfoxtrot six", " 9\tgolf seven"]);
    let lines = plan(&once, &copied);
    assert_eq!((lines.counts, lines.notes), (LineCounts { added: 0, removed: 0, moved: 2 }, vec![Note::PlacedTwice { before: (2, 3), now: (6, 7) }]));

    // The second half of a run placed elsewhere too: `charlie three` alone.
    let half = once.pick(&[1, 2, 3, 4, 3]);
    let halved = identity(&once.pick(&[1, 2, 3, 4]), &half);
    let line = ("charlie three\n".len()) as u64;
    assert_eq!((halved.bytes(), halved.again().len()), (Bytes { new: 0, gone: 0, moved: line }, 1), "the half stands again, the run cut where it begins");
}

/// A plan past the bound is refused before any of it is built.
///
/// One range placed three hundred times in each text makes ninety thousand
/// pairs, past the bound, and is refused naming the count; placed two
/// hundred and fifty times it is planned, every place staying; and an image
/// cut into more pieces than the bound is refused by its pieces (the mutant
/// that builds first holds every pair before it refuses).
#[test]
fn a_plan_past_the_bound_is_refused_before_it_is_built() {
    let placed = |times: usize| whole_image(&json!({"resp": "runs", "runs": vec![json!({"i_start": format!("{}.1", CHAINS[0]), "width": "8"}); times]})).expect("an image");
    assert_eq!(Identity::of(&placed(300), &placed(300)), Err(Unplanned { pairs: 90_000 }));
    assert!(90_000 > MAX_PAIRS as u64 && 250 * 250 <= MAX_PAIRS);
    let planned = Identity::of(&placed(250), &placed(250)).expect("within the bound");
    assert!(planned.unchanged(), "every place stays with its own");
    // One long run against 4,096 single positions of it, placed 17 times:
    // each place is cut into 8,191 pieces.
    let singles: Vec<Value> = (0..4_096u64).map(|k| json!({"i_start": format!("{}.{}", CHAINS[0], 2 * k + 2), "width": "1"})).collect();
    let cut = whole_image(&json!({"resp": "runs", "runs": singles})).expect("an image");
    let long = whole_image(&json!({"resp": "runs", "runs": vec![json!({"i_start": format!("{}.1", CHAINS[0]), "width": "8192"}); 17]})).expect("an image");
    assert_eq!(Identity::of(&long, &cut), Err(Unplanned { pairs: 17 * 8_192 }), "refused by the pieces of one image");
}

// ── the lines ────────────────────────────────────────────────────────────

/// An insert, a delete and a change are new and gone lines.
///
/// A line typed between two others is one new line; a line deleted is one
/// gone line, read by identity; and a line changed in place is a gone line
/// and a new one, the bytes the change kept counted as shared — each under
/// its hunk's header, two lines of context either side, and the counts as
/// identity has them.
#[test]
fn an_insert_a_delete_and_a_change_are_new_and_gone_lines() {
    let before = Doc::typed(0, 1, EIGHT);
    let typed = Doc::typed(0, 500, "india nine\n");
    let inserted = before.pick(&[1, 2, 3]).then(&typed).then(&before.pick(&[4, 5, 6, 7, 8]));
    assert_eq!(diffed(&before, &inserted), ["@@ -2,4 +2,5 @@", " 2\tbravo two", " 3\tcharlie three", "+4\tindia nine", " 5\tdelta four", " 6\techo five"]);
    let plan_of = identity(&before, &inserted);
    assert_eq!((plan_of.bytes(), plan_of.shared(), plan_of.gone().len()), (Bytes { new: 11, gone: 0, moved: 0 }, EIGHT.len() as u64, 0));
    assert_eq!(plan(&before, &inserted).counts, LineCounts { added: 1, removed: 0, moved: 0 });

    let deleted = before.pick(&[1, 2, 3, 5, 6, 7, 8]);
    assert_eq!(diffed(&before, &deleted), ["@@ -2,5 +2,4 @@", " 2\tbravo two", " 3\tcharlie three", "-4\tdelta four", " 4\techo five", " 5\tfoxtrot six"]);
    let plan_of = identity(&before, &deleted);
    let at = ("alpha one\nbravo two\ncharlie three\n".len()) as u64 + 1;
    assert_eq!(plan_of.gone(), [Gone { before: at, prefix: CHAINS[0].into(), first: at, width: 11 }], "the line's values are read by identity, at its own addresses");
    assert_eq!(plan_of.bytes(), Bytes { new: 0, gone: 11, moved: 0 });

    // `delta four` made `delta 4`: the word typed anew, the rest kept.
    let line = before.pick(&[4]);
    let changed = before.pick(&[1, 2, 3]).then(&Doc(line.0[..6].to_vec())).then(&Doc::typed(0, 600, "4")).then(&Doc(line.0[10..].to_vec())).then(&before.pick(&[5, 6, 7, 8]));
    assert_eq!(changed.text(), EIGHT.replace("delta four", "delta 4"));
    assert_eq!(diffed(&before, &changed), ["@@ -2,5 +2,5 @@", " 2\tbravo two", " 3\tcharlie three", "-4\tdelta four", "+4\tdelta 4", " 5\techo five", " 6\tfoxtrot six"]);
    let plan_of = identity(&before, &changed);
    assert_eq!((plan_of.bytes(), plan_of.shared()), (Bytes { new: 1, gone: 4, moved: 0 }, EIGHT.len() as u64 - 4));
    let lines = plan(&before, &changed);
    assert_eq!((lines.counts, lines.notes), (LineCounts { added: 1, removed: 1, moved: 0 }, vec![]));
}

/// A block moved up or down is told where it stands and where it left.
///
/// Its lines are moved-in rows at their new place, numbered there, and one
/// row at the place they left names both; no line is gone and none new, the
/// bytes moved are counted and none is new or gone, and the note names the
/// lines in both texts. Of the block and the stretch it crossed, the heavier
/// stays (the mutant whose staying set keeps no order holds every line, or
/// tells the move as lines gone and new).
#[test]
fn a_block_moved_up_or_down_is_told_where_it_stands_and_where_it_left() {
    let before = Doc::typed(0, 1, EIGHT);
    let up = before.pick(&[1, 6, 7, 2, 3, 4, 5, 8]);
    assert_eq!(
        diffed(&before, &up),
        ["@@ -1,8 +1,8 @@", " 1\talpha one", ">2\tfoxtrot six", ">3\tgolf seven", " 4\tbravo two", " 5\tcharlie three", " 6\tdelta four", " 7\techo five", "<6-7 to 2-3", " 8\thotel eight"]
    );
    let lines = plan(&before, &up);
    assert_eq!((lines.counts, lines.notes.clone()), (LineCounts { added: 0, removed: 0, moved: 2 }, vec![Note::Moved { before: (6, 7), now: (2, 3) }]));
    let moved = ("foxtrot six\ngolf seven\n".len()) as u64;
    assert_eq!(identity(&before, &up).bytes(), Bytes { new: 0, gone: 0, moved });

    let down = before.pick(&[1, 4, 5, 6, 7, 2, 3, 8]);
    assert_eq!(
        diffed(&before, &down),
        ["@@ -1,8 +1,8 @@", " 1\talpha one", "<2-3 to 6-7", " 2\tdelta four", " 3\techo five", " 4\tfoxtrot six", " 5\tgolf seven", ">6\tbravo two", ">7\tcharlie three", " 8\thotel eight"]
    );
    assert_eq!(plan(&before, &down).notes, [Note::Moved { before: (2, 3), now: (6, 7) }]);
    assert!(plan(&before, &down).ops.iter().all(|op| !matches!(op, Op::Gone { .. } | Op::New { .. })), "no line gone, none new");
}

/// A line that moved takes no part in the match by text.
///
/// A line moved to the text's end by identity, with a copy of it typed
/// where it stood, is told as moved — one row where it left, one where it
/// stands — and the copy as a new line: the two read the same, and the line
/// that left is no partner of the copy (the mutant that matches them as
/// text draws the copy unchanged, no row where the line left, and says the
/// copy re-typed).
#[test]
fn a_line_that_moved_takes_no_part_in_the_match_by_text() {
    let before = Doc::typed(0, 1, EIGHT);
    let now = before.pick(&[1]).then(&Doc::typed(0, 500, "bravo two\n")).then(&before.pick(&[3, 4, 5, 6, 7, 8, 2]));
    assert_eq!(now.text(), EIGHT.to_string() + "bravo two\n");
    assert_eq!(
        diffed(&before, &now),
        ["@@ -1,4 +1,4 @@", " 1\talpha one", "<2-2 to 9-9", "+2\tbravo two", " 3\tcharlie three", " 4\tdelta four", "@@ -7,2 +7,3 @@", " 7\tgolf seven", " 8\thotel eight", ">9\tbravo two"]
    );
    let lines = plan(&before, &now);
    assert_eq!(
        (lines.counts, lines.notes),
        (LineCounts { added: 1, removed: 0, moved: 1 }, vec![Note::Moved { before: (2, 2), now: (9, 9) }]),
        "the line that left is not gone, so the copy is no re-typing of it"
    );
}

/// A line is held or moved only with its line break, at a whole line.
///
/// A line whose words moved while its line break was typed anew is no
/// moved line: it is gone at the one place and new at the other, its bytes
/// counted as moved within lines; and a line that stays while its break is
/// typed anew is unchanged as text, never re-typed (the mutant that takes a
/// line from a pair holding it without its break tells both as lines kept
/// whole by identity).
#[test]
fn a_line_is_held_or_moved_only_with_its_line_break() {
    let before = Doc::typed(0, 1, EIGHT);
    let words = Doc(before.pick(&[2]).0[..9].to_vec());
    // `bravo two` moved past line 4, its line break typed anew there.
    let moved = before.pick(&[1, 3, 4]).then(&words).then(&Doc::typed(0, 700, "\n")).then(&before.pick(&[5, 6, 7, 8]));
    assert_eq!(moved.text(), "alpha one\ncharlie three\ndelta four\nbravo two\necho five\nfoxtrot six\ngolf seven\nhotel eight\n");
    assert_eq!(diffed(&before, &moved), ["@@ -1,6 +1,6 @@", " 1\talpha one", "-2\tbravo two", " 2\tcharlie three", " 3\tdelta four", "+4\tbravo two", " 5\techo five", " 6\tfoxtrot six"]);
    let lines = plan(&before, &moved);
    assert_eq!(lines.notes, [Note::MovedWithinLines { bytes: 9 }], "the words moved, and no whole line holds them");
    assert_eq!(identity(&before, &moved).bytes(), Bytes { new: 1, gone: 1, moved: 9 });
    // In place: the words stay, the break is new.
    let kept = before.pick(&[1]).then(&words).then(&Doc::typed(0, 700, "\n")).then(&before.pick(&[3, 4, 5, 6, 7, 8]));
    assert_eq!(kept.text(), EIGHT);
    assert!(diffed(&before, &kept).is_empty(), "unchanged as text: no row");
    assert!(plan(&before, &kept).notes.is_empty(), "and never re-typed: its words are the old bytes");
    assert_eq!(identity(&before, &kept).bytes(), Bytes { new: 1, gone: 1, moved: 0 });
}

/// A block deleted and typed again is gone and new lines, and said re-typed.
///
/// Typed again at another place, the block is gone lines where it stood and
/// new lines where it stands, never a moved one, and the note names both;
/// typed again in place, it is unchanged as text, drawn in no row, and the
/// note alone says its bytes are new.
#[test]
fn a_block_deleted_and_typed_again_is_gone_and_new_and_said_retyped() {
    let before = Doc::typed(0, 1, EIGHT);
    let again = Doc::typed(0, 800, "bravo two\ncharlie three\n");
    let elsewhere = before.pick(&[1, 4, 5, 6]).then(&again).then(&before.pick(&[7, 8]));
    assert_eq!(
        diffed(&before, &elsewhere),
        [
            "@@ -1,8 +1,8 @@",
            " 1\talpha one",
            "-2\tbravo two",
            "-3\tcharlie three",
            " 2\tdelta four",
            " 3\techo five",
            " 4\tfoxtrot six",
            "+5\tbravo two",
            "+6\tcharlie three",
            " 7\tgolf seven",
            " 8\thotel eight"
        ]
    );
    let lines = plan(&before, &elsewhere);
    assert_eq!((lines.counts, lines.notes), (LineCounts { added: 2, removed: 2, moved: 0 }, vec![Note::Retyped { before: (2, 3), now: (5, 6) }]));
    assert_eq!(identity(&before, &elsewhere).bytes(), Bytes { new: 24, gone: 24, moved: 0 });

    let in_place = before.pick(&[1]).then(&again).then(&before.pick(&[4, 5, 6, 7, 8]));
    assert_eq!(in_place.text(), EIGHT);
    assert!(diffed(&before, &in_place).is_empty(), "the text reads as it did");
    let lines = plan(&before, &in_place);
    assert_eq!((lines.counts, lines.notes), (LineCounts::default(), vec![Note::Retyped { before: (2, 3), now: (2, 3) }]));
    assert!(!identity(&before, &in_place).unchanged());
}

/// A re-typed block under the threshold is not said.
///
/// A block is said re-typed where it holds at least the edit's kept-stretch
/// threshold of characters that are no whitespace: `}` lines and a blank
/// one typed again, seven such characters among them, say nothing, and one
/// character more is said (the mutant that drops the threshold says both).
#[test]
fn a_retyped_block_under_the_threshold_is_not_said() {
    assert_eq!(MIN_KEPT_BETWEEN, 8);
    let before = Doc::typed(0, 1, "fn a() {\n    b();\n}}}}\n\n}}}\nfn c() {\n}\n");
    let small = before.pick(&[1, 2]).then(&Doc::typed(0, 900, "}}}}\n\n}}}\n")).then(&before.pick(&[6, 7]));
    assert_eq!(small.text(), before.text());
    assert!(plan(&before, &small).notes.is_empty(), "seven characters that are no whitespace: under the threshold");
    let enough = before.pick(&[1]).then(&Doc::typed(0, 900, "    b();\n}}}}\n")).then(&before.pick(&[4, 5, 6, 7]));
    assert_eq!(enough.text(), before.text());
    assert_eq!(plan(&before, &enough).notes, [Note::Retyped { before: (2, 3), now: (2, 3) }], "eight: said");
    // A new line equal to a gone one, under the threshold, is not said either.
    let moved = before.pick(&[1, 2, 3, 4, 6, 7]).then(&Doc::typed(0, 950, "}}}\n"));
    assert_eq!(diffed(&before, &moved), ["@@ -3,5 +3,5 @@", " 3\t}}}}", " 4\t", "-5\t}}}", " 5\tfn c() {", " 6\t}", "+7\t}}}"]);
    assert!(plan(&before, &moved).notes.is_empty());
}

/// An indent an edit wrote again is unchanged as text and draws no row.
///
/// An edit of two lines that writes the short stretch between its changes
/// again leaves the line break and the indent between them new bytes on
/// lines that read as they did: the two changed lines are gone and new, the
/// blank line between them is unchanged, drawn as context and said by no
/// note.
#[test]
fn an_indent_an_edit_wrote_again_is_unchanged_as_text_and_draws_no_row() {
    let before = Doc::typed(0, 1, "    a = 1\n\n    b = 2\nend of it\n");
    // `1\n\n    b = 2` written again as `10\n\n    b = 20`.
    let head = Doc(before.0[..8].to_vec());
    let now = head.then(&Doc::typed(0, 300, "10\n\n    b = 20")).then(&Doc(before.0[20..].to_vec()));
    assert_eq!(now.text(), "    a = 10\n\n    b = 20\nend of it\n");
    assert_eq!(diffed(&before, &now), ["@@ -1,4 +1,4 @@", "-1\t    a = 1", "+1\t    a = 10", " 2\t", "-3\t    b = 2", "+3\t    b = 20", " 4\tend of it"]);
    let lines = plan(&before, &now);
    assert_eq!((lines.counts, lines.notes), (LineCounts { added: 2, removed: 2, moved: 0 }, vec![]), "the blank line's new bytes say nothing");
}

/// Two changes share a hunk where their context touches.
///
/// Changes four unchanged lines apart are one hunk, the lines between them
/// all context; five apart they are two, each under its own header with its
/// own numbers; and a change at the text's first or last line has the
/// context that exists.
#[test]
fn two_changes_share_a_hunk_where_their_context_touches() {
    let text: String = (1..=12).map(|n| format!("line number {n}\n")).collect();
    let before = Doc::typed(0, 1, &text);
    let near = before.pick(&[1, 2, 4, 5, 6, 7, 9, 10, 11, 12]);
    assert_eq!(
        diffed(&before, &near),
        [
            "@@ -1,10 +1,8 @@",
            " 1\tline number 1",
            " 2\tline number 2",
            "-3\tline number 3",
            " 3\tline number 4",
            " 4\tline number 5",
            " 5\tline number 6",
            " 6\tline number 7",
            "-8\tline number 8",
            " 7\tline number 9",
            " 8\tline number 10"
        ]
    );
    let far = before.pick(&[1, 2, 4, 5, 6, 7, 8, 10, 11, 12]);
    assert_eq!(
        diffed(&before, &far),
        [
            "@@ -1,5 +1,4 @@",
            " 1\tline number 1",
            " 2\tline number 2",
            "-3\tline number 3",
            " 3\tline number 4",
            " 4\tline number 5",
            "@@ -7,5 +6,4 @@",
            " 6\tline number 7",
            " 7\tline number 8",
            "-9\tline number 9",
            " 8\tline number 10",
            " 9\tline number 11"
        ]
    );
    assert_eq!(plan(&before, &far).hunks.iter().map(|hunk| (hunk.before, hunk.now)).collect::<Vec<_>>(), [((1, 5), (1, 4)), ((7, 5), (6, 4))]);
    let ends = before.pick(&[2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
    assert_eq!(
        diffed(&before, &ends),
        ["@@ -1,3 +1,2 @@", "-1\tline number 1", " 1\tline number 2", " 2\tline number 3", "@@ -10,3 +9,2 @@", " 9\tline number 10", " 10\tline number 11", "-12\tline number 12"]
    );
    // A text emptied, and one filled: a hunk of one text's lines alone.
    let empty = Doc::default();
    let three = before.pick(&[1, 2, 3]);
    assert_eq!(diffed(&three, &empty), ["@@ -1,3 +0,0 @@", "-1\tline number 1", "-2\tline number 2", "-3\tline number 3"]);
    assert_eq!(diffed(&empty, &three), ["@@ -0,0 +1,3 @@", "+1\tline number 1", "+2\tline number 2", "+3\tline number 3"]);
}

/// The widest images a board can answer are planned, and none panics.
///
/// An image of one run as wide as the reader admits, against itself, stays
/// whole; against one a position shorter its last position is gone; and
/// against a run of another chain all of each is gone and new (the mutant
/// that adds a width past the range's end overflows).
#[test]
fn the_widest_images_are_planned() {
    let run = |chain: usize, width: u64| whole_image(&json!({"resp": "runs", "runs": [{"i_start": format!("{}.1", CHAINS[chain]), "width": width.to_string()}]})).expect("an image");
    let widest = u64::MAX - 1;
    let same = Identity::of(&run(0, widest), &run(0, widest)).expect("a plan");
    assert!(same.unchanged());
    assert_eq!(same.sources(), [Stretch { before: 1, width: widest, source: Source::Now(1) }]);
    let shorter = Identity::of(&run(0, widest), &run(0, widest - 1)).expect("a plan");
    assert_eq!((shorter.bytes(), shorter.gone()), (Bytes { new: 0, gone: 1, moved: 0 }, &[Gone { before: widest, prefix: CHAINS[0].into(), first: widest, width: 1 }][..]));
    let apart = Identity::of(&run(0, widest), &run(1, widest)).expect("a plan");
    assert_eq!((apart.bytes(), apart.shared()), (Bytes { new: widest, gone: widest, moved: 0 }, 0));
    let line = |start| Line { start, len: 1, key: 0u8, closed: true, solid: 1 };
    let lines = apart.lines(&[line(1), line(widest)], &[line(1), line(widest)], 2);
    assert_eq!(lines.counts, LineCounts { added: 0, removed: 0, moved: 0 }, "equal as text, every position new: unchanged lines, re-typed");
    assert_eq!(lines.notes, [], "one character each: under the threshold");
}

/// Nothing changed is unchanged, and two empty texts are.
#[test]
fn nothing_changed_is_unchanged() {
    let before = Doc::typed(0, 1, EIGHT);
    let plan_of = identity(&before, &before);
    assert!(plan_of.unchanged());
    assert_eq!((plan_of.bytes(), plan_of.shared()), (Bytes::default(), EIGHT.len() as u64));
    assert_eq!(plan_of.stays(), [Pair { before: 1, now: 1, width: EIGHT.len() as u64 }], "one pair, however many runs");
    let lines = plan(&before, &before);
    assert!(lines.hunks.is_empty() && lines.notes.is_empty() && lines.ops.len() == 8 && lines.counts == LineCounts::default());
    let empty = identity(&Doc::default(), &Doc::default());
    assert!(empty.unchanged() && empty.sources().is_empty());
    // Texts that share no position: all of the one gone, all of the other new.
    let other = Doc::typed(1, 1, EIGHT);
    let apart = identity(&before, &other);
    assert_eq!((apart.shared(), apart.bytes(), apart.unchanged()), (0, Bytes { new: EIGHT.len() as u64, gone: EIGHT.len() as u64, moved: 0 }, false));
}

/// A last line with no line break is a line, numbered as any.
///
/// Held on both sides, it is unchanged; closed by a line break typed after
/// it, it is gone and new — the two are not one line as text — and said by
/// no note under the threshold; a line added after it leaves it gone, new
/// and followed by the new last line; and a text that loses its last line
/// break numbers its lines as before (the mutant that counts a line for a
/// text's end, or drops the open line, numbers the last rows one off).
#[test]
fn a_last_line_with_no_line_break_is_a_line() {
    let closed = Doc::typed(0, 1, "one\ntwo\nthree\n");
    let open = Doc(closed.0[..closed.0.len() - 1].to_vec());
    assert_eq!(open.lines().len(), 3);
    assert!(identity(&open, &open).unchanged() && diffed(&open, &open).is_empty());
    assert_eq!(diffed(&closed, &open), ["@@ -1,3 +1,3 @@", " 1\tone", " 2\ttwo", "-3\tthree", "+3\tthree"], "the last line lost its break: the two are not one line");
    assert_eq!(identity(&closed, &open).bytes(), Bytes { new: 0, gone: 1, moved: 0 });
    assert!(plan(&closed, &open).notes.is_empty(), "its words are the old bytes: not re-typed");
    // A line typed after an open last line, the break between them typed too.
    let more = open.clone().then(&Doc::typed(0, 400, "\nfour"));
    assert_eq!(more.text(), "one\ntwo\nthree\nfour");
    assert_eq!(diffed(&open, &more), ["@@ -1,3 +1,4 @@", " 1\tone", " 2\ttwo", "-3\tthree", "+3\tthree", "+4\tfour"]);
    assert_eq!(plan(&open, &more).hunks[0].ops, 0..5);
    // The open last line deleted: the line before it is the text's last.
    let less = closed.pick(&[1, 2]);
    assert_eq!(diffed(&open, &less), ["@@ -1,3 +1,2 @@", " 1\tone", " 2\ttwo", "-3\tthree"]);
    // An open last line typed again, long enough to be said: equal to the
    // closed one it replaces, break or none.
    let long = Doc::typed(0, 1, "one\nthe last line of it\n");
    let retyped = long.pick(&[1]).then(&Doc::typed(0, 450, "the last line of it"));
    assert_eq!(plan(&long, &retyped).notes, [Note::Retyped { before: (2, 2), now: (2, 2) }]);
}

/// Lines past the text match's bound are gone and new, whole.
///
/// Between two held lines, lines are matched as text only where the two
/// counts multiply within the edit's bound: a thousand and one lines typed
/// again as a thousand are matched nowhere, every one gone or new, where a
/// hundred typed again are every one unchanged (the mutant that matches past
/// the bound walks a million places).
#[test]
fn lines_past_the_text_matchs_bound_are_gone_and_new_whole() {
    let lines = |count: usize| "x\n".repeat(count);
    let (before, now) = (Doc::typed(0, 1, &lines(1_001)), Doc::typed(1, 1, &lines(1_000)));
    assert!(before.lines().len() * now.lines().len() > super::super::MAX_MATCH_PRODUCT, "premise: the two counts multiply past the bound");
    let past = plan(&before, &now);
    assert_eq!(past.counts, LineCounts { added: 1_000, removed: 1_001, moved: 0 });
    assert_eq!(past.hunks.len(), 1);
    let (before, now) = (Doc::typed(0, 1, &lines(100)), Doc::typed(1, 1, &lines(100)));
    let within = plan(&before, &now);
    assert_eq!((within.counts, within.hunks.len()), (LineCounts::default(), 0), "matched as text, every line");
}

/// A line holding a value that is no text is equal to no other as text.
///
/// Two lines that read the same but for a value that is no text carry keys
/// their caller made unequal: typed again they are gone and new, never
/// matched as text; kept by identity they are held as any line is.
#[test]
fn a_line_holding_a_value_that_is_no_text_is_equal_to_no_other() {
    let before = Doc::typed(0, 1, "one\ntwo\nthree\n");
    let now = Doc::typed(1, 1, "one\ntwo\nthree\n");
    let keyed = |doc: &Doc, unique: u8| {
        let mut lines = doc.lines();
        lines[1].key = vec![0xff, unique];
        lines
    };
    let apart = identity(&before, &now).lines(&keyed(&before, 1), &keyed(&now, 2), 2);
    assert_eq!(apart.ops, [Op::Same { before: 1, now: 1 }, Op::Gone { before: 2 }, Op::New { now: 2 }, Op::Same { before: 3, now: 3 }]);
    assert!(apart.notes.is_empty(), "equal to no gone line: not re-typed");
    let held = identity(&before, &before).lines(&keyed(&before, 1), &keyed(&before, 2), 2);
    assert_eq!(held.ops[1], Op::Same { before: 2, now: 2 }, "held by identity, whatever its key");
}
