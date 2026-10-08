use super::*;
use crate::unit::{Class, GapKind, Kind, UnitKey};
use skep_address::{validate, Nat, Tumbler};

fn addr(comps: &[u32]) -> Address {
    let t = Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("nonempty");
    validate(t).expect("a T4-valid address")
}

/// A unit of `items`, the extent starting at the first item's ordinal.
fn unit(items: Vec<Item>) -> Unit {
    Unit::new(UnitKey::new(addr(&[1, 0, 1, 0, 1])), None, Kind::Edition, Class::Guest, 1, items)
        .expect("one extent")
}

fn text_unit(text: &str) -> Unit {
    unit(vec![Item::Text { start: 1, bytes: text.as_bytes().to_vec() }])
}

fn mark(offset: usize, len: usize, kind: MarkKind) -> Mark {
    Mark { offset, len, kind }
}

fn term(t: &str) -> MarkKind {
    MarkKind::Term { term: t.to_string() }
}

/// The span and the mark of `word` at its first occurrence in `text`.
fn at(text: &str, word: &str) -> (Span, Marked<'static>) {
    let offset = text.find(word).expect("present") as u64;
    let len = word.len() as u32;
    (Span { start: 1 + offset, width: u64::from(len) }, Marked { offset, len, term: leak(word) })
}

fn leak(s: &str) -> &'static str {
    Box::leak(s.to_lowercase().into_boxed_str())
}

/// §3.1 the rung is the range's own shape: a document's prefix the Document
/// rung, an account's the Account rung — a position under a document the
/// former, the node the latter.
#[test]
fn the_rung_is_the_ranges_own_shape() {
    assert_eq!(Rung::of(&addr(&[1, 0, 2, 0, 4])), Rung::Document);
    assert_eq!(Rung::of(&addr(&[1, 0, 2, 0, 4, 1])), Rung::Document, "a member");
    assert_eq!(Rung::of(&addr(&[1, 0, 2, 0, 4, 0, 1, 7])), Rung::Document, "a position");
    assert_eq!(Rung::of(&addr(&[1, 0, 2])), Rung::Account);
    assert_eq!(Rung::of(&addr(&[1])), Rung::Account, "the node, the coarser");
}

/// §3.2 THE TIGHTEST WINDOW: one form's first match; of several forms the
/// least window holding one of each, the earliest of equals; none where a
/// form has no match.
#[test]
fn the_tightest_window_holds_one_match_of_each_form() {
    assert_eq!(tightest(&[vec![(3, 8), (20, 25)]]), Some((3, 8, vec![0])));
    assert_eq!(
        tightest(&[vec![(0, 5), (12, 17)], vec![(20, 25)]]),
        Some((12, 25, vec![1, 0])),
        "`alpha` at 12 with `gamma` at 20, not `alpha` at 0"
    );
    assert_eq!(
        tightest(&[vec![(20, 25)], vec![(0, 5), (12, 17)]]),
        Some((12, 25, vec![0, 1])),
        "the leftmost may be any form's"
    );
    assert_eq!(
        tightest(&[vec![(0, 1), (10, 11)], vec![(2, 3), (12, 13)]]),
        Some((0, 3, vec![0, 0])),
        "equal widths: the earliest"
    );
    assert_eq!(
        tightest(&[vec![(0, 9), (4, 6)], vec![(7, 8)]]),
        Some((4, 8, vec![1, 0])),
        "the least end among the matches from the left edge on"
    );
    assert_eq!(tightest(&[vec![(0, 1)], vec![]]), None);
    assert_eq!(tightest(&[]), None);
}

/// §6 THE PARAGRAPH WINDOW: the text between the nearest two blank-line
/// breaks around the span, `start` the V-ordinal of its first byte, the span
/// and the matched term marked inside it.
#[test]
fn the_snippet_is_the_paragraph_around_the_span_with_its_marks() {
    let text = "first paragraph.\n\nsecond paragraph with the word here.\n\nthird paragraph.";
    let u = text_unit(text);
    let (span, marked) = at(text, "word");
    let cut = snippet(&u, span, (0, 0), &[marked]);
    assert_eq!(cut.text, "second paragraph with the word here.");
    assert_eq!(cut.start, 1 + 18);
    assert_eq!(cut.marks, [mark(26, 4, MarkKind::Span), mark(26, 4, term("word"))]);
    // U+2029 is a paragraph break too; a lone line feed is not.
    let text = "one\u{2029}two\nthree word\u{2029}four";
    let u = text_unit(text);
    let (span, marked) = at(text, "word");
    let cut = snippet(&u, span, (0, 0), &[marked]);
    assert_eq!(cut.text, "two\nthree word");
}

/// §6 the bound of 240 bytes either side, each bound moved inward to the
/// nearest CHARACTER boundary: a multi-byte character at the bound is never
/// split.
#[test]
fn a_multi_byte_character_at_the_bound_is_never_split() {
    let run: String = "é".repeat(200);
    let text = format!("{run} word {run}");
    let u = text_unit(&text);
    let (span, marked) = at(&text, "word");
    let cut = snippet(&u, span, (0, 0), &[marked]);
    // 401 − 240 = 161 falls inside the 81st `é` (bytes 160..162): moved to
    // 162; 405 + 240 = 645 falls inside an `é` at 644..646: moved to 644.
    assert_eq!(cut.start, 1 + 162);
    assert_eq!(cut.text.len(), 644 - 162);
    assert!(cut.text.starts_with('é') && cut.text.ends_with('é'));
    assert_eq!(cut.marks[0], mark(401 - 162, 4, MarkKind::Span));
    assert_eq!(cut.marks[1], mark(401 - 162, 4, term("word")));
}

/// §6 a `Gap` inside the window is cut out of the text and carried as a gap
/// mark at its offset with its width; an invalid byte of a `hex` stretch the
/// same, at width one.
#[test]
fn a_gap_inside_the_window_is_cut_out_and_marked() {
    let origin = addr(&[1, 0, 2, 0, 9]);
    let u = unit(vec![
        Item::Text { start: 1, bytes: b"alpha ".to_vec() },
        Item::Gap { start: 7, width: 5, kind: GapKind::Withheld { origin } },
        Item::Text { start: 12, bytes: b"beta \xFFgamma".to_vec() },
    ]);
    // `gamma` at offset 17 from the unit's start: V-ordinal 18.
    let span = Span { start: 18, width: 5 };
    let marked = [Marked { offset: 17, len: 5, term: "gamma" }];
    let cut = snippet(&u, span, (0, 0), &marked);
    assert_eq!(cut.text, "alpha beta gamma");
    assert_eq!(cut.start, 1);
    assert_eq!(
        cut.marks,
        [
            mark(6, 0, MarkKind::Gap { width: 5 }),
            mark(11, 0, MarkKind::Gap { width: 1 }),
            mark(11, 5, MarkKind::Span),
            mark(11, 5, term("gamma")),
        ]
    );
    // A window opening on the gap: `start` names the gap's first position.
    let narrow = snippet_at(&u, Span { start: 18, width: 5 }, 6);
    assert_eq!(narrow.start, 7, "the gap's first position, V-ordinal 7");
    assert_eq!(narrow.marks[0], mark(0, 0, MarkKind::Gap { width: 5 }));
    assert_eq!(narrow.text, "beta gamma");
}

/// The cut from an offset the test fixes, for the window-on-a-gap case.
fn snippet_at(u: &Unit, span: Span, lo: u64) -> Snippet {
    // The bound is a constant; a window from `lo` is had by a span of the
    // same width placed so that `lo` is its left bound.
    let focus = (lo + SNIPPET_BOUND, lo + SNIPPET_BOUND);
    let wide = Span { start: span.start, width: SNIPPET_BOUND + 1 };
    snippet(u, wide, focus, &[])
}

/// §6 a conjunction's window wider than the bound is centred on its rarest
/// matched word, the others marked where they fall inside — the span mark
/// clipped to the window and the far word absent, so the marks say which
/// term fell inside.
#[test]
fn a_wide_conjunction_is_centred_on_its_rarest_word() {
    let filler = "x ".repeat(300);
    let text = format!("alpha {filler}beta");
    let u = text_unit(&text);
    let (alpha, alpha_mark) = at(&text, "alpha");
    let (beta, beta_mark) = at(&text, "beta");
    let span = Span { start: alpha.start, width: beta.start + beta.width - alpha.start };
    assert!(span.width > SNIPPET_BOUND);
    let focus = (beta_mark.offset, beta_mark.offset + 4);
    let cut = snippet(&u, span, focus, &[alpha_mark, beta_mark]);
    assert_eq!(cut.start, 1 + beta_mark.offset - SNIPPET_BOUND);
    assert!(cut.text.ends_with("x beta"));
    assert!(!cut.text.contains("alpha"));
    assert_eq!(
        cut.marks,
        [
            mark(0, SNIPPET_BOUND as usize + 4, MarkKind::Span),
            mark(SNIPPET_BOUND as usize, 4, term("beta")),
        ],
        "the span clipped to the window; `alpha` fell outside and is absent"
    );
}

/// The marks' order: by offset, a gap before the span before a term, then
/// by length and the term's spelling.
#[test]
fn the_marks_are_ordered_once() {
    let mut marks = vec![
        mark(4, 2, term("b")),
        mark(4, 0, MarkKind::Gap { width: 1 }),
        mark(4, 2, term("a")),
        mark(4, 9, MarkKind::Span),
        mark(1, 1, term("z")),
    ];
    marks.sort_by(mark_order);
    assert_eq!(
        marks,
        [
            mark(1, 1, term("z")),
            mark(4, 0, MarkKind::Gap { width: 1 }),
            mark(4, 9, MarkKind::Span),
            mark(4, 2, term("a")),
            mark(4, 2, term("b")),
        ]
    );
}
