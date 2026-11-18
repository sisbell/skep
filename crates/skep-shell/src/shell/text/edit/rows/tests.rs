//! The unit suite of the rows: the lines a plan's text shows, numbered.
//!
//! Each cell plans pairs over a scripted text as `text.edit` plans them
//! (`plan`), nothing written, and reads the rows of the text the plan leaves
//! by the pieces it spliced in step. The rows an `edited` answer carries,
//! through the call's own writes, are held in `edit/tests.rs`, and against
//! the board's own `line_numbers` in `shell/tests/text.rs`.

use serde_json::{json, Value};

use super::super::super::tests::{text_of, DOC, READ_AT};
use super::super::{plan, Pair};
use super::*;

/// Returns the rows the pairs `edits` leave of a draft holding `items`.
fn rows_of(items: Value, edits: &[(&str, &str)]) -> Rows {
    let mut text = text_of(items);
    let pairs: Vec<Pair<'_>> = edits.iter().map(|&(old, new)| Pair { old, new }).collect();
    let plan = plan(DOC, &mut text, READ_AT, &pairs).unwrap_or_else(|refused| panic!("a plan: {}", refused.value));
    rows(&text, &plan.pieces)
}

/// Returns the rows the pairs `edits` leave of a draft holding `text`.
fn lines_of(text: &str, edits: &[(&str, &str)]) -> Vec<String> {
    rows_of(json!([{"content": text}]), edits).lines
}

/// Returns `rows` as the answer carries them.
fn said(rows: &[&str]) -> Vec<String> {
    rows.iter().map(|row| row.to_string()).collect()
}

/// Returns a text of `count` lines, `line 1` to `line {count}`.
fn numbered(count: usize) -> String {
    (1..=count).map(|n| format!("line {n}\n")).collect()
}

/// A change at the text's first line, and at its last, is numbered there.
///
/// The changed line is `+`, and the two lines either side of it that the
/// text holds are shown around it, numbered from line 1. At the last line
/// of a text that ends in a line break, and of one that ends in none, the
/// line is the text's last; a line appended where the text ends in no line
/// break shows the line before it too, whose line break is new.
#[test]
fn a_change_at_the_first_line_and_at_the_last_is_numbered_with_the_lines_around_it() {
    let six = "one\ntwo\nthree\nfour\nfive\nsix\n";
    assert_eq!(lines_of(six, &[("one", "ONE")]), said(&["+1\tONE", " 2\ttwo", " 3\tthree"]));
    assert_eq!(lines_of(six, &[("six", "SIX")]), said(&[" 4\tfour", " 5\tfive", "+6\tSIX"]));
    let open = "one\ntwo\nthree";
    assert_eq!(lines_of(open, &[("three", "THREE")]), said(&[" 1\tone", " 2\ttwo", "+3\tTHREE"]), "no line break at the end");
    assert_eq!(lines_of(open, &[("three", "three\nfour")]), said(&[" 1\tone", " 2\ttwo", "+3\tthree", "+4\tfour"]), "the line before an appended one holds its new line break");
    assert_eq!(ROWS_CONTEXT_LINES, 2);
}

/// A removal of whole lines is one row between the lines that now meet.
///
/// Lines taken out from a line start through a line break are
/// `-<TAB>(N bytes removed here)` between the line before and the line
/// after, two lines shown either side; at the text's start nothing stands
/// before it, and at its end the row says so — where the text ends in a
/// line break, and where it ends in none and the line break before the
/// last line went with it. A text emptied is that row alone.
#[test]
fn a_removal_of_whole_lines_is_one_row_between_the_lines_that_now_meet() {
    let five = "a\nb\nc\nd\ne\n";
    assert_eq!(lines_of(five, &[("c\n", "")]), said(&[" 1\ta", " 2\tb", "-\t(2 bytes removed here)", " 3\td", " 4\te"]));
    assert_eq!(lines_of(five, &[("a\nb\n", "")]), said(&["-\t(4 bytes removed here)", " 1\tc", " 2\td"]), "at the text's start");
    assert_eq!(lines_of(five, &[("e\n", "")]), said(&[" 3\tc", " 4\td", "-\t(2 bytes removed here, at the text's end)"]), "at the end of a text ending in a line break");
    assert_eq!(lines_of("a\nb\nc", &[("b\nc", "b")]), said(&[" 1\ta", " 2\tb", "-\t(2 bytes removed here, at the text's end)"]), "the last line, with the line break before it");
    assert_eq!(lines_of(five, &[(five, "")]), said(&["-\t(10 bytes removed here, at the text's end)"]), "a text emptied");
}

/// A removal inside a line marks the line its two sides now meet on.
///
/// `b, ` taken out of a call's arguments leaves no byte the call inserted
/// and no whole line gone: the line where the text either side of it now
/// meets is the `+` row (the mutant that marks no line for it answers the
/// next line alone, as context of nothing).
#[test]
fn a_removal_inside_a_line_marks_the_line_its_sides_now_meet_on() {
    assert_eq!(lines_of("f(a, b, c)\nnext\n", &[("a, b, c", "a, c")]), said(&["+1\tf(a, c)", " 2\tnext"]));
    assert_eq!(lines_of("a\n", &[("a\n", "a")]), said(&["+1\ta"]), "a last line break alone is no whole line");
}

/// Changes that touch are one stretch, whichever pairs made them.
///
/// One pair takes a line out and the next puts another in at the very place:
/// the two are one change of that line, `+`, and no `-` row stands beside it
/// (the mutant that tells each pair's changes apart answers both).
#[test]
fn changes_that_touch_are_one_stretch_whichever_pairs_made_them() {
    assert_eq!(lines_of("a\nb\nc\n", &[("b\n", ""), ("a\nc", "a\nB\nc")]), said(&[" 1\ta", "+2\tB", " 3\tc"]));
}

/// Rows whose lines touch are one group, and `--` parts two that do not.
///
/// Changes four lines apart show two lines either side each, which overlap:
/// one group; five lines apart, the two groups' lines meet edge to edge:
/// one group still; six apart, one line stands between them unshown, and
/// `--` parts the two.
#[test]
fn rows_whose_lines_touch_are_one_group_and_two_that_do_not_are_parted() {
    let text = numbered(12);
    let changed = |n: u32| (format!("line {n}\n"), format!("LINE {n}\n"));
    let at = |first: u32, second: u32| {
        let ((a, b), (c, d)) = (changed(first), changed(second));
        lines_of(&text, &[(&a, &b), (&c, &d)])
    };
    assert_eq!(at(2, 6), said(&[" 1\tline 1", "+2\tLINE 2", " 3\tline 3", " 4\tline 4", " 5\tline 5", "+6\tLINE 6", " 7\tline 7", " 8\tline 8"]));
    assert_eq!(at(2, 7), said(&[" 1\tline 1", "+2\tLINE 2", " 3\tline 3", " 4\tline 4", " 5\tline 5", " 6\tline 6", "+7\tLINE 7", " 8\tline 8", " 9\tline 9"]), "edge to edge");
    assert_eq!(at(2, 8), said(&[" 1\tline 1", "+2\tLINE 2", " 3\tline 3", " 4\tline 4", "--", " 6\tline 6", " 7\tline 7", "+8\tLINE 8", " 9\tline 9", " 10\tline 10"]), "one line between");
}

/// The rows number the text as the call leaves it, every change shifting
/// those after it.
///
/// A later pair's text inside an earlier pair's new text is one change with
/// it, on the line where both now stand; and two lines a later pair inserts
/// above an earlier pair's change move that change two lines down (the
/// mutants that number the text as first read, or leave an earlier stretch
/// where a later change found it, answer other lines and other numbers).
#[test]
fn the_rows_number_the_text_as_the_call_leaves_it() {
    assert_eq!(lines_of("x\ny\n", &[("y", "hello world"), ("world", "there")]), said(&[" 1\tx", "+2\thello there"]));
    let edited = lines_of("a\nb\nc\nd\ne\nf\ng\n", &[("f", "F"), ("a\n", "a\nA1\nA2\n")]);
    assert_eq!(edited, said(&[" 1\ta", "+2\tA1", "+3\tA2", " 4\tb", " 5\tc", " 6\td", " 7\te", "+8\tF", " 9\tg"]), "`f` stood on line 6");
}

/// A run of more than sixteen `+` rows shows its first six and its last three.
///
/// Seventeen lines put in are six rows, one row counting the eight between,
/// and three; sixteen are sixteen rows (the mutant that cuts every run, or
/// none, answers otherwise).
#[test]
fn a_run_of_more_than_sixteen_changed_lines_shows_its_first_six_and_its_last_three() {
    assert_eq!((ROWS_MAX_RUN, ROWS_RUN_HEAD, ROWS_RUN_TAIL), (16, 6, 3));
    let put_in = |count: usize| {
        let new: String = (1..=count).map(|n| format!("n{n}\n")).collect();
        lines_of("start\nend\n", &[("start\n", &format!("start\n{new}"))])
    };
    let mut cut = vec![" 1\tstart".to_string()];
    cut.extend((1..=ROWS_RUN_HEAD).map(|n| format!("+{}\tn{n}", n + 1)));
    cut.push(format!("+…\t({} more lines)", ROWS_MAX_RUN + 1 - ROWS_RUN_HEAD - ROWS_RUN_TAIL));
    cut.extend((ROWS_MAX_RUN + 1 - ROWS_RUN_TAIL + 1..=ROWS_MAX_RUN + 1).map(|n| format!("+{}\tn{n}", n + 1)));
    cut.push(format!(" {}\tend", ROWS_MAX_RUN + 3));
    assert_eq!(put_in(ROWS_MAX_RUN + 1), cut);
    assert_eq!(cut[ROWS_RUN_HEAD + 1], "+…\t(8 more lines)");
    let whole = put_in(ROWS_MAX_RUN);
    assert_eq!(whole.len(), ROWS_MAX_RUN + 2, "every line shown: {whole:?}");
    assert!(whole.iter().all(|row| !row.starts_with("+…")), "{whole:?}");
}

/// A row draws a value that is no text as `{…}`, bytes that are no UTF-8 as
/// one `{hex:…}`, and cuts a long line.
///
/// An atom on the changed line is one `{…}` in its place; two bytes that
/// are no UTF-8 side by side are one run; and a line of more characters
/// than a row shows is cut there, the rest counted (the mutant that counts
/// bytes for characters cuts it elsewhere).
#[test]
fn a_row_draws_an_atom_bytes_that_are_no_text_and_a_long_line_as_it_says() {
    let atom = rows_of(json!([{"content": "a\nx "}, {"atom": "v"}, {"content": " y\nz\n"}]), &[("x", "X")]);
    assert_eq!(atom, Rows { lines: said(&[" 1\ta", "+2\tX {…} y", " 3\tz"]), masked: false });
    let raw = rows_of(json!([{"content": "a\n"}, {"hex": "fffe"}, {"content": "q\n"}]), &[("q", "Q")]);
    assert_eq!(raw.lines, said(&[" 1\ta", "+2\t{hex:fffe}Q"]));
    assert_eq!(ROWS_MAX_LINE_CHARS, 2000);
    let long = format!("a\nx{}\n", "é".repeat(ROWS_MAX_LINE_CHARS + 4));
    assert_eq!(lines_of(&long, &[("a\nx", "a\nX")]), said(&[" 1\ta", &format!("+2\tX{}…[+5 chars]", "é".repeat(ROWS_MAX_LINE_CHARS - 1))]));
    let full = format!("a\nx{}\n", "é".repeat(ROWS_MAX_LINE_CHARS - 1));
    assert_eq!(lines_of(&full, &[("a\nx", "a\nX")]), said(&[" 1\ta", &format!("+2\tX{}", "é".repeat(ROWS_MAX_LINE_CHARS - 1))]), "a line of exactly the most is whole");
}

/// A withheld run on or before a line the rows show sets `masked`.
///
/// Its line breaks are counted nowhere, so the numbers past it are the
/// reader's own view: one standing on a line shown before the change marks
/// the rows; one standing past every line shown does not (the mutant that
/// drops the mark, or sets it for any withheld run, answers otherwise).
#[test]
fn a_withheld_run_on_or_before_a_line_shown_sets_masked() {
    let withheld = json!({"withheld": {"origin": "1.0.1.0.9", "width": "5"}});
    let before = rows_of(json!([{"content": "a\n"}, withheld, {"content": "b\nc\n"}]), &[("c", "C")]);
    assert_eq!(before, Rows { lines: said(&[" 1\ta", " 2\t{…}b", "+3\tC"]), masked: true });
    let past = rows_of(json!([{"content": "a\nb\nc\nd\ne\nf\n"}, withheld, {"content": "g\n"}]), &[("a", "A")]);
    assert_eq!(past, Rows { lines: said(&["+1\tA", " 2\tb", " 3\tc"]), masked: false });
}

/// The rows stop before the first that would pass their byte bound.
///
/// Thirty-four changes six lines apart, each line fifteen hundred bytes,
/// are more rows than the bound holds: the rows stop whole before it, short
/// of it by less than a row, and a last row counts the changed lines left
/// (the mutant that draws every row passes the bound).
#[test]
fn the_rows_stop_before_the_first_that_would_pass_their_byte_bound() {
    assert_eq!(ROWS_MAX_BYTES, 40_000);
    let text: String = (1..=200).map(|n| format!("{n:03}{}\n", "x".repeat(1500))).collect();
    let pairs: Vec<(String, String)> = (0..34).map(|k| 1 + 6 * k).map(|n| (format!("{n:03}x"), format!("{n:03}y"))).collect();
    let edits: Vec<(&str, &str)> = pairs.iter().map(|(old, new)| (old.as_str(), new.as_str())).collect();
    let lines = lines_of(&text, &edits);
    let (last, shown) = lines.split_last().expect("rows");
    let changed = shown.iter().filter(|row| row.starts_with('+')).count();
    assert!(changed > 0 && changed < 34, "{changed} changed lines shown");
    assert_eq!(*last, format!("({} more changed lines not shown)", 34 - changed));
    let used: usize = shown.iter().map(String::len).sum();
    assert!(used <= ROWS_MAX_BYTES && used + 1600 > ROWS_MAX_BYTES, "the rows fill the bound to within a row: {used}");
}

/// A stretch that only inserts or only removes slides to a line's start.
///
/// A line appended after a line's text, its line break first, is told as
/// the new line alone, slid on; one put in before a line that reads the
/// same is slid back to the line's start; one whose slide reaches no line
/// start stays where it was made; and lines put in or taken out at a line
/// start stay there (the mutants with no slide, with no stop at a line
/// start, or keeping a slide that reaches none, answer other lines).
#[test]
fn a_stretch_that_only_inserts_or_removes_slides_to_a_lines_start() {
    assert_eq!(lines_of("foo\nbar\n", &[("foo", "foo\nbaz")]), said(&[" 1\tfoo", "+2\tbaz", " 3\tbar"]), "slid on");
    assert_eq!(lines_of("x foo", &[("foo", "foo\nx foo")]), said(&["+1\tx foo", " 2\tx foo"]), "slid back");
    assert_eq!(lines_of("x foo", &[("x foo", "x foo\nfoo")]), said(&["+1\tx foo", "+2\tfoo"]), "no line start reached: not slid");
    assert_eq!(lines_of("a\nb\nc\n", &[("b\n", "")]), said(&[" 1\ta", "-\t(2 bytes removed here)", " 2\tc"]), "a whole line out, at a line start");
    assert_eq!(lines_of("a\nc\n", &[("c", "b\nc")]), said(&[" 1\ta", "+2\tb", " 3\tc"]), "a whole line in, at a line start");
    assert_eq!(lines_of("a\nb\nc\nd", &[("b\nc", "b")]), said(&[" 1\ta", " 2\tb", "-\t(2 bytes removed here)", " 3\td"]), "a line taken out with the break before it, slid on");
}

/// The pieces tell every position of the text the plan leaves.
///
/// Their lengths sum to the text's positions, an atom among them; none is
/// empty and no two side by side make one; the bytes removed are kept by
/// their positions as read, each as the draft held it; and the stretches
/// read off them are a replacement and a removal (the mutants that carry
/// no piece past a change, or keep no removed byte, answer otherwise).
#[test]
fn the_pieces_tell_every_position_of_the_text_the_plan_leaves() {
    let mut text = text_of(json!([{"content": "alpha beta\n"}, {"atom": "v"}, {"content": " gamma delta\n"}]));
    let pairs = [Pair { old: "beta", new: "B" }, Pair { old: "gamma delta", new: "gamma" }];
    let plan = plan(DOC, &mut text, READ_AT, &pairs).unwrap_or_else(|refused| panic!("a plan: {}", refused.value));
    let pieces = &plan.pieces;
    assert_eq!(pieces.pieces, [Piece::Kept { from: 1, len: 6 }, Piece::New { len: 1 }, Piece::Kept { from: 11, len: 8 }, Piece::Kept { from: 25, len: 1 }]);
    assert_eq!(pieces.pieces.iter().map(|piece| piece.len()).sum::<u64>(), text.positions());
    assert!(pieces.pieces.windows(2).all(|two| two[0].joined(two[1]).is_none()), "no two side by side make one");
    assert_eq!(pieces.removed, [(7, &b"beta"[..]), (19, &b" delta"[..])]);
    assert_eq!(pieces.changed(), [Changed { new: 7..8, gone: 7..11 }, Changed { new: 16..16, gone: 19..25 }]);
    assert_eq!(rows(&text, pieces).lines, said(&["+1\talpha B", "+2\t{…} gamma"]));
}
