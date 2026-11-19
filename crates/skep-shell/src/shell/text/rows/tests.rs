//! The unit suite of the rows: the lines a call's text shows, numbered.
//!
//! Each cell plans pairs over a scripted text as `text.edit` plans them
//! (`plan`), nothing written, and reads the rows of the text the plan leaves
//! by the pieces it spliced in step; the last cells count a text's lines and
//! their starts, and draw the rows of a text whose lines a move set in
//! another order. The rows an `edited` answer carries, through the call's
//! own writes, are held in `edit/tests.rs`, a `moved` one's in
//! `moving/tests.rs`, and both against the board's own `line_numbers` in
//! `shell/tests/text.rs`.

use serde_json::{json, Value};

use super::super::edit::{plan, Pair};
use super::super::tests::{text_of, DOC, READ_AT};
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

/// A text's lines are counted, and each starts past the break before it.
///
/// They are counted as `line_numbers` counts them, each starting one
/// position past the line break before it. A text that ends in a line break
/// has no empty last line, and one that
/// ends in none ends in a line no break closes; an empty text holds no line;
/// a line break stands in text alone, so an atom between two lines takes its
/// position and starts none; the line one past the count starts one position
/// past the text's last, and line 0 and any line past that start nowhere
/// (the mutants that count an empty last line, count a break in an atom, or
/// start the line past the last anywhere else answer otherwise).
#[test]
fn a_texts_lines_are_counted_and_each_starts_one_past_the_break_before_it() {
    let closed = text_of(json!([{"content": "ab\n\ncd\n"}]));
    let lines = Lines::of(&closed);
    assert_eq!((lines.count(), lines.closed()), (3, true), "a text ending in a line break has no empty last line");
    assert_eq!(lines.starts([1, 2, 3, 4, 5, 0]), [Some(1), Some(4), Some(5), Some(8), None, None], "the line past the last starts one past the text's end");
    let open = text_of(json!([{"content": "ab\n\ncd"}]));
    let lines = Lines::of(&open);
    assert_eq!((lines.count(), lines.closed()), (3, false), "the last line, no break closing it, is a line");
    assert_eq!(lines.starts([4, 3, 1]), [Some(7), Some(5), Some(1)], "asked in any order");
    let empty = text_of(json!([]));
    let lines = Lines::of(&empty);
    assert_eq!((lines.count(), lines.closed(), lines.starts([1, 2])), (0, false, [Some(1), None]), "an empty text holds no line, and a first line would start at 1");
    let atoms = text_of(json!([{"content": "a\n"}, {"atom": "\n"}, {"content": "b\n"}, {"atom": "v"}]));
    let lines = Lines::of(&atoms);
    assert_eq!((lines.count(), lines.closed()), (3, false), "an atom holds no line break, and one at the text's end is a line");
    assert_eq!(lines.starts([2, 3, 4]), [Some(3), Some(6), Some(7)], "an atom takes a position and starts no line");
}

/// The rows of a move show the lines where they stand and where they left.
///
/// Three lines moved up are `+` where they now stand, the two lines either
/// side of them shown, and one `-` row names them where they left by their
/// numbers as read and as they stand; one line is named alone; a run of more
/// than sixteen is cut as any is; the row where the lines left follows the
/// text's last line where its place is past it, the lines before it shown
/// as beside any such row; and lines the text does not hold draw no `+` row
/// and show no line beside them (the mutants that leave the `-` row out,
/// number it in the old text, set it past the text with no line beside it,
/// or draw a line past the count answer otherwise).
#[test]
fn the_rows_of_a_move_show_the_lines_where_they_stand_and_where_they_left() {
    let text = text_of(json!([{"content": "a\nd\ne\nf\nb\nc\ng\nh\ni\n"}]));
    let up = moved(&text, (4, 6), (2, 4), 6);
    assert_eq!(up, Rows { lines: said(&[" 1\ta", "+2\td", "+3\te", "+4\tf", " 5\tb", " 6\tc", "-\t(lines 4–6 moved to 2–4)", " 7\tg", " 8\th"]), masked: false });
    let down = moved(&text, (2, 2), (8, 8), 1);
    assert_eq!(down.lines, said(&[" 1\ta", "-\t(line 2 moved to 8)", " 2\td", " 3\te", "--", " 6\tc", " 7\tg", "+8\th", " 9\ti"]), "one line, named alone, its two places parted");
    let long = text_of(json!([{"content": numbered(24)}]));
    let run = moved(&long, (5, 22), (1, 18), 22).lines;
    assert_eq!(
        run[..ROWS_RUN_HEAD + 1],
        [said(&["+1\tline 1", "+2\tline 2", "+3\tline 3", "+4\tline 4", "+5\tline 5", "+6\tline 6"]), vec![format!("+…\t({} more lines)", 18 - ROWS_RUN_HEAD - ROWS_RUN_TAIL)]].concat()[..]
    );
    assert_eq!(run[run.len() - 4..], said(&[" 22\tline 22", "-\t(lines 5–22 moved to 1–18)", " 23\tline 23", " 24\tline 24"])[..], "{run:?}");
    let fewer = text_of(json!([{"content": "abc\nxyz\n"}]));
    assert_eq!(moved(&fewer, (3, 3), (2, 2), 3).lines, said(&[" 1\tabc", "+2\txyz", "-\t(line 3 moved to 2)"]), "the place the line left is past the last line");
    assert_eq!(moved(&fewer, (2, 2), (3, 3), 1).lines, said(&[" 1\tabc", "-\t(line 2 moved to 3)", " 2\txyz"]), "a line the text does not hold draws no row");
    assert_eq!(moved(&text, (2, 2), (10, 10), 1).lines, said(&[" 1\ta", "-\t(line 2 moved to 10)", " 2\td", " 3\te"]), "and shows no line beside the one it is not");
    let past = moved(&text, (11, 11), (1, 1), 11).lines;
    assert_eq!(past, said(&["+1\ta", " 2\td", " 3\te", "--", " 8\th", " 9\ti", "-\t(line 11 moved to 1)"]), "a place past the last line is the text's end, the lines before it shown");
    let withheld = text_of(json!([{"content": "a\n"}, {"withheld": {"origin": "1.0.1.0.9", "width": "5"}}, {"content": "b\nc\n"}]));
    assert_eq!(moved(&withheld, (3, 3), (1, 1), 3), Rows { lines: said(&["+1\ta", " 2\t{…}b", " 3\tc", "-\t(line 3 moved to 1)"]), masked: true }, "a withheld run on a line shown");
}

// ── a diff's rows ────────────────────────────────────────────────────────

/// One piece of a text a diff's cell types.
///
/// It is text minted from an ordinal on, or a value that is no text.
#[derive(Debug, Clone, Copy)]
enum Typed<'t> {
    /// Text, its first byte minted at this ordinal of the cell's chain.
    Text(u64, &'t str),
    /// An atom minted at this ordinal.
    Atom(u64),
    /// A withheld run of this width, minted from this ordinal on.
    Withheld(u64, u64),
}

/// Returns the text `pieces` make and its image, as a board would hold them.
///
/// A piece typed twice — the same ordinal and text — is the same bytes by
/// identity, wherever it stands.
fn typed(pieces: &[Typed<'_>]) -> (Text, skep_client::board::Image) {
    let chain = format!("{DOC}.0.1");
    let (mut items, mut runs) = (Vec::new(), Vec::new());
    for piece in pieces {
        let (first, width, item) = match *piece {
            Typed::Text(first, text) => (first, text.len() as u64, json!({"content": text})),
            Typed::Atom(first) => (first, 1, json!({"atom": "a value"})),
            Typed::Withheld(first, width) => (first, width, json!({"withheld": {"origin": "1.0.1.0.9", "width": width.to_string()}})),
        };
        items.push(item);
        runs.push(json!({"i_start": format!("{chain}.{first}"), "width": width.to_string()}));
    }
    (text_of(Value::Array(items)), skep_client::board::whole_image(&json!({"resp": "runs", "runs": runs})).expect("an image"))
}

/// Returns the lines `lines`, each typed apart.
///
/// Line `k`, from 1, is minted at `1000 * k`.
fn lines_typed<'t>(lines: &[&'t str]) -> Vec<Typed<'t>> {
    lines.iter().enumerate().map(|(k, line)| Typed::Text(1000 * (k as u64 + 1), line)).collect()
}

/// Returns the rows of the diff from `before` to `now`.
///
/// They start at the hunk of index `from`.
fn diff_of(before: &[Typed<'_>], now: &[Typed<'_>], from: usize) -> DiffRows {
    let ((was, was_image), (is, is_image)) = (typed(before), typed(now));
    let identity = skep_client::text::diff::Identity::of(&was_image, &is_image).expect("a plan");
    let plan = identity.lines(&line_table(&was, false), &line_table(&is, true), ROWS_CONTEXT_LINES);
    diffed(&was, &is, &plan, from)
}

/// Returns the pieces of `all` at the indexes `picked`, in that order.
fn picked<'t>(all: &[Typed<'t>], picked: &[usize]) -> Vec<Typed<'t>> {
    picked.iter().map(|k| all[*k]).collect()
}

/// A diff's hunks stand under their headers, each text's lines numbered.
///
/// A line gone is numbered in the text before and drawn from it; a line new
/// and the lines unchanged are numbered in the draft; and each header names
/// the first line and the count of its hunk's lines in each text, a hunk
/// that follows a change counting the lines that change moved (the mutant
/// that numbers a gone line in the draft, or a header by one text, answers
/// other numbers).
#[test]
fn a_diffs_hunks_stand_under_their_headers_each_texts_lines_numbered() {
    let texts: Vec<String> = (1..=12).map(|n| format!("line {n}\n")).collect();
    let before = lines_typed(&texts.iter().map(String::as_str).collect::<Vec<_>>());
    let mut now = picked(&before, &[0, 1, 3, 4, 5, 6, 7, 8]);
    now.push(Typed::Text(50_000, "added\n"));
    now.extend(picked(&before, &[9, 10, 11]));
    let rows = diff_of(&before, &now, 0);
    assert_eq!(
        rows.rows,
        said(&["@@ -1,5 +1,4 @@", " 1\tline 1", " 2\tline 2", "-3\tline 3", " 3\tline 4", " 4\tline 5", "@@ -8,4 +7,5 @@", " 7\tline 8", " 8\tline 9", "+9\tadded", " 10\tline 10", " 11\tline 11"])
    );
    assert_eq!((rows.masked, rows.next_hunk), (false, None));
    assert_eq!(diff_of(&before, &now, 1).rows[0], "@@ -8,4 +7,5 @@", "from the second hunk on");
    assert!(diff_of(&before, &before, 0).rows.is_empty(), "nothing changed: no row");
    // A text emptied, and one filled.
    let three = picked(&before, &[0, 1, 2]);
    assert_eq!(diff_of(&three, &[], 0).rows, said(&["@@ -1,3 +0,0 @@", "-1\tline 1", "-2\tline 2", "-3\tline 3"]));
    assert_eq!(diff_of(&[], &three, 0).rows, said(&["@@ -0,0 +1,3 @@", "+1\tline 1", "+2\tline 2", "+3\tline 3"]));
}

/// Lines that moved are drawn where they stand, their leaving in one row.
///
/// A block moved up is `>` rows at its new place, numbered in the draft,
/// and one `<` row where it stood, naming its lines before and now; one line
/// moved says `line`; and no row is a line gone or a line new (the mutant
/// that draws a moved line as new, or a row for each line that left, answers
/// other rows).
#[test]
fn lines_that_moved_are_drawn_where_they_stand_and_one_row_says_where_they_left() {
    let before = lines_typed(&["alpha\n", "bravo\n", "charlie\n", "delta\n", "echo\n", "foxtrot\n", "golf\n", "hotel\n"]);
    let up = picked(&before, &[0, 5, 6, 1, 2, 3, 4, 7]);
    assert_eq!(
        diff_of(&before, &up, 0).rows,
        said(&["@@ -1,8 +1,8 @@", " 1\talpha", ">2\tfoxtrot", ">3\tgolf", " 4\tbravo", " 5\tcharlie", " 6\tdelta", " 7\techo", "<\t(lines 6–7 moved to 2–3)", " 8\thotel"])
    );
    let one = picked(&before, &[0, 1, 2, 3, 4, 6, 7, 5]);
    assert_eq!(diff_of(&before, &one, 0).rows, said(&["@@ -4,5 +4,5 @@", " 4\tdelta", " 5\techo", "<\t(line 6 moved to 8)", " 6\tgolf", " 7\thotel", ">8\tfoxtrot"]));
}

/// A long run of gone, new or moved-in rows shows its two ends.
///
/// Thirty lines gone show their first six, one row of their own sign
/// counting the twenty-one left out, and their last three; so do thirty
/// lines new and thirty moved here; and a run of sixteen is shown whole
/// (the mutant that cuts every sign as `+`, or counts the rows shown, says
/// otherwise).
#[test]
fn a_long_run_of_gone_new_or_moved_in_rows_shows_its_two_ends() {
    let texts: Vec<String> = (1..=34).map(|n| format!("line {n}\n")).collect();
    let all = lines_typed(&texts.iter().map(String::as_str).collect::<Vec<_>>());
    let ends = picked(&all, &[0, 1, 32, 33]);
    let gone = diff_of(&all, &ends, 0).rows;
    assert_eq!(gone.len(), 1 + 2 + 6 + 1 + 3 + 2);
    assert_eq!(gone[..4], said(&["@@ -1,34 +1,4 @@", " 1\tline 1", " 2\tline 2", "-3\tline 3"])[..]);
    assert_eq!(gone[8..], said(&["-8\tline 8", "-…\t(21 more lines)", "-30\tline 30", "-31\tline 31", "-32\tline 32", " 3\tline 33", " 4\tline 34"])[..]);
    let new = diff_of(&ends, &all, 0).rows;
    assert_eq!(new[8..], said(&["+8\tline 8", "+…\t(21 more lines)", "+30\tline 30", "+31\tline 31", "+32\tline 32", " 33\tline 33", " 34\tline 34"])[..]);
    // Thirty lines moved above one line that outweighs them: the heavier
    // stretch stays, so the thirty are the lines moved here.
    let heavy = Typed::Text(900_000, "a line long enough to outweigh thirty short ones: ................................................................................................................................................................................................................................................\n");
    let mut before = vec![heavy];
    before.extend(picked(&all, &(2..32).collect::<Vec<_>>()));
    let mut moved_up = picked(&all, &(2..32).collect::<Vec<_>>());
    moved_up.push(heavy);
    let moved = diff_of(&before, &moved_up, 0).rows;
    assert_eq!(moved[..8], said(&["@@ -1,31 +1,31 @@", ">1\tline 3", ">2\tline 4", ">3\tline 5", ">4\tline 6", ">5\tline 7", ">6\tline 8", ">…\t(21 more lines)"])[..]);
    assert_eq!(moved[8..11], said(&[">28\tline 30", ">29\tline 31", ">30\tline 32"])[..]);
    assert!(moved[11].starts_with(" 31\ta line long enough"), "the heavy line stays: the thirty are the ones that moved");
    assert_eq!(moved[12..], said(&["<\t(lines 2–31 moved to 1–30)"])[..], "one row where they left, however many they are");
    let sixteen = diff_of(&picked(&all, &(0..18).collect::<Vec<_>>()), &picked(&all, &[0, 17]), 0).rows;
    assert_eq!(sixteen.len(), 1 + 1 + 16 + 1, "a run of sixteen is shown whole");
    assert_eq!((ROWS_MAX_RUN, ROWS_RUN_HEAD, ROWS_RUN_TAIL), (16, 6, 3));
}

/// The rows stop after the last whole hunk that fits, and say the next.
///
/// Five hunks of some nine thousand bytes each pass the byte bound: the
/// first four are drawn whole and the fifth is the hunk to ask next; asked
/// from the fifth on, it is drawn and no hunk is next. One hunk past the
/// bound alone is cut where the bound falls, its last row counting the
/// changed lines it leaves out, and the hunk after it is the one to ask
/// next (the mutants that cut a hunk in two, or stop without saying where,
/// answer otherwise).
#[test]
fn the_rows_stop_after_the_last_whole_hunk_that_fits_and_say_the_next() {
    let wide = |n: usize| format!("{n:>4} {}\n", "x".repeat(1_890));
    let texts: Vec<String> = (1..=60).map(wide).collect();
    let all = lines_typed(&texts.iter().map(String::as_str).collect::<Vec<_>>());
    // One line gone in every twelve: five hunks, five lines each.
    let kept: Vec<usize> = (0..60).filter(|k| k % 12 != 5).collect();
    let now = picked(&all, &kept);
    let whole = diff_of(&all, &now, 0);
    let headers = |rows: &DiffRows| rows.rows.iter().filter(|row| row.starts_with("@@")).count();
    assert_eq!((headers(&whole), whole.next_hunk), (4, Some(5)), "four whole hunks fit, the fifth is next");
    assert!(whole.rows.iter().map(String::len).sum::<usize>() <= ROWS_MAX_BYTES);
    assert_eq!(whole.rows.len(), 4 * 6, "each hunk whole: its header, four lines of context and the gone line");
    let rest = diff_of(&all, &now, 4);
    assert_eq!((headers(&rest), rest.next_hunk, rest.rows.len()), (1, None, 6), "from the fifth on: the last hunk");
    // Every other line gone, in one hunk of thirty-nine lines, then a
    // second hunk far below it.
    let texts: Vec<String> = (1..=60).map(wide).collect();
    let all = lines_typed(&texts.iter().map(String::as_str).collect::<Vec<_>>());
    let kept: Vec<usize> = (0..60).filter(|k| !(k % 2 == 1 && *k < 40) && *k != 55).collect();
    let cut = diff_of(&all, &picked(&all, &kept), 0);
    assert_eq!((headers(&cut), cut.next_hunk), (1, Some(2)), "the first hunk does not fit alone: cut, and the second is next");
    let (last, shown) = (cut.rows.last().expect("a row"), cut.rows.iter().filter(|row| row.starts_with('-')).count());
    assert_eq!(*last, format!("({} more changed lines not shown)", 20 - shown));
    assert!(shown > 0 && shown < 20 && cut.rows[..cut.rows.len() - 1].iter().map(String::len).sum::<usize>() <= ROWS_MAX_BYTES);
    assert_eq!(ROWS_MAX_BYTES, 40_000);
}

/// A line holding a value that is no text equals no other.
///
/// It is drawn `{…}` where the value stands.
/// Typed again around another atom, a line that reads the same but for the
/// atom is a line gone and a line new, each drawn with `{…}` where the value
/// stands; kept by identity it is held, and no row is drawn (the mutant
/// that keys a line by its text alone matches the two and draws nothing).
#[test]
fn a_line_holding_a_value_that_is_no_text_is_drawn_and_equals_no_other() {
    let before = [Typed::Text(1000, "one\n"), Typed::Text(2000, "see "), Typed::Atom(2100), Typed::Text(2200, " here\n"), Typed::Text(3000, "three\n")];
    let again = [Typed::Text(1000, "one\n"), Typed::Text(7000, "see "), Typed::Atom(7100), Typed::Text(7200, " here\n"), Typed::Text(3000, "three\n")];
    assert_eq!(diff_of(&before, &again, 0).rows, said(&["@@ -1,3 +1,3 @@", " 1\tone", "-2\tsee {…} here", "+2\tsee {…} here", " 3\tthree"]));
    assert!(diff_of(&before, &before, 0).rows.is_empty(), "held by identity");
    let (text, _) = typed(&before);
    let table = line_table(&text, true);
    assert_eq!(table.iter().map(|line| (line.start, line.len, line.closed)).collect::<Vec<_>>(), [(1, 4, true), (5, 11, true), (16, 6, true)]);
    assert_eq!((table[0].key, table[1].key, table[2].key), (Key::Text(b"one"), Key::Other { now: true, number: 2 }, Key::Text(b"three")));
    assert_ne!(line_table(&text, false)[1].key, table[1].key, "equal to no line of the other text either");
}

/// A last line no line break ends is followed by the row that says so.
///
/// Gone, new or unchanged, a text's last line with no line break is drawn
/// as any line and followed by `\ no line break at the end`; a text that
/// ends in a line break has no such row; and the line table counts the open
/// line, its key its bytes and no line break (the mutant that numbers a
/// last line one off draws the row after another line, or none).
#[test]
fn a_last_line_no_line_break_ends_is_followed_by_the_row_that_says_so() {
    let closed = lines_typed(&["one\n", "two\n", "three\n"]);
    let open = [closed[0], closed[1], Typed::Text(9000, "three")];
    assert_eq!(diff_of(&closed, &open, 0).rows, said(&["@@ -1,3 +1,3 @@", " 1\tone", " 2\ttwo", "-3\tthree", "+3\tthree", "\\ no line break at the end"]));
    assert_eq!(diff_of(&open, &closed, 0).rows, said(&["@@ -1,3 +1,3 @@", " 1\tone", " 2\ttwo", "-3\tthree", "\\ no line break at the end", "+3\tthree"]));
    let both = [Typed::Text(8000, "zero\n"), closed[0], closed[1], Typed::Text(9000, "three")];
    assert_eq!(diff_of(&open, &both, 0).rows, said(&["@@ -1,2 +1,3 @@", "+1\tzero", " 2\tone", " 3\ttwo"]), "the open last line lies past the hunk");
    let near = [closed[0], Typed::Text(8000, "new\n"), closed[1], Typed::Text(9000, "three")];
    assert_eq!(diff_of(&open, &near, 0).rows, said(&["@@ -1,3 +1,4 @@", " 1\tone", "+2\tnew", " 3\ttwo", " 4\tthree", "\\ no line break at the end"]), "unchanged and open: said once");
    let (text, _) = typed(&open);
    let table = line_table(&text, false);
    assert_eq!((table.len(), table[2].start, table[2].len, table[2].closed, table[2].key), (3, 9, 5, false, Key::Text(b"three")));
    assert_eq!(line_table(&Text::default(), true), vec![], "an empty text has no line");
    let (blank, _) = typed(&[Typed::Text(1, "a b\n\n  \tcd\u{e9}\n")]);
    assert_eq!(line_table(&blank, true).iter().map(|line| line.solid).collect::<Vec<_>>(), [2, 0, 3], "the characters that are no whitespace");
}

/// A withheld run on or before a line a diff shows sets `masked`.
///
/// Its line breaks are counted nowhere, so every number past it is the
/// reader's own: in the draft or in the text before, on or before the last
/// line of that text the rows reach, `masked` is set, and past it it is not.
#[test]
fn a_withheld_run_on_or_before_a_line_a_diff_shows_sets_masked() {
    let texts: Vec<String> = (1..=9).map(|n| format!("line {n}\n")).collect();
    let all = lines_typed(&texts.iter().map(String::as_str).collect::<Vec<_>>());
    let run = Typed::Withheld(70_000, 5);
    let ahead: Vec<Typed<'_>> = [vec![run], all.clone()].concat();
    let ahead_now: Vec<Typed<'_>> = [vec![run], picked(&all, &[0, 1, 3, 4, 5, 6, 7, 8])].concat();
    let rows = diff_of(&ahead, &ahead_now, 0);
    assert_eq!(rows.rows, said(&["@@ -1,5 +1,4 @@", " 1\t{…}line 1", " 2\tline 2", "-3\tline 3", " 3\tline 4", " 4\tline 5"]));
    assert!(rows.masked, "the run stands on the first line shown");
    let past: Vec<Typed<'_>> = [all.clone(), vec![run]].concat();
    let past_now: Vec<Typed<'_>> = [picked(&all, &[0, 1, 3, 4, 5, 6, 7, 8]), vec![run]].concat();
    assert!(!diff_of(&past, &past_now, 0).masked, "the run stands past every line shown");
    // In the text before alone: a run gone, drawn from the text before.
    let gone = diff_of(&ahead, &picked(&all, &[0, 1, 2, 3]), 0);
    assert!(gone.masked && gone.rows.contains(&"-1\t{…}line 1".to_string()), "{:?}", gone.rows);
}
