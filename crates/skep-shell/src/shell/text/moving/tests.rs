//! The unit suite of `text.move`.
//!
//! It holds the members, the cuts each move sends against a scripted board
//! (the text suite's `Script`) with the text they leave worked by the wire's
//! own rule, the refusals a read decides with nothing written, the one
//! write's every end and the rows a landed move answers. The row itself, its
//! order, the identities a real board keeps and a draft that moved under the
//! call run against the daemon in `shell/tests/text.rs`.

use super::super::tests::{held_answer, lines, moved_verdict, settling, text_of, Script, DOC, READ_AT};
use super::super::MAX_DRAFT_POSITIONS;
use super::*;
use crate::refusal::Name;

/// Five lines, each longer than the one before, ending in a line break.
///
/// The lines start at the positions 1, 3, 6, 10 and 15, and the text ends
/// at 20.
const FIVE: &str = "a\nbb\nccc\ndddd\neeeee\n";

/// Three lines, the last closed by no line break.
///
/// The lines start at the positions 1, 3 and 6, and the text ends at 8.
const OPEN: &str = "a\nbb\nccc";

/// Three lines, the second empty and the last closed by no line break.
///
/// The lines start at the positions 1, 5 and 6, and the text ends at 8.
const GAPPED: &str = "abc\n\nxyz";

/// The commit the scripted `rearrange` lands at.
const LANDED_AT: u64 = 44;

/// The reads the call opens with, over a draft holding `items`.
///
/// A draft of no position is read in two, no part of its text asked.
fn reads(items: &Value) -> Vec<Result<Value, Refusal>> {
    let positions = text_of(items.clone()).positions();
    let set = if positions == 0 { json!([]) } else { json!([{"start": "1.1", "width": format!("0.{positions}")}]) };
    let mut reads = vec![Ok(json!({"resp": "doc_metadata", "doc": DOC, "published": false, "as_of": READ_AT - 1})), Ok(json!({"resp": "span_set", "as_of": READ_AT, "set": set}))];
    if positions > 0 {
        reads.push(Ok(json!({"resp": "delivery", "as_of": READ_AT + 2, "items": items})));
    }
    reads
}

/// Returns the call's outcome over a draft holding `items`.
///
/// Beside it are the calls made past the draft's reads. `args` are the
/// call's members bar `doc`, and the board answers `after` past the reads.
fn run(items: Value, mut args: Value, after: Vec<Result<Value, Refusal>>) -> (Result<Answer, Refusal>, Vec<Value>) {
    let opening = reads(&items);
    let read = opening.len();
    let script = Script::of(opening.into_iter().chain(after).collect());
    args["doc"] = Value::from(DOC);
    let outcome = Asked::read(&args).and_then(|asked| move_lines(&script, &asked));
    (outcome, script.sent_past(read))
}

/// Returns the answer of a move of `text` that lands, and its cuts.
///
/// The one write sent is the `rearrange` about those cuts, typed against the
/// read; the answer is held to its declared shape and returned as the row
/// answers it.
fn landed(text: &str, args: Value) -> (Value, Vec<u64>) {
    let (answer, sent) = run(json!([{"content": text}]), args.clone(), vec![Ok(json!({"resp": "ack", "at": LANDED_AT}))]);
    let answer = answer.unwrap_or_else(|refusal| panic!("{args}: {refusal}"));
    assert!(!answer.is_error, "{args}: {}", answer.value);
    let value = answer.into_value();
    crate::shapes::assert_declared("TextMoved", &value);
    let cuts: Vec<u64> = value["cuts"].as_array().expect("the cuts").iter().map(|cut| cut.as_str().and_then(|cut| cut.parse().ok()).expect("a cut, a decimal string")).collect();
    assert_eq!(sent, [frames::rearrange(DOC, &cuts, READ_AT, None)], "{args}: one write, typed against the read");
    (value, cuts)
}

/// Returns `text` as the board's `rearrange` about `cuts` leaves it.
///
/// wire.md §Arrangement: three cuts exchange the two regions between them,
/// four the two outer regions around the middle one.
fn rearranged(text: &str, cuts: &[u64]) -> String {
    let at = |cut: u64| cut as usize - 1;
    match *cuts {
        [a, b, c] => [&text[..at(a)], &text[at(b)..at(c)], &text[at(a)..at(b)], &text[at(c)..]].concat(),
        [a, b, c, d] => [&text[..at(a)], &text[at(c)..at(d)], &text[at(b)..at(c)], &text[at(a)..at(b)], &text[at(d)..]].concat(),
        _ => panic!("three cuts or four: {cuts:?}"),
    }
}

/// Returns `rows` as the answer carries them.
fn said(rows: &[&str]) -> Value {
    json!(rows)
}

/// A block moved changes places with the stretch it crosses.
///
/// Up, down, to the text's end and from it,
/// each move is one `rearrange` of three cuts, the starts of the lines it
/// names, typed against the read's position though a later read of the call
/// answered a later one; the text they leave holds every line whole, in the
/// order asked; and the answer names the lines as asked, where they now
/// stand, the cuts as decimal strings and the commit (the mutants that take
/// the block's end at its last byte, type the write against another read, or
/// number the lines as read answer other cuts, another frame or other
/// lines).
#[test]
fn a_block_moved_changes_places_with_the_stretch_it_crosses() {
    for (args, cuts, text, to) in [
        (json!({"first": 4, "last": 5, "before": 2}), vec![3, 10, 21], "a\ndddd\neeeee\nbb\nccc\n", (2, 3)),
        (json!({"first": 1, "last": 2, "before": 5}), vec![1, 6, 15], "ccc\ndddd\na\nbb\neeeee\n", (3, 4)),
        (json!({"first": 2}), vec![3, 6, 21], "a\nccc\ndddd\neeeee\nbb\n", (5, 5)),
        (json!({"first": 2, "last": null, "before": 6}), vec![3, 6, 21], "a\nccc\ndddd\neeeee\nbb\n", (5, 5)),
        (json!({"first": 5, "before": 1}), vec![1, 15, 21], "eeeee\na\nbb\nccc\ndddd\n", (1, 1)),
        (json!({"first": 3, "last": 3, "before": 2}), vec![3, 6, 10], "a\nccc\nbb\ndddd\neeeee\n", (2, 2)),
    ] {
        let (answer, sent) = landed(FIVE, args.clone());
        assert_eq!((&sent, rearranged(FIVE, &sent).as_str()), (&cuts, text), "{args}");
        let (first, last) = (args["first"].as_u64().expect("first"), args["last"].as_u64().or(args["first"].as_u64()).expect("last"));
        let strings: Vec<String> = cuts.iter().map(u64::to_string).collect();
        let mut expected = json!({"outcome": "moved", "doc": DOC, "first": first, "last": last, "to_first": to.0, "to_last": to.1, "cuts": strings, "at": LANDED_AT});
        expected["lines"] = answer["lines"].clone();
        assert_eq!(answer, expected, "{args}");
    }
    let (answer, _) = landed(FIVE, json!({"first": 4, "last": 5, "before": 2}));
    assert_eq!(answer["lines"], said(&[" 1\ta", "+2\tdddd", "+3\teeeee", " 4\tbb", " 5\tccc", "-\t(lines 4–5 moved to 2–3)"]), "up: the block, then where it left");
    let (answer, _) = landed(FIVE, json!({"first": 1, "last": 2, "before": 5}));
    assert_eq!(answer["lines"], said(&["-\t(lines 1–2 moved to 3–4)", " 1\tccc", " 2\tdddd", "+3\ta", "+4\tbb", " 5\teeeee"]), "down: where it left, then the block");
    let (answer, _) = landed(FIVE, json!({"first": 3, "before": 2}));
    assert_eq!(answer["lines"], said(&[" 1\ta", "+2\tccc", " 3\tbb", "-\t(line 3 moved to 2)", " 4\tdddd", " 5\teeeee"]), "one line");
}

/// A text ending in no line break takes four cuts, every line kept whole.
///
/// The last line moved up, alone or in a block, and a block moved down to
/// the end, would each set the unclosed line before another: four cuts keep
/// one line break between the two regions exchanged, and the text ends in no
/// line break still. A move that sets nothing after the last line is three
/// cuts, as any is (the mutant that sends three for every move joins two
/// lines, and the one that sends four where three do refuses at the board).
#[test]
fn a_text_ending_in_no_line_break_takes_four_cuts_so_every_line_stays_whole() {
    for (args, cuts, text) in [
        (json!({"first": 3, "before": 1}), vec![1, 5, 6, 9], "ccc\na\nbb"),
        (json!({"first": 2, "last": 3, "before": 1}), vec![1, 2, 3, 9], "bb\nccc\na"),
        (json!({"first": 1}), vec![1, 2, 3, 9], "bb\nccc\na"),
        (json!({"first": 1, "last": 2}), vec![1, 5, 6, 9], "ccc\na\nbb"),
        (json!({"first": 1, "before": 3}), vec![1, 3, 6], "bb\na\nccc"),
        (json!({"first": 2, "before": 1}), vec![1, 3, 6], "bb\na\nccc"),
    ] {
        let (_, sent) = landed(OPEN, args.clone());
        assert_eq!((&sent, rearranged(OPEN, &sent).as_str()), (&cuts, text), "{args}");
    }
    let (answer, _) = landed(OPEN, json!({"first": 3, "before": 1}));
    assert_eq!((answer["to_first"].as_u64(), answer["to_last"].as_u64(), &answer["lines"]), (Some(1), Some(1), &said(&["+1\tccc", " 2\ta", " 3\tbb", "-\t(line 3 moved to 1)"])), "{answer}");
    let (answer, _) = landed(OPEN, json!({"first": 1}));
    assert_eq!((answer["to_first"].as_u64(), answer["to_last"].as_u64(), &answer["lines"]), (Some(3), Some(3), &said(&["-\t(line 1 moved to 3)", " 1\tbb", " 2\tccc", "+3\ta"])), "{answer}");
}

/// An empty first region sends three cuts, and the text holds a line fewer.
///
/// The last line moved up across one empty line, and one empty line moved
/// down to the end, each leave the empty line's break closing the text: the
/// three cuts are sent, the text ends in a line break and holds two lines
/// for three. The rows number it so: the row where the lines left follows
/// the last line and no later one, and the empty line, now the text's last
/// line break, is no line — it is answered one past the last line and drawn
/// by no `+` row (the mutants that send four cuts not ascending, number the
/// rows by the read's count, or draw the line that is none answer
/// otherwise).
#[test]
fn where_the_four_cuts_first_region_would_be_empty_three_are_sent_and_the_text_holds_one_line_fewer() {
    let counted = |cuts: &[u64]| Lines::of(&text_of(json!([{"content": GAPPED}])).rearranged(cuts)).count();
    assert_eq!(Lines::of(&text_of(json!([{"content": GAPPED}]))).count(), 3, "premise: three lines as read");
    let (up, cuts) = landed(GAPPED, json!({"first": 3, "before": 2}));
    assert_eq!((&cuts, rearranged(GAPPED, &cuts).as_str(), counted(&cuts)), (&vec![5, 6, 9], "abc\nxyz\n", 2), "the last line up across one empty line");
    assert_eq!((up["to_first"].as_u64(), up["to_last"].as_u64(), &up["lines"]), (Some(2), Some(2), &said(&[" 1\tabc", "+2\txyz", "-\t(line 3 moved to 2)"])), "no row past the two lines: {up}");
    let (down, cuts) = landed(GAPPED, json!({"first": 2}));
    assert_eq!((&cuts, rearranged(GAPPED, &cuts).as_str(), counted(&cuts)), (&vec![5, 6, 9], "abc\nxyz\n", 2), "one empty line down to the end");
    assert_eq!(
        (down["to_first"].as_u64(), down["to_last"].as_u64(), &down["lines"]),
        (Some(3), Some(3), &said(&[" 1\tabc", "-\t(line 2 moved to 3)", " 2\txyz"])),
        "the line that is none has no row: {down}"
    );
    let (block, cuts) = landed(GAPPED, json!({"first": 2, "last": 3, "before": 1}));
    assert_eq!((&cuts, rearranged(GAPPED, &cuts).as_str(), counted(&cuts)), (&vec![1, 4, 5, 9], "\nxyz\nabc", 3), "an empty line in a block of two is four cuts");
    assert_eq!(block["lines"], said(&["+1\t", "+2\txyz", " 3\tabc", "-\t(lines 2–3 moved to 1–2)"]), "{block}");
}

/// A `before` at the block's own edges moves nothing.
///
/// The block stands before its own first line and before the line after its
/// last already; the text's last lines moved to the end too, named or not.
/// The answer is `unchanged` with the position the draft was read at, and no
/// write is sent (the mutant that sends the cuts of such a move is refused
/// by the board, its cuts not ascending).
#[test]
fn a_before_at_the_blocks_own_edges_moves_nothing() {
    for args in
        [json!({"first": 2, "last": 3, "before": 2}), json!({"first": 2, "last": 3, "before": 4}), json!({"first": 4, "last": 5}), json!({"first": 5, "before": 6}), json!({"first": 1, "last": 5})]
    {
        let (answer, sent) = run(json!([{"content": FIVE}]), args.clone(), Vec::new());
        assert!(sent.is_empty(), "{args}: no write: {sent:?}");
        let answer = answer.expect("an answer");
        crate::shapes::assert_declared("TextMoveUnchanged", &answer.value);
        assert_eq!(answer, Answer { value: json!({"outcome": "unchanged", "doc": DOC, "as_of": READ_AT}), is_error: false }, "{args}");
    }
}

/// A line the text does not hold is refused before any write.
///
/// A `first` or a `last` past the last line, and a `before` past the line
/// one beyond it, each answer `no_such_line` as data, naming the member, the
/// line it names and the text's count, the first of the three speaking; one
/// past the last line is a place a block may stand before; and a draft of no
/// position holds no line (the mutants that take a line past the count for
/// the text's end, or check `before` first, answer a move or another
/// member).
#[test]
fn a_line_the_text_does_not_hold_is_refused_before_any_write() {
    let refused = |items: Value, args: Value, what: &str, line: u64, count: u64| {
        let (answer, sent) = run(items, args.clone(), Vec::new());
        assert!(sent.is_empty(), "{args}: no write: {sent:?}");
        let answer = answer.expect("an answer");
        crate::shapes::assert_declared("TextRefused", &answer.value);
        assert_eq!(answer, Answer { value: json!({"outcome": "refused", "cause": "no_such_line", "doc": DOC, "what": what, "line": line, "count": count}), is_error: false }, "{args}");
    };
    let five = || json!([{"content": FIVE}]);
    refused(five(), json!({"first": 6}), "first", 6, 5);
    refused(five(), json!({"first": 6, "last": 9, "before": 12}), "first", 6, 5);
    refused(five(), json!({"first": 5, "last": 6, "before": 12}), "last", 6, 5);
    refused(five(), json!({"first": 2, "last": u64::MAX}), "last", u64::MAX, 5);
    refused(five(), json!({"first": 2, "last": 3, "before": 7}), "before", 7, 5);
    refused(json!([{"content": OPEN}]), json!({"first": 1, "before": 5}), "before", 5, 3);
    refused(json!([]), json!({"first": 1}), "first", 1, 0);
    let (answer, _) = landed(FIVE, json!({"first": 2, "last": 3, "before": 6}));
    assert_eq!(answer["to_last"], 5, "one past the last line is the text's end");
}

/// A member of the wrong form is refused before any call.
///
/// `doc` is an address in its one spelling; `first` a whole number from 1,
/// and so are `last` and `before` where they are present, a `null` read as
/// absent; then `last` is refused before `first`, and `before` inside the
/// block — past `first`, and at or before `last` — each `malformed_args`
/// naming the member, the forms speaking before the two orders (the mutants
/// that read a number in a string, take line 0, or let a block be set inside
/// itself go on to the read).
#[test]
fn a_member_of_the_wrong_form_is_refused_before_any_call() {
    for (args, what) in [
        (json!({"first": 1}), "doc"),
        (json!({"doc": 7, "first": 1}), "doc"),
        (json!({"doc": "01.0.1", "first": 1}), "doc"),
        (json!({"doc": DOC}), "first"),
        (json!({"doc": DOC, "first": null}), "first"),
        (json!({"doc": DOC, "first": 0}), "first"),
        (json!({"doc": DOC, "first": -1}), "first"),
        (json!({"doc": DOC, "first": 1.5}), "first"),
        (json!({"doc": DOC, "first": "1"}), "first"),
        (json!({"doc": DOC, "first": "1", "last": "2"}), "first"),
        (json!({"doc": DOC, "first": 2, "last": 0}), "last"),
        (json!({"doc": DOC, "first": 2, "last": "3"}), "last"),
        (json!({"doc": DOC, "first": 2, "last": 3.0}), "last"),
        (json!({"doc": DOC, "first": 2, "last": [3], "before": 0}), "last"),
        (json!({"doc": DOC, "first": 2, "before": 0}), "before"),
        (json!({"doc": DOC, "first": 2, "before": "1"}), "before"),
        (json!({"doc": DOC, "first": 3, "last": 2, "before": "x"}), "before"),
        (json!({"doc": DOC, "first": 3, "last": 2}), "last"),
        (json!({"doc": DOC, "first": 3, "last": 2, "before": 3}), "last"),
        (json!({"doc": DOC, "first": 2, "last": 4, "before": 3}), "before"),
        (json!({"doc": DOC, "first": 2, "last": 4, "before": 4}), "before"),
    ] {
        let script = Script::of(Vec::new());
        let refusal = Asked::read(&args).and_then(|asked| move_lines(&script, &asked)).expect_err("a refusal");
        assert_eq!(refusal.to_value(), Refusal::malformed(what).to_value(), "{args}");
        assert!(script.sent_past(0).is_empty());
    }
    assert_eq!(Asked::read(&json!({"doc": DOC, "first": 2, "last": null, "before": null})), Ok(Asked { doc: DOC, first: 2, last: 2, before: None }), "a null is the member absent");
    for (before, read) in [(2, Some(2)), (5, Some(5)), (1, Some(1)), (9, Some(9))] {
        assert_eq!(
            Asked::read(&json!({"doc": DOC, "first": 2, "last": 4, "before": before})),
            Ok(Asked { doc: DOC, first: 2, last: 4, before: read }),
            "{before}: outside the block, its own edges among them"
        );
    }
}

/// A block holding an atom moves whole, and a withheld run marks the rows.
///
/// A value that is no text takes its positions and holds no line break: a
/// line that starts with an atom is cut before the atom, which moves with
/// its line, and a cut before a withheld run stands at the run's first
/// position, never inside it. The rows draw each such value as `{…}`, and
/// `masked` is set where the withheld run stands on a line they show, and
/// left off where it stands past them (the mutants that count an atom's
/// bytes for positions, cut inside the run, or mark every answer read
/// otherwise).
#[test]
fn a_block_holding_an_atom_moves_whole_and_a_withheld_run_marks_the_rows() {
    let withheld = json!({"withheld": {"origin": "1.0.1.0.9", "width": "5"}});
    let items = json!([{"content": "one\n"}, withheld, {"content": "two\nthree\n"}, {"atom": "a long value\n"}, {"content": "four\n"}]);
    let ack = || vec![Ok(json!({"resp": "ack", "at": LANDED_AT}))];
    let (answer, sent) = run(items.clone(), json!({"first": 4, "before": 2}), ack());
    assert_eq!(sent, [frames::rearrange(DOC, &[5, 20, 26], READ_AT, None)], "the withheld run's first position, the atom's, and the end");
    let answer = answer.expect("an answer").into_value();
    crate::shapes::assert_declared("TextMoved", &answer);
    assert_eq!((&answer["lines"], &answer["masked"]), (&said(&[" 1\tone", "+2\t{…}four", " 3\t{…}two", " 4\tthree", "-\t(line 4 moved to 2)"]), &json!(true)), "{answer}");
    let (answer, sent) = run(items, json!({"first": 2, "before": 4}), ack());
    assert_eq!(sent, [frames::rearrange(DOC, &[5, 14, 20], READ_AT, None)], "the run moves with its line");
    assert_eq!(answer.expect("an answer").value["lines"], said(&[" 1\tone", "-\t(line 2 moved to 3)", " 2\tthree", "+3\t{…}two", " 4\t{…}four"]));
    let past = json!([{"content": "a\nb\nc\nd\ne\nf\ng\nh\n"}, withheld, {"content": "z\n"}]);
    let (answer, _) = run(past, json!({"first": 2, "before": 1}), ack());
    let answer = answer.expect("an answer").into_value();
    assert_eq!((&answer["lines"], answer.get("masked")), (&said(&["+1\tb", " 2\ta", "-\t(line 2 moved to 1)", " 3\tc", " 4\td"]), None), "the run stands past every line shown: {answer}");
}

/// The move's one write ends as `text.replace`'s one write ends.
///
/// A draft that changed since the read is refused by the board, the shell
/// holding the line: the call reads the verdict off it, drops it and answers
/// the verdict as data, nothing standing and nothing queued, and so for a
/// draft that is not the session's; a line held with no verdict is dropped
/// too, and the answer is an error with the hold's cause; a drop that finds
/// the write landed is a move that landed, its commit unnamed; a line the
/// shell will not drop is answered `held`, an error naming it and its write;
/// and the `op` row's own refusal of the write is the call's (the mutants
/// that leave the line queued, read a held line as landed, or answer a
/// landing nobody read as refused answer otherwise).
#[test]
fn the_moves_one_write_ends_as_a_text_replaces_one_write_ends() {
    let args = || json!({"first": 3, "before": 2});
    let write = frames::rearrange(DOC, &[3, 6, 10], READ_AT, None);
    let five = || json!([{"content": FIVE}]);
    let stale = moved_verdict("rearrange", READ_AT, 43);
    let foreign = json!({"resp": "rejected", "op": "rearrange", "code": "not_owner", "disposition": "permanent", "site": {"addr": DOC}});
    for (cause, verdict) in [("moved", stale), ("not_owner:the session does not own the document", foreign)] {
        let code = verdict["code"].as_str().expect("a code").to_string();
        let (answer, sent) = run(five(), args(), vec![held_answer(3, cause), lines(3, cause, verdict.clone()), Ok(json!({}))]);
        assert_eq!(sent, [vec![write.clone()], settling(3)].concat(), "the write, then its line read and dropped");
        let answer = answer.expect("an answer");
        crate::shapes::assert_declared("TextRefused", &answer.value);
        assert_eq!(answer, Answer { value: json!({"outcome": "refused", "cause": code, "doc": DOC, "refusal": verdict}), is_error: false });
    }
    let (answer, sent) = run(five(), args(), vec![held_answer(5, "unreachable"), lines(5, "unreachable", Value::Null), Ok(json!({}))]);
    assert_eq!(sent[1..], settling(5)[..]);
    assert_eq!(answer.expect("an answer").into_value(), json!({"outcome": "refused", "cause": "unreachable", "doc": DOC, "error": true}), "no verdict: an error, nothing held");
    let gone = || Err(Refusal::shell(Name::NO_SUCH_HELD, json!({"held": 6})));
    for found in [Ok(json!({"kept": true})), gone()] {
        let (answer, _) = run(five(), args(), vec![held_answer(6, "unreachable"), lines(6, "unreachable", Value::Null), found]);
        let answer = answer.expect("an answer").into_value();
        crate::shapes::assert_declared("TextMoved", &answer);
        assert_eq!(
            (answer["outcome"].as_str(), answer.get("at"), answer["to_first"].as_u64(), answer["lines"][1].as_str()),
            (Some("moved"), None, Some(2), Some("+2\tccc")),
            "landed, its commit unnamed: {answer}"
        );
    }
    let unread = || Err(Refusal::shell(Name::LANDING_UNREAD, json!({"held": 8, "why": "unanswered"})));
    let (answer, sent) = run(five(), args(), vec![held_answer(8, "unreachable"), lines(8, "unreachable", Value::Null), unread()]);
    assert_eq!(sent.len(), 3, "the write and its settling: nothing sent after a line that may land");
    let answer = answer.expect("an answer");
    assert!(answer.is_error, "{}", answer.value);
    let answer = answer.into_value();
    crate::shapes::assert_declared("TextMoveHeld", &answer);
    assert_eq!(answer, json!({"outcome": "held", "doc": DOC, "held": 8, "cause": "unreachable", "write": "rearrange", "error": true}));
    let another = || Refusal::shell(Name::ANOTHER_WINDOW, json!({"op": "rearrange"}));
    let (answer, sent) = run(five(), args(), vec![Err(another())]);
    assert_eq!((answer, sent), (Err(another()), vec![write]), "the row's refusal of the write is the call's");
}

/// A draft's own refusals are answered as `text.replace` reads them.
///
/// A published document is refused at the first read, a draft past the cap
/// before any part of its text is read, and a value whose positions the
/// shell cannot count at the part that holds it: each is data, and nothing
/// is written (SP-8).
#[test]
fn a_drafts_own_refusals_are_answered_as_text_replace_reads_them() {
    let args = json!({"doc": DOC, "first": 2, "before": 1});
    let asked = Asked::read(&args).expect("the members");
    let unpublished = || Ok(json!({"resp": "doc_metadata", "doc": DOC, "published": false}));
    let extent = |positions: u64| Ok(json!({"resp": "span_set", "as_of": READ_AT, "set": [{"start": "1.1", "width": format!("0.{positions}")}]}));
    let cases = [
        (vec![Ok(json!({"resp": "doc_metadata", "doc": "1.0.1.0.7", "published": true}))], json!({"cause": "published", "published": "1.0.1.0.7"})),
        (
            vec![unpublished(), extent(MAX_DRAFT_POSITIONS + 1)],
            json!({"cause": "too_large", "what": "draft", "positions": (MAX_DRAFT_POSITIONS + 1).to_string(), "cap": MAX_DRAFT_POSITIONS.to_string()}),
        ),
        (vec![unpublished(), extent(4), Ok(json!({"resp": "delivery", "as_of": READ_AT, "items": [{"content": "a\nb\n"}, {"later": {}}]}))], json!({"cause": "unknown_item", "kind": "later"})),
    ];
    for (answers, detail) in cases {
        let calls = answers.len();
        let script = Script::of(answers);
        let answer = move_lines(&script, &asked).expect("an answer");
        let mut expected = json!({"outcome": "refused", "doc": DOC});
        expected.as_object_mut().expect("an object").extend(detail.as_object().expect("an object").clone());
        assert_eq!(answer, Answer { value: expected, is_error: false });
        assert_eq!(script.sent_past(0).len(), calls, "the reads alone: no write");
    }
}
