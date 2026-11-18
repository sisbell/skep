//! The unit suite of `text.edit`.
//!
//! It holds the members, the plan made of one read with nothing written,
//! the writes chained by position against a scripted board (the text
//! suite's `Script`), the take-back and every answer that names what
//! stands. The row itself, its order, the identities a real board keeps and
//! a take-back landed on one run against the daemon in
//! `shell/tests/text.rs`.

use skep_client::halt::Refused;
use skep_client::DialError;

use super::super::tests::{died, held_answer, image_frame, lines, moved_verdict, ordinal_of, read_frames, reads_of, settling, text_of, Rowed, Script, CODE, DOC, READ_AT};
use super::super::{Rows, Under};
use super::*;
use crate::refusal::Name;

/// The draft's own content I-address at `ordinal`.
fn own(ordinal: u64) -> String {
    format!("{DOC}.0.1.{ordinal}")
}

/// The address the scripted insert `k` mints its first byte at.
fn minted(k: u64) -> String {
    own(100 * k)
}

/// The ack of the scripted insert `k`, committed at `at`.
fn inserted(k: u64, at: u64) -> Result<Value, Refusal> {
    Ok(json!({"resp": "ack_addr", "addr": minted(k), "at": at}))
}

/// The ack of a removal committed at `at`.
fn removed(at: u64) -> Result<Value, Refusal> {
    Ok(json!({"resp": "ack", "at": at}))
}

/// The image the scripted call reads before its first write.
///
/// [`CODE`] in two runs: forty bytes of the draft's own, and the rest
/// windowed from version 2 of another document.
fn image() -> Result<Value, Refusal> {
    Ok(json!({"resp": "runs", "as_of": READ_AT + 3, "runs": [{"i_start": own(1), "width": "40"}, {"i_start": "1.0.1.0.9.2.0.1.7", "width": (CODE.len() - 40).to_string()}]}))
}

/// The take-back of [`image`], typed against `at`.
///
/// Each run names its origin by the client's rule, a version's bytes their
/// document.
fn take_back(at: u64) -> Value {
    let runs = [frames::shot_run(DOC, &own(1), 40), frames::shot_run("1.0.1.0.9", "1.0.1.0.9.2.0.1.7", CODE.len() as u64 - 40)];
    frames::set_arrangement(DOC, &runs, at, None, None, None, None)
}

/// An image an undo reads.
///
/// It holds `width` bytes minted at `addr` standing from `ordinal`, read at
/// `as_of`.
fn image_holding(addr: &str, width: u64, ordinal: u64, as_of: u64) -> Result<Value, Refusal> {
    Ok(
        json!({"resp": "runs", "as_of": as_of, "runs": [{"i_start": own(1), "width": (ordinal - 1).to_string()}, {"i_start": addr, "width": width.to_string()}, {"i_start": own(ordinal), "width": "9"}]}),
    )
}

/// Returns the call's outcome, and every call made.
///
/// The board answers `answers`, in order.
fn run(answers: Vec<Result<Value, Refusal>>, edits: Value) -> (Result<Answer, Refusal>, Vec<Value>) {
    let script = Script::of(answers);
    let args = json!({"doc": DOC, "edits": edits});
    let outcome = Asked::read(&args).and_then(|asked| edit(&script, &asked));
    (outcome, script.sent_past(0))
}

/// Returns the call's outcome over [`CODE`], and the calls past its reads.
///
/// The board answers `after` past the three reads of [`CODE`].
fn edit_of(edits: Value, after: Vec<Result<Value, Refusal>>) -> (Result<Answer, Refusal>, Vec<Value>) {
    let (outcome, sent) = run(reads_of(CODE).into_iter().chain(after).collect(), edits);
    assert_eq!(sent[..3], read_frames(CODE)[..], "the three reads, in order");
    (outcome, sent[3..].to_vec())
}

/// A change that stands whole, as `stands` names it.
fn standing(pair: u64, change: u64, ordinal: u64, removed: u64, inserted: u64, addr: Option<String>, at: Option<u64>) -> Value {
    let mut value = json!({"pair": pair, "change": change, "ordinal": ordinal.to_string(), "removed": removed.to_string(), "inserted": inserted.to_string()});
    if let Some(addr) = addr {
        value["addr"] = Value::from(addr);
    }
    if let Some(at) = at {
        value["at"] = Value::from(at);
    }
    value
}

/// Holds an error answer to its declared shape.
///
/// Each change of its `stands` is held to its own, and the answer is
/// returned as the row answers it.
fn declared(shape: &str, answer: Answer) -> Value {
    assert!(answer.is_error, "{}", answer.value);
    let value = answer.into_value();
    crate::shapes::assert_declared(shape, &value);
    for stands in value["stands"].as_array().expect("the changes that stand") {
        crate::shapes::assert_declared(if stands.get("new_text").is_some() { "TextEditHalf" } else { "TextEditStanding" }, stands);
    }
    value
}

/// The two pairs most cells send: an insert, then a removal before it.
///
/// `add(` reads `addition(`, five bytes inserted, and `total = ` goes, eight
/// bytes removed: one write each, the second after the first landed.
fn two_writes() -> Value {
    json!([{"old": "add(", "new": "addition("}, {"old": "total = ", "new": ""}])
}

/// The two writes of [`two_writes`].
///
/// The insert is typed against the read, the removal against the insert's
/// commit, 41.
fn two_frames() -> Vec<Value> {
    vec![frames::insert_text(DOC, ordinal_of(CODE, "add") + 3, "ition", READ_AT, None), frames::delete(DOC, ordinal_of(CODE, "total"), 8, 41, None)]
}

/// The insert of [`two_writes`] as it stands, landed at 41.
fn first_stands() -> Value {
    standing(0, 0, ordinal_of(CODE, "add") + 3, 0, 5, Some(minted(1)), Some(41))
}

/// The two pairs of the cells on a change in part.
///
/// They are an insert, then a replacement after it: `add(` reads
/// `addition(`, and `left` reads `first`: `lef` gives way to
/// `firs`, two writes, at an ordinal the first pair moved by five.
fn in_part() -> Value {
    json!([{"old": "add(", "new": "addition("}, {"old": "left", "new": "first"}])
}

/// The ordinal `left` stands at once [`in_part`]'s first pair landed.
fn left() -> u64 {
    ordinal_of(CODE, "left") + 5
}

/// The three writes of [`in_part`], the commits 41 and 42 between them.
fn in_part_frames() -> Vec<Value> {
    vec![frames::insert_text(DOC, ordinal_of(CODE, "add") + 3, "ition", READ_AT, None), frames::insert_text(DOC, left() + 3, "firs", 41, None), frames::delete(DOC, left(), 3, 42, None)]
}

/// The replacement of [`in_part`] standing in part.
///
/// Its new bytes are placed, with `acked` the address and the commit its
/// insert named, and its old ones are not removed.
fn half_stands(acked: bool) -> Value {
    let mut new_text = json!({"ordinal": (left() + 3).to_string(), "width": "4"});
    if acked {
        new_text["addr"] = Value::from(minted(2));
        new_text["at"] = Value::from(42);
    }
    json!({"pair": 1, "change": 0, "new_text": new_text, "old_text": {"ordinal": left().to_string(), "width": "3"}})
}

// ── the members ─────────────────────────────────────────────────────────

/// A member of the wrong form is refused before any call, by its index.
///
/// `doc` is read first, then the list, then each pair in order, its `old`
/// before its `new`: the first member not of its form is named, a pair's by
/// its index in `edits`; a list of one wire list's pairs is read, and one
/// more is refused (the mutants that read `new` first, name the list for a
/// pair, or admit a longer list answer otherwise).
#[test]
fn a_member_of_the_wrong_form_is_refused_before_any_call_by_its_index() {
    let pair = json!({"old": "a", "new": "b"});
    for (args, what) in [
        (json!({"edits": [pair]}), "doc"),
        (json!({"doc": "1..2", "edits": [pair]}), "doc"),
        (json!({"doc": 7, "edits": []}), "doc"),
        (json!({"doc": DOC}), "edits"),
        (json!({"doc": DOC, "edits": pair}), "edits"),
        (json!({"doc": DOC, "edits": []}), "edits"),
        (json!({"doc": DOC, "edits": vec![pair.clone(); MAX_WIRE_LIST + 1]}), "edits"),
        (json!({"doc": DOC, "edits": [pair, "a"]}), "edits[1]"),
        (json!({"doc": DOC, "edits": [pair, {"new": "b"}]}), "edits[1].old"),
        (json!({"doc": DOC, "edits": [pair, {"old": "", "new": "b"}]}), "edits[1].old"),
        (json!({"doc": DOC, "edits": [{"old": 7, "new": "b"}]}), "edits[0].old"),
        (json!({"doc": DOC, "edits": [pair, pair, {"old": "a"}]}), "edits[2].new"),
        (json!({"doc": DOC, "edits": [{"old": "a", "new": null}]}), "edits[0].new"),
        (json!({"doc": DOC, "edits": [{"old": "", "new": 7}, "x"]}), "edits[0].old"),
        (json!({"doc": DOC, "edits": [pair, {"old": "a", "new": 7}, 3]}), "edits[1].new"),
    ] {
        let script = Script::of(Vec::new());
        let refusal = Asked::read(&args).and_then(|asked| edit(&script, &asked)).expect_err("a refusal");
        assert_eq!(refusal.to_value(), Refusal::malformed(what).to_value(), "{}", args["edits"].to_string().chars().take(80).collect::<String>());
        assert!(script.sent_past(0).is_empty());
    }
    let most = json!({"doc": DOC, "edits": vec![pair; MAX_WIRE_LIST]});
    assert_eq!(Asked::read(&most).expect("one wire list of pairs").pairs.len(), MAX_WIRE_LIST);
    assert_eq!(MAX_WIRE_LIST, 4096);
}

// ── the plan ────────────────────────────────────────────────────────────

/// A later pair's old text is found in the text the pairs before it leave.
///
/// The second pair names text only the first pair's landing makes — and is
/// found there, its change placed past the bytes the first put in; the same
/// two pairs the other way round, a later pair whose text an earlier one
/// took out, and one an earlier pair made stand twice are each refused
/// naming the pair, the image never read and nothing written (the mutants
/// that seek every pair in the text as read, or write before every pair is
/// checked, answer or send otherwise).
#[test]
fn a_later_pairs_old_text_is_found_in_the_text_the_pairs_before_it_leave() {
    let word = ordinal_of(CODE, "add");
    let (first, second) = (json!({"old": "add(", "new": "sum_up("}), json!({"old": "sum_up(left", "new": "sum_up(first"}));
    let (answer, sent) = edit_of(json!([first, second]), vec![image(), inserted(1, 41), removed(42), inserted(2, 43), removed(44)]);
    let expected = [
        image_frame(),
        frames::insert_text(DOC, word + 3, "sum_up", READ_AT, None),
        frames::delete(DOC, word, 3, 41, None),
        frames::insert_text(DOC, word + 7 + 3, "firs", 42, None),
        frames::delete(DOC, word + 7, 3, 43, None),
    ];
    assert_eq!(sent, expected, "`lef` stands seven bytes into the text the first pair wrote");
    assert_eq!(answer.expect("an answer").value["outcome"], "edited");
    let refused = |edits: Value, detail: Value| {
        let (answer, sent) = edit_of(edits, Vec::new());
        assert!(sent.is_empty(), "the reads alone: no image, no write: {sent:?}");
        let mut expected = json!({"outcome": "refused", "doc": DOC, "as_of": READ_AT});
        expected.as_object_mut().expect("an object").extend(detail.as_object().expect("an object").clone());
        let answer = answer.expect("an answer");
        assert_eq!(answer, Answer { value: expected, is_error: false });
        crate::shapes::assert_declared("TextRefused", &answer.into_value());
    };
    refused(json!([second, first]), json!({"cause": "not_found", "count": 0, "pair": 0}));
    refused(json!([{"old": "add", "new": "sub"}, {"old": "add(", "new": "x("}]), json!({"cause": "not_found", "count": 0, "pair": 1}));
    refused(json!([{"old": "left", "new": "right"}, {"old": "right", "new": "other"}]), json!({"cause": "not_unique", "count": 2, "pair": 1}));
    refused(json!([{"old": "add", "new": "sub"}, {"old": "total", "new": "sum"}, {"old": "left", "new": "l"}]), json!({"cause": "not_unique", "count": 2, "pair": 1}));
}

/// A pair that empties a stretch leaves later ordinals right.
///
/// The first pair takes out the whole text between two atoms; the second
/// pair's text is then found two positions lower, the atoms still one
/// position each, and a pair whose text would read across the two atoms now
/// standing side by side is refused naming the first (the mutants that keep
/// the emptied stretch, or move no gap, place the second pair elsewhere or
/// find the text across).
#[test]
fn a_pair_that_empties_a_stretch_between_two_atoms_leaves_later_ordinals_right() {
    let reads = || {
        vec![
            Ok(json!({"resp": "doc_metadata", "doc": DOC, "published": false})),
            Ok(json!({"resp": "span_set", "as_of": READ_AT, "set": [{"start": "1.1", "width": "0.10"}]})),
            Ok(json!({"resp": "delivery", "as_of": READ_AT, "items": [{"content": "ab"}, {"atom": "v"}, {"content": "cd"}, {"atom": "w"}, {"content": "efgh"}]})),
        ]
    };
    let whole = Ok(json!({"resp": "runs", "as_of": READ_AT, "runs": [{"i_start": own(1), "width": "10"}]}));
    let (answer, sent) = run([reads(), vec![whole, removed(41), inserted(1, 42), removed(43)]].concat(), json!([{"old": "cd", "new": ""}, {"old": "gh", "new": "xy"}]));
    assert_eq!(sent[4..], [frames::delete(DOC, 4, 2, READ_AT, None), frames::insert_text(DOC, 9, "xy", 41, None), frames::delete(DOC, 7, 2, 42, None)], "`gh` stood at 9, and stands at 7");
    assert_eq!(
        answer.expect("an answer").value["pairs"],
        json!([[{"ordinal": "4", "removed": "2", "inserted": "0", "at": 41}], [{"ordinal": "7", "removed": "2", "inserted": "2", "addr": minted(1), "at": 43}]])
    );
    let (answer, sent) = run(reads(), json!([{"old": "cd", "new": ""}, {"old": "bef", "new": "x"}]));
    assert_eq!(sent.len(), 3, "the reads alone");
    assert_eq!(answer.expect("an answer").value, json!({"outcome": "refused", "cause": "crosses_atom", "doc": DOC, "ordinal": "3", "kind": "atom", "as_of": READ_AT, "pair": 1}));
}

/// Pairs that change nothing are found, and nothing is written.
///
/// Every pair's old text must stand once though its new text is the same,
/// and the call then answers `unchanged` with no image read; one such pair
/// beside a pair that changes the text is an empty list in the answer's
/// pairs.
#[test]
fn pairs_that_change_nothing_are_found_and_nothing_is_written() {
    let (answer, sent) = edit_of(json!([{"old": "add", "new": "add"}, {"old": "total = ", "new": "total = "}]), Vec::new());
    assert!(sent.is_empty(), "no image and no write: {sent:?}");
    let answer = answer.expect("an answer");
    assert_eq!(answer, Answer { value: json!({"outcome": "unchanged", "doc": DOC, "as_of": READ_AT}), is_error: false });
    crate::shapes::assert_declared("TextEditUnchanged", &answer.into_value());
    let (answer, _) = edit_of(json!([{"old": "add", "new": "add"}, {"old": "subtract", "new": "subtract"}]), Vec::new());
    assert_eq!(answer.expect("an answer").value, json!({"outcome": "refused", "cause": "not_found", "doc": DOC, "count": 0, "as_of": READ_AT, "pair": 1}));
    let (answer, sent) = edit_of(json!([{"old": "add", "new": "add"}, {"old": "add(", "new": "addition("}]), vec![image(), inserted(1, 41)]);
    assert_eq!(sent[1..], two_frames()[..1]);
    let whole =
        json!({"outcome": "edited", "doc": DOC, "pairs": [[], [{"ordinal": (ordinal_of(CODE, "add") + 3).to_string(), "removed": "0", "inserted": "5", "addr": minted(1), "at": 41}]], "at": 41});
    assert_eq!(answer.expect("an answer"), Answer { value: whole, is_error: false });
}

/// Each change's new text is held to one insert's cap, by itself.
///
/// A pair of two changes whose new texts each fill the cap is planned, the
/// two together past it; one byte more in the second is refused naming the
/// pair and that change, the image never read.
#[test]
fn each_changes_new_text_is_held_to_one_inserts_cap_by_itself() {
    let old = "one 12345678 two";
    let grown = |last: usize| format!("{} 12345678 {}", "X".repeat(MAX_NEW_BYTES), "Y".repeat(last));
    let planned = |new: &str| {
        plan(DOC, &mut text_of(json!([{"content": old}])), READ_AT, &[Pair { old, new }])
            .map(|plan| plan.iter().map(|planned| (planned.change, planned.edit.ordinal, planned.edit.removed, planned.edit.inserted.len())).collect::<Vec<_>>())
    };
    assert_eq!(planned(&grown(MAX_NEW_BYTES)), Ok(vec![(0, 1, 3, MAX_NEW_BYTES), (1, MAX_NEW_BYTES as u64 + 11, 3, MAX_NEW_BYTES)]));
    let refused = planned(&grown(MAX_NEW_BYTES + 1)).expect_err("the second change is past the cap");
    assert_eq!(
        refused.value,
        json!({"outcome": "refused", "cause": "too_large", "doc": DOC, "what": "new", "bytes": (MAX_NEW_BYTES + 1).to_string(), "cap": MAX_NEW_BYTES.to_string(), "pair": 0, "change": 1})
    );
    let (answer, sent) = edit_of(json!([{"old": "add", "new": "add"}, {"old": "fn", "new": format!("fn{}", "x".repeat(MAX_NEW_BYTES + 1))}]), Vec::new());
    assert!(sent.is_empty(), "refused of the reads alone");
    assert_eq!((answer.expect("an answer").value["pair"].as_u64(), MAX_NEW_BYTES), (Some(1), 1 << 18));
}

// ── the writes ──────────────────────────────────────────────────────────

/// Several changes land, each write typed against the commit before it.
///
/// One pair's old text spans a word replaced, a word lengthened and a
/// stretch taken out: three changes, the text between them in no write; a
/// pair before them and one after land behind them, each ordinal moved by
/// the changes already made. The first write carries the read's position
/// and each later one the commit of the write before it, with no read
/// between; the answer lists each pair's changes (the mutants that make a
/// pair as one stretch, type every write against the read, or leave an
/// ordinal where the read found it send other frames).
#[test]
fn three_changes_of_one_pair_and_two_more_pairs_land_each_typed_against_the_commit_before_it() {
    let old = "    let total = add(left, right);\n    println!(\"{total}\");\n";
    let new = "    let sum = add(left, right_side);\n    println!(\"\");\n";
    let edits = json!([{"old": old, "new": new}, {"old": "main", "new": "start"}, {"old": "}\n", "new": "}\n// end\n"}]);
    let acks = vec![image(), inserted(1, 41), removed(42), inserted(2, 43), removed(44), inserted(3, 45), removed(46), inserted(4, 47)];
    let (answer, sent) = edit_of(edits, acks);
    let (lines, main, end) = (ordinal_of(CODE, old), ordinal_of(CODE, "main"), ordinal_of(CODE, "}\n"));
    let expected = [
        image_frame(),
        frames::insert_text(DOC, lines + 8 + 5, "sum", READ_AT, None),
        frames::delete(DOC, lines + 8, 5, 41, None),
        frames::insert_text(DOC, lines + 29, "_side", 42, None),
        frames::delete(DOC, lines + 51, 7, 43, None),
        frames::insert_text(DOC, main + 4, "start", 44, None),
        frames::delete(DOC, main, 4, 45, None),
        frames::insert_text(DOC, end - 4 + 1 + 2, "// end\n", 46, None),
    ];
    assert_eq!(sent, expected);
    let pairs = json!([
        [
            {"ordinal": (lines + 8).to_string(), "removed": "5", "inserted": "3", "addr": minted(1), "at": 42},
            {"ordinal": (lines + 29).to_string(), "removed": "0", "inserted": "5", "addr": minted(2), "at": 43},
            {"ordinal": (lines + 51).to_string(), "removed": "7", "inserted": "0", "at": 44},
        ],
        [{"ordinal": main.to_string(), "removed": "4", "inserted": "5", "addr": minted(3), "at": 46}],
        [{"ordinal": (end - 1).to_string(), "removed": "0", "inserted": "7", "addr": minted(4), "at": 47}],
    ]);
    let answer = answer.expect("an answer");
    assert_eq!(answer, Answer { value: json!({"outcome": "edited", "doc": DOC, "pairs": pairs, "at": 47}), is_error: false });
    let value = answer.into_value();
    crate::shapes::assert_declared("TextEdited", &value);
    for change in value["pairs"].as_array().expect("pairs").iter().flat_map(|pair| pair.as_array().expect("a pair's changes")) {
        crate::shapes::assert_declared("TextEditChange", change);
    }
}

/// A first write that does not land leaves nothing to take back.
///
/// Refused by the row, the refusal is the call's; its line dropped, the
/// answer is `refused` with the verdict, or with the hold's cause and the
/// error member where the board gave none, naming the change — and no
/// `set_arrangement` follows either: the draft is as the call found it.
#[test]
fn a_first_write_that_does_not_land_leaves_nothing_and_nothing_is_taken_back() {
    let refusal = || Refusal::shell(Name::ANOTHER_WINDOW, json!({"op": "insert"}));
    let (outcome, sent) = edit_of(two_writes(), vec![image(), Err(refusal())]);
    assert_eq!(sent, [image_frame(), two_frames()[0].clone()], "the image, the insert, and nothing after it");
    assert_eq!(outcome.expect_err("the row's refusal").to_value(), refusal().to_value());
    let verdict = moved_verdict("insert", READ_AT, 43);
    let (answer, sent) = edit_of(two_writes(), vec![image(), held_answer(3, "moved"), lines(3, "moved", verdict.clone()), Ok(json!({}))]);
    assert_eq!(sent[2..], settling(3)[..], "its line read and dropped: no other write");
    assert_eq!(answer.expect("an answer"), Answer { value: json!({"outcome": "refused", "cause": "arrangement_moved", "doc": DOC, "refusal": verdict, "pair": 0, "change": 0}), is_error: false });
    let (answer, sent) = edit_of(two_writes(), vec![image(), held_answer(3, "halted"), lines(3, "halted", Value::Null), Ok(json!({}))]);
    assert_eq!(sent.len(), 4);
    let answer = answer.expect("an answer");
    assert_eq!(answer, Answer { value: json!({"outcome": "refused", "cause": "halted", "doc": DOC, "pair": 0, "change": 0}), is_error: true });
    crate::shapes::assert_declared("TextRefused", &answer.into_value());
}

// ── all or nothing ──────────────────────────────────────────────────────

/// A write past the first that does not land has the draft set back.
///
/// The second write's line is dropped with no verdict, or with a verdict
/// other than a moved draft's, or the row refuses the write outright: each
/// is answered by exactly one `set_arrangement` of the image read before
/// the first write — its runs with their origins — typed against the first
/// write's commit, and the call answers what stopped the write, nothing
/// standing (the mutants that take nothing back, type the take-back against
/// the read or a fresh one, or send another write after it send otherwise).
#[test]
fn a_write_past_the_first_that_does_not_land_has_the_draft_set_back_as_it_stood() {
    let landed = || Ok(json!({"resp": "ack", "at": 43}));
    let opening = [vec![image_frame()], two_frames()].concat();
    let (answer, sent) = edit_of(two_writes(), vec![image(), inserted(1, 41), held_answer(5, "halted"), lines(5, "halted", Value::Null), Ok(json!({})), landed()]);
    assert_eq!(sent, [opening.clone(), settling(5), vec![take_back(41)]].concat(), "the removal's line settled, then the one take-back");
    assert_eq!(answer.expect("an answer"), Answer { value: json!({"outcome": "refused", "cause": "halted", "doc": DOC, "pair": 1, "change": 0}), is_error: true });
    let verdict = json!({"resp": "rejected", "op": "delete", "code": "not_owner", "disposition": "permanent", "site": {"addr": DOC}});
    let (answer, sent) = edit_of(two_writes(), vec![image(), inserted(1, 41), held_answer(5, "not_owner:x"), lines(5, "not_owner:x", verdict.clone()), Ok(json!({})), landed()]);
    assert_eq!(sent.last(), Some(&take_back(41)));
    assert_eq!(answer.expect("an answer"), Answer { value: json!({"outcome": "refused", "cause": "not_owner", "doc": DOC, "refusal": verdict, "pair": 1, "change": 0}), is_error: false });
    let refusal = || Refusal::shell(Name::ANOTHER_WINDOW, json!({"op": "delete"}));
    let (outcome, sent) = edit_of(two_writes(), vec![image(), inserted(1, 41), Err(refusal()), landed()]);
    assert_eq!(sent, [opening, vec![take_back(41)]].concat());
    assert_eq!(outcome.expect_err("the row's refusal").to_value(), refusal().to_value());
    assert_eq!(take_back(41)["runs"], json!([{"origin": DOC, "i_start": own(1), "width": "40"}, {"origin": "1.0.1.0.9", "i_start": "1.0.1.0.9.2.0.1.7", "width": "33"}]));
    assert_eq!((take_back(41)["as_of"].as_u64(), take_back(41).get("head"), take_back(41).get("base"), take_back(41).get("merge")), (Some(41), None, None, None));
}

/// Another writer's change is never taken back over.
///
/// The board refuses the second write as typed against an older state:
/// another writer's change landed after the first. No `set_arrangement` is
/// sent, and the answer is `partial`, naming the change that stands by its
/// address and commit; a moved line whose verdict could not be read is
/// taken the same way. And where the take-back itself is refused as typed
/// against an older state it is not sent again, the answer naming what
/// stands and the take-back's refusal (the mutants that take back over a
/// moved draft, or type the take-back afresh, send a `set_arrangement`
/// more).
#[test]
fn another_writers_change_is_never_taken_back_over() {
    let verdict = moved_verdict("delete", 41, 44);
    let (answer, sent) = edit_of(two_writes(), vec![image(), inserted(1, 41), held_answer(5, "moved"), lines(5, "moved", verdict.clone()), Ok(json!({}))]);
    assert_eq!(sent, [vec![image_frame()], two_frames(), settling(5)].concat(), "no take-back");
    let stands = json!({"outcome": "partial", "doc": DOC, "pair": 1, "change": 0, "stands": [first_stands()], "cause": "arrangement_moved", "refusal": verdict, "error": true});
    assert_eq!(declared("TextEditPartial", answer.expect("an answer")), stands);
    let unlisted = Err(Refusal::shell(Name::STORE_HALTED, json!({"why": "damaged"})));
    let (answer, sent) = edit_of(two_writes(), vec![image(), inserted(1, 41), held_answer(5, "moved"), unlisted, Ok(json!({}))]);
    assert_eq!(sent.len(), 5, "no take-back over a moved draft whose verdict was not read");
    assert_eq!(declared("TextEditPartial", answer.expect("an answer")), json!({"outcome": "partial", "doc": DOC, "pair": 1, "change": 0, "stands": [first_stands()], "cause": "moved", "error": true}));
    let moved = || Refusal::Board(Refused { status: 200, code: "arrangement_moved".into(), detail: None, op: Some("set_arrangement".into()), body: moved_verdict("set_arrangement", 41, 44) });
    let (answer, sent) = edit_of(two_writes(), vec![image(), inserted(1, 41), held_answer(5, "halted"), lines(5, "halted", Value::Null), Ok(json!({})), Err(moved())]);
    assert_eq!(sent.iter().filter(|frame| frame["op"] == "set_arrangement").count(), 1, "sent once, never typed afresh");
    assert_eq!(sent.last(), Some(&take_back(41)), "and nothing after it");
    let expected = json!({
        "outcome": "partial", "doc": DOC, "pair": 1, "change": 0, "stands": [first_stands()], "cause": "halted",
        "take_back": {"cause": "arrangement_moved", "refusal": moved().to_value()}, "error": true,
    });
    assert_eq!(declared("TextEditPartial", answer.expect("an answer")), expected);
}

/// A take-back that does not land names what stands, and what may.
///
/// Refused by the shell under a standing hold, or by the board, the
/// take-back's refusal rides the answer beside each change that stands;
/// where its answer was lost — no answer once the request left, the board's
/// handler panicked, its write path poisoned — the take-back may have
/// landed, and the changes are named as ones that may stand.
#[test]
fn a_take_back_that_does_not_land_names_what_stands_and_what_may() {
    let refused_run = || {
        Refusal::Board(Refused {
            status: 200,
            code: "withheld".into(),
            detail: None,
            op: Some("set_arrangement".into()),
            body: json!({"resp": "rejected", "code": "withheld", "disposition": "permanent"}),
        })
    };
    let poisoned = || {
        Refusal::Board(Refused { status: 200, code: "poisoned".into(), detail: None, op: Some("set_arrangement".into()), body: json!({"resp": "rejected", "code": "poisoned", "disposition": "halt"}) })
    };
    let cases: Vec<(Refusal, bool)> = vec![
        (Refusal::shell(Name::STOPPED, json!({"op": "set_arrangement"})), false),
        (Refusal::shell(Name::POISONED, json!({"op": "set_arrangement"})), false),
        (Refusal::shell(Name::HALTED, json!({"op": "set_arrangement"})), false),
        (refused_run(), false),
        (Refusal::Unreachable(DialError::Connect("refused".into())), false),
        (Refusal::Unreachable(DialError::Timeout("no answer".into())), true),
        (Refusal::board(500, json!({"error": "internal_panic"})), true),
        (poisoned(), true),
    ];
    for (refusal, lost) in cases {
        let refusal_of_the_write = || Refusal::shell(Name::ANOTHER_WINDOW, json!({"op": "delete"}));
        let (answer, sent) = edit_of(two_writes(), vec![image(), inserted(1, 41), Err(refusal_of_the_write()), Err(refusal.clone())]);
        assert_eq!(sent, [vec![image_frame()], two_frames(), vec![take_back(41)]].concat(), "{refusal}");
        let mut expected = json!({
            "outcome": "partial", "doc": DOC, "pair": 1, "change": 0, "stands": [first_stands()],
            "cause": "another_window", "refusal": refusal_of_the_write().to_value(),
            "take_back": {"cause": refusal.name(), "refusal": refusal.to_value()}, "error": true,
        });
        if lost {
            expected["may_stand"] = json!(true);
        }
        assert_eq!(declared("TextEditPartial", answer.expect("an answer")), expected, "{refusal}");
    }
}

/// A write that landed with no commit read ends the call there.
///
/// An insert's ack that names no commit, and a line whose drop finds its
/// write landed, leave nothing to type the next write against: no write
/// follows and nothing is taken back, and the answer is `partial`, naming
/// the write and each change that stands, that one among them. On the
/// call's last write the same is the call landed whole, that change's
/// commit unnamed (the mutants that go on from the read's position, or take
/// back with no commit to type against, send a write more).
#[test]
fn a_write_that_landed_with_no_commit_read_ends_the_call_there() {
    let word = ordinal_of(CODE, "add");
    let (answer, sent) = edit_of(two_writes(), vec![image(), Ok(json!({"resp": "ack_addr", "addr": minted(1)}))]);
    assert_eq!(sent.len(), 2, "the image and the insert: nothing after it");
    let unread = json!({"outcome": "partial", "doc": DOC, "pair": 0, "change": 0, "stands": [standing(0, 0, word + 3, 0, 5, Some(minted(1)), None)], "cause": "unread", "op": "insert", "error": true});
    assert_eq!(declared("TextEditPartial", answer.expect("an answer")), unread);
    let (answer, sent) = edit_of(two_writes(), vec![image(), held_answer(6, "unreachable"), lines(6, "unreachable", Value::Null), Ok(json!({"kept": true}))]);
    assert_eq!(sent.len(), 4, "the insert and its settling: nothing after it");
    let lost = json!({"outcome": "partial", "doc": DOC, "pair": 0, "change": 0, "stands": [standing(0, 0, word + 3, 0, 5, None, None)], "cause": "answer_lost", "op": "insert", "error": true});
    assert_eq!(declared("TextEditPartial", answer.expect("an answer")), lost);
    let whole = |second: Value| json!({"outcome": "edited", "doc": DOC, "pairs": [[{"ordinal": (word + 3).to_string(), "removed": "0", "inserted": "5", "addr": minted(1), "at": 41}], [second]]});
    let unnamed = json!({"ordinal": ordinal_of(CODE, "total").to_string(), "removed": "8", "inserted": "0"});
    for last in [vec![Ok(json!({"resp": "ack"}))], vec![held_answer(6, "unreachable"), lines(6, "unreachable", Value::Null), Ok(json!({"kept": true}))]] {
        let (answer, sent) = edit_of(two_writes(), [vec![image(), inserted(1, 41)], last].concat());
        assert!(sent.iter().all(|frame| frame["op"] != "set_arrangement"), "nothing taken back");
        assert_eq!(answer.expect("an answer"), Answer { value: whole(unnamed.clone()), is_error: false }, "the last write: landed whole, no commit named");
    }
    // The insert of a change of two writes: its bytes stand beside the old
    // ones, which no removal can be typed for.
    let (answer, sent) = edit_of(in_part(), vec![image(), inserted(1, 41), Ok(json!({"resp": "ack", "at": 42}))]);
    assert_eq!(sent.len(), 3, "an ack naming no address: the removal is not sent");
    let stands = json!({"outcome": "partial", "doc": DOC, "pair": 1, "change": 0, "stands": [first_stands(), half_stands(false)], "cause": "unread", "op": "insert", "error": true});
    assert_eq!(declared("TextEditPartial", answer.expect("an answer")), stands);
}

/// A change in part is taken back by identity, or named with both spans.
///
/// A replacement's new bytes landed and the board refused the removal of
/// its old ones over another writer's change: nothing is taken back whole,
/// and the new bytes are removed by identity where the image shows them —
/// the answer then names the changes before it alone. Where that removal
/// cannot be made, the change is named with both its spans; and where the
/// replacement is the call's only write and its undo lands, nothing stands
/// and the answer is the removal's verdict.
#[test]
fn a_change_in_part_is_taken_back_by_identity_or_named_with_both_spans() {
    let verdict = moved_verdict("delete", 42, 44);
    let moved = || vec![held_answer(4, "moved"), lines(4, "moved", verdict.clone()), Ok(json!({}))];
    let opening = || [vec![image(), inserted(1, 41), inserted(2, 42)], moved()].concat();
    let undone = vec![image_holding(&minted(2), 4, left() + 9, 50), removed(51)];
    let (answer, sent) = edit_of(in_part(), [opening(), undone].concat());
    let expected = [vec![image_frame()], in_part_frames(), settling(4), vec![image_frame(), frames::delete(DOC, left() + 9, 4, 50, None)]].concat();
    assert_eq!(sent, expected, "the new bytes removed where the other writer's change moved them, typed against that read");
    let partial = |stands: Value| json!({"outcome": "partial", "doc": DOC, "pair": 1, "change": 0, "stands": stands, "cause": "arrangement_moved", "refusal": verdict, "error": true});
    assert_eq!(declared("TextEditPartial", answer.expect("an answer")), partial(json!([first_stands()])));
    let too_large = Err(Refusal::Board(Refused { status: 200, code: "image_too_large".into(), detail: None, op: Some("image".into()), body: json!({"resp": "rejected", "code": "image_too_large"}) }));
    let (answer, _) = edit_of(in_part(), [opening(), vec![too_large]].concat());
    assert_eq!(declared("TextEditPartial", answer.expect("an answer")), partial(json!([first_stands(), half_stands(true)])), "the undo not made: both spans");
    // The replacement alone: its insert the one landed write.
    let word = ordinal_of(CODE, "add");
    let alone = json!([{"old": "add", "new": "subtract"}]);
    let verdict = moved_verdict("delete", 41, 44);
    let (answer, sent) =
        edit_of(alone.clone(), vec![image(), inserted(1, 41), held_answer(4, "moved"), lines(4, "moved", verdict.clone()), Ok(json!({})), image_holding(&minted(1), 8, word + 3, 50), removed(51)]);
    assert_eq!(sent.last(), Some(&frames::delete(DOC, word + 3, 8, 50, None)));
    assert_eq!(
        answer.expect("an answer"),
        Answer { value: json!({"outcome": "refused", "cause": "arrangement_moved", "doc": DOC, "refusal": verdict, "pair": 0, "change": 0}), is_error: false },
        "nothing stands: the verdict"
    );
    // Its removal refused for the board's own cause: the draft set back.
    let (answer, sent) = edit_of(alone.clone(), vec![image(), inserted(1, 41), held_answer(4, "halted"), lines(4, "halted", Value::Null), Ok(json!({})), removed(43)]);
    assert_eq!(sent.last(), Some(&take_back(41)), "the insert's commit is the last landed write's");
    assert_eq!(answer.expect("an answer").value, json!({"outcome": "refused", "cause": "halted", "doc": DOC, "pair": 0, "change": 0}));
    // The take-back refused, the undo held by the same stop and dropped: the
    // change stands in part, and the take-back's refusal is told.
    let stopped = || Refusal::shell(Name::STOPPED, json!({"op": "set_arrangement"}));
    let after = vec![
        image(),
        inserted(1, 41),
        held_answer(4, "halted"),
        lines(4, "halted", Value::Null),
        Ok(json!({})),
        Err(stopped()),
        image_holding(&minted(1), 8, word + 3, 50),
        held_answer(5, "stopped"),
        lines(5, "stopped", Value::Null),
        Ok(json!({})),
    ];
    let (answer, sent) = edit_of(alone, after);
    assert_eq!(sent[5..7], [take_back(41), image_frame()], "the take-back once, then the undo by identity");
    let value = declared("TextEditPartial", answer.expect("an answer"));
    let both = json!({"pair": 0, "change": 0, "new_text": {"ordinal": (word + 3).to_string(), "width": "8", "addr": minted(1), "at": 41}, "old_text": {"ordinal": word.to_string(), "width": "3"}});
    assert_eq!((&value["stands"], &value["cause"], &value["take_back"]["cause"], value.get("may_stand")), (&json!([both]), &json!("halted"), &json!("stopped"), None), "{value}");
}

/// A line the shell will not drop is answered `held`.
///
/// The shell refuses a drop where it cannot tell whether the write landed:
/// the line stands, no write follows it and no `set_arrangement` is sent
/// while it does, and the answer names the line, the write it is and each
/// change that stands — the change the line is of by its two spans where it
/// is of two writes, and an undo's line as `undo` (the mutant that takes
/// back beside a line that may land sets the draft back under it).
#[test]
fn a_line_the_shell_will_not_drop_is_answered_held_and_nothing_is_taken_back() {
    let unread = |held: u64| Err(Refusal::shell(Name::LANDING_UNREAD, json!({"held": held, "why": "unanswered"})));
    let standing_line = |held: u64| vec![held_answer(held, "unreachable"), lines(held, "unreachable", Value::Null), unread(held)];
    let held =
        |write: &str, pair: u64, stands: Value| json!({"outcome": "held", "doc": DOC, "held": 8, "cause": "unreachable", "write": write, "pair": pair, "change": 0, "stands": stands, "error": true});
    let (answer, sent) = edit_of(two_writes(), [vec![image()], standing_line(8)].concat());
    assert_eq!(sent.len(), 4, "the first write's line stands: nothing after it");
    assert_eq!(declared("TextEditHeld", answer.expect("an answer")), held("insert", 0, json!([])));
    let (answer, sent) = edit_of(two_writes(), [vec![image(), inserted(1, 41)], standing_line(8)].concat());
    assert_eq!(sent, [vec![image_frame()], two_frames(), settling(8)].concat(), "no take-back while the removal may land");
    assert_eq!(declared("TextEditHeld", answer.expect("an answer")), held("delete", 1, json!([first_stands()])));
    let (answer, sent) = edit_of(in_part(), [vec![image(), inserted(1, 41)], standing_line(8)].concat());
    assert_eq!(sent.len(), 5, "the removal is not sent behind an insert that may not have landed");
    assert_eq!(declared("TextEditHeld", answer.expect("an answer")), held("insert", 1, json!([first_stands(), half_stands(false)])));
    let (answer, sent) = edit_of(in_part(), [vec![image(), inserted(1, 41), inserted(2, 42)], standing_line(8)].concat());
    assert_eq!(sent, [vec![image_frame()], in_part_frames(), settling(8)].concat(), "no take-back and no undo while the removal may land");
    assert_eq!(declared("TextEditHeld", answer.expect("an answer")), held("delete", 1, json!([first_stands(), half_stands(true)])));
    let verdict = moved_verdict("delete", 42, 44);
    let undo_held =
        [vec![image(), inserted(1, 41), inserted(2, 42), held_answer(4, "moved"), lines(4, "moved", verdict), Ok(json!({})), image_holding(&minted(2), 4, left() + 3, 50)], standing_line(8)].concat();
    let (answer, sent) = edit_of(in_part(), undo_held);
    assert_eq!(sent[sent.len() - 3..], [vec![frames::delete(DOC, left() + 3, 4, 50, None)], settling(8)].concat()[..], "the undo's removal and its line: no write after it");
    assert_eq!(declared("TextEditHeld", answer.expect("an answer")), held("undo", 1, json!([first_stands(), half_stands(true)])));
    let write = crate::shapes::shape("TextEditHeld").and_then(|shape| shape.fields.iter().find(|field| field.name == "write")).map(|field| field.ty);
    assert_eq!(write, Some("'insert' | 'delete' | 'undo'"), "the shapes declare every write a held line of the call's may be");
}

/// An image the call cannot send back or read is refused first.
///
/// A draft in more runs than one `set_arrangement` names could not be set
/// back: the call is refused `too_large` naming the runs, where the board
/// says so or the image holds one run past the cap, and an image that lists
/// no runs, a run that does not read and an address that names no origin
/// are `unread`, an error — each with the image the last call made (the
/// mutants that write first, or take an unread image for an empty draft's,
/// send the insert).
#[test]
fn an_image_past_one_write_or_one_the_shell_does_not_read_is_refused_before_any_write() {
    let runs_of = |count: usize| Ok(json!({"resp": "runs", "as_of": READ_AT, "runs": (0..count).map(|k| json!({"i_start": own(2 * k as u64 + 1), "width": "1"})).collect::<Vec<_>>()}));
    let refused = |image: Result<Value, Refusal>| {
        let (answer, sent) = edit_of(two_writes(), vec![image]);
        assert_eq!(sent, [image_frame()], "the image, and no write");
        answer.expect("an answer")
    };
    let cap = MAX_WIRE_LIST.to_string();
    assert_eq!(
        refused(runs_of(MAX_WIRE_LIST + 1)),
        Answer { value: json!({"outcome": "refused", "cause": "too_large", "doc": DOC, "what": "runs", "runs": (MAX_WIRE_LIST + 1).to_string(), "cap": cap}), is_error: false }
    );
    let too_large = Err(Refusal::Board(Refused { status: 200, code: "image_too_large".into(), detail: None, op: Some("image".into()), body: json!({"resp": "rejected", "code": "image_too_large"}) }));
    assert_eq!(refused(too_large), Answer { value: json!({"outcome": "refused", "cause": "too_large", "doc": DOC, "what": "runs", "cap": cap}), is_error: false });
    let unread = Answer { value: json!({"outcome": "refused", "cause": "unread", "doc": DOC, "op": "image"}), is_error: true };
    for image in [
        json!({"resp": "runs", "as_of": READ_AT}),
        json!({"resp": "runs", "runs": [{"i_start": own(1)}]}),
        json!({"resp": "runs", "runs": [{"width": "3"}]}),
        json!({"resp": "runs", "runs": [{"i_start": "1.0.1.0.64", "width": "3"}]}),
    ] {
        assert_eq!(refused(Ok(image.clone())), unread, "{image}");
    }
    let (answer, sent) = edit_of(two_writes(), vec![runs_of(MAX_WIRE_LIST), inserted(1, 41), removed(42)]);
    assert_eq!((answer.expect("an answer").value["outcome"].as_str(), sent.len()), (Some("edited"), 3), "one wire list of runs is written over");
    let withheld = || Refusal::Board(Refused { status: 200, code: "withheld".into(), detail: None, op: Some("image".into()), body: json!({"resp": "rejected", "code": "withheld"}) });
    let (outcome, sent) = edit_of(two_writes(), vec![Err(withheld())]);
    assert_eq!((outcome.expect_err("the read's refusal").to_value(), sent.len()), (withheld().to_value(), 1), "any other refusal of the read is the call's");
}

// ── the session ─────────────────────────────────────────────────────────

/// A take-back that meets a death is made again under the re-open.
///
/// The death executed nothing, so the one take-back is the one the re-open
/// carries: it lands, and the call answers the refusal that stopped it.
#[test]
fn a_take_back_that_meets_a_death_the_restart_arm_re_opened_is_made_under_the_re_open() {
    let refusal = || Refusal::shell(Name::ANOTHER_WINDOW, json!({"op": "delete"}));
    let rows = Rowed::of([reads_of(CODE), vec![image(), inserted(1, 41), Err(refusal()), died(Some("s-2")), removed(43)]].concat(), vec!["s-2"]);
    let args = json!({"doc": DOC, "edits": two_writes()});
    let under = Under::new(&rows, "s-1");
    assert!(rows.stands("s-2"));
    let outcome = edit(&under, &Asked::read(&args).expect("the members"));
    assert_eq!(outcome.expect_err("the row's refusal").to_value(), refusal().to_value());
    assert_eq!(rows.sessions()[6..], ["s-1", "s-2"], "the take-back, then the same take-back under the re-open");
}
