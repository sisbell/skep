//! The unit suite of `text.edit`.
//!
//! It holds the members, the plan made of one read with nothing written,
//! the one frame the call's changes are sent as against a scripted board
//! (the text suite's `Script`) — its net changes in the draft's order, the
//! addresses its acknowledgment names, its two caps — and every answer:
//! landed, unchanged, refused, and an answer lost, settled from the change
//! feed or not. The row itself, its order, the identities a real board
//! keeps and the door it meets run against the daemon in
//! `shell/tests/text.rs`.

use super::super::tests::{died, edit_frame, feed_page, feed_read, less_id, lost, ordinal_of, own_key, read_frames, reads_of, refused_edit, text_of, Rowed, Script, CODE, DOC, READ_AT};
use super::super::{Rows, Under};
use super::*;
use skep_client::halt::Refused;

/// The draft's own content I-address at `ordinal`.
fn own(ordinal: u64) -> String {
    format!("{DOC}.0.1.{ordinal}")
}

/// The last component of the address the scripted frame mints its first
/// byte at.
const FIRST: u64 = 100;

/// The ack of a frame that minted, its first byte at [`FIRST`], committed
/// at `at`.
fn minted(at: u64) -> Result<Value, Refusal> {
    Ok(json!({"resp": "ack_addr", "addr": own(FIRST), "at": at, "committed": true}))
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

/// One change as a pair's list names it.
fn change(ordinal: u64, removed: u64, inserted: u64, addr: Option<u64>, at: Option<u64>) -> Value {
    let mut value = json!({"ordinal": ordinal.to_string(), "removed": removed.to_string(), "inserted": inserted.to_string()});
    if let Some(addr) = addr {
        value["addr"] = Value::from(own(addr));
    }
    if let Some(at) = at {
        value["at"] = Value::from(at);
    }
    value
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
    let asked = Asked::read(&most).expect("one wire list of pairs");
    assert_eq!((asked.pairs.len(), asked.doc()), (MAX_WIRE_LIST, DOC));
    assert_eq!(MAX_WIRE_LIST, 4096);
}

// ── the plan ────────────────────────────────────────────────────────────

/// A later pair's old text is found in the text the pairs before it leave.
///
/// The second pair names text only the first pair's change makes — and is
/// found there, its own change placed past the bytes the first put in, the
/// two sent as one frame in the coordinates of the draft as read; the same
/// two pairs the other way round, a later pair whose text an earlier one
/// took out, and one an earlier pair made stand twice are each refused
/// naming the pair, nothing written (the mutants that seek every pair in
/// the text as read, or write before every pair is checked, answer or send
/// otherwise).
#[test]
fn a_later_pairs_old_text_is_found_in_the_text_the_pairs_before_it_leave() {
    let word = ordinal_of(CODE, "add");
    let (first, second) = (json!({"old": "add(", "new": "sum_up("}), json!({"old": "sum_up(left", "new": "sum_up(first"}));
    let (answer, sent) = edit_of(json!([first, second]), vec![minted(41)]);
    let frame = edit_frame(&[frames::minted(word, 3, "sum_up"), frames::minted(word + 4, 3, "firs")]);
    assert_eq!(sent.iter().map(less_id).collect::<Vec<_>>(), [frame], "`lef` stood four bytes past `add` as read, whatever the first pair wrote before it");
    let pairs = json!([[change(word, 3, 6, Some(FIRST), Some(41))], [change(word + 7, 3, 4, Some(FIRST + 6), Some(41))]]);
    assert_eq!(answer.expect("an answer").value["pairs"], pairs, "the second pair's change seven bytes into the text the first wrote, its bytes minted past the first's six");
    let refused = |edits: Value, detail: Value| {
        let (answer, sent) = edit_of(edits, Vec::new());
        assert!(sent.is_empty(), "the reads alone: no write: {sent:?}");
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
/// position each, and is written at the position it held as read, the frame
/// naming the draft as it stands; a pair whose text would read across the
/// two atoms now standing side by side is refused naming the first (the
/// mutants that keep the emptied stretch, or move no gap, place the second
/// pair elsewhere or find the text across).
#[test]
fn a_pair_that_empties_a_stretch_between_two_atoms_leaves_later_ordinals_right() {
    let reads = || {
        vec![
            Ok(json!({"resp": "doc_metadata", "doc": DOC, "published": false})),
            Ok(json!({"resp": "span_set", "as_of": READ_AT, "set": [{"start": "1.1", "width": "0.10"}]})),
            Ok(json!({"resp": "delivery", "as_of": READ_AT, "items": [{"content": "ab"}, {"atom": "v"}, {"content": "cd"}, {"atom": "w"}, {"content": "efgh"}]})),
        ]
    };
    let (answer, sent) = run([reads(), vec![minted(41)]].concat(), json!([{"old": "cd", "new": ""}, {"old": "gh", "new": "xy"}]));
    assert_eq!(sent[3..].iter().map(less_id).collect::<Vec<_>>(), [edit_frame(&[frames::minted(4, 2, ""), frames::minted(9, 2, "xy")])], "`gh` stood at 9 as read: the frame names it there");
    assert_eq!(answer.expect("an answer").value["pairs"], json!([[change(4, 2, 0, None, Some(41))], [change(7, 2, 2, Some(FIRST), Some(41))]]), "and at 7 in the text the first pair leaves");
    let (answer, sent) = run(reads(), json!([{"old": "cd", "new": ""}, {"old": "bef", "new": "x"}]));
    assert_eq!(sent.len(), 3, "the reads alone");
    assert_eq!(answer.expect("an answer").value, json!({"outcome": "refused", "cause": "crosses_atom", "doc": DOC, "ordinal": "3", "kind": "atom", "as_of": READ_AT, "pair": 1}));
}

/// Pairs that change nothing are found, and nothing is written.
///
/// Every pair's old text must stand once though its new text is the same,
/// and the call then answers `unchanged`; so does a call whose later pair
/// takes out exactly what an earlier one put in, the text left as it was
/// read; one unchanging pair beside a pair that changes the text is an empty
/// list in the answer's pairs, and the rows show the one line the other
/// changed.
#[test]
fn pairs_that_change_nothing_are_found_and_nothing_is_written() {
    let unchanged = Answer { value: json!({"outcome": "unchanged", "doc": DOC, "as_of": READ_AT}), is_error: false };
    let (answer, sent) = edit_of(json!([{"old": "add", "new": "add"}, {"old": "total = ", "new": "total = "}]), Vec::new());
    assert!(sent.is_empty(), "no write: {sent:?}");
    let answer = answer.expect("an answer");
    assert_eq!(answer, unchanged);
    crate::shapes::assert_declared("TextEditUnchanged", &answer.into_value());
    let (answer, sent) = edit_of(json!([{"old": "add(", "new": "addition("}, {"old": "addition(", "new": "add("}]), Vec::new());
    assert_eq!((answer.expect("an answer"), sent.len()), (unchanged, 0), "what the first pair put in, the second took out: nothing to write");
    let (answer, _) = edit_of(json!([{"old": "add", "new": "add"}, {"old": "subtract", "new": "subtract"}]), Vec::new());
    assert_eq!(answer.expect("an answer").value, json!({"outcome": "refused", "cause": "not_found", "doc": DOC, "count": 0, "as_of": READ_AT, "pair": 1}));
    let word = ordinal_of(CODE, "add");
    let (answer, sent) = edit_of(json!([{"old": "add", "new": "add"}, {"old": "add(", "new": "addition("}]), vec![minted(41)]);
    assert_eq!(sent.iter().map(less_id).collect::<Vec<_>>(), [edit_frame(&[frames::minted(word + 3, 0, "ition")])]);
    let shown = [" 1\tfn main() {", "+2\t    let total = addition(left, right);", " 3\t    println!(\"{total}\");", " 4\t}"];
    let whole = json!({"outcome": "edited", "doc": DOC, "pairs": [[], [change(word + 3, 0, 5, Some(FIRST), Some(41))]], "at": 41, "lines": shown});
    assert_eq!(answer.expect("an answer"), Answer { value: whole, is_error: false });
}

/// A call that lands answers its rows, masked where a withheld run numbers
/// them.
///
/// The draft holds a run its reader may not read on the line before the
/// one changed: the change lands as one frame typed against the read, and
/// the answer carries the lines it changed — the withheld run drawn as a
/// value that is no text — and `masked` beside them, declared on `edited`
/// (the mutant that drops the mark answers no `masked`).
#[test]
fn a_call_that_lands_answers_its_rows_masked_where_a_withheld_run_numbers_them() {
    let reads = vec![
        Ok(json!({"resp": "doc_metadata", "doc": DOC, "published": false})),
        Ok(json!({"resp": "span_set", "as_of": READ_AT, "set": [{"start": "1.1", "width": "0.11"}]})),
        Ok(json!({"resp": "delivery", "as_of": READ_AT, "items": [{"content": "a\n"}, {"withheld": {"origin": "1.0.1.0.9", "width": "5"}}, {"content": "b\nc\n"}]})),
    ];
    let (answer, sent) = run([reads, vec![minted(41)]].concat(), json!([{"old": "c", "new": "cc"}]));
    assert_eq!(sent[3..].iter().map(less_id).collect::<Vec<_>>(), [edit_frame(&[frames::minted(11, 0, "c")])], "one change, after the `c`");
    let answer = answer.expect("an answer");
    let expected = json!({"outcome": "edited", "doc": DOC, "pairs": [[change(11, 0, 1, Some(FIRST), Some(41))]], "at": 41, "lines": [" 1\ta", " 2\t{…}b", "+3\tcc"], "masked": true});
    assert_eq!(answer, Answer { value: expected, is_error: false });
    crate::shapes::assert_declared("TextEdited", &answer.into_value());
}

/// A call's new text is held to the frame's cap, all its changes together.
///
/// A pair of two changes whose new texts together fill the cap is sent, one
/// frame; one byte more in the second is refused `too_large` naming the
/// call's new bytes and the cap, nothing written (the mutant that holds each
/// change to the cap by itself sends a frame the board refuses whole).
#[test]
fn a_calls_new_text_is_held_to_the_frames_cap_all_its_changes_together() {
    let old = "one 12345678 two";
    let grown = |last: usize| format!("{} 12345678 {}", "X".repeat(MAX_NEW_BYTES / 2), "Y".repeat(last));
    let reads = || {
        vec![
            Ok(json!({"resp": "doc_metadata", "doc": DOC, "published": false})),
            Ok(json!({"resp": "span_set", "as_of": READ_AT, "set": [{"start": "1.1", "width": format!("0.{}", old.len())}]})),
            Ok(json!({"resp": "delivery", "as_of": READ_AT, "items": [{"content": old}]})),
        ]
    };
    let (answer, sent) = run([reads(), vec![minted(41)]].concat(), json!([{"old": old, "new": grown(MAX_NEW_BYTES / 2)}]));
    let changes = sent[3]["changes"].as_array().expect("the frame's changes");
    assert_eq!((sent.len(), changes.len()), (4, 2), "one frame of two changes");
    assert_eq!(changes.iter().map(|change| change["values"][0].as_str().map_or(0, str::len)).sum::<usize>(), MAX_NEW_BYTES, "the cap's bytes, the two changes together");
    assert_eq!(answer.expect("an answer").value["outcome"], "edited");
    let (answer, sent) = run(reads(), json!([{"old": old, "new": grown(MAX_NEW_BYTES / 2 + 1)}]));
    assert_eq!(sent.len(), 3, "refused of the reads alone");
    assert_eq!(answer.expect("an answer").value, json!({"outcome": "refused", "cause": "too_large", "doc": DOC, "what": "new", "bytes": (MAX_NEW_BYTES + 1).to_string(), "cap": MAX_NEW_BYTES.to_string()}));
    assert_eq!(MAX_NEW_BYTES, 1 << 18, "the board's cap on one edit's values");
}

/// A call of more changes than one frame lists is refused before any write.
///
/// Each pair is made as two changes, a kept stretch between them: 2,048
/// pairs are 4,096 changes, one frame; one pair more is refused `too_large`
/// naming the changes and the cap, nothing written.
#[test]
fn a_call_of_more_changes_than_one_frame_lists_is_refused_before_any_write() {
    let line = |k: usize, upper: bool| if upper { format!("A{k:05} 12345678 B{k:05}\n") } else { format!("a{k:05} 12345678 b{k:05}\n") };
    let call = |pairs: usize, after: Vec<Result<Value, Refusal>>| {
        let text: String = (0..pairs).map(|k| line(k, false)).collect();
        let reads = vec![
            Ok(json!({"resp": "doc_metadata", "doc": DOC, "published": false})),
            Ok(json!({"resp": "span_set", "as_of": READ_AT, "set": [{"start": "1.1", "width": format!("0.{}", text.len())}]})),
            Ok(json!({"resp": "delivery", "as_of": READ_AT, "items": [{"content": text}]})),
        ];
        let edits: Vec<Value> = (0..pairs).map(|k| json!({"old": line(k, false), "new": line(k, true)})).collect();
        run([reads, after].concat(), Value::Array(edits))
    };
    let (answer, sent) = call(MAX_WIRE_LIST / 2, vec![minted(41)]);
    assert_eq!(sent[3]["changes"].as_array().map(Vec::len), Some(MAX_WIRE_LIST), "the premise: two changes a pair, one frame's list of them");
    assert_eq!(answer.expect("an answer").value["outcome"], "edited");
    let (answer, sent) = call(MAX_WIRE_LIST / 2 + 1, Vec::new());
    assert_eq!(sent.len(), 3, "refused of the reads alone");
    assert_eq!(answer.expect("an answer").value, json!({"outcome": "refused", "cause": "too_large", "doc": DOC, "what": "changes", "changes": (MAX_WIRE_LIST + 2).to_string(), "cap": MAX_WIRE_LIST.to_string()}));
}

// ── the one frame ───────────────────────────────────────────────────────

/// Several pairs are one frame, its changes in the draft's order.
///
/// One pair's old text spans a word replaced, a word lengthened and a
/// stretch taken out: three changes, the text between them in no change; a
/// pair that stands before them in the draft and one after are asked after
/// it. The call sends ONE frame typed against the read, with no read and no
/// write beside it: five changes ascending in the draft as read, whatever
/// order the pairs came in. The answer lists each pair's changes in the
/// pairs' order, each ordinal a place in the text as the changes planned
/// before it leave it, and every one at the one commit; the rows show the
/// lines they changed (the mutants that make a pair as one stretch, send a
/// frame a change, or send the changes in the pairs' order send other
/// frames).
#[test]
fn several_pairs_are_one_frame_its_changes_in_the_drafts_order() {
    let old = "    let total = add(left, right);\n    println!(\"{total}\");\n";
    let new = "    let sum = add(left, right_side);\n    println!(\"\");\n";
    let edits = json!([{"old": old, "new": new}, {"old": "main", "new": "start"}, {"old": "}\n", "new": "}\n// end\n"}]);
    let (answer, sent) = edit_of(edits, vec![minted(41)]);
    let (lines, main, end) = (ordinal_of(CODE, old), ordinal_of(CODE, "main"), ordinal_of(CODE, "}\n"));
    let frame = edit_frame(&[
        frames::minted(main, 4, "start"),
        frames::minted(ordinal_of(CODE, "total"), 5, "sum"),
        frames::minted(ordinal_of(CODE, "right") + 5, 0, "_side"),
        frames::minted(ordinal_of(CODE, "{total}"), 7, ""),
        frames::minted(CODE.len() as u64 + 1, 0, "// end\n"),
    ]);
    assert_eq!(sent.iter().map(less_id).collect::<Vec<_>>(), [frame], "one frame, nothing read or written beside it");
    // The frame mints `start`, `sum`, `_side` and the last line, in that
    // order, from the first address on.
    let pairs = json!([
        [change(lines + 8, 5, 3, Some(FIRST + 5), Some(41)), change(lines + 29, 0, 5, Some(FIRST + 8), Some(41)), change(lines + 51, 7, 0, None, Some(41))],
        [change(main, 4, 5, Some(FIRST), Some(41))],
        [change(end - 1, 0, 7, Some(FIRST + 13), Some(41))],
    ]);
    let shown = ["+1\tfn start() {", "+2\t    let sum = add(left, right_side);", "+3\t    println!(\"\");", " 4\t}", "+5\t// end"];
    let answer = answer.expect("an answer");
    assert_eq!(answer, Answer { value: json!({"outcome": "edited", "doc": DOC, "pairs": pairs, "at": 41, "lines": shown}), is_error: false });
    let value = answer.into_value();
    crate::shapes::assert_declared("TextEdited", &value);
    for change in value["pairs"].as_array().expect("pairs").iter().flat_map(|pair| pair.as_array().expect("a pair's changes")) {
        crate::shapes::assert_declared("TextEditChange", change);
    }
}

/// Each change's address is taken in the frame's order, not the pairs'.
///
/// The first pair changes the draft's last line and the second its first:
/// the frame carries the second pair's change first, the draft's order, and
/// the board mints its bytes first, so the second pair's address is the
/// acknowledgment's and the first pair's stands past the second's bytes
/// (the mutant that hands the addresses out in the pairs' order names the
/// first pair's bytes at the address the board gave the second's).
#[test]
fn each_changes_address_is_taken_in_the_frames_order_not_the_pairs() {
    let (late, early) = (json!({"old": "println", "new": "eprintln"}), json!({"old": "main", "new": "start"}));
    let (print, main) = (ordinal_of(CODE, "println"), ordinal_of(CODE, "main"));
    let (answer, sent) = edit_of(json!([late, early]), vec![minted(41)]);
    assert_eq!(sent.iter().map(less_id).collect::<Vec<_>>(), [edit_frame(&[frames::minted(main, 4, "start"), frames::minted(print, 0, "e")])], "the draft's order");
    let pairs = json!([[change(print, 0, 1, Some(FIRST + 5), Some(41))], [change(main, 4, 5, Some(FIRST), Some(41))]]);
    assert_eq!(answer.expect("an answer").value["pairs"], pairs, "the second pair's five bytes minted first, the first pair's one after them");
}

/// A pair over an earlier pair's new text mints only what stands.
///
/// The first pair lengthens a word and the second replaces the lengthened
/// word whole: the frame is one change, the word as read removed and the
/// second pair's text minted — never the first pair's bytes minted and then
/// removed — and its removal names only positions the draft held as read.
/// The first pair's change is answered with no address, none of its bytes
/// standing. A later pair that writes between two of an earlier pair's bytes
/// leaves that change no one address either, and the frame mints the one
/// stretch that stands (the mutants that send each pair's changes unmerged
/// remove bytes the frame itself mints, which the board refuses, or mint
/// them twice).
#[test]
fn a_pair_over_an_earlier_pairs_new_text_mints_only_what_stands() {
    let word = ordinal_of(CODE, "add");
    let (answer, sent) = edit_of(json!([{"old": "add(", "new": "addition("}, {"old": "addition(", "new": "plus("}]), vec![minted(41)]);
    assert_eq!(sent.iter().map(less_id).collect::<Vec<_>>(), [edit_frame(&[frames::minted(word, 3, "plus")])], "three positions as read removed, four bytes minted: none of `ition`");
    let pairs = json!([[change(word + 3, 0, 5, None, Some(41))], [change(word, 8, 4, Some(FIRST), Some(41))]]);
    assert_eq!(answer.expect("an answer").value["pairs"], pairs, "the first pair's bytes stand nowhere, and are named at no address");
    let (answer, sent) = edit_of(json!([{"old": "add(", "new": "add_all_of_them("}, {"old": "all_of_them", "new": "all_the_rest_of_them"}]), vec![minted(41)]);
    let frame = less_id(&sent[0]);
    assert_eq!((sent.len(), frame["changes"].as_array().map(Vec::len)), (1, Some(1)), "one frame of one change: {frame}");
    assert_eq!((&frame["changes"][0]["at"], &frame["changes"][0]["width"], &frame["changes"][0]["values"]), (&frames::place(word + 3), &json!("0"), &json!(["_all_the_rest_of_them"])), "the one stretch that stands");
    let listed = answer.expect("an answer").value["pairs"].clone();
    assert_eq!(listed[0][0].get("addr"), None, "the first pair's bytes stand in two parts, the second's between them: {listed}");
    assert!(listed[1][0]["addr"].is_string(), "the second pair's stand whole: {listed}");
}

/// New bytes that are no text go as hex, a value a byte.
#[test]
fn new_bytes_that_are_no_text_go_as_hex() {
    let text = text_of(json!([{"content": "ab"}, {"hex": "c328"}, {"content": "cd"}]));
    let cut = Net { at: 3, width: 1, new: 3..5 };
    assert_eq!(cut.frame(&text), json!({"at": frames::place(3), "width": "1", "values": [{"hex": "c328"}]}));
    let whole = Net { at: 1, width: 0, new: 5..7 };
    assert_eq!(whole.frame(&text), frames::minted(1, 0, "cd"));
    assert_eq!((cut.minted(), whole.minted()), (2, 2));
}

// ── the answers ─────────────────────────────────────────────────────────

/// A frame the board refuses is the call's refusal, nothing written.
///
/// The board refuses the one frame as typed against an older state, another
/// writer's change having landed since the read, or for any other cause: the
/// answer is `refused`, data, the board's code its cause and the verdict
/// under `refusal`; nothing of the call stands, so nothing is read or
/// written after it. The shell's own refusal of the frame is the call's.
#[test]
fn a_frame_the_board_refuses_is_the_calls_refusal_nothing_written() {
    let edits = || json!([{"old": "add(", "new": "addition("}, {"old": "total = ", "new": ""}]);
    for code in ["arrangement_moved", "not_owner"] {
        let refusal = refused_edit(code);
        let Refusal::Board(Refused { body: verdict, .. }) = refusal.clone() else { unreachable!() };
        let (answer, sent) = edit_of(edits(), vec![Err(refusal)]);
        assert_eq!(sent.len(), 1, "{code}: the one frame");
        let answer = answer.expect("an answer");
        assert_eq!(answer, Answer { value: json!({"outcome": "refused", "cause": code, "doc": DOC, "refusal": verdict}), is_error: false }, "{code}");
        crate::shapes::assert_declared("TextRefused", &answer.into_value());
    }
    let held_lines = || Refusal::shell(crate::refusal::Name::HELD_LINES, json!({"doc": DOC, "held": 1}));
    let (outcome, sent) = edit_of(edits(), vec![Err(held_lines())]);
    assert_eq!((outcome.expect_err("the refusal").to_value(), sent.len()), (held_lines().to_value(), 1));
}

/// A lost answer is asked again, then read off the change feed.
///
/// The frame's answer is lost: the same frame is asked again once, and its
/// acknowledgment there is the call's, addresses and all. Where the re-ask
/// is refused as typed against an older state, the draft's first row past
/// the read is read: the call's own `edit` under the session's key answers
/// `edited` at that row's position, every change at it and none with an
/// address, the rows drawn as for any landing; another writer's row leaves
/// the call `answer_lost`, an error naming the read's position, nothing sent
/// after it.
#[test]
fn a_lost_answer_is_asked_again_then_read_off_the_change_feed() {
    let edits = || json!([{"old": "add(", "new": "addition("}, {"old": "total = ", "new": ""}]);
    let (word, total) = (ordinal_of(CODE, "add"), ordinal_of(CODE, "total"));
    let frame = edit_frame(&[frames::minted(total, 8, ""), frames::minted(word + 3, 0, "ition")]);
    let (answer, sent) = edit_of(edits(), vec![Err(lost()), minted(44)]);
    assert_eq!((sent.len(), sent[0] == sent[1], less_id(&sent[0])), (2, true, frame.clone()), "the same frame, asked again once");
    assert_eq!(answer.expect("an answer").value["pairs"], json!([[change(word + 3, 0, 5, Some(FIRST), Some(44))], [change(total, 8, 0, None, Some(44))]]));
    let (answer, sent) = edit_of(edits(), vec![Err(lost()), Err(refused_edit("arrangement_moved")), feed_page("edit", &own_key(), 47)]);
    assert_eq!((sent.len(), &sent[2]), (3, &feed_read(DOC, READ_AT)));
    let shown = [" 1\tfn main() {", "+2\t    let addition(left, right);", " 3\t    println!(\"{total}\");", " 4\t}"];
    let landed = json!({"outcome": "edited", "doc": DOC, "pairs": [[change(word + 3, 0, 5, None, Some(47))], [change(total, 8, 0, None, Some(47))]], "at": 47, "lines": shown});
    let answer = answer.expect("an answer");
    assert_eq!(answer, Answer { value: landed, is_error: false }, "landed at its own row's position, no address named");
    crate::shapes::assert_declared("TextEdited", &answer.into_value());
    let (answer, sent) = edit_of(edits(), vec![Err(lost()), Err(refused_edit("arrangement_moved")), feed_page("edit", &"cd".repeat(32), 47)]);
    assert_eq!(sent.len(), 3, "nothing sent after the read");
    let answer = answer.expect("an answer");
    assert_eq!(answer, Answer { value: json!({"outcome": "answer_lost", "doc": DOC, "as_of": READ_AT, "cause": "unreachable", "refusal": lost().to_value()}), is_error: true });
    crate::shapes::assert_declared("TextAnswerLost", &answer.into_value());
}

/// A frame that meets the session's death is made again under the re-open.
///
/// The frame's dial meets the death, which executed nothing: it is made once
/// more under the session the restart arm re-opened, the same frame, and
/// lands there as one no death met.
#[test]
fn a_frame_that_meets_the_sessions_death_is_made_again_under_the_re_open() {
    let rows = Rowed::of([reads_of(CODE), vec![died(Some("s-2")), minted(44)]].concat(), vec!["s-2"]);
    let args = json!({"doc": DOC, "edits": [{"old": "add(", "new": "addition("}]});
    let asked = Asked::read(&args).expect("the members");
    let answer = edit(&Under::new(&rows, "s-1"), &asked).expect("an answer");
    assert_eq!((&answer.value["outcome"], &answer.value["at"]), (&json!("edited"), &json!(44)), "{}", answer.value);
    assert_eq!(rows.sessions(), ["s-1", "s-1", "s-1", "s-1", "s-2"], "the frame made again under the re-open");
    assert!(rows.stands("s-2") && !rows.stands("s-1"));
}
