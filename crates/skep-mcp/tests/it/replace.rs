//! `replace_text`, `edit_text` and `move_lines`, end to end on a real board.
//!
//! A draft holding a few lines of code text is edited through the built
//! adapter, and the board is read back by identity: a one-word change mints
//! that word's bytes and no other, a link on an unchanged word of the edited
//! line still projects onto its word, and an edit that does not land leaves
//! the draft as it was — refused before any write where a read decides it,
//! and, where another writer's change commits at the wrong moment, with the
//! draft exactly as that writer left it and no line of the edit's held. An
//! edit is one frame and one commit, removal and insert together, and is
//! refused behind a held line of the agent's on its draft. The
//! other writer is staged, never raced: the adapter dials the board through
//! `common`'s relay, whose rule lands a second session's write between two
//! exchanges of one tool call. Two pairs in one `edit_text` call land with
//! the text between them at its own addresses, the answer's rows after it,
//! each changed line where the board's own `line_numbers` numbers it. A line
//! moved by `move_lines` mints nothing: every byte stands at the address it
//! had, and a link made on the line before the move projects onto it where
//! it now stands. A draft put back to an earlier state by `restore_text`
//! holds its old bytes at their own addresses again, a link on a word an
//! edit took out projecting onto that word, nothing minted, and the way back
//! the answer names brings the edits back. The measurement at the foot is
//! run by hand.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::common::{draft_of, stage_of, Fixture, Launch, Mcp, Passed, AGENT_SPACE, CLAIMANT_ACCOUNT};

/// The code text the suite's drafts hold: each word an edit names stands
/// once in it.
const CODE: &str = "fn main() {\n    let total = add(left, right);\n    println!(\"{total}\");\n}\n";

/// The second line of [`CODE`], whole: the context an agent quotes around a
/// one-word change.
const LINE: &str = "    let total = add(left, right);\n";

/// The most bytes of new text one edit inserts, as skep-shell's
/// `MAX_NEW_BYTES` states it.
const MAX_NEW_BYTES: usize = 1 << 18;

/// The positions one read of a draft's text asks, as skep-shell's text edit
/// has it: the board's delivery budget.
const READ_POSITIONS: usize = 1 << 17;

/// Returns the content ordinal at which `word` begins in `text`.
fn ordinal_of(text: &str, word: &str) -> usize {
    text.find(word).unwrap_or_else(|| panic!("`{word}` stands in the text")) + 1
}

/// Returns a fresh draft of `account` holding `text`, typed in by `insert`.
fn draft_holding(mcp: &mut Mcp, account: &str, text: &str) -> String {
    let doc = draft_of(mcp, account);
    let typed = mcp.position();
    mcp.acked("insert", json!({"as_of": typed, "doc": doc, "at": {"subspace": "1", "ordinal": "1"}, "values": [text]}));
    doc
}

/// Returns how many content positions `doc` arranges.
fn extent_of(mcp: &mut Mcp, doc: &str) -> usize {
    let set = mcp.call_json("retrieve_doc_v_span_set", json!({"doc": doc}));
    let spans = set["set"].as_array().unwrap_or_else(|| panic!("a span set: {set}"));
    spans
        .iter()
        .find(|span| span["start"] == "1.1")
        .map_or(0, |span| span["width"].as_str().and_then(|width| width.rsplit('.').next()).and_then(|n| n.parse().ok()).unwrap_or_else(|| panic!("a content width: {set}")))
}

/// Returns the delivery items of `width` content positions of `doc` from
/// ordinal `from`.
fn items_of(mcp: &mut Mcp, doc: &str, from: usize, width: usize) -> Value {
    mcp.call_json("retrieve_v", json!({"specs": [{"doc": doc, "span": {"start": format!("1.{from}"), "width": format!("0.{width}")}}]}))["items"].clone()
}

/// Returns `doc`'s whole content, which is one run of text.
fn text_of(mcp: &mut Mcp, doc: &str) -> String {
    let extent = extent_of(mcp, doc);
    if extent == 0 {
        return String::new();
    }
    let items = items_of(mcp, doc, 1, extent);
    assert_eq!(items.as_array().map(Vec::len), Some(1), "one run of text: {items}");
    items[0]["content"].as_str().unwrap_or_else(|| panic!("a run of text: {items}")).to_string()
}

/// Returns the I-address at each content position of `doc`, in order.
fn addresses(mcp: &mut Mcp, doc: &str) -> Vec<String> {
    let extent = extent_of(mcp, doc);
    let image = mcp.call_json("image", json!({"d": doc, "region": [{"start": "1.1", "width": format!("0.{}", extent.max(1))}]}));
    let mut addresses = Vec::new();
    for run in image["runs"].as_array().unwrap_or_else(|| panic!("an image: {image}")) {
        let (prefix, first) = run["i_start"].as_str().and_then(|start| start.rsplit_once('.')).unwrap_or_else(|| panic!("a run: {run}"));
        let (first, width): (u64, u64) = (first.parse().expect("an ordinal"), run["width"].as_str().and_then(|width| width.parse().ok()).expect("a width"));
        addresses.extend((first..first + width).map(|n| format!("{prefix}.{n}")));
    }
    assert_eq!(addresses.len(), extent, "the image covers the extent: {image}");
    addresses
}

/// Returns the address `n` positions past the I-address `addr`.
fn address_past(addr: &str, n: u64) -> String {
    let (prefix, first) = addr.rsplit_once('.').expect("an I-address");
    format!("{prefix}.{}", first.parse::<u64>().expect("an ordinal") + n)
}

/// Returns how many content values `doc` has minted.
fn minted(mcp: &mut Mcp, doc: &str) -> u64 {
    mcp.call_json("content_frontier", json!({"doc": doc}))["next"].as_str().and_then(|next| next.parse::<u64>().ok()).expect("the frontier") - 1
}

/// Calls `replace_text`, answering whether the result is `isError` and its
/// text as JSON.
fn replace(mcp: &mut Mcp, doc: &str, old: &str, new: &str) -> (bool, Value) {
    let (is_error, text) = mcp.call("replace_text", json!({"doc": doc, "old": old, "new": new}));
    (is_error, serde_json::from_str(&text).unwrap_or_else(|e| panic!("replace_text's text is JSON ({e}): {text}")))
}

/// Calls `replace_text` where the edit lands: its `replaced` answer.
fn replaced(mcp: &mut Mcp, doc: &str, old: &str, new: &str) -> Value {
    let (is_error, answer) = replace(mcp, doc, old, new);
    assert!(!is_error && answer["outcome"] == "replaced", "the edit lands: {answer}\n{}", mcp.log());
    answer
}

/// Calls `edit_text`, answering whether the result is `isError`, its first
/// line as JSON, and each line after it, a row of the changed lines.
fn edit(mcp: &mut Mcp, doc: &str, edits: Value) -> (bool, Value, Vec<String>) {
    let (is_error, text) = mcp.call("edit_text", json!({"doc": doc, "edits": edits}));
    let (first, rows) = text.split_once('\n').unwrap_or((&text, ""));
    let answer = serde_json::from_str(first).unwrap_or_else(|e| panic!("edit_text's first line is JSON ({e}): {text}"));
    (is_error, answer, rows.split('\n').filter(|row| !row.is_empty()).map(str::to_string).collect())
}

/// Calls `move_lines`, and reads its result as [`edit`] reads `edit_text`'s.
///
/// It answers whether the result is `isError`, its first line as JSON, and
/// each line after it, a row.
fn move_lines(mcp: &mut Mcp, args: Value) -> (bool, Value, Vec<String>) {
    let (is_error, text) = mcp.call("move_lines", args);
    let (first, rows) = text.split_once('\n').unwrap_or((&text, ""));
    let answer = serde_json::from_str(first).unwrap_or_else(|e| panic!("move_lines' first line is JSON ({e}): {text}"));
    (is_error, answer, rows.split('\n').filter(|row| !row.is_empty()).map(str::to_string).collect())
}

/// Waits until the adapter's own index has read the board through its head.
///
/// The shell's feed thread reads a draft again after each commit to it, by
/// the same frames an edit reads it by; a rule that waits for the edit's
/// read is armed only once that thread has nothing left to read.
fn settle_the_index(mcp: &mut Mcp) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let head = mcp.position();
        let state = mcp.call_json("places", json!({}))["state"].clone();
        if state["arm"] == "complete" && state["as_of"].as_u64().is_some_and(|as_of| as_of >= head) {
            return;
        }
        assert!(Instant::now() < deadline, "the index never read through the head {head}: {state}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// A link homed in `doc` from `word`'s positions in `text`: its address.
fn link_on(mcp: &mut Mcp, doc: &str, text: &str, word: &str) -> String {
    let from = json!([{"source": doc, "span": {"start": format!("1.{}", ordinal_of(text, word)), "width": format!("0.{}", word.len())}}]);
    mcp.acked("make_link", json!({"home": doc, "from_": from, "to": {"addrs": [doc]}, "ty": {"addrs": [format!("{doc}.0.3.6.1")]}}))["addr"].as_str().expect("the link's address").to_string()
}

/// The text `link`'s FROM end projects onto in `doc` now: each span the
/// projection answers, read back, in order.
fn projected(mcp: &mut Mcp, link: &str, doc: &str) -> Vec<String> {
    let set = mcp.call_json("project", json!({"a": link, "slot": 1, "d": doc}));
    let spans = set["set"].as_array().unwrap_or_else(|| panic!("a projection: {set}")).clone();
    spans
        .iter()
        .map(|span| mcp.call_json("retrieve_v", json!({"specs": [{"doc": doc, "span": span}]}))["items"][0]["content"].as_str().unwrap_or_else(|| panic!("text under {span}")).to_string())
        .collect()
}

/// A one-word change replaces only that word.
///
/// The agent quotes the whole line around the word; the answer names the
/// word's own position and widths; and the draft's image shows it: every
/// other position holds the I-address it held before, and the three new
/// positions hold three addresses the draft had not minted, from the one the
/// answer names (the mutant that leaves the context untrimmed re-mints the
/// whole line: thirty-four addresses new, not three). The answer's `at` is
/// the draft's typed state: a raw burst typed against it lands.
#[test]
fn a_one_word_change_replaces_only_that_word() {
    let fixture = Fixture::new("replace-word");
    let mut mcp = Launch::over(&fixture, 1).spawn();
    mcp.initialize();
    let doc = draft_holding(&mut mcp, CLAIMANT_ACCOUNT, CODE);
    let before = addresses(&mut mcp, &doc);
    let answer = replaced(&mut mcp, &doc, LINE, &LINE.replace("add", "sub"));
    let word = ordinal_of(CODE, "add");
    assert_eq!((&answer["doc"], &answer["ordinal"], &answer["removed"], &answer["inserted"]), (&json!(doc), &json!(word.to_string()), &json!("3"), &json!("3")), "the word alone: {answer}");
    let addr = answer["addr"].as_str().expect("the first new I-address").to_string();
    assert_eq!(text_of(&mut mcp, &doc), CODE.replace("add", "sub"));
    let after = addresses(&mut mcp, &doc);
    assert_eq!(after.len(), before.len(), "three bytes for three");
    for (k, (was, is)) in before.iter().zip(&after).enumerate() {
        match (k + 1).checked_sub(word).filter(|offset| *offset < 3) {
            Some(offset) => {
                assert_eq!(*is, address_past(&addr, offset as u64), "position {} holds the new word's byte {offset}", k + 1);
                assert!(!before.contains(is), "the new word's bytes are new: {is}");
            }
            None => assert_eq!(is, was, "position {} keeps its identity", k + 1),
        }
    }
    assert_eq!(minted(&mut mcp, &doc), CODE.len() as u64 + 3, "three values minted, and no more");
    let at = answer["at"].as_u64().expect("the edit's commit");
    mcp.acked("delete", json!({"as_of": at, "doc": doc, "p": {"subspace": "1", "ordinal": "1"}, "width": "3"}));
    assert_eq!(mcp.call_json("held", json!({})), json!([]));
    assert!(mcp.finish().success());
}

/// A link on an unchanged word of the edited line still follows.
///
/// Four links are homed in the agent's draft: on a word before the change,
/// on two words of the changed line after it, and on a word of the next
/// line; a fifth is on the word that is replaced. The edit changes the
/// line's length, so every position past it moves; each of the four links
/// still projects onto its own word, read back from where the projection
/// says it stands now, and the fifth, whose bytes left the draft, projects
/// onto nothing.
#[test]
fn a_link_on_an_unchanged_word_of_the_edited_line_still_follows() {
    let fixture = Fixture::new("replace-link");
    let mut mcp = Launch::over(&fixture, 1).spawn();
    mcp.initialize();
    let doc = draft_holding(&mut mcp, CLAIMANT_ACCOUNT, CODE);
    let words = ["main", "left", "right", "println"];
    let links: Vec<String> = words.iter().map(|word| link_on(&mut mcp, &doc, CODE, word)).collect();
    let replaced_word = link_on(&mut mcp, &doc, CODE, "add");
    for (word, link) in words.iter().zip(&links) {
        assert_eq!(projected(&mut mcp, link, &doc), [*word], "premise: the link stands on its word");
    }
    let answer = replaced(&mut mcp, &doc, LINE, &LINE.replace("add", "subtract"));
    assert_eq!((&answer["removed"], &answer["inserted"]), (&json!("3"), &json!("8")), "{answer}");
    let edited = CODE.replace("add", "subtract");
    assert_eq!(text_of(&mut mcp, &doc), edited);
    for (word, link) in words.iter().zip(&links) {
        assert_eq!(projected(&mut mcp, link, &doc), [*word], "the link on `{word}` follows its word");
        let set = mcp.call_json("project", json!({"a": link, "slot": 1, "d": doc}));
        assert_eq!(set["set"], json!([{"start": format!("1.{}", ordinal_of(&edited, word)), "width": format!("0.{}", word.len())}]), "at the word's place in the edited text: {set}");
    }
    assert!(projected(&mut mcp, &replaced_word, &doc).is_empty(), "the replaced word's bytes left the draft");
    assert!(mcp.finish().success());
}

/// Two pairs land in one `edit_text` call, answered with the lines changed.
///
/// One pair renames the function and the next changes a word of the line
/// after it. The result's first line is the `edited` answer, the commit the
/// call was whole at in it and no rows; each line after it is a row — the
/// two changed lines `+`, the two after them as context, a tab between each
/// number and its line. The board's own `line_numbers` puts each change's
/// first new byte on its `+` row's line; the draft reads the new text, and
/// every byte outside the two changes, the text between them among it,
/// stands at the I-address it had (the mutants that number the text as
/// first read, or leave the rows in the answer, answer otherwise).
#[test]
fn two_pairs_land_in_one_edit_text_call_answered_with_the_lines_they_changed() {
    let fixture = Fixture::new("edit-text");
    let mut mcp = Launch::over(&fixture, 1).spawn();
    mcp.initialize();
    let doc = draft_holding(&mut mcp, CLAIMANT_ACCOUNT, CODE);
    let before = addresses(&mut mcp, &doc);
    let (is_error, answer, rows) = edit(&mut mcp, &doc, json!([{"old": "main", "new": "start"}, {"old": "right", "new": "other"}]));
    assert!(!is_error && answer["outcome"] == "edited", "the call lands: {answer}\n{}", mcp.log());
    assert!(answer["at"].is_u64() && answer.get("lines").is_none() && answer.get("masked").is_none(), "the answer, its rows after it: {answer}");
    assert_eq!(rows, ["+1\tfn start() {", "+2\t    let total = add(left, other);", " 3\t    println!(\"{total}\");", " 4\t}"], "{answer}");
    let (first, second) = (&answer["pairs"][0][0], &answer["pairs"][1][0]);
    let ordinal = |change: &Value| change["ordinal"].as_str().and_then(|ordinal| ordinal.parse::<u64>().ok()).unwrap_or_else(|| panic!("an ordinal: {change}"));
    let numbered =
        mcp.call_json("line_numbers", json!({"doc": doc, "positions": [{"subspace": "1", "ordinal": ordinal(first).to_string()}, {"subspace": "1", "ordinal": ordinal(second).to_string()}]}));
    assert_eq!((&numbered["positions"][0]["line"], &numbered["positions"][1]["line"]), (&json!("1"), &json!("2")), "the board numbers each change on its row's line: {numbered}");
    assert_eq!(text_of(&mut mcp, &doc), CODE.replace("main", "start").replace("right", "other"));
    let right = ordinal_of(CODE, "right") - 1;
    let new = |change: &Value| -> Vec<String> { (0..5).map(|k| address_past(change["addr"].as_str().expect("the change's I-address"), k)).collect() };
    let expected = [&before[..3], &new(first)[..], &before[7..right], &new(second)[..], &before[right + 5..]].concat();
    assert_eq!(addresses(&mut mcp, &doc), expected, "every byte outside the two changes at the I-address it had, the text between them among it");
    assert!(mcp.finish().success());
}

/// A line moved keeps its identity, and a link on it still finds it.
///
/// Links are homed in the agent's draft on a word of each of three lines;
/// the third line is then moved up to stand before the second, by line
/// numbers alone. The result's first line is the `moved` answer — the line
/// as asked, where it now stands, the three cuts and the commit, and no rows
/// — and each line after it a row: the moved line `+` where it stands, the
/// lines either side, and the row where it left. The draft reads the lines
/// in their new order with no value minted, every byte at the I-address it
/// had; each link projects onto its own word still, at the word's new place;
/// and the answer's `at` is the draft's typed state. A line the draft does
/// not hold is refused `no_such_line` as data, naming the argument, the line
/// and the count, a line standing where it is asked to stand answers
/// `unchanged`, and neither writes (the mutant that removes the line and
/// types it again mints it anew, and the link on it projects onto nothing).
#[test]
fn a_line_moved_keeps_its_identity_and_a_link_on_it_still_finds_it() {
    let fixture = Fixture::new("move-lines");
    let mut mcp = Launch::over(&fixture, 1).spawn();
    mcp.initialize();
    let doc = draft_holding(&mut mcp, CLAIMANT_ACCOUNT, CODE);
    let before = addresses(&mut mcp, &doc);
    let words = ["main", "add", "println"];
    let links: Vec<String> = words.iter().map(|word| link_on(&mut mcp, &doc, CODE, word)).collect();
    for (word, link) in words.iter().zip(&links) {
        assert_eq!(projected(&mut mcp, link, &doc), [*word], "premise: the link stands on its word");
    }
    let (is_error, answer, rows) = move_lines(&mut mcp, json!({"doc": doc, "first": 3, "before": 2}));
    assert!(!is_error && answer["outcome"] == "moved", "the move lands: {answer}\n{}", mcp.log());
    let at = answer["at"].as_u64().expect("the move's commit");
    assert_eq!(answer, json!({"outcome": "moved", "doc": doc, "first": 3, "last": 3, "to_first": 2, "to_last": 2, "cuts": ["13", "47", "72"], "at": at}), "the answer, its rows after it");
    assert_eq!(rows, [" 1\tfn main() {", "+2\t    println!(\"{total}\");", " 3\t    let total = add(left, right);", "-\t(line 3 moved to 2)", " 4\t}"]);
    let moved = "fn main() {\n    println!(\"{total}\");\n    let total = add(left, right);\n}\n";
    assert_eq!(text_of(&mut mcp, &doc), moved);
    assert_eq!(addresses(&mut mcp, &doc), [&before[..12], &before[46..71], &before[12..46], &before[71..]].concat(), "every byte at the I-address it had");
    assert_eq!(minted(&mut mcp, &doc), CODE.len() as u64, "no value minted");
    for (word, link) in words.iter().zip(&links) {
        assert_eq!(projected(&mut mcp, link, &doc), [*word], "the link on `{word}` follows its word");
        let set = mcp.call_json("project", json!({"a": link, "slot": 1, "d": doc}));
        assert_eq!(set["set"], json!([{"start": format!("1.{}", ordinal_of(moved, word)), "width": format!("0.{}", word.len())}]), "at the word's place in the text as moved: {set}");
    }
    let numbered = mcp.call_json("line_numbers", json!({"doc": doc, "positions": [{"subspace": "1", "ordinal": ordinal_of(moved, "println").to_string()}]}));
    assert_eq!(numbered["positions"][0]["line"], "2", "the board numbers the moved line as its row does: {numbered}");
    let (is_error, answer, rows) = move_lines(&mut mcp, json!({"doc": doc, "first": 5, "before": 1}));
    assert_eq!(
        (is_error, &answer, rows.len()),
        (false, &json!({"outcome": "refused", "cause": "no_such_line", "doc": doc, "what": "first", "line": 5, "count": 4}), 0),
        "data, naming the line and the count"
    );
    let (is_error, answer, _) = move_lines(&mut mcp, json!({"doc": doc, "first": 2, "last": 3, "before": 4}));
    assert_eq!((is_error, answer["outcome"].as_str()), (false, Some("unchanged")), "{answer}");
    assert_eq!((text_of(&mut mcp, &doc), addresses(&mut mcp, &doc).len()), (moved.to_string(), CODE.len()), "neither wrote");
    mcp.acked("delete", json!({"as_of": at, "doc": doc, "p": {"subspace": "1", "ordinal": "1"}, "width": "3"}));
    assert_eq!(mcp.call_json("held", json!({})), json!([]));
    assert!(mcp.finish().success());
}

/// A restore puts the old bytes back, and a link on them follows.
///
/// A draft holding the code text has a link made on a word, the board's
/// position then taken; two `replace_text` edits follow, the first taking
/// that word out, so the link projects onto nothing. `restore_text` to the
/// position before the edits, typed at the second edit's ack, answers its
/// result as data — `{draft, at, position, as_of, marker}`, `as_of` the
/// board's position as the call read it and `position` past it — and the
/// draft reads the code text at the very I-addresses it had, the link
/// projecting onto its word, no value minted. The same restore sent again
/// is answered from the board's memo: the same `position`, nothing
/// written, and `as_of` the call's own. The way back the first answer names
/// brings both edits back. A restore typed below the later writes is the
/// board's `arrangement_moved`, as data, its words asking a read first,
/// nothing changed; one at the draft's own position is `merge_refused`
/// with `not_past`, `isError`, naming the draft's position as `current`;
/// and a call naming `doc` is refused -32602 (the mutants that send the
/// tool as `history.past`, or answer the shell's read as the way back of
/// a write the memo answered, answer otherwise).
#[test]
fn a_restore_puts_the_old_bytes_back_and_a_link_on_them_follows() {
    let fixture = Fixture::new("restore-text");
    let mut mcp = Launch::over(&fixture, 1).spawn();
    mcp.initialize();
    let doc = draft_holding(&mut mcp, CLAIMANT_ACCOUNT, CODE);
    let before = addresses(&mut mcp, &doc);
    let link = link_on(&mut mcp, &doc, CODE, "add");
    assert_eq!(projected(&mut mcp, &link, &doc), ["add"], "premise: the link stands on its word");
    let at0 = mcp.position();
    let at1 = replaced(&mut mcp, &doc, LINE, &LINE.replace("add", "sub"))["at"].as_u64().expect("the first edit's commit");
    let at2 = replaced(&mut mcp, &doc, "main", "start")["at"].as_u64().expect("the second edit's commit");
    let edited = CODE.replace("add", "sub").replace("main", "start");
    assert_eq!(text_of(&mut mcp, &doc), edited);
    assert!(projected(&mut mcp, &link, &doc).is_empty(), "premise: the linked word's bytes left the draft");
    let minted_before = minted(&mut mcp, &doc);
    let restore = |mcp: &mut Mcp, at: u64, as_of: u64| -> (bool, Value) {
        let (is_error, text) = mcp.call("restore_text", json!({"draft": doc, "at": at, "as_of": as_of}));
        (is_error, serde_json::from_str(&text).unwrap_or_else(|e| panic!("restore_text's text is JSON ({e}): {text}")))
    };
    let head = mcp.position();
    let (is_error, restored) = restore(&mut mcp, at0, at2);
    let position = restored["position"].as_u64().unwrap_or_else(|| panic!("the write's commit: {restored}\n{}", mcp.log()));
    assert_eq!((is_error, &restored), (false, &json!({"draft": doc, "at": at0, "position": position, "as_of": head, "marker": null})), "the shell's answer, as data");
    assert!(position > head, "{restored}");
    assert_eq!((text_of(&mut mcp, &doc), addresses(&mut mcp, &doc)), (CODE.to_string(), before), "the old bytes at their own addresses");
    assert_eq!(projected(&mut mcp, &link, &doc), ["add"], "the link projects onto its word again");
    assert_eq!(minted(&mut mcp, &doc), minted_before, "no value minted");
    // The same restore sent again: the board's memo answers, nothing
    // written, its way back the call's own as_of.
    let (is_error, again) = restore(&mut mcp, at0, at2);
    assert_eq!((is_error, &again), (false, &json!({"draft": doc, "at": at0, "position": position, "as_of": at2, "marker": null})), "the first write's acknowledgment");
    assert_eq!((mcp.position(), text_of(&mut mcp, &doc)), (position, CODE.to_string()), "nothing written again");
    // The way back: both edits again.
    let (is_error, back) = restore(&mut mcp, head, position);
    assert!(!is_error && back["position"].as_u64().is_some_and(|at| at > position), "{back}");
    assert_eq!(text_of(&mut mcp, &doc), edited, "the way back brings both edits back");
    // Typed below the later writes: the board's verdict, nothing changed.
    let (is_error, moved) = restore(&mut mcp, at1, at2);
    assert_eq!((is_error, moved["kind"].as_str(), moved["name"].as_str()), (false, Some("refused"), Some("arrangement_moved")), "{moved}");
    assert!(moved["detail"].as_str().is_some_and(|detail| detail.contains("read the draft as it stands, then restore again typed at that read")), "{moved}");
    assert_eq!(text_of(&mut mcp, &doc), edited, "nothing changed");
    // At the draft's own position: no past state.
    let now = mcp.position();
    let (is_error, refused) = restore(&mut mcp, now, now);
    assert_eq!(
        (is_error, refused["name"].as_str(), refused["arm"].as_str(), refused["at"].as_u64(), refused["current"].as_u64()),
        (true, Some("merge_refused"), Some("not_past"), Some(now), Some(now)),
        "{refused}"
    );
    let refused = mcp.request("tools/call", json!({"name": "restore_text", "arguments": {"doc": doc, "at": at0, "as_of": now}}));
    assert!(refused["error"]["code"] == json!(-32602) && refused["error"]["message"].as_str().unwrap_or_default().contains("'doc'"), "the draft restored is `draft`: {refused}");
    assert_eq!(mcp.call_json("held", json!({})), json!([]));
    assert!(mcp.finish().success());
}

/// A mark, then a change and a move, are told by `diff_text` since the mark.
///
/// `mark_text` answers `marked` on one line, naming a private document that
/// holds the draft's text at the draft's own I-addresses, no value minted,
/// and the diff since it of the unchanged draft is `unchanged`. A word
/// changed and a line moved, `diff_text` answers `diffed` on its first line
/// — the counts by identity, the lines counted, the note of the move, the
/// rows taken off — then the hunk, one row a line as the shell spelled it:
/// the changed line gone and new, the moved line `>` where it stands and one
/// `<` row where it left. `stat` answers the counts alone on one line, and a
/// member the row does not take is refused before any call (the mutants
/// that leave the rows inside the JSON, or copy by minting, answer
/// otherwise).
#[test]
fn a_mark_then_a_change_and_a_move_are_told_by_diff_text_since_the_mark() {
    let fixture = Fixture::new("mark-diff");
    let mut mcp = Launch::over(&fixture, 1).spawn();
    mcp.initialize();
    let doc = draft_holding(&mut mcp, CLAIMANT_ACCOUNT, CODE);
    let before = addresses(&mut mcp, &doc);
    let (is_error, text) = mcp.call("mark_text", json!({"doc": doc}));
    let marked: Value = serde_json::from_str(&text).unwrap_or_else(|e| panic!("mark_text's result is one line of JSON ({e}): {text}"));
    assert!(!is_error && marked["outcome"] == "marked", "the mark is made: {marked}\n{}", mcp.log());
    let mark = marked["mark"].as_str().expect("the mark's address").to_string();
    assert_eq!(marked, json!({"outcome": "marked", "doc": doc, "mark": mark, "link": marked["link"], "at": marked["at"]}));
    assert_eq!((text_of(&mut mcp, &mark), addresses(&mut mcp, &mark)), (CODE.to_string(), before), "the draft's own bytes, by identity");
    assert_eq!(minted(&mut mcp, &mark), 0, "no value minted in the mark");
    let (is_error, text) = mcp.call("diff_text", json!({"doc": doc, "since": mark}));
    assert_eq!((is_error, serde_json::from_str::<Value>(&text).expect("one line of JSON")["outcome"].as_str().map(str::to_string)), (false, Some("unchanged".to_string())), "{text}");

    let (is_error, answer, _) = edit(&mut mcp, &doc, json!([{"old": "add(left, right)", "new": "sum(left, right)"}]));
    assert!(!is_error && answer["outcome"] == "edited", "{answer}");
    let (is_error, answer, _) = move_lines(&mut mcp, json!({"doc": doc, "first": 3, "before": 2}));
    assert!(!is_error && answer["outcome"] == "moved", "{answer}");
    let (is_error, text) = mcp.call("diff_text", json!({"doc": doc, "since": mark}));
    let (first, rows) = text.split_once('\n').expect("rows after the answer");
    let diffed: Value = serde_json::from_str(first).unwrap_or_else(|e| panic!("diff_text's first line is JSON ({e}): {text}"));
    assert_eq!(
        (is_error, &diffed),
        (
            false,
            &json!({
                "outcome": "diffed", "doc": doc, "since": mark, "as_of": answer["at"], "shared": (CODE.len() - 3).to_string(), "bytes": {"new": "3", "gone": "3", "moved": "25"},
                "lines": {"added": "1", "removed": "1", "moved": "1"}, "notes": [{"kind": "moved", "before": [3, 3], "now": [2, 2]}],
            })
        ),
        "the answer, its rows after it"
    );
    assert_eq!(
        rows.split('\n').collect::<Vec<_>>(),
        ["@@ -1,4 +1,4 @@", " 1\tfn main() {", "-2\t    let total = add(left, right);", "<\t(line 3 moved to 2)", ">2\t    println!(\"{total}\");", "+3\t    let total = sum(left, right);", " 4\t}"]
    );
    let (is_error, text) = mcp.call("diff_text", json!({"doc": doc, "since": mark, "stat": true}));
    let stat: Value = serde_json::from_str(&text).unwrap_or_else(|e| panic!("a stat answer is one line of JSON ({e}): {text}"));
    assert_eq!((is_error, &stat["bytes"], stat.get("lines")), (false, &json!({"new": "3", "gone": "3", "moved": "25"}), None), "the counts alone: {stat}");
    let refused = mcp.request("tools/call", json!({"name": "diff_text", "arguments": {"doc": doc, "mark": mark}}));
    assert!(refused["error"]["code"] == json!(-32602) && refused["error"]["message"].as_str().unwrap_or_default().contains("'mark'"), "the document compared with is `since`: {refused}");
    assert_eq!(mcp.call_json("held", json!({})), json!([]));
    assert!(mcp.finish().success());
}

/// `not_found` and `not_unique` write nothing.
///
/// A text the draft does not hold is refused `not_found`, count 0, and one
/// it holds three times `not_unique`, count 3 — each data, each with the
/// position the draft was read at; an empty `old` is refused before any
/// read, as a member of the wrong form is; and `old` and `new` the same
/// text answers `unchanged`. The draft's text, its image, its minted count
/// and the held bursts are as they were after each.
#[test]
fn not_found_and_not_unique_write_nothing() {
    let fixture = Fixture::new("replace-find");
    let mut mcp = Launch::over(&fixture, 1).spawn();
    mcp.initialize();
    let doc = draft_holding(&mut mcp, CLAIMANT_ACCOUNT, CODE);
    let before = addresses(&mut mcp, &doc);
    let read_at = mcp.position();
    let (is_error, answer) = replace(&mut mcp, &doc, "subtract", "add");
    assert!(!is_error, "{answer}");
    assert_eq!(answer, json!({"outcome": "refused", "cause": "not_found", "doc": doc, "count": 0, "as_of": read_at}));
    let (is_error, answer) = replace(&mut mcp, &doc, "total", "sum");
    assert!(!is_error, "{answer}");
    assert_eq!(answer, json!({"outcome": "refused", "cause": "not_unique", "doc": doc, "count": 2, "as_of": read_at}));
    let (is_error, answer) = replace(&mut mcp, &doc, "t", "T");
    assert_eq!((is_error, &answer["cause"], &answer["count"]), (false, &json!("not_unique"), &json!(CODE.matches('t').count())), "{answer}");
    let (is_error, answer) = replace(&mut mcp, &doc, "main", "main");
    assert!(!is_error, "{answer}");
    assert_eq!(answer, json!({"outcome": "unchanged", "doc": doc, "ordinal": ordinal_of(CODE, "main").to_string(), "as_of": read_at}));
    for (old, new, what) in [(json!(""), json!("x"), "old"), (json!(7), json!("x"), "old"), (json!("main"), json!(null), "new")] {
        let refused = mcp.call_error("replace_text", json!({"doc": doc, "old": old, "new": new}));
        assert_eq!((refused["kind"].as_str(), refused["name"].as_str(), refused["what"].as_str()), (Some("shell"), Some("malformed_args"), Some(what)), "{refused}");
    }
    let refused = mcp.call_error("replace_text", json!({"doc": "1..2", "old": "a", "new": "b"}));
    assert_eq!((refused["name"].as_str(), refused["what"].as_str()), (Some("malformed_args"), Some("doc")), "{refused}");
    let unregistered = mcp.call_json("replace_text", json!({"doc": "1.0.9.0.1", "old": "a", "new": "b"}));
    assert_eq!(
        (unregistered["kind"].as_str(), unregistered["name"].as_str(), unregistered["op"].as_str()),
        (Some("refused"), Some("doc_not_registered"), Some("doc_metadata")),
        "the board's verdict on the read, as data: {unregistered}"
    );
    assert_eq!(text_of(&mut mcp, &doc), CODE);
    assert_eq!(addresses(&mut mcp, &doc), before);
    assert_eq!(minted(&mut mcp, &doc), CODE.len() as u64);
    assert_eq!(mcp.call_json("held", json!({})), json!([]));
    assert!(mcp.finish().success());
}

/// A published document is refused before any write.
///
/// A document is published with a text; `replace_text` on it, and on its
/// version member, answers `refused`, `published`, naming the document —
/// as data — where the text asked for stands exactly once in it. No write
/// of the adapter's reached the board, none is held, and the member reads
/// as published (the mutant that asks no such question finds the text and
/// sends its insert, which the board refuses `published_target`).
#[test]
fn a_published_document_is_refused_before_any_write() {
    let fixture = Fixture::relayed("replace-published");
    let mut mcp = Launch::over(&fixture, 1).spawn();
    mcp.initialize();
    let edition = mcp.acked("create_new_document", json!({"account": CLAIMANT_ACCOUNT, "published": true}))["addr"].as_str().expect("the edition").to_string();
    let draft = stage_of(&mut mcp, &edition);
    let typed = mcp.position();
    mcp.acked("insert", json!({"as_of": typed, "doc": draft, "at": {"subspace": "1", "ordinal": "1"}, "values": [CODE]}));
    mcp.call_json("publication_open", json!({"draft": draft, "doc": edition}));
    let acked = mcp.call_json("publication_confirm", json!({}));
    let member = format!("{edition}.1");
    assert_eq!((acked["outcome"].as_str(), acked["member"].as_str()), (Some("acknowledged"), Some(member.as_str())), "{acked}");
    fixture.relay().forget();
    for doc in [&edition, &member] {
        let (is_error, answer) = replace(&mut mcp, doc, "add", "sub");
        assert!(!is_error, "{answer}");
        assert_eq!(answer, json!({"outcome": "refused", "cause": "published", "doc": doc, "published": edition}));
    }
    let writes: Vec<Passed> = fixture.relay().passed().into_iter().filter(|passed| ["insert", "delete", "edit", "set_arrangement"].contains(&passed.op.as_str())).collect();
    assert!(writes.is_empty(), "no write reached the board: {writes:?}");
    assert_eq!(mcp.call_json("held", json!({})), json!([]));
    assert_eq!(text_of(&mut mcp, &member), CODE);
    assert!(mcp.finish().success());
}

/// An edit made against text that changed since its read leaves the draft
/// exactly as the other writer left it.
///
/// Another session writes into the draft just after the edit has read its
/// text and before it writes: the relay lands that write as the read's
/// answer passes. The edit is refused `arrangement_moved`, as data, with
/// the board's verdict naming the position it was typed against and the one
/// the draft moved at; the draft reads as the other writer left it, every
/// byte it held before at its own address behind the other's new ones,
/// nothing of the edit minted; and no line of the edit's is held, so the
/// same edit, called again, lands against the text as it now stands (the
/// mutant that types its write against a fresh read made just before it
/// lands the first call, at positions the other writer's bytes moved). An
/// edit of one write, a removal, is refused the same way.
#[test]
fn an_edit_against_text_that_changed_since_its_read_leaves_the_draft_as_the_other_writer_left_it() {
    let fixture = Fixture::relayed("replace-stale");
    let mut mcp = Launch::over(&fixture, 1).logged().spawn();
    mcp.initialize();
    let doc = draft_holding(&mut mcp, CLAIMANT_ACCOUNT, CODE);
    let before = addresses(&mut mcp, &doc);
    let racer = fixture.racer(1);
    let raced = "// raced\n";
    let mut expected = CODE.to_string();
    for (old, new) in [("add", "sub"), ("    println!(\"{total}\");\n", "")] {
        settle_the_index(&mut mcp);
        let (rule_doc, rule_racer, landed) = (doc.clone(), racer.clone(), Arc::new(AtomicUsize::new(0)));
        let seen = Arc::clone(&landed);
        fixture.relay().on(move |passing| {
            let reads_the_text = passing.frame["op"] == "retrieve_v" && passing.frame["specs"][0]["doc"] == rule_doc.as_str();
            if reads_the_text && passing.answer.is_some() && seen.load(Ordering::SeqCst) == 0 {
                seen.store(rule_racer.insert(&rule_doc, 1, raced) as usize, Ordering::SeqCst);
            }
        });
        let read_at = mcp.position();
        let (is_error, answer) = replace(&mut mcp, &doc, old, new);
        let moved_at = landed.load(Ordering::SeqCst);
        assert!(moved_at > 0, "premise: the other writer's change landed inside the call");
        assert!(!is_error, "the board's verdict is data: {answer}");
        assert_eq!((&answer["outcome"], &answer["cause"], &answer["doc"]), (&json!("refused"), &json!("arrangement_moved"), &json!(doc)), "{answer}\n{}", mcp.log());
        assert_eq!(answer["refusal"]["site"], json!({"as_of": read_at, "current": moved_at}), "typed against its read, refused at the other's commit: {answer}");
        expected.insert_str(0, raced);
        assert_eq!(text_of(&mut mcp, &doc), expected, "the draft as the other writer left it");
        assert_eq!(mcp.call_json("held", json!({})), json!([]), "no line of the edit's is held");
    }
    let after = addresses(&mut mcp, &doc);
    assert_eq!(after[2 * raced.len()..], before[..], "every byte the draft held keeps its address");
    assert_eq!(minted(&mut mcp, &doc), (CODE.len() + 2 * raced.len()) as u64, "the edit minted nothing");
    fixture.relay().on(|_| {});
    let answer = replaced(&mut mcp, &doc, "add", "sub");
    assert_eq!(answer["ordinal"], json!((ordinal_of(CODE, "add") + 2 * raced.len()).to_string()), "the edit, called again, finds its word where it now stands: {answer}");
    assert_eq!(text_of(&mut mcp, &doc), expected.replace("add", "sub"));
    assert!(mcp.finish().success());
}

/// A replacement is one commit, and another writer's change ahead of it
/// refuses it whole.
///
/// A change that both removes and inserts is ONE frame, the board's `edit`:
/// one commit, no state standing between a removal and an insert. Another
/// session writes into the draft as that frame is on its way — the relay
/// lands its write before the frame reaches the board — so the frame, typed
/// against the call's read, is refused: the answer is the board's verdict,
/// as data, the one write the call sent the frame refused; the draft reads
/// exactly as the other writer left it, nothing of the edit minted, and no
/// line is held. Called again, the edit lands by one frame more, and the
/// draft's feed shows one entry for it, an `edit` (the mutant that sends the
/// insert and then the removal sends two writes, and leaves the new bytes
/// minted where the second is refused).
#[test]
fn a_replacement_is_one_commit_and_another_writers_change_ahead_of_it_refuses_it_whole() {
    let fixture = Fixture::relayed("replace-second");
    let mut mcp = Launch::over(&fixture, 1).logged().spawn();
    mcp.initialize();
    let doc = draft_holding(&mut mcp, CLAIMANT_ACCOUNT, CODE);
    let before = addresses(&mut mcp, &doc);
    let (racer, raced) = (fixture.racer(1), "// raced\n");
    let (rule_doc, landed) = (doc.clone(), Arc::new(AtomicUsize::new(0)));
    let seen = Arc::clone(&landed);
    fixture.relay().on(move |passing| {
        let edits = passing.frame["op"] == "edit" && passing.frame["doc"] == rule_doc.as_str();
        if edits && passing.answer.is_none() && seen.load(Ordering::SeqCst) == 0 {
            seen.store(racer.insert(&rule_doc, 1, raced) as usize, Ordering::SeqCst);
        }
    });
    fixture.relay().forget();
    let (is_error, answer) = replace(&mut mcp, &doc, "add", "sub");
    let moved_at = landed.load(Ordering::SeqCst);
    assert!(moved_at > 0, "premise: the other writer's change landed ahead of the frame");
    assert!(!is_error, "the board's verdict is data: {answer}");
    assert_eq!((&answer["outcome"], &answer["cause"]), (&json!("refused"), &json!("arrangement_moved")), "{answer}\n{}", mcp.log());
    assert_eq!((&answer["refusal"]["op"], &answer["refusal"]["site"]["current"]), (&json!("edit"), &json!(moved_at)), "the one frame is the write refused: {answer}");
    let writes = |fixture: &Fixture| -> Vec<(String, String)> {
        fixture
            .relay()
            .passed()
            .iter()
            .filter(|passed| ["insert", "delete", "edit", "set_arrangement"].contains(&passed.op.as_str()) && passed.frame["doc"] == doc.as_str())
            .map(|passed| (passed.op.clone(), passed.answer["resp"].as_str().unwrap_or_default().to_string()))
            .collect()
    };
    assert_eq!(writes(&fixture), [("edit".to_string(), "rejected".to_string())], "one write, refused: nothing to take back");
    assert_eq!(text_of(&mut mcp, &doc), format!("{raced}{CODE}"), "the draft exactly as the other writer left it");
    assert_eq!(addresses(&mut mcp, &doc)[raced.len()..], before[..], "every byte the draft held keeps its address");
    assert_eq!(minted(&mut mcp, &doc), (CODE.len() + raced.len()) as u64, "nothing of the edit was minted");
    assert_eq!(mcp.call_json("held", json!({})), json!([]), "no line of the edit's is held");
    fixture.relay().on(|_| {});
    fixture.relay().forget();
    let typed = mcp.position();
    let landed = replaced(&mut mcp, &doc, "add", "sub");
    assert_eq!(writes(&fixture), [("edit".to_string(), "ack_addr".to_string())], "one frame: the removal and the insert together");
    assert_eq!(text_of(&mut mcp, &doc), format!("{raced}{}", CODE.replace("add", "sub")));
    let page = mcp.call_json("changes_since", json!({"since": typed, "under": doc, "class": "drafts"}));
    let entries: Vec<(&str, u64)> = page["entries"].as_array().expect("entries").iter().map(|entry| (entry["op"].as_str().unwrap_or_default(), entry["at"].as_u64().unwrap_or_default())).collect();
    assert_eq!(entries, [("edit", landed["at"].as_u64().expect("the edit's commit"))], "one commit on the feed, the edit's own: {page}");
    assert!(mcp.finish().success());
}

/// An edit behind a held line of the agent's is refused `held_lines`.
///
/// A raw insert typed against an older state is held `moved`, its line
/// standing on the draft. `replace_text`, `edit_text` and a raw `edit` are
/// each refused `held_lines`, `isError`, naming the draft and the one line,
/// nothing read past the door and nothing written: an edit is no burst and
/// would land ahead of the line. The one line held is still the raw
/// insert's. Once the agent resolves that line, the edit lands.
#[test]
fn an_edit_behind_a_held_line_is_refused_held_lines_and_lands_once_it_is_resolved() {
    let fixture = Fixture::new("replace-behind");
    let mut mcp = Launch::over(&fixture, 1).spawn();
    mcp.initialize();
    let stale = mcp.position();
    let doc = draft_holding(&mut mcp, CLAIMANT_ACCOUNT, CODE);
    let held = mcp.call_json("insert", json!({"as_of": stale, "doc": doc, "at": {"subspace": "1", "ordinal": "1"}, "values": ["x"]}));
    assert_eq!((held["resp"].as_str(), held["cause"].as_str()), (Some("held"), Some("moved")), "premise: a stale raw insert is held: {held}");
    let refused = json!({"kind": "shell", "name": "held_lines", "doc": doc, "held": 1});
    let (is_error, answer) = replace(&mut mcp, &doc, "add", "sub");
    assert!(is_error, "the shell's own refusal: {answer}");
    assert_eq!(answer, refused, "replace_text");
    let (is_error, answer, _) = edit(&mut mcp, &doc, json!([{"old": "add", "new": "sub"}]));
    assert_eq!((is_error, &answer), (true, &refused), "edit_text");
    let typed = mcp.position();
    let raw = mcp.call_error("edit", json!({"as_of": typed, "doc": doc, "changes": [{"at": {"subspace": "1", "ordinal": "1"}, "width": "0", "values": ["y"]}]}));
    assert_eq!(raw, refused, "a raw edit");
    let lines = mcp.call_json("held", json!({}));
    assert_eq!(lines.as_array().map(Vec::len), Some(1), "the raw insert's line alone: {lines}");
    assert_eq!((&lines[0]["held"], &lines[0]["cause"]), (&held["held"], &json!("moved")), "{lines}");
    assert_eq!(text_of(&mut mcp, &doc), CODE);
    assert_eq!(mcp.call_json("resolve", json!({"held": held["held"], "act": "drop"})), json!({}));
    replaced(&mut mcp, &doc, "add", "sub");
    assert_eq!(text_of(&mut mcp, &doc), CODE.replace("add", "sub"));
    assert!(mcp.finish().success());
}

/// An `edit` whose changes place runs lands them by identity in one commit.
///
/// The agent sends ONE `edit` call of three changes in the placed form:
/// another draft's line placed ahead of the first position, a word removed
/// with nothing put in its place, and the draft's own first line placed
/// again past its end. The adapter sends ONE write, a `set_arrangement`
/// frame carrying the three changes, and the board acknowledges it, minting
/// nothing; the draft's feed shows one entry for it, a `set_arrangement`;
/// and the draft's image reads, position for position, the I-addresses the
/// call named — the other draft's own, then the draft's with the word's
/// gone, then its first line's again (the mutant that sends the placed form
/// as a `delete` and a `reinstate` a change relays two writes or more, none
/// of that name, and leaves as many rows). A call minting values is still
/// one `edit` frame and one `edit` row. A call mixing the two forms, and a
/// placed call carrying a landing's `base`, are refused as invalid
/// arguments with no frame sent. And behind a held line of the agent's on
/// the draft the placed call is refused `held_lines`, nothing relayed and
/// the draft as it was (the mutant that asks the held-lines gate of an
/// `edit` frame alone lands it ahead of the line); once the line is
/// resolved it lands.
#[test]
fn an_edit_placing_runs_lands_them_by_identity_as_one_set_arrangement_commit() {
    let fixture = Fixture::relayed("replace-placed");
    let mut mcp = Launch::over(&fixture, 1).logged().spawn();
    mcp.initialize();
    let doc = draft_holding(&mut mcp, CLAIMANT_ACCOUNT, CODE);
    let other_line = "// from the other draft\n";
    let other = draft_holding(&mut mcp, CLAIMANT_ACCOUNT, other_line);
    let (own, theirs) = (addresses(&mut mcp, &doc), addresses(&mut mcp, &other));
    let first_line = CODE.find('\n').expect("a first line") + 1;
    let (word_at, word) = (ordinal_of(CODE, "let "), "let ".len());
    let run = |origin: &str, first: &str, width: usize| json!({"origin": origin, "i_start": first, "width": width.to_string()});
    let at = |ordinal: usize| json!({"subspace": "1", "ordinal": ordinal.to_string()});
    let placed = |as_of: u64| {
        json!({"as_of": as_of, "doc": doc, "changes": [
            {"at": at(1), "width": "0", "runs": [run(&other, &theirs[0], theirs.len())]},
            {"at": at(word_at), "width": word.to_string(), "runs": []},
            {"at": at(CODE.len() + 1), "width": "0", "runs": [run(&doc, &own[0], first_line)]},
        ]})
    };
    // The writes the relay passed for the draft, by op and the board's
    // answer.
    let writes = |fixture: &Fixture| -> Vec<(String, String)> {
        fixture
            .relay()
            .passed()
            .iter()
            .filter(|passed| ["insert", "delete", "reinstate", "copy", "rearrange", "edit", "set_arrangement"].contains(&passed.op.as_str()) && passed.frame["doc"] == doc.as_str())
            .map(|passed| (passed.op.clone(), passed.answer["resp"].as_str().unwrap_or_default().to_string()))
            .collect()
    };
    let rows = |mcp: &mut Mcp, since: u64| -> Vec<(String, u64)> {
        let page = mcp.call_json("changes_since", json!({"since": since, "under": doc, "class": "drafts"}));
        page["entries"].as_array().expect("entries").iter().map(|entry| (entry["op"].as_str().unwrap_or_default().to_string(), entry["at"].as_u64().unwrap_or_default())).collect()
    };
    let minted_before = minted(&mut mcp, &doc);
    fixture.relay().forget();
    let typed = mcp.position();
    let landed = mcp.acked("edit", placed(typed));
    assert_eq!(landed["resp"], "ack", "runs placed by identity mint nothing: {landed}\n{}", mcp.log());
    let at_commit = landed["at"].as_u64().expect("the commit's position");
    assert_eq!(writes(&fixture), [("set_arrangement".to_string(), "ack".to_string())], "one write relayed, the placed form's frame");
    let sent = fixture.relay().passed().into_iter().find(|passed| passed.op == "set_arrangement").expect("the frame");
    assert_eq!(sent.frame["changes"], placed(typed)["changes"], "the call's changes are the frame's, as they stood");
    assert!(sent.frame.get("base").is_none() && sent.frame.get("merge").is_none(), "no landing rides it: {}", sent.frame);
    assert_eq!(rows(&mut mcp, typed), [("set_arrangement".to_string(), at_commit)], "one commit on the feed, under the name a frame placing runs is sent as");
    // The draft's image, position for position: the identities named.
    let mut expected: Vec<String> = theirs.clone();
    expected.extend_from_slice(&own[..word_at - 1]);
    expected.extend_from_slice(&own[word_at - 1 + word..]);
    expected.extend_from_slice(&own[..first_line]);
    assert_eq!(addresses(&mut mcp, &doc), expected, "every position holds the I-address the call named for it");
    assert_eq!(minted(&mut mcp, &doc), minted_before, "nothing minted in the draft");
    assert_eq!(addresses(&mut mcp, &other), theirs, "the other draft stands as it was: its words are shared, not moved");
    // The values form, as ever: one `edit` frame, one `edit` row.
    fixture.relay().forget();
    let typed = mcp.position();
    let minted_values = mcp.acked("edit", json!({"as_of": typed, "doc": doc, "changes": [{"at": at(1), "width": "0", "values": ["// "]}]}));
    assert_eq!(writes(&fixture), [("edit".to_string(), "ack_addr".to_string())]);
    assert_eq!(rows(&mut mcp, typed), [("edit".to_string(), minted_values["at"].as_u64().expect("the commit"))]);
    // One form a call, and no landing on this tool: refused at the
    // adapter's door, no frame sent.
    fixture.relay().forget();
    let typed = mcp.position();
    let mut mixed = placed(typed);
    mixed["changes"][1] = json!({"at": at(word_at), "width": "0", "values": ["x"]});
    let mut landing = placed(typed);
    landing["base"] = json!({"at": doc, "extent": "0"});
    for (call, says) in [(mixed, "one form a call"), (landing, "takes no 'base'")] {
        let refused = mcp.request("tools/call", json!({"name": "edit", "arguments": call}));
        assert_eq!(refused["error"]["code"], json!(-32602), "invalid arguments: {refused}");
        assert!(refused["error"]["message"].as_str().is_some_and(|message| message.contains(says)), "{refused}");
    }
    assert_eq!(writes(&fixture), [], "neither reached the board");
    // Behind a held line of the agent's on the draft: refused, nothing sent.
    let stale = typed - 1;
    let held = mcp.call_json("insert", json!({"as_of": stale, "doc": doc, "at": at(1), "values": ["x"]}));
    assert_eq!((held["resp"].as_str(), held["cause"].as_str()), (Some("held"), Some("moved")), "premise: a stale raw insert is held: {held}");
    let standing = addresses(&mut mcp, &doc);
    fixture.relay().forget();
    let behind = json!({"as_of": mcp.position(), "doc": doc, "changes": [{"at": at(1), "width": "0", "runs": [run(&other, &theirs[0], 2)]}]});
    assert_eq!(mcp.call_error("edit", behind.clone()), json!({"kind": "shell", "name": "held_lines", "doc": doc, "held": 1}), "the placed form behind a held line");
    assert_eq!(writes(&fixture), [], "nothing relayed");
    assert_eq!(addresses(&mut mcp, &doc), standing, "the draft as it was");
    assert_eq!(mcp.call_json("resolve", json!({"held": held["held"], "act": "drop"})), json!({}));
    let mut after = behind;
    after["as_of"] = json!(mcp.position());
    assert_eq!(mcp.acked("edit", after)["resp"], "ack", "the line resolved, the placed call lands");
    assert_eq!(addresses(&mut mcp, &doc)[..2], theirs[..2], "its two positions the other draft's own");
    assert!(mcp.finish().success());
}

/// A draft the session does not own is refused by the board, nothing held.
///
/// The agent space's principal reads the claimant's draft, which lies above
/// it, and may not write it: the edit is found, its one write refused
/// `not_owner` by the board — the verdict under `refusal`, as data — and
/// nothing is held, the write being no burst.
#[test]
fn a_draft_that_is_not_the_sessions_is_refused_by_the_board_and_nothing_is_held() {
    let fixture = Fixture::new("replace-owner");
    let racer = fixture.racer(1);
    let doc = racer.op(&json!({"op": "create_new_document", "account": CLAIMANT_ACCOUNT}))["addr"].as_str().expect("the claimant's draft").to_string();
    racer.insert(&doc, 1, CODE);
    let mut mcp = Launch::over(&fixture, fixture.agent_principal()).spawn();
    mcp.initialize();
    assert_eq!(text_of(&mut mcp, &doc), CODE, "premise: the agent reads the draft above it");
    let (is_error, answer) = replace(&mut mcp, &doc, "add", "sub");
    assert!(!is_error, "the board's verdict is data: {answer}");
    assert_eq!(
        (&answer["outcome"], &answer["cause"], &answer["refusal"]["code"], &answer["refusal"]["op"]),
        (&json!("refused"), &json!("not_owner"), &json!("not_owner"), &json!("edit")),
        "{answer}"
    );
    assert_eq!(mcp.call_json("held", json!({})), json!([]), "nothing held");
    assert_eq!(text_of(&mut mcp, &doc), CODE);
    let own = draft_holding(&mut mcp, AGENT_SPACE, CODE);
    replaced(&mut mcp, &own, "add", "sub");
    assert!(mcp.finish().success());
}

/// An atom takes one position and is no text.
///
/// A draft holds text, an atom, and text. An edit after the atom lands at
/// the right bytes — the atom counted as the one position it takes, never
/// as its bytes — and the atom keeps its address; a text that would match
/// only across the atom is refused `crosses_atom`, naming the atom's
/// position, nothing written.
#[test]
fn an_atom_takes_one_position_and_is_no_text() {
    let fixture = Fixture::new("replace-atom");
    let mut mcp = Launch::over(&fixture, 1).spawn();
    mcp.initialize();
    let doc = draft_of(&mut mcp, CLAIMANT_ACCOUNT);
    let typed = mcp.position();
    mcp.acked("insert", json!({"as_of": typed, "doc": doc, "at": {"subspace": "1", "ordinal": "1"}, "values": ["alpha ", {"atom": "one indivisible value"}, " beta gamma\n"]}));
    let before = addresses(&mut mcp, &doc);
    let (is_error, answer) = replace(&mut mcp, &doc, "alpha  beta", "alpha beta");
    assert!(!is_error, "{answer}");
    assert_eq!((&answer["outcome"], &answer["cause"], &answer["ordinal"], &answer["kind"]), (&json!("refused"), &json!("crosses_atom"), &json!("7"), &json!("atom")), "{answer}");
    let answer = replaced(&mut mcp, &doc, "gamma", "delta");
    assert_eq!(
        (&answer["ordinal"], &answer["removed"], &answer["inserted"]),
        (&json!("14"), &json!("4"), &json!("4")),
        "six bytes, one atom, six bytes, then the word less the letter it keeps: {answer}"
    );
    assert_eq!(items_of(&mut mcp, &doc, 1, 19), json!([{"content": "alpha "}, {"atom": "one indivisible value"}, {"content": " beta delta\n"}]));
    let after = addresses(&mut mcp, &doc);
    assert_eq!(after[..13], before[..13], "the atom and the text before the change keep their addresses");
    assert_eq!(after[17..], before[17..], "and the letter the two words share, and the newline after it");
    assert!(mcp.finish().success());
}

/// A draft past one read is read in parts, a character cut between two.
///
/// The draft's text runs one position past the delivery budget, a two-byte
/// character lying across the boundary, so each part's edge run arrives as
/// hex. The edit finds a word past the boundary and replaces it at its own
/// position, and the cut character reads whole after it.
#[test]
fn a_draft_past_one_read_is_read_in_parts_and_a_character_cut_between_them_is_text() {
    let fixture = Fixture::new("replace-parts");
    let mut mcp = Launch::over(&fixture, 1).spawn();
    mcp.initialize();
    let tail = "é\nlet word = 1;\n";
    let text = format!("{}{tail}", "a".repeat(READ_POSITIONS - 1));
    let doc = draft_holding(&mut mcp, CLAIMANT_ACCOUNT, &text);
    let edges = items_of(&mut mcp, &doc, READ_POSITIONS, 2);
    assert_eq!(edges, json!([{"content": "é"}]), "premise: the character lies across the first part's end");
    let answer = replaced(&mut mcp, &doc, "let word", "let name");
    assert_eq!((&answer["ordinal"], &answer["removed"], &answer["inserted"]), (&json!(ordinal_of(&text, "word").to_string()), &json!("4"), &json!("4")), "{answer}");
    let read = items_of(&mut mcp, &doc, READ_POSITIONS - 1, tail.len() + 1);
    assert_eq!(read, json!([{"content": "aé\nlet name = 1;\n"}]));
    assert!(mcp.finish().success());
}

/// One edit inserts as much as one `edit` frame carries, and no more.
///
/// A changed text of the frame's cap lands in one commit, and one a byte
/// past it is refused `too_large` before any write, naming the cap — the
/// figure skep-shell's `MAX_NEW_BYTES` states and the catalog tells an
/// agent (SP-25): a cap the board lowered would fail the first, one it
/// raised leaves the second refusing what the board would take.
#[test]
fn one_edit_inserts_as_much_as_one_insert_carries_and_no_more() {
    let fixture = Fixture::new("replace-cap");
    let mut mcp = Launch::over(&fixture, 1).spawn();
    mcp.initialize();
    let doc = draft_holding(&mut mcp, CLAIMANT_ACCOUNT, "[]");
    let (is_error, answer) = replace(&mut mcp, &doc, "[]", &format!("[{}]", "b".repeat(MAX_NEW_BYTES + 1)));
    assert!(!is_error, "{answer}");
    assert_eq!(answer, json!({"outcome": "refused", "cause": "too_large", "doc": doc, "what": "new", "bytes": (MAX_NEW_BYTES + 1).to_string(), "cap": MAX_NEW_BYTES.to_string()}));
    assert_eq!(minted(&mut mcp, &doc), 2, "nothing written");
    let answer = replaced(&mut mcp, &doc, "[]", &format!("[{}]", "b".repeat(MAX_NEW_BYTES)));
    assert_eq!((&answer["ordinal"], &answer["removed"], &answer["inserted"]), (&json!("2"), &json!("0"), &json!(MAX_NEW_BYTES.to_string())), "{answer}");
    assert_eq!(extent_of(&mut mcp, &doc), MAX_NEW_BYTES + 2);
    assert!(mcp.finish().success());
}

/// An edit whose line holds a lone surrogate escape is refused, not run.
///
/// JSON's grammar writes one half of a surrogate pair alone and no UTF-8
/// string holds it: the adapter reads such a line with U+FFFD at the escape
/// to find whose request it is, and runs nothing of it. The draft holds the
/// very text that reading spells, once, so an edit run from it would land;
/// the request is answered -32602 under its own id, and the draft's text,
/// its identities, its minted count and the lines held are as they were. A
/// pair escaped whole is one character: the edit lands and reads back as it.
#[test]
fn an_edit_holding_a_lone_surrogate_escape_is_refused_under_its_id_and_a_pair_lands() {
    let fixture = Fixture::new("replace-surrogate");
    let mut mcp = Launch::over(&fixture, 1).spawn();
    mcp.initialize();
    let text = "a\u{FFFD}b = c\n";
    let doc = draft_holding(&mut mcp, CLAIMANT_ACCOUNT, text);
    let before = (addresses(&mut mcp, &doc), minted(&mut mcp, &doc));
    mcp.send_line(&format!(r#"{{"jsonrpc":"2.0","id":"lone","method":"tools/call","params":{{"name":"replace_text","arguments":{{"doc":"{doc}","old":"a\ud800b","new":"c"}}}}}}"#));
    let refused = mcp.read_message();
    assert_eq!((&refused["id"], &refused["error"]["code"]), (&json!("lone"), &json!(-32602)), "{refused}");
    assert!(refused["error"]["message"].as_str().is_some_and(|said| said.contains("lone surrogate")), "the refusal names its cause: {refused}");
    assert_eq!(text_of(&mut mcp, &doc), text, "the draft's text stands");
    assert_eq!((addresses(&mut mcp, &doc), minted(&mut mcp, &doc)), before, "nothing written");
    assert_eq!(mcp.call_json("held", json!({})), json!([]));
    mcp.send_line(&format!(r#"{{"jsonrpc":"2.0","id":"pair","method":"tools/call","params":{{"name":"replace_text","arguments":{{"doc":"{doc}","old":"= c","new":"= \ud83d\ude00"}}}}}}"#));
    let landed = mcp.read_message();
    let answer: Value = serde_json::from_str(landed["result"]["content"][0]["text"].as_str().unwrap_or_default()).unwrap_or_else(|e| panic!("replace_text's text is JSON ({e}): {landed}"));
    assert_eq!((&landed["id"], &landed["result"]["isError"], &answer["outcome"]), (&json!("pair"), &json!(false), &json!("replaced")), "{landed}");
    assert_eq!((&answer["removed"], &answer["inserted"]), (&json!("1"), &json!("4")), "one character of four bytes for the one letter: {answer}");
    assert_eq!(text_of(&mut mcp, &doc), "a\u{FFFD}b = \u{1F600}\n");
    assert!(mcp.finish().success());
}

// ── the measurement ─────────────────────────────────────────────────────

/// Returns a code-like text of at least `bytes` bytes, each line its own.
fn numbered_lines(bytes: usize) -> String {
    let mut text = String::with_capacity(bytes + 64);
    let mut line = 0;
    while text.len() < bytes {
        text.push_str(&format!("    let value_{line:06} = compute({line:06});\n"));
        line += 1;
    }
    text
}

/// Returns the median of `samples`, in milliseconds.
fn median_ms(samples: &mut [Duration]) -> f64 {
    samples.sort_unstable();
    samples[samples.len() / 2].as_secs_f64() * 1e3
}

/// Times `replace_text` on a loopback board, by its parts, beside the raw ops.
///
/// Three drafts — about 2 KB, 40 KB and 200 KB, the last past the delivery
/// budget — each take `SKEP_MEASURE_RUNS` one-word edits (3 unless set; the
/// report's figures are of 15) in the middle of their text. A first pass, on
/// a plain board, times each call whole as the agent meets it: `replace_text`,
/// and the same edit by a raw `edit` of one change with the position given.
/// A second, through the relay, splits the call by what it asked of the
/// board: its reads — how many, their bytes and the board's time on them —
/// and its one write, the `edit` frame. Prints its figures; asserts only
/// that each edit landed.
#[test]
#[ignore = "measurement - run by hand"]
fn measure_replace_text_by_its_parts_beside_the_raw_ops() {
    let runs: usize = std::env::var("SKEP_MEASURE_RUNS").ok().and_then(|n| n.parse().ok()).unwrap_or(3);
    let sizes = [("2 KB", 2 * 1024), ("40 KB", 40 * 1024), ("200 KB", 200 * 1024)];
    // The words the edits toggle between, on the text's middle line.
    let spelled = |text: &str, flip: bool| -> (String, String) {
        let line = text.lines().count() / 2;
        let (from, to) = if flip { ("combine", "compute") } else { ("compute", "combine") };
        (format!("{from}({line:06})"), format!("{to}({line:06})"))
    };
    eprintln!("replace_text measured over {runs} runs a size (medians, ms)");
    // The first pass: each call whole, on a plain board.
    let fixture = Fixture::new("replace-measure");
    let mut mcp = Launch::over(&fixture, 1).spawn();
    mcp.initialize();
    let mut idle: Vec<Duration> = (0..runs.max(5))
        .map(|_| {
            let began = Instant::now();
            mcp.call_json("boards", json!({}));
            began.elapsed()
        })
        .collect();
    eprintln!("  a call that dials nothing (boards): {:.3}", median_ms(&mut idle));
    for (label, bytes) in sizes {
        let text = numbered_lines(bytes);
        let doc = draft_holding(&mut mcp, CLAIMANT_ACCOUNT, &text);
        let (mut whole, mut raw) = (Vec::new(), Vec::new());
        for run in 0..runs {
            settle_the_index(&mut mcp);
            let (old, new) = spelled(&text, run % 2 == 1);
            let began = Instant::now();
            let answer = replaced(&mut mcp, &doc, &old, &new);
            whole.push(began.elapsed());
            assert_eq!((&answer["removed"], &answer["inserted"]), (&json!("3"), &json!("3")), "{answer}");
        }
        let mut typed = mcp.position();
        for run in 0..runs {
            settle_the_index(&mut mcp);
            let (old, new) = spelled(&text, (runs + run) % 2 == 1);
            // The agent's own arithmetic, done before the clock: the word's
            // position in the text it holds.
            let at = ordinal_of(&text, &old.replace("combine", "compute")) + 3;
            let began = Instant::now();
            let edited = mcp.acked("edit", json!({"as_of": typed, "doc": doc, "changes": [{"at": {"subspace": "1", "ordinal": at.to_string()}, "width": "3", "values": [&new[3..6]]}]}));
            raw.push(began.elapsed());
            typed = edited["at"].as_u64().expect("the edit's commit");
        }
        eprintln!("  {label} ({} bytes): replace_text {:.3}; a raw edit of one change, its position given {:.3}", text.len(), median_ms(&mut whole), median_ms(&mut raw));
    }
    assert!(mcp.finish().success());
    // The second pass: the call split by what it asked of the board.
    let fixture = Fixture::relayed("replace-measure-parts");
    let mut mcp = Launch::over(&fixture, 1).spawn();
    mcp.initialize();
    for (label, bytes) in sizes {
        let text = numbered_lines(bytes);
        let doc = draft_holding(&mut mcp, CLAIMANT_ACCOUNT, &text);
        let (mut whole, mut reading, mut writing) = (Vec::new(), Vec::new(), Vec::new());
        let (mut reads, mut read_bytes, mut write_bytes) = (0, 0, 0);
        for run in 0..runs {
            settle_the_index(&mut mcp);
            let (old, new) = spelled(&text, run % 2 == 1);
            fixture.relay().forget();
            let began = Instant::now();
            replaced(&mut mcp, &doc, &old, &new);
            whole.push(began.elapsed());
            // The edit's exchanges: its reads are those ahead of its write —
            // the index is settled, so no other reader is about — and its
            // one write is the `edit` frame on the draft.
            let passed = fixture.relay().passed();
            let first_write = passed.iter().position(|passed| passed.op == "edit").expect("the call's one write");
            assert_eq!(passed.iter().filter(|passed| ["edit", "insert", "delete"].contains(&passed.op.as_str())).count(), 1, "one write a call");
            let of_the_draft = |passed: &&Passed| passed.frame["doc"] == doc.as_str() || passed.frame["specs"][0]["doc"] == doc.as_str();
            let read: Vec<&Passed> = passed[..first_write].iter().filter(of_the_draft).collect();
            (reads, read_bytes) = (read.len(), read.iter().map(|passed| passed.answer_bytes).sum::<usize>());
            reading.push(read.iter().map(|passed| passed.took).sum());
            writing.push(passed[first_write].took);
            write_bytes = passed[first_write].request_bytes;
        }
        eprintln!(
            "  {label} ({} bytes), through the relay: replace_text {:.3} — {reads} reads answering {read_bytes} bytes {:.3}, its one write (an edit, a frame of {write_bytes} bytes) {:.3}",
            text.len(),
            median_ms(&mut whole),
            median_ms(&mut reading),
            median_ms(&mut writing)
        );
    }
    assert!(mcp.finish().success());
}
