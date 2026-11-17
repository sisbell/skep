//! `replace_text`, end to end against a real board.
//!
//! A draft holding a few lines of code text is edited through the built
//! adapter, and the board is read back by identity: a one-word change mints
//! that word's bytes and no other, a link on an unchanged word of the edited
//! line still projects onto its word, and an edit that does not land leaves
//! the draft as it was — refused before any write where a read decides it,
//! and, where another writer's change commits at the wrong moment, with the
//! draft exactly as that writer left it and no line of the edit's held. The
//! other writer is staged, never raced: the adapter dials the board through
//! `common`'s relay, whose rule lands a second session's write between two
//! exchanges of one tool call. The measurement at the foot is run by hand.

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

/// The most bytes of new text one edit inserts, as `src/replace.rs` states it.
const MAX_NEW_BYTES: usize = 1 << 18;

/// The positions one read of a draft's text asks, as `src/replace.rs` has it.
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
    let writes: Vec<Passed> = fixture.relay().passed().into_iter().filter(|passed| ["insert", "delete", "set_arrangement"].contains(&passed.op.as_str())).collect();
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

/// A replacement whose second write is refused is taken back whole.
///
/// A change that both removes and inserts is two commits. Another session
/// writes into the draft between the two: the relay lands its write as the
/// insert's ack passes, so the removal, typed against the insert's own
/// commit, is refused. The edit takes its insert back by identity — found
/// where the other writer's bytes moved it to — and answers the refusal, as
/// data: the draft reads exactly as the other writer left it, the three
/// bytes the insert minted arranged nowhere, and no line is held. Called
/// again, the edit lands.
#[test]
fn a_replacement_whose_second_write_is_refused_is_taken_back_whole() {
    let fixture = Fixture::relayed("replace-second");
    let mut mcp = Launch::over(&fixture, 1).logged().spawn();
    mcp.initialize();
    let doc = draft_holding(&mut mcp, CLAIMANT_ACCOUNT, CODE);
    let before = addresses(&mut mcp, &doc);
    let (racer, raced) = (fixture.racer(1), "// raced\n");
    let (rule_doc, landed) = (doc.clone(), Arc::new(AtomicUsize::new(0)));
    let seen = Arc::clone(&landed);
    fixture.relay().on(move |passing| {
        let inserts = passing.frame["op"] == "insert" && passing.frame["doc"] == rule_doc.as_str();
        if inserts && passing.answer.is_some_and(|answer| answer["resp"] == "ack_addr") && seen.load(Ordering::SeqCst) == 0 {
            seen.store(racer.insert(&rule_doc, 1, raced) as usize, Ordering::SeqCst);
        }
    });
    fixture.relay().forget();
    let (is_error, answer) = replace(&mut mcp, &doc, "add", "sub");
    let moved_at = landed.load(Ordering::SeqCst);
    assert!(moved_at > 0, "premise: the other writer's change landed between the two commits");
    assert!(!is_error, "the board's verdict is data: {answer}");
    assert_eq!((&answer["outcome"], &answer["cause"]), (&json!("refused"), &json!("arrangement_moved")), "{answer}\n{}", mcp.log());
    assert_eq!((&answer["refusal"]["op"], &answer["refusal"]["site"]["current"]), (&json!("delete"), &json!(moved_at)), "the removal is the write refused: {answer}");
    let passed = fixture.relay().passed();
    let writes: Vec<(&str, &str)> = passed
        .iter()
        .filter(|passed| ["insert", "delete"].contains(&passed.op.as_str()) && passed.frame["doc"] == doc.as_str())
        .map(|passed| (passed.op.as_str(), passed.answer["resp"].as_str().unwrap_or_default()))
        .collect();
    assert_eq!(writes, [("insert", "ack_addr"), ("delete", "rejected"), ("delete", "ack")], "the insert, the removal refused, and the insert taken back");
    assert_eq!(text_of(&mut mcp, &doc), format!("{raced}{CODE}"), "the draft exactly as the other writer left it");
    assert_eq!(addresses(&mut mcp, &doc)[raced.len()..], before[..], "every byte the draft held keeps its address");
    assert_eq!(minted(&mut mcp, &doc), (CODE.len() + raced.len() + 3) as u64, "the insert's three bytes were minted, and are arranged nowhere");
    assert_eq!(mcp.call_json("held", json!({})), json!([]), "no line of the edit's is held");
    fixture.relay().on(|_| {});
    replaced(&mut mcp, &doc, "add", "sub");
    assert_eq!(text_of(&mut mcp, &doc), format!("{raced}{}", CODE.replace("add", "sub")));
    assert!(mcp.finish().success());
}

/// A replacement that lands in part says exactly what stands.
///
/// Another session writes into the draft ahead of every removal the edit
/// sends — its second write, and each attempt to take its insert back — so
/// neither lands. The answer is `partial`, `isError`: it names the new
/// bytes standing, by their I-address, their commit and their width, and
/// the old bytes not removed, and the board bears each out — the new word
/// read back by identity, standing in the draft directly after the old one,
/// which still stands — with no line held. The edit is then finished as the
/// answer says: `replace_text` with `old` the two together.
#[test]
fn a_replacement_that_lands_in_part_says_exactly_what_stands() {
    let fixture = Fixture::relayed("replace-partial");
    let mut mcp = Launch::over(&fixture, 1).logged().spawn();
    mcp.initialize();
    let doc = draft_holding(&mut mcp, CLAIMANT_ACCOUNT, CODE);
    let racer = fixture.racer(1);
    let (rule_doc, raced) = (doc.clone(), Arc::new(AtomicUsize::new(0)));
    let races = Arc::clone(&raced);
    fixture.relay().on(move |passing| {
        if passing.frame["op"] == "delete" && passing.frame["doc"] == rule_doc.as_str() && passing.answer.is_none() {
            racer.insert(&rule_doc, 1, "/");
            races.fetch_add(1, Ordering::SeqCst);
        }
    });
    let (is_error, answer) = replace(&mut mcp, &doc, "add", "subtract");
    assert!(is_error, "a partial landing is an error: {answer}");
    assert_eq!((&answer["outcome"], &answer["cause"], &answer["refusal"]["op"]), (&json!("partial"), &json!("arrangement_moved"), &json!("delete")), "{answer}\n{}", mcp.log());
    let raced = raced.load(Ordering::SeqCst);
    assert_eq!(raced, 4, "the removal, and three attempts to take the insert back");
    let word = ordinal_of(CODE, "add");
    assert_eq!(answer["old_text"], json!({"ordinal": word.to_string(), "width": "3"}), "{answer}");
    assert_eq!((&answer["new_text"]["ordinal"], &answer["new_text"]["width"]), (&json!((word + 3).to_string()), &json!("8")), "directly after the old word, as the insert left it: {answer}");
    let (addr, at) = (answer["new_text"]["addr"].as_str().expect("the new bytes' address").to_string(), answer["new_text"]["at"].as_u64().expect("the insert's commit"));
    let minted_new = mcp.call_json("retrieve_i", json!({"spans": [{"start": addr, "width": "8"}]}));
    let new_word: String = minted_new["items"].as_array().expect("items").iter().map(|item| item["value"]["content"].as_str().expect("a byte")).collect();
    assert_eq!(new_word, "subtract", "the address names the new word's bytes");
    assert!(at < mcp.position(), "the insert's commit is behind the head");
    let text = text_of(&mut mcp, &doc);
    assert_eq!(text, format!("{}{}", "/".repeat(raced), CODE.replace("add", "addsubtract")), "the new word stands directly after the old, which was not removed");
    let now = addresses(&mut mcp, &doc);
    assert_eq!(now[raced + word + 3 - 1], addr, "the new bytes stand where the image finds their address");
    assert_eq!(mcp.call_json("held", json!({})), json!([]), "no line of the edit's is held");
    fixture.relay().on(|_| {});
    let finished = replaced(&mut mcp, &doc, "addsubtract", "subtract");
    assert_eq!((&finished["removed"], &finished["inserted"]), (&json!("3"), &json!("0")), "finishing is one removal: {finished}");
    assert_eq!(text_of(&mut mcp, &doc), format!("{}{}", "/".repeat(raced), CODE.replace("add", "subtract")));
    assert_eq!(addresses(&mut mcp, &doc)[raced + word - 1], addr, "the new word keeps the identity its insert gave it");
    assert!(mcp.finish().success());
}

/// An edit behind a held line of the agent's is refused, and leaves none.
///
/// A raw insert typed against an older state is held `moved`, and the shell
/// sends no burst of the agent's past a held line. `replace_text` is then
/// refused `behind`, `isError` — the shell could not get its write to the
/// board — its own line dropped: the one line held is still the raw
/// insert's. Once the agent resolves that line, the edit lands.
#[test]
fn an_edit_behind_a_held_line_is_refused_and_leaves_no_line_of_its_own() {
    let fixture = Fixture::new("replace-behind");
    let mut mcp = Launch::over(&fixture, 1).spawn();
    mcp.initialize();
    let stale = mcp.position();
    let doc = draft_holding(&mut mcp, CLAIMANT_ACCOUNT, CODE);
    let held = mcp.call_json("insert", json!({"as_of": stale, "doc": doc, "at": {"subspace": "1", "ordinal": "1"}, "values": ["x"]}));
    assert_eq!((held["resp"].as_str(), held["cause"].as_str()), (Some("held"), Some("moved")), "premise: a stale raw insert is held: {held}");
    let (is_error, answer) = replace(&mut mcp, &doc, "add", "sub");
    assert!(is_error, "the shell could not get the write to the board: {answer}");
    assert_eq!(answer, json!({"outcome": "refused", "cause": "behind", "doc": doc}));
    let lines = mcp.call_json("held", json!({}));
    assert_eq!(lines.as_array().map(Vec::len), Some(1), "the raw insert's line alone: {lines}");
    assert_eq!((&lines[0]["held"], &lines[0]["cause"]), (&held["held"], &json!("moved")), "{lines}");
    assert_eq!(text_of(&mut mcp, &doc), CODE);
    assert_eq!(mcp.call_json("resolve", json!({"held": held["held"], "act": "drop"})), json!({}));
    replaced(&mut mcp, &doc, "add", "sub");
    assert_eq!(text_of(&mut mcp, &doc), CODE.replace("add", "sub"));
    assert!(mcp.finish().success());
}

/// A draft the session does not own is refused by the board, nothing held.
///
/// The agent space's principal reads the claimant's draft, which lies above
/// it, and may not write it: the edit is found, its write refused
/// `not_owner` by the board — the verdict under `refusal`, as data — and
/// the refused run the shell held for it is dropped within the call.
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
        (&json!("refused"), &json!("not_owner"), &json!("not_owner"), &json!("insert")),
        "{answer}"
    );
    assert_eq!(mcp.call_json("held", json!({})), json!([]), "the refused run is dropped within the call");
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

/// One edit inserts as much as one insert carries, and no more.
///
/// A changed text of the insert's cap lands in one commit, and one a byte
/// past it is refused `too_large` before any write, naming the cap — the
/// figure `src/replace.rs` states and the catalog tells an agent (SP-25):
/// a cap the board lowered would fail the first, one it raised leaves the
/// second refusing what the board would take.
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
/// and the same edit by a raw `insert` then `delete` with the positions
/// given. A second, through the relay, splits the call by what it asked of
/// the board: its reads — how many, their bytes and the board's time on
/// them — and each write. Prints its figures; asserts only that each edit
/// landed.
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
            let inserted = mcp.acked("insert", json!({"as_of": typed, "doc": doc, "at": {"subspace": "1", "ordinal": (at + 3).to_string()}, "values": [&new[3..6]]}));
            let deleted = mcp.acked("delete", json!({"as_of": inserted["at"], "doc": doc, "p": {"subspace": "1", "ordinal": at.to_string()}, "width": "3"}));
            raw.push(began.elapsed());
            typed = deleted["at"].as_u64().expect("the delete's commit");
        }
        eprintln!("  {label} ({} bytes): replace_text {:.3}; raw insert + delete, positions given {:.3}", text.len(), median_ms(&mut whole), median_ms(&mut raw));
    }
    assert!(mcp.finish().success());
    // The second pass: the call split by what it asked of the board.
    let fixture = Fixture::relayed("replace-measure-parts");
    let mut mcp = Launch::over(&fixture, 1).spawn();
    mcp.initialize();
    for (label, bytes) in sizes {
        let text = numbered_lines(bytes);
        let doc = draft_holding(&mut mcp, CLAIMANT_ACCOUNT, &text);
        let (mut whole, mut reading, mut inserting, mut deleting) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        let (mut reads, mut read_bytes, mut insert_bytes) = (0, 0, 0);
        for run in 0..runs {
            settle_the_index(&mut mcp);
            let (old, new) = spelled(&text, run % 2 == 1);
            fixture.relay().forget();
            let began = Instant::now();
            replaced(&mut mcp, &doc, &old, &new);
            whole.push(began.elapsed());
            // The edit's exchanges: its reads are those ahead of its insert —
            // the index is settled, so no other reader is about — and its two
            // writes are the one insert and the one delete on the draft.
            let passed = fixture.relay().passed();
            let first_write = passed.iter().position(|passed| passed.op == "insert").expect("the edit's insert");
            let of_the_draft = |passed: &&Passed| passed.frame["doc"] == doc.as_str() || passed.frame["specs"][0]["doc"] == doc.as_str();
            let read: Vec<&Passed> = passed[..first_write].iter().filter(of_the_draft).collect();
            (reads, read_bytes) = (read.len(), read.iter().map(|passed| passed.answer_bytes).sum::<usize>());
            reading.push(read.iter().map(|passed| passed.took).sum());
            inserting.push(passed[first_write].took);
            insert_bytes = passed[first_write].request_bytes;
            deleting.push(passed.iter().find(|passed| passed.op == "delete").expect("the edit's delete").took);
        }
        eprintln!(
            "  {label} ({} bytes), through the relay: replace_text {:.3} — {reads} reads answering {read_bytes} bytes {:.3}, insert (a frame of {insert_bytes} bytes, its signature within) {:.3}, delete {:.3}",
            text.len(),
            median_ms(&mut whole),
            median_ms(&mut reading),
            median_ms(&mut inserting),
            median_ms(&mut deleting)
        );
    }
    assert!(mcp.finish().success());
}
