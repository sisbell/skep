//! Historical reads (wire v3): `/op-at` answers read frames as of any
//! committed position — exact earlier states, rejections included (a
//! document before its creation, a link before its nullification) — with
//! byte-identical answers across repeats and restarts; `/dump?at` is the
//! same determinism for whole worlds. Writes never reach history, and a
//! position beyond the head or between commits is refused with the
//! documented transport errors. Store semantics stay trusted to the stores;
//! these tests assert the transport's history surface.
//!
//! The scenario's documents are PRIVATE drafts (an account's later mints),
//! so every historical read of them below runs as their OWNER — the
//! presented session's principal (PUB-8.13) — and the guest's own cells
//! (`withheld` at every position, ahead of every history refusal, PUB-6.48
//! and PUB-6.49) are pinned in their own test at the end.

use crate::common;

use std::collections::BTreeSet;

use common::*;
use serde_json::Value;

/// One scenario with its positions: doc1 gets "alpha" then loses "lp"
/// (leaving "aha"), doc2 gets "beta", and one link doc1→doc2 is made and
/// then nullified (`retraction` is the retraction link's own minted
/// address). Every field's `at_*` is the committed position the
/// corresponding ack carried. `token` is the owning principal's session,
/// which every read of the drafts presents.
struct Scenario {
    token: String,
    doc1: String,
    doc2: String,
    link: String,
    retraction: String,
    at_c1: u64,
    at_i1: u64,
    at_c2: u64,
    at_i2: u64,
    at_del: u64,
    at_link: u64,
    at_nullify: u64,
}

fn acked_at(v: &Value) -> u64 {
    let resp = v["resp"].as_str().unwrap_or("");
    assert!(
        resp == "ack" || resp == "ack_addr" || resp == "ack_edit",
        "not a write ack: {v}"
    );
    v["at"].as_u64().expect("write acks carry at")
}

fn seed(port: u16) -> Scenario {
    let boot = open_session(port, 0);
    let v = op(port, Some(&boot), r#"{"op":"next_account_prefix","parent":"1"}"#);
    let prefix =
        expect_resp(&v, "maybe_addr")["addr"].as_str().expect("delegable prefix").to_string();
    let v = op(
        port,
        Some(&boot),
        &format!(r#"{{"op":"delegate","new_prefix":"{prefix}","new_id":1}}"#),
    );
    let account = acked_addr(&v);
    let s1 = open_session(port, 1);

    let create = |account: &str| {
        let v = op(
            port,
            Some(&s1),
            &format!(r#"{{"op":"create_new_document","account":"{account}"}}"#),
        );
        (acked_addr(&v), acked_at(&v))
    };
    let insert = |doc: &str, ordinal: u64, text: &str| {
        let v = op(
            port,
            Some(&s1),
            &format!(
                r#"{{"op":"insert","doc":"{doc}","at":{{"subspace":"1","ordinal":"{ordinal}"}},"values":["{text}"]}}"#
            ),
        );
        (acked_addr(&v), acked_at(&v))
    };

    // MINT-FIRST (RES-26): the account's first mint is its doc 1, born
    // published, where bare writes are gated by design. The home is minted
    // and left alone; the scenario's documents are later, private mints.
    create(&account);
    let (doc1, at_c1) = create(&account);
    let (_, at_i1) = insert(&doc1, 1, "alpha");
    let (doc2, at_c2) = create(&account);
    let (_, at_i2) = insert(&doc2, 1, "beta");
    let v = op(
        port,
        Some(&s1),
        &format!(
            r#"{{"op":"delete","doc":"{doc1}","p":{{"subspace":"1","ordinal":"2"}},"width":"2"}}"#
        ),
    );
    let at_del = acked_at(&v);
    let (tdoc, _) = create(&account);
    insert(&tdoc, 1, "T");
    let v = op(
        port,
        Some(&s1),
        &format!(
            concat!(
                r#"{{"op":"make_link","home":"{d1}","#,
                r#""from":[{{"source":"{d1}","span":{{"start":"1.1","width":"0.1"}}}}],"#,
                r#""to":[{{"source":"{d2}","span":{{"start":"1.1","width":"0.1"}}}}],"#,
                r#""ty":[{{"source":"{t}","span":{{"start":"1.1","width":"0.1"}}}}]}}"#
            ),
            d1 = doc1,
            d2 = doc2,
            t = tdoc
        ),
    );
    let link = acked_addr(&v);
    let at_link = acked_at(&v);
    let v = op(
        port,
        Some(&s1),
        &format!(r#"{{"op":"nullify","home":"{doc1}","target":"{link}"}}"#),
    );
    let retraction = acked_addr(&v);
    let at_nullify = acked_at(&v);

    Scenario {
        token: s1,
        doc1,
        doc2,
        link,
        retraction,
        at_c1,
        at_i1,
        at_c2,
        at_i2,
        at_del,
        at_link,
        at_nullify,
    }
}

fn head_of(port: u16) -> u64 {
    let (st, body) = get(port, "/health");
    assert_eq!(st, 200);
    json(&body)["log_position"].as_u64().expect("log_position")
}

/// One `/op-at` exchange presenting `token` (`None` = the guest).
fn op_at_raw(port: u16, token: Option<&str>, at: u64, frame: &str) -> (u16, Vec<u8>) {
    let body = format!(r#"{{"at":{at},"frame":{frame}}}"#);
    http(port, "POST", "/op-at", token, body.as_bytes())
}

fn op_at(port: u16, token: Option<&str>, at: u64, frame: &str) -> (u16, Value) {
    let (st, body) = op_at_raw(port, token, at, frame);
    (st, json(&body))
}

/// A 200 historical answer, shape-checked.
fn op_at_ok(port: u16, token: Option<&str>, at: u64, frame: &str) -> Value {
    let (st, v) = op_at(port, token, at, frame);
    assert_eq!(st, 200, "historical read failed: {v}");
    v
}

fn retrieve(doc: &str, width: u64) -> String {
    format!(
        r#"{{"op":"retrieve_v","specs":[{{"doc":"{doc}","span":{{"start":"1.1","width":"0.{width}"}}}}]}}"#
    )
}

fn spanset(doc: &str) -> String {
    format!(r#"{{"op":"retrieve_doc_v_span_set","doc":"{doc}"}}"#)
}

fn read_link(a: &str) -> String {
    format!(r#"{{"op":"read_link","a":"{a}"}}"#)
}

fn find_links(doc: &str) -> String {
    format!(
        r#"{{"op":"find_links_v","d":"{doc}","region":[{{"start":"1.1","width":"0.1"}}]}}"#
    )
}

/// The retracted-links read over the same region, from the start.
fn find_links_history(doc: &str) -> String {
    format!(
        r#"{{"op":"find_links_v_history","cur":null,"n":16,"d":"{doc}","region":[{{"start":"1.1","width":"0.1"}}]}}"#
    )
}

/// A `links` answer's rows as `(a, at, retracted_at)`.
fn rows_of(v: &Value) -> Vec<(String, Option<u64>, Option<u64>)> {
    expect_resp(v, "links")["links"]
        .as_array()
        .expect("links")
        .iter()
        .map(|r| (r["a"].as_str().expect("a").to_string(), r["at"].as_u64(), r["retracted_at"].as_u64()))
        .collect()
}

/// An `addrs` answer's addresses.
fn addrs_in(v: &Value) -> Vec<String> {
    expect_resp(v, "addrs")["addrs"]
        .as_array()
        .expect("addrs")
        .iter()
        .map(|a| a.as_str().expect("an address").to_string())
        .collect()
}

/// THE RETRACTED-LINKS READ AGAINST THE REPLAY (the link-sets design §7,
/// lane 7: `/op-at` stays the forensic replay, never the switch): on the
/// scenario's board the LIVE `find_links_v_history` at the head answers the
/// link as a row retracted at the retraction's position and the retraction
/// as an active row at its own — the active rows exactly the head's
/// `find_links_v`, on `/op` and on `/op-at` alike, and the retracted rows
/// exactly the links `/op-at`'s `find_links_v` answered at the position
/// before the retraction and the head's does not. Replayed itself at each
/// of the three positions the suite uses, the read answers what stood: no
/// row before the link, the link active at its mint, and at the retraction
/// the head's own answer — a rebuilt world's hint agreeing with the live
/// one. `/op-at` at the head is byte-identical to `/op`.
#[test]
fn the_retracted_links_read_at_the_head_agrees_with_the_replay_at_each_position() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let scenario = seed(port);
    let head = head_of(port);
    let owner = Some(scenario.token.as_str());
    let (link, retraction) = (scenario.link.clone(), scenario.retraction.clone());

    // The live read at the head: the link, retracted at the retraction's
    // position; the retraction, active at its own.
    let live = op(port, owner, &find_links_history(&scenario.doc1));
    assert_eq!(
        rows_of(&live),
        vec![
            (link.clone(), Some(scenario.at_link), Some(scenario.at_nullify)),
            (retraction.clone(), Some(scenario.at_nullify), None),
        ],
        "{live}"
    );
    assert_eq!(live["exhausted"], Value::Bool(true));
    assert_eq!(live["next"].as_str(), Some(retraction.as_str()));
    let active_rows: Vec<String> =
        rows_of(&live).into_iter().filter(|(_, _, r)| r.is_none()).map(|(a, _, _)| a).collect();
    let retracted_rows: Vec<String> =
        rows_of(&live).into_iter().filter(|(_, _, r)| r.is_some()).map(|(a, _, _)| a).collect();
    // The active rows are the head's `find_links_v`, live and replayed.
    assert_eq!(active_rows, addrs_in(&op(port, owner, &find_links(&scenario.doc1))));
    assert_eq!(active_rows, addrs_in(&op_at_ok(port, owner, head, &find_links(&scenario.doc1))));
    // The retracted rows are what the replay answered before the retraction
    // and the head does not.
    let before = addrs_in(&op_at_ok(port, owner, scenario.at_link, &find_links(&scenario.doc1)));
    let gone: Vec<String> = before.into_iter().filter(|a| !active_rows.contains(a)).collect();
    assert_eq!(retracted_rows, gone, "the replay before the retraction found exactly the retracted rows");

    // The read replayed at the three positions: nothing, the link active,
    // the head's answer.
    let v = op_at_ok(port, owner, scenario.at_i2, &find_links_history(&scenario.doc1));
    assert_eq!(rows_of(&v), vec![]);
    assert_eq!(v["as_of"].as_u64(), Some(scenario.at_i2));
    let v = op_at_ok(port, owner, scenario.at_link, &find_links_history(&scenario.doc1));
    assert_eq!(rows_of(&v), vec![(link.clone(), Some(scenario.at_link), None)], "not yet retracted at its mint");
    let v = op_at_ok(port, owner, scenario.at_nullify, &find_links_history(&scenario.doc1));
    assert_eq!(rows_of(&v), rows_of(&live), "the rebuilt world's hint agrees with the live one");
    let (st, replayed) = op_at_raw(port, owner, head, &find_links_history(&scenario.doc1));
    let (st_live, live_bytes) =
        http(port, "POST", "/op", owner, find_links_history(&scenario.doc1).as_bytes());
    assert_eq!((st, st_live), (200, 200));
    assert_eq!(replayed, live_bytes, "/op-at at the head is byte-identical to /op");
    sd.shutdown();
}

#[test]
fn historical_reads_answer_every_earlier_state() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let scenario = seed(port);
    let head = head_of(port);
    assert_eq!(head, scenario.at_nullify, "the last write's at is the head");
    let owner = Some(scenario.token.as_str());

    // ── content history: the text at each position, as_of = the position ──
    let v = op_at_ok(port, owner, scenario.at_i1, &retrieve(&scenario.doc1, 5));
    assert_eq!(expect_resp(&v, "delivery")["as_of"].as_u64(), Some(scenario.at_i1));
    let expect: Value = serde_json::from_str(r#"[{"content":"alpha"}]"#).expect("json");
    assert_eq!(v["items"], expect, "doc1's text as of its insert");

    let v = op_at_ok(port, owner, scenario.at_del, &retrieve(&scenario.doc1, 3));
    assert_eq!(v["as_of"].as_u64(), Some(scenario.at_del));
    let expect: Value = serde_json::from_str(r#"[{"content":"aha"}]"#).expect("json");
    assert_eq!(v["items"], expect, "doc1's text as of the delete");

    // ── arrangement history: one contiguous run before the delete ──
    let v = op_at_ok(port, owner, scenario.at_i1, &spanset(&scenario.doc1));
    assert_eq!(expect_resp(&v, "span_set")["as_of"].as_u64(), Some(scenario.at_i1));
    let expect: Value =
        serde_json::from_str(r#"[{"start":"1.1","width":"0.5"}]"#).expect("json");
    assert_eq!(v["set"], expect);
    let v_after = op_at_ok(port, owner, scenario.at_del, &spanset(&scenario.doc1));
    assert_eq!(v_after["as_of"].as_u64(), Some(scenario.at_del));
    assert_ne!(v_after["set"], expect, "the delete must be visible in the span set");

    // ── a document BEFORE its creation: that position's own rejection ──
    //    (to its OWNER — the head-set check admits the owner, and the
    //    N-world's registration check then speaks, PUB-6.49)
    assert!(scenario.at_i1 < scenario.at_c2);
    let v = op_at_ok(port, owner, scenario.at_i1, &spanset(&scenario.doc2));
    let rej = expect_resp(&v, "rejected");
    assert_eq!(rej["op"].as_str(), Some("retrieve_doc_v_span_set"));
    assert_eq!(rej["code"].as_str(), Some("doc_not_registered"));
    // Position 0 is genesis: before every document.
    let v = op_at_ok(port, owner, 0, &spanset(&scenario.doc1));
    assert_eq!(expect_resp(&v, "rejected")["code"].as_str(), Some("doc_not_registered"));

    // ── link history: absent → discoverable → nullified-but-readable ──
    let v = op_at_ok(port, owner, scenario.at_i2, &read_link(&scenario.link));
    assert_eq!(expect_resp(&v, "link_value")["as_of"].as_u64(), Some(scenario.at_i2));
    assert!(v["link"].is_null(), "the link does not exist yet at {}", scenario.at_i2);
    let v = op_at_ok(port, owner, scenario.at_i2, &find_links(&scenario.doc1));
    assert_eq!(expect_resp(&v, "addrs")["addrs"], Value::Array(vec![]));

    let v = op_at_ok(port, owner, scenario.at_link, &read_link(&scenario.link));
    assert_eq!(
        v["link"]["slots"].as_array().map(Vec::len),
        Some(3),
        "the link exists as of its creation: {v}"
    );
    let v = op_at_ok(port, owner, scenario.at_link, &find_links(&scenario.doc1));
    let addrs = expect_resp(&v, "addrs")["addrs"].as_array().expect("addrs").clone();
    assert!(addrs.iter().any(|a| a.as_str() == Some(scenario.link.as_str())));

    let v = op_at_ok(port, owner, scenario.at_nullify, &read_link(&scenario.link));
    assert!(
        v["link"]["slots"].is_array(),
        "a nullified link still reads back (audit permanence): {v}"
    );
    // The nullified link leaves active discovery; the retraction takes its
    // place (a retraction is itself an active link whose document-homed FROM
    // covers every content extent of doc1 — M7's contract, replayed here as
    // the state a live client saw at that position).
    let v = op_at_ok(port, owner, scenario.at_nullify, &find_links(&scenario.doc1));
    assert_eq!(
        expect_resp(&v, "addrs")["addrs"],
        Value::Array(vec![Value::String(scenario.retraction.clone())]),
        "at the nullify position, active discovery holds exactly the retraction"
    );

    // ── determinism, and history-at-head ≡ the live answer (same session) ──
    let (st1, b1) = op_at_raw(port, owner, scenario.at_i1, &retrieve(&scenario.doc1, 5));
    let (st2, b2) = op_at_raw(port, owner, scenario.at_i1, &retrieve(&scenario.doc1, 5));
    assert_eq!((st1, st2), (200, 200));
    assert_eq!(b1, b2, "equal positions must answer byte-identically");
    let (st, hist) = op_at_raw(port, owner, head, &retrieve(&scenario.doc1, 3));
    let (st_live, live) = http(port, "POST", "/op", owner, retrieve(&scenario.doc1, 3).as_bytes());
    assert_eq!((st, st_live), (200, 200));
    assert_eq!(hist, live, "/op-at at the head is byte-identical to /op");

    // ── the refusals, with the documented bodies ──
    let (st, v) = op_at(port, owner, head, r#"{"op":"fork"}"#);
    assert_eq!(st, 400);
    assert_eq!(v, serde_json::json!({"error": "write_at_history"}));

    let (st, v) = op_at(port, owner, head + 7, &retrieve(&scenario.doc1, 3));
    assert_eq!(st, 400);
    assert_eq!(v, serde_json::json!({"error": "beyond_head", "head": head}));

    // An insert commits content + placement in one composite, so its ack's
    // position sits ≥ 2 past the previous boundary — the seq between is an
    // interior coordinate, never observable, never a position.
    assert!(scenario.at_i1 >= scenario.at_c1 + 2, "insert must be a multi-record commit");
    let (st, v) = op_at(port, owner, scenario.at_c1 + 1, &retrieve(&scenario.doc1, 3));
    assert_eq!(st, 400);
    assert_eq!(v, serde_json::json!({"error": "not_a_position", "nearest": scenario.at_c1}));

    // Envelope faults are transport errors; an unparseable FRAME is answered
    // on the op channel like /op answers it.
    for bad in [
        r#"{"frame":{"op":"fork"}}"#.to_string(),
        format!(r#"{{"at":"{}","frame":{{"op":"fork"}}}}"#, head),
        format!(r#"{{"at":{head}}}"#),
        format!(r#"{{"at":{head},"frame":{{"op":"fork"}},"stray":1}}"#),
        format!(r#"{{"at":{head},"frame":"fork"}}"#),
    ] {
        let (st, body) = http(port, "POST", "/op-at", None, bad.as_bytes());
        assert_eq!(st, 400, "envelope fault must be a 400: {bad}");
        assert_eq!(json(&body)["error"].as_str(), Some("malformed_op_at"), "{bad}");
    }
    let (st, v) = op_at(port, None, head, r#"{"op":"frobnicate"}"#);
    assert_eq!(st, 200);
    let rej = expect_resp(&v, "rejected");
    assert_eq!(rej["op"].as_str(), Some("unparseable"));

    sd.shutdown();
}

/// The read shapes the history route stamps: every one M10's
/// `Response::as_of_mut` classifies as carrying an `as_of`. Nineteen: the
/// seventeen of lane 3.4, the owner-of-address read's `effective_owner`
/// (AUTH-6.37) and the any-principal discovery read's `universal_grants`
/// (PUB-8.47). The test below counts the shapes its rows visit against this,
/// so its rows are known to reach every one.
const STAMPED_SHAPES: usize = 19;

/// wire.md §The response envelope: `as_of` reports the position the answer
/// is OF. On the history surface `stamp_as_of` is what makes that true —
/// the throwaway kernel is rooted at the historical world with its own seq
/// at 0, so M10's live stamping must be overwritten.
///
/// Which shapes carry an `as_of` is M10's classification, and M10's own
/// coordinate law holds `Response::as_of_mut` to every read shape. What this
/// pins is the other half, over the wire: that the history route APPLIES
/// the stamp to each of them. A shape the route left unstamped would answer
/// `as_of: 0` at every position, and a client scrubbing history or
/// correlating a historical read with `/changes` would read the answer as
/// one of genesis.
#[test]
fn every_read_shape_stamps_the_position_it_is_of() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let scenario = seed(port);
    let owner = Some(scenario.token.as_str());
    // Neither 0 nor the head, so a stamp that answered the throwaway
    // kernel's own seq and one that answered the LIVE head both show.
    let at = scenario.at_link;
    assert!(at > 0 && at < head_of(port), "the fixture position is interior");

    let (d1, d2, link) = (&scenario.doc1, &scenario.doc2, &scenario.link);
    let region = r#"[{"start":"1.1","width":"0.1"}]"#;
    let span = r#"{"start":"1.1","width":"0.1"}"#;
    let rows: Vec<(&str, String)> = vec![
        ("delivery", retrieve(d1, 1)),
        ("span_set", spanset(d1)),
        ("addrs", find_links(d1)),
        ("addrs", format!(r#"{{"op":"show_origin","doc":"{d1}","span":{span}}}"#)),
        ("maybe_addr", r#"{"op":"next_account_prefix","parent":"1"}"#.into()),
        ("count", format!(r#"{{"op":"count_v","d":"{d1}","region":{region}}}"#)),
        (
            "page",
            format!(r#"{{"op":"window_v","d":"{d1}","region":{region},"cur":null,"n":4}}"#),
        ),
        ("endsets", format!(r#"{{"op":"retrieve_endsets","d":"{d1}","region":{region}}}"#)),
        ("runs", format!(r#"{{"op":"image","d":"{d1}","region":{region}}}"#)),
        ("bool", format!(r#"{{"op":"discoverable_from","a":"{link}","d":"{d1}"}}"#)),
        ("link_value", read_link(link)),
        ("follow", format!(r#"{{"op":"follow_link","a":"{link}","slot":1}}"#)),
        ("deletions", format!(r#"{{"op":"show_deletions","d_a":"{d1}","d_b":"{d2}"}}"#)),
        (
            "compare",
            format!(
                r#"{{"op":"compare","rho1":[{{"doc":"{d1}","spans":{region}}}],"rho2":[{{"doc":"{d2}","spans":{region}}}]}}"#
            ),
        ),
        (
            "orphans",
            format!(
                r#"{{"op":"delete_orphans","d":"{d1}","p":{{"subspace":"1","ordinal":"1"}},"width":"1"}}"#
            ),
        ),
        ("claims", format!(r#"{{"op":"in_claims","y":"{link}","view":"default"}}"#)),
        ("claims", format!(r#"{{"op":"out_claims","x":"{link}","view":"default"}}"#)),
        ("doc_metadata", format!(r#"{{"op":"doc_metadata","doc":"{d1}"}}"#)),
        // The one row whose argument is a DOCUMENT rather than the link:
        // M10 refuses an unregistered target `doc_not_registered`.
        ("edition_claims", format!(r#"{{"op":"edition_claims","target":"{d2}"}}"#)),
        // The owner-of-address read (AUTH-6.37): a registry probe, no
        // document argument, answered for any address.
        ("effective_owner", format!(r#"{{"op":"effective_owner","addr":"{d1}"}}"#)),
        // The any-principal discovery read (PUB-8.47): no argument; the
        // owner is bound, so the SHAPE answers — its rows empty on this
        // board, and `as_of` still the position asked.
        ("universal_grants", r#"{"op":"universal_grants"}"#.to_string()),
    ];

    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for (shape, frame) in &rows {
        let v = op_at_ok(port, owner, at, frame);
        // The SHAPE first: a rejection carries no `as_of` at all, so a row
        // whose frame does not answer would pass the stamp check vacuously.
        assert_eq!(v["resp"].as_str(), Some(*shape), "{frame}: {v}");
        assert_eq!(
            v["as_of"].as_u64(),
            Some(at),
            "{shape} must stamp the position it is OF, not the throwaway kernel's 0: {v}"
        );
        seen.insert(*shape);
    }
    assert_eq!(seen.len(), STAMPED_SHAPES, "every stamped shape is visited: {seen:?}");

    sd.shutdown();
}

/// wire.md §Reading history: an `id` in a historical frame is accepted and
/// ignored. A client replaying a frame it stored from `/op` must get the
/// ordinary answer — and, since reads are never memoized, the same `id` at
/// a different position must answer THAT position, never replay the first.
#[test]
fn op_at_accepts_and_ignores_a_frame_id() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let scenario = seed(port);
    let owner = Some(scenario.token.as_str());

    let with_id = format!(
        r#"{{"op":"retrieve_v","id":"stored-key-1","specs":[{{"doc":"{}","span":{{"start":"1.1","width":"0.5"}}}}]}}"#,
        scenario.doc1
    );
    let (st_plain, plain) = op_at_raw(port, owner, scenario.at_i1, &retrieve(&scenario.doc1, 5));
    let (st_id, id_body) = op_at_raw(port, owner, scenario.at_i1, &with_id);
    assert_eq!((st_plain, st_id), (200, 200), "{}", String::from_utf8_lossy(&id_body));
    assert_eq!(id_body, plain, "an id in a historical frame changes nothing about the answer");

    let (st, later) = op_at_raw(port, owner, scenario.at_del, &with_id);
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&later));
    assert_ne!(
        later, id_body,
        "a read is never memoized, so an id cannot replay an earlier position's answer"
    );

    sd.shutdown();
}

#[test]
fn history_answers_survive_restart() {
    let dir = tempfile::tempdir().expect("tempdir");

    let probes: Vec<(u64, String)>;
    let before: Vec<Vec<u8>>;
    #[cfg(feature = "observe")]
    let dump_probe: String;
    #[cfg(feature = "observe")]
    let dump_before: Vec<u8>;

    // ── first life: seed, then capture every probe's exact bytes ──
    {
        let sd = spawn(dir.path());
        let port = sd.port();
        let scenario = seed(port);
        let owner = Some(scenario.token.as_str());
        probes = vec![
            (scenario.at_i1, retrieve(&scenario.doc1, 5)),
            (scenario.at_del, retrieve(&scenario.doc1, 3)),
            (scenario.at_i1, spanset(&scenario.doc1)),
            (scenario.at_i1, spanset(&scenario.doc2)), // a rejection is history too
            (0, spanset(&scenario.doc1)),
            (scenario.at_i2, read_link(&scenario.link)),
            (scenario.at_nullify, read_link(&scenario.link)),
            (scenario.at_link, find_links(&scenario.doc1)),
            (scenario.at_nullify, find_links(&scenario.doc1)),
        ];
        before = probes
            .iter()
            .map(|(at, frame)| {
                let (st, body) = op_at_raw(port, owner, *at, frame);
                assert_eq!(st, 200, "probe at {at} failed: {}", String::from_utf8_lossy(&body));
                body
            })
            .collect();
        #[cfg(feature = "observe")]
        {
            dump_probe = format!("/dump?at={}", scenario.at_link);
            let (st, body) = get(port, &dump_probe);
            assert_eq!(st, 200);
            dump_before = body;
        }
        sd.shutdown();
    }

    // ── second life: every historical answer is byte-identical, for
    //    positions committed entirely before this process existed. Sessions
    //    are uptime-scoped, so the owner re-authenticates: the same
    //    principal, a fresh token. ──
    {
        let sd = spawn(dir.path());
        let port = sd.port();
        let s1 = open_session(port, 1);
        let owner = Some(s1.as_str());
        for ((at, frame), expected) in probes.iter().zip(&before) {
            let (st, body) = op_at_raw(port, owner, *at, frame);
            assert_eq!(st, 200);
            assert_eq!(
                &body,
                expected,
                "history at {at} drifted across restart:\n before {}\n after  {}",
                String::from_utf8_lossy(expected),
                String::from_utf8_lossy(&body),
            );
        }
        #[cfg(feature = "observe")]
        {
            let (st, body) = get(port, &dump_probe);
            assert_eq!(st, 200);
            assert_eq!(body, dump_before, "historical dump drifted across restart");
        }
        sd.shutdown();
    }
}

/// The reconstruction permit: at most 2 `world_at` rebuilds run at once;
/// a surplus caller is refused `503 history_busy` instead of queueing.
/// A real reconstruction finishes in milliseconds, so true concurrency
/// cannot be raced from the wire — the permits are pinned through the
/// daemon's doc(hidden) test hook (holding one is exactly what an
/// in-flight `world_at` holds), and the counter accounting is asserted
/// directly alongside the wire's busy answer.
///
/// Every `/op-at` frame kind is held to that budget, `key_set` included: it
/// reconstructs through its OWN arm of the route — `History::reconstruct`
/// beside `read_at`, the canonical identity rebuilt over the world it hands
/// back (AUTH-6.20) — so no `read_at` row reaches it.
#[test]
fn op_at_reconstruction_is_permit_bounded() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let scenario = seed(port);
    let owner = Some(scenario.token.as_str());

    // Sanity: the historical read serves before any permit is pinned.
    op_at_ok(port, owner, scenario.at_i1, &retrieve(&scenario.doc1, 5));

    // The accounting, directly: 2 acquires succeed, the 3rd fails, a drop
    // reopens exactly one slot.
    let daemon = sd.daemon();
    let p1 = daemon.try_hold_reconstruction_permit().expect("permit 1 of 2");
    let p2 = daemon.try_hold_reconstruction_permit().expect("permit 2 of 2");
    assert!(
        daemon.try_hold_reconstruction_permit().is_none(),
        "the reconstruction permit is exactly 2"
    );

    // N+1 concurrent /op-at calls while both slots are held: every one is
    // answered 503 history_busy at once — none queues behind replay.
    let answers: Vec<(u16, Value)> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..3)
            .map(|_| s.spawn(|| op_at(port, owner, scenario.at_i1, &retrieve(&scenario.doc1, 5))))
            .collect();
        handles.into_iter().map(|jh| jh.join().expect("op-at caller thread")).collect()
    });
    for (st, v) in &answers {
        assert_eq!(*st, 503, "saturated reconstruction must answer busy: {v}");
        assert_eq!(v["error"].as_str(), Some("history_busy"), "{v}");
    }
    // The `key_set` frame, through its own arm: busy too — never an
    // unbudgeted whole-world replay and identity rebuild for any guest.
    let key_set_frame = format!(r#"{{"op":"key_set","account":"{CLAIMANT_ACCOUNT}"}}"#);
    let (st, v) = op_at(port, None, scenario.at_i1, &key_set_frame);
    assert_eq!(st, 503, "a historical key_set is a reconstruction too: {v}");
    assert_eq!(v["error"].as_str(), Some("history_busy"), "{v}");

    // Only position-addressed reconstruction is gated: live reads (and the
    // plain head dump) serve while history is saturated.
    let v = op(port, owner, &retrieve(&scenario.doc1, 3));
    expect_resp(&v, "delivery");
    #[cfg(feature = "observe")]
    {
        let (st, _body) = get(port, "/dump");
        assert_eq!(st, 200, "the head dump is not permit-gated");
        let (st, body) = get(port, &format!("/dump?at={}", scenario.at_i1));
        assert_eq!(st, 503, "/dump?at rides the same permit");
        assert_eq!(json(&body)["error"].as_str(), Some("history_busy"));
    }

    // Releasing one slot restores service through the wire, and the wire
    // call returns its permit: the slot is reusable afterwards.
    drop(p1);
    let v = op_at_ok(port, owner, scenario.at_i1, &retrieve(&scenario.doc1, 5));
    assert_eq!(v["as_of"].as_u64(), Some(scenario.at_i1));
    let p3 = daemon.try_hold_reconstruction_permit().expect("the wire call released its permit");
    assert!(daemon.try_hold_reconstruction_permit().is_none());
    drop(p3);
    drop(p2);
    op_at_ok(port, owner, scenario.at_i1, &retrieve(&scenario.doc1, 5));
    let v = op_at_ok(port, None, scenario.at_i1, &key_set_frame);
    assert_eq!(
        expect_resp(&v, "key_set")["as_of"].as_u64(),
        Some(scenario.at_i1),
        "and served once a permit is free: {v}"
    );

    sd.shutdown();
}

/// EACH HISTORICAL ANSWER LOADS ONE BASE, AND A REFUSAL AHEAD OF THE REPLAY
/// NONE — the history surface's cost in the kernel's own unit
/// (`Daemon::bases_loaded`, counting each base a history read selects: a
/// whole checkpoint deserialized and seeded, or genesis). An `/op-at` read,
/// an `/op-at` `key_set`, a `/chain?at` and (in `observe` builds) a
/// `/dump?at` each move the count by ONE — the chain read included, which
/// folds no world and loads its base all the same (`Kernel::chain_at`'s
/// card) — and `history_busy` with the pool held, `beyond_head`, and the
/// guest's `withheld` at the head's check (PUB-6.49) move it by none. The
/// cadence is parked, so no landing's reclaim-floor probe moves the count
/// between two answers.
#[test]
fn each_historical_answer_loads_one_base_and_a_refusal_ahead_of_the_replay_none() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    sd.daemon().park_the_cadence();
    let port = sd.port();
    let scenario = seed(port);
    let owner = Some(scenario.token.as_str());
    let at = scenario.at_i1;
    let cost = |answer: &dyn Fn()| {
        let before = sd.daemon().bases_loaded();
        answer();
        sd.daemon().bases_loaded() - before
    };
    let read = || {
        op_at_ok(port, owner, at, &retrieve(&scenario.doc1, 5));
    };
    assert_eq!(cost(&read), 1, "an /op-at read");
    let key_set = || {
        let frame = format!(r#"{{"op":"key_set","account":"{CLAIMANT_ACCOUNT}"}}"#);
        let (st, v) = op_at(port, owner, at, &frame);
        assert_eq!(st, 200, "{v}");
    };
    assert_eq!(cost(&key_set), 1, "an /op-at key_set");
    let chain = || {
        let (st, body) = get(port, &format!("/chain?at={at}"));
        assert_eq!(st, 200, "{}", String::from_utf8_lossy(&body));
    };
    assert_eq!(cost(&chain), 1, "a /chain?at: no world folded, its base loaded all the same");
    #[cfg(feature = "observe")]
    {
        let dump = || assert_eq!(get(port, &format!("/dump?at={at}")).0, 200);
        assert_eq!(cost(&dump), 1, "a /dump?at");
    }
    let held: Vec<_> =
        (0..2).map(|_| sd.daemon().try_hold_reconstruction_permit().expect("a permit")).collect();
    let busy = || {
        let (st, v) = op_at(port, owner, at, &retrieve(&scenario.doc1, 5));
        assert_eq!((st, v["error"].as_str()), (503, Some("history_busy")), "{v}");
    };
    assert_eq!(cost(&busy), 0, "history_busy: the permit before the journal");
    drop(held);
    let head = head_of(port);
    let beyond = || {
        let (st, v) = op_at(port, owner, head + 1_000, &retrieve(&scenario.doc1, 5));
        assert_eq!((st, v["error"].as_str()), (400, Some("beyond_head")), "{v}");
    };
    assert_eq!(cost(&beyond), 0, "beyond_head: refused ahead of the base");
    let withheld = || {
        let (st, v) = op_at(port, None, at, &retrieve(&scenario.doc1, 5));
        assert_eq!((st, v["code"].as_str()), (200, Some("withheld")), "{v}");
    };
    assert_eq!(cost(&withheld), 0, "the guest's withheld, at the head's check (PUB-6.49)");
    sd.shutdown();
}

/// The reconstruction permit is taken AFTER the frame is classified and
/// BEFORE the journal sees `at` — `Unavailable::Busy`, `History::reconstruct`
/// and `refuse_unavailable` each say so, and the order decides what
/// disposition a client is handed.
///
/// The fear is the tidy inversion: pre-checking `at` against the head before
/// taking a permit answers `beyond_head` here, turning a documented
/// retry-class refusal into a permanent one with nothing to notice. The
/// write probe is the same seam from the other side.
#[test]
fn saturation_precedes_the_journals_verdict_and_not_the_write_refusal() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let scenario = seed(port);
    let head = head_of(port);
    let owner = Some(scenario.token.as_str());

    // With a permit free, the journal's own verdict answers. `at_c1 + 1` is
    // inside the insert's commit — a coordinate, not a position.
    let bad: [(&str, u64, &str); 2] = [
        ("beyond the head", head + 7, "beyond_head"),
        ("between commits", scenario.at_c1 + 1, "not_a_position"),
    ];
    for (what, at, err) in bad {
        let (st, v) = op_at(port, owner, at, &retrieve(&scenario.doc1, 3));
        assert_eq!(st, 400, "{what}: {v}");
        assert_eq!(v["error"].as_str(), Some(err), "{what}: the journal's verdict");
    }

    // Exhaust the budget through the hook rather than racing a
    // millisecond-long reconstruction.
    let daemon = sd.daemon();
    let mut held = Vec::new();
    while let Some(p) = daemon.try_hold_reconstruction_permit() {
        held.push(p);
    }
    assert!(!held.is_empty(), "the daemon has a reconstruction budget to exhaust");

    for (what, at, _) in bad {
        let (st, v) = op_at(port, owner, at, &retrieve(&scenario.doc1, 3));
        assert_eq!(st, 503, "{what} under saturation: {v}");
        assert_eq!(
            v["error"].as_str(),
            Some("history_busy"),
            "{what}: saturation masks the journal's verdict, which is why a Busy \
             answer says nothing about whether `at` is a good position"
        );
    }

    // …and does NOT mask what is decided before the permit: the frame is
    // classified first, so a write is still refused at the transport, and
    // the HEAD-SET CHECK runs first too (PUB-6.49) — a guest asking about the
    // draft under saturation is answered `withheld`, never `history_busy`,
    // and occupies no permit (PUB-7.11).
    let (st, v) = op_at(port, owner, head, r#"{"op":"fork"}"#);
    assert_eq!(st, 400, "{v}");
    assert_eq!(v, serde_json::json!({"error": "write_at_history"}));
    let (st, v) = op_at(port, None, scenario.at_i1, &retrieve(&scenario.doc1, 3));
    assert_eq!(st, 200, "{v}");
    assert_eq!(
        expect_resp(&v, "rejected")["code"].as_str(),
        Some("withheld"),
        "the head-set check precedes history_busy (PUB-6.49): {v}"
    );

    drop(held);
    sd.shutdown();
}

/// PUB-6.48 / PUB-6.49 / PUB-8.13 over the wire: `/op-at` honors the
/// presented session and evaluates `readable()` against the HEAD's sets.
/// A guest and a non-entitled principal answer `withheld` on the draft at
/// EVERY position — a position before the draft's creation included, where
/// the owner is answered that position's own `doc_not_registered` — and a
/// grant committed AFTER a position satisfies a read AT that position: the
/// grantee, refused before the grant, reads the same `at` once it lands,
/// and its answer equals the owner's byte for byte.
#[test]
fn op_at_reads_as_the_presented_session_against_the_head_s_sets() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    // The draft is the CLAIMANT's (its second mint — the home is the ceremony's
    // doc 1), so the grant below can be deposited from the claimant's SIGNED
    // session into its published home.
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let v = op(
        port,
        Some(&bare),
        &format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"}}"#),
    );
    let draft = acked_addr(&v);
    let at_created = acked_at(&v);
    let v = op(
        port,
        Some(&bare),
        &format!(
            r#"{{"op":"insert","doc":"{draft}","at":{{"subspace":"1","ordinal":"1"}},"values":["omega"]}}"#
        ),
    );
    let at_written = acked_at(&v);
    // A stranger under node [1]: outside the claimant's subtree.
    let boot = open_session(port, 0);
    let v = op(port, Some(&boot), r#"{"op":"next_account_prefix","parent":"1"}"#);
    let b_account = expect_resp(&v, "maybe_addr")["addr"].as_str().expect("prefix").to_string();
    expect_resp(
        &op(
            port,
            Some(&boot),
            &format!(r#"{{"op":"delegate","new_prefix":"{b_account}","new_id":901}}"#),
        ),
        "ack_addr",
    );
    let b = open_session(port, 901);
    let before_draft = at_created - 1;

    // The guest and the stranger: withheld at every position — after the
    // write, at the creation, and BEFORE the creation, where the owner is
    // told that position's own registration answer instead.
    for token in [None, Some(b.as_str())] {
        for at in [at_written, at_created, before_draft] {
            let (st, v) = op_at(port, token, at, &retrieve(&draft, 5));
            assert_eq!(st, 200, "{v}");
            let rej = expect_resp(&v, "rejected");
            assert_eq!(rej["code"].as_str(), Some("withheld"), "at {at}: {v}");
            assert_eq!(rej["disposition"].as_str(), Some("reorder"), "{v}");
            assert_eq!(rej["site"]["addr"].as_str(), Some(draft.as_str()), "{v}");
            assert!(rej.get("detail").is_none(), "withheld carries no detail: {v}");
        }
    }
    let v = op_at_ok(port, Some(&bare), before_draft, &retrieve(&draft, 5));
    assert_eq!(
        expect_resp(&v, "rejected")["code"].as_str(),
        Some("doc_not_registered"),
        "the owner meets the N-world's registration check, after the head-set check: {v}"
    );
    let owner_view = op_at_ok(port, Some(&bare), at_written, &retrieve(&draft, 5));
    let expect: Value = serde_json::from_str(r#"[{"content":"omega"}]"#).expect("json");
    assert_eq!(expect_resp(&owner_view, "delivery")["items"], expect);

    // A grant to B, committed AFTER `at_written`, in the claimant's published
    // home (the GRANTS class, `to` the grantee account).
    let v = op(
        port,
        Some(&signed),
        &format!(
            r#"{{"op":"make_link","home":"{CLAIMANT_DOC1}","from":{{"addrs":["{draft}"]}},"to":{{"addrs":["{b_account}"]}},"ty":{{"addrs":["1.1.0.1.0.1.0.3.90"]}}}}"#
        ),
    );
    let at_grant = acked_at(&v);
    assert!(at_grant > at_written);
    // The grantee now reads AT `at_written` — a position before the grant —
    // because the predicate is the head's (PUB-6.48), and reads exactly what
    // the owner reads there.
    let (st, grantee_view) = op_at_raw(port, Some(&b), at_written, &retrieve(&draft, 5));
    assert_eq!(st, 200);
    let (st, owner_bytes) = op_at_raw(port, Some(&bare), at_written, &retrieve(&draft, 5));
    assert_eq!(st, 200);
    assert_eq!(
        grantee_view, owner_bytes,
        "the grantee's historical answer is the owner's, byte for byte, once the head holds the grant"
    );
    // The guest is still outside every grant (PUB-5.109).
    let (_, v) = op_at(port, None, at_written, &retrieve(&draft, 5));
    assert_eq!(expect_resp(&v, "rejected")["code"].as_str(), Some("withheld"));

    sd.shutdown();
}

#[cfg(feature = "observe")]
#[test]
fn dump_at_is_deterministic_and_head_matches_live() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let scenario = seed(port);
    let head = head_of(port);

    // Equal positions: byte-equal. Distinct positions: distinct worlds.
    let mut dumps = Vec::new();
    for at in [0, scenario.at_i1, scenario.at_link] {
        let path = format!("/dump?at={at}");
        let (st1, d1) = get(port, &path);
        let (st2, d2) = get(port, &path);
        assert_eq!((st1, st2), (200, 200));
        assert_eq!(d1, d2, "dump at {at} must be deterministic");
        dumps.push(d1);
    }
    assert_ne!(dumps[0], dumps[1], "genesis and a populated world must dump differently");

    // The head position IS the live world.
    let (st, at_head) = get(port, &format!("/dump?at={head}"));
    let (st_live, live) = get(port, "/dump");
    assert_eq!((st, st_live), (200, 200));
    assert_eq!(at_head, live, "dump?at=head must equal the plain dump");

    // Position errors ride the same transport-error shapes as /op-at.
    let (st, body) = get(port, &format!("/dump?at={}", head + 9));
    assert_eq!(st, 400);
    assert_eq!(json(&body)["error"].as_str(), Some("beyond_head"));
    assert_eq!(json(&body)["head"].as_u64(), Some(head));
    let (st, body) = get(port, "/dump?at=abc");
    assert_eq!(st, 400);
    assert_eq!(json(&body)["error"].as_str(), Some("malformed_at"));
    let (st, body) = get(port, "/dump?position=3");
    assert_eq!(st, 400);
    assert_eq!(json(&body)["error"].as_str(), Some("malformed_at"));

    sd.shutdown();
}

/// JOURNAL DAMAGE A HISTORY READ MEETS IS SAID, ONCE, AND RE-SAID WHILE IT
/// STANDS (RUNBOOK §2): a byte of the journal's first frame flipped while
/// the board serves — the write path never reads it back, and every history
/// read scans the journal from its base to its end — and `/op-at` answers
/// `500 history_corrupt`, its reply what it was, `/chain?at` too, while the
/// operator stream says ONE `failure: history: journal corrupt at rest; …`
/// line naming the damage, what serves and the act, and no second at the
/// next read; a read at the head and a write serve throughout; and the
/// standing line re-says the damage at its tick.
#[test]
fn journal_damage_a_history_read_meets_is_said_once_and_re_said_while_it_stands() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let scenario = seed(port);
    let lines = |prefix: &str| -> Vec<String> {
        sd.daemon().lines_said().into_iter().filter(|l| l.starts_with(prefix)).collect()
    };
    let damage = || lines("failure: history: ");
    assert_eq!(damage(), Vec::<String>::new(), "a sound journal: nothing said");

    // The fifth byte of the first frame's payload, past its 12-byte header
    // (`[magic][len][crc]`): the frame's crc no longer validates, and intact
    // frames follow it.
    let segment = dir.path().join("seg-1.wal");
    let mut bytes = std::fs::read(&segment).expect("the journal's first segment");
    bytes[16] ^= 0xFF;
    std::fs::write(&segment, &bytes).expect("rewrite the segment in place");

    let read = retrieve(&scenario.doc1, 5);
    let (st, v) = op_at(port, Some(&scenario.token), scenario.at_i1, &read);
    assert_eq!((st, v["error"].as_str()), (500, Some("history_corrupt")), "{v}");
    let said = damage();
    assert_eq!(said.len(), 1, "FINDING (RUNBOOK §2): the damage is said, once: {said:?}");
    assert!(
        said[0].starts_with("failure: history: journal corrupt at rest; position "),
        "the kernel's own account of the damage: {said:?}"
    );
    assert!(
        said[0].ends_with(
            "; reads at the head and every write serve on, since neither reads the journal \
             back, but the next start's open reads the journal above its start point and may \
             refuse on the same file: copy the data directory, run skepd inventory over the \
             copy (its open reads the journal as a start does), and restore what it refuses \
             from a copy before the board restarts; where no copy holds that file whole, keep \
             the board serving and do not restart it until the next checkpoint lands: an open \
             then starts above the damage and passes it over; check the volume and its device"
        ),
        "the line says what serves and the act: {said:?}"
    );

    let (st, body) = get(port, &format!("/chain?at={}", scenario.at_i1));
    assert_eq!((st, json(&body)["error"].as_str()), (500, Some("history_corrupt")));
    assert_eq!(damage().len(), 1, "FINDING (the rates): a second read says nothing more");

    // The head's reads and the write path serve on.
    let v = op(port, Some(&scenario.token), &retrieve(&scenario.doc1, 3));
    assert_eq!(v["resp"].as_str(), Some("delivery"), "a read at the head serves: {v}");
    let v = op(
        port,
        Some(&scenario.token),
        &format!(
            r#"{{"op":"insert","doc":"{}","at":{{"subspace":"1","ordinal":"1"}},"values":["z"]}}"#,
            scenario.doc2
        ),
    );
    assert!(v["at"].is_u64(), "a write serves: {v}");

    sd.daemon().set_standing_interval_millis(40);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        let standing = lines("standing: ");
        if standing.iter().any(|l| l.contains("a history read found the journal unreadable")) {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "no standing line re-said it: {standing:?}");
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    sd.shutdown();
}

/// `src` copied whole under `dst`: the copy RUNBOOK §2 has the inventory run
/// over, so its open reads the copy's journal and never the board's.
fn copy_dir(src: &std::path::Path, dst: &std::path::Path) {
    std::fs::create_dir_all(dst).expect("the copy's directory");
    for entry in std::fs::read_dir(src).expect("the board lists") {
        let entry = entry.expect("an entry");
        let to = dst.join(entry.file_name());
        if entry.file_type().expect("a file type").is_dir() {
            copy_dir(&entry.path(), &to);
        } else {
            std::fs::copy(entry.path(), &to).expect("copy a file");
        }
    }
}

/// Checks that journal damage a checkpoint lands above is passed over.
///
/// A byte of the active segment's first frame is flipped while the board
/// serves — the case RUNBOOK §2's restore can only rewind, a copy of the
/// active segment holding only the commits made before it — and a copy's
/// inventory refuses the journal, as the next start would. Then a checkpoint
/// lands at the head, above the damage: a copy taken after it opens, and so
/// does the board, its start point that checkpoint, the run below it passed
/// over (Start, step 3, item 5), and its head the head it had.
#[test]
fn journal_damage_a_checkpoint_lands_above_is_passed_over_by_the_next_open() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let scenario = seed(port);
    assert!(
        !dir.path().join("seg-2.wal").exists(),
        "the premise: the damage lies in the active segment"
    );
    let segment = dir.path().join("seg-1.wal");
    let mut bytes = std::fs::read(&segment).expect("the journal's first segment");
    bytes[16] ^= 0xFF;
    std::fs::write(&segment, &bytes).expect("rewrite the segment in place");
    let read = retrieve(&scenario.doc1, 5);
    let (st, v) = op_at(port, Some(&scenario.token), scenario.at_i1, &read);
    assert_eq!((st, v["error"].as_str()), (500, Some("history_corrupt")), "{v}");

    let copies = tempfile::tempdir().expect("tempdir");
    let before = copies.path().join("before");
    copy_dir(dir.path(), &before);
    let refused = skepd::tools::inventory(&before, skepd::tools::HoleCheck::LengthOnly)
        .expect_err("an open from genesis folds through the damage and refuses");
    assert!(refused.to_string().contains("durable committed data cannot be read"), "{refused}");

    sd.daemon().checkpoint_now();
    let base = sd.daemon().newest_checkpoint().expect("the checkpoint landed").seq;
    let after = copies.path().join("after");
    copy_dir(dir.path(), &after);
    skepd::tools::inventory(&after, skepd::tools::HoleCheck::LengthOnly).unwrap_or_else(|e| {
        panic!("FINDING (RUNBOOK §2): an open from the checkpoint passes the damage over: {e}")
    });
    let head = head_of(port);
    sd.shutdown();

    let sd = spawn(dir.path());
    let recovery = sd.daemon().recovery().expect("a journaled open's account");
    assert_eq!(recovery.start_point, base, "the open starts at the checkpoint above the damage");
    assert!(recovery.runs_passed_over >= 1, "…and passes the damage over: {recovery:?}");
    assert_eq!(head_of(sd.port()), head, "nothing acknowledged is lost");
    sd.shutdown();
}

/// Checks that a history read's I/O failure names no path to its client.
///
/// The data directory is made unreadable while the board serves, so every
/// history read's listing of the journal directory fails, and the kernel's
/// account of the failure names the directory by its name alone
/// (`the journal directory: list: …`). A guest's `/chain?at=0`, the owner's
/// `/op-at` and, in `observe` builds, `/dump?at` each answer
/// `500 history_io` with the one fixed detail and no byte of the path. The
/// operator stream says one `failure: history:` line carrying the account,
/// no byte of the path in it either (PATTERNS SP-15), and no second at the
/// later reads; a read at the head and a write serve on, neither listing the
/// directory.
#[cfg(unix)]
#[test]
fn a_history_reads_io_failure_carries_no_path_to_its_client_and_its_account_to_the_operator() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let scenario = seed(port);
    let path = dir.path().display().to_string();
    let expected =
        r#"{"detail":"reading the journal for this position failed","error":"history_io"}"#;
    let unreadable = Unreadable::new(dir.path());
    if std::fs::read_dir(dir.path()).is_ok() {
        // A privileged process lists a mode-0300 directory: the listing the
        // claim needs to fail does not, and nothing is judged.
        drop(unreadable);
        eprintln!("a privileged process lists the directory: the claim is not run");
        sd.shutdown();
        return;
    }
    let text = |body: &[u8]| String::from_utf8_lossy(body).to_string();
    let (st, body) = get(port, "/chain?at=0");
    assert_eq!(
        (st, text(&body).as_str()),
        (500, expected),
        "FINDING (#422): the guest's answer carries the kernel's account"
    );
    let read = retrieve(&scenario.doc1, 5);
    let (st, body) = op_at_raw(port, Some(&scenario.token), scenario.at_i1, &read);
    assert_eq!((st, text(&body).as_str()), (500, expected), "the owner's /op-at");
    #[cfg(feature = "observe")]
    {
        let (st, body) = get(port, &format!("/dump?at={}", scenario.at_i1));
        assert_eq!((st, text(&body).as_str()), (500, expected), "a /dump?at");
    }

    // The account is the operator's: one line, the directory and the act in
    // it, and no path.
    let said: Vec<String> = sd
        .daemon()
        .lines_said()
        .into_iter()
        .filter(|l| l.starts_with("failure: history: "))
        .collect();
    assert_eq!(said.len(), 1, "said once for the uptime: {said:?}");
    assert!(
        said[0].starts_with(
            "failure: history: history read I/O failure: the journal directory: list: "
        ),
        "the operator's line carries the kernel's account: {said:?}"
    );
    assert!(!said[0].contains(&path), "no byte of the path in the operator's line: {said:?}");

    // Neither a read at the head nor the write path lists the directory.
    let v = op(port, Some(&scenario.token), &retrieve(&scenario.doc1, 3));
    assert_eq!(v["resp"].as_str(), Some("delivery"), "a read at the head serves: {v}");
    let v = op(
        port,
        Some(&scenario.token),
        &format!(
            r#"{{"op":"insert","doc":"{}","at":{{"subspace":"1","ordinal":"1"}},"values":["z"]}}"#,
            scenario.doc2
        ),
    );
    assert!(v["at"].is_u64(), "a write serves: {v}");
    drop(unreadable);
    sd.shutdown();
}
