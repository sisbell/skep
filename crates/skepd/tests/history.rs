//! Historical reads (wire v3): `/op-at` answers read frames as of any
//! committed position — exact earlier states, rejections included (a
//! document before its creation, a link before its nullification) — with
//! byte-identical answers across repeats and restarts; `/dump?at` is the
//! same determinism for whole worlds. Writes never reach history, and a
//! position beyond the head or between commits is refused with the
//! documented transport errors. Store semantics stay trusted to the stores;
//! these tests assert the transport's history surface.

mod common;

use common::*;
use serde_json::Value;

/// One scenario with its positions: doc1 gets "alpha" then loses "lp"
/// (leaving "aha"), doc2 gets "beta", and one link doc1→doc2 is made and
/// then nullified (`retraction` is the retraction link's own minted
/// address). Every field's `at_*` is the committed position the
/// corresponding ack carried.
struct Scenario {
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

fn op_at_raw(port: u16, at: u64, frame: &str) -> (u16, Vec<u8>) {
    let body = format!(r#"{{"at":{at},"frame":{frame}}}"#);
    http(port, "POST", "/op-at", None, body.as_bytes())
}

fn op_at(port: u16, at: u64, frame: &str) -> (u16, Value) {
    let (st, body) = op_at_raw(port, at, frame);
    (st, json(&body))
}

/// A 200 historical answer, shape-checked.
fn op_at_ok(port: u16, at: u64, frame: &str) -> Value {
    let (st, v) = op_at(port, at, frame);
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

#[test]
fn historical_reads_answer_every_earlier_state() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let scenario = seed(port);
    let head = head_of(port);
    assert_eq!(head, scenario.at_nullify, "the last write's at is the head");

    // ── content history: the text at each position, as_of = the position ──
    let v = op_at_ok(port, scenario.at_i1, &retrieve(&scenario.doc1, 5));
    assert_eq!(expect_resp(&v, "delivery")["as_of"].as_u64(), Some(scenario.at_i1));
    let expect: Value = serde_json::from_str(r#"[{"content":"alpha"}]"#).expect("json");
    assert_eq!(v["items"], expect, "doc1's text as of its insert");

    let v = op_at_ok(port, scenario.at_del, &retrieve(&scenario.doc1, 3));
    assert_eq!(v["as_of"].as_u64(), Some(scenario.at_del));
    let expect: Value = serde_json::from_str(r#"[{"content":"aha"}]"#).expect("json");
    assert_eq!(v["items"], expect, "doc1's text as of the delete");

    // ── arrangement history: one contiguous run before the delete ──
    let v = op_at_ok(port, scenario.at_i1, &spanset(&scenario.doc1));
    assert_eq!(expect_resp(&v, "span_set")["as_of"].as_u64(), Some(scenario.at_i1));
    let expect: Value =
        serde_json::from_str(r#"[{"start":"1.1","width":"0.5"}]"#).expect("json");
    assert_eq!(v["set"], expect);
    let v_after = op_at_ok(port, scenario.at_del, &spanset(&scenario.doc1));
    assert_eq!(v_after["as_of"].as_u64(), Some(scenario.at_del));
    assert_ne!(v_after["set"], expect, "the delete must be visible in the span set");

    // ── a document BEFORE its creation: that position's own rejection ──
    assert!(scenario.at_i1 < scenario.at_c2);
    let v = op_at_ok(port, scenario.at_i1, &spanset(&scenario.doc2));
    let rej = expect_resp(&v, "rejected");
    assert_eq!(rej["op"].as_str(), Some("retrieve_doc_v_span_set"));
    assert_eq!(rej["code"].as_str(), Some("doc_not_registered"));
    // Position 0 is genesis: before every document.
    let v = op_at_ok(port, 0, &spanset(&scenario.doc1));
    assert_eq!(expect_resp(&v, "rejected")["code"].as_str(), Some("doc_not_registered"));

    // ── link history: absent → discoverable → nullified-but-readable ──
    let v = op_at_ok(port, scenario.at_i2, &read_link(&scenario.link));
    assert_eq!(expect_resp(&v, "link_value")["as_of"].as_u64(), Some(scenario.at_i2));
    assert!(v["link"].is_null(), "the link does not exist yet at {}", scenario.at_i2);
    let v = op_at_ok(port, scenario.at_i2, &find_links(&scenario.doc1));
    assert_eq!(expect_resp(&v, "addrs")["addrs"], Value::Array(vec![]));

    let v = op_at_ok(port, scenario.at_link, &read_link(&scenario.link));
    assert_eq!(
        v["link"]["slots"].as_array().map(Vec::len),
        Some(3),
        "the link exists as of its creation: {v}"
    );
    let v = op_at_ok(port, scenario.at_link, &find_links(&scenario.doc1));
    let addrs = expect_resp(&v, "addrs")["addrs"].as_array().expect("addrs").clone();
    assert!(addrs.iter().any(|a| a.as_str() == Some(scenario.link.as_str())));

    let v = op_at_ok(port, scenario.at_nullify, &read_link(&scenario.link));
    assert!(
        v["link"]["slots"].is_array(),
        "a nullified link still reads back (audit permanence): {v}"
    );
    // The nullified link leaves active discovery; the retraction takes its
    // place (a retraction is itself an active link whose document-homed FROM
    // covers every content extent of doc1 — M7's contract, replayed here as
    // the state a live client saw at that position).
    let v = op_at_ok(port, scenario.at_nullify, &find_links(&scenario.doc1));
    assert_eq!(
        expect_resp(&v, "addrs")["addrs"],
        Value::Array(vec![Value::String(scenario.retraction.clone())]),
        "at the nullify position, active discovery holds exactly the retraction"
    );

    // ── determinism, and history-at-head ≡ the live answer ──
    let (st1, b1) = op_at_raw(port, scenario.at_i1, &retrieve(&scenario.doc1, 5));
    let (st2, b2) = op_at_raw(port, scenario.at_i1, &retrieve(&scenario.doc1, 5));
    assert_eq!((st1, st2), (200, 200));
    assert_eq!(b1, b2, "equal positions must answer byte-identically");
    let (st, hist) = op_at_raw(port, head, &retrieve(&scenario.doc1, 3));
    let (st_live, live) = http(port, "POST", "/op", None, retrieve(&scenario.doc1, 3).as_bytes());
    assert_eq!((st, st_live), (200, 200));
    assert_eq!(hist, live, "/op-at at the head is byte-identical to /op");

    // ── the refusals, with the documented bodies ──
    let (st, v) = op_at(port, head, r#"{"op":"fork"}"#);
    assert_eq!(st, 400);
    assert_eq!(v, serde_json::json!({"error": "write_at_history"}));

    let (st, v) = op_at(port, head + 7, &retrieve(&scenario.doc1, 3));
    assert_eq!(st, 400);
    assert_eq!(v, serde_json::json!({"error": "beyond_head", "head": head}));

    // An insert commits content + placement in one composite, so its ack's
    // position sits ≥ 2 past the previous boundary — the seq between is an
    // interior coordinate, never observable, never a position.
    assert!(scenario.at_i1 >= scenario.at_c1 + 2, "insert must be a multi-record commit");
    let (st, v) = op_at(port, scenario.at_c1 + 1, &retrieve(&scenario.doc1, 3));
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
    let (st, v) = op_at(port, head, r#"{"op":"frobnicate"}"#);
    assert_eq!(st, 200);
    let rej = expect_resp(&v, "rejected");
    assert_eq!(rej["op"].as_str(), Some("unparseable"));

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

    let with_id = format!(
        r#"{{"op":"retrieve_v","id":"stored-key-1","specs":[{{"doc":"{}","span":{{"start":"1.1","width":"0.5"}}}}]}}"#,
        scenario.doc1
    );
    let (st_plain, plain) = op_at_raw(port, scenario.at_i1, &retrieve(&scenario.doc1, 5));
    let (st_id, id_body) = op_at_raw(port, scenario.at_i1, &with_id);
    assert_eq!((st_plain, st_id), (200, 200), "{}", String::from_utf8_lossy(&id_body));
    assert_eq!(id_body, plain, "an id in a historical frame changes nothing about the answer");

    let (st, later) = op_at_raw(port, scenario.at_del, &with_id);
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
                let (st, body) = op_at_raw(port, *at, frame);
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
    //    positions committed entirely before this process existed ──
    {
        let sd = spawn(dir.path());
        let port = sd.port();
        for ((at, frame), expected) in probes.iter().zip(&before) {
            let (st, body) = op_at_raw(port, *at, frame);
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
#[test]
fn op_at_reconstruction_is_permit_bounded() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let scenario = seed(port);

    // Sanity: the historical read serves before any permit is pinned.
    op_at_ok(port, scenario.at_i1, &retrieve(&scenario.doc1, 5));

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
            .map(|_| s.spawn(|| op_at(port, scenario.at_i1, &retrieve(&scenario.doc1, 5))))
            .collect();
        handles.into_iter().map(|jh| jh.join().expect("op-at caller thread")).collect()
    });
    for (st, v) in &answers {
        assert_eq!(*st, 503, "saturated reconstruction must answer busy: {v}");
        assert_eq!(v["error"].as_str(), Some("history_busy"), "{v}");
    }

    // Only position-addressed reconstruction is gated: live reads (and the
    // plain head dump) serve while history is saturated.
    let v = op(port, None, &retrieve(&scenario.doc1, 3));
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
    let v = op_at_ok(port, scenario.at_i1, &retrieve(&scenario.doc1, 5));
    assert_eq!(v["as_of"].as_u64(), Some(scenario.at_i1));
    let p3 = daemon.try_hold_reconstruction_permit().expect("the wire call released its permit");
    assert!(daemon.try_hold_reconstruction_permit().is_none());
    drop(p3);
    drop(p2);
    op_at_ok(port, scenario.at_i1, &retrieve(&scenario.doc1, 5));

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

    // With a permit free, the journal's own verdict answers. `at_c1 + 1` is
    // inside the insert's commit — a coordinate, not a position.
    let bad: [(&str, u64, &str); 2] = [
        ("beyond the head", head + 7, "beyond_head"),
        ("between commits", scenario.at_c1 + 1, "not_a_position"),
    ];
    for (what, at, err) in bad {
        let (st, v) = op_at(port, at, &retrieve(&scenario.doc1, 3));
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
        let (st, v) = op_at(port, at, &retrieve(&scenario.doc1, 3));
        assert_eq!(st, 503, "{what} under saturation: {v}");
        assert_eq!(
            v["error"].as_str(),
            Some("history_busy"),
            "{what}: saturation masks the journal's verdict, which is why a Busy \
             answer says nothing about whether `at` is a good position"
        );
    }

    // …and does NOT mask what is decided before the permit: the frame is
    // classified first, so a write is still refused at the transport.
    let (st, v) = op_at(port, head, r#"{"op":"fork"}"#);
    assert_eq!(st, 400, "{v}");
    assert_eq!(v, serde_json::json!({"error": "write_at_history"}));

    drop(held);
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
