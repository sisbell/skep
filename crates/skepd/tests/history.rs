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

mod common;

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
