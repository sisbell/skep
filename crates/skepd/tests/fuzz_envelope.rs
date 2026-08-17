//! H2 tier 1 — the envelope parsers: `POST /session`, `POST /op-at`,
//! `GET /changes`, `GET /dump`. These wrap the codec with their own JSON and
//! query grammars, and each has its own documented failure vocabulary.
//!
//! The contract: **any bytes in → one documented answer out.** Either a
//! well-formed success (a 2xx the endpoint defines) or a well-formed HTTP
//! error whose `error` name is one wire.md's tables list — never an
//! undocumented name, never a malformed frame, never silence. The generic
//! oracle is [`envelope_oracle`]; targeted cases pin the specific documented
//! shapes so a regression names itself.

mod common;
mod fuzz_common;

use serde_json::Value;
use skepd::fuzz_support::{envelope_oracle, hex, mutate, splitmix64};

use common::{http, open_session, spawn};
use fuzz_common::{iters, op_at_envelopes, random_bytes};

/// Advance the log a little so `/op-at` and `/changes` have real positions to
/// probe (a delegate commits; the exact chain is trusted to other tests).
fn seed_some_history(port: u16) {
    let boot = open_session(port, 0);
    let (_, body) = http(port, "POST", "/op", Some(&boot), br#"{"op":"next_account_prefix","parent":"1"}"#);
    let v: Value = serde_json::from_slice(&body).expect("prefix answer JSON");
    if let Some(prefix) = v["addr"].as_str() {
        let frame = format!(r#"{{"op":"delegate","new_prefix":"{prefix}","new_id":1}}"#);
        let _ = http(port, "POST", "/op", Some(&boot), frame.as_bytes());
    }
}

#[test]
fn envelope_parsers_answer_documented_shapes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    seed_some_history(port);

    // Corpora for the two JSON-body endpoints and the two query endpoints.
    let session_bodies: Vec<Vec<u8>> =
        vec![br#"{"principal":2}"#.to_vec(), br#"{"principal":0}"#.to_vec()];
    let op_ats = op_at_envelopes();
    let queries: Vec<Vec<u8>> = vec![
        b"since=0".to_vec(),
        b"since=1&limit=2".to_vec(),
        b"at=0".to_vec(),
        b"at=1".to_vec(),
    ];

    let mut st = 0x454E_5650_0000_0001; // "ENVP\0\0\0\1"
    for i in 0..iters(1_500) {
        let sel = (splitmix64(&mut st) % 4) as u8;
        let payload = match sel {
            0 => mutate(splitmix64(&mut st), &session_bodies),
            1 => mutate(splitmix64(&mut st), &op_ats),
            2 => mutate_or_random(&mut st, &queries),
            _ => mutate_or_random(&mut st, &queries),
        };
        let mut data = Vec::with_capacity(payload.len() + 1);
        data.push(sel);
        data.extend_from_slice(&payload);
        envelope_oracle(port, &data).unwrap_or_else(|e| {
            panic!(
                "FINDING (fuzz_envelope): i={i} sel={sel} undocumented answer: {e}\n  \
                 payload: {}",
                hex(&payload)
            )
        });
    }

    targeted_documented_cases(port);
    sd.shutdown();
}

/// Half the time mutate the query corpus (structured), half arbitrary bytes
/// (queries are not JSON, so raw byte fuzz is apt).
fn mutate_or_random(st: &mut u64, corpus: &[Vec<u8>]) -> Vec<u8> {
    if splitmix64(st) & 1 == 0 {
        mutate(splitmix64(st), corpus)
    } else {
        random_bytes(st, 48)
    }
}

/// The specific documented behaviors, pinned so a regression is named.
fn targeted_documented_cases(port: u16) {
    // /session: the good shape and the malformed one.
    let (st, body) = http(port, "POST", "/session", None, br#"{"principal":2}"#);
    assert_eq!(st, 200, "a valid session opens");
    assert!(json(&body)["session"].is_string(), "session token present: {}", text(&body));
    let (st, body) = http(port, "POST", "/session", None, br#"{"nope":1}"#);
    assert_eq!(st, 400, "an unknown field is refused");
    assert_eq!(json(&body)["error"], "malformed_session_request", "{}", text(&body));

    // /op-at: a read frame answers 200; a write frame is refused at the
    // transport with the ruling-fixed body.
    let (st, body) = http(
        port,
        "POST",
        "/op-at",
        None,
        br#"{"at":0,"frame":{"op":"retrieve_v","specs":[{"doc":"1.0.9.0.1","span":{"start":"1.1","width":"0.1"}}]}}"#,
    );
    assert_eq!(st, 200, "a historical read answers 200: {}", text(&body));
    assert!(json(&body)["resp"].is_string(), "op response tagged: {}", text(&body));
    let (st, body) = http(
        port,
        "POST",
        "/op-at",
        None,
        br#"{"at":0,"frame":{"op":"fork"}}"#,
    );
    assert_eq!(st, 400, "a write at history is refused");
    assert_eq!(json(&body)["error"], "write_at_history", "{}", text(&body));
    // A number past the head is the documented beyond_head.
    let (st, body) = http(
        port,
        "POST",
        "/op-at",
        None,
        br#"{"at":999999,"frame":{"op":"retrieve_doc_v_span","doc":"1.0.1.0.1"}}"#,
    );
    assert_eq!(st, 400, "beyond the head is refused: {}", text(&body));
    assert_eq!(json(&body)["error"], "beyond_head", "{}", text(&body));

    // /changes: the good shape and a malformed query.
    let (st, body) = http(port, "GET", "/changes?since=0", None, b"");
    assert_eq!(st, 200, "changes since 0: {}", text(&body));
    assert!(json(&body)["changes"].is_array(), "changes array: {}", text(&body));
    let (st, body) = http(port, "GET", "/changes?bogus=1", None, b"");
    assert_eq!(st, 400, "an unknown query parameter is refused");
    assert_eq!(json(&body)["error"], "malformed_changes", "{}", text(&body));

    // /dump (observe builds): a malformed at= query is the documented shape.
    #[cfg(feature = "observe")]
    {
        let (st, body) = http(port, "GET", "/dump?at=notanumber", None, b"");
        assert_eq!(st, 400, "a non-numeric at= is refused");
        assert_eq!(json(&body)["error"], "malformed_at", "{}", text(&body));
    }
}

fn json(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap_or_else(|e| panic!("non-JSON body ({e}): {}", text(bytes)))
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}
