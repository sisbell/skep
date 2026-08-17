//! H2 tier 1 — the codec under hostile bytes.
//!
//! The contract: **any bytes in → exactly one well-formed response out,
//! never a panic, never silence.** Two seeded, deterministic loops (H3's
//! discipline — the seed is the whole reproduction):
//!
//! * arbitrary byte frames through [`codec_roundtrip_oracle`]: `parse` never
//!   panics, a parse that succeeds canonicalizes to a fixpoint, a parse that
//!   fails is the Unparseable path — and every pinned wire.md frame parses
//!   AND round-trips;
//! * grammar-aware mutants of the wire.md examples: the same parse oracle,
//!   then — if the mutant parses — one execution against a live daemon to a
//!   single decodable response tagged with a documented `resp` shape (never
//!   silence).
//!
//! A violation fails loudly with `seed` + hex(mutant); per the H3 finding
//! protocol that failing test is then converted to
//! `#[ignore = "FINDING-n: …"]` with its assertion intact, and the fix is
//! its own round.

mod common;
mod fuzz_common;

use std::any::Any;
use std::panic::{catch_unwind, AssertUnwindSafe};

use serde_json::Value;
use skepd::fuzz_support::{codec_roundtrip_oracle, hex, mutate, RESP_SHAPES};

use common::{http, open_session, spawn};
use fuzz_common::{frame_corpus, iters, random_bytes};

/// Extract a human-readable cause from a caught panic payload.
fn panic_msg(e: &(dyn Any + Send)) -> String {
    if let Some(s) = e.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = e.downcast_ref::<String>() {
        s.clone()
    } else {
        "<non-string panic>".to_string()
    }
}

#[test]
fn codec_parse_arbitrary_bytes_never_panics_and_roundtrips() {
    // Anchor: every pinned wire.md frame must parse and round-trip.
    let corpus = frame_corpus();
    for frame in &corpus {
        assert!(
            codec_roundtrip_oracle(frame),
            "a pinned wire.md frame does not parse: {}",
            String::from_utf8_lossy(frame)
        );
    }

    // Storm: arbitrary bytes never panic the parser (returning is the
    // property); the seed is the reproduction.
    let mut st = 0xF17E_C0DE_0000_0001;
    for i in 0..iters(30_000) {
        let bytes = random_bytes(&mut st, 512);
        let res = catch_unwind(AssertUnwindSafe(|| codec_roundtrip_oracle(&bytes)));
        if let Err(e) = res {
            panic!(
                "FINDING (fuzz_codec arbitrary): parser panicked at i={i}\n  \
                 input: {}\n  cause: {}",
                hex(&bytes),
                panic_msg(e.as_ref())
            );
        }
    }
}

#[test]
fn codec_grammar_mutation_single_response() {
    let corpus = frame_corpus();
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    // A bootstrap session so parsed write mutants reach the write path
    // (namespace ops can commit); reads are principal-free regardless.
    let session = open_session(port, 0);

    let mut base_seed = 0x6D75_7461_7465_0001u64;
    for i in 0..iters(1_500) {
        base_seed = base_seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mutant = mutate(base_seed, &corpus);
        let res = catch_unwind(AssertUnwindSafe(|| {
            // (1) never panics; a parse that succeeds round-trips.
            let parsed = codec_roundtrip_oracle(&mutant);
            // (2) execute against the daemon: exactly one decodable response,
            // tagged with a documented shape — parsed or not (an unparseable
            // frame is the Unparseable rejection, itself a documented shape).
            let (status, body) = http(port, "POST", "/op", Some(&session), &mutant);
            assert_eq!(
                status, 200,
                "/op must answer 200 with an operation response, got {status}: {}",
                String::from_utf8_lossy(&body)
            );
            let v: Value = serde_json::from_slice(&body).unwrap_or_else(|e| {
                panic!("/op body is not JSON ({e}): {}", String::from_utf8_lossy(&body))
            });
            let resp = v["resp"]
                .as_str()
                .unwrap_or_else(|| panic!("/op response has no 'resp' tag: {v}"));
            assert!(RESP_SHAPES.contains(&resp), "undocumented response shape '{resp}': {v}");
            // A parse failure MUST surface as the unparseable rejection —
            // never a silent success.
            if !parsed {
                assert_eq!(resp, "rejected", "an unparseable frame answered non-rejected: {v}");
                assert_eq!(v["op"].as_str(), Some("unparseable"), "wrong op tag: {v}");
            }
        }));
        if let Err(e) = res {
            panic!(
                "FINDING (fuzz_codec mutation): seed={base_seed:#018x} i={i}\n  \
                 mutant: {}\n  as text: {}\n  cause: {}",
                hex(&mutant),
                String::from_utf8_lossy(&mutant),
                panic_msg(e.as_ref())
            );
        }
    }

    sd.shutdown();
}
