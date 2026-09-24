//! `GET /chain?at=N` (the chain's open items, item 7; QUEUE item 10): the
//! commit chain's value AS OF a committed position — the board's
//! RECOMPUTATION off its own journal, under the verification a historical
//! read runs and the same reconstruction permit, with no world materialized.
//! What a peer holding a saved `(position, chain)` pair checks against, where
//! the published head's byte compare (`head.rs`) checks the board's stored
//! CLAIM. Token-blind like `/health`, whose `chain_head` it equals at the
//! head — the one answer the brief calls a STOP if it ever differs.
//!
//! The refusals are `/op-at`'s (`history.rs`): each by code here, and the
//! reclaimed one reached honestly through the same recipe `changes.rs` uses
//! for the sidecar's compaction.

use crate::common;

use common::{
    acked_addr, acked_at, get, json, op, open_session, spawn, CLAIMANT_ACCOUNT,
    CLAIMANT_PRINCIPAL,
};
use serde_json::Value;

/// The chain's genesis seed as the wire renders it: sixty-four `0`s.
const GENESIS_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// The `/health` pair — `(log_position, chain_head)`.
fn health(port: u16) -> (u64, String) {
    let (st, body) = get(port, "/health");
    assert_eq!(st, 200, "/health");
    let v = json(&body);
    (
        v["log_position"].as_u64().expect("log_position"),
        v["chain_head"].as_str().expect("chain_head").to_string(),
    )
}

/// One committing write as `session`: a fresh private draft under the
/// claimant's account. Returns the committed position.
fn commit(port: u16, session: &str) -> u64 {
    let v = op(
        port,
        Some(session),
        &format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"}}"#),
    );
    acked_at(&v)
}

/// `GET /chain?<query>` → `(status, body)`.
fn chain_raw(port: u16, query: &str) -> (u16, Value) {
    let path = if query.is_empty() { "/chain".to_string() } else { format!("/chain?{query}") };
    let (st, body) = get(port, &path);
    (st, json(&body))
}

/// `GET /chain?at=N`, required to answer `200` with exactly `at` and a
/// 64-lowercase-hex `chain`.
fn chain_ok(port: u16, at: u64) -> Value {
    let (st, v) = chain_raw(port, &format!("at={at}"));
    assert_eq!(st, 200, "/chain?at={at}: {v}");
    assert_eq!(v.as_object().map(|o| o.len()), Some(2), "exactly at and chain: {v}");
    assert_eq!(v["at"].as_u64(), Some(at), "the answer names the position asked: {v}");
    let chain = v["chain"].as_str().unwrap_or_else(|| panic!("chain is a string: {v}"));
    assert_eq!(chain.len(), 64, "64 hex characters: {chain}");
    assert!(
        chain.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
        "lowercase hex only: {chain}"
    );
    v
}

/// The happy path: every `(log_position, chain_head)` pair a polling peer
/// saved off `/health` — after the ceremony and after each of five commits —
/// is what `/chain?at=` recomputes at that position; at the head the answer
/// IS `/health`'s `chain_head` beside its `log_position`; `0` is the seed;
/// the answer is byte-deterministic and moves nothing; and across a restart
/// the recomputation is the same for every saved pair.
#[test]
fn chain_at_answers_every_saved_health_pair_and_equals_health_at_the_head() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pairs = {
        let sd = spawn(dir.path());
        let port = sd.port();
        let owner = open_session(port, CLAIMANT_PRINCIPAL);

        let mut pairs = vec![health(port)];
        for _ in 0..5 {
            let at = commit(port, &owner);
            let pair = health(port);
            assert_eq!(pair.0, at, "the pair is the commit's own");
            pairs.push(pair);
        }
        for (at, chain) in &pairs {
            let v = chain_ok(port, *at);
            assert_eq!(
                v["chain"].as_str(),
                Some(chain.as_str()),
                "the recomputation at {at} is the pair the peer saved"
            );
        }

        // AT THE HEAD: /chain?at IS /health.chain_head — the two must agree.
        let (head, chain_head) = health(port);
        let v = chain_ok(port, head);
        assert_eq!(
            v["chain"].as_str(),
            Some(chain_head.as_str()),
            "STOP by name: /chain?at={head} differs from /health.chain_head"
        );
        assert_eq!(chain_ok(port, 0)["chain"].as_str(), Some(GENESIS_HEX), "genesis is the seed");

        // Deterministic bytes, and a bounded read that moves nothing.
        let (st1, b1) = get(port, &format!("/chain?at={head}"));
        let (st2, b2) = get(port, &format!("/chain?at={head}"));
        assert_eq!((st1, &b1), (st2, &b2), "two asks, one byte string");
        assert_eq!(health(port), (head, chain_head), "a chain read moves the head's pair not at all");
        sd.shutdown();
        pairs
    };

    // Across a restart the recomputation is the same: every saved pair still
    // answers, and the head still agrees with /health.
    let sd = spawn(dir.path());
    let port = sd.port();
    for (at, chain) in &pairs {
        assert_eq!(chain_ok(port, *at)["chain"].as_str(), Some(chain.as_str()), "at {at} after a restart");
    }
    let (head, chain_head) = health(port);
    assert_eq!(chain_ok(port, head)["chain"].as_str(), Some(chain_head.as_str()));
    sd.shutdown();
}

/// The refusals, each by code, as `/op-at` gives them: `beyond_head` carrying
/// `head`; `not_a_position` at a multi-record commit's interior seq, carrying
/// `nearest`; `malformed_at` for an absent, non-numeric, repeated or unknown
/// query; and `history_busy` while both reconstruction permits are held — the
/// first refusal, ahead of the journal's verdict — with service restored the
/// moment one is released.
#[test]
fn chain_at_refuses_as_op_at_does() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);

    // beyond_head, carrying the head.
    let (head, _) = health(port);
    let (st, v) = chain_raw(port, &format!("at={}", head + 1));
    assert_eq!(st, 400, "{v}");
    assert_eq!(v["error"].as_str(), Some("beyond_head"), "{v}");
    assert_eq!(v["head"].as_u64(), Some(head), "{v}");

    // not_a_position: an interior seq of a multi-record commit — a two-value
    // insert — with `nearest` the boundary below it.
    let draft = acked_addr(&op(
        port,
        Some(&owner),
        &format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"}}"#),
    ));
    let (after_mint, _) = health(port);
    let v = op(
        port,
        Some(&owner),
        &format!(
            r#"{{"op":"insert","doc":"{draft}","at":{{"subspace":"1","ordinal":"1"}},"values":["a","b"]}}"#
        ),
    );
    let at = acked_at(&v);
    assert!(at >= after_mint + 2, "a two-value insert is a multi-record commit: {at} after {after_mint}");
    let (st, v) = chain_raw(port, &format!("at={}", at - 1));
    assert_eq!(st, 400, "{v}");
    assert_eq!(v["error"].as_str(), Some("not_a_position"), "{v}");
    assert_eq!(v["nearest"].as_u64(), Some(after_mint), "{v}");
    chain_ok(port, at);
    chain_ok(port, after_mint);

    // malformed_at: the query is exactly `at=<position>`, and required.
    for query in ["", "at=abc", "at=1&at=2", "position=3", "at=-1", "at"] {
        let (st, v) = chain_raw(port, query);
        assert_eq!(st, 400, "{query:?}: {v}");
        assert_eq!(v["error"].as_str(), Some("malformed_at"), "{query:?}: {v}");
    }

    // history_busy: the same permit pool as /op-at, taken before `at` is
    // examined, so even genesis — answered from no journal at all — waits.
    let daemon = sd.daemon();
    let p1 = daemon.try_hold_reconstruction_permit().expect("permit 1 of 2");
    let p2 = daemon.try_hold_reconstruction_permit().expect("permit 2 of 2");
    let (st, v) = chain_raw(port, "at=0");
    assert_eq!(st, 503, "{v}");
    assert_eq!(v["error"].as_str(), Some("history_busy"), "{v}");
    let (st, v) = chain_raw(port, &format!("at={}", head + 1));
    assert_eq!(st, 503, "busy precedes beyond_head: {v}");
    drop(p1);
    chain_ok(port, 0);
    let p3 = daemon.try_hold_reconstruction_permit().expect("the chain read released its permit");
    drop((p2, p3));
    chain_ok(port, at);
    sd.shutdown();
}

/// `history_reclaimed`, reached honestly: bulk inserts rotate the journal's
/// segment, a checkpoint at the head retaining one drops the segments wholly
/// below it (the recipe `changes.rs` compacts the sidecar with), and a
/// position below the floor answers `410 history_reclaimed` — `floor` named
/// when known — while the head still answers the pair it was saved as.
#[test]
fn chain_at_below_the_retention_floor_is_history_reclaimed() {
    use skep_engine::{Engine, KernelConfig};
    use skep_kernel::{BurnedSeqPolicy, CheckpointPolicy, Durability, Seq};

    let dir = tempfile::tempdir().expect("tempdir");
    let (early, head, head_chain) = {
        let sd = spawn(dir.path());
        let port = sd.port();
        let owner = open_session(port, CLAIMANT_PRINCIPAL);
        let draft = acked_addr(&op(
            port,
            Some(&owner),
            &format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"}}"#),
        ));
        let (early, early_chain) = health(port);
        assert_eq!(chain_ok(port, early)["chain"].as_str(), Some(early_chain.as_str()));
        let bulk = "z".repeat(8192);
        for _ in 0..6 {
            let v = op(
                port,
                Some(&owner),
                &format!(
                    r#"{{"op":"insert","doc":"{draft}","at":{{"subspace":"1","ordinal":"1"}},"values":["{bulk}"]}}"#
                ),
            );
            acked_at(&v);
        }
        let (head, head_chain) = health(port);
        sd.shutdown();
        (early, head, head_chain)
    };

    // Reclaim without committing: one checkpoint at the head, retaining one.
    {
        let cfg = KernelConfig {
            durability: Durability::Fsync {
                journal_path: dir.path().to_path_buf(),
                retain_checkpoints: 1,
                burned_seq: BurnedSeqPolicy::Rollback,
            },
            checkpoint: CheckpointPolicy::Manual,
        };
        let engine = Engine::open(cfg).expect("engine recover");
        engine.kernel().checkpoint().expect("checkpoint reclaims below itself");
        assert_eq!(engine.kernel().current_seq().0, head, "no new commit was made");
        assert!(
            engine.world_at(Seq(0)).is_err(),
            "the journal must actually have reclaimed for this test to mean anything"
        );
    }

    let sd = spawn(dir.path());
    let port = sd.port();
    let (st, v) = chain_raw(port, &format!("at={early}"));
    assert_eq!(st, 410, "below the floor: {v}");
    assert_eq!(v["error"].as_str(), Some("history_reclaimed"), "{v}");
    assert!(
        v["floor"].is_u64() || v.get("floor").is_none(),
        "floor is named when known and omitted otherwise, never something else: {v}"
    );
    let (st, v) = chain_raw(port, "at=0");
    assert_eq!(st, 410, "genesis is below the floor too: {v}");
    assert_eq!(
        chain_ok(port, head)["chain"].as_str(),
        Some(head_chain.as_str()),
        "the head — now the base's own seq — still answers the pair it was saved as"
    );
    sd.shutdown();
}
