//! `/health`'s `chain_head` (QUEUE item 10, piece (c)): the committed head's
//! commit-chain value, 64 lowercase hex, beside the `log_position` it is the
//! chain of — the KERNEL's value, read with the position off ONE root.
//!
//! WHICH ACCESSOR THE PIN COMPARES AGAINST. The harness cannot reach the
//! served kernel (`Daemon` holds its engine privately, and piece (c) adds no
//! accessor), so the check that the served value IS the kernel's reopens the
//! board's journal with `skep-engine` after the daemon stops and reads the
//! recovered kernel's `chain_head()` beside its `current_seq()` — the way
//! `auth_wire` and `changes` already look below the door. Recovery
//! recomputes every link over the frames above its base and halts on a
//! mismatch, so the recovered value is the SHA-256 recomputed over the
//! board's own frames, not a copy of what was served.
//!
//! DURABILITY. Every daemon this harness spawns journals — `Daemon::open`
//! fixes `Durability::Fsync`; there is no in-memory daemon — so the value
//! moves with every commit here. The in-memory reading (the seed at every
//! position, there being no frames to hash) is stated in wire.md and is the
//! kernel's own suite's to pin.

use crate::common;

use std::path::Path;
use std::time::Duration;

use skep_engine::{Engine, KernelConfig};
use skep_kernel::{BurnedSeqPolicy, CheckpointPolicy, Durability, SaltSource};

use common::{
    acked_at, claim_board, get, json, op, op_at, open_session, spawn_unclaimed,
    CLAIMANT_ACCOUNT, CLAIMANT_PRINCIPAL,
};

/// The chain's genesis seed — thirty-two zero bytes — as `/health` renders
/// it: the value a fresh world answers, never `null`.
const GENESIS_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// One `/health` probe → `(log_position, chain_head)`, the member's SHAPE
/// asserted on every read (check (i)): present, a string, 64 characters,
/// lowercase hex and nothing else.
fn probe(port: u16) -> (u64, String) {
    let (st, body) = get(port, "/health");
    assert_eq!(st, 200);
    let v = json(&body);
    let position = v["log_position"].as_u64().expect("log_position");
    let chain = v["chain_head"]
        .as_str()
        .unwrap_or_else(|| panic!("chain_head is present and a string: {v}"));
    assert_eq!(chain.len(), 64, "64 hex characters: {chain}");
    assert!(
        chain.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
        "lowercase hex only: {chain}"
    );
    (position, chain.to_string())
}

/// Lowercase hex of the kernel's bytes — the pin's OWN encoder, so the
/// equality with the served string shares nothing with the daemon's.
fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The board's journal reopened BELOW the door once the daemon has stopped,
/// under `Daemon::open_with`'s own configuration so recovery reads the same
/// base and the same segments. The journal-directory flock a stopped server
/// released is not always re-acquirable the instant `shutdown` returns
/// under the parallel suite's load (`common::spawn_with_blocked_prefixes`
/// names the race), so the one transient shape — an `Io` of kind
/// `WouldBlock` in the error's source chain — is retried, bounded; any
/// other refusal is a real fault and panics at once.
fn reopen(dir: &Path) -> Engine {
    const ATTEMPTS: usize = 12;
    let cfg = KernelConfig {
        durability: Durability::Fsync {
            journal_path: dir.to_path_buf(),
            retain_checkpoints: 2,
            burned_seq: BurnedSeqPolicy::Rollback,
        },
        checkpoint: CheckpointPolicy::EveryN(1024),
        salt: SaltSource::Seeded(0),
    };
    let mut last_lock_err = None;
    for _ in 0..ATTEMPTS {
        match Engine::open(cfg.clone()) {
            Ok(engine) => return engine,
            Err(e) if is_lock_contention(&e) => {
                last_lock_err = Some(e.to_string());
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(e) => panic!("engine recover at {}: {e}", dir.display()),
        }
    }
    panic!(
        "engine recover: lost the journal-lock race {ATTEMPTS} times running \
         (last lock error: {last_lock_err:?})"
    )
}

/// Does this open failure carry the transient lock contention — an
/// `std::io::Error` of kind `WouldBlock` somewhere down its `source` chain —
/// rather than a real fault?
fn is_lock_contention(err: &(dyn std::error::Error + 'static)) -> bool {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(e) = source {
        if let Some(io) = e.downcast_ref::<std::io::Error>() {
            return io.kind() == std::io::ErrorKind::WouldBlock;
        }
        source = e.source();
    }
    false
}

/// Piece (c)'s five checks, on one DURABLE board:
///
/// - (i) the member is present, 64 lowercase hex, on every probe;
/// - (ii) it equals the kernel's `chain_head()` — the recovered kernel's,
///   below the door, read beside `current_seq()` for the position, and
///   again off one `Snapshot` as the daemon reads the pair;
/// - (iii) after ONE committed op it changes, `log_position` in the same
///   answer is that op's acked position, and the pair again equals the
///   kernel's;
/// - (iv) a bounded read (`/op-at`, `/changes`) moves neither member;
/// - (v) two probes with no commit between them are equal.
///
/// And the fresh world first: the seed, sixty-four `0`s, at position 0 —
/// never `null`.
#[test]
fn health_serves_the_chain_head_of_the_position_beside_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn_unclaimed(dir.path());
    let port = sd.port();

    // A FRESH WORLD: nothing committed, the root at Seq(0) carries the
    // seed — rendered, not null.
    let fresh = probe(port);
    assert_eq!(fresh, (0, GENESIS_HEX.to_string()), "a fresh world answers the seed at 0");
    assert_eq!(probe(port), fresh, "(v) no commit between two probes: equal");

    // The ceremony commits several: the chain leaves the seed.
    claim_board(port);
    let claimed = probe(port);
    assert!(claimed.0 > 0, "the ceremony committed: {claimed:?}");
    assert_ne!(claimed.1, GENESIS_HEX, "the chain moved off the seed");
    assert_eq!(probe(port), claimed, "(v) no commit between two probes: equal");

    // (iii) ONE committed op: the position advances by one, and the chain
    // value changes with it — the answer's `log_position` is the position
    // the ack named, and the `chain_head` beside it is that position's.
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let v = op(
        port,
        Some(&owner),
        &format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"}}"#),
    );
    let at = acked_at(&v);
    assert_eq!(at, claimed.0 + 1, "one op, one position");
    let after = probe(port);
    assert_eq!(after.0, at, "log_position in the same answer is the op's position");
    assert_ne!(after.1, claimed.1, "one commit changes the chain value");
    assert_eq!(probe(port), after, "(v) no commit between two probes: equal");

    // (iv) Bounded reads move neither member: a historical read at a
    // ceremony position, and a guest page of the feed.
    let (st, v) = op_at(
        port,
        None,
        2,
        &format!(r#"{{"op":"key_set","account":"{CLAIMANT_ACCOUNT}"}}"#),
    );
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["resp"].as_str(), Some("key_set"), "{v}");
    let (st, body) = get(port, "/changes?since=0");
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&body));
    assert_eq!(probe(port), after, "(iv) bounded reads leave the pair as it was");

    // (ii) The KERNEL's value: stop the daemon and read the board's journal
    // below the door — the recovered head IS the served pair, position and
    // chain, and the two come off one root.
    sd.shutdown();
    let engine = reopen(dir.path());
    let kernel = engine.kernel();
    assert_eq!(kernel.current_seq().0, after.0, "the recovered head is the served position");
    assert_eq!(hex(&kernel.chain_head()), after.1, "the served chain_head is the kernel's");
    let snap = kernel.snapshot();
    assert_eq!(
        (snap.seq().0, hex(&snap.chain())),
        after,
        "one Snapshot carries the pair the daemon serves"
    );
}
