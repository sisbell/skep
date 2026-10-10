//! THE WRITE PERMIT POOL over the wire (`operations.md` §4 rows 25, 27; the
//! ops lanes' D6; the spike S25, the owner's W = 4): every write request on
//! `/op` — the plain, the credential and the registry sequence alike — takes
//! one of `MAX_CONCURRENT_WRITES` permits BEFORE the credential lock and the
//! write path's guard and holds it through its commit, and a write that
//! finds none is refused `503 write_busy` AT ONCE, retry-class, the body
//! naming the op, nothing committed and no lock taken — a pool, never a
//! queue, as the four pools before it; the head writer's own commits take
//! none, running inside the triggering write's turn under its permit. So
//! while an inline backstop holds the guard, writes occupy at most W workers
//! — the trigger and W − 1 parked — and `/health`, `/session` and every read
//! stay answered.
//!
//! In `scan_bound.rs`'s permit-test form: a real write holds its permit for
//! milliseconds, so the pool is pinned through the daemon's doc(hidden) hook
//! (`try_hold_write_permit`, exactly what an in-flight write holds) where a
//! COUNT is the claim, and through the guard's hold (`hold_the_write_guard`,
//! the shape of the trigger inside an inline run) where OCCUPANCY is — W
//! real writes parked, each holding a worker and a permit.
//!
//! The fixture is `common::spawn`'s claimed board; a session write is a fresh
//! private draft of the claimant's, the one write a bare claimed-permissive
//! session commits (`head.rs`'s own write).

use crate::common;

use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use common::*;
use serde_json::Value;
use skepd::Daemon;

/// The write pool's width — `MAX_CONCURRENT_WRITES`, 4 (the owner's pin
/// after S25): restated here as the count the hook must drain, so a pool
/// that moves is a visible decision at this file, as `scan_bound.rs` holds
/// its pool to "exactly 2".
const W: usize = 4;

/// The head document `H` — doc 2 of the system account (PUB-6.65), whose
/// bare address floats to the latest head.
const H: &str = "1.1.0.1.0.2";

/// A well past-the-hour clock jump, so a commit after it drives the head's
/// time bound (trigger (c)); the real bound is one hour and this is many.
const WELL_PAST_THE_HOUR_MILLIS: u64 = 10_000_000;

/// The node account's principal and its own key's seed, above every other
/// suite's ids.
const NODE_PRINCIPAL: u64 = 941;
const NODE_SEED: u8 = 41;

/// The documented refusal: `503`, `error: write_busy`, the `op` named, the
/// detail in the four siblings' voice — and a TRANSPORT body, no `resp` and
/// no `code`, exactly as `scan_busy` is a transport refusal.
fn assert_write_busy(st: u16, v: &Value, op: &str) {
    assert_eq!(st, 503, "a saturated write pool answers 503 at once: {v}");
    assert_eq!(v["error"].as_str(), Some("write_busy"), "{v}");
    assert_eq!(v["op"].as_str(), Some(op), "the refusal names the op it refused: {v}");
    assert_eq!(
        v["detail"].as_str(),
        Some("all write permits are in use; retry shortly"),
        "the detail, in the siblings' voice: {v}"
    );
    assert!(v.get("resp").is_none(), "a transport refusal is not an operation response: {v}");
    assert!(v.get("code").is_none(), "no Op ran, so there is no rejection code: {v}");
}

/// Every write permit, held through the hook — exactly W of them.
fn drain(daemon: &Daemon) -> Vec<skepd::Permit<'_>> {
    let mut held = Vec::new();
    while let Some(p) = daemon.try_hold_write_permit() {
        held.push(p);
    }
    assert_eq!(held.len(), W, "the write pool is exactly MAX_CONCURRENT_WRITES");
    held
}

/// One session write's frame: a fresh private draft of the claimant's.
fn draft_frame() -> String {
    create_frame(CLAIMANT_ACCOUNT, None)
}

/// The `/health` pair — `(log_position, chain_head)`.
fn health(port: u16) -> (u64, String) {
    let (st, body) = get(port, "/health");
    assert_eq!(st, 200, "/health: {}", String::from_utf8_lossy(&body));
    let v = json(&body);
    (
        v["log_position"].as_u64().expect("log_position"),
        v["chain_head"].as_str().expect("chain_head").to_string(),
    )
}

/// The position the LATEST head record names — the head-record atom at
/// content position 1 of the bare `H`, read as the guest (`H` is published)
/// — or `None` where no head stands.
fn latest_head_position(port: u16) -> Option<u64> {
    let v = op(
        port,
        None,
        &format!(
            r#"{{"op":"retrieve_v","specs":[{{"doc":"{H}","span":{{"start":"1.1","width":"0.1"}}}}]}}"#
        ),
    );
    let atom = v
        .get("items")?
        .as_array()?
        .iter()
        .find_map(|it| it.get("atom").and_then(Value::as_str))?;
    serde_json::from_str::<Value>(atom).ok()?["position"].as_u64()
}

/// The wall clock now, in unix milliseconds — the head writer's own domain,
/// so a reading set through the seam is relative to now rather than a small
/// number a resumed origin would dwarf into "not yet an hour".
fn clock_origin() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after the epoch")
        .as_millis() as u64
}

/// THE HOLD's RELEASE on every path: a worker parked at the guard's hold is
/// one the daemon's stop joins, so a claim that armed the hold releases it
/// before its daemon drops — on its return and on its unwind alike.
struct Released;

impl Drop for Released {
    fn drop(&mut self) {
        Daemon::release_the_write_guard();
    }
}

/// §4 ROWS 25, 27 — W HELD, THE NEXT WRITE REFUSED AT ONCE, `/health`
/// ANSWERS: with every write permit held through the hook — exactly
/// `MAX_CONCURRENT_WRITES`, 4 — a session write on `/op` is answered `503
/// write_busy` at once, the body naming its `op` and the detail, the
/// documented bytes exactly, and nothing is committed (`/health`'s
/// `log_position` unmoved); meanwhile `/health` answers `ok`, a session
/// opens and a read on `/op` is served, as the guest and as the owner —
/// none takes a write permit; the permits dropped, the same write lands,
/// and the pool is whole again.
#[test]
fn w_held_the_next_write_is_refused_at_once_and_health_answers() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let frame = draft_frame();
    let before = head_position(port);

    let daemon = sd.daemon();
    let held = drain(daemon);

    let started = Instant::now();
    let (st, body) = http(port, "POST", "/op", Some(&owner), frame.as_bytes());
    let took = started.elapsed();
    assert_write_busy(st, &json(&body), "create_new_document");
    // The documented bytes, exactly (canonical key order).
    assert_eq!(
        String::from_utf8_lossy(&body),
        r#"{"detail":"all write permits are in use; retry shortly","error":"write_busy","op":"create_new_document"}"#
    );
    println!("the refusal past the pool took {} ms", took.as_millis());
    assert_eq!(head_position(port), before, "a refused write commits nothing");

    // The surfaces the record names, with every write permit held: the
    // liveness probe, the handshake, and a read on `/op` — reads take no
    // write permit and no lock.
    let (st, h) = get(port, "/health");
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&h));
    assert_eq!(json(&h)["ok"].as_bool(), Some(true), "/health answers ok with every write permit held");
    let fresh = open_session(port, CLAIMANT_PRINCIPAL);
    assert!(!fresh.is_empty(), "POST /session answers a session with every write permit held");
    let read = format!(r#"{{"op":"doc_metadata","doc":"{CLAIMANT_DOC1}"}}"#);
    expect_resp(&op(port, Some(&owner), &read), "doc_metadata");
    expect_resp(&op(port, None, &read), "doc_metadata");

    // Released: the same write lands, and the pool is whole again.
    drop(held);
    let at = acked_at(&op(port, Some(&owner), &frame));
    assert!(at > before, "the same write lands once the permits return");
    assert!(head_position(port) >= at, "the head stands at or past the landing");
    drop(drain(daemon));
    sd.shutdown();
}

/// S25 §0.5 — A PARKED WRITER HOLDS ITS PERMIT; THE REFUSAL IS BEFORE THE
/// LOCK: with the guard's hold armed — the plain sequence parks after its
/// permit and its two locks, the trigger's shape inside an inline backstop
/// — W + 1 real session writes are sent at once. Exactly ONE is answered,
/// `503 write_busy`, BEFORE the hold is released — the pool refused it at
/// once, not after the guard freed — and the other W stand parked, one at
/// the hold and W − 1 on the guard, each holding a worker AND a permit:
/// were the permit taken after the guard, or dropped before the commit, the
/// W + 1th would park too and nothing would answer. Meanwhile `/health`
/// answers and a read on `/op` is served. Released, the parked W land, one
/// commit each — W acks at W distinct positions, the owner's feed listing
/// exactly those — and the pool is whole again.
#[test]
fn parked_writers_hold_their_permits_and_the_one_past_the_pool_is_refused_before_the_lock() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let frame = draft_frame();
    let before = head_position(port);

    Daemon::hold_the_write_guard();
    let _released = Released;

    // W + 1 writers at once, each on a thread of its own, each answered
    // down the channel with the instant it was answered.
    let (tx, rx) = mpsc::channel();
    let writers: Vec<_> = (0..=W)
        .map(|n| {
            let tx = tx.clone();
            let frame = frame.clone();
            let owner = owner.clone();
            thread::spawn(move || {
                let (st, body) = http(port, "POST", "/op", Some(&owner), frame.as_bytes());
                let _ = tx.send((n, st, body, Instant::now()));
            })
        })
        .collect();
    drop(tx);

    // THE ONE REFUSAL, AT ONCE: the first answer of the W + 1, while the
    // guard is still held. Which writer it is depends on arrival order;
    // that there is exactly one does not.
    let (refused, st, body, _) = rx.recv_timeout(Duration::from_secs(20)).expect(
        "one of W + 1 writers is refused at once while W park: none answered, so the pool \
         admitted every writer onto the guard",
    );
    assert_write_busy(st, &json(&body), "create_new_document");
    println!("writer {refused} was the one past the pool");
    // …and no second answer while the guard is held: the W others PARK,
    // each holding its permit, where a permit dropped before the commit
    // would have let the W + 1th in.
    assert!(
        matches!(rx.recv_timeout(Duration::from_millis(750)), Err(mpsc::RecvTimeoutError::Timeout)),
        "a second writer answered while the guard was held: a parked writer let its permit go, \
         or the pool admitted W + 1"
    );
    // Meanwhile: the liveness probe and a read, on the workers the W parked
    // writers leave free.
    let (st, h) = get(port, "/health");
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&h));
    assert_eq!(json(&h)["ok"].as_bool(), Some(true), "/health answers while W writers park");
    expect_resp(
        &op(port, None, &format!(r#"{{"op":"doc_metadata","doc":"{CLAIMANT_DOC1}"}}"#)),
        "doc_metadata",
    );
    assert_eq!(head_position(port), before, "nothing has committed while the guard is held");

    // THE RELEASE: the parked W land, one commit each, after it.
    let released_at = Instant::now();
    Daemon::release_the_write_guard();
    let mut landed = Vec::new();
    for _ in 0..W {
        let (n, st, body, when) =
            rx.recv_timeout(Duration::from_secs(30)).expect("a parked writer lands once released");
        assert_eq!(st, 200, "writer {n}: {}", String::from_utf8_lossy(&body));
        assert!(when >= released_at, "writer {n} answered only after the release");
        landed.push(acked_at(&json(&body)));
    }
    for writer in writers {
        writer.join().expect("a writer thread");
    }
    landed.sort_unstable();
    landed.dedup();
    assert_eq!(landed.len(), W, "one commit each, at W distinct positions: {landed:?}");
    assert!(landed.iter().all(|&at| at > before), "every landing is above the start: {landed:?}");
    // The owner's feed above the start holds exactly those W commits.
    let (st, body) = http(port, "GET", &format!("/changes?since={before}"), Some(&owner), b"");
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&body));
    let page = json(&body);
    let mut rows: Vec<u64> = page["changes"]
        .as_array()
        .expect("changes")
        .iter()
        .map(|row| row["at"].as_u64().expect("at"))
        .collect();
    rows.sort_unstable();
    assert_eq!(rows, landed, "the feed holds the W commits and nothing else: {page}");
    // The permits returned with the writers: the pool is whole again.
    drop(drain(sd.daemon()));
    sd.shutdown();
}

/// THE REGISTER's `W` ROW — THE HEAD WRITER's COMMIT TAKES NO PERMIT: with
/// W − 1 permits held and the head writer's clock fixed well past the hour,
/// one session write takes the last permit and lands, and ITS TURN commits
/// the head's own records inside that same `commit_under`, under that same
/// permit — the latest head names the write's position, `/health`'s
/// `chain_head` moved and its `log_position` stands past the write's own —
/// with no second permit to be had: a head writer that took one would find
/// the pool empty and refuse or wait, and no head would name the write. The
/// write's permit returns; the W − 1 stay held, so exactly one comes back.
#[test]
fn the_head_writers_commit_takes_no_permit() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let daemon = sd.daemon();
    let held: Vec<_> = (1..W)
        .map(|k| daemon.try_hold_write_permit().unwrap_or_else(|| panic!("permit {k} of {W}")))
        .collect();
    let head_before = latest_head_position(port).expect("the claim wrote H.1");
    let (position_before, chain_before) = health(port);

    // The time bound, through the seam: the next write's turn is due.
    daemon.set_head_writer_clock_millis(clock_origin() + WELL_PAST_THE_HOUR_MILLIS);
    let at = acked_at(&op(port, Some(&owner), &draft_frame()));
    assert!(at > position_before, "the write landed under the one free permit");
    assert_eq!(
        latest_head_position(port),
        Some(at),
        "the write's turn wrote the head naming the write's own position, with no second permit"
    );
    assert!(head_before < at, "the head moved past the claim's");
    let (position_after, chain_after) = health(port);
    assert!(position_after > at, "the head's own records landed after the write, in its turn");
    assert_ne!(chain_after, chain_before, "the chain head moved");

    // The write returned its permit, and only it: the W − 1 stay held.
    let free = daemon.try_hold_write_permit().expect("the write returned its permit");
    assert!(daemon.try_hold_write_permit().is_none(), "exactly one slot came back");
    drop(free);
    drop(held);
    sd.shutdown();
}

/// THE FORM's ITEM 3 — THE REGISTRY SEQUENCE MEETS THE POOL (the lanes
/// record's STOP 5, this lane's call): the registrar's console deposits a
/// binding's signed atom with the pool free — the plain sequence — and then,
/// with every permit held, the registry-typed `make_link` — the third write
/// path, which commits through `commit_under` under the same guard the
/// other two take — is refused `503 write_busy` with its `op` named, nothing
/// committed; released, it lands: a binding-typed link from the atom's
/// verified I-address to the account bound.
#[test]
fn the_registry_sequence_meets_the_pool() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    // The registrar's board, as `registry.rs` stands it up: the console, the
    // node account delegated from principal 0 and keyed by a hire.
    let console = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let (node_account, _bare) = bootstrap_delegate(port, NODE_PRINCIPAL);
    let _node_signed =
        hire(port, &console, CLAIMANT_DOC1, &node_account, NODE_PRINCIPAL, &distinct_key(NODE_SEED));
    // The record's atom, signed at the record grade and inserted DECLARED
    // under the binding's row, with the pool free.
    let body = binding_body("1.2", None);
    let atom = signed_atom(port, &console, CLAIMANT_DOC1, T_BINDING, &[&node_account], &json_atom(&body));
    let ordinal = next_content_ordinal(port, Some(&console), CLAIMANT_DOC1);
    let v = op(
        port,
        Some(&console),
        &format!(
            r#"{{"op":"insert","doc":"{CLAIMANT_DOC1}","at":{{"subspace":"1","ordinal":"{ordinal}"}},"values":[{{"atom":{atom}}}],"deposit":"{T_BINDING}"}}"#
        ),
    );
    let atom_addr = acked_addr(&v);
    let link = typed_link_frame(CLAIMANT_DOC1, &[&atom_addr], &[&node_account], T_BINDING);
    let before = head_position(port);

    // Every permit held: the registry-typed write meets the pool.
    let daemon = sd.daemon();
    let held = drain(daemon);
    let (st, body) = http(port, "POST", "/op", Some(&console), link.as_bytes());
    assert_write_busy(st, &json(&body), "make_link");
    assert_eq!(head_position(port), before, "a refused registry write commits nothing");

    // Released: the binding lands, typed by its row.
    drop(held);
    let binding = acked_addr(&op(port, Some(&console), &link));
    let stored = read_link(port, None, &binding);
    assert_eq!(stored["slots"][0][0]["start"].as_str(), Some(atom_addr.as_str()), "{stored}");
    assert_eq!(stored["slots"][1][0]["start"].as_str(), Some(node_account.as_str()), "{stored}");
    assert_eq!(stored["slots"][2][0]["start"].as_str(), Some(T_BINDING), "{stored}");
    drop(drain(daemon));
    sd.shutdown();
}
