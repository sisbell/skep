//! THE CATCHES, THE KERNEL's HALT AND THE UNLINK UNDER THE CATCH
//! (`operations.md` §1.1 rows 41 and m10; §4 rows 24, 25, 29 and 32), judged
//! through the daemon's own record of its lines and `/health`:
//!
//! * m10 AT THE DOOR: a commit's barrier failed and its repair failed — the
//!   kernel poisoned, the write answered `poisoned` — the ruled line ONCE,
//!   with the position the kernel halted at; a second refused write adds
//!   none; `writes.halted` true; the next tick says `the kernel is
//!   poisoned`.
//! * m10 AT THE CATCH: the journal's append PANICKED and the repair failed
//!   — the kernel poisoned and the panic re-raised, the write answered `500
//!   internal_panic` — the ruled line is in the record BEFORE any further
//!   write, read at the handler's catch; a later refused write adds none.
//! * ROW 25: the checkpoint thread's seam armed, a crossing wakes it — the
//!   consequence line ONCE, the flag; a further crossing runs inline as the
//!   backstop and adds no landing line; the stop still joins.
//! * ROW 24: the pruner's seam armed, its next turn — the consequence line
//!   ONCE, the flag; no pass runs; the next tick says `the pruner's thread
//!   is gone`.
//! * ROW 32: the unlink's seam armed, a blob-family request answers
//!   normally and the SAME worker — the daemon serves with one — serves the
//!   next request; the catch adds no line (the hook's is the binary's).
//!
//! The words are the unit suite's (`server/tests.rs`); the class word
//! `failure:` is read here off the record. The seams are the daemon's own
//! (`server/hooks.rs`), each fired once; every daemon is shut down before
//! the claim returns.

use std::io::ErrorKind;
use std::time::{Duration, Instant};

use skep_kernel::Step;
use skepd::Skepd;

use crate::common;
use common::{
    acked_at, blob_deposit_read, get, http, json, op, open_session, release_the_walk, spawn,
    spawn_walk_held, spawn_with_workers, CLAIMANT_ACCOUNT, CLAIMANT_PRINCIPAL,
};

/// ROW 41's consequence line for the checkpoint thread, with its class word.
const CHECKPOINT_THREAD_ENDED: &str = "failure: checkpoint thread ended: every checkpoint from \
                                       here is the backstop's, unsaid; the byte bound and the \
                                       floor stay where they were";

/// ROW 41's consequence line for the pruner, with its class word.
const PRUNER_THREAD_ENDED: &str = "failure: pruner thread ended: no pass runs until a restart; \
                                   the blob logs' compaction and the lapsed tail's reclaim stop";

/// m10's line at position `at`, with its class word.
fn halt_line(at: u64) -> String {
    format!(
        "failure: the kernel halted its write paths at position {at}: every write is refused \
         poisoned until a restart; reads serve. The cause is one of three the kernel does not \
         report — a commit that could not be rolled back durably, an unwind past the \
         durability barrier, or the sequence order exhausted; check the volume and the device, \
         then restart"
    )
}

/// How many times the daemon's record holds `line`.
fn said(sd: &Skepd, line: &str) -> usize {
    sd.daemon().lines_said().iter().filter(|l| l.as_str() == line).count()
}

/// The `failure:` lines the daemon has said.
fn failures(sd: &Skepd) -> Vec<String> {
    sd.daemon().lines_said().into_iter().filter(|l| l.starts_with("failure: ")).collect()
}

/// The `standing:` lines the daemon has said.
fn standing_lines(sd: &Skepd) -> Vec<String> {
    sd.daemon().lines_said().into_iter().filter(|l| l.starts_with("standing: ")).collect()
}

/// A committing write's frame: a fresh private draft under the claimant's
/// account.
fn create_frame() -> String {
    format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"}}"#)
}

/// `/health`'s `writes.halted`.
fn writes_halted(port: u16) -> bool {
    let (st, body) = get(port, "/health");
    assert_eq!(st, 200, "/health: {}", String::from_utf8_lossy(&body));
    json(&body)["writes"]["halted"].as_bool().expect("writes.halted")
}

/// `/health`'s `log_position`.
fn head(port: u16) -> u64 {
    let (st, body) = get(port, "/health");
    assert_eq!(st, 200, "/health: {}", String::from_utf8_lossy(&body));
    json(&body)["log_position"].as_u64().expect("log_position")
}

/// Poll until `done`, within the suite's deadline, naming what was waited
/// for where it never comes.
fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// m10 — THE HALT LINE AT THE DOOR (§4 row 29): the next commit's barrier
/// armed to fail on a full volume and its repair armed to fail, the write
/// answers `rejected`/`poisoned`/`halt` and the record holds the ruled line
/// ONCE, `{p}` the head the kernel halted at; a second refused write adds
/// no line; `/health`'s `writes.halted` is true; nothing committed; and the
/// next tick re-says it as `the kernel is poisoned`.
#[test]
fn the_kernels_halt_is_said_once_at_the_write_paths_door_and_health_says_halted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    assert!(!writes_halted(port), "a healthy board");
    let at = head(port);
    sd.daemon().fail_the_next_checkpoint_step(Step::JournalBarrier, ErrorKind::StorageFull);
    sd.daemon().fail_the_next_checkpoint_step(Step::JournalRepair, ErrorKind::Other);
    let v = op(port, Some(&owner), &create_frame());
    assert_eq!(
        (v["resp"].as_str(), v["code"].as_str(), v["disposition"].as_str()),
        (Some("rejected"), Some("poisoned"), Some("halt")),
        "the kernel poisoned on the unrepaired barrier: {v}"
    );
    assert_eq!(
        said(&sd, &halt_line(at)),
        1,
        "FINDING (m10): the ruled line, once, at the door:\n{}",
        sd.daemon().lines_said().join("\n")
    );
    let v = op(port, Some(&owner), &create_frame());
    assert_eq!(v["code"].as_str(), Some("poisoned"), "every later write is refused: {v}");
    assert_eq!(
        failures(&sd).iter().filter(|l| l.contains("the kernel halted")).count(),
        1,
        "a second refused write adds no line:\n{}",
        failures(&sd).join("\n")
    );
    assert!(writes_halted(port), "FINDING (op-D10 (a)): writes.halted is false under the poison");
    assert_eq!(head(port), at, "no refused write committed");
    sd.daemon().set_standing_interval_millis(50);
    wait_until("the standing line", || !standing_lines(&sd).is_empty());
    assert_eq!(
        standing_lines(&sd)[0],
        "standing: the kernel is poisoned; CLAIMED-PERMISSIVE",
        "the poison re-said at the tick"
    );
    sd.shutdown();
}

/// m10 — THE HALT LINE AT THE CATCH (§4 row 29): the journal's next append
/// armed to PANIC and the repair armed to fail, the write's unwind poisons
/// the kernel and re-raises — the transport answers `500 internal_panic` —
/// and the record holds the ruled line BEFORE any further write, read at
/// the handler's catch, `{p}` the head; `writes.halted` true; a later write
/// refused `poisoned` adds no second line.
#[test]
fn the_kernels_halt_is_said_at_the_handlers_catch_after_a_panic_on_a_write() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let at = head(port);
    sd.daemon().panic_at_the_next_kernel_step(Step::JournalAppend);
    sd.daemon().fail_the_next_checkpoint_step(Step::JournalRepair, ErrorKind::Other);
    let (st, body) = http(port, "POST", "/op", Some(&owner), create_frame().as_bytes());
    assert_eq!(st, 500, "{}", String::from_utf8_lossy(&body));
    assert_eq!(
        json(&body)["error"].as_str(),
        Some("internal_panic"),
        "{}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(
        said(&sd, &halt_line(at)),
        1,
        "FINDING (m10): the ruled line is not in the record right after the caught panic — \
         the quiet-board gap stands:\n{}",
        sd.daemon().lines_said().join("\n")
    );
    assert!(writes_halted(port), "FINDING (op-D10 (a)): writes.halted is false under the poison");
    let v = op(port, Some(&owner), &create_frame());
    assert_eq!(v["code"].as_str(), Some("poisoned"), "every later write is refused: {v}");
    assert_eq!(
        failures(&sd).iter().filter(|l| l.contains("the kernel halted")).count(),
        1,
        "a later refused write adds no second line:\n{}",
        failures(&sd).join("\n")
    );
    assert_eq!(head(port), at, "nothing committed");
    sd.shutdown();
}

/// ROW 25 — THE CHECKPOINT THREAD's DEATH: its seam armed and a crossing
/// waking it, the thread panics at the top of its turn and its catch says
/// the consequence line ONCE and sets the flag; the flag the crossing set
/// stands unserviced; a further crossing runs inline as the kernel's
/// backstop — the count moves — and the dead thread adds no landing line
/// and no backstop line; the stop still joins (the shutdown returns).
#[test]
fn the_checkpoint_threads_death_is_said_once_with_what_is_lost_and_the_backstop_runs_on() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    assert!(!sd.daemon().checkpoint_thread_ended());
    let lines_before = sd.daemon().checkpoint_lines().len();
    sd.daemon().panic_the_checkpoint_thread_next();
    sd.daemon().set_checkpoint_bytes_bound(1);
    commit(port, &owner);
    wait_until("the checkpoint thread's catch", || sd.daemon().checkpoint_thread_ended());
    assert_eq!(
        said(&sd, CHECKPOINT_THREAD_ENDED),
        1,
        "FINDING (row 41): the consequence line, once:\n{}",
        sd.daemon().lines_said().join("\n")
    );
    assert_eq!(
        sd.daemon().checkpoint_lines().len(),
        lines_before,
        "the thread died before servicing the flag: no landing"
    );
    assert!(sd.daemon().checkpoint_is_due_now(), "the crossing's flag stands, unserviced");
    assert_eq!(sd.daemon().inline_checkpoints(), 0);
    // A further crossing meets the standing flag and runs inline: the
    // backstop, which the dead carrier says nothing of.
    commit(port, &owner);
    assert!(sd.daemon().inline_checkpoints() >= 1, "the second crossing ran inline");
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(
        sd.daemon().checkpoint_lines().len(),
        lines_before,
        "no landing line and no backstop line: the thread is gone: {:?}",
        sd.daemon().checkpoint_lines()
    );
    assert_eq!(said(&sd, CHECKPOINT_THREAD_ENDED), 1, "said once");
    sd.shutdown();
}

/// ROW 24 — THE PRUNER's DEATH: the board spawned with the cell index's walk
/// held, so the pruner polls readiness and reaches its next turn within the
/// poll; its seam armed, its catch says the consequence line ONCE and sets
/// the flag; the walk released, no pass ever runs; and the next tick says
/// `the pruner's thread is gone`.
#[test]
fn the_pruners_death_is_said_once_and_the_standing_line_names_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (sd, seam) = spawn_walk_held(dir.path());
    assert!(!sd.daemon().pruner_thread_ended());
    assert_eq!(sd.daemon().prune_passes_completed(), 0, "no pass under a held walk");
    sd.daemon().panic_the_pruner_next();
    wait_until("the pruner's catch", || sd.daemon().pruner_thread_ended());
    assert_eq!(
        said(&sd, PRUNER_THREAD_ENDED),
        1,
        "FINDING (row 41): the consequence line, once:\n{}",
        sd.daemon().lines_said().join("\n")
    );
    release_the_walk(&sd, seam);
    std::thread::sleep(Duration::from_millis(600));
    assert_eq!(sd.daemon().prune_passes_completed(), 0, "no pass runs: the thread is gone");
    sd.daemon().set_standing_interval_millis(50);
    wait_until("the standing line", || !standing_lines(&sd).is_empty());
    assert_eq!(
        standing_lines(&sd)[0],
        "standing: the pruner's thread is gone; CLAIMED-PERMISSIVE",
        "the dead pruner re-said at the tick"
    );
    assert_eq!(said(&sd, PRUNER_THREAD_ENDED), 1, "said once");
    sd.shutdown();
}

/// ROW 32 — THE UNLINK UNDER THE CATCH: the daemon serving with ONE worker
/// and the unlink's seam armed, a blob-family request (the deposit read)
/// answers normally — the deferred step runs after its reply and panics —
/// and the same worker serves the next request; the catch adds no line of
/// its own (the hook's line is the binary's, not asserted in-process).
#[test]
fn a_panic_in_the_deferred_unlink_is_contained_and_the_one_worker_serves_on() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn_with_workers(dir.path(), 1);
    let port = sd.port();
    let token = open_session(port, CLAIMANT_PRINCIPAL);
    let failures_before = failures(&sd).len();
    sd.daemon().panic_in_the_next_unlink();
    let (st, _, body) = blob_deposit_read(port, Some(&token));
    assert_eq!(st, 200, "the blob family's request answers normally: {}", String::from_utf8_lossy(&body));
    let (st, body) = get(port, "/health");
    assert_eq!(
        (st, json(&body)["ok"].as_bool()),
        (200, Some(true)),
        "FINDING (§4 row 32): the one worker did not serve its next request — the unlink's \
         panic took it"
    );
    assert_eq!(
        failures(&sd).len(),
        failures_before,
        "the catch adds no line of its own: {:?}",
        failures(&sd)
    );
    sd.shutdown();
}

/// One committing write as `session`: a fresh private draft under the
/// claimant's account. Answers the committed position.
fn commit(port: u16, session: &str) -> u64 {
    acked_at(&op(port, Some(session), &create_frame()))
}
