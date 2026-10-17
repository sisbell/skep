//! THE CATCHES, THE KERNEL's HALT AND THE UNLINK UNDER THE CATCH
//! (`operations.md` §1.1 rows 41 and m10; §4 rows 24, 25, 29 and 32), judged
//! through the daemon's own record of its lines and `/health`:
//!
//! * m10 AT THE DOOR: a commit's barrier failed and its repair failed — the
//!   kernel poisoned, the write answered `poisoned` — the ruled line ONCE,
//!   with the position the kernel halted at and the kernel's own cause; a
//!   second refused write adds none; `writes.halted` true; the next tick says `the kernel is
//!   poisoned`.
//! * m10 AT THE HEAD WRITER's OWN COMMIT: the claim's `H.1` refused, owed at
//!   the next turn — a write refused ahead of the store takes it, the
//!   barrier and the repair armed to fail — the head's own commit poisons
//!   the kernel: row 38's line, then the ruled line at once, the kernel read
//!   at the door rather than the answer the head writer swallowed.
//! * m10 AT THE CATCH: the journal's append PANICKED and the repair failed
//!   — the kernel poisoned and the panic re-raised, the write answered `500
//!   internal_panic` — the ruled line, its cause the unwind's, is in the
//!   record BEFORE any further write; a later refused write adds none.
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
    acked_at, blob_deposit_read, board_term, ceremony_before_the_claim, claim_frame, device_key,
    get, http, json, op, op_as_written, open_session, open_signed_session, release_the_walk, spawn,
    spawn_unclaimed, spawn_walk_held, spawn_with_workers, typed_link_frame, verdict,
    CLAIMANT_ACCOUNT, CLAIMANT_DOC1, CLAIMANT_PRINCIPAL, T_GRANT,
};

/// ROW 41's consequence line for the checkpoint thread, with its class word:
/// row 41's words, then the rest of what the board lost and the act.
const CHECKPOINT_THREAD_ENDED: &str = "failure: checkpoint thread ended: every checkpoint from \
                                       here is the backstop's, unsaid; the byte bound and the \
                                       floor stay where they were; until a restart re-spawns \
                                       it, the change feed's files are not compacted and no \
                                       standing line will come: each state is said at its \
                                       transition alone";

/// ROW 41's consequence line for the pruner, with its class word.
const PRUNER_THREAD_ENDED: &str = "failure: pruner thread ended: no pass runs until a restart; \
                                   the blob logs' compaction and the lapsed tail's reclaim stop";

/// How many of the daemon's lines are m10's at position `at`, with its
/// class word, carrying the kernel's own cause — read by the fragment of
/// it that names which unrecoverable failure it was.
fn halt_lines(sd: &Skepd, at: u64, cause: &str) -> usize {
    let head = format!("failure: the kernel halted its write paths at position {at}: ");
    let tail = "; every write is refused poisoned until a restart; reads serve; check the volume \
                and the device, then restart";
    sd.daemon()
        .lines_said()
        .iter()
        .filter(|l| l.starts_with(&head) && l.ends_with(tail) && l.contains(cause))
        .count()
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
/// next tick re-says it as `the kernel is poisoned since position {p}`, the
/// position the halt line named, so the two join on the stream.
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
        halt_lines(&sd, at, "), and the truncation that repairs it failed too ("),
        1,
        "FINDING (m10): the ruled line, once, at the door, the kernel's cause riding it:\n{}",
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
        format!("standing: the kernel is poisoned since position {at}; CLAIMED-PERMISSIVE"),
        "the poison re-said at the tick, at the position the halt line named"
    );
    sd.shutdown();
}

/// m10 — THE HALT LINE AT THE HEAD WRITER's OWN COMMIT (§4 row 29): the
/// claim's `H.1` refused at the seam, the head is owed at the next turn; the
/// journal's next barrier armed to fail on a full volume and its repair to
/// fail, an attested write refused ahead of the store — no board term to
/// name — gives the head writer its turn, and the head's own commit poisons
/// the kernel. The head writer turns its refusal into its own line (row 38,
/// `poisoned`), and the ruled line follows it ONCE, before any further
/// write: the door reads the kernel after every execute, not the answer the
/// head writer swallowed.
#[test]
fn the_kernels_halt_is_said_when_the_head_writers_own_commit_poisons_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn_unclaimed(dir.path());
    let port = sd.port();
    ceremony_before_the_claim(port);
    sd.daemon().refuse_the_next_head_once();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let claim = op(port, Some(&signed), &claim_frame(CLAIMANT_DOC1, CLAIMANT_ACCOUNT));
    let at = acked_at(&claim);
    assert!(board_term(port).is_none(), "the premise: the claim stands, its H.1 refused");
    sd.daemon().fail_the_next_checkpoint_step(Step::JournalBarrier, ErrorKind::StorageFull);
    sd.daemon().fail_the_next_checkpoint_step(Step::JournalRepair, ErrorKind::Other);
    let grant = typed_link_frame(CLAIMANT_DOC1, &[CLAIMANT_ACCOUNT], &[], T_GRANT);
    let v = op_as_written(port, Some(&signed), &grant);
    assert_eq!(
        verdict(&v),
        "credential_refused:attestation_invalid:board_unavailable",
        "the write itself is refused ahead of the store: {v}"
    );
    assert!(writes_halted(port), "the head's own commit poisoned the kernel");
    assert_eq!(head(port), at, "nothing committed");
    let cause = "), and the truncation that repairs it failed too (";
    assert_eq!(
        halt_lines(&sd, at, cause),
        1,
        "FINDING (m10): the head writer's own poisoned commit says the halt at once:\n{}",
        sd.daemon().lines_said().join("\n")
    );
    let said = sd.daemon().lines_said();
    let row_38 = format!("failure: head writer: the head at position {at} was refused (poisoned)");
    let refused = said.iter().position(|l| l.starts_with(&row_38));
    let halted = said.iter().position(|l| l.contains("the kernel halted its write paths"));
    let all = said.join("\n");
    assert!(refused.is_some() && refused < halted, "row 38's line, then the halt:\n{all}");
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
        halt_lines(&sd, at, "a panic unwound out of the commit of "),
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
/// and no backstop line; with a state standing and the tick shortened, no
/// standing line comes, as the consequence line says — the thread was its
/// carrier; the stop still joins (the shutdown returns).
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
    // The floor bound and the tick shortened: a live thread would say the
    // floor's clause within a few ticks; the dead one says nothing.
    sd.daemon().set_media_free_space(Some(1));
    sd.daemon().set_standing_interval_millis(40);
    std::thread::sleep(Duration::from_millis(400));
    assert_eq!(
        standing_lines(&sd),
        Vec::<String>::new(),
        "FINDING (row 41): a standing line came with its carrier gone"
    );
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
