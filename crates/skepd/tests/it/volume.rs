//! THE FULL VOLUME AT A WRITE, AND THE REFUSED OPEN (`operations.md` §1.1
//! m1 and row 2; §4 rows 1 and 6), judged through the daemon's own record
//! of its lines, `/health` and `Daemon::open`'s error:
//!
//! * m1 — THE WRITE REFUSED AT A FULL VOLUME: the kernel's next journal
//!   append (and, in the second claim, its next barrier) armed `StorageFull`
//!   through the write-fault seam, the write is refused `durability`,
//!   disposition `retry`, the I/O text as `detail`; the record holds the
//!   ruled line ONCE, `{p}` the position the refused write would have
//!   taken; the arm set again and a second write refused: no second line;
//!   a write LANDS, the arm again, the line is said AGAIN; `writes.halted`
//!   stays `false` throughout — the condition clears by itself; nothing
//!   refused commits.
//! * ROW 2 — A REFUSED OPEN NAMES ITS FILE: a data directory whose
//!   `feed-attest.log` (then `commits.log`) is unreadable refuses the open
//!   `change-feed sidecar: feed-attest.log: Permission denied (os error
//!   13)`, the kind `PermissionDenied` kept inside.
//!
//! The words are the unit suite's (`write_path/tests.rs`); the class word
//! and the figures are read here. Every daemon is shut down before the
//! claim returns, and every file made unreadable is restored.

use std::io::ErrorKind;

use skep_kernel::Step;
use skepd::{AuthOptions, Daemon, DaemonError, Skepd};

use crate::common;
use common::{
    acked_at, get, json, op, open_session, spawn, spawn_unclaimed, WalkUnheld,
    ALLOW_PREVIEW_KEYS_IN_FIXTURES, CLAIMANT_ACCOUNT, CLAIMANT_PRINCIPAL,
};

/// m1's line at position `at`, with its class word.
fn full_volume_line(at: u64) -> String {
    format!(
        "failure: a write was refused at a full volume at position {at}: no write lands until \
         room is freed on the volume; reads serve; the next write succeeds by itself once room \
         stands, and no restart is owed"
    )
}

/// How many times the daemon's record holds `line`.
fn said(sd: &Skepd, line: &str) -> usize {
    sd.daemon().lines_said().iter().filter(|l| l.as_str() == line).count()
}

/// The m1 lines the daemon has said, in order.
fn full_volume_lines(sd: &Skepd) -> Vec<String> {
    sd.daemon()
        .lines_said()
        .into_iter()
        .filter(|l| l.contains("refused at a full volume"))
        .collect()
}

/// A committing write's frame: a fresh private draft under the claimant's
/// account — one record, so the position it takes is the head plus one.
fn create_frame() -> String {
    format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"}}"#)
}

/// `/health`'s `writes.halted` and `log_position`.
fn health(port: u16) -> (bool, u64) {
    let (st, body) = get(port, "/health");
    assert_eq!(st, 200, "/health: {}", String::from_utf8_lossy(&body));
    let v = json(&body);
    (
        v["writes"]["halted"].as_bool().expect("writes.halted"),
        v["log_position"].as_u64().expect("log_position"),
    )
}

/// One write refused by the volume at `step`: the arm, the write, and the
/// refusal's shape — `durability`, `retry`, the seam's text as `detail`.
fn refuse_at(sd: &Skepd, session: &str, step: Step) {
    let port = sd.port();
    sd.daemon().fail_the_next_checkpoint_step(step, ErrorKind::StorageFull);
    let v = op(port, Some(session), &create_frame());
    assert_eq!(
        (v["resp"].as_str(), v["code"].as_str(), v["disposition"].as_str()),
        (Some("rejected"), Some("durability"), Some("retry")),
        "the volume's refusal, a true no-op: {v}"
    );
    assert_eq!(
        v["detail"].as_str(),
        Some(format!("injected StorageFull at {step:?}").as_str()),
        "the I/O text as detail: {v}"
    );
}

/// m1 at `step`: the line once, the second refusal silent, the clearing at
/// a landed commit, the line again — `writes.halted` false throughout.
fn the_full_volume_is_said_once_and_cleared_by_a_landing(step: Step) {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let (halted, head) = health(port);
    assert!(!halted, "a healthy board");
    assert!(full_volume_lines(&sd).is_empty(), "nothing said on a healthy board");

    // The first refusal: the line, once, at the position the write would
    // have taken.
    refuse_at(&sd, &owner, step);
    assert_eq!(
        said(&sd, &full_volume_line(head + 1)),
        1,
        "FINDING (m1): the ruled line, once, at head + 1:\n{}",
        sd.daemon().lines_said().join("\n")
    );
    assert_eq!(health(port), (false, head), "no halt, nothing committed");

    // The second refusal under the same condition: no second line.
    refuse_at(&sd, &owner, step);
    assert_eq!(
        full_volume_lines(&sd).len(),
        1,
        "FINDING (m1): a second refusal under one condition said it again:\n{}",
        full_volume_lines(&sd).join("\n")
    );
    assert_eq!(health(port), (false, head), "still no halt, still nothing committed");

    // Room stands: a write LANDS, by itself, and clears the condition.
    let landed = acked_at(&op(port, Some(&owner), &create_frame()));
    assert!(landed > head, "the next write succeeds by itself: {landed} > {head}");
    assert_eq!(full_volume_lines(&sd).len(), 1, "a landing says nothing");
    let (_, head) = health(port);

    // The volume full again: a fresh condition, said again at its position.
    refuse_at(&sd, &owner, step);
    assert_eq!(
        said(&sd, &full_volume_line(head + 1)),
        1,
        "FINDING (m1): the clearing at the landed commit did not take — the line is not said \
         again for the new condition:\n{}",
        sd.daemon().lines_said().join("\n")
    );
    assert_eq!(full_volume_lines(&sd).len(), 2, "two conditions, two lines");
    assert_eq!(health(port), (false, head), "writes.halted stays false: the condition self-heals");
    sd.shutdown();
}

/// m1 / §4 ROW 1 — THE JOURNAL's APPEND refused by the volume: the line
/// once per condition, cleared at the next landed commit, `writes.halted`
/// false throughout.
#[test]
fn a_write_refused_at_a_full_volume_is_said_once_and_again_after_a_landed_commit() {
    the_full_volume_is_said_once_and_cleared_by_a_landing(Step::JournalAppend);
}

/// m1 / §4 ROW 1 — THE JOURNAL's BARRIER refused by the volume, the frames
/// appended and none durable, the kernel's repair truncating them: the same
/// `durability` refusal with the kind kept, and the same line, once per
/// condition.
#[test]
fn a_barrier_refused_at_a_full_volume_is_said_the_same_way() {
    the_full_volume_is_said_once_and_cleared_by_a_landing(Step::JournalBarrier);
}

/// The daemon opened over `dir` as the fixtures open one, in-process — what
/// a refused open answers, with no socket to bind.
fn open_in_process(dir: &std::path::Path) -> Result<Daemon, DaemonError> {
    let _unheld = WalkUnheld::take();
    let mut opts = AuthOptions::default();
    opts.allow_preview_keys = ALLOW_PREVIEW_KEYS_IN_FIXTURES;
    Daemon::open_with(dir, opts)
}

/// ROW 2 / §4 ROW 6 — A REFUSED OPEN NAMES ITS FILE: over a board a daemon
/// served and closed, `feed-attest.log` made unreadable refuses the open as
/// `change-feed sidecar: feed-attest.log: Permission denied (os error 13)`,
/// the kind `PermissionDenied` kept on the error inside; `commits.log` made
/// unreadable, the same with its own name. Each file is restored before
/// the claim returns, and a user who can read a mode-000 file (root) has
/// nothing to judge here.
#[test]
#[cfg(unix)]
fn a_refused_open_names_its_file_and_keeps_the_kind() {
    use std::fs::{set_permissions, File, Permissions};
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("tempdir");
    {
        let sd = spawn_unclaimed(dir.path());
        sd.shutdown();
    }
    for file in ["feed-attest.log", "commits.log"] {
        let path = dir.path().join(file);
        assert!(path.exists(), "{file} stands after a served life");
        set_permissions(&path, Permissions::from_mode(0o000)).expect("mode 000");
        if File::open(&path).is_ok() {
            set_permissions(&path, Permissions::from_mode(0o600)).expect("restore");
            eprintln!("a privileged user reads a mode-000 file: the row 2 claim judges nothing");
            return;
        }
        let refused = open_in_process(dir.path()).err().expect("the open is refused");
        set_permissions(&path, Permissions::from_mode(0o600)).expect("restore");
        assert_eq!(
            refused.to_string(),
            format!("change-feed sidecar: {file}: Permission denied (os error 13)"),
            "FINDING (row 2): the refused open does not name its file"
        );
        match &refused {
            DaemonError::Sidecar(e) => {
                assert_eq!(e.kind(), ErrorKind::PermissionDenied, "the kind is kept: {e}");
            }
            other => panic!("the sidecar's arm, not {other}"),
        }
    }
    // Restored, the board opens and serves again.
    let sd = spawn_unclaimed(dir.path());
    assert!(!health(sd.port()).0);
    sd.shutdown();
}
