//! THE FULL VOLUME AT A WRITE, AND THE REFUSED OPEN (`operations.md` §1.1
//! m1 and row 2; §4 rows 1 and 6), judged through the daemon's own record
//! of its lines, `/health` and `Daemon::open`'s error:
//!
//! * m1 — THE WRITE REFUSED AT A FULL VOLUME: the kernel's next journal
//!   append (and, in the second claim, its next barrier) armed `StorageFull`
//!   through the write-fault seam, the write is refused `durability`,
//!   disposition `retry`, the I/O text as `detail`; the record holds the
//!   ruled line ONCE, `{p}` the position the refused write would have
//!   taken and the refusal's detail after it; the arm set again and a
//!   second write refused: no second line; a write LANDS, said once with
//!   the refusals it ends; the arm again, the line is said AGAIN;
//!   `writes.halted` stays `false` throughout — the condition clears by
//!   itself; nothing refused commits.
//! * A write refused for a cause but room — the append armed
//!   `QuotaExceeded` — is refused `durability`, `retry`, as at a full
//!   volume, and said by its own line, naming the cause and the acts that
//!   clear it, as RUNBOOK §1 step 1 says.
//! * A write refused at a segment rotation — the data directory unreadable,
//!   which takes the next segment's create and refuses the directory's sync
//!   — is refused `durability`, `retry`, its detail naming
//!   `the journal directory` and no byte of the directory's path (PATTERNS
//!   SP-13, SP-15), and said by that same line.
//! * ROW 2 — A REFUSED OPEN NAMES ITS FILE: a data directory whose
//!   `feed-attest.log` (then `commits.log`) is unreadable refuses the open
//!   `change-feed sidecar: feed-attest.log: Permission denied (os error
//!   13)`, the kind `PermissionDenied` kept inside.
//!
//! The words are the core's unit suite's (`commits/tests.rs`); the class word
//! and the figures are read here. Every daemon is shut down before the
//! claim returns, and every file made unreadable is restored.

use std::io::ErrorKind;

use skep_kernel::Step;
use skepd::{AuthOptions, Daemon, DaemonError, Skepd};

use crate::common;
use common::{
    acked_addr, acked_at, get, json, op, open_session, spawn, spawn_unclaimed, WalkUnheld,
    ALLOW_PREVIEW_KEYS_IN_FIXTURES, CLAIMANT_ACCOUNT, CLAIMANT_PRINCIPAL,
};

/// m1's line at position `at` with the refusal's `detail`, and its class
/// word.
fn full_volume_line(at: u64, detail: &str) -> String {
    format!(
        "failure: a write was refused at a full volume at position {at} ({detail}): no write \
         lands until room is freed on the volume; reads serve; the next write succeeds by itself \
         once room stands, and no restart is owed — a restart before room stands runs its open \
         into the full volume, and where the open refuses, reads stop with it"
    )
}

/// The line a write refused `durability` for a cause but room is said by.
///
/// It names position `at` with the refusal's `detail`, and its class word.
fn durability_refused_line(at: u64, detail: &str) -> String {
    format!(
        "failure: a write was refused durability at position {at} ({detail}): no write lands \
         until its cause clears; reads serve; check the volume, its device and the board user's \
         quota — the next write succeeds by itself once the cause clears; a restart before then \
         runs its open into the same cause, and where the open refuses, reads stop with it"
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
/// refusal's shape — `durability`, `retry`, and as `detail` the segment the
/// write met, the act that failed and the seam's text, as the kernel names
/// every failure on a journal file. Answers the detail, which m1's line
/// carries after its position.
fn refuse_at(sd: &Skepd, session: &str, step: Step) -> String {
    let port = sd.port();
    sd.daemon().fail_the_next_checkpoint_step(step, ErrorKind::StorageFull);
    let v = op(port, Some(session), &create_frame());
    assert_eq!(
        (v["resp"].as_str(), v["code"].as_str(), v["disposition"].as_str()),
        (Some("rejected"), Some("durability"), Some("retry")),
        "the volume's refusal, a true no-op: {v}"
    );
    let act = match step {
        Step::JournalAppend => "append",
        Step::JournalBarrier => "fsync",
        other => unreachable!("a write meets the journal's append or barrier, not {other:?}"),
    };
    let detail = v["detail"].as_str().unwrap_or_else(|| panic!("a detail: {v}"));
    let (segment, said) =
        detail.split_once(": ").unwrap_or_else(|| panic!("the file named first: {v}"));
    assert!(
        segment.starts_with("seg-") && segment.ends_with(".wal"),
        "the segment the write met, by its name: {v}"
    );
    assert_eq!(
        said,
        format!("{act}: injected StorageFull at {step:?}"),
        "the act and the I/O text as detail: {v}"
    );
    detail.to_string()
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
    // have taken, the kernel's account after it.
    let detail = refuse_at(&sd, &owner, step);
    assert_eq!(
        said(&sd, &full_volume_line(head + 1, &detail)),
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

    // Room stands: a write LANDS, by itself, clears the condition, and says
    // so once, counting the two refusals it ends and how long they stood.
    let landed = acked_at(&op(port, Some(&owner), &create_frame()));
    assert!(landed > head, "the next write succeeds by itself: {landed} > {head}");
    assert_eq!(full_volume_lines(&sd).len(), 1, "a landing says no full volume");
    let first = head + 1;
    let lead = format!("landing: writes land again at position {landed}, 2 refused over ");
    let trail = format!(" ms since position {first}");
    let landings: Vec<String> = sd
        .daemon()
        .lines_said()
        .into_iter()
        .filter(|l| {
            l.strip_prefix(&lead)
                .and_then(|rest| rest.strip_suffix(&trail))
                .is_some_and(|ms| ms.parse::<u128>().is_ok())
        })
        .collect();
    assert_eq!(
        landings.len(),
        1,
        "the landing that ends the refusals is said once, the refusals' span in whole ms:\n{}",
        sd.daemon().lines_said().join("\n")
    );
    let (_, head) = health(port);

    // The volume full again: a fresh condition, said again at its position.
    let detail = refuse_at(&sd, &owner, step);
    assert_eq!(
        said(&sd, &full_volume_line(head + 1, &detail)),
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

/// Checks that a write refused for a cause but room is said by its own line.
///
/// The journal's next append is armed `QuotaExceeded`, the board's user
/// over its quota: the write is refused `durability`, `retry`, its detail
/// the segment, the act and the cause, nothing committed and
/// `writes.halted` false, as at a full volume — and ONE `failure:` line
/// names it, its position and detail, what serves and the acts that clear
/// it, and none of the full volume's room. RUNBOOK §1 step 1 quotes it
/// (`runbook_doc.rs` holds the sentence).
#[test]
fn a_write_refused_for_a_cause_but_room_is_refused_durability_and_said_by_its_own_line() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let (_, head) = health(port);
    let said_before = sd.daemon().lines_said().len();
    sd.daemon().fail_the_next_checkpoint_step(Step::JournalAppend, ErrorKind::QuotaExceeded);
    let v = op(port, Some(&owner), &create_frame());
    assert_eq!(
        (v["resp"].as_str(), v["code"].as_str(), v["disposition"].as_str()),
        (Some("rejected"), Some("durability"), Some("retry")),
        "the quota's refusal, a true no-op: {v}"
    );
    let detail = v["detail"].as_str().unwrap_or_else(|| panic!("a detail: {v}"));
    assert!(detail.ends_with(": append: injected QuotaExceeded at JournalAppend"), "{v}");
    assert_eq!(health(port), (false, head), "no halt, nothing committed");
    let failures: Vec<String> = sd.daemon().lines_said()[said_before..]
        .iter()
        .filter(|l| l.starts_with("failure:"))
        .cloned()
        .collect();
    assert_eq!(
        failures,
        [durability_refused_line(head + 1, detail)],
        "RUNBOOK §1 step 1: one line, its own cause and acts"
    );
    sd.shutdown();
}

/// Checks that a write refused at a segment rotation hands its writer no path.
///
/// The data directory is made unreadable (mode `0300`) and bulk prepends are
/// written until one reaches the kernel's segment rotation, which creates the
/// next segment — the mode takes the create — and syncs the directory, which
/// the mode refuses. That write is refused `durability`, `retry`, its detail
/// the kernel's account naming the directory by its name alone,
/// `the journal directory: sync: …`, and no byte of the directory's path is
/// in the answer (PATTERNS SP-13, SP-15); nothing commits, the operator's
/// line says the refusal once with that detail, and restored, the write
/// lands. A process that lists a mode-`0300` directory (root) stages no
/// refusal, and the claim is not run.
#[cfg(unix)]
#[test]
fn a_write_refused_at_a_rotation_hands_its_writer_no_path() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    sd.daemon().park_the_cadence();
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let doc = acked_addr(&op(port, Some(&owner), &create_frame()));
    let bulk = "z".repeat(262_144);
    // A prepend, so the ordinal is in bounds whatever the draft holds.
    let prepend = format!(
        r#"{{"op":"insert","doc":"{doc}","at":{{"subspace":"1","ordinal":"1"}},"values":["{bulk}"]}}"#
    );
    let path = dir.path().display().to_string();
    let leaf = dir.path().file_name().expect("a leaf").to_string_lossy().into_owned();
    let unreadable = common::Unreadable::new(dir.path());
    if std::fs::read_dir(dir.path()).is_ok() {
        drop(unreadable);
        eprintln!("a privileged process lists a mode-0300 directory: the claim is not run");
        sd.shutdown();
        return;
    }
    let said_before = sd.daemon().lines_said().len();

    // Each prepend lands, filling the segment, until one meets the rotation.
    let mut landed = 0;
    let (v, head) = loop {
        let (_, head) = health(port);
        let v = op(port, Some(&owner), &prepend);
        if v["resp"].as_str() == Some("rejected") {
            break (v, head);
        }
        acked_at(&v);
        landed += 1;
        assert!(landed < 64, "no prepend met the rotation: the segment never filled");
    };
    assert_eq!(
        (v["code"].as_str(), v["disposition"].as_str()),
        (Some("durability"), Some("retry")),
        "the rotation's refusal, a true no-op: {v}"
    );
    let detail = v["detail"].as_str().unwrap_or_else(|| panic!("a detail: {v}"));
    assert!(
        detail.starts_with("the journal directory: sync: "),
        "the kernel's account, the directory by its name: {v}"
    );
    let answer = v.to_string();
    assert!(
        !answer.contains(&path) && !answer.contains(&leaf),
        "FINDING (#592): the refused writer is handed the directory's path: {v}"
    );
    assert_eq!(health(port), (false, head), "no halt, nothing committed");
    let failures: Vec<String> = sd.daemon().lines_said()[said_before..]
        .iter()
        .filter(|l| l.starts_with("failure:"))
        .cloned()
        .collect();
    assert_eq!(
        failures,
        [durability_refused_line(head + 1, detail)],
        "one line, the kernel's account as its detail"
    );

    // Restored, the rotation's sync passes and the write lands.
    drop(unreadable);
    assert!(acked_at(&op(port, Some(&owner), &prepend)) > head, "the next write lands");
    sd.shutdown();
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
        let refused = open_in_process(dir.path()).expect_err("the open is refused");
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
