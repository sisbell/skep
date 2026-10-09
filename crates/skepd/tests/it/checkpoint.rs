//! THE CHECKPOINT THREAD's LINES (`operations.md` §1.1 rows 25 and 26 and
//! m13; §4 rows 2, 14 and 35): what the thread says when a checkpoint lands,
//! when one fails — before its rename, or after its base landed — and when
//! the kernel's backstop ran one inline on a writer; and what FOLLOWS each
//! landing, the thread's own or not: the cadence's byte bound and the media
//! floor re-read off the newest checkpoint, the change feed's files
//! compacted to the journal's reclaim floor.
//!
//! Every daemon here is `common::spawn`'s. No suite captures the operator
//! stream in-process, so every line is read back through
//! `Daemon::checkpoint_lines` — each as `{class}: {text}` — and pinned by
//! phrase, the class word by prefix; the figures a line carries are judged
//! against the thread's own hooks (the kernel's reclaimed bytes and inline
//! count, the daemon's resident-set peak, the floor in force) and against
//! the data directory. The words themselves are the unit suite's
//! (`server/tests.rs`, by `to_string()` at fixed figures).

use std::collections::BTreeMap;
use std::fs;
use std::io::ErrorKind;
use std::path::Path;
use std::time::{Duration, Instant};

use skep_kernel::Step;
use skepd::Skepd;

use crate::common;
use common::{acked_addr, acked_at, op, open_session, spawn, CLAIMANT_ACCOUNT, CLAIMANT_PRINCIPAL};

/// One committing write as `session`: a fresh private draft under the
/// claimant's account. Answers the committed position.
fn commit(port: u16, session: &str) -> u64 {
    acked_at(&op(
        port,
        Some(session),
        &format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"}}"#),
    ))
}

/// The journal's segment files under `dir`, by name with their lengths.
fn segments(dir: &Path) -> BTreeMap<String, u64> {
    fs::read_dir(dir)
        .expect("the data dir")
        .map(|e| e.expect("an entry"))
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            (name.starts_with("seg-") && name.ends_with(".wal"))
                .then(|| (name, e.metadata().expect("metadata").len()))
        })
        .collect()
}

/// Bulk inserts into a fresh draft until the journal has rotated its
/// segment — a closed segment below the head, which the next landing
/// reclaims (the recipe `chain_at.rs` reclaims with). Asserted, so a landing
/// this suite expects to reclaim has something to reclaim.
fn rotate_the_segment(port: u16, session: &str, dir: &Path) {
    let draft = acked_addr(&op(
        port,
        Some(session),
        &format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"}}"#),
    ));
    let bulk = "z".repeat(8192);
    for _ in 0..64 {
        if segments(dir).len() >= 2 {
            return;
        }
        acked_at(&op(
            port,
            Some(session),
            &format!(
                r#"{{"op":"insert","doc":"{draft}","at":{{"subspace":"1","ordinal":"1"}},"values":["{bulk}"]}}"#
            ),
        ));
    }
    panic!("the fixture must rotate the journal's segment: {:?}", segments(dir));
}

/// The decimal figure a line carries right after `key`.
fn figure_after(line: &str, key: &str) -> u64 {
    let at = line.find(key).unwrap_or_else(|| panic!("{key:?} missing from {line:?}"));
    let digits: String =
        line[at + key.len()..].chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().unwrap_or_else(|_| panic!("no figure after {key:?} in {line:?}"))
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

/// The lines the checkpoint thread's arms have said, as the hook keeps them.
fn lines(sd: &Skepd) -> Vec<String> {
    sd.daemon().checkpoint_lines()
}

/// ROW 25 — THE FIGURES ARE THE KERNEL's AND THE HOST's (and the class word
/// is `landing`): through the thread's act, a landing after the journal
/// rotated carries the bytes the kernel reclaimed — `last_reclaimed_bytes()`'s
/// figure, which is the closed segment's length on disk — and a landing after
/// none says "nothing reclaimed"; the size is the newest header's length; the
/// volume's free space is the figure the floor's seam pinned, read through
/// the gate's one door, and with no pin the host's own, a figure within the
/// volume's capacity; the duration clause is PRESENT in milliseconds — a
/// small world lands inside one, so the figure may read zero and is never
/// held above it; the resident set is above zero, equal to the daemon's
/// high-water, and never decreases across two landings; both bounds are the
/// small board's, and the compaction fence is the reclaim floor.
#[test]
fn a_landing_line_carries_the_kernels_reclaimed_bytes_the_hosts_free_space_and_the_resident_peak() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    rotate_the_segment(port, &owner, dir.path());
    let before = segments(dir.path());
    assert!(before.len() >= 2, "a closed segment stands below the head: {before:?}");
    assert!(lines(&sd).is_empty(), "nothing said before the first landing");

    sd.daemon().set_media_free_space(Some(777_000_000));
    sd.daemon().service_the_checkpoint_now();
    let said = lines(&sd);
    assert_eq!(said.len(), 1, "one line per landing: {said:?}");
    let line = &said[0];
    assert!(
        line.starts_with("landing: checkpoint at position "),
        "the class word, then row 25: {line}"
    );
    let landed = sd.daemon().newest_checkpoint().expect("the landing");
    assert!(
        line.starts_with(&format!(
            "landing: checkpoint at position {} landed ({} bytes) in ",
            landed.seq.0, landed.len
        )),
        "the position and the newest header's length: {line}"
    );
    let _duration_ms = figure_after(line, " bytes) in ");
    assert!(line.contains(" ms; "), "the duration in milliseconds: {line}");

    // THE RECLAIMED BYTES: the kernel's figure, and the segment that is gone.
    let after = segments(dir.path());
    let gone: u64 =
        before.iter().filter(|(name, _)| !after.contains_key(*name)).map(|(_, len)| len).sum();
    assert!(gone > 0, "the landing reclaimed the closed segment: {before:?} → {after:?}");
    let reclaimed = sd.daemon().last_reclaimed_bytes().expect("a landing's figure");
    assert_eq!(reclaimed, gone, "the kernel's figure is the segment's length on disk");
    assert!(
        line.contains(&format!("; {reclaimed} journal bytes reclaimed; ")),
        "the line carries the kernel's figure: {line}"
    );

    // BOTH BOUNDS, the small board's; THE FREE SPACE the seam pinned, through
    // the gate's door; THE RESIDENT SET, the daemon's own high-water.
    assert!(
        line.contains(&format!(
            "; the cadence's byte bound {}, the media floor in force {}, the volume's free space \
             777000000; ",
            24 * 1024 * 1024,
            256 * 1024 * 1024
        )),
        "{line}"
    );
    let peak = sd.daemon().resident_set_peak().expect("a reading was made at the landing");
    assert!(peak > 0);
    assert_eq!(figure_after(line, "the process's resident set peaked at "), peak, "{line}");
    assert!(
        line.ends_with(&format!(
            "; the change feed's files compacted below position {}",
            landed.seq.0
        )),
        "the fence is the reclaim floor — the oldest kept base — and no file stood, no inline \
         run moved: {line}"
    );

    // THE SECOND LANDING, at the same head with nothing committed between:
    // the one surviving segment is the active one, so nothing is reclaimed
    // and the kernel says so; the host's own free space with the pin lifted;
    // the peak not below the first; the feed holding nothing below a floor
    // that did not move. (A commit between would rotate the segment the bulk
    // insert filled past the threshold, and the landing would reclaim it.)
    sd.daemon().set_media_free_space(None);
    sd.daemon().service_the_checkpoint_now();
    let said = lines(&sd);
    assert_eq!(said.len(), 2, "{said:?}");
    let line = &said[1];
    assert!(
        line.starts_with(&format!("landing: checkpoint at position {} landed (", landed.seq.0)),
        "the same head: {line}"
    );
    assert!(line.contains(" ms; nothing reclaimed; "), "{line}");
    assert_eq!(
        sd.daemon().last_reclaimed_bytes(),
        Some(0),
        "the kernel's figure: a landing that reclaimed nothing"
    );
    let free = figure_after(line, "the volume's free space ");
    assert!(free > 0, "the host's figure: {line}");
    if let Some(capacity) = sd.daemon().media_capacity() {
        assert!(free <= capacity, "free {free} within the volume's capacity {capacity}: {line}");
    }
    let peak_after = sd.daemon().resident_set_peak().expect("a second reading");
    assert!(peak_after >= peak, "the high-water never decreases: {peak} then {peak_after}");
    assert_eq!(figure_after(line, "the process's resident set peaked at "), peak_after, "{line}");
    assert!(
        line.ends_with("; the change feed's files hold nothing below the reclaim floor"),
        "{line}"
    );
    assert!(!line.contains("ran inline"), "no inline run: no clause: {line}");
    sd.shutdown();
}

/// ROW 25 — A FILE THAT STOOD IS NAMED: a derived file whose compaction
/// rewrite fails BEFORE its rename — a directory squatting on its `.compact`
/// twin's name, so the temp file cannot be created — stands as it was, and
/// the landing line names it beside the fence; the four files whose rewrite
/// the seam fails PAST its rename were compacted (the new file is in place)
/// and are stopped for the uptime, said by each file in its own words (lines
/// 27 and 28, untouched here), and the landing line does not call them
/// standing. The seam's arm on the standing file is not spent — its rewrite
/// never reached the reopen — so it is the one file not stopped.
#[test]
fn a_landing_line_names_the_file_that_stood_beside_the_fence() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    rotate_the_segment(port, &owner, dir.path());
    let squat = dir.path().join("feed-index.log.compact");
    fs::create_dir(&squat).expect("a directory on the temp name");
    sd.daemon().fail_the_feeds_next_rewrite_past_rename();

    sd.daemon().service_the_checkpoint_now();
    let said = lines(&sd);
    assert_eq!(said.len(), 1, "{said:?}");
    let line = &said[0];
    let landed = sd.daemon().newest_checkpoint().expect("the landing").seq.0;
    assert!(
        line.ends_with(&format!(
            "; the change feed's files compacted below position {landed}, feed-index.log \
             standing as it was"
        )),
        "the one file that stood is named, and no other: {line}"
    );
    let stopped = sd.daemon().stopped_feed_files();
    assert!(
        !stopped.contains(&"feed-index.log"),
        "the file that stood is not stopped: {stopped:?}"
    );
    for compacted_then_stopped in
        ["commits.log", "feed-offsets.log", "feed-masked.log", "feed-streams.log"]
    {
        assert!(stopped.contains(&compacted_then_stopped), "{compacted_then_stopped}: {stopped:?}");
        assert!(
            !line.contains(&format!("{compacted_then_stopped} standing")),
            "a file compacted past its rename did not stand: {line}"
        );
    }
    fs::remove_dir(&squat).expect("the squat removed");
    sd.shutdown();
}

/// ROW 26 / §4 ROW 2 — A FAILURE PAST THE RENAME, and the class word
/// `failure`: through the daemon's door to the kernel's write-fault seam, the
/// directory's sync after the rename fails on a full volume — the base
/// LANDED, so the line is the landed arm, naming the landed position, "the
/// directory's sync" and "the volume is full", and the thread takes the
/// landing's re-reads off the landed base: the media floor, moved aside
/// beforehand, is back at the figure the base sizes, and the byte bound,
/// moved to one byte, is back at the floor's 24 MiB, so a small commit after
/// crosses nothing. Retention failing — a directory squatting on a name it
/// must remove — is the landed arm with "retention". A failure BEFORE the
/// rename — the temp file's sync — is the `Io` arm: no base, the head's
/// position as an ordering, the floor unmoved; and SAID PER ATTEMPT, a second
/// armed attempt saying it again.
#[test]
fn a_failure_after_the_base_landed_names_the_base_and_its_step_and_re_reads_the_figures() {
    let mib: u64 = 1024 * 1024;
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    commit(port, &owner);

    // THE DIRECTORY's SYNC, on a full volume, after the rename.
    sd.daemon().set_media_floor(1);
    sd.daemon().set_checkpoint_bytes_bound(1);
    sd.daemon().fail_the_next_checkpoint_step(Step::CheckpointDirSync, ErrorKind::StorageFull);
    sd.daemon().service_the_checkpoint_now();
    let landed = sd.daemon().newest_checkpoint().expect("the base landed before the step failed");
    let said = lines(&sd);
    assert_eq!(said.len(), 1, "{said:?}");
    assert!(
        said[0].starts_with(&format!(
            "failure: a checkpoint landed at position {} but the directory's sync failed: the \
             volume is full (",
            landed.seq.0
        )),
        "{}",
        said[0]
    );
    assert!(
        said[0].ends_with(
            "; the journal is not reclaimed and holds every commit; the next attempt is at the \
             cadence's next crossing"
        ),
        "{}",
        said[0]
    );
    assert_eq!(
        sd.daemon().media_floor_in_force(),
        256 * mib,
        "the floor re-read off the landed base"
    );
    // The byte bound re-read too: a small commit crosses nothing, the thread
    // lands nothing more and says nothing more.
    let settled = landed.seq;
    commit(port, &owner);
    std::thread::sleep(Duration::from_millis(300));
    assert!(!sd.daemon().checkpoint_is_due_now(), "the one-byte bound was re-read to the floor's");
    assert_eq!(sd.daemon().newest_checkpoint().map(|h| h.seq), Some(settled));
    assert_eq!(lines(&sd).len(), 1, "{:?}", lines(&sd));

    // RETENTION: a directory squatting on the oldest name retention must
    // remove, once a third base stands.
    fs::create_dir(dir.path().join("checkpoint.0")).expect("a directory on a checkpoint's name");
    commit(port, &owner);
    sd.daemon().set_media_floor(1);
    sd.daemon().service_the_checkpoint_now();
    let landed = sd.daemon().newest_checkpoint().expect("the base landed before retention failed");
    assert!(landed.seq > settled);
    let said = lines(&sd);
    assert_eq!(said.len(), 2, "{said:?}");
    assert!(
        said[1].starts_with(&format!(
            "failure: a checkpoint landed at position {} but retention failed: ",
            landed.seq.0
        )),
        "{}",
        said[1]
    );
    assert!(
        !said[1].contains("the volume is full"),
        "not a full volume: its own text: {}",
        said[1]
    );
    assert_eq!(sd.daemon().media_floor_in_force(), 256 * mib, "re-read after the landed base");
    fs::remove_dir(dir.path().join("checkpoint.0")).expect("the squat removed");

    // BEFORE THE RENAME: no base, the `Io` arm, the floor unmoved — and said
    // again at the second attempt.
    let before = sd.daemon().newest_checkpoint().map(|h| h.seq);
    sd.daemon().set_media_floor(1);
    for attempt in 1..=2 {
        sd.daemon().fail_the_next_checkpoint_step(Step::CheckpointSync, ErrorKind::StorageFull);
        let at = sd.daemon().log_position().0;
        sd.daemon().service_the_checkpoint_now();
        let said = lines(&sd);
        assert_eq!(said.len(), 2 + attempt, "said per attempt: {said:?}");
        let line = said.last().expect("the attempt's line");
        assert_eq!(
            line,
            &format!(
                "failure: checkpoint FAILED (the head stood at position {at} when the run began): \
                 the volume is full (injected StorageFull at CheckpointSync); the \
                 journal is not reclaimed and holds every commit; the next attempt is at the \
                 cadence's next crossing"
            )
        );
        assert_eq!(sd.daemon().newest_checkpoint().map(|h| h.seq), before, "no base landed");
        assert_eq!(sd.daemon().media_floor_in_force(), 1, "nothing landed: nothing re-read");
    }
    sd.shutdown();
}

/// m13 / §4 ROW 35 — THE BACKSTOP IS SAID ONCE AND AGAIN WHEN THE COUNT
/// MOVES, and the re-reads follow a landing the thread did not take: the
/// checkpoint thread HELD before it looks at the flag, the byte bound at one
/// byte, two crossings land — the first sets the flag, the second finds it
/// set and the kernel's backstop runs that checkpoint inline on the
/// committing thread (the count moves to one, the kernel's suite having
/// proved the half) — then the thread released: it finds no flag, reads the
/// newest checkpoint once, re-reads the floor (moved aside beforehand) and
/// the byte bound off it, and says the backstop's line ONCE, counting the one
/// run from the open's start point, genesis — and nothing else, no landing
/// of its own. A quiet commit after says nothing. A third and fourth crossing
/// the same way move the count again, and the line is said again, counting
/// from the first backstop's landed position. The head writer's head for each
/// landed base is refused through its seam for the crossing commit's turn,
/// so the head's own commits do not cross the one-byte bound inside the
/// fixture; the next commit writes it under the re-read bound.
#[test]
fn two_crossings_in_one_run_are_said_once_as_the_backstops_and_again_when_the_count_moves() {
    let mib: u64 = 1024 * 1024;
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    assert!(sd.daemon().newest_checkpoint().is_none());
    assert_eq!(sd.daemon().inline_checkpoints(), 0);
    let start_point = sd.daemon().recovery().expect("journaled").start_point;
    assert_eq!(start_point.0, 0, "a fresh board's start point is genesis");

    // ROUND ONE. The thread held, the floor moved aside, the bound at one
    // byte: the first crossing sets the flag; the second runs inline.
    sd.daemon().hold_the_checkpoint_thread();
    sd.daemon().set_media_floor(1);
    sd.daemon().refuse_the_next_head_once();
    sd.daemon().set_checkpoint_bytes_bound(1);
    let first = commit(port, &owner);
    assert!(sd.daemon().checkpoint_is_due_now(), "the first crossing set the flag");
    assert_eq!(sd.daemon().inline_checkpoints(), 0, "…and ran nothing inline");
    let second = commit(port, &owner);
    assert_eq!(sd.daemon().inline_checkpoints(), 1, "the second crossing ran inline: the backstop");
    assert_eq!(sd.daemon().last_inline_checkpoint_failure(), None, "…and landed");
    let backstop = sd.daemon().newest_checkpoint().expect("the backstop's base");
    assert_eq!(backstop.seq.0, second, "at the committing write's position");
    assert!(lines(&sd).is_empty(), "the held thread has said nothing");
    assert_eq!(sd.daemon().media_floor_in_force(), 1, "…and re-read nothing");

    sd.daemon().release_the_checkpoint_thread();
    wait_until("the backstop's line", || lines(&sd).len() == 1);
    let said = lines(&sd);
    assert_eq!(
        said[0],
        format!(
            "landing: checkpoint: the cadence outran the checkpoint thread; 1 checkpoints ran \
             inline on a writer since position {start_point}, the last landed"
        ),
        "counted from the start point, the class word `landing`"
    );
    assert_eq!(
        sd.daemon().media_floor_in_force(),
        256 * mib,
        "the floor re-read off the backstop's base, no landing of the thread's own"
    );
    assert_eq!(
        sd.daemon().newest_checkpoint().map(|h| h.seq),
        Some(backstop.seq),
        "the thread took no checkpoint of its own"
    );
    assert!(first < second);

    // NO CROSSING, NO LINE: a commit under the re-read bound (the head
    // writer's own commits for the landed base among them) crosses nothing.
    commit(port, &owner);
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(lines(&sd).len(), 1, "{:?}", lines(&sd));
    assert_eq!(sd.daemon().inline_checkpoints(), 1);
    assert!(!sd.daemon().checkpoint_is_due_now());

    // ROUND TWO: the count moves again, and the line is said again, counted
    // from the first backstop's landed position.
    sd.daemon().hold_the_checkpoint_thread();
    sd.daemon().refuse_the_next_head_once();
    sd.daemon().set_checkpoint_bytes_bound(1);
    commit(port, &owner);
    assert!(sd.daemon().checkpoint_is_due_now());
    let fourth = commit(port, &owner);
    assert_eq!(sd.daemon().inline_checkpoints(), 2, "the fourth crossing ran inline");
    assert_eq!(sd.daemon().newest_checkpoint().map(|h| h.seq.0), Some(fourth));
    assert_eq!(lines(&sd).len(), 1, "the held thread has said nothing more");
    sd.daemon().release_the_checkpoint_thread();
    wait_until("the second backstop line", || lines(&sd).len() == 2);
    let said = lines(&sd);
    assert_eq!(
        said[1],
        format!(
            "landing: checkpoint: the cadence outran the checkpoint thread; 1 checkpoints ran \
             inline on a writer since position {}, the last landed",
            backstop.seq.0
        ),
        "counted from the position the thread last said a line for"
    );
    assert_eq!(
        sd.daemon().newest_checkpoint().map(|h| h.seq.0),
        Some(fourth),
        "no checkpoint of the thread's own"
    );
    sd.shutdown();
}
