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
//! count, the daemon's resident-set high-water, the floor in force) and against
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
    let bulk = "z".repeat(262_144);
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

/// Returns line 25's last clause, what `feed-attest.log` holds.
///
/// It is read off the data directory: no write of this suite is attested —
/// each lands in a private draft — so the file's size stands from the open
/// on and no slot is resident.
fn attest_figures(dir: &Path) -> String {
    let bytes = fs::metadata(dir.join("feed-attest.log")).expect("the attest store").len();
    format!("; feed-attest.log {bytes} bytes, 0 slots resident")
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

/// Waits for the pruner's first pass to be said.
///
/// Its line takes a reading of the resident set too, and the next pass is
/// an hour on, so once it is said no reading but the checkpoint thread's
/// lands: a suite pinning a landing's resident figures against the daemon's
/// high-water waits for it first.
fn wait_for_the_first_pass(sd: &Skepd) {
    wait_until("the pruner's first pass", || {
        sd.daemon().lines_said().iter().any(|l| l.starts_with("landing: pruner: "))
    });
}

/// The resident clause's two figures: the reading the line took, and the
/// largest of the uptime's readings beside it, the reading never above it.
fn resident_figures(line: &str) -> (u64, u64) {
    let now = figure_after(line, "the process's resident set ");
    let largest = figure_after(line, ", the largest of this uptime's readings ");
    assert!(now > 0 && now <= largest, "a reading, never above the largest: {line}");
    (now, largest)
}

/// `line` with the milliseconds figure between `lead` and `trail` — a run's
/// duration, the one figure no test can fix — read out and judged a whole
/// number, and the rest of the line handed back for its pin with `N` in the
/// figure's place.
fn ms_read_out(line: &str, lead: &str, trail: &str) -> String {
    let (head, tail) =
        line.split_once(lead).unwrap_or_else(|| panic!("the line says {lead:?}: {line}"));
    let (ms, rest) =
        tail.split_once(trail).unwrap_or_else(|| panic!("…in milliseconds: {line}"));
    ms.parse::<u128>()
        .unwrap_or_else(|e| panic!("{ms:?} is no whole number of milliseconds ({e}): {line}"));
    format!("{head}{lead}N{trail}{rest}")
}

/// The backstop's line with how long the inline run held every write read
/// out ([`ms_read_out`]).
fn held_ms_read_out(line: &str) -> String {
    ms_read_out(line, "holding every write ", " ms, ")
}

/// The backstop's line cut at the newest checkpoint's clause: the line up to
/// it, and the clause after `; the newest checkpoint at position `, where
/// the wake took the landing's re-reads.
fn newest_clause(line: &str) -> (&str, &str) {
    line.split_once("; the newest checkpoint at position ")
        .unwrap_or_else(|| panic!("the line names the newest checkpoint and what it moved: {line}"))
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
/// held above it; the resident set's reading is above zero and never above
/// the largest of the uptime's readings beside it, that one is the daemon's
/// high-water and never decreases across two landings; both bounds are the
/// small board's, and the compaction fence is the reclaim floor, its
/// duration whole milliseconds.
#[test]
fn a_landing_line_carries_the_kernels_reclaimed_bytes_the_hosts_free_space_and_the_resident_peak() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    wait_for_the_first_pass(&sd);
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
    let (_, largest) = resident_figures(line);
    assert_eq!(largest, peak, "the largest reading is the daemon's high-water: {line}");
    assert!(!line.contains("peaked"), "the largest reading is no peak of the process's: {line}");
    let compacted = ms_read_out(
        line,
        &format!("; the change feed's files compacted below position {} in ", landed.seq.0),
        " ms",
    );
    assert!(
        compacted.ends_with(&format!(
            "; the change feed's files compacted below position {} in N ms{}",
            landed.seq.0,
            attest_figures(dir.path())
        )),
        "the fence is the reclaim floor — the oldest kept base — the hold in whole milliseconds, \
         no file stood, then what the attest store holds, and no inline run moved: {line}"
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
    assert_eq!(resident_figures(line).1, peak_after, "{line}");
    assert!(
        line.ends_with(&format!(
            "; the change feed's files hold nothing below the reclaim floor{}",
            attest_figures(dir.path())
        )),
        "{line}"
    );
    assert!(!line.contains("ran inline"), "no inline run: no clause: {line}");
    sd.shutdown();
}

/// ROW 25 — A CHECKPOINT RETENTION REMOVED IS NAMED: the daemon keeps two
/// bases, so a third landing at a new head removes the oldest, and that
/// landing's line names the file by its own name and its length on disk,
/// read before the landing, beside the bytes reclaimed — where the two
/// landings before it, which removed none, named none.
#[test]
fn a_landing_line_names_each_checkpoint_its_retention_removed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let mut landed = Vec::new();
    for _ in 0..2 {
        commit(port, &owner);
        sd.daemon().service_the_checkpoint_now();
        landed.push(sd.daemon().newest_checkpoint().expect("a landing").seq.0);
    }
    assert!(landed[0] < landed[1], "two landings at two heads: {landed:?}");
    let said = lines(&sd);
    assert!(
        said.iter().all(|line| !line.contains(" removed (")),
        "two kept, none removed: {said:?}"
    );

    let oldest = dir.path().join(format!("checkpoint.{}", landed[0]));
    let oldest_len = fs::metadata(&oldest).expect("the oldest base stands").len();
    commit(port, &owner);
    sd.daemon().service_the_checkpoint_now();
    let said = lines(&sd);
    let line = said.last().expect("the third landing's line");
    assert!(!oldest.exists(), "retention removed the oldest base");
    assert!(
        line.contains(&format!(
            " reclaimed; checkpoint.{} removed ({oldest_len} bytes); the cadence's byte bound ",
            landed[0]
        )),
        "the removed base by its name and its length, after the reclaimed clause: {line}"
    );
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
    let compacted = ms_read_out(
        line,
        &format!("; the change feed's files compacted below position {landed} in "),
        " ms, ",
    );
    assert!(
        compacted.ends_with(&format!(
            "; the change feed's files compacted below position {landed} in N ms, \
             feed-index.log standing as it was{}",
            attest_figures(dir.path())
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
/// LANDED, so the line is the landed arm, naming the landed position, its
/// size, the run's duration, "the directory's sync" and "the volume is
/// full", and the thread takes the landing's re-reads off the landed base and
/// SAYS them: the media floor, moved aside beforehand, is back at the figure
/// the base sizes, and the byte bound, moved to one byte, is back at the
/// floor's 24 MiB — each figure on the line — so a small commit after crosses
/// nothing. Retention failing — a directory squatting on a name it must
/// remove — is the landed arm with "retention". A failure BEFORE the rename —
/// the temp file's sync — is the `Io` arm: no base, the run's duration, the
/// head's position as an ordering, the floor unmoved; and SAID PER ATTEMPT, a
/// second armed attempt saying it again.
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
    let line = ms_read_out(&said[0], " bytes) in ", " ms but ");
    assert!(
        line.starts_with(&format!(
            "failure: a checkpoint landed at position {} ({} bytes) in N ms but the directory's \
             sync failed: the volume is full (",
            landed.seq.0, landed.len
        )),
        "{line}"
    );
    assert!(
        line.contains(&format!(
            "; the cadence's byte bound {}, the media floor in force {}, the volume's free space ",
            24 * mib,
            256 * mib
        )),
        "what the re-reads off the landed base moved, said: {line}"
    );
    assert!(!line.contains("reclaimed;"), "no reclaim figure for a call that failed: {line}");
    assert!(
        line.ends_with(
            "; the journal is not reclaimed and holds every commit; the next attempt is at the \
             cadence's next crossing"
        ),
        "{line}"
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
        ms_read_out(&said[1], " bytes) in ", " ms but ").starts_with(&format!(
            "failure: a checkpoint landed at position {} ({} bytes) in N ms but retention \
             failed: ",
            landed.seq.0, landed.len
        )),
        "{}",
        said[1]
    );
    assert!(said[1].contains("the media floor in force 268435456"), "{}", said[1]);
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
            ms_read_out(line, "FAILED after ", " ms ("),
            format!(
                "failure: checkpoint FAILED after N ms (the head stood at position {at} when the \
                 run began): the volume is full (checkpoint.tmp: fsync: injected StorageFull at \
                 CheckpointSync); the journal is not reclaimed and holds every commit; the next \
                 attempt is at the cadence's next crossing"
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
    let (line, newest) = newest_clause(&said[0]);
    assert_eq!(
        held_ms_read_out(line),
        format!(
            "landing: checkpoint: the cadence outran the checkpoint thread; 1 checkpoints ran \
             inline on a writer since position {start_point}, the last run by the commit at \
             position {second}, holding every write N ms, landed at position {second}"
        ),
        "counted from the start point, the class word `landing`, the run named by the commit \
         that carried it"
    );
    assert!(
        newest.starts_with(&format!("{second} ({} bytes): ", backstop.len)),
        "the base the wake took the re-reads off: {newest}"
    );
    assert!(
        newest.contains(&format!(
            "reclaimed; the cadence's byte bound {}, the media floor in force {}, ",
            24 * mib,
            256 * mib
        )),
        "a run that landed its base whole: what it reclaimed, then what the re-reads moved, the \
         floor and the bound among them: {newest}"
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
    let (line, newest) = newest_clause(&said[1]);
    assert_eq!(
        held_ms_read_out(line),
        format!(
            "landing: checkpoint: the cadence outran the checkpoint thread; 1 checkpoints ran \
             inline on a writer since position {}, the last run by the commit at position \
             {fourth}, holding every write N ms, landed at position {fourth}",
            backstop.seq.0
        ),
        "counted from the position the thread last said a line for"
    );
    assert!(newest.starts_with(&format!("{fourth} (")), "{newest}");
    assert!(newest.contains("the media floor in force 268435456"), "{newest}");
    assert_eq!(
        sd.daemon().newest_checkpoint().map(|h| h.seq.0),
        Some(fourth),
        "no checkpoint of the thread's own"
    );
    sd.shutdown();
}

/// m13 — A BACKSTOP WHOSE INLINE RUN LANDED ITS BASE AND THEN FAILED says
/// what the landing moved and no reclaim figure: the thread held, the floor
/// moved aside and the byte bound at one byte, the first crossing sets the
/// flag; the directory's sync armed to fail on a full volume, the second
/// crossing runs the checkpoint inline — its base LANDS and its directory's
/// sync fails, the commit acknowledged all the same, so the kernel stores no
/// reclaim figure for the run. Released, the thread finds the newest
/// checkpoint moved and takes the landing's re-reads off it: the backstop's
/// line says the run FAILED, then the newest base and what the re-reads
/// moved — the floor back at the figure the base sizes, the byte bound at
/// the floor's 24 MiB — and nothing reclaimed, a figure the kernel holds for
/// a run that landed whole alone.
#[test]
fn a_backstop_whose_run_landed_its_base_and_then_failed_says_what_moved_and_no_reclaim() {
    let mib: u64 = 1024 * 1024;
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    sd.daemon().hold_the_checkpoint_thread();
    sd.daemon().set_media_floor(1);
    sd.daemon().refuse_the_next_head_once();
    sd.daemon().set_checkpoint_bytes_bound(1);
    commit(port, &owner);
    assert!(sd.daemon().checkpoint_is_due_now(), "the first crossing set the flag");
    sd.daemon().fail_the_next_checkpoint_step(Step::CheckpointDirSync, ErrorKind::StorageFull);
    let second = commit(port, &owner);
    assert_eq!(sd.daemon().inline_checkpoints(), 1, "the second crossing ran inline");
    assert!(
        sd.daemon().last_inline_checkpoint_failure().is_some(),
        "…and its directory's sync failed"
    );
    let landed = sd.daemon().newest_checkpoint().expect("the inline run's base landed");
    assert_eq!(landed.seq.0, second, "at the committing write's position");
    sd.daemon().release_the_checkpoint_thread();
    wait_until("the backstop's line", || lines(&sd).len() == 1);
    let said = lines(&sd);
    let (line, newest) = newest_clause(&said[0]);
    assert!(
        line.starts_with("landing: checkpoint: the cadence outran the checkpoint thread; "),
        "{line}"
    );
    assert!(line.contains(&format!("the last run by the commit at position {second}, ")), "{line}");
    assert!(line.contains(" ms, FAILED: "), "the run's failure, in the kernel's words: {line}");
    assert!(
        newest.starts_with(&format!(
            "{second} ({} bytes): the cadence's byte bound {}, the media floor in force {}, ",
            landed.len,
            24 * mib,
            256 * mib
        )),
        "what the re-reads off the landed base moved, and no reclaim figure: {newest}"
    );
    assert!(!newest.contains("reclaimed"), "no reclaim figure for a run that failed: {newest}");
    assert_eq!(sd.daemon().media_floor_in_force(), 256 * mib, "the floor re-read off the base");
    assert_eq!(
        sd.daemon().newest_checkpoint().map(|h| h.seq.0),
        Some(second),
        "no checkpoint of the thread's own"
    );
    sd.shutdown();
}
