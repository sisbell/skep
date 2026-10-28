//! THE START's THREE CHECKPOINT SETTINGS (RUNBOOK §3 step 2's rows;
//! `StartOptions`): the cadence's commit count, the retained count and the
//! journal's reclamation — the library's face of `--checkpoint-every`,
//! `--retain-checkpoints` and `--reclaim-journal`, each read once at the
//! open and persisted nowhere — spawned through
//! `common::spawn_with_checkpoint_settings` over a board the default spawn
//! seeded and claimed first, so the open's base is a recovered head and no
//! commit of the seed's or the claim's counts toward a window:
//!
//! * THE CADENCE: under a count of eight the first landing comes at the
//!   eighth commit after the open, and the next eight kernel commits later —
//!   the head writer's two commits for the landed base among them.
//! * THE RETAINED COUNT: under three, four landings leave three bases
//!   standing and the fourth's line names the one its retention removed, by
//!   its name and its length, as the kernel accounts it; and every landing's
//!   media floor is the newest base's, as under the default count.
//! * THE RECLAMATION: under `never` every segment since genesis stands
//!   across four landings, each line reading `nothing reclaimed`,
//!   `/chain?at=0` answers the genesis chain, and `/op-at` below the oldest
//!   retained base answers the state — member for member what a board that
//!   never crossed a cadence answers at the same position.
//! * ONE START's WORD: that board restarted without the word reclaims below
//!   its oldest retained base at its next landing, the segments gone, and
//!   `/op-at` below answers `history_reclaimed` with the floor.
//! * THE CEILING: under a cadence of eight and two retained, a torn
//!   `commits.log` is re-covered behind the listener over at most sixteen
//!   boundaries — the retained window — the rest fenced at the floor.
//!
//! Every landing a claim drives comes by the cadence itself, one commit at
//! a time, so the counts are the kernel's; no suite captures the operator
//! stream in-process, so each line is read back through
//! `Daemon::checkpoint_lines` and the walk's through `Daemon::lines_said`.

use std::collections::BTreeSet;
use std::fs;
use std::num::{NonZeroU64, NonZeroUsize};
use std::path::Path;
use std::time::{Duration, Instant};

use serde_json::Value;
use skepd::{JournalReclamation, Skepd, StartOptions};

use crate::common::{
    acked_addr, acked_at, get, http, json, op, open_session, spawn,
    spawn_with_checkpoint_settings, CLAIMANT_ACCOUNT, CLAIMANT_PRINCIPAL, SEED_HEAD,
};

/// The claimed board's head as the claim leaves it (`feed_walk.rs` pins it).
const CLAIMED_HEAD: u64 = SEED_HEAD + 22;

/// The start under the three settings, every other option the default's.
fn settings(every: u64, retain: usize, reclaim: JournalReclamation) -> StartOptions {
    let mut start = StartOptions::default();
    start.checkpoint_every = NonZeroU64::new(every).expect("a cadence");
    start.retain_checkpoints = NonZeroUsize::new(retain).expect("a count");
    start.reclaim_journal = reclaim;
    start
}

/// One committing write as `session`: a fresh private draft under the
/// claimant's account — one record, so the position advances by one.
fn commit(port: u16, session: &str) -> u64 {
    acked_at(&op(
        port,
        Some(session),
        &format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"}}"#),
    ))
}

/// A fresh private draft's address, under the claimant's account.
fn draft(port: u16, session: &str) -> String {
    acked_addr(&op(
        port,
        Some(session),
        &format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"}}"#),
    ))
}

/// One bulk insert into `doc`: 256 KiB of one letter, so four fill a
/// segment past its rotation threshold (the recipe `checkpoint.rs` rotates
/// with). Answers the committed position.
fn insert_bulk(port: u16, session: &str, doc: &str) -> u64 {
    let bulk = "z".repeat(262_144);
    acked_at(&op(
        port,
        Some(session),
        &format!(
            r#"{{"op":"insert","doc":"{doc}","at":{{"subspace":"1","ordinal":"1"}},"values":["{bulk}"]}}"#
        ),
    ))
}

/// A read frame: the first `width` characters of `doc`'s text.
fn retrieve(doc: &str, width: u64) -> String {
    format!(
        r#"{{"op":"retrieve_v","specs":[{{"doc":"{doc}","span":{{"start":"1.1","width":"0.{width}"}}}}]}}"#
    )
}

/// One `/op-at` exchange as `token`: the status and the body.
fn op_at(port: u16, token: &str, at: u64, frame: &str) -> (u16, Value) {
    let body = format!(r#"{{"at":{at},"frame":{frame}}}"#);
    let (st, body) = http(port, "POST", "/op-at", Some(token), body.as_bytes());
    (st, json(&body))
}

/// `GET /changes?{query}` as `token`: the status and the body.
fn changes(port: u16, token: &str, query: &str) -> (u16, Value) {
    let (st, body) = http(port, "GET", &format!("/changes?{query}"), Some(token), b"");
    (st, json(&body))
}

/// The journal's segment files under `dir`, by name.
fn segments(dir: &Path) -> BTreeSet<String> {
    fs::read_dir(dir)
        .expect("the data dir")
        .map(|e| e.expect("an entry").file_name().into_string().expect("a name"))
        .filter(|name| name.starts_with("seg-") && name.ends_with(".wal"))
        .collect()
}

/// The checkpoint files under `dir`, by the position each embodies.
fn checkpoints(dir: &Path) -> BTreeSet<u64> {
    fs::read_dir(dir)
        .expect("the data dir")
        .map(|e| e.expect("an entry").file_name().into_string().expect("a name"))
        .filter_map(|name| name.strip_prefix("checkpoint.")?.parse().ok())
        .collect()
}

/// The lines the checkpoint thread's arms have said, as the hook keeps them.
fn lines(sd: &Skepd) -> Vec<String> {
    sd.daemon().checkpoint_lines()
}

/// The position a landing's line names: `landing: checkpoint at position
/// {p} landed (`.
fn landing_position(line: &str) -> u64 {
    let rest = line
        .strip_prefix("landing: checkpoint at position ")
        .unwrap_or_else(|| panic!("a landing's line: {line}"));
    let (p, _) = rest.split_once(" landed (").unwrap_or_else(|| panic!("{line}"));
    p.parse().expect("a position")
}

/// Poll until `done`, within the suite's patience, naming what never came.
fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Drives the `nth` landing by the cadence alone: one commit of `write`'s
/// at a time, the checkpoint thread held meanwhile so the crossing's flag
/// stands until this sees it and no write of this suite's runs on into the
/// next window while the checkpoint is in flight; then the thread released
/// and its `nth` line awaited and answered. Bounded, so a cadence that never
/// crosses fails here by name.
fn land_by_the_cadence(sd: &Skepd, nth: usize, mut write: impl FnMut() -> u64) -> String {
    assert_eq!(lines(sd).len(), nth - 1, "landing {nth} next: {:?}", lines(sd));
    sd.daemon().hold_the_checkpoint_thread();
    let crossed = (0..64).any(|_| {
        write();
        sd.daemon().checkpoint_is_due_now()
    });
    assert!(crossed, "sixty-four commits and no crossing for landing {nth}");
    sd.daemon().release_the_checkpoint_thread();
    wait_until(&format!("landing {nth}"), || lines(sd).len() >= nth);
    let said = lines(sd);
    assert_eq!(said.len(), nth, "one line per landing: {said:?}");
    said[nth - 1].clone()
}

/// Tear `commits.log` back to the entry at `low`: every line whose `at` lies
/// above `low` dropped, so the next open's region is `(low, head]`
/// (`feed_walk.rs`'s recipe).
fn tear_to(dir: &Path, low: u64) {
    let path = dir.join("commits.log");
    let text = fs::read_to_string(&path).expect("commits.log");
    let kept: String = text
        .lines()
        .filter(|line| {
            let v: Value = serde_json::from_str(line).expect("a line is JSON");
            v.get("at").and_then(Value::as_u64).is_none_or(|at| at <= low)
        })
        .map(|line| format!("{line}\n"))
        .collect();
    fs::write(&path, kept).expect("tear the file");
}

/// THE CADENCE SETTING: under `--checkpoint-every 8` nothing lands through
/// seven commits after the open and the eighth lands, at its own position —
/// one record per commit and nothing else committed, so the position is the
/// open's head plus eight; the next window is eight kernel commits, and the
/// head writer's two commits for the landed base (`H.2`'s insert and
/// publish, at the next write's turn) count among them, so the second
/// landing comes at the sixth of this suite's writes after the first, the
/// fourteenth in all, at that write's position. A cadence left at the
/// default would land nothing here.
#[test]
fn the_cadence_setting_lands_at_the_eighth_commit_and_eight_kernel_commits_later() {
    let dir = tempfile::tempdir().expect("tempdir");
    spawn(dir.path()).shutdown();
    let sd = spawn_with_checkpoint_settings(
        dir.path(),
        settings(8, 2, JournalReclamation::BelowOldestCheckpoint),
    );
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let head_at_open = sd.daemon().log_position().0;
    assert!(sd.daemon().newest_checkpoint().is_none(), "the default spawn landed no base");

    let mut last = head_at_open;
    for n in 1..=7u64 {
        last = commit(port, &owner);
        assert!(!sd.daemon().checkpoint_is_due_now(), "commit {n} of 8: inside the window");
        assert!(lines(&sd).is_empty(), "no landing inside the window: {:?}", lines(&sd));
    }
    assert_eq!(last, head_at_open + 7, "one record per commit, nothing else committed");
    let eighth = commit(port, &owner);
    assert_eq!(eighth, head_at_open + 8);
    wait_until("the first landing", || lines(&sd).len() == 1);
    let first = sd.daemon().newest_checkpoint().expect("the first landing");
    assert_eq!(first.seq.0, eighth, "the eighth commit after the open's base crossed");
    assert_eq!(landing_position(&lines(&sd)[0]), eighth);

    // The next window: eight kernel commits from the crossing. The head
    // writer writes `H.2` for the landed base at the next write's turn, two
    // commits of its own, so the ninth write stands one position above the
    // eighth and the tenth more than one above the ninth.
    let ninth = commit(port, &owner);
    assert_eq!(ninth, eighth + 1, "the ninth write commits before the head writer's turn");
    let mut positions = vec![ninth];
    for n in 10..=13u64 {
        positions.push(commit(port, &owner));
        assert!(!sd.daemon().checkpoint_is_due_now(), "write {n}: inside the second window");
        assert_eq!(lines(&sd).len(), 1, "no second landing yet: {:?}", lines(&sd));
    }
    assert!(
        positions[1] > positions[0] + 1,
        "the head's two commits for the landed base landed after the ninth write: {positions:?}"
    );
    let fourteenth = commit(port, &owner);
    wait_until("the second landing", || lines(&sd).len() == 2);
    let second = sd.daemon().newest_checkpoint().expect("the second landing");
    assert_eq!(
        second.seq.0, fourteenth,
        "eight kernel commits after the first crossing — the head's two among them — the \
         fourteenth write crossed: {:?}",
        lines(&sd)
    );
    assert_eq!(landing_position(&lines(&sd)[1]), fourteenth);
    sd.shutdown();
}

/// THE RETAINED COUNT SETTING, AND THE FLOOR THAT IS NOT THE COUNT's: under
/// `--retain-checkpoints 3 --checkpoint-every 8`, four landings by the
/// cadence leave exactly three `checkpoint.<n>` files — the newest three —
/// the first three lines naming no removal and the fourth naming the first
/// base by its name and its length on disk, read before the landing, as the
/// kernel's own account of the landing has it; and every landing's line
/// carries the media floor the default board's lines carry at the same
/// newest-checkpoint size, 256 MiB, since the floor is sized by the newest
/// base and never by how many stand.
#[test]
fn the_retained_count_setting_keeps_three_bases_and_the_fourth_landing_names_the_one_removed() {
    let dir = tempfile::tempdir().expect("tempdir");
    spawn(dir.path()).shutdown();
    let sd = spawn_with_checkpoint_settings(
        dir.path(),
        settings(8, 3, JournalReclamation::BelowOldestCheckpoint),
    );
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let mut landed = Vec::new();
    for n in 1..=3 {
        let line = land_by_the_cadence(&sd, n, || commit(port, &owner));
        landed.push(landing_position(&line));
        assert!(!line.contains(" removed ("), "{n} of 3 kept, none removed: {line}");
    }
    assert_eq!(checkpoints(dir.path()), landed.iter().copied().collect(), "three stand");
    let first_len =
        fs::metadata(dir.path().join(format!("checkpoint.{}", landed[0]))).expect("the first").len();

    let line = land_by_the_cadence(&sd, 4, || commit(port, &owner));
    landed.push(landing_position(&line));
    assert_eq!(
        checkpoints(dir.path()),
        landed[1..].iter().copied().collect(),
        "the newest three stand, the first removed"
    );
    let removed = sd.daemon().last_removed_checkpoints();
    assert_eq!(removed.len(), 1, "the kernel's account: one removed: {removed:?}");
    assert_eq!((removed[0].0 .0, removed[0].1), (landed[0], first_len));
    assert!(
        line.contains(&format!(
            " reclaimed; checkpoint.{} removed ({first_len} bytes); the cadence's byte bound ",
            landed[0]
        )),
        "the removed base by its name and its length, after the reclaimed clause: {line}"
    );
    for line in lines(&sd) {
        assert!(
            line.contains(", the media floor in force 268435456, "),
            "the floor is the newest base's — 256 MiB on a small board whatever the count: {line}"
        );
    }
    sd.shutdown();
}

/// THE RECLAMATION SETTING, `never`, AND ONE START's WORD: under
/// `--reclaim-journal never --checkpoint-every 8 --retain-checkpoints 2`
/// four landings by the cadence, each window rotating the journal's segment,
/// leave every `seg-<n>.wal` since genesis standing — the set only grows —
/// each line reading `nothing reclaimed` where the default would have
/// reclaimed from the second on, the kernel's figure zero; `/chain?at=0`
/// answers the genesis chain; and `/op-at` at a position below the oldest
/// retained base — the first bulk insert's — answers the state, member for
/// member what a board that never crossed a cadence answers at that
/// position, never `history_reclaimed`. Then the same board RESTARTED
/// without the word: at its next landing the journal below its oldest
/// retained base is reclaimed, the segments gone, the line carrying the
/// bytes, and the same `/op-at` answers `history_reclaimed` with the floor
/// — the setting was that start's alone.
#[test]
fn never_keeps_every_segment_and_serves_below_the_oldest_base_until_a_restart_reclaims() {
    // THE TWIN: the same first two writes on a board that never crosses a
    // cadence, whose answer below the floor is the one to equal.
    let twin_dir = tempfile::tempdir().expect("tempdir");
    let twin = spawn(twin_dir.path());
    let twin_owner = open_session(twin.port(), CLAIMANT_PRINCIPAL);
    let twin_draft = draft(twin.port(), &twin_owner);
    let twin_at = insert_bulk(twin.port(), &twin_owner, &twin_draft);
    let (st, expected) = op_at(twin.port(), &twin_owner, twin_at, &retrieve(&twin_draft, 8));
    assert_eq!(st, 200, "{expected}");
    assert_eq!(expected["resp"].as_str(), Some("delivery"), "{expected}");
    assert_eq!(expected["items"][0]["content"].as_str(), Some("zzzzzzzz"), "{expected}");
    twin.shutdown();

    let dir = tempfile::tempdir().expect("tempdir");
    spawn(dir.path()).shutdown();
    let sd = spawn_with_checkpoint_settings(dir.path(), settings(8, 2, JournalReclamation::Never));
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let doc = draft(port, &owner);
    let at = insert_bulk(port, &owner, &doc);
    assert_eq!((doc.as_str(), at), (twin_draft.as_str(), twin_at), "the twin's positions");

    let mut standing = segments(dir.path());
    let mut landed = Vec::new();
    for n in 1..=4 {
        let line = land_by_the_cadence(&sd, n, || insert_bulk(port, &owner, &doc));
        landed.push(landing_position(&line));
        let now = segments(dir.path());
        assert!(now.is_superset(&standing), "landing {n} removed a segment: {standing:?} → {now:?}");
        assert!(now.len() > standing.len(), "the window rotated the segment: {now:?}");
        standing = now;
        assert!(line.contains(" ms; nothing reclaimed; "), "landing {n}: {line}");
        assert_eq!(sd.daemon().last_reclaimed_bytes(), Some(0), "the kernel's figure");
    }
    assert!(standing.contains("seg-1.wal"), "the segment that began the log stands: {standing:?}");
    assert_eq!(checkpoints(dir.path()), landed[2..].iter().copied().collect(), "two retained");
    assert!(at < landed[2], "the read's position lies below the oldest retained base");

    let (st, body) = get(port, "/chain?at=0");
    let chain = json(&body);
    assert_eq!((st, chain["at"].as_u64()), (200, Some(0)), "genesis answers: {chain}");
    let (st, answer) = op_at(port, &owner, at, &retrieve(&doc, 8));
    assert_eq!(st, 200, "served from the kept journal: {answer}");
    assert_eq!(answer, expected, "the state, member for member, as the twin answers it");
    let oldest_retained = landed[2];
    let before_restart = segments(dir.path());
    sd.shutdown();

    // THE RESTART WITHOUT THE WORD: the defaults, so the next landing — at a
    // new head, so three bases stand before its retention — reclaims below
    // the oldest base kept, the fourth landing's.
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    commit(port, &owner);
    sd.daemon().service_the_checkpoint_now();
    let said = lines(&sd);
    assert_eq!(said.len(), 1, "{said:?}");
    let reclaimed = sd.daemon().last_reclaimed_bytes().expect("a landing's figure");
    assert!(reclaimed > 0, "the journal below the oldest retained base reclaimed: {}", said[0]);
    assert!(
        said[0].contains(&format!(
            " ms; {reclaimed} journal bytes reclaimed; checkpoint.{oldest_retained} removed ("
        )),
        "the landings {landed:?}, the oldest retained {oldest_retained}, the files {:?}: {}",
        checkpoints(dir.path()),
        said[0]
    );
    let after = segments(dir.path());
    assert!(!after.contains("seg-1.wal"), "the segment that began the log is gone: {after:?}");
    assert!(after.len() < before_restart.len(), "{before_restart:?} → {after:?}");
    let floor = landed[3];
    let (st, answer) = op_at(port, &owner, at, &retrieve(&doc, 8));
    assert_eq!(st, 410, "{answer}");
    assert_eq!(answer["error"].as_str(), Some("history_reclaimed"), "{answer}");
    assert_eq!(answer["floor"].as_u64(), Some(floor), "the oldest retained base: {answer}");
    sd.shutdown();
}

/// THE CEILING FOLLOWS THE SETTINGS: under `--checkpoint-every 8
/// --retain-checkpoints 2` five landings by the cadence, each window
/// rotating the journal's segment, leave the oldest retained base at most
/// sixteen commits behind the head and the journal reclaimed below it;
/// `commits.log` torn back to the claim and the board restarted under the
/// same settings, the walk behind the listener re-covers at most sixteen
/// boundaries — the retained window, where the default's is two thousand
/// and forty-eight — fences the rest where the journal refused, and
/// `/changes` below the fence answers `history_reclaimed` naming the first
/// line held, at or above the oldest retained base, while a page from there
/// serves to the head.
#[test]
fn the_walk_behind_the_listener_re_covers_at_most_the_retained_window() {
    let dir = tempfile::tempdir().expect("tempdir");
    spawn(dir.path()).shutdown();
    let start = settings(8, 2, JournalReclamation::BelowOldestCheckpoint);
    let sd = spawn_with_checkpoint_settings(dir.path(), start);
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let doc = draft(port, &owner);
    let mut landed = Vec::new();
    for n in 1..=5 {
        let line = land_by_the_cadence(&sd, n, || insert_bulk(port, &owner, &doc));
        landed.push(landing_position(&line));
    }
    let head = sd.daemon().log_position().0;
    let oldest_retained = landed[3];
    assert_eq!(checkpoints(dir.path()), landed[3..].iter().copied().collect(), "two retained");
    assert!(
        sd.daemon().last_reclaimed_bytes().is_some_and(|bytes| bytes > 0),
        "the fifth landing reclaimed the journal below the oldest retained base"
    );
    assert!(!segments(dir.path()).contains("seg-1.wal"), "genesis is gone: {:?}", segments(dir.path()));
    sd.shutdown();

    tear_to(dir.path(), CLAIMED_HEAD);
    let sd = spawn_with_checkpoint_settings(dir.path(), start);
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let landing: Vec<String> = sd
        .daemon()
        .lines_said()
        .into_iter()
        .filter(|l| l.starts_with("landing: commits.log re-covered positions ("))
        .collect();
    assert_eq!(landing.len(), 1, "the walk's landing line once: {landing:?}");
    let rest = landing[0].strip_prefix("landing: commits.log re-covered positions (").unwrap();
    let (_region, rest) = rest.split_once("]: ").unwrap_or_else(|| panic!("{landing:?}"));
    let (walked, _) = rest.split_once(" boundaries walked, ").unwrap_or_else(|| panic!("{landing:?}"));
    let walked: u64 = walked.parse().expect("a count");
    assert!(
        (1..=16).contains(&walked),
        "the walk re-covers the retained window at most — the cadence times the count, 16 — \
         never the default's 2,048: {landing:?}"
    );
    let (st, v) = changes(port, &owner, &format!("since={CLAIMED_HEAD}&limit=4096"));
    assert_eq!((st, v["error"].as_str()), (410, Some("history_reclaimed")), "{v}");
    let floor = v["floor"].as_u64().expect("the first line held");
    assert!(
        oldest_retained <= floor && floor <= head,
        "the first line held lies at or above the oldest retained base, the journal having \
         refused the boundaries below it: floor {floor}, the oldest retained base \
         {oldest_retained}, the head {head}"
    );
    let (st, v) = changes(port, &owner, &format!("since={floor}&limit=4096"));
    assert_eq!(st, 200, "a page from the floor serves: {v}");
    assert_eq!(v["last"].as_u64(), Some(head), "…to the head: {v}");
    sd.shutdown();
}
