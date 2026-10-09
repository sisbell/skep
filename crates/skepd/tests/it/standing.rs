//! THE STANDING LINE (`operations.md` §1 THE RATES; §1.1 m11), judged
//! through the daemon's own record of its lines: at each tick of the
//! checkpoint thread's timed wait, ONE `standing:` line naming every
//! standing bad state — each by name, with its position or file, in THE
//! RATES' order — while at least one stands, and NOTHING on a healthy
//! board. The shipped interval is an hour, so every claim shortens the tick
//! through the seam (`Daemon::set_standing_interval_millis`), as the head
//! suite drives the head writer's clock.
//!
//! * NOTHING ON A HEALTHY BOARD: ticks run and no line comes; `/health`
//!   says `"writes":{"halted":false}`; a state pinned later is said at the
//!   next tick, which is how the ticks are known to have run.
//! * ONE LINE PER TICK, EVERY STANDING CLAUSE ON IT: the floor pinned below
//!   itself on a CLAIMED-PERMISSIVE board — both clauses on each line, with
//!   the floor's figures; the floor cleared — the permissive clause alone;
//!   an ENFORCING board with the floor cleared — nothing more.
//! * THE TICK UNDER WAKES: with the cadence crossing far more often than
//!   the interval, ticks still come at the interval — the deadline is
//!   carried across the crossings' wakes, never reset by one.
//! * THE WRITE PATH's HALT: `the write path is halted since position {p}
//!   (feed-attest.log)`, `{p}` the failed position, beside `/health`'s
//!   `writes.halted` — false before, true after, false after the restart.
//! * A STOPPED FILE: `{file} stopped since position {p}` for each of the
//!   five, `{p}` the position each stop names — the fence for
//!   `commits.log`'s rewrite, the coverage for the derived files'.
//!
//! The words are the unit suite's (`server/tests.rs`); the class word and
//! the figures are read here. Every daemon is shut down before the claim
//! returns, so no checkpoint thread outlives its test.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use skepd::Skepd;

use crate::common;
use common::{
    acked_addr, acked_at, claim_board, device_key, get, json, op, open_session,
    open_signed_session, spawn, spawn_configured, spawn_unclaimed, CLAIMANT_ACCOUNT,
    CLAIMANT_DOC1, CLAIMANT_PRINCIPAL,
};

/// The `standing:` lines the daemon has said, oldest first, as its record
/// keeps them.
fn standing_lines(sd: &Skepd) -> Vec<String> {
    sd.daemon().lines_said().into_iter().filter(|l| l.starts_with("standing: ")).collect()
}

/// `/health`'s `writes` object, read whole: its one member, `halted`.
fn writes_halted(port: u16) -> bool {
    let (st, body) = get(port, "/health");
    assert_eq!(st, 200, "/health: {}", String::from_utf8_lossy(&body));
    let v = json(&body);
    let writes = v["writes"].as_object().expect("the writes object");
    assert_eq!(writes.len(), 1, "one member, halted: {v}");
    writes["halted"].as_bool().expect("writes.halted is a boolean")
}

/// `/health`'s `log_position`.
fn head(port: u16) -> u64 {
    let (st, body) = get(port, "/health");
    assert_eq!(st, 200, "/health: {}", String::from_utf8_lossy(&body));
    json(&body)["log_position"].as_u64().expect("log_position")
}

/// One committing write as `session`: a fresh private draft under the
/// claimant's account. Answers the committed position.
fn commit(port: u16, session: &str) -> u64 {
    acked_at(&op(
        port,
        Some(session),
        &format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"}}"#),
    ))
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

/// A QUIET STRETCH: one tick's settling (a tick in flight at the clearing
/// may still say the cleared state), then no `standing:` line across two
/// windows of several ticks each.
fn no_line_comes(sd: &Skepd, what: &str) {
    std::thread::sleep(Duration::from_millis(150));
    let before = standing_lines(sd).len();
    for _ in 0..2 {
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(
            standing_lines(sd).len(),
            before,
            "FINDING (THE RATES): a line came with {what}: {:?}",
            standing_lines(sd)
        );
    }
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
/// reclaims and so compacts the feed's files (the checkpoint suite's
/// recipe). Asserted, so a landing this suite expects to compact has
/// something to compact.
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

/// THE RATES — NOTHING ON A HEALTHY BOARD: an unclaimed board with nothing
/// standing runs ten ticks and says no `standing:` line; `/health` says
/// `"writes":{"halted":false}`, the member whole; then the floor pinned
/// below itself is said at the next tick — the ticks were running all
/// along — and cleared, nothing more comes.
#[test]
fn a_healthy_board_says_no_standing_line_and_health_says_writes_are_not_halted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn_unclaimed(dir.path());
    let port = sd.port();
    sd.daemon().set_standing_interval_millis(40);
    std::thread::sleep(Duration::from_millis(400));
    assert_eq!(
        standing_lines(&sd),
        Vec::<String>::new(),
        "FINDING (THE RATES): a healthy board said a standing line"
    );
    assert!(!writes_halted(port), "FINDING (op-D10 (a)): writes.halted on a healthy board");
    let (_, body) = get(port, "/health");
    assert!(
        String::from_utf8_lossy(&body).contains(r#""writes":{"halted":false}"#),
        "the member as the wire spells it: {}",
        String::from_utf8_lossy(&body)
    );
    // The ticks ran: a state pinned now is said at the next one.
    let floor = sd.daemon().media_floor_in_force();
    sd.daemon().set_media_free_space(Some(1));
    wait_until("the floor's clause", || !standing_lines(&sd).is_empty());
    assert_eq!(
        standing_lines(&sd)[0],
        format!(
            "standing: deposits refused at the floor (free space 1 below the floor in force \
             {floor})"
        ),
        "the class word and the floor's two figures"
    );
    sd.daemon().set_media_free_space(Some(floor));
    no_line_comes(&sd, "the floor cleared on an unclaimed board");
    sd.shutdown();
}

/// THE RATES — ONE LINE PER TICK, EVERY STANDING CLAUSE ON IT: a
/// CLAIMED-PERMISSIVE board with the floor pinned below itself says, at
/// each tick, ONE line carrying both clauses with the floor's figures —
/// never more lines than ticks; the floor cleared, the next tick's line
/// carries the permissive clause alone; and an ENFORCING board says the
/// floor's clause alone while it binds, and nothing once it clears.
#[test]
fn each_tick_says_one_line_carrying_every_standing_clause_and_none_once_the_states_clear() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let floor = sd.daemon().media_floor_in_force();
    sd.daemon().set_media_free_space(Some(100));
    let started = Instant::now();
    sd.daemon().set_standing_interval_millis(60);
    wait_until("three ticks", || standing_lines(&sd).len() >= 3);
    let elapsed = started.elapsed();
    let said = standing_lines(&sd);
    let both = format!(
        "standing: deposits refused at the floor (free space 100 below the floor in force \
         {floor}); CLAIMED-PERMISSIVE"
    );
    for line in &said {
        assert_eq!(line, &both, "every clause standing rides every line");
    }
    assert!(
        said.len() as u128 <= elapsed.as_millis() / 60 + 2,
        "one line per tick and never more: {} lines in {elapsed:?}",
        said.len()
    );
    // The floor cleared: the line past the clearing carries the permissive
    // clause alone (the one right at it may still have been in flight).
    sd.daemon().set_media_free_space(Some(floor));
    let n = standing_lines(&sd).len();
    wait_until("a tick past the clearing", || standing_lines(&sd).len() > n + 1);
    assert_eq!(
        standing_lines(&sd).last().expect("a line"),
        "standing: CLAIMED-PERMISSIVE",
        "the floor's clause stopped by itself once room stood"
    );
    sd.shutdown();

    // ENFORCING: the floor's clause alone, then nothing.
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn_configured(dir.path(), false);
    claim_board(sd.port());
    let floor = sd.daemon().media_floor_in_force();
    sd.daemon().set_media_free_space(Some(7));
    sd.daemon().set_standing_interval_millis(40);
    wait_until("the enforcing board's line", || !standing_lines(&sd).is_empty());
    assert_eq!(
        standing_lines(&sd)[0],
        format!(
            "standing: deposits refused at the floor (free space 7 below the floor in force \
             {floor})"
        ),
        "no permissive clause on an enforcing board"
    );
    sd.daemon().set_media_free_space(Some(floor));
    no_line_comes(&sd, "the floor cleared on an enforcing board");
    sd.shutdown();
}

/// THE RATES — THE TICK UNDER WAKES: the interval at one second and the
/// cadence crossing at every commit (the byte bound re-set to one byte
/// before each, so each raises the thread's `Due` wake — a checkpoint, its
/// backstop and the head writer's commits ride each, some 200 ms under
/// load), far more often than the interval, the ticks still come at the
/// interval on a board whose CLAIMED-PERMISSIVE clause stands — the
/// deadline carried across the wakes. A wait timed from each wake would
/// tick only where a gap between two crossings reached the interval, so
/// the gaps that did are counted and the ticks held above them: under no
/// load none does, and under the gate's a stalled commit or two cannot
/// hide a starved carrier.
#[test]
fn ticks_come_at_the_interval_under_a_stream_of_the_cadences_wakes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let interval = Duration::from_secs(1);
    let run = interval * 6;
    sd.daemon().set_standing_interval_millis(interval.as_millis() as u64);
    let started = Instant::now();
    let mut crossings = 0u32;
    let mut gaps_at_the_interval = 0usize;
    let mut longest_gap = Duration::ZERO;
    let mut last = started;
    while started.elapsed() < run {
        sd.daemon().set_checkpoint_bytes_bound(1);
        commit(port, &owner);
        crossings += 1;
        let now = Instant::now();
        let gap = now.duration_since(last);
        longest_gap = longest_gap.max(gap);
        if gap >= interval {
            gaps_at_the_interval += 1;
        }
        last = now;
    }
    let elapsed = started.elapsed();
    let said = standing_lines(&sd);
    println!(
        "{} ticks in {elapsed:?} under {crossings} crossings; the longest gap between two \
         {longest_gap:?}, {gaps_at_the_interval} gaps at or past the interval",
        said.len()
    );
    assert!(
        crossings >= 6,
        "the premise: the crossings came more often than the interval ({crossings} in \
         {elapsed:?})"
    );
    assert!(
        said.len() >= gaps_at_the_interval + 3,
        "FINDING (THE RATES): {} ticks in {elapsed:?} under {crossings} crossings, \
         {gaps_at_the_interval} of whose gaps reached the interval — a wait timed from each \
         wake starves the tick",
        said.len()
    );
    for line in &said {
        assert_eq!(line, "standing: CLAIMED-PERMISSIVE");
    }
    sd.shutdown();
}

/// m11 — THE WRITE PATH's HALT, RE-SAID WITH ITS POSITION: the attest
/// store's next write failed (the changes suite's drive), the failing write
/// acked at `{p}`; `/health`'s `writes.halted` false before it, true after;
/// the next tick says `the write path is halted since position {p}
/// (feed-attest.log)` beside the board's permissive clause; and after the
/// restart, whose open rebuilt the line, `writes.halted` is false again.
#[test]
fn the_write_paths_halt_is_re_said_with_its_position_and_health_says_halted_until_a_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ghost = |n: u64| {
        format!(
            r#"{{"op":"make_link","home":"{CLAIMANT_DOC1}","from":{{"addrs":[]}},"to":{{"addrs":[]}},"ty":{{"addrs":["{CLAIMANT_DOC1}.0.3.6.{n}"]}}}}"#
        )
    };
    {
        let sd = spawn(dir.path());
        let port = sd.port();
        let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
        acked_at(&op(port, Some(&signed), &ghost(1)));
        assert!(!writes_halted(port), "a healthy board");
        sd.daemon().set_head_writer_clock_millis(u64::MAX);
        sd.daemon().fail_the_attest_stores_next_write();
        let failed_at = acked_at(&op(port, Some(&signed), &ghost(2)));
        assert!(
            writes_halted(port),
            "FINDING (op-D10 (a)): writes.halted is false after the attest halt"
        );
        sd.daemon().set_standing_interval_millis(50);
        wait_until("the halt's clause", || !standing_lines(&sd).is_empty());
        assert_eq!(
            standing_lines(&sd)[0],
            format!(
                "standing: the write path is halted since position {failed_at} \
                 (feed-attest.log); CLAIMED-PERMISSIVE"
            ),
            "FINDING (m11): the halt's clause and its position"
        );
        sd.shutdown();
    }
    let sd = spawn(dir.path());
    assert!(!writes_halted(sd.port()), "the restart's open rebuilt the line: writes admitted");
    sd.shutdown();
}

/// m11 — A STOPPED FILE, RE-SAID WITH THE POSITION ITS STOP NAMES: each of
/// the five files' next compaction rewrite failed past its rename (the
/// existing drive), on a landing that compacts; the next tick names each
/// file with its position — `commits.log` the fence it rewrote behind (the
/// landing line's "compacted below position" less one), the four derived
/// files the coverage they fenced at, the head — beside the board's
/// permissive clause.
#[test]
fn a_stopped_feed_file_is_re_said_with_the_position_its_stop_names() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    rotate_the_segment(port, &owner, dir.path());
    let head = head(port);
    sd.daemon().fail_the_feeds_next_rewrite_past_rename();
    sd.daemon().service_the_checkpoint_now();
    let landing = sd.daemon().checkpoint_lines().last().cloned().expect("the landing's line");
    let fence = figure_after(&landing, "compacted below position ") - 1;
    assert_eq!(sd.daemon().stopped_feed_files().len(), 5, "every file stopped: {landing}");
    sd.daemon().set_standing_interval_millis(50);
    wait_until("the stopped files' clauses", || !standing_lines(&sd).is_empty());
    assert_eq!(
        standing_lines(&sd)[0],
        format!(
            "standing: commits.log stopped since position {fence}; feed-index.log stopped \
             since position {head}; feed-offsets.log stopped since position {head}; \
             feed-masked.log stopped since position {head}; feed-streams.log stopped since \
             position {head}; CLAIMED-PERMISSIVE"
        ),
        "FINDING (m11): the five files, each with the position its stop names"
    );
    sd.shutdown();
}
