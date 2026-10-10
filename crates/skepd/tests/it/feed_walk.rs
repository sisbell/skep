//! THE WALK BEHIND THE LISTENER (`operations.md` §3.3 step 2; §1.1 m15; §4
//! row 16; the ops lanes' D9): where `commits.log` was lost or torn, the
//! open records the positions it does not cover as a PENDING REGION
//! `(low, head]` and returns; a thread of the write path's walks the region
//! while the board serves and lands it by ONE rewrite; meanwhile a
//! `/changes` page whose rows would come from the region is refused `503
//! feed_rebuilding`, retry-class, pages below and above serving and
//! `/events` untouched. Judged in-process through the daemon's hold on the
//! walk (`Daemon::hold_the_feed_walk`, armed before the open) and its record
//! of its lines:
//!
//! * T1 — the board serves while the walk is held: `/health`, the `open:`
//!   line, the region read, the refusal with its `detail`, a page above the
//!   head, a write that commits and reaches `/events`; the landing restores
//!   the feed — the torn positions bare, the write recorded — byte-identical
//!   to a clean restart's, the offset array agreeing with the file.
//! * T5 — the three lines at the cadence: `open:` once, `progress:` every
//!   two boundaries with `{p}` ascending, `landing:` once with the
//!   boundaries proved; none at the shipped cadence over a short region.
//! * T6 — the refusal's arithmetic: the page's ROWS, not its `since` alone
//!   — a page below the region serves its `limit` rows at or below `low`
//!   with `more: true`, one that would reach past `low` is refused, `low`
//!   itself is covered and `head` is not, a page from the head serves, and
//!   a sparse class (the guest's) is refused where the position range
//!   alone would have served it over the region.
//! * T9 — the walk's death: the catch's line once, the board serving, the
//!   region refused, a write admitted, the standing line's clause, and a
//!   reopen walking again.
//! * T10 — a checkpoint during the walk: the fence moves in memory and no
//!   file is written; the landing's fence is the floor as it then stands,
//!   positions below it `410 history_reclaimed` with the floor, those above
//!   served.
//!
//! The hold is PROCESS-WIDE, as the cell index walk's is: nextest gives
//! each test its own process; under plain `cargo test` the tests here take
//! [`HOLD`] one at a time, and a reopen elsewhere of a board with a region
//! may park behind a hold here until its release.
//!
//! The walk's figures the spike was to price — the per-boundary time and
//! the landing rewrite's length — are printed by T1 and T5 for the record.

use std::path::Path;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use serde_json::Value;
use skepd::{bind, serve_bound, AuthOptions, Daemon, Origin, Skepd, DEFAULT_WORKERS};

use crate::common::{
    acked_addr, acked_at, expect_resp, get, http, json, op, open_session, spawn, Sse,
    CLAIMANT_ACCOUNT, CLAIMANT_PRINCIPAL,
};

/// The tests here hold the walk one at a time (the module doc).
static HOLD: Mutex<()> = Mutex::new(());

/// How long a claim waits on a line, a landing or a wedge: a walk over a
/// test-sized region is milliseconds; a minute is the room machine weather
/// gets.
const PATIENCE: Duration = Duration::from_secs(60);

/// The claimed board's head as the claim leaves it: the ceremony's five
/// commits and `H.1`'s three, the publish at 20 (`changes.rs` pins them).
const CLAIMED_HEAD: u64 = 20;

/// The hold, taken for a test's span and RELEASED at its end, pass or
/// fail, so a red leaves no later walk parked.
struct Held(#[allow(dead_code)] MutexGuard<'static, ()>);

impl Drop for Held {
    fn drop(&mut self) {
        Daemon::release_the_feed_walk();
    }
}

fn hold() -> Held {
    Held(HOLD.lock().unwrap_or_else(PoisonError::into_inner))
}

/// One committing write as `session`: a fresh private draft under the
/// claimant's account — one record, so the position advances by one.
fn commit(port: u16, session: &str) -> u64 {
    acked_at(&op(port, Some(session), &format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"}}"#)))
}

/// `GET /changes?{query}` as `token` (`None` = the guest): the status and
/// the body.
fn changes(port: u16, token: Option<&str>, query: &str) -> (u16, Value) {
    let (st, body) = http(port, "GET", &format!("/changes?{query}"), token, b"");
    (st, json(&body))
}

/// The positions of a page's entries.
fn positions(v: &Value) -> Vec<u64> {
    v["changes"].as_array().expect("changes").iter().map(|e| e["at"].as_u64().expect("at")).collect()
}

/// The owner's whole feed from `since`, as bytes — a fresh session per
/// daemon life.
fn owner_feed_bytes(port: u16, since: u64) -> Vec<u8> {
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let (st, body) = http(port, "GET", &format!("/changes?since={since}&limit=4096"), Some(&owner), b"");
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&body));
    body
}

/// A claimed board with `n` commits of the owner's above the claim's head,
/// served and stopped: the head, the owner's whole feed and the guest's as
/// recorded.
fn seeded_board(dir: &Path, n: usize) -> (u64, Value, Value) {
    let sd = spawn(dir);
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let mut head = CLAIMED_HEAD;
    for _ in 0..n {
        head = commit(port, &owner);
    }
    let before = json(&owner_feed_bytes(port, 0));
    assert_eq!(positions(&before).last(), Some(&head), "the feed runs to the head");
    let (st, guest) = changes(port, None, "since=0&limit=4096");
    assert_eq!(st, 200);
    sd.shutdown();
    (head, before, guest)
}

/// Tear `commits.log` back to the entry at `low`: every line whose `at`
/// lies above `low` dropped, so the next open's region is `(low, head]`.
/// Answers the file's bytes after the tear.
fn tear_to(dir: &Path, low: u64) -> Vec<u8> {
    let path = dir.join("commits.log");
    let text = std::fs::read_to_string(&path).expect("commits.log");
    let kept: String = text
        .lines()
        .filter(|line| {
            let v: Value = serde_json::from_str(line).expect("a line is JSON");
            v.get("at").and_then(Value::as_u64).is_none_or(|at| at <= low)
        })
        .map(|line| format!("{line}\n"))
        .collect();
    std::fs::write(&path, &kept).expect("tear the file");
    kept.into_bytes()
}

/// Whether an open's failure is the transient journal-lock race a reopen
/// after a stop can meet (`common::spawn_under`'s retry).
fn lost_the_lock_race(err: &skepd::DaemonError) -> bool {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(e) = source {
        if let Some(io) = e.downcast_ref::<std::io::Error>() {
            return io.kind() == std::io::ErrorKind::WouldBlock;
        }
        source = e.source();
    }
    false
}

/// A reopen WITH THE WALK HELD: the hold armed, process-wide, then the
/// daemon opened and served over an ephemeral port with the fixtures'
/// options — `common::spawn`'s, which waits on the landing and under the
/// hold would never return. The region is pending when this answers; the
/// caller releases through `release_and_land`. `pub(crate)` for the head
/// suite's resume claim.
pub(crate) fn spawn_holding_the_walk(dir: &Path) -> Skepd {
    Daemon::hold_the_feed_walk();
    for _ in 0..12 {
        let listener = bind(0).expect("bind an ephemeral port");
        let port = listener.port();
        let origin = Origin::parse(&format!("http://127.0.0.1:{port}")).expect("a loopback origin");
        let mut opts = AuthOptions::default();
        opts.local_trust = true;
        opts.configured = vec![origin];
        opts.allow_preview_keys = true;
        match Daemon::open_with(dir, opts) {
            Ok(daemon) => {
                let sd = serve_bound(daemon, listener, DEFAULT_WORKERS).expect("serve over the bound port");
                assert!(sd.daemon().feed_pending_region().is_some(), "a region pends at this open");
                return sd;
            }
            Err(e) if lost_the_lock_race(&e) => {
                drop(listener);
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(e) => panic!("reopen at {}: {e}", dir.display()),
        }
    }
    panic!("the reopen lost the journal-lock race twelve times running")
}

/// Poll until `done`, within the suite's patience, naming what never came.
fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + PATIENCE;
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Release the hold and wait for the landing.
fn release_and_land(sd: &Skepd) {
    Daemon::release_the_feed_walk();
    wait_until("the walk's landing", || sd.daemon().feed_pending_region().is_none());
}

/// The daemon's lines opening with `prefix`.
fn lines_with(sd: &Skepd, prefix: &str) -> Vec<String> {
    sd.daemon().lines_said().into_iter().filter(|l| l.starts_with(prefix)).collect()
}

/// The `open:` line of the walk, awaited.
fn await_the_open_line(sd: &Skepd) -> String {
    wait_until("the walk's open: line", || !lines_with(sd, "open: commits.log covers").is_empty());
    let open = lines_with(sd, "open: commits.log covers");
    assert_eq!(open.len(), 1, "the open: line once: {open:?}");
    open[0].clone()
}

/// The figures off a `landing:` line — `{b} walked, {k} of them bare, in
/// {d} ms` — as (walked, bare, ms).
fn landing_figures(line: &str) -> (u64, u64, u64) {
    let rest = line.strip_prefix("landing: ").unwrap_or_else(|| panic!("{line:?}"));
    let (walked, rest) = rest.split_once(" walked, ").unwrap_or_else(|| panic!("{line:?}"));
    let (bare, rest) = rest.split_once(" of them bare, in ").unwrap_or_else(|| panic!("{line:?}"));
    let ms = rest.strip_suffix(" ms").unwrap_or_else(|| panic!("{line:?}"));
    (walked.parse().expect("walked"), bare.parse().expect("bare"), ms.parse().expect("ms"))
}

/// The position off a `progress:` line — `the walk at position {p} of
/// {h}, {d} ms in` — with `{h}` and `{d}` checked.
fn progress_position(line: &str, head: u64) -> u64 {
    let rest = line.strip_prefix("progress: the walk at position ").unwrap_or_else(|| panic!("{line:?}"));
    let (p, rest) = rest.split_once(" of ").unwrap_or_else(|| panic!("{line:?}"));
    let (h, rest) = rest.split_once(", ").unwrap_or_else(|| panic!("{line:?}"));
    assert_eq!(h.parse::<u64>().expect("head"), head, "{line:?}");
    let ms = rest.strip_suffix(" ms in").unwrap_or_else(|| panic!("{line:?}"));
    ms.parse::<u64>().expect("a duration in milliseconds");
    p.parse().expect("position")
}

/// The offset array's agreement with the file: every `{"at":N,"offset":O}`
/// line of `feed-offsets.log` names a byte of `commits.log` at which the
/// line for `N` begins.
fn assert_offsets_agree(dir: &Path) {
    let commits = std::fs::read(dir.join("commits.log")).expect("commits.log");
    let offsets = std::fs::read_to_string(dir.join("feed-offsets.log")).expect("feed-offsets.log");
    let mut checked = 0;
    for line in offsets.lines() {
        let v: Value = serde_json::from_str(line).expect("an offsets line is JSON");
        let (Some(at), Some(offset)) = (v["at"].as_u64(), v["offset"].as_u64()) else { continue };
        // A recorded line opens `{"at":N,`; a bare line with no journal
        // answer is `{"at":N}` whole.
        let recorded = format!("{{\"at\":{at},");
        let bare = format!("{{\"at\":{at}}}");
        let there = &commits[offset as usize..];
        assert!(
            there.starts_with(recorded.as_bytes()) || there.starts_with(bare.as_bytes()),
            "feed-offsets.log names byte {offset} for position {at}, where commits.log holds {:?}",
            String::from_utf8_lossy(&there[..there.len().min(40)])
        );
        checked += 1;
    }
    assert!(checked > 0, "the offset array holds lines");
}

/// T1 — THE WALK RUNS BEHIND THE LISTENER; THE BOARD SERVES; THE LANDING
/// RESTORES THE FEED (§3.3 step 2; §4 row 16). A board of ten owner commits,
/// its feed read whole, stopped, its `commits.log` torn back six entries;
/// the walk held, the reopen serves `/health` at once, says the `open:`
/// line, reads the region as `(low, head]` and leaves the file as the open
/// found it; a page into the region is `503 feed_rebuilding` carrying
/// `error` and `detail` alone, a page from the head is 200; a write commits
/// and is announced on `/events`, and a page from the head carries it; the
/// release lands: the `landing:` line once, the region `None`, every
/// position at or below the head as before — the torn six BARE (`docs`,
/// `key`, `time` null, the op the journal's: none for a mint), the rest
/// verbatim — the write recorded whole, the guest's page unchanged (a bare
/// draft mint classifies from the journal and stays masked, PUB-6.45), the
/// offset array agreeing with the file; and a clean restart serves the same
/// bytes.
#[test]
fn the_walk_runs_behind_the_listener_and_the_landing_restores_the_feed() {
    let _held = hold();
    let dir = tempfile::tempdir().expect("tempdir");
    let (head, before, guest_before) = seeded_board(dir.path(), 10);
    let low = head - 6;
    let torn = tear_to(dir.path(), low);

    let sd = spawn_holding_the_walk(dir.path());
    let port = sd.port();
    let (st, body) = get(port, "/health");
    assert_eq!(st, 200, "FINDING (P22): /health is not served while the walk is held");
    assert_eq!(json(&body)["log_position"].as_u64(), Some(head));
    assert!(json(&body)["head_time"].is_null(), "the head's record is in the region: head_time null");
    assert_eq!(sd.daemon().feed_pending_region(), Some((low, head)), "the region as the open read it");
    let open = await_the_open_line(&sd);
    assert_eq!(open, format!("open: commits.log covers to position {low}; walking 6 boundaries to position {head}"));
    assert_eq!(
        std::fs::read(dir.path().join("commits.log")).expect("read"),
        torn,
        "the file as the open found it: no line appended while the walk is held"
    );

    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let (st, v) = changes(port, Some(&owner), &format!("since={low}"));
    assert_eq!(st, 503, "a page into the region: {v}");
    assert_eq!(v["error"].as_str(), Some("feed_rebuilding"));
    let detail = v["detail"].as_str().expect("a detail in words");
    assert!(detail.contains("retry shortly") && detail.contains(&format!("through {head}")), "{detail}");
    assert_eq!(v.as_object().expect("an object").len(), 2, "error and detail alone, no region member: {v}");
    let (st, v) = changes(port, Some(&owner), &format!("since={head}"));
    assert_eq!(st, 200, "a page from the head serves: {v}");
    assert!(positions(&v).is_empty() && v["more"] == Value::Bool(false), "{v}");

    // A write commits while the walk is held and is announced as ever.
    let mut sse = Sse::connect(port);
    let at = commit(port, &owner);
    assert_eq!(at, head + 1);
    wait_until("the commit on /events", || sse.expect_commit() >= at);
    let (st, v) = changes(port, Some(&owner), &format!("since={head}"));
    assert_eq!(st, 200);
    assert_eq!(positions(&v), [at], "the write recorded in memory serves above the head: {v}");
    assert!(v["changes"][0]["op"].as_str() == Some("create_new_document"), "whole, not bare: {v}");
    assert_eq!(sd.daemon().feed_pending_region(), Some((low, head)), "still pending under the hold");

    let began = Instant::now();
    release_and_land(&sd);
    let landed_in = began.elapsed();
    let landing = lines_with(&sd, "landing: ");
    assert_eq!(landing.len(), 1, "the landing: line once: {landing:?}");
    let (walked, bare, ms) = landing_figures(&landing[0]);
    assert_eq!((walked, bare), (6, 0), "six boundaries proved, every one classified: {landing:?}");
    let size = std::fs::metadata(dir.path().join("commits.log")).expect("metadata").len();
    println!(
        "feed walk: {walked} boundaries in {ms} ms ({:.2} ms per boundary); the landing rewrite \
         {size} bytes for {} entries; release to landing {landed_in:?}",
        ms as f64 / walked as f64,
        positions(&before).len() + 1
    );

    let after = json(&owner_feed_bytes(port, 0));
    let mut want: Vec<u64> = positions(&before);
    want.push(at);
    assert_eq!(positions(&after), want, "every position, the write among them");
    let before_rows = before["changes"].as_array().expect("changes");
    let after_rows = after["changes"].as_array().expect("changes");
    for (b, a) in before_rows.iter().zip(after_rows) {
        let p = a["at"].as_u64().expect("at");
        if p <= low {
            assert_eq!(a, b, "a recorded position keeps its metadata verbatim");
        } else {
            assert!(
                a["docs"].is_null() && a["key"].is_null() && a["time"].is_null(),
                "a torn position answers bare in every testimony field: {a}"
            );
            assert!(a["op"].is_null(), "a mint's op is not the journal's to name: {a}");
        }
    }
    let last = after_rows.last().expect("the write");
    assert_eq!(last["at"].as_u64(), Some(at));
    assert_eq!(last["op"].as_str(), Some("create_new_document"), "recorded whole: {last}");
    assert_eq!(last["key"].as_str(), Some("bare"), "{last}");
    let (st, guest) = changes(port, None, "since=0&limit=4096");
    assert_eq!(st, 200);
    assert_eq!(
        positions(&guest),
        positions(&guest_before),
        "FINDING (PUB-6.45): the bare mints classify from the journal and stay masked"
    );
    assert_offsets_agree(dir.path());
    let landed = owner_feed_bytes(port, 0);
    sd.shutdown();

    // A clean restart: no region, the same bytes.
    let sd = spawn(dir.path());
    assert_eq!(sd.daemon().feed_pending_region(), None, "the landed file covers the head");
    assert_eq!(owner_feed_bytes(sd.port(), 0), landed, "/changes byte-identical across a clean restart");
    assert!(lines_with(&sd, "open: commits.log covers").is_empty(), "no walk on a covered file");
    sd.shutdown();
}

/// T5 — THE THREE LINES AT THE CADENCE (§1.1 m15): over a region of six
/// boundaries with the cadence set to every two, the stream carries the
/// `open:` line once, `progress:` lines at the second, fourth and sixth
/// boundary with `{p}` ascending and `{h}` the head, and the `landing:`
/// line once naming the six proved; at the shipped cadence (a thousand
/// boundaries or a minute) the same region yields no `progress:` line.
#[test]
fn the_three_lines_come_at_the_cadence() {
    let _held = hold();
    let dir = tempfile::tempdir().expect("tempdir");
    let (head, _, _) = seeded_board(dir.path(), 10);
    let low = head - 6;
    tear_to(dir.path(), low);

    let sd = spawn_holding_the_walk(dir.path());
    await_the_open_line(&sd);
    sd.daemon().set_feed_walk_progress_cadence(2, 60_000);
    release_and_land(&sd);
    let progress = lines_with(&sd, "progress: ");
    let ps: Vec<u64> = progress.iter().map(|l| progress_position(l, head)).collect();
    assert_eq!(ps, [low + 2, low + 4, low + 6], "every second boundary, ascending to the head: {progress:?}");
    let landing = lines_with(&sd, "landing: ");
    assert_eq!(landing.len(), 1, "{landing:?}");
    let (walked, bare, ms) = landing_figures(&landing[0]);
    assert_eq!((walked, bare), (6, 0), "{landing:?}");
    println!("feed walk at cadence 2: {walked} boundaries in {ms} ms; lines: {progress:?}");
    sd.shutdown();

    // The shipped cadence over the same region: no progress line.
    tear_to(dir.path(), low);
    let sd = spawn_holding_the_walk(dir.path());
    await_the_open_line(&sd);
    sd.daemon().set_feed_walk_progress_cadence(1_000, 60_000);
    release_and_land(&sd);
    assert!(lines_with(&sd, "progress: ").is_empty(), "no progress line within the cadence");
    assert_eq!(lines_with(&sd, "landing: ").len(), 1);
    sd.shutdown();
}

/// T6 — THE RANGE, NOT THE START (§3.3 step 2: "a page starting below the
/// region would otherwise silently skip its positions"). THE ARITHMETIC
/// PINNED: `low` is COVERED and `head` the last of the region, UNCOVERED;
/// a page with `since < head` is refused unless its `limit` ROWS all lie
/// at or below `low`, and a served page below the region says `more:
/// true`. With `low = 24` and `head = 30` on the owner's feed (positions
/// 2, 3, 6, 9, 12, 20, 21–30): `since=20&limit=10` → 503; `since=20&limit=3`
/// → 200 with 21, 22, 23; `since=30` → 200, empty; `since=29` → 503;
/// `since=23&limit=1` → 200 with 24, the fence itself; `since=24&limit=1`
/// → 503; and on the GUEST's sparse feed (2, 3, 6, 9, 12, 20 at or below
/// `low`) `since=0&limit=8` → 503 where the position range `(0, 8]` alone
/// would have served it and then run past the region, `since=0&limit=6` →
/// 200 with the six and `more: true`. After the landing the guest's
/// `since=0&limit=8` serves the six with `more: false`: the over-claim was
/// the safe one.
#[test]
fn a_page_is_refused_by_its_rows_not_its_since_alone() {
    let _held = hold();
    let dir = tempfile::tempdir().expect("tempdir");
    let (head, _, _) = seeded_board(dir.path(), 10);
    assert_eq!(head, 30, "ten mints above the claimed head of 20");
    let low = 24;
    tear_to(dir.path(), low);

    let sd = spawn_holding_the_walk(dir.path());
    let port = sd.port();
    assert_eq!(sd.daemon().feed_pending_region(), Some((low, head)));
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let refused = |token: Option<&str>, query: &str| {
        let (st, v) = changes(port, token, query);
        assert_eq!(st, 503, "{query}: {v}");
        assert_eq!(v["error"].as_str(), Some("feed_rebuilding"), "{query}: {v}");
    };
    let served = |token: Option<&str>, query: &str, want: &[u64], more: bool| {
        let (st, v) = changes(port, token, query);
        assert_eq!(st, 200, "{query}: {v}");
        assert_eq!(positions(&v), want, "{query}: {v}");
        assert_eq!(v["more"].as_bool(), Some(more), "{query}: {v}");
        assert_eq!(v["last"].as_u64(), Some(want.last().copied().unwrap_or(0).max(0)), "{query}: {v}");
    };
    refused(Some(&owner), "since=20&limit=10");
    served(Some(&owner), "since=20&limit=3", &[21, 22, 23], true);
    let (st, v) = changes(port, Some(&owner), "since=30");
    assert_eq!((st, positions(&v).len(), v["more"].as_bool()), (200, 0, Some(false)), "{v}");
    refused(Some(&owner), "since=29");
    served(Some(&owner), "since=23&limit=1", &[24], true);
    refused(Some(&owner), "since=24&limit=1");
    served(Some(&owner), "since=0&limit=10", &[2, 3, 6, 9, 12, 20, 21, 22, 23, 24], true);
    // THE SPARSE CLASS: the guest sees six positions at or below `low`.
    refused(None, "since=0&limit=8");
    served(None, "since=0&limit=6", &[2, 3, 6, 9, 12, 20], true);
    refused(None, "since=20&limit=1");

    release_and_land(&sd);
    let (st, v) = changes(port, None, "since=0&limit=8");
    assert_eq!((st, positions(&v), v["more"].as_bool()), (200, vec![2, 3, 6, 9, 12, 20], Some(false)), "{v}");
    let (st, v) = changes(port, Some(&owner), "since=20&limit=10");
    assert_eq!((st, positions(&v)), (200, (21..=30).collect::<Vec<_>>()), "{v}");
    sd.shutdown();
}

/// T9 — THE WALK's DEATH IS SAID AND THE BOARD SERVES (§1.1 row 41; L9's
/// standing line): the walk held and its panic arm set, the release ends
/// the thread at its first boundary — the catch's consequence line once,
/// naming the region (the hook's prefixed line is the binary's, not
/// asserted in-process) — `/health` 200, a page into the region still
/// refused, a write still admitted, the standing line's clause at the next
/// tick; a reopen walks the region again and lands it.
#[test]
fn the_walks_death_is_said_once_and_the_board_serves_with_the_region_pending() {
    let _held = hold();
    let dir = tempfile::tempdir().expect("tempdir");
    let (head, before, _) = seeded_board(dir.path(), 10);
    let low = head - 6;
    tear_to(dir.path(), low);

    let sd = spawn_holding_the_walk(dir.path());
    let port = sd.port();
    await_the_open_line(&sd);
    Daemon::panic_the_feed_walk();
    Daemon::release_the_feed_walk();
    let ended = format!(
        "failure: the feed walk ended: the test seam's fault in the feed walk; positions ({low}, \
         {head}] stay uncovered — /changes refuses pages into them until a restart, which walks \
         again"
    );
    wait_until("the catch's line", || !lines_with(&sd, "failure: the feed walk ended").is_empty());
    assert_eq!(lines_with(&sd, "failure: the feed walk ended"), [ended.clone()], "FINDING (row 41)");
    assert_eq!(sd.daemon().feed_pending_region(), Some((low, head)), "the region pends for the uptime");
    assert!(lines_with(&sd, "landing: ").is_empty(), "nothing landed");
    let (st, _) = get(port, "/health");
    assert_eq!(st, 200);
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let (st, v) = changes(port, Some(&owner), &format!("since={low}"));
    assert_eq!((st, v["error"].as_str()), (503, Some("feed_rebuilding")), "{v}");
    let at = commit(port, &owner);
    let (st, v) = changes(port, Some(&owner), &format!("since={head}"));
    assert_eq!((st, positions(&v)), (200, vec![at]), "a write is admitted and serves above the head: {v}");
    sd.daemon().set_standing_interval_millis(50);
    wait_until("the standing line", || !lines_with(&sd, "standing: ").is_empty());
    let standing = lines_with(&sd, "standing: ");
    assert_eq!(
        standing[0],
        format!("standing: the feed walk's thread is gone; positions ({low}, {head}] stay uncovered; CLAIMED-PERMISSIVE"),
        "the dead walk re-said at the tick"
    );
    assert_eq!(lines_with(&sd, "failure: the feed walk ended"), [ended], "said once");
    sd.shutdown();

    // A reopen walks again — from `low`, over the region and the write.
    let sd = spawn(dir.path());
    assert_eq!(sd.daemon().feed_pending_region(), None);
    let open = lines_with(&sd, "open: commits.log covers");
    assert_eq!(open, [format!("open: commits.log covers to position {low}; walking 7 boundaries to position {at}")]);
    let (walked, bare, _) = landing_figures(&lines_with(&sd, "landing: ")[0]);
    assert_eq!((walked, bare), (7, 0));
    let after = json(&owner_feed_bytes(sd.port(), 0));
    let mut want = positions(&before);
    want.push(at);
    assert_eq!(positions(&after), want);
    let last = after["changes"].as_array().expect("changes").last().expect("the write");
    assert!(last["key"].is_null() && last["time"].is_null(), "the write admitted under the dead walk is BARE at the reopen: {last}");
    sd.shutdown();
}

/// Six bulk prepends into `doc` from `session` — a segment has to rotate
/// before anything below it can be reclaimed (`changes.rs`'s recipe).
fn rotate_a_segment(port: u16, session: &str, doc: &str) {
    let bulk = "z".repeat(8192);
    for _ in 0..6 {
        let v = op(
            port,
            Some(session),
            &format!(r#"{{"op":"insert","doc":"{doc}","at":{{"subspace":"1","ordinal":"1"}},"values":["{bulk}"]}}"#),
        );
        expect_resp(&v, "ack_addr");
    }
}

/// T10 — A CHECKPOINT DURING THE WALK DOES NOT REWRITE THE FILE (§3.3
/// step 2: "a checkpoint landing meanwhile moves the floor and
/// `walk_min_since` drops what the journal reclaimed"). A board with two
/// checkpoints, A then B, inside what becomes the region; the walk held, a
/// third checkpoint serviced as the checkpoint thread services one — the
/// floor moves to B — and the file's bytes do not change; the landing's
/// fence is the floor as it then stands: positions below B answer `410
/// history_reclaimed` naming B as the floor, B itself and everything above
/// serve.
#[test]
fn a_checkpoint_during_the_walk_defers_its_rewrite_to_the_landing() {
    let _held = hold();
    let dir = tempfile::tempdir().expect("tempdir");
    let (a, b, head) = {
        let sd = spawn(dir.path());
        let port = sd.port();
        // The cadence parked: the two checkpoints are this test's own, so
        // the retained pair at the reopen is A and B and nothing else.
        sd.daemon().park_the_cadence();
        let owner = open_session(port, CLAIMANT_PRINCIPAL);
        let v = op(port, Some(&owner), &format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"}}"#));
        let doc = acked_addr(&v);
        rotate_a_segment(port, &owner, &doc);
        let a = commit(port, &owner);
        sd.daemon().checkpoint_now();
        for _ in 0..3 {
            commit(port, &owner);
        }
        rotate_a_segment(port, &owner, &doc);
        let b = commit(port, &owner);
        sd.daemon().checkpoint_now();
        let mut head = b;
        for _ in 0..3 {
            head = commit(port, &owner);
        }
        sd.shutdown();
        (a, b, head)
    };
    let low = a + 1;
    tear_to(dir.path(), low);

    let sd = spawn_holding_the_walk(dir.path());
    let port = sd.port();
    sd.daemon().park_the_cadence();
    let (region_low, region_head) = sd.daemon().feed_pending_region().expect("pending");
    assert!(
        region_low <= low && region_low < b && region_head == head,
        "the region spans B at {b}: ({region_low}, {region_head}], torn at {low}"
    );
    let as_opened = std::fs::read(dir.path().join("commits.log")).expect("read");
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let doc = acked_addr(&op(port, Some(&owner), &format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"}}"#)));
    rotate_a_segment(port, &owner, &doc);
    sd.daemon().service_the_checkpoint_now();
    let floor = sd.daemon().newest_checkpoint().expect("a third checkpoint landed").seq;
    assert!(floor.0 > head, "the third checkpoint lies above the head");
    assert_eq!(
        std::fs::read(dir.path().join("commits.log")).expect("read"),
        as_opened,
        "FINDING: the checkpoint's compaction rewrote the file under the pending region"
    );
    assert!(sd.daemon().feed_pending_region().is_some(), "still pending");
    // The fence moved in memory: below B is reclaimed at once, as /op-at
    // answers it, the floor named B — the region's first position above
    // the fence, which the landing has yet to prove — never a position
    // above the region.
    let (st, v) = changes(port, Some(&owner), &format!("since={}", a));
    assert_eq!((st, v["error"].as_str(), v["floor"].as_u64()), (410, Some("history_reclaimed"), Some(b)), "{v}");
    let (st, v) = changes(port, Some(&owner), &format!("since={}", b - 1));
    assert_eq!((st, v["error"].as_str()), (503, Some("feed_rebuilding")), "from the floor, into the region: {v}");

    release_and_land(&sd);
    let landing = lines_with(&sd, "landing: ");
    let (walked, bare, ms) = landing_figures(&landing[0]);
    assert_eq!(bare, 1, "B, the floor's own boundary, is proved from the base embodying it and unclassifiable: {landing:?}");
    // B, the three mints above it and the cadence head the checkpoint
    // triggered (its draft insert and its publish): six boundaries, no
    // more than the positions from B to the head.
    assert!((4..=head - b + 1).contains(&(walked as u64)), "B and every boundary above it to the head: {landing:?}");
    println!("feed walk over a bulk-written world: {walked} boundaries in {ms} ms ({:.0} ms per boundary)", ms as f64 / walked as f64);
    let text = std::fs::read_to_string(dir.path().join("commits.log")).expect("commits.log");
    assert!(text.starts_with(&format!("{{\"min_since\":{}}}\n", b - 1)), "the landing's fence is the floor's: {text}");
    let (st, v) = changes(port, Some(&owner), &format!("since={}", b - 2));
    assert_eq!((st, v["error"].as_str(), v["floor"].as_u64()), (410, Some("history_reclaimed"), Some(b)), "{v}");
    let (st, v) = changes(port, Some(&owner), &format!("since={}", b - 1));
    assert_eq!(st, 200, "{v}");
    let served = positions(&v);
    assert_eq!(served.first(), Some(&b), "the floor itself serves: {served:?}");
    assert!(served.contains(&head), "and the feed runs past the head: {served:?}");
    sd.shutdown();
}
