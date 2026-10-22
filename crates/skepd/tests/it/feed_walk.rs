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
//!   file is written, line 25 saying the files wait on the walk's landing;
//!   the landing's fence is the floor as it then stands, positions below it
//!   `410 history_reclaimed` with the floor, those above served.
//! * T11 — a derived file's landing rewrite refused before its rename: said
//!   once with the fence the file stands at, the file stopped there, the
//!   walk's landing after it, the feed served from memory.
//!
//! And THE LOST INDEX (#461, the owner's D8 (a)): where `feed-index.log` was
//! lost or cut, the bare positions it no longer classifies are a PENDING
//! SET the same thread sorts behind the listener, a world reconstruction
//! each, landed one by one as they are sorted — the open serves at once
//! where it classified them before. Judged through the hold's two arms
//! (`Daemon::hold_the_feed_walk`, `Daemon::hold_the_feed_walk_after_sorting`)
//! and the set's read (`Daemon::feed_pending_set`):
//!
//! * T12 — the board serves while the sort is held, the set is every bare
//!   position the index lost, the sort's `open:` line names their count;
//!   the refusal over the set by the page's rows; the landing byte-equal to
//!   the never-lost board's, whole and paged, every file covering the head.
//! * T13 — writes while the set pends: admitted, announced, served from
//!   memory, no index file takes a line ahead of the landing, and the
//!   landing carries them whole.
//! * T14 — why the refusal: served, a page over unsorted positions would
//!   differ from the never-lost board's.
//! * T15 — a kill mid-sort keeps the positions sorted so far: the next open
//!   pends the rest, serves at once, and lands them once each.
//! * T16 — a supervisor restarting before the sort finishes sees `/health`
//!   each time, and the sort completes across the restarts.
//! * T17 — a checkpoint during the sort moves the fence in memory and
//!   rewrites nothing; the landing writes the compaction it owed.
//! * T18 — a torn log and a lost index pend together: one walk, one landing
//!   with a line per file, the pages as never lost.
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
    CLAIMANT_ACCOUNT, CLAIMANT_PRINCIPAL, SEED_HEAD,
};

/// The tests here hold the walk one at a time (the module doc).
static HOLD: Mutex<()> = Mutex::new(());

/// How long a claim waits on a line, a landing or a wedge: a walk over a
/// test-sized region is milliseconds; a minute is the room machine weather
/// gets.
const PATIENCE: Duration = Duration::from_secs(60);

/// The claimed board's head as the claim leaves it: the registry seed's
/// commits (`common::SEED_HEAD`), the ceremony's five and `H.1`'s two, the
/// publish nineteen records above the seed (`changes.rs` pins them).
const CLAIMED_HEAD: u64 = SEED_HEAD + 19;

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
/// hold would never return. The region or the set is pending when this
/// answers; the caller releases through `release_and_land`. `pub(crate)`
/// for the head suite's resume claim.
pub(crate) fn spawn_holding_the_walk(dir: &Path) -> Skepd {
    Daemon::hold_the_feed_walk();
    spawn_under_the_hold(dir)
}

/// A reopen with the walk held AFTER `k` POSITIONS of a lost index's set
/// sorted: the walk sorts and lands `k`, then parks until the release — the
/// state a kill after `k` positions leaves — or lands everything where fewer
/// than `k` remain. Nothing may be pending when this answers.
fn spawn_holding_the_walk_after_sorting(dir: &Path, k: u64) -> Skepd {
    Daemon::hold_the_feed_walk_after_sorting(k);
    spawn_under_the_hold(dir)
}

/// The open and the serve of the two holds, the hold already armed: the
/// walk left pending at this open, which `spawn_holding_the_walk`'s callers
/// rely on, is asserted by them.
fn spawn_under_the_hold(dir: &Path) -> Skepd {
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
                return serve_bound(daemon, listener, DEFAULT_WORKERS)
                    .expect("serve over the bound port");
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

/// Release the hold and wait for the landing: the region landed, the set
/// sorted and the four files rewritten.
fn release_and_land(sd: &Skepd) {
    Daemon::release_the_feed_walk();
    wait_until("the walk's landing", || !sd.daemon().feed_walk_pending());
}

/// The four derived files, in their table's order.
const DERIVED: [&str; 4] =
    ["feed-index.log", "feed-offsets.log", "feed-masked.log", "feed-streams.log"];

/// A derived file's coverage as the next open would read it: the highest
/// of its fences and its records' positions.
fn coverage_of(dir: &Path, name: &str) -> u64 {
    std::fs::read_to_string(dir.join(name))
        .unwrap_or_else(|e| panic!("{name}: {e}"))
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("a line is JSON"))
        .filter_map(|r| r.get("covered").or(r.get("at"))?.as_u64())
        .max()
        .unwrap_or(0)
}

/// The positions `feed-index.log` holds a record for, in file order.
fn index_records(dir: &Path) -> Vec<u64> {
    std::fs::read_to_string(dir.join("feed-index.log"))
        .expect("feed-index.log")
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("a line is JSON"))
        .filter_map(|r| r.get("at")?.as_u64())
        .collect()
}

/// A class's pages from 0 at `limit`, each page's bytes, to the last.
fn paged(port: u16, token: Option<&str>, limit: usize) -> Vec<Vec<u8>> {
    let mut pages = Vec::new();
    let mut since = 0u64;
    loop {
        let (st, body) =
            http(port, "GET", &format!("/changes?since={since}&limit={limit}"), token, b"");
        assert_eq!(st, 200, "{}", String::from_utf8_lossy(&body));
        let v = json(&body);
        let (last, more) = (v["last"].as_u64().expect("last"), v["more"].as_bool().expect("more"));
        pages.push(body);
        if !more || last == since {
            return pages;
        }
        since = last;
    }
}

/// A board's pages as a never-lost board serves them: the owner's whole
/// feed and the guest's as bytes, and each class's paged walk at four a
/// page — what the lost-index cases are judged byte for byte against.
struct NeverLost {
    owner: Vec<u8>,
    guest: Vec<u8>,
    owner_paged: Vec<Vec<u8>>,
    guest_paged: Vec<Vec<u8>>,
}

/// Every class's pages of the board at `dir`, served and stopped.
fn pages_of(dir: &Path) -> NeverLost {
    let sd = spawn(dir);
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let (st, guest) = http(port, "GET", "/changes?since=0&limit=4096", None, b"");
    assert_eq!(st, 200);
    let pages = NeverLost {
        owner: owner_feed_bytes(port, 0),
        guest,
        owner_paged: paged(port, Some(&owner), 4),
        guest_paged: paged(port, None, 4),
    };
    sd.shutdown();
    pages
}

/// Checks every class's pages at `port` against the never-lost board's.
fn assert_pages_as_never_lost(port: u16, never_lost: &NeverLost) {
    assert_eq!(
        owner_feed_bytes(port, 0),
        never_lost.owner,
        "the owner's whole feed, byte for byte"
    );
    let (st, guest) = http(port, "GET", "/changes?since=0&limit=4096", None, b"");
    assert_eq!(st, 200);
    assert_eq!(guest, never_lost.guest, "the guest's whole feed, byte for byte");
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    assert_eq!(
        paged(port, Some(&owner), 4),
        never_lost.owner_paged,
        "the owner's pages at four a page"
    );
    assert_eq!(paged(port, None, 4), never_lost.guest_paged, "the guest's pages at four a page");
}

/// Bare the positions above `low`: `commits.log` torn back to `low` and
/// walked by a spawn, whose landing writes them bare; then the never-lost
/// board's pages, read after that landing.
fn bare_the_tail(dir: &Path, low: u64) -> NeverLost {
    tear_to(dir, low);
    pages_of(dir)
}

/// Lose `feed-index.log`: the next open pends every bare position the log
/// holds, for the walk to sort.
fn lose_the_index(dir: &Path) {
    std::fs::remove_file(dir.join("feed-index.log")).expect("lose the index");
}

/// The walk's `open:` line for the set, awaited.
fn await_the_sort_open_line(sd: &Skepd) -> String {
    wait_until("the sort's open: line", || {
        !lines_with(sd, "open: feed-index.log covers").is_empty()
    });
    let open = lines_with(sd, "open: feed-index.log covers");
    assert_eq!(open.len(), 1, "the sort's open: line once: {open:?}");
    open[0].clone()
}

/// The walk's `landing:` lines for the set.
fn sort_landings(sd: &Skepd) -> Vec<String> {
    lines_with(sd, "landing: feed-index.log: ")
}

/// A refused page's detail: `503 feed_rebuilding`, `error` and `detail` alone.
fn refused_detail(port: u16, token: Option<&str>, query: &str) -> String {
    let (st, v) = changes(port, token, query);
    assert_eq!(st, 503, "{query}: {v}");
    assert_eq!(v["error"].as_str(), Some("feed_rebuilding"), "{query}: {v}");
    assert_eq!(v.as_object().expect("an object").len(), 2, "error and detail alone: {v}");
    v["detail"].as_str().expect("a detail in words").to_string()
}

/// A served page: 200 with `want`'s positions, `more` and `last` as given.
fn served_page(port: u16, token: Option<&str>, query: &str, want: &[u64], more: bool) {
    let (st, v) = changes(port, token, query);
    assert_eq!(st, 200, "{query}: {v}");
    assert_eq!(positions(&v), want, "{query}: {v}");
    assert_eq!(v["more"].as_bool(), Some(more), "{query}: {v}");
    assert_eq!(v["last"].as_u64(), Some(want.last().copied().unwrap_or(0)), "{query}: {v}");
}

/// The daemon's lines opening with `prefix`.
fn lines_with(sd: &Skepd, prefix: &str) -> Vec<String> {
    sd.daemon().lines_said().into_iter().filter(|l| l.starts_with(prefix)).collect()
}

/// THE WALK's LANDING LINES and no other subsystem's: the daemon's record
/// is shared (`operations.md` §1.1) — the pruner's pass says its own
/// `landing: pruner: …` (row 34) on it as soon as the cell index is ready,
/// on a thread of its own, ahead of the walk's `landing: commits.log
/// re-covered positions ({low}, {head}]: {b} boundaries walked, …` (m15) —
/// so a claim counting the walk's landing takes it by its own subject, the
/// figures `landing_figures` reads (`hazard.rs`'s walk-landing claim names
/// it the same way), rather than by the pruner's prefix dropped: a landing
/// line a later subsystem puts on the record cannot re-break these claims.
fn walk_landings(sd: &Skepd) -> Vec<String> {
    lines_with(sd, "landing: ").into_iter().filter(|l| is_the_walks_landing(l)).collect()
}

/// Whether a `landing:` line is the walk's: it names `commits.log` and the
/// positions it re-covered.
fn is_the_walks_landing(line: &str) -> bool {
    line.starts_with("landing: commits.log re-covered positions (")
}

/// Wait for the pruner's first pass to have said its line — row 34, on the
/// daemon's record once the cell index is ready, from the pruner's own
/// thread — before a claim counts the walk's landing: nothing in the code
/// orders that thread against the walk's, so the claim does, and meets the
/// other subsystem's landing line on every run rather than by timing
/// (`blob_routes.rs`'s `after_the_first_pass`). Taken before the held
/// walk's release where the walk lands, so the pruner's line precedes the
/// walk's on the record too.
fn after_the_first_pass(sd: &Skepd) {
    wait_until("the pruner's first pass's line", || !lines_with(sd, "landing: pruner: ").is_empty());
}

/// The `open:` line of the walk, awaited.
fn await_the_open_line(sd: &Skepd) -> String {
    wait_until("the walk's open: line", || !lines_with(sd, "open: commits.log covers").is_empty());
    let open = lines_with(sd, "open: commits.log covers");
    assert_eq!(open.len(), 1, "the open: line once: {open:?}");
    open[0].clone()
}

/// The figures off the walk's `landing:` line — `commits.log re-covered
/// positions ({low}, {head}]: {b} boundaries walked, {k} of them
/// unclassifiable and served to every class, in {d} ms; the landing held
/// the change feed's lock {r} ms` — as (walked, unclassified, ms), the lock's
/// span checked to be a count of milliseconds, and the fence's clause, where
/// the line carries one, left to the claim that reads it.
fn landing_figures(line: &str) -> (u64, u64, u64) {
    let rest = line
        .strip_prefix("landing: commits.log re-covered positions (")
        .unwrap_or_else(|| panic!("{line:?}"));
    let (_region, rest) = rest.split_once("]: ").unwrap_or_else(|| panic!("{line:?}"));
    let (walked, rest) =
        rest.split_once(" boundaries walked, ").unwrap_or_else(|| panic!("{line:?}"));
    let (unclassified, rest) = rest
        .split_once(" of them unclassifiable and served to every class, in ")
        .unwrap_or_else(|| panic!("{line:?}"));
    let (ms, held) = rest
        .split_once(" ms; the landing held the change feed's lock ")
        .unwrap_or_else(|| panic!("{line:?}"));
    let held = held.split_once("; ").map_or(held, |(held, _fence)| held);
    let held = held.strip_suffix(" ms").unwrap_or_else(|| panic!("{line:?}"));
    assert!(held.parse::<u64>().is_ok(), "the lock's span in milliseconds: {line:?}");
    (
        walked.parse().expect("walked"),
        unclassified.parse().expect("unclassified"),
        ms.parse().expect("ms"),
    )
}

/// Returns the figures off a `progress:` line, `{h}` and `{d}` checked.
///
/// The line reads `the walk at position {p} of {h}, boundary {i} of {b}, {d}
/// ms in`; the figures are (position, boundary, boundaries).
fn progress_figures(line: &str, head: u64) -> (u64, u64, u64) {
    let rest =
        line.strip_prefix("progress: the walk at position ").unwrap_or_else(|| panic!("{line:?}"));
    let (p, rest) = rest.split_once(" of ").unwrap_or_else(|| panic!("{line:?}"));
    let (h, rest) = rest.split_once(", boundary ").unwrap_or_else(|| panic!("{line:?}"));
    assert_eq!(h.parse::<u64>().expect("head"), head, "{line:?}");
    let (i, rest) = rest.split_once(" of ").unwrap_or_else(|| panic!("{line:?}"));
    let (b, rest) = rest.split_once(", ").unwrap_or_else(|| panic!("{line:?}"));
    let ms = rest.strip_suffix(" ms in").unwrap_or_else(|| panic!("{line:?}"));
    ms.parse::<u64>().expect("a duration in milliseconds");
    (p.parse().expect("position"), i.parse().expect("boundary"), b.parse().expect("boundaries"))
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
/// release lands: the walk's `landing:` line once, the region `None`, every
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
    assert!(sd.daemon().feed_pending_region().is_some(), "a region pends at this open");
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

    // The pruner's own landing line on the record before the walk's.
    after_the_first_pass(&sd);
    let began = Instant::now();
    release_and_land(&sd);
    let landed_in = began.elapsed();
    let landing = walk_landings(&sd);
    assert_eq!(landing.len(), 1, "the walk's landing line once: {landing:?}");
    let (walked, unclassified, ms) = landing_figures(&landing[0]);
    assert_eq!(
        (walked, unclassified),
        (6, 0),
        "six boundaries proved, every one classified: {landing:?}"
    );
    assert!(
        landing[0]
            .starts_with(&format!("landing: commits.log re-covered positions ({low}, {head}]: ")),
        "the landing names its file and the region it re-covered: {landing:?}"
    );
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
/// boundary with `{p}` ascending, `{h}` the head and `boundary {i} of 6`
/// the walk's place in the list, and the walk's `landing:` line once naming
/// the six proved; at the shipped cadence (a thousand boundaries or a
/// minute) the same region yields no `progress:` line.
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
    // The pruner's own landing line on the record before the walk's.
    after_the_first_pass(&sd);
    release_and_land(&sd);
    let progress = lines_with(&sd, "progress: ");
    let figures: Vec<(u64, u64, u64)> =
        progress.iter().map(|l| progress_figures(l, head)).collect();
    assert_eq!(
        figures,
        [(low + 2, 2, 6), (low + 4, 4, 6), (low + 6, 6, 6)],
        "every second boundary, ascending to the head, each with its place among the six: \
         {progress:?}"
    );
    let landing = walk_landings(&sd);
    assert_eq!(landing.len(), 1, "the walk's landing line once: {landing:?}");
    let (walked, unclassified, ms) = landing_figures(&landing[0]);
    assert_eq!((walked, unclassified), (6, 0), "{landing:?}");
    println!("feed walk at cadence 2: {walked} boundaries in {ms} ms; lines: {progress:?}");
    sd.shutdown();

    // The shipped cadence over the same region: no progress line.
    tear_to(dir.path(), low);
    let sd = spawn_holding_the_walk(dir.path());
    await_the_open_line(&sd);
    sd.daemon().set_feed_walk_progress_cadence(1_000, 60_000);
    after_the_first_pass(&sd);
    release_and_land(&sd);
    assert!(lines_with(&sd, "progress: ").is_empty(), "no progress line within the cadence");
    assert_eq!(walk_landings(&sd).len(), 1, "the walk's landing line once");
    sd.shutdown();
}

/// The positions every class sees at or below the claimed head, off the one
/// constant: the registry seed's publish at 8 and its links three records
/// apart to `SEED_HEAD` (the draft's mint at 1 and the sections' insert at 4
/// are the system account's private writes, masked at every class but the
/// system's), the ceremony's five commits, and `H.1`'s publish, the claimed
/// head itself (`changes.rs` pins them).
fn public_ats_through_the_claimed_head() -> Vec<u64> {
    (8..=SEED_HEAD)
        .step_by(3)
        .chain([SEED_HEAD + 2, SEED_HEAD + 3, SEED_HEAD + 6, SEED_HEAD + 9, SEED_HEAD + 12])
        .chain([CLAIMED_HEAD])
        .collect()
}

/// T6 — THE RANGE, NOT THE START (§3.3 step 2: "a page starting below the
/// region would otherwise silently skip its positions"). THE ARITHMETIC
/// PINNED: `low` is COVERED and `head` the last of the region, UNCOVERED;
/// a page with `since < head` is refused unless its `limit` ROWS all lie
/// at or below `low`, and a served page below the region says `more:
/// true`. With `low` four mints above the claimed head `C` and `head` ten,
/// on the owner's feed (the public positions through `C`, then `C+1`–`C+10`):
/// `since=C&limit=10` → 503; `since=C&limit=3` → 200 with the first three
/// mints; `since=head` → 200, empty; `since=head-1` → 503;
/// `since=low-1&limit=1` → 200 with `low`, the fence itself;
/// `since=low&limit=1` → 503; a page from 0 of exactly the owner's rows
/// through `low` → 200 and `more: true`; and on the GUEST's sparse feed
/// (the public positions through `C` alone at or below `low`) a page from 0
/// one row longer than them → 503 where the position range alone would have
/// served it and then run past the region, the page of exactly them → 200
/// and `more: true`. After the landing the guest's longer page serves them
/// with `more: false`: the over-claim was the safe one.
#[test]
fn a_page_is_refused_by_its_rows_not_its_since_alone() {
    let _held = hold();
    let dir = tempfile::tempdir().expect("tempdir");
    let (head, _, _) = seeded_board(dir.path(), 10);
    assert_eq!(head, CLAIMED_HEAD + 10, "ten mints above the claimed head");
    let low = CLAIMED_HEAD + 4;
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
        assert_eq!(v["last"].as_u64(), Some(want.last().copied().unwrap_or(0)), "{query}: {v}");
    };
    let c = CLAIMED_HEAD;
    refused(Some(&owner), &format!("since={c}&limit=10"));
    served(Some(&owner), &format!("since={c}&limit=3"), &[c + 1, c + 2, c + 3], true);
    let (st, v) = changes(port, Some(&owner), &format!("since={head}"));
    assert_eq!((st, positions(&v).len(), v["more"].as_bool()), (200, 0, Some(false)), "{v}");
    refused(Some(&owner), &format!("since={}", head - 1));
    served(Some(&owner), &format!("since={}&limit=1", low - 1), &[low], true);
    refused(Some(&owner), &format!("since={low}&limit=1"));
    let owners_through_low: Vec<u64> =
        public_ats_through_the_claimed_head().into_iter().chain(c + 1..=low).collect();
    served(
        Some(&owner),
        &format!("since=0&limit={}", owners_through_low.len()),
        &owners_through_low,
        true,
    );
    // THE SPARSE CLASS: the guest sees the public positions through the
    // claimed head at or below `low`, and none of the owner's mints.
    let guests = public_ats_through_the_claimed_head();
    refused(None, &format!("since=0&limit={}", guests.len() + 1));
    served(None, &format!("since=0&limit={}", guests.len()), &guests, true);
    refused(None, &format!("since={c}&limit=1"));

    release_and_land(&sd);
    let (st, v) = changes(port, None, &format!("since=0&limit={}", guests.len() + 1));
    assert_eq!((st, positions(&v), v["more"].as_bool()), (200, guests, Some(false)), "{v}");
    let (st, v) = changes(port, Some(&owner), &format!("since={c}&limit=10"));
    assert_eq!((st, positions(&v)), (200, (c + 1..=head).collect::<Vec<_>>()), "{v}");
    sd.shutdown();
}

/// T9 — THE WALK's DEATH IS SAID AND THE BOARD SERVES (§1.1 row 41; L9's
/// standing line): the walk held and its panic arm set, the release ends
/// the thread at its first boundary — the catch's consequence line once,
/// naming the region (the hook's prefixed line is the binary's, not
/// asserted in-process) — `/health` 200, a page into the region still
/// refused, its detail naming the restart and no retry, a write still
/// admitted, the standing line's clause at the next
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
         again; until that restart commits.log takes no line: every write since this open is \
         held in memory alone, and the restart's walk re-covers each as a bare entry, its key and \
         its time lost — restart soon"
    );
    wait_until("the catch's line", || !lines_with(&sd, "failure: the feed walk ended").is_empty());
    assert_eq!(lines_with(&sd, "failure: the feed walk ended"), std::slice::from_ref(&ended), "FINDING (row 41)");
    assert_eq!(sd.daemon().feed_pending_region(), Some((low, head)), "the region pends for the uptime");
    // The pruner's own landing line is on the record; the walk's never comes.
    after_the_first_pass(&sd);
    assert!(walk_landings(&sd).is_empty(), "no walk landing: the walk died before its first boundary");
    let (st, _) = get(port, "/health");
    assert_eq!(st, 200);
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let (st, v) = changes(port, Some(&owner), &format!("since={low}"));
    assert_eq!((st, v["error"].as_str()), (503, Some("feed_rebuilding")), "{v}");
    // The dead walk's refusal names the restart, never a retry: no landing
    // comes this uptime (`operations.md` §1.1 row 41).
    let detail = v["detail"].as_str().unwrap_or_default();
    assert!(
        detail.contains("until a restart") && !detail.contains("retry shortly"),
        "the dead walk's page names the restart: {detail}"
    );
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
    // The spawn waited on the landing; the pruner's line beside it before the count.
    after_the_first_pass(&sd);
    let (walked, unclassified, _) = landing_figures(&walk_landings(&sd)[0]);
    assert_eq!((walked, unclassified), (7, 0));
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
    let bulk = "z".repeat(262_144);
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
    // Line 25 says what the compaction did: the resident entries trimmed
    // below B, the files' rewrite waiting on the walk's landing over the
    // region — never that the files compacted, since no file was written.
    let landed = format!("landing: checkpoint at position {} landed", floor.0);
    let line_25 = sd
        .daemon()
        .checkpoint_lines()
        .into_iter()
        .rfind(|line| line.starts_with(&landed))
        .expect("the third checkpoint's landing line");
    assert!(
        line_25.contains(&format!(
            "; the change feed's files wait on the walk's landing over positions \
             ({region_low}, {region_head}] for their rewrite, the resident entries trimmed below \
             position {b} in "
        )),
        "line 25 names the region and the fence it trimmed to: {line_25}"
    );
    assert!(!line_25.contains("compacted below"), "no file was compacted: {line_25}");
    // The fence moved in memory: below B is reclaimed at once, as /op-at
    // answers it, the floor named B — the region's first position above
    // the fence, which the landing has yet to prove — never a position
    // above the region.
    let (st, v) = changes(port, Some(&owner), &format!("since={}", a));
    assert_eq!((st, v["error"].as_str(), v["floor"].as_u64()), (410, Some("history_reclaimed"), Some(b)), "{v}");
    let (st, v) = changes(port, Some(&owner), &format!("since={}", b - 1));
    assert_eq!((st, v["error"].as_str()), (503, Some("feed_rebuilding")), "from the floor, into the region: {v}");

    // The pruner's own landing line on the record before the walk's.
    after_the_first_pass(&sd);
    release_and_land(&sd);
    let landing = walk_landings(&sd);
    let (walked, unclassified, ms) = landing_figures(&landing[0]);
    assert_eq!(
        unclassified, 1,
        "B, the floor's own boundary, is proved from the base embodying it and unclassifiable: \
         {landing:?}"
    );
    assert!(
        landing[0].ends_with(&format!(
            "; the fence stands at position {}: /changes answers 410 history_reclaimed for every \
             since below it",
            b - 1
        )),
        "the landing says the fence the checkpoint moved inside the region: {landing:?}"
    );
    // B, the three mints above it and the cadence head the checkpoint
    // triggered (its draft insert and its publish): six boundaries, no
    // more than the positions from B to the head.
    assert!((4..=head - b + 1).contains(&walked), "B and every boundary above it to the head: {landing:?}");
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

/// T11 — a derived file's landing rewrite refused before its rename.
///
/// It is §3.3 step 2's case (`operations.md` §1.1 m15): a board's
/// `commits.log` torn back, the walk held, and a directory planted on
/// `feed-index.log.compact` — the rewrite's temp name, which no create
/// passes — after the open has rewritten the four derived files fenced at
/// the region's lower edge; the release lands, and the landing's rewrite of
/// the index is refused before its rename: said once, under `failure:`,
/// naming the file, the fence it stands at — the region's lower edge, the
/// position the next open re-derives above — that it takes no further line
/// and that the next open re-derives it, the board serving from memory; the
/// file stopped since that fence; the walk's own `landing:` line follows it,
/// the region landed in `commits.log` all the same, and the feed answers
/// from memory.
#[test]
fn a_derived_files_landing_rewrite_refused_names_the_fence_it_stands_at() {
    let _held = hold();
    let dir = tempfile::tempdir().expect("tempdir");
    let (head, _, _) = seeded_board(dir.path(), 4);
    tear_to(dir.path(), head - 2);
    let sd = spawn_holding_the_walk(dir.path());
    let (low, region_head) = sd.daemon().feed_pending_region().expect("pending");
    assert_eq!(region_head, head, "the region runs to the head");
    std::fs::create_dir(dir.path().join("feed-index.log.compact")).expect("the obstacle");
    release_and_land(&sd);
    let refused = "failure: feed-index.log: the walk's landing rewrite failed before its rename: ";
    let tail = format!(
        "; the file stands fenced at position {low}, short of what the walk landed, and takes no \
         further line, so the next open re-derives above it — the board serves from memory, and \
         nothing is lost; check the volume, its device and the board user's quota before that \
         restart: its open writes this file"
    );
    let said = sd.daemon().lines_said();
    let at = said
        .iter()
        .position(|l| l.starts_with(refused))
        .unwrap_or_else(|| panic!("the refusal is said:\n{}", said.join("\n")));
    assert!(said[at].ends_with(&tail), "the file and the fence it stands at: {}", said[at]);
    assert_eq!(
        said.iter().filter(|l| l.contains("landing rewrite failed")).count(),
        1,
        "the index alone stood, and said so once:\n{}",
        said.join("\n")
    );
    assert!(
        said[at + 1..].iter().any(|l| is_the_walks_landing(l)),
        "the walk's landing follows the refusal:\n{}",
        said.join("\n")
    );
    assert_eq!(sd.daemon().stopped_feed_files(), ["feed-index.log"], "the index alone stopped");
    let text = std::fs::read_to_string(dir.path().join("commits.log")).expect("commits.log");
    assert!(
        text.lines().any(|l| l.starts_with(&format!("{{\"at\":{head}"))),
        "the region landed in commits.log all the same: {text}"
    );
    let owner = open_session(sd.port(), CLAIMANT_PRINCIPAL);
    let (st, v) = changes(sd.port(), Some(&owner), &format!("since={low}"));
    assert_eq!(st, 200, "{v}");
    assert_eq!(positions(&v).last(), Some(&head), "the feed answers to the head from memory: {v}");
    sd.shutdown();
}

/// T12 — A LOST INDEX IS SORTED BEHIND THE LISTENER; THE BOARD SERVES; A
/// PAGE REACHING AN UNSORTED POSITION WAITS; THE LANDING RESTORES THE FEED
/// (#461, the owner's D8 (a); `operations.md` §3.3 step 2; §4 row 16). A
/// board of ten owner commits, its `commits.log` torn back six entries and
/// walked, so the six are bare in the log, the never-lost pages read; then
/// `feed-index.log` lost. The walk held, the reopen serves `/health` at
/// once, pends exactly the six bare positions and no region, says the
/// sort's `open:` line with their count and the reconstructions owed — one
/// a position and one below the run, none at the head: six — and fences the
/// four derived files below the first of them. THE REFUSAL's ARITHMETIC
/// over the set: a page from `low`, whose first row would be the first
/// unsorted position, is `503 feed_rebuilding`, its detail naming the count,
/// the first position and the retry; a page whose rows all lie below the set
/// serves with `more: true`; one row longer is refused; the guest's sparse
/// page likewise; a page from the head serves, empty. Released, the walk
/// lands: the sort's `landing:` line once, the six classified and the six
/// reconstructions paid, no landing of the log's (no region); every class's
/// pages byte-equal to the never-lost board's, whole and paged; the four
/// files covering the head and the offset array agreeing with `commits.log`;
/// a clean restart serves the same bytes and sorts nothing.
#[test]
fn a_lost_index_is_sorted_behind_the_listener_and_pages_reaching_it_wait() {
    let _held = hold();
    let dir = tempfile::tempdir().expect("tempdir");
    let (head, _, _) = seeded_board(dir.path(), 10);
    let low = head - 6;
    let never_lost = bare_the_tail(dir.path(), low);
    let bare: Vec<u64> = (low + 1..=head).collect();
    lose_the_index(dir.path());

    let sd = spawn_holding_the_walk(dir.path());
    let port = sd.port();
    let (st, body) = get(port, "/health");
    assert_eq!(st, 200, "FINDING (D8 (a)): /health is not served while the sort is held");
    assert_eq!(json(&body)["log_position"].as_u64(), Some(head));
    assert_eq!(sd.daemon().feed_pending_set(), bare, "every bare position the index lost pends");
    assert_eq!(sd.daemon().feed_pending_region(), None, "the log covers the head: no region");
    let open = await_the_sort_open_line(&sd);
    assert_eq!(
        open,
        format!(
            "open: feed-index.log covers to position {low}: 6 bare positions are classified from \
             the journal behind the listener, 6 world reconstructions in all"
        )
    );
    for name in DERIVED {
        assert_eq!(coverage_of(dir.path(), name), low, "{name} is fenced below the set");
    }

    // THE REFUSAL over the set, by the page's rows.
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let detail = refused_detail(port, Some(&owner), &format!("since={low}"));
    assert!(
        detail.contains("6 bare positions")
            && detail.contains(&format!("the first at position {}", low + 1))
            && detail.contains("retry shortly"),
        "the detail names the set and the retry: {detail}"
    );
    served_page(port, Some(&owner), &format!("since={}&limit=1", low - 1), &[low], true);
    let c = CLAIMED_HEAD;
    let owners_through_low: Vec<u64> =
        public_ats_through_the_claimed_head().into_iter().chain(c + 1..=low).collect();
    let n = owners_through_low.len();
    served_page(port, Some(&owner), &format!("since=0&limit={n}"), &owners_through_low, true);
    refused_detail(port, Some(&owner), &format!("since=0&limit={}", n + 1));
    let guests = public_ats_through_the_claimed_head();
    served_page(port, None, &format!("since=0&limit={}", guests.len()), &guests, true);
    refused_detail(port, None, &format!("since=0&limit={}", guests.len() + 1));
    let (st, v) = changes(port, Some(&owner), &format!("since={head}"));
    assert_eq!((st, positions(&v).len(), v["more"].as_bool()), (200, 0, Some(false)), "{v}");

    // THE LANDING.
    release_and_land(&sd);
    let landing = sort_landings(&sd);
    assert_eq!(landing.len(), 1, "the sort's landing line once: {landing:?}");
    assert!(
        landing[0].starts_with(
            "landing: feed-index.log: 6 of 6 bare positions classified from the journal, 6 world \
             reconstructions, in "
        ) && landing[0].contains(" ms; the landing held the change feed's lock ")
            && landing[0].ends_with(" ms"),
        "the landing's figures: {landing:?}"
    );
    assert!(walk_landings(&sd).is_empty(), "no region: the log's landing line never comes");
    assert_pages_as_never_lost(port, &never_lost);
    for name in DERIVED {
        assert_eq!(coverage_of(dir.path(), name), head, "{name} covers the head after the landing");
    }
    assert_offsets_agree(dir.path());
    sd.shutdown();

    let sd = spawn(dir.path());
    assert!(sd.daemon().feed_pending_set().is_empty(), "nothing to sort on a covered index");
    assert!(
        lines_with(&sd, "open: feed-index.log covers").is_empty(),
        "no sort on a covered index"
    );
    assert_pages_as_never_lost(sd.port(), &never_lost);
    sd.shutdown();
}

/// T13 — WRITES WHILE THE SET PENDS (the ruling: "`Feed::record` writes a
/// new commit's derived entries to the in-memory twins only, and
/// `commits.log` keeps appending"). The lost-index board held: a write
/// commits at the next position, is announced on `/events` and served from
/// memory above the set, whole; `commits.log` grew by its line and no
/// derived file took one — each byte for byte as the open left it, fenced
/// below the set, so no claim rises over an unsorted position; the set still
/// pends. Released, the landing carries the write whole after every row as
/// never lost, the guest's page unchanged (a private draft's mint), the four
/// files covering the write and the offset array agreeing.
#[test]
fn writes_while_the_set_pends_take_no_index_line_and_land_whole() {
    let _held = hold();
    let dir = tempfile::tempdir().expect("tempdir");
    let (head, _, _) = seeded_board(dir.path(), 10);
    let low = head - 6;
    let never_lost = bare_the_tail(dir.path(), low);
    lose_the_index(dir.path());

    let sd = spawn_holding_the_walk(dir.path());
    let port = sd.port();
    assert_eq!(sd.daemon().feed_pending_set().len(), 6);
    let files_before: Vec<Vec<u8>> =
        DERIVED.iter().map(|name| std::fs::read(dir.path().join(name)).expect(name)).collect();
    let log_before = std::fs::read(dir.path().join("commits.log")).expect("commits.log");
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let mut sse = Sse::connect(port);
    let at = commit(port, &owner);
    assert_eq!(at, head + 1, "admitted at the next position");
    wait_until("the commit on /events", || sse.expect_commit() >= at);
    let (st, v) = changes(port, Some(&owner), &format!("since={head}"));
    assert_eq!((st, positions(&v)), (200, vec![at]), "served from memory above the set: {v}");
    assert_eq!(v["changes"][0]["op"].as_str(), Some("create_new_document"), "whole: {v}");
    for (name, before) in DERIVED.iter().zip(&files_before) {
        assert_eq!(
            &std::fs::read(dir.path().join(name)).expect(name),
            before,
            "FINDING (the fence): {name} took a line while the set pends"
        );
    }
    let log_now = std::fs::read(dir.path().join("commits.log")).expect("commits.log");
    assert!(
        log_now.len() > log_before.len() && log_now.starts_with(&log_before),
        "commits.log keeps appending"
    );
    assert_eq!(sd.daemon().feed_pending_set().len(), 6, "still pending under the hold");

    release_and_land(&sd);
    let after = json(&owner_feed_bytes(port, 0));
    let before = json(&never_lost.owner);
    let before_rows = before["changes"].as_array().expect("rows");
    let after_rows = after["changes"].as_array().expect("rows");
    assert_eq!(&after_rows[..before_rows.len()], before_rows.as_slice(), "every row as never lost");
    let last = after_rows.last().expect("the write");
    assert_eq!(last["at"].as_u64(), Some(at));
    assert_eq!(last["op"].as_str(), Some("create_new_document"), "recorded whole: {last}");
    assert_eq!(last["key"].as_str(), Some("bare"), "{last}");
    let (st, guest) = http(port, "GET", "/changes?since=0&limit=4096", None, b"");
    assert_eq!(st, 200);
    assert_eq!(guest, never_lost.guest, "a private draft's mint is masked to the guest");
    for name in DERIVED {
        assert_eq!(coverage_of(dir.path(), name), at, "{name} covers the write after the landing");
    }
    assert_offsets_agree(dir.path());
    sd.shutdown();
}

/// T14 — WHY THE REFUSAL (the ruling: "serving those pages without the
/// refusal is NOT an option"). Every position of a claimed board bare —
/// `commits.log` torn to its fence line and walked — then the index lost:
/// the set is every position the log holds, the seed's published links and
/// the claim's publish among them, rows every class may see. Until they are
/// sorted no twin holds them, so a page served over them would differ from
/// the never-lost board's: a guest's page from 0 would carry none of its
/// rows and claim completeness, an owner's none of the owner's; and had an
/// index file stood over them, a page read off it could carry rows a class
/// may not see — an issuer's draft stream taken whole past the filter's
/// bound, a straddling row's `attest`. So each is refused until the landing,
/// after which every class's pages are byte-equal to the never-lost board's.
/// MUTANT: the reach test dropped → the page served differs → red here.
#[test]
fn a_page_reaching_an_unsorted_position_is_refused_because_served_it_would_differ() {
    let _held = hold();
    let dir = tempfile::tempdir().expect("tempdir");
    let (head, _, _) = seeded_board(dir.path(), 4);
    let never_lost = bare_the_tail(dir.path(), 0);
    lose_the_index(dir.path());

    let sd = spawn_holding_the_walk(dir.path());
    let port = sd.port();
    let set = sd.daemon().feed_pending_set();
    let guests = public_ats_through_the_claimed_head();
    assert!(
        guests.iter().all(|at| set.contains(at)),
        "every row a guest may see is unsorted: {set:?}"
    );
    assert_eq!(set.last(), Some(&head), "to the head");
    let guest_landed = positions(&json(&never_lost.guest));
    assert_eq!(
        guest_landed, guests,
        "the premise: the never-lost board serves the guest these rows"
    );
    let (st, v) = changes(port, None, "since=0&limit=4096");
    assert_eq!(
        st, 503,
        "FINDING (D8 (a)): served {v} where the never-lost board serves {guest_landed:?}"
    );
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let (st, v) = changes(port, Some(&owner), "since=0&limit=4096");
    assert_eq!(
        st,
        503,
        "FINDING (D8 (a)): served {v} where the never-lost board serves {}",
        String::from_utf8_lossy(&never_lost.owner)
    );
    release_and_land(&sd);
    assert_pages_as_never_lost(port, &never_lost);
    sd.shutdown();
}

/// T15 — A KILL MID-SORT KEEPS THE POSITIONS SORTED SO FAR (the per-position
/// append's purpose). The lost-index board, the walk held after its third
/// position: three sorted and landed, the index appended through the third
/// and the other three files fenced below the set, the three serving and a
/// page reaching the fourth refused; the daemon stopped there — the stop
/// ends the parked walk with nothing further written, the files as a kill
/// leaves them. The next open, held, serves at once and pends the three
/// left, never the three sorted; released, it lands them — its `open:` and
/// `landing:` lines naming three — every position's record standing once,
/// the pages as never lost. MUTANT: the progress dropped → the next open
/// pends six → red at the count.
#[test]
fn a_kill_mid_sort_keeps_the_positions_sorted_so_far_and_the_next_open_pends_the_rest() {
    let _held = hold();
    let dir = tempfile::tempdir().expect("tempdir");
    let (head, _, _) = seeded_board(dir.path(), 10);
    let low = head - 6;
    let never_lost = bare_the_tail(dir.path(), low);
    let bare: Vec<u64> = (low + 1..=head).collect();
    lose_the_index(dir.path());

    let sd = spawn_holding_the_walk_after_sorting(dir.path(), 3);
    let port = sd.port();
    wait_until("three positions sorted", || sd.daemon().feed_pending_set() == bare[3..]);
    assert_eq!(
        coverage_of(dir.path(), "feed-index.log"),
        bare[2],
        "the index appended through the third position as it was sorted"
    );
    for name in &DERIVED[1..] {
        assert_eq!(
            coverage_of(dir.path(), name),
            low,
            "{name} waits on the landing, fenced below the set"
        );
    }
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    served_page(port, Some(&owner), &format!("since={low}&limit=3"), &bare[..3], true);
    refused_detail(port, Some(&owner), &format!("since={low}&limit=4"));
    // THE KILL: stopped while the walk parks, nothing further written.
    sd.shutdown();
    Daemon::release_the_feed_walk();

    let sd = spawn_holding_the_walk(dir.path());
    let port = sd.port();
    let (st, _) = get(port, "/health");
    assert_eq!(st, 200, "the next open serves at once");
    assert_eq!(
        sd.daemon().feed_pending_set(),
        bare[3..],
        "FINDING (F6): n − k pending — the progress the per-position append kept"
    );
    let open = await_the_sort_open_line(&sd);
    assert!(
        open.contains(": 3 bare positions are classified from the journal behind the listener, "),
        "the three left: {open}"
    );
    release_and_land(&sd);
    let landing = sort_landings(&sd);
    assert!(
        landing.len() == 1
            && landing[0].starts_with(
                "landing: feed-index.log: 3 of 3 bare positions classified from the journal, "
            ),
        "{landing:?}"
    );
    let records = index_records(dir.path());
    let mut once = records.clone();
    once.sort_unstable();
    once.dedup();
    assert_eq!(records, once, "each position's record stands once: {records:?}");
    assert!(
        bare.iter().all(|at| records.contains(at)),
        "every bare position classified: {records:?}"
    );
    assert_pages_as_never_lost(port, &never_lost);
    assert_offsets_agree(dir.path());
    sd.shutdown();
}

/// T16 — THE SUPERVISOR (the issue: "a supervisor whose start window is
/// shorter than the open plus two rebuilds never lets one position finish;
/// the daemon then restarts forever and never serves"). The lost-index board
/// started again and again, each start sorting two positions before it is
/// stopped — the walk held after its second — serves `/health` within the
/// window every time, and the sort completes across the starts: six
/// positions, three starts, the third landing; the board then serves the
/// never-lost pages and sorts nothing. MUTANT: the sort run before the
/// listener → `/health` waits on the whole sort → red at the window.
#[test]
fn a_supervisor_restarting_before_the_sort_finishes_sees_health_each_time_and_the_sort_completes() {
    let _held = hold();
    let dir = tempfile::tempdir().expect("tempdir");
    let (head, _, _) = seeded_board(dir.path(), 10);
    let low = head - 6;
    let never_lost = bare_the_tail(dir.path(), low);
    lose_the_index(dir.path());

    // The supervisor's window: generous against this machine's weather, and
    // far below a sort of a large world, which the base measured in minutes.
    let window = Duration::from_secs(20);
    let mut starts = 0usize;
    let mut left = 6usize;
    loop {
        let started = Instant::now();
        let sd = spawn_holding_the_walk_after_sorting(dir.path(), 2);
        let (st, _) = get(sd.port(), "/health");
        assert_eq!(st, 200);
        let took = started.elapsed();
        assert!(
            took < window,
            "FINDING (F7): the start took {took:?}, past the supervisor's window"
        );
        starts += 1;
        let expect_left = left.saturating_sub(2);
        // Two more sorted — the walk parks there — or, where no more than
        // two were left, the landing itself: the set empties ahead of the
        // landing's rewrite, so an empty set is not yet a landing.
        wait_until("two more positions sorted, or the landing", || {
            (expect_left > 0 && sd.daemon().feed_pending_set().len() <= expect_left)
                || !sd.daemon().feed_walk_pending()
        });
        let landed = !sd.daemon().feed_walk_pending();
        sd.shutdown();
        Daemon::release_the_feed_walk();
        if landed {
            break;
        }
        left = expect_left;
        assert!(starts < 10, "the sort never completes across the restarts");
    }
    assert_eq!(starts, 3, "two positions a start, six positions: the third start lands");
    let sd = spawn(dir.path());
    assert!(lines_with(&sd, "open: feed-index.log covers").is_empty(), "nothing left to sort");
    assert_pages_as_never_lost(sd.port(), &never_lost);
    sd.shutdown();
}

/// T17 — A CHECKPOINT DURING THE SORT DEFERS ITS REWRITE TO THE LANDING
/// (the ruling: "`compact_below_reclaim_floor` moves the fence in memory
/// and writes nothing while the set pends"). T10's board — two checkpoints,
/// A then B, inside what becomes the set — its tail above A bared and its
/// index lost; the walk held, a third checkpoint serviced as the checkpoint
/// thread services one: the floor moves to B, and `commits.log` and the four
/// derived files do not change by a byte; line 25 says the files wait on
/// the walk's landing over the set, the resident entries trimmed below B;
/// positions below B answer `410 history_reclaimed` naming B at once, and
/// the set drops them. Released, the landing writes what the compaction
/// owed, as a never-lost board's compaction would have: `commits.log`
/// behind the fence B − 1, no index record below B — B itself unclassifiable,
/// the base embodying it the floor, said once — and the feed serving from B.
#[test]
fn a_checkpoint_during_the_sort_defers_its_rewrite_to_the_landing() {
    let _held = hold();
    let dir = tempfile::tempdir().expect("tempdir");
    let (a, b, head) = {
        let sd = spawn(dir.path());
        let port = sd.port();
        sd.daemon().park_the_cadence();
        let owner = open_session(port, CLAIMANT_PRINCIPAL);
        let v = op(
            port,
            Some(&owner),
            &format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"}}"#),
        );
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
    // The tail above A bared by a reopen's walk — the floor stands at A, so
    // no page from 0 is read here — then the index lost.
    tear_to(dir.path(), a + 1);
    spawn(dir.path()).shutdown();
    lose_the_index(dir.path());

    let sd = spawn_holding_the_walk(dir.path());
    let port = sd.port();
    sd.daemon().park_the_cadence();
    let set = sd.daemon().feed_pending_set();
    assert!(set.contains(&b) && set.last() == Some(&head), "the set spans B at {b}: {set:?}");
    assert_eq!(sd.daemon().feed_pending_region(), None, "the log covers the head");
    let as_opened: Vec<Vec<u8>> =
        DERIVED.iter().map(|name| std::fs::read(dir.path().join(name)).expect(name)).collect();
    let log_as_opened = std::fs::read(dir.path().join("commits.log")).expect("commits.log");
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let doc = acked_addr(&op(
        port,
        Some(&owner),
        &format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"}}"#),
    ));
    rotate_a_segment(port, &owner, &doc);
    sd.daemon().service_the_checkpoint_now();
    let floor = sd.daemon().newest_checkpoint().expect("a third checkpoint landed").seq;
    assert!(floor.0 > head, "the third checkpoint lies above the head");
    for (name, before) in DERIVED.iter().zip(&as_opened) {
        assert_eq!(
            &std::fs::read(dir.path().join(name)).expect(name),
            before,
            "FINDING (F8): {name} was rewritten under the pending set"
        );
    }
    // `commits.log` keeps appending while the set pends — the writes above
    // took their lines — and is not rewritten: its lines below B stand.
    let log_now = std::fs::read(dir.path().join("commits.log")).expect("commits.log");
    assert!(
        log_now.starts_with(&log_as_opened) && log_now.len() > log_as_opened.len(),
        "FINDING (F8): commits.log was rewritten under the pending set, not appended to"
    );
    assert!(sd.daemon().feed_walk_pending(), "still pending");
    let landed = format!("landing: checkpoint at position {} landed", floor.0);
    let line_25 = sd
        .daemon()
        .checkpoint_lines()
        .into_iter()
        .rfind(|line| line.starts_with(&landed))
        .expect("the third checkpoint's landing line");
    assert!(
        line_25.contains("; the change feed's files wait on the walk's landing over ")
            && line_25.contains(&format!(
                " bare positions the index lost for their rewrite, the resident entries trimmed \
                 below position {b} in "
            )),
        "line 25 names the set and the fence it trimmed to: {line_25}"
    );
    assert!(!line_25.contains("compacted below"), "no file was compacted: {line_25}");
    let (st, v) = changes(port, Some(&owner), &format!("since={a}"));
    assert_eq!(
        (st, v["error"].as_str(), v["floor"].as_u64()),
        (410, Some("history_reclaimed"), Some(b)),
        "{v}"
    );
    assert!(
        sd.daemon().feed_pending_set().iter().all(|&at| at >= b),
        "the set drops what the journal reclaimed"
    );
    let (st, v) = changes(port, Some(&owner), &format!("since={}", b - 1));
    assert_eq!(
        (st, v["error"].as_str()),
        (503, Some("feed_rebuilding")),
        "from the floor, reaching the set: {v}"
    );

    release_and_land(&sd);
    let text = std::fs::read_to_string(dir.path().join("commits.log")).expect("commits.log");
    assert!(
        text.starts_with(&format!("{{\"min_since\":{}}}\n", b - 1)),
        "the compaction the landing owed, written: {text}"
    );
    let records = index_records(dir.path());
    assert!(
        records.iter().all(|&at| at > b),
        "no index record at or below the floor's own boundary: {records:?}"
    );
    let refused = lines_with(&sd, "failure: feed-index.log: the journal refused to classify ");
    assert_eq!(
        refused.len(),
        1,
        "B, proved from the base embodying it, is unclassifiable, said once: {refused:?}"
    );
    assert!(refused[0].contains(&format!("the first at position {b} (")), "{refused:?}");
    let (st, v) = changes(port, Some(&owner), &format!("since={}", b - 1));
    assert_eq!(st, 200, "{v}");
    let served = positions(&v);
    assert_eq!(served.first(), Some(&b), "the floor itself serves: {served:?}");
    assert!(served.contains(&head), "and the feed runs to the head: {served:?}");
    sd.shutdown();
}

/// T18 — BOTH AT ONCE: a torn `commits.log` AND a lost index pend together,
/// one walk, one landing. Ten owner commits, the tail of six bared and the
/// never-lost pages read; then the log torn back three more and the index
/// lost: the region `(head − 3, head]` and the set, the three bare positions
/// below it. The walk held, both `open:` lines come, each with its count,
/// the files fenced below both; a page reaching either is refused by one
/// refusal naming both; a page below serves. Released, one landing: the
/// log's `landing:` line once and the sort's once, every class's pages
/// byte-equal to the never-lost board's, the files covering the head, the
/// offsets agreeing.
#[test]
fn a_torn_log_and_a_lost_index_pend_together_and_land_in_one_walk() {
    let _held = hold();
    let dir = tempfile::tempdir().expect("tempdir");
    let (head, _, _) = seeded_board(dir.path(), 10);
    let low = head - 6;
    let never_lost = bare_the_tail(dir.path(), low);
    tear_to(dir.path(), head - 3);
    lose_the_index(dir.path());

    let sd = spawn_holding_the_walk(dir.path());
    let port = sd.port();
    assert_eq!(sd.daemon().feed_pending_region(), Some((head - 3, head)), "the region");
    assert_eq!(sd.daemon().feed_pending_set(), [low + 1, low + 2, low + 3], "the set below it");
    let walk_open = await_the_open_line(&sd);
    assert_eq!(
        walk_open,
        format!(
            "open: commits.log covers to position {}; walking 3 boundaries to position {head}",
            head - 3
        )
    );
    let sort_open = await_the_sort_open_line(&sd);
    assert_eq!(
        sort_open,
        format!(
            "open: feed-index.log covers to position {low}: 3 bare positions are classified from \
             the journal behind the listener, 4 world reconstructions in all"
        )
    );
    for name in DERIVED {
        assert_eq!(
            coverage_of(dir.path(), name),
            low,
            "{name} is fenced below the set and the region"
        );
    }
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let detail = refused_detail(port, Some(&owner), &format!("since={low}"));
    assert!(
        detail.contains(&format!("positions above {} through {head}", head - 3))
            && detail.contains("3 bare positions"),
        "the one refusal names both: {detail}"
    );
    let detail = refused_detail(port, Some(&owner), &format!("since={}", head - 2));
    assert!(detail.contains("3 bare positions"), "inside the region, the set named too: {detail}");
    served_page(port, Some(&owner), &format!("since={}&limit=1", low - 1), &[low], true);

    release_and_land(&sd);
    let (walk, sort) = (walk_landings(&sd), sort_landings(&sd));
    assert_eq!((walk.len(), sort.len()), (1, 1), "one landing, a line per file: {walk:?} {sort:?}");
    assert!(
        walk[0].starts_with(&format!(
            "landing: commits.log re-covered positions ({}, {head}]: 3 boundaries walked, 0 of \
             them unclassifiable",
            head - 3
        )),
        "{walk:?}"
    );
    assert!(
        sort[0].starts_with(
            "landing: feed-index.log: 3 of 3 bare positions classified from the journal, 4 world \
             reconstructions, in "
        ),
        "{sort:?}"
    );
    assert_pages_as_never_lost(port, &never_lost);
    for name in DERIVED {
        assert_eq!(coverage_of(dir.path(), name), head, "{name} covers the head after the landing");
    }
    assert_offsets_agree(dir.path());
    sd.shutdown();
}
