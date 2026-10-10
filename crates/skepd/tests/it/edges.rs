//! THE EDGE PAIRS (`operations.md` §1.1 m12; §4 rows 27 and 33; §6's three
//! rows): the five permit pools — the reconstruction, the class scan, the
//! fetch, the upload and the write — the live-stream budget, the challenge
//! store and the workers' `accept` each say their condition at its EDGES,
//! once per episode, on the operator stream: a `failure:` line when a
//! request first meets the bound, a `landing:` line at the first act the
//! bound admits once it has stood clear for `EDGE_HOLD_DOWN`; nothing per
//! request; nothing on a line but the condition — no count (the upload
//! pool's landing alone carries the episode's refusals), no path, query,
//! principal, peer or reader. The refusals themselves — the five `503
//! …_busy` bodies, the budget's clean close, `/challenge`'s answer — are
//! the standing suites' and unchanged.
//!
//! Judged through the daemon's own record of its lines (`lines_said`) and
//! the media gate's (`media_lines_said`), since no suite captures the
//! stream in-process; the hold-down through the daemon's clock seam
//! (`advance_edge_clock_ms`), never a sleep; the pools held full through
//! the `try_hold_*` hooks, which hold the pool and cross no edge; the
//! accept pair through the accept seam (`fail_the_next_accepts`), which
//! fails the next `k` accepts with a chosen error in place of exhausting
//! descriptors — the real `EMFILE` stays untested (§4 row 33's TEST column).
//!
//! * P1 — each pool's pair, once per episode: the five claims over one
//!   driver, [`the_pools_pair_is_said_once_per_episode`].
//! * P2 — the budget's pair at the 65th stream and the first admission a
//!   hold-down later.
//! * P3 — the challenge pair at a live eviction past the cap and a clean
//!   mint a hold-down later (the store's own claims are
//!   `auth/session/tests.rs`'s).
//! * P4 — the accept pair, one line across two workers, `{n}` counted.
//! * P5 — the door: every line captured opens with its class word, and no
//!   pair's site takes the un-classed door — read off the sources.

use crate::common;

use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::time::{Duration, Instant};

use common::*;
use skepd::{Daemon, Permit, Skepd};

/// `EDGE_HOLD_DOWN`, 15 s, restated here on purpose — the discipline
/// `events.rs` applies to the budget: a constant that moves is a visible
/// event at this file, not a claim that quietly measures less.
const EDGE_HOLD_DOWN_MS: u64 = 15_000;

/// A clock advance SHORT of the hold-down — two of them past the first
/// refusal is a whole hold-down past it, which is how the claims tell a
/// hold-down measured from the LAST refusal from one measured from the
/// first.
const SHORT_OF_THE_HOLD_DOWN_MS: u64 = 10_000;

/// A clock advance PAST the hold-down, by a second.
const PAST_THE_HOLD_DOWN_MS: u64 = EDGE_HOLD_DOWN_MS + 1_000;

/// The daemon's live-stream budget (`MAX_SUBSCRIBERS`), restated as
/// `events.rs` restates it.
const SUBSCRIBER_CAP: usize = 64;

/// The challenge store's cap (`MAX_LIVE_NONCES`), restated.
const NONCE_CAP: usize = 4096;

/// The challenge TTL (`CHALLENGE_TTL`), restated — the wire's `ttl_ms`.
const CHALLENGE_TTL_MS: u64 = 60_000;

/// The daemon's record, filtered to the lines holding `needle`.
fn said(sd: &Skepd, needle: &str) -> Vec<String> {
    sd.daemon().lines_said().into_iter().filter(|l| l.contains(needle)).collect()
}

/// The media gate's record, filtered to the lines holding `needle`.
fn media_said(sd: &Skepd, needle: &str) -> Vec<String> {
    sd.daemon().media_lines_said().into_iter().filter(|l| l.contains(needle)).collect()
}

/// P5's class word, at the head of every captured line: the record keeps
/// `{class}: {what}`, the stream's own head `skepd: {time} ` being the
/// door's.
fn assert_classed(lines: &[String]) {
    for line in lines {
        assert!(
            line.starts_with("failure: ") || line.starts_with("landing: "),
            "FINDING (P5): a line without its class word: {line}"
        );
    }
}

/// No digit on a line that carries no count — a line naming no reader and
/// counting nothing is not read telemetry (D9, read loose), and a count,
/// a position or a principal would be a digit.
fn assert_no_digit(lines: &[String]) {
    for line in lines {
        assert!(
            !line.chars().any(|c| c.is_ascii_digit()),
            "FINDING (m12): a digit rides it: {line}"
        );
    }
}

/// Poll until `holds`, within a deadline, naming what never came.
fn wait_until(what: &str, holds: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !holds() {
        assert!(Instant::now() < deadline, "{what}: not within 20 s");
        std::thread::sleep(Duration::from_millis(5));
    }
}

// ── P1: the five pools ───────────────────────────────────────────────────

/// One pool under the fence: the word its lines name it by (the refusal's
/// own, `{word}_busy`), the hook that holds one of its permits exactly as
/// an in-flight request does, the request that meets it — `503 {word}_busy`
/// with the pool full, `200` with a permit free — the door its lines are
/// read through, and whether its landing carries the episode's count.
struct Pool {
    word: &'static str,
    hold: for<'a> fn(&'a Daemon) -> Option<Permit<'a>>,
    request: Box<dyn Fn() -> (u16, Vec<u8>)>,
    door: fn(&Skepd, &str) -> Vec<String>,
    counted: bool,
}

/// THE DRIVER (P1; m12; §4 row 27): the pool held full through the hook; a
/// request refused `503 {word}_busy` → exactly ONE `failure: the {word} pool
/// is saturated`, its text whole; a second refusal → no new line; a permit
/// released and the clock advanced short of the hold-down, then a request
/// admitted → no `landing:`; the pool refilled and refused inside the
/// hold-down → still no `landing:` and no second `failure:` (the hold-down
/// restarts); released, the clock advanced to a whole hold-down past the
/// FIRST refusal but not the last, a request admitted → still none (M3:
/// measured from the last refusal); the clock past the hold-down since the
/// last refusal, the holder's next admitted act → exactly ONE `landing: the
/// {word} pool has room again` (the upload pool's with its count); a second
/// admission → no second landing; a refusal after it → a NEW `failure:`.
/// The read pools' and the write pool's lines carry no digit; every line
/// opens with its class word.
fn the_pools_pair_is_said_once_per_episode(sd: &Skepd, pool: &Pool) {
    let daemon = sd.daemon();
    let needle = format!("the {} pool", pool.word);
    let lines = || (pool.door)(sd, &needle);
    let failure = format!("failure: the {} pool is saturated", pool.word);
    let landing = if pool.counted {
        format!("landing: the {} pool has room again after 3 refusals", pool.word)
    } else {
        format!("landing: the {} pool has room again", pool.word)
    };
    let refused = |what: &str| {
        let (st, body) = (pool.request)();
        let text = String::from_utf8_lossy(&body).to_string();
        assert_eq!(st, 503, "{}: {what}: {text}", pool.word);
        assert_eq!(
            json(&body)["error"].as_str(),
            Some(format!("{}_busy", pool.word).as_str()),
            "{}: {what}: {text}",
            pool.word
        );
    };
    let admitted = |what: &str| {
        let (st, body) = (pool.request)();
        assert_eq!(st, 200, "{}: {what}: {}", pool.word, String::from_utf8_lossy(&body));
    };

    admitted("the pool free, before anything");
    assert_eq!(
        lines(),
        Vec::<String>::new(),
        "{}: nothing said while the pool has room",
        pool.word
    );

    // THE FIRST EDGE, ONCE: the pool held full, the first request past it.
    let mut held: Vec<Permit<'_>> = std::iter::repeat_with(|| (pool.hold)(daemon))
        .take_while(Option::is_some)
        .flatten()
        .collect();
    assert!(!held.is_empty(), "{}: a pool to hold", pool.word);
    refused("the first request to meet the pool full");
    assert_eq!(lines(), [failure.clone()], "FINDING (m12): the first edge, once, its text whole");
    refused("the second");
    assert_eq!(lines(), [failure.clone()], "FINDING (m12): no line at the next refusal");

    // SHORT OF THE HOLD-DOWN: a permit back, the clock short, a request
    // admitted — no landing.
    drop(held.pop());
    daemon.advance_edge_clock_ms(SHORT_OF_THE_HOLD_DOWN_MS);
    admitted("one permit free, short of the hold-down");
    assert_eq!(lines(), [failure.clone()], "FINDING (M2): a landing short of the hold-down");

    // INSIDE THE HOLD-DOWN, REFUSED AGAIN: the episode stays open, the
    // hold-down restarts, nothing said.
    held.push((pool.hold)(daemon).expect("the released slot held again"));
    refused("refilled, inside the hold-down");
    assert_eq!(
        lines(),
        [failure.clone()],
        "FINDING (m12): a refusal inside the hold-down says nothing"
    );

    // A WHOLE HOLD-DOWN PAST THE FIRST REFUSAL, NOT THE LAST: admitted, and
    // still no landing — the hold-down is measured from the last refusal.
    drop(held.pop());
    daemon.advance_edge_clock_ms(SHORT_OF_THE_HOLD_DOWN_MS);
    admitted("a hold-down past the first refusal, half of one past the last");
    assert_eq!(
        lines(),
        [failure.clone()],
        "FINDING (M3): the hold-down did not restart at the refusal inside it"
    );

    // PAST THE HOLD-DOWN SINCE THE LAST REFUSAL: the next admitted act is
    // the landing, once.
    daemon.advance_edge_clock_ms(PAST_THE_HOLD_DOWN_MS - SHORT_OF_THE_HOLD_DOWN_MS);
    admitted("a whole hold-down past the last refusal");
    assert_eq!(
        lines(),
        [failure.clone(), landing.clone()],
        "FINDING (m12): the second edge, once, its text whole"
    );
    admitted("again");
    assert_eq!(lines(), [failure.clone(), landing.clone()], "no second landing");

    // AFTER THE LANDING, A REFUSAL: a new episode, a new failure line.
    held.push((pool.hold)(daemon).expect("the slot held once more"));
    refused("after the landing");
    assert_eq!(
        lines(),
        [failure.clone(), landing.clone(), failure.clone()],
        "FINDING (m12): the next refusal after a landing opens a new episode"
    );
    drop(held);
    admitted("the pool whole again");

    // THE WORDS: the class word at every head; no digit but the counted
    // landing's, which carries the episode's refusals and nothing else.
    let all = lines();
    assert_classed(&all);
    if pool.counted {
        assert_no_digit(&all[..1]);
        assert_no_digit(&all[2..]);
        assert!(all[1].ends_with(" after 3 refusals"), "{}", all[1]);
    } else {
        assert_no_digit(&all);
    }
}

/// P1 — THE RECONSTRUCTION POOL (`503 history_busy`; `/op-at` at a position,
/// the smallest reconstruction): its pair on the daemon's record, the word
/// `history`.
#[test]
fn the_history_pools_pair_is_said_once_per_episode() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let pool = Pool {
        word: "history",
        hold: Daemon::try_hold_reconstruction_permit,
        request: Box::new(move || {
            http(
                port,
                "POST",
                "/op-at",
                None,
                br#"{"at":0,"frame":{"op":"next_account_prefix","parent":"1"}}"#,
            )
        }),
        door: said,
        counted: false,
    };
    the_pools_pair_is_said_once_per_episode(&sd, &pool);
    sd.shutdown();
}

/// P1 — THE CLASS-SCAN POOL (`503 scan_busy`; an all-`any` `count_ftt`, the
/// cheapest member of the bounded set): its pair on the daemon's record,
/// the word `scan`.
#[test]
fn the_scan_pools_pair_is_said_once_per_episode() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let pool = Pool {
        word: "scan",
        hold: Daemon::try_hold_scan_permit,
        request: Box::new(move || {
            http(
                port,
                "POST",
                "/op",
                None,
                br#"{"op":"count_ftt","q":{"from":"any","home":"any","to":"any","ty":"any"}}"#,
            )
        }),
        door: said,
        counted: false,
    };
    the_pools_pair_is_said_once_per_episode(&sd, &pool);
    sd.shutdown();
}

/// P1 — THE FETCH POOL (`503 fetch_busy`; the owner's fetch of its own
/// draft's cell, past the gate and the classification): its pair on the
/// MEDIA GATE's record — said through a clone of the gate's door, below the
/// daemon's — the word `fetch`.
#[test]
fn the_fetch_pools_pair_is_said_once_per_episode_through_the_gates_door() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let bytes = b"a small picture the owner fetches";
    put_whole(port, &owner, bytes);
    let draft = owner_draft(port, &owner);
    assert_eq!(insert_cell(port, &owner, &draft, bytes, bytes.len() as u64), "ok");
    let i = format!("{draft}.0.1.1");
    let pool = Pool {
        word: "fetch",
        hold: Daemon::try_hold_fetch_permit,
        request: Box::new(move || {
            let (st, _, body) = fetch(port, Some(&owner), &i);
            (st, body)
        }),
        door: media_said,
        counted: false,
    };
    the_pools_pair_is_said_once_per_episode(&sd, &pool);
    assert!(
        said(&sd, "the fetch pool").is_empty(),
        "said below the daemon's door, not on its record"
    );
    sd.shutdown();
}

/// P1 — THE UPLOAD POOL (`503 upload_busy`; a bodiless creation, which holds
/// its permit for the milliseconds its record takes): its pair on the MEDIA
/// GATE's record, the word `upload` — and its landing the one line of the
/// eight pairs that carries a count, the episode's refusals (the ruling's
/// "may carry", taken).
#[test]
fn the_upload_pools_pair_is_said_once_per_episode_and_its_landing_counts_the_refusals() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let token = open_session(port, CLAIMANT_PRINCIPAL);
    let pool = Pool {
        word: "upload",
        hold: Daemon::try_hold_upload_permit,
        request: Box::new(move || {
            let (st, _, body) = blob_create(port, Some(&token), 10, b"");
            (st, body)
        }),
        door: media_said,
        counted: true,
    };
    the_pools_pair_is_said_once_per_episode(&sd, &pool);
    assert!(
        said(&sd, "the upload pool").is_empty(),
        "said below the daemon's door, not on its record"
    );
    sd.shutdown();
}

/// P1 — THE WRITE POOL (`503 write_busy`; a session write, the plain
/// sequence): its pair on the daemon's record, the word `write`, judged at
/// the one door the three write sequences share.
#[test]
fn the_write_pools_pair_is_said_once_per_episode() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let frame = create_frame(CLAIMANT_ACCOUNT, None);
    let pool = Pool {
        word: "write",
        hold: Daemon::try_hold_write_permit,
        request: Box::new(move || http(port, "POST", "/op", Some(&owner), frame.as_bytes())),
        door: said,
        counted: false,
    };
    the_pools_pair_is_said_once_per_episode(&sd, &pool);
    sd.shutdown();
}

// ── P2: the live-stream budget ───────────────────────────────────────────

/// One raw `GET /events` connection, returning the first bytes the daemon
/// sends — a served stream's `200` head, or nothing for a refused one (the
/// clean close `events.rs` pins).
fn raw_events(port: u16) -> (TcpStream, Vec<u8>) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect /events");
    s.set_read_timeout(Some(Duration::from_secs(10))).expect("read timeout");
    s.write_all(b"GET /events HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").expect("write request");
    let mut head = [0u8; 256];
    let n: usize = s.read(&mut head).unwrap_or_default();
    (s, head[..n].to_vec())
}

/// P2 — THE BUDGET's PAIR (m12; §6's row): 64 streams open and the 65th
/// refused with the clean close → exactly one `failure: the live-stream
/// budget is saturated`; a 66th → none; one stream closed, its slot reaped
/// by the commits that wake the parked subscriber, the clock past the
/// hold-down before every attempt (a refused attempt restarts it), the next
/// admission → `landing: the live-stream budget has room again`, once; no
/// count on either line, the budget's size unsaid.
#[test]
fn the_budgets_pair_is_said_at_the_65th_stream_and_at_the_first_admission_a_hold_down_later() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let lines = || said(&sd, "live-stream budget");
    let failure = "failure: the live-stream budget is saturated".to_string();

    let mut held: Vec<(TcpStream, Vec<u8>)> =
        (0..SUBSCRIBER_CAP).map(|_| raw_events(port)).collect();
    for (i, (_, head)) in held.iter().enumerate() {
        assert!(head.starts_with(b"HTTP/1.1 200 "), "stream {i} of the budget is served");
    }
    assert_eq!(lines(), Vec::<String>::new(), "the budget full and nothing past it: nothing said");

    let (_surplus, head) = raw_events(port);
    assert!(
        head.is_empty(),
        "the 65th is refused with the clean close: {:?}",
        String::from_utf8_lossy(&head)
    );
    assert_eq!(
        lines(),
        [failure.clone()],
        "FINDING (M5): the 65th stream says the first edge, once"
    );
    let (_surplus_too, head) = raw_events(port);
    assert!(head.is_empty(), "the 66th is refused too");
    assert_eq!(lines(), [failure.clone()], "FINDING (m12): no line at the next refusal");

    // One stream closed; its slot returns by the daemon's own mechanism — a
    // commit wakes the parked subscriber, whose failed write ends it, and
    // the next admission reaps it (`events.rs` states why one commit does
    // not settle it). The clock is moved a whole hold-down before EVERY
    // attempt, since a refused attempt restarts the hold-down.
    drop(held.pop());
    let boot = open_session(port, 0);
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut node = 2_000u64;
    let _admitted = loop {
        sd.daemon().advance_edge_clock_ms(PAST_THE_HOLD_DOWN_MS);
        node += 1;
        let v = op(port, Some(&boot), &format!(r#"{{"op":"register_node","addr":"1.{node}"}}"#));
        assert!(v["at"].is_u64(), "the poll's commit must actually commit: {v}");
        let (s, head) = raw_events(port);
        if head.starts_with(b"HTTP/1.1 200 ") {
            break s;
        }
        assert!(Instant::now() < deadline, "the departed subscriber's slot never returned");
    };
    assert_eq!(
        lines(),
        [failure.clone(), "landing: the live-stream budget has room again".to_string()],
        "FINDING (m12): the second edge at the first admission a hold-down after the last refusal"
    );
    assert_classed(&lines());
    assert_no_digit(&lines());
    sd.shutdown();
}

// ── P3: the challenge store ──────────────────────────────────────────────

/// P3 — THE CHALLENGE PAIR THROUGH `GET /challenge` (m12; §6's row): the
/// store filled to its cap says nothing; the mint past it evicts a nonce
/// inside its time to live → `failure: challenge store: a nonce was evicted
/// inside its time to live; a handshake it belonged to will be refused`,
/// once, naming no caller; further mints that evict live nonces → none; a
/// live eviction after the hold-down → still none (a refusal never lands);
/// the clock past the TTL, a mint that evicts only an EXPIRED nonce — no
/// handshake lost — a whole hold-down after the last live eviction →
/// `landing: challenge store: minting without evicting a live nonce again`.
/// The store's own claims — a live eviction's edge once, an expired
/// eviction's none, the landing judged at a mint — are the unit suite's.
#[test]
fn the_challenge_pair_is_said_at_a_live_eviction_once_and_at_a_clean_mint_a_hold_down_later() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let lines = || said(&sd, "challenge store:");
    let mint = || {
        let (st, body) = get(port, "/challenge?principal=7");
        assert_eq!(st, 200, "{}", String::from_utf8_lossy(&body));
    };
    let failure = "failure: challenge store: a nonce was evicted inside its time to live; a \
                   handshake it belonged to will be refused"
        .to_string();

    for _ in 0..NONCE_CAP {
        mint();
    }
    assert_eq!(lines(), Vec::<String>::new(), "the store filled to its cap: no eviction, no line");
    mint();
    assert_eq!(
        lines(),
        [failure.clone()],
        "FINDING (m12): the first live eviction, once, its text whole"
    );
    mint();
    mint();
    assert_eq!(lines(), [failure.clone()], "FINDING (m12): no line at the next live evictions");

    // After the hold-down, a mint that still evicts a live nonce: a refusal
    // never lands, and the episode stands.
    sd.daemon().advance_edge_clock_ms(PAST_THE_HOLD_DOWN_MS);
    mint();
    assert_eq!(lines(), [failure.clone()], "a live eviction after the hold-down lands nothing");

    // Past the TTL: the oldest nonce standing is expired, so the mint evicts
    // it dead — a clean mint, a whole hold-down after the last live eviction.
    sd.daemon().advance_edge_clock_ms(CHALLENGE_TTL_MS + 1_000);
    mint();
    assert_eq!(
        lines(),
        [
            failure.clone(),
            "landing: challenge store: minting without evicting a live nonce again".to_string()
        ],
        "FINDING (m12): the landing at the first clean mint after the hold-down"
    );
    assert_classed(&lines());
    assert_no_digit(&lines());
    for line in lines() {
        assert!(!line.contains("principal") && !line.contains("nonce was evicted by"), "{line}");
    }
    sd.shutdown();
}

// ── P4: the accept loop ──────────────────────────────────────────────────

/// P4 — THE ACCEPT PAIR (m12; §4 row 33): the seam fails the next accepts
/// with the OS's own words for the descriptor wall, two connections opened
/// together so two workers take them — ONE `failure: worker: accept failed
/// (Too many open files (os error 24)); new connections wait` across the
/// workers; the daemon serves meanwhile (`/health` 200, inside the
/// hold-down: no landing); the clock past the hold-down, the next accepted
/// connection → `landing: worker: accept recovered after {n} failures`,
/// `{n}` every worker's failures counted; `/health` 200 after.
#[test]
fn the_accept_pair_is_said_once_across_two_workers_and_recovered_after_the_hold_down() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let lines = || said(&sd, "worker: accept");
    let text = "Too many open files (os error 24)";
    let (st, _) = get(port, "/health");
    assert_eq!(st, 200);
    assert_eq!(lines(), Vec::<String>::new(), "a serving board: nothing said");
    let (fired_before, _) = Daemon::accept_faults_fired();

    // Two failing accepts on TWO workers: the connections are opened
    // together, each taken by a worker blocked in `accept`, which fires the
    // seam, drops it and sleeps the retry pause — so the second goes to
    // another worker. Re-armed where the same worker took both (every fire
    // is a refusal inside the one episode, so the line count holds).
    let mut attempts = 0;
    loop {
        Daemon::fail_the_next_accepts(2, ErrorKind::Other, text);
        let first = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        let second = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        wait_until("the seam's two accepts", || Daemon::accept_faults_remaining() == 0);
        drop((first, second));
        let (_, workers) = Daemon::accept_faults_fired();
        if workers >= 2 {
            break;
        }
        attempts += 1;
        assert!(attempts < 20, "two workers never took the two connections");
    }
    assert_eq!(
        lines(),
        [format!("failure: worker: accept failed ({text}); new connections wait")],
        "FINDING (M7): one failure line across the workers, the OS text as the cause"
    );

    // The daemon serves throughout; a success inside the hold-down lands
    // nothing.
    let (st, body) = get(port, "/health");
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&body));
    assert_eq!(json(&body)["ok"].as_bool(), Some(true));
    assert_eq!(lines().len(), 1, "inside the hold-down: no landing");

    // Past the hold-down, the next accepted connection is the recovery,
    // counting every failure the episode held.
    sd.daemon().advance_edge_clock_ms(PAST_THE_HOLD_DOWN_MS);
    let (st, _) = get(port, "/health");
    assert_eq!(st, 200);
    let (fired, workers) = Daemon::accept_faults_fired();
    let n = fired - fired_before;
    assert!(workers >= 2 && n >= 2, "two workers, {n} failures");
    assert_eq!(
        lines(),
        [
            format!("failure: worker: accept failed ({text}); new connections wait"),
            format!("landing: worker: accept recovered after {n} failures"),
        ],
        "FINDING (m12): the recovery once, after the hold-down, with every worker's failures"
    );
    assert_classed(&lines());
    let (st, _) = get(port, "/health");
    assert_eq!(st, 200, "the daemon serves after the pair");
    sd.shutdown();
}

// ── P5: the door ─────────────────────────────────────────────────────────

/// P5 — THE DOOR, OFF THE SOURCES: no pair's site takes the un-classed
/// `notice::line`/`notice::lines` — the holders' files hold none, and the
/// pairs' sections of the files that hold older un-classed lines elsewhere
/// hold none — every site says its edge under the edge's own class word
/// (`edge.class()`, or `Class::Landing` for the recovery), and the write
/// pool's three sequences take their permit through the one helper and no
/// other door. The class word on every captured line is the other half,
/// asserted by every claim above.
#[test]
fn no_edge_pair_takes_the_unclassed_door_and_the_write_pool_has_one_door() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let read = |path: &str| {
        std::fs::read_to_string(manifest.join(path)).unwrap_or_else(|e| panic!("{path}: {e}"))
    };
    let section = |text: &str, from: &str, to: &str| -> String {
        let start = text.find(from).unwrap_or_else(|| panic!("`{from}`"));
        let end = text[start..].find(to).unwrap_or_else(|| panic!("`{to}` after `{from}`")) + start;
        text[start..end].to_string()
    };
    let unclassed = |what: &str, text: &str| {
        assert!(
            !text.contains("notice::line(") && !text.contains("notice::lines("),
            "FINDING (M8): {what} takes the un-classed door"
        );
    };
    // The holders' files, whole.
    for path in [
        "src/history.rs",
        "src/server/scan.rs",
        "src/auth/session.rs",
        "../skep-util/src/permits.rs",
        "../skep-media/src/serve.rs",
        "../skep-media/src/lib.rs",
    ] {
        unclassed(path, &read(path));
    }
    // The pairs' sections of the files that hold older un-classed lines.
    let server = read("src/server.rs");
    let drain =
        section(&server, "    fn say_the_edges_crossed(", "// ── the checkpoint thread's work");
    unclassed("the daemon's drain", &drain);
    for site in ["self.history", "self.scans", "self.auth.challenges"] {
        assert!(
            drain.contains(&format!("{site}\n")) || drain.contains(site),
            "the drain reaches {site}"
        );
    }
    assert_eq!(
        drain.matches("edge.class()").count(),
        3,
        "each drained edge under its own class word"
    );
    let words = section(&server, "// ── the edge pairs' words", "#[cfg(test)]");
    unclassed("the pairs' words", &words);
    let listen = read("src/server/listen.rs");
    let accept = section(&listen, "fn say_accept_failed_once(", "/// The live event streams:");
    unclassed("the accept pair", &accept);
    assert!(accept.contains("daemon.say(edge.class(), AcceptFailedLine(e))"));
    assert!(
        accept.contains("daemon.say(Class::Landing, AcceptRecoveredLine { failures: refusals })")
    );
    let budget = section(&listen, "    fn admit(&self, daemon: Arc<Daemon>", "    fn join_all(");
    unclassed("the budget's pair", &budget);
    assert_eq!(budget.matches("daemon.say(edge.class(), BudgetEdgeLine(edge))").count(), 2);
    let op = read("src/server/op.rs");
    let door =
        section(&op, "    fn take_write_permit(", "    /// The locked state one write sequence");
    unclassed("the write pool's door", &door);
    assert!(door.contains("self.say(edge.class(), PoolEdgeLine::new(WRITE_POOL, edge))"));
    assert_eq!(
        op.matches("self.write_permits.try_acquire()").count(),
        1,
        "the pool's permits are taken through the one door and nowhere else in op.rs"
    );
    assert_eq!(
        op.matches("self.take_write_permit()").count(),
        3,
        "the three sequences take the one door"
    );
}
