//! THE CHANGE FEED KEPT FROM GENESIS FOREVER (wire.md §The change feed,
//! Retention; skep #578): `commits.log` and its four derived sidecars are
//! never compacted to the journal's reclaim floor, the daemon holds a
//! WINDOW of recent positions in memory (`skep_core::limits::
//! FEED_RESIDENT_WINDOW`) and reads the rest from the files by position,
//! `/changes` answers every position that ever had a line at any age, and a
//! mirror begins from genesis on a board of any age. Judged against the
//! daemon's own record of its lines and against a second daemon over a copy
//! of the same board:
//!
//! * K1 — nothing dropped: a board driven past three checkpoint landings,
//!   the journal reclaiming below its first commits, answers `/changes`
//!   from 0 with every row it answered before, owner and guest alike, and
//!   `/op-at` at a reclaimed position answers `history_reclaimed` as ever.
//! * K2 — the window: with the window set to 64 positions for the board,
//!   a board of two thousand positions serves every page — plain, `under=`,
//!   `drafts=true`, a page straddling the window's edge — byte-equal to a
//!   daemon over a copy of the board holding every position resident, and
//!   the entries resident never exceed the window.
//! * K3 — a restart refills the window from the files and the pages below
//!   it still serve; a landing after a torn tail keeps every line the file
//!   held and lands the torn positions, one line each.
//! * K4 — a hole an earlier build's compaction left: a `commits.log`
//!   fenced by hand opens, says the hole once, answers `410` with `floor`
//!   the first line held below it, and serves everything above.
//! * K5 — the mirror: a walk of `/changes` from 0 after the board reclaimed
//!   reaches the head and reads the rows it read before, and the resolver's
//!   own mirror opens cold at that age.
//! * K6 — a lost index on a board of three thousand bare positions is
//!   sorted behind the listener and landed, and nothing compacts after it.
//!
//! The walk's hold is PROCESS-WIDE (`feed_walk.rs`'s module doc): under
//! nextest each test has its own process; under plain `cargo test` a test
//! here that holds the walk may park another suite's reopen until its
//! release, and is run alone where that shows.

use std::path::Path;
use std::time::{Duration, Instant};

use serde_json::Value;
use skep_identity::Fingerprint;
use skep_resolve::{Mirror, Origin, RealmId, RootHint};
use skepd::{Daemon, Skepd};

use crate::changes::op_at_floor;
use crate::common::{
    acked_addr, acked_at, anchor_key, copy_board, device_key, expect_resp, get, http, json, op,
    open_session, public_key_of, spawn, tear_commits_log_to, CLAIMANT_ACCOUNT, CLAIMANT_DOC1,
    CLAIMANT_PRINCIPAL,
};

/// The registry seed's first public row: the member's publish at 8.
const SEED_PUBLISH_AT: u64 = 8;

/// The window K2 and K3 set for their boards, in positions.
const SMALL_WINDOW: u64 = 64;

/// The lines K6 bares at the tail of its three-thousand-position board.
const BARED: usize = 256;

/// The claimed board's head as the claim leaves it, `feed_walk.rs`'s figure.
fn head(port: u16) -> u64 {
    let (st, body) = get(port, "/health");
    assert_eq!(st, 200, "/health: {}", String::from_utf8_lossy(&body));
    json(&body)["log_position"].as_u64().expect("log_position")
}

/// One committing write as `session`: a fresh private draft under the
/// claimant's account — one record, so the position advances by one.
fn mint(port: u16, session: &str) -> u64 {
    acked_at(&op(
        port,
        Some(session),
        &format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"}}"#),
    ))
}

/// A fresh private draft under the claimant's account, its address.
fn draft(port: u16, session: &str) -> String {
    acked_addr(&op(
        port,
        Some(session),
        &format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"}}"#),
    ))
}

/// One insert of `text` into `doc` as `session`, a prepend: its position.
fn insert(port: u16, session: &str, doc: &str, text: &str) -> u64 {
    acked_at(&op(
        port,
        Some(session),
        &format!(
            r#"{{"op":"insert","doc":"{doc}","at":{{"subspace":"1","ordinal":"1"}},"values":["{text}"]}}"#
        ),
    ))
}

/// A public row every class sees: a `delegate` from the bootstrap session,
/// seating principal `id` at the next account prefix — a `[]`-docs entry,
/// never masked.
fn delegate(port: u16, boot: &str, id: u64) -> u64 {
    let v = op(port, Some(boot), r#"{"op":"next_account_prefix","parent":"1"}"#);
    let prefix = expect_resp(&v, "maybe_addr")["addr"].as_str().expect("prefix").to_string();
    acked_at(&op(
        port,
        Some(boot),
        &format!(r#"{{"op":"delegate","new_prefix":"{prefix}","new_id":{id}}}"#),
    ))
}

/// Six bulk prepends into `doc` from `session` — a segment has to rotate
/// before anything below it can be reclaimed (`changes.rs`'s recipe).
fn rotate_a_segment(port: u16, session: &str, doc: &str) {
    let bulk = "z".repeat(262_144);
    for _ in 0..6 {
        insert(port, session, doc, &bulk);
    }
}

/// `GET /changes?{query}` as `token` (`None` = the guest): the status and
/// the body.
fn changes(port: u16, token: Option<&str>, query: &str) -> (u16, Value) {
    let (st, body) = http(port, "GET", &format!("/changes?{query}"), token, b"");
    (st, json(&body))
}

/// Every row at or below `through`, read from 0 at 256 a page, each row as
/// its own JSON text — the mirror's walk, following `last`.
fn rows_through(port: u16, token: Option<&str>, through: u64) -> Vec<String> {
    let mut rows = Vec::new();
    let mut since = 0u64;
    loop {
        let (st, v) = changes(port, token, &format!("since={since}&limit=256"));
        assert_eq!(st, 200, "since={since}: {v}");
        for row in v["changes"].as_array().expect("changes") {
            if row["at"].as_u64().expect("at") <= through {
                rows.push(row.to_string());
            }
        }
        let last = v["last"].as_u64().expect("last");
        if !v["more"].as_bool().expect("more") || last == since || last >= through {
            return rows;
        }
        since = last;
    }
}

/// A class's pages from 0 under `query` (a `limit` among its members), each
/// page's bytes, to the last.
fn pages(port: u16, token: Option<&str>, query: &str) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut since = 0u64;
    loop {
        let (st, body) = http(port, "GET", &format!("/changes?since={since}&{query}"), token, b"");
        assert_eq!(st, 200, "{query} since={since}: {}", String::from_utf8_lossy(&body));
        let v = json(&body);
        let (last, more) = (v["last"].as_u64().expect("last"), v["more"].as_bool().expect("more"));
        out.push(body);
        if !more || last == since {
            return out;
        }
        since = last;
    }
}

/// Runs a landing and reads the feed's figures off its line: the first
/// position held, `commits.log`'s bytes, the entries resident and the most
/// resident this uptime.
fn landing_feed_figures(sd: &Skepd) -> (u64, u64, u64, u64) {
    sd.daemon().service_the_checkpoint_now();
    let line = sd.daemon().checkpoint_lines().last().cloned().expect("the landing's line");
    assert!(!line.contains("compacted"), "nothing compacts: {line}");
    let head = "; the change feed holds every line from position ";
    let at = line.find(head).unwrap_or_else(|| panic!("{head:?} in {line}"));
    let clause = &line[at + head.len()..];
    let figure = |key: &str| -> u64 {
        let at = clause.find(key).unwrap_or_else(|| panic!("{key:?} in {clause}"));
        clause[at + key.len()..]
            .chars()
            .take_while(char::is_ascii_digit)
            .collect::<String>()
            .parse()
            .unwrap_or_else(|_| panic!("a figure after {key:?} in {clause}"))
    };
    let first = clause
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .expect("the first position");
    (
        first,
        figure(": commits.log "),
        figure(" bytes, "),
        figure(" entries resident, the most this uptime "),
    )
}

/// Waits for `done`, within `patience`, naming what never came.
fn wait_until(what: &str, patience: Duration, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + patience;
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// `commits.log`'s lines under `dir`, as text.
fn log_lines(dir: &Path) -> Vec<String> {
    std::fs::read_to_string(dir.join("commits.log"))
        .expect("commits.log")
        .lines()
        .map(str::to_string)
        .collect()
}

/// The root hint for a board at `port`: its loopback origin and the suite's
/// realm, the fingerprint of the ceremony's genesis set (`resolve.rs`'s).
fn hint_for(port: u16) -> RootHint {
    let realm = RealmId::genesis_fingerprint(&[
        Fingerprint::of(&public_key_of(&anchor_key())),
        Fingerprint::of(&public_key_of(&device_key())),
    ]);
    let origin = Origin::parse(&format!("http://127.0.0.1:{port}")).expect("canonical");
    RootHint::new(vec![origin], realm, None).expect("one origin")
}

/// A claimed board driven past THREE checkpoint landings, each after a
/// segment rotated, so the journal reclaims below the board's first
/// commits: its head before the landings, the owner's session and the rows
/// every class read through that head, owner and guest.
struct Reclaimed {
    sd: Skepd,
    owner: String,
    head_before: u64,
    owner_rows: Vec<String>,
    guest_rows: Vec<String>,
}

fn reclaimed_board(dir: &Path) -> Reclaimed {
    let sd = spawn(dir);
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let boot = open_session(port, 0);
    let draft = draft(port, &owner);
    delegate(port, &boot, 7);
    mint(port, &owner);
    insert(port, &owner, &draft, "two");
    let head_before = head(port);
    let owner_rows = rows_through(port, Some(&owner), head_before);
    let guest_rows = rows_through(port, None, head_before);
    assert!(owner_rows.len() > guest_rows.len(), "the draft's rows are the owner's alone");
    assert!(
        owner_rows[0].contains(&format!("\"at\":{SEED_PUBLISH_AT},")),
        "from the seed's first public row"
    );
    for _ in 0..3 {
        rotate_a_segment(port, &owner, &draft);
        mint(port, &owner);
        sd.daemon().service_the_checkpoint_now();
    }
    // The head a public row, so every class's walk reaches it.
    delegate(port, &boot, 8);
    let floor = op_at_floor(port);
    assert!(floor > head_before, "the premise: the journal reclaimed past the board's first commits: floor {floor}, head before {head_before}");
    Reclaimed { sd, owner, head_before, owner_rows, guest_rows }
}

/// K1 — NOTHING DROPPED (D1 (b): the record of events is kept forever). A
/// board past three landings, the journal reclaiming below its first
/// commits, answers `/changes?since=0` with every row from the seed's first
/// public row, owner and guest pages row for row what they were before the
/// landings; the landing line says the feed holds every line from position
/// 1, `commits.log`'s size the file's own; `/op-at` at a reclaimed position
/// answers `history_reclaimed` as today; a reopen answers the same rows.
/// MUTANT: the open's compaction restored → red at `since=0`.
#[test]
fn k1_nothing_is_dropped_past_three_checkpoint_landings() {
    let dir = tempfile::tempdir().expect("tempdir");
    let board = reclaimed_board(dir.path());
    let port = board.sd.port();
    assert_eq!(
        rows_through(port, Some(&board.owner), board.head_before),
        board.owner_rows,
        "the owner's rows from genesis, row for row"
    );
    assert_eq!(
        rows_through(port, None, board.head_before),
        board.guest_rows,
        "the guest's rows from genesis"
    );
    let (first, bytes, resident, most) = landing_feed_figures(&board.sd);
    assert_eq!(first, 1, "the feed holds every line from position 1");
    assert_eq!(
        bytes,
        std::fs::metadata(dir.path().join("commits.log")).expect("commits.log").len()
    );
    assert!(resident > 0 && resident <= most, "{resident} resident, {most} at most");
    let (st, v) = changes(port, None, "since=0&limit=1");
    assert_eq!((st, v["changes"][0]["at"].as_u64()), (200, Some(SEED_PUBLISH_AT)), "{v}");
    let env = format!(
        r#"{{"at":{},"frame":{{"op":"read_link","a":"{CLAIMANT_DOC1}"}}}}"#,
        board.head_before
    );
    let (st, body) = http(port, "POST", "/op-at", None, env.as_bytes());
    assert_eq!(st, 410, "a reclaimed STATE: {}", String::from_utf8_lossy(&body));
    assert_eq!(json(&body)["error"].as_str(), Some("history_reclaimed"));
    let said = board.sd.daemon().lines_said();
    assert!(
        !said.iter().any(|l| l.contains("hold no line at or below")),
        "no hole: nothing was dropped"
    );
    board.sd.shutdown();

    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    assert_eq!(
        rows_through(port, Some(&owner), board.head_before),
        board.owner_rows,
        "after a reopen, the same rows"
    );
    assert_eq!(rows_through(port, None, board.head_before), board.guest_rows);
    let opened: Vec<String> = sd
        .daemon()
        .lines_said()
        .into_iter()
        .filter(|l| l.starts_with("open: the change feed answers from position "))
        .collect();
    assert!(
        opened[0].starts_with("open: the change feed answers from position 1 to position "),
        "{opened:?}"
    );
    sd.shutdown();
}

/// A board of two thousand positions under a window of [`SMALL_WINDOW`]
/// positions, served and stopped: its head, the claimant's draft and the
/// principal it delegated.
fn two_thousand_positions(dir: &Path) -> (u64, String) {
    skep_core::commits::set_feed_resident_window(dir, SMALL_WINDOW);
    let sd = spawn(dir);
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let boot = open_session(port, 0);
    let draft = draft(port, &owner);
    let mut at = 0u64;
    let mut i = 0u64;
    while at < 2_000 {
        at = match i % 3 {
            0 => mint(port, &owner),
            1 => delegate(port, &boot, 100 + i),
            _ => insert(port, &owner, &draft, &format!("d{i}")),
        };
        i += 1;
    }
    let head = head(port);
    assert!(head >= 2_000, "two thousand positions: {head}");
    sd.shutdown();
    (head, draft)
}

/// Every class's pages under every query shape, from a daemon at `port`:
/// the plain feed, `under=` the account, the draft and the public doc,
/// `drafts=true`, and one page straddling the window's edge — the owner's
/// and the guest's, the token per daemon.
fn every_page(port: u16, head: u64, draft: &str) -> Vec<(String, Vec<Vec<u8>>)> {
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let straddle = format!("limit=4096&since={}", head.saturating_sub(SMALL_WINDOW + 40));
    let shapes = [
        "limit=100".to_string(),
        format!("limit=100&under={CLAIMANT_ACCOUNT}"),
        format!("limit=100&under={draft}"),
        format!("limit=100&under={CLAIMANT_DOC1}"),
        "limit=100&drafts=true".to_string(),
        "limit=37".to_string(),
    ];
    let mut out = Vec::new();
    for shape in &shapes {
        out.push((format!("owner {shape}"), pages(port, Some(&owner), shape)));
        out.push((format!("guest {shape}"), pages(port, None, shape)));
    }
    let (st, body) = http(port, "GET", &format!("/changes?{straddle}"), Some(&owner), b"");
    assert_eq!(st, 200);
    out.push((format!("owner {straddle}"), vec![body]));
    let (st, body) = http(port, "GET", &format!("/changes?{straddle}"), None, b"");
    assert_eq!(st, 200);
    out.push((format!("guest {straddle}"), vec![body]));
    out
}

/// Checks every page of the daemon at `port` against the whole-window
/// daemon's at `whole`, byte for byte, page for page.
fn assert_pages_match(port: u16, whole: u16, head: u64, draft: &str) {
    let small = every_page(port, head, draft);
    let whole = every_page(whole, head, draft);
    assert_eq!(small.len(), whole.len());
    for ((label, small), (_, whole)) in small.iter().zip(&whole) {
        assert_eq!(small.len(), whole.len(), "{label}: the same count of pages");
        for (i, (s, w)) in small.iter().zip(whole).enumerate() {
            if s != w {
                let (sv, wv) = (json(s), json(w));
                let (sr, wr) = (
                    sv["changes"].as_array().expect("rows"),
                    wv["changes"].as_array().expect("rows"),
                );
                let differs = sr.iter().zip(wr).position(|(a, b)| a != b);
                panic!(
                    "{label}, page {i}: the bytes differ below the window: {} rows against {}, last {} against {}, more {} against {}; first row that differs {:?}: {} against {}",
                    sr.len(), wr.len(), sv["last"], wv["last"], sv["more"], wv["more"], differs,
                    differs.map_or("none".to_string(), |d| sr[d].to_string()),
                    differs.map_or("none".to_string(), |d| wr[d].to_string())
                );
            }
        }
    }
    assert!(small.iter().any(|(_, p)| p.len() > 10), "the pages were read, many a shape");
}

/// K2 — THE WINDOW (D1, memory): with the window set to 64 positions for the
/// board, a board of two thousand positions serves pages below the window
/// byte-equal to pages above it and to a daemon's over a copy of the board
/// holding every position resident — plain, `under=`, `drafts=true`, an
/// owner-stream page and a page straddling the window's edge — and the
/// entries resident never exceed the window, read off the landing line.
/// MUTANT: the read below the window answering the resident entries alone
/// → red below the window.
#[test]
fn k2_pages_below_the_window_are_byte_equal_to_pages_above_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (head, draft) = two_thousand_positions(dir.path());
    let copy = tempfile::tempdir().expect("tempdir");
    copy_board(dir.path(), copy.path());
    let whole = spawn(copy.path());
    let small = spawn(dir.path());
    assert_pages_match(small.port(), whole.port(), head, &draft);
    let (first, _, resident, most) = landing_feed_figures(&small);
    assert_eq!(first, 1);
    assert!(
        resident <= SMALL_WINDOW && most <= SMALL_WINDOW,
        "the resident entries never exceed the window: {resident} now, {most} at most"
    );
    assert!(resident > 0, "and the window holds the newest positions");
    let (_, _, whole_resident, _) = landing_feed_figures(&whole);
    assert!(
        whole_resident > SMALL_WINDOW,
        "the copy holds the whole board resident: {whole_resident}"
    );
    small.shutdown();
    whole.shutdown();
}

/// K3 — A RESTART (D1): after a restart the window refills from the files
/// and the pages below it still serve, byte-equal to the whole-window
/// daemon's; a landing after a torn tail keeps every line the file held,
/// verbatim and first, and lands the torn positions, one line each, the
/// rows at or below the tear unchanged. MUTANT: the landing's rewrite
/// writing from the fence → red.
#[test]
fn k3_a_restart_refills_the_window_and_a_landing_keeps_every_line() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (head, draft) = two_thousand_positions(dir.path());
    let copy = tempfile::tempdir().expect("tempdir");
    copy_board(dir.path(), copy.path());
    let whole = spawn(copy.path());
    let small = spawn(dir.path());
    assert_pages_match(small.port(), whole.port(), head, &draft);
    let (_, _, resident, most) = landing_feed_figures(&small);
    assert!(resident <= SMALL_WINDOW && most <= SMALL_WINDOW, "{resident} now, {most} at most");
    small.shutdown();

    // The tail torn: the lines above `low` dropped, the walk re-covering
    // them bare at the reopen, by one rewrite that keeps the rest.
    let before = log_lines(dir.path());
    let low = head - 5;
    tear_commits_log_to(dir.path(), low);
    let torn = std::fs::read(dir.path().join("commits.log")).expect("commits.log");
    assert!(torn.len() < before.join("\n").len(), "the premise: lines were torn");
    let small = spawn(dir.path());
    let after = std::fs::read(dir.path().join("commits.log")).expect("commits.log");
    assert!(after.starts_with(&torn), "every line the file held, kept, verbatim and first");
    assert_eq!(
        log_lines(dir.path()).len(),
        before.len(),
        "the torn positions landed, one line each, nothing dropped"
    );
    assert!(
        !after.windows(9).any(|w| w == b"min_since"),
        "no fence: the journal answered every boundary"
    );
    let port = small.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let whole_owner = open_session(whole.port(), CLAIMANT_PRINCIPAL);
    assert_eq!(
        rows_through(port, Some(&owner), low),
        rows_through(whole.port(), Some(&whole_owner), low),
        "the rows at or below the tear, as the whole-window daemon serves them"
    );
    assert_eq!(rows_through(port, None, low), rows_through(whole.port(), None, low));
    let (st, v) = changes(port, Some(&owner), &format!("since={low}&limit=4096"));
    assert_eq!(st, 200, "{v}");
    let landed = v["changes"].as_array().expect("changes");
    assert!(
        !landed.is_empty() && landed.iter().all(|r| r["time"].is_null() && r["key"].is_null()),
        "the torn positions, bare: {v}"
    );
    small.shutdown();
    whole.shutdown();
}

/// K4 — THE PRE-EXISTING HOLE: a data dir whose `commits.log` an earlier
/// build compacted — the file fenced by hand with a `min_since` line below
/// its oldest surviving line, the four derived files fenced with it —
/// opens, says the hole once, answers `410` with `floor` the first line held
/// for every `since` below the fence, at every class, and serves everything
/// above; a reopen says it once again, and the fence is kept as found.
/// MUTANT: the fence line read as a compaction order → red.
#[test]
fn k4_a_hole_an_earlier_build_left_is_said_once_and_kept() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (head, positions) = {
        let sd = spawn(dir.path());
        let port = sd.port();
        let owner = open_session(port, CLAIMANT_PRINCIPAL);
        let positions: Vec<u64> = (0..6).map(|_| mint(port, &owner)).collect();
        let head = head(port);
        sd.shutdown();
        (head, positions)
    };
    // The earlier build's compaction, by hand: the fence one below the
    // third mint, every line at or below it dropped, the four derived files
    // fenced at the head over their surviving lines.
    let first_held = positions[2];
    let fence = first_held - 1;
    let kept: Vec<String> = log_lines(dir.path())
        .into_iter()
        .filter(|line| json(line.as_bytes())["at"].as_u64().is_some_and(|at| at > fence))
        .collect();
    let dropped = log_lines(dir.path()).len() - kept.len();
    assert!(dropped > 0, "the premise: lines lie below the fence");
    std::fs::write(
        dir.path().join("commits.log"),
        format!("{{\"min_since\":{fence}}}\n{}\n", kept.join("\n")),
    )
    .expect("the compacted log");
    for name in ["feed-index.log", "feed-offsets.log", "feed-masked.log", "feed-streams.log"] {
        let path = dir.path().join(name);
        let kept: Vec<String> = std::fs::read_to_string(&path)
            .expect(name)
            .lines()
            .filter(|line| json(line.as_bytes())["at"].as_u64().is_some_and(|at| at > fence))
            .map(str::to_string)
            .collect();
        std::fs::write(
            &path,
            format!(
                "{}{{\"covered\":{head}}}\n",
                kept.iter().map(|l| format!("{l}\n")).collect::<String>()
            ),
        )
        .expect(name);
    }
    let hole = format!(
        "open: the change feed's files hold no line at or below position {fence}: an earlier \
         build's compaction, or a walk the journal refused, left the fence there; /changes answers \
         410 history_reclaimed for every since below position {first_held}, the first line held"
    );
    for reopen in 0..2 {
        let sd = spawn(dir.path());
        let port = sd.port();
        let said = sd.daemon().lines_said();
        assert_eq!(
            said.iter().filter(|l| **l == hole).count(),
            1,
            "reopen {reopen}: the hole, said once:\n{}",
            said.join("\n")
        );
        assert!(
            said.iter().any(|l| l.starts_with(&format!("open: the change feed answers from position {first_held} to position {head}: commits.log {} entries", kept.len()))),
            "reopen {reopen}: the open answers from the first line held:\n{}",
            said.join("\n")
        );
        let owner = open_session(port, CLAIMANT_PRINCIPAL);
        for (token, label) in [(Some(owner.as_str()), "owner"), (None, "guest")] {
            for since in [0, fence - 1] {
                let (st, v) = changes(port, token, &format!("since={since}"));
                assert_eq!(
                    (st, v["error"].as_str(), v["floor"].as_u64()),
                    (410, Some("history_reclaimed"), Some(first_held)),
                    "{label} since={since}: {v}"
                );
            }
        }
        let (st, v) = changes(port, Some(&owner), &format!("since={fence}&limit=4096"));
        assert_eq!(st, 200, "{v}");
        let served: Vec<u64> = v["changes"]
            .as_array()
            .expect("changes")
            .iter()
            .map(|r| r["at"].as_u64().expect("at"))
            .collect();
        assert_eq!(served.first(), Some(&first_held), "the first line held serves: {served:?}");
        assert_eq!(served.last(), Some(&head), "and everything above, to the head: {served:?}");
        assert!(served.starts_with(&positions[2..]), "the four mints above the fence: {served:?}");
        let (first, _, _, _) = landing_feed_figures(&sd);
        assert_eq!(first, first_held, "the landing line names the first line held");
        assert!(
            log_lines(dir.path())[0] == format!("{{\"min_since\":{fence}}}"),
            "the fence kept as found"
        );
        sd.shutdown();
    }
}

/// K5 — THE MIRROR (D5 (b): a mirror may begin at any age, from the feed).
/// Over the board K1 drives — three landings, the journal reclaimed below
/// its first commits — the resolver's walk of `/changes` from 0, following
/// `last` and reading nothing else, reaches the head and reads every row
/// it read before the landings; and the resolver's own mirror
/// (`skep-resolve`, `ARCHITECTURE.md` §The resolver) opens cold at that
/// age and reaches the same head. MUTANT: K1's.
#[test]
fn k5_a_mirror_begins_from_genesis_after_the_board_reclaimed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let board = reclaimed_board(dir.path());
    // The board restarted once since its reclamation, as a board of any
    // age has been: the walk reads what an open found in the files.
    board.sd.shutdown();
    let sd = spawn(dir.path());
    let port = sd.port();
    let head = head(port);
    let mut since = 0u64;
    let mut rows: Vec<Value> = Vec::new();
    let mut pages_read = 0;
    loop {
        let (st, v) = changes(port, None, &format!("since={since}&limit=256"));
        assert_eq!(st, 200, "the mirror's walk from {since}: {v}");
        rows.extend(v["changes"].as_array().expect("changes").iter().cloned());
        pages_read += 1;
        let last = v["last"].as_u64().expect("last");
        if !v["more"].as_bool().expect("more") || last == since {
            break;
        }
        since = last;
    }
    assert!(
        pages_read >= 1 && rows.last().and_then(|r| r["at"].as_u64()) == Some(head),
        "the walk reaches the head {head}: {} rows over {pages_read} pages",
        rows.len()
    );
    let through: Vec<String> = rows
        .iter()
        .filter(|r| r["at"].as_u64().expect("at") <= board.head_before)
        .map(Value::to_string)
        .collect();
    assert_eq!(
        through, board.guest_rows,
        "the rows through the head before the landings, as read then"
    );
    let mdir = tempfile::tempdir().expect("tempdir");
    let mirror = Mirror::open(&hint_for(port), mdir.path(), &skep_resolve::dial_http)
        .unwrap_or_else(|e| panic!("a cold mirror at any age: {e}"));
    assert_eq!(mirror.head(), head, "the resolver's mirror reaches the head");
    assert_eq!(mirror.stats().rows, rows.len() as u64, "over the rows the walk read");
    sd.shutdown();
}

/// K6 — THE D8 SET UNCHANGED, AT SIZE: a lost index on a board of three
/// thousand positions, its tail of `BARED` lines bare, is sorted behind the
/// listener and landed — every bare position classified from the journal,
/// the recorded ones re-derived from their lines, the owner's rows and the
/// guest's the sets they were — and nothing compacts after it:
/// `commits.log` holds the lines it held, no fence written. (`feed_walk.rs`
/// holds the set's own cases, F1–F10, as landed.)
#[test]
fn k6_a_lost_index_on_a_three_thousand_position_board_is_sorted_and_nothing_compacts() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (head, owner_ats, guest_ats) = {
        let sd = spawn(dir.path());
        let port = sd.port();
        let owner = open_session(port, CLAIMANT_PRINCIPAL);
        let seed_lines = log_lines(dir.path()).len();
        let mut head = 0;
        while log_lines(dir.path()).len() < seed_lines + 3_000 {
            for _ in 0..100 {
                head = mint(port, &owner);
            }
        }
        let ats = |token: Option<&str>| -> Vec<u64> {
            rows_through(port, token, head)
                .iter()
                .map(|r| json(r.as_bytes())["at"].as_u64().expect("at"))
                .collect()
        };
        let (owner_ats, guest_ats) = (ats(Some(&owner)), ats(None));
        sd.shutdown();
        (head, owner_ats, guest_ats)
    };
    // The tail's lines bared, as a walk's landing writes them — the sort
    // classifies each from the journal at about a fifth of a second a
    // position, so the set is the last `BARED` lines, not the board — and
    // the index lost: the recorded lines re-derive their records at the
    // open, the bared ones pend for the sort.
    let lines = log_lines(dir.path());
    let bare: Vec<String> = lines
        .iter()
        .enumerate()
        .map(|(i, line)| match json(line.as_bytes())["at"].as_u64() {
            Some(at) if i + BARED >= lines.len() => format!("{{\"at\":{at}}}"),
            _ => line.clone(),
        })
        .collect();
    assert!(head >= 3_000, "three thousand positions: {head}");
    std::fs::write(dir.path().join("commits.log"), format!("{}\n", bare.join("\n")))
        .expect("the bare log");
    std::fs::remove_file(dir.path().join("feed-index.log")).expect("lose the index");
    let lines_before = bare.len();

    let sd = crate::feed_walk::spawn_holding_the_walk(dir.path());
    let set = sd.daemon().feed_pending_set();
    assert_eq!(set.len(), BARED, "every bare position pends for the sort: {}", set.len());
    let started = Instant::now();
    Daemon::release_the_feed_walk();
    wait_until("the sort's landing", Duration::from_secs(600), || !sd.daemon().feed_walk_pending());
    println!("K6: {} bare positions sorted and landed in {:?}", set.len(), started.elapsed());
    assert!(sd.daemon().feed_pending_set().is_empty());
    assert_eq!(log_lines(dir.path()).len(), lines_before, "nothing compacts after the sort");
    assert!(!log_lines(dir.path()).iter().any(|l| l.contains("min_since")), "no fence");
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let ats = |token: Option<&str>| -> Vec<u64> {
        rows_through(port, token, head)
            .iter()
            .map(|r| json(r.as_bytes())["at"].as_u64().expect("at"))
            .collect()
    };
    assert_eq!(ats(Some(&owner)), owner_ats, "the owner's positions, classified from the journal");
    assert_eq!(ats(None), guest_ats, "the guest's: the drafts masked as before");
    let (first, _, resident, most) = landing_feed_figures(&sd);
    assert_eq!(first, 1);
    assert!(
        resident <= skep_core::limits::FEED_RESIDENT_WINDOW && most >= resident,
        "{resident} resident, {most} at most"
    );
    sd.shutdown();
}
