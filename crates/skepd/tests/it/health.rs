//! THE DAEMON CONDITIONS on `/health` (the link-sets design §5.7, W8 (5);
//! lane S4): a system producer's refused publish — the head writer's, the
//! time writer's, the registry seed's, in-process writes with no person and
//! no face — is a condition echoed on `/health` as the write halt is, in the
//! `conditions` member: one object per producer whose last shot was
//! refused, naming the producer, the act the refusal met, the refusal's
//! code and detail as the wire spells them, the position the shot was to
//! stand above and the attempts refused since the producer last landed;
//! EMPTY on a healthy board; CLEARED by that producer's next landed shot —
//! the head's with its `landing:` line, the time writer's at its next
//! record, the seed's at its next open. The standing line carries the same
//! fact as its clause, read off the same memo, so the operator stream and
//! the wire say one thing; `writes.halted` stands beside it, a refusal
//! being no halt.
//!
//! Each producer is refused at the daemon's one driver seam
//! (`refuse_the_next_head_once`, which refuses the next commit through the
//! head writer's door whichever producer makes it, and the seed's own
//! `refuse_the_seeds_commit_once`), so the refusal rides each producer's
//! whole path, as the head suite drives it.

use std::time::{Duration, Instant};

use serde_json::Value;
use skep_core::commits::refuse_the_seeds_commit_once;
use skepd::Skepd;

use crate::common;
use common::{acked_at, get, json, op, open_session, spawn, spawn_unclaimed, CLAIMANT_ACCOUNT, CLAIMANT_PRINCIPAL};

/// A well past-the-hour clock jump, as the head suite drives trigger (c).
const WELL_PAST_THE_HOUR_MILLIS: u64 = 10_000_000;

/// Half an hour, and an hour and a minute: the two readings that make the
/// time writer's hour due while the head's is not.
const HALF_AN_HOUR_MILLIS: u64 = 1_800_000;
const AN_HOUR_AND_A_MINUTE_MILLIS: u64 = 3_660_000;

/// The head writer's count bound: commits since the last head.
const COUNT_BOUND: u64 = 64;

/// `/health`'s `conditions` member, whole.
fn conditions(port: u16) -> Vec<Value> {
    let (st, body) = get(port, "/health");
    assert_eq!(st, 200, "/health: {}", String::from_utf8_lossy(&body));
    json(&body)["conditions"].as_array().expect("the conditions array").clone()
}

/// `/health`'s `writes.halted`.
fn writes_halted(port: u16) -> bool {
    json(&get(port, "/health").1)["writes"]["halted"].as_bool().expect("writes.halted")
}

/// The `standing:` lines the daemon has said, oldest first.
fn standing_lines(sd: &Skepd) -> Vec<String> {
    sd.daemon().lines_said().into_iter().filter(|l| l.starts_with("standing: ")).collect()
}

/// One condition as the wire spells it.
fn condition(producer: &str, act: &str, code: &str, detail: &str, position: u64, attempts: u64) -> Value {
    serde_json::json!({
        "act": act,
        "attempts": attempts,
        "code": code,
        "detail": detail,
        "position": position,
        "producer": producer,
    })
}

/// One committing write as `session`: a fresh private draft, its position.
fn commit(port: u16, session: &str) -> u64 {
    acked_at(&op(port, Some(session), &format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"}}"#)))
}

/// The wall clock now, in unix milliseconds — the head writer's domain.
fn clock_origin() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("after the epoch").as_millis() as u64
}

/// Poll until `done`, within the suite's deadline.
fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// THE HEAD WRITER's CONDITION: a head due by the hour and refused at its
/// insert is one object on `/health` — the producer `head`, the act, the
/// seam's `durability` with its detail, the position the head would have
/// named, one attempt — a second refusal of the same cause, unsaid on the
/// stream, counts two attempts at the later position; `writes.halted` stays
/// false; the standing line's clause says the same fact beside the
/// board's `CLAIMED-PERMISSIVE`; and the head that next lands clears the
/// condition at the same place its `landing:` line is said, the next tick's
/// line carrying the permissive clause alone.
#[test]
fn a_refused_head_is_a_condition_until_a_head_lands_and_the_standing_line_says_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    sd.daemon().set_standing_interval_millis(40);
    assert_eq!(conditions(port), Vec::<Value>::new(), "a healthy board: no condition");

    let clock = clock_origin() + WELL_PAST_THE_HOUR_MILLIS;
    sd.daemon().set_head_writer_clock_millis(clock);
    sd.daemon().refuse_the_next_head_once();
    let p1 = commit(port, &owner);
    assert_eq!(
        conditions(port),
        vec![condition("head", "insert", "durability", "the test seam's refusal", p1, 1)],
        "the refused head, as the wire spells it"
    );
    assert!(!writes_halted(port), "a refusal is no halt");
    // The same cause again: not re-said, counted, at the later position.
    sd.daemon().refuse_the_next_head_once();
    let p2 = commit(port, &owner);
    assert_eq!(
        conditions(port),
        vec![condition("head", "insert", "durability", "the test seam's refusal", p2, 2)],
        "two attempts, the later position"
    );
    let clause = format!(
        "the head producer's last shot was refused at its insert (durability: the test seam's \
         refusal) at position {p2}, 2 attempts refused since its last landing"
    );
    wait_until("the standing line's clause", || standing_lines(&sd).iter().any(|l| l.contains(&clause)));
    let said = standing_lines(&sd);
    assert_eq!(
        said.last().map(String::as_str),
        Some(format!("standing: {clause}; CLAIMED-PERMISSIVE").as_str()),
        "the clause beside the board's own, the two reading one memo: {said:?}"
    );
    // The landing clears it: the head lands at the next commit's turn.
    let p3 = commit(port, &owner);
    assert!(
        sd.daemon().lines_said().iter().any(|l| l.starts_with("landing: head writer: a head landed at position") && l.contains(&format!("{p3}"))),
        "the clearing line"
    );
    assert_eq!(conditions(port), Vec::<Value>::new(), "cleared at the landing");
    wait_until("a tick after the clearing", || standing_lines(&sd).last().map(String::as_str) == Some("standing: CLAIMED-PERMISSIVE"));
    sd.shutdown();
}

/// THE TIME WRITER's CONDITION: with the head landed half an hour after
/// the time writer's record (the count bound brings it), the next hour
/// finds the time writer due and the head not; the seam refuses the time
/// record's insert — the producer `time`, its act, the cause, the position
/// the record would have named, one attempt — the head writer unrefused
/// beside it; and the next commit's retry lands the record and clears it.
#[test]
fn a_refused_time_record_is_a_condition_until_a_record_lands() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    // The first hour: a head and the time writer's first record land.
    let mut clock = clock_origin() + WELL_PAST_THE_HOUR_MILLIS;
    sd.daemon().set_head_writer_clock_millis(clock);
    commit(port, &owner);
    assert_eq!(conditions(port), Vec::<Value>::new());
    // Half an hour on, the count bound lands a head; the time writer's
    // record is half an hour old.
    clock += HALF_AN_HOUR_MILLIS;
    sd.daemon().set_head_writer_clock_millis(clock);
    for _ in 0..COUNT_BOUND {
        commit(port, &owner);
    }
    // An hour and a minute past the record: the time writer is due, the
    // head — half an hour old, its count fresh — is not.
    clock += AN_HOUR_AND_A_MINUTE_MILLIS - HALF_AN_HOUR_MILLIS;
    sd.daemon().set_head_writer_clock_millis(clock);
    sd.daemon().refuse_the_next_head_once();
    let p = commit(port, &owner);
    assert_eq!(
        conditions(port),
        vec![condition("time", "insert", "durability", "the test seam's refusal", p, 1)],
        "the time writer refused, the head writer not: {:?}",
        sd.daemon().lines_said()
    );
    assert!(
        sd.daemon().lines_said().iter().any(|l| l == &format!("failure: time writer: the time record at position {p} was refused at its insert (durability: the test seam's refusal); no record written this cycle")),
        "the time writer's own line: {:?}",
        sd.daemon().lines_said()
    );
    // The retry at the next commit lands the record and clears the memo.
    commit(port, &owner);
    assert_eq!(conditions(port), Vec::<Value>::new(), "the record landed: cleared");
    sd.shutdown();
}

/// THE REGISTRY SEED's CONDITION: a seed cut short at the open — its fifth
/// commit, a row's `make_link`, refused at the seam — is one object on
/// `/health` for the uptime: the producer `registry`, the act, the cause,
/// the kernel's head at the refusal, one attempt; the standing line's one
/// clause says the same on the unclaimed board; and the next open, which
/// seeds the rest, starts clear.
#[test]
fn a_seed_cut_short_at_the_open_is_a_condition_for_the_uptime_and_the_next_open_starts_clear() {
    let dir = tempfile::tempdir().expect("tempdir");
    refuse_the_seeds_commit_once(dir.path(), 5);
    {
        let sd = spawn_unclaimed(dir.path());
        let port = sd.port();
        sd.daemon().set_standing_interval_millis(40);
        let position = json(&get(port, "/health").1)["log_position"].as_u64().expect("log_position");
        assert_eq!(
            conditions(port),
            vec![condition("registry", "make_link", "durability", "the test seam's refusal", position, 1)],
            "the seed cut short at its third link"
        );
        assert!(!writes_halted(port));
        let clause = format!(
            "the registry producer's last shot was refused at its make_link (durability: the test \
             seam's refusal) at position {position}, 1 attempts refused since its last landing"
        );
        wait_until("the standing line", || !standing_lines(&sd).is_empty());
        assert_eq!(standing_lines(&sd)[0], format!("standing: {clause}"), "the one clause on the unclaimed board");
        sd.shutdown();
    }
    let sd = spawn_unclaimed(dir.path());
    assert_eq!(conditions(sd.port()), Vec::<Value>::new(), "the next open seeds the rest and starts clear");
    sd.shutdown();
}
