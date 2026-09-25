//! The PUBLISHED HEAD, against a served DURABLE daemon (PUB-6.65, RES-304;
//! QUEUE item 10 piece 2). Every daemon here is `common::spawn`'s — `Fsync`
//! durability (there is no in-memory daemon), so the head document `H` =
//! `1.1.0.1.0.2` is journalled and survives restart, which the tail-cut and
//! re-chain checks below rest on.
//!
//! The cadence's clock and its checkpoint are driven through the daemon's test
//! seams (`set_head_writer_clock_millis`, `checkpoint_now`) — never a `sleep`.
//! The clock seam's readings are wall-clock unix milliseconds (the writer's
//! domain, since its resume takes the hour's origin from the feed's recorded
//! times — the chain's open items, item 2), so every reading here is set
//! relative to [`clock_origin`]; the hour-survives-a-restart test moves the
//! RECORD, not the clock.
//!
//! THE FIRST HEAD IS THE CLAIM'S (signed ops, s1; RULED 2026-09-25): `spawn`
//! returns a board whose `H.1` the claim's own step wrote, naming the claim's
//! position, so the first head a test FORCES here is `H.2`, every `prev`
//! chain starts at the claim's head, and the cadence's counters start from it;
//! the positions the determinism pins name include `H.1`'s eight records. The
//! claim's own rule — one head, at the claim, the cadence counting from it, and
//! none on the unclaimed board — has its own cells under (vi).

use crate::common;

use std::path::Path;

use common::{
    acked_at, assert_withheld, ceremony_before_the_claim, claim_frame, claimed, device_key,
    doc_metadata, expect_resp, get, json, op, open_session, open_signed_session, spawn,
    spawn_seeded, spawn_unclaimed, CLAIMANT_ACCOUNT, CLAIMANT_DOC1, CLAIMANT_PRINCIPAL,
};
use serde_json::Value;
use skep_namespace::SYSTEM_PRINCIPAL;
use skepd::Skepd;

/// The head document `H` — doc 2 of the system account (PUB-6.65).
const H: &str = "1.1.0.1.0.2";

/// The staging draft — doc 3 of the system account, the one document the
/// head writer mints (PUB-6.65), private at every class.
const STAGING_DRAFT: &str = "1.1.0.1.0.3";

/// The head record's `format` member — the journal stamp in force, `SKJ4`
/// since the chain's salt. The one head member that moved at the bump.
const FORMAT: &str = "SKJ4";

/// The k-th head — the k-th version member of `H`'s trunk chain, `H·k`.
fn head_member(k: u64) -> String {
    format!("{H}.{k}")
}

/// A well past-the-hour clock jump, so a commit after it drives the head's
/// time bound (trigger (c)); the real bound is one hour and this is many.
const WELL_PAST_THE_HOUR_MILLIS: u64 = 10_000_000;

/// One committing write as `session`: a fresh private draft under `account`
/// (ω-gated, not published, so a bare claimed-permissive session commits it).
/// Returns the committed position.
fn commit(port: u16, session: &str, account: &str) -> u64 {
    let v = op(
        port,
        Some(session),
        &format!(r#"{{"op":"create_new_document","account":"{account}"}}"#),
    );
    acked_at(&v)
}

/// The `/health` pair — `(log_position, chain_head)`.
fn health(port: u16) -> (u64, String) {
    let (st, body) = get(port, "/health");
    assert_eq!(st, 200, "/health");
    let v = json(&body);
    (
        v["log_position"].as_u64().expect("log_position"),
        v["chain_head"].as_str().expect("chain_head").to_string(),
    )
}

/// The raw head-record ATOM STRING at content position 1 of `doc` (the bare
/// `H` floats to the latest head; a version member `H·k` answers itself), read
/// as the GUEST (no token — `H` and its members are published), or `None` when
/// there is no member/atom there. The RAW string, so a byte-equality check
/// compares what the board stored, not a reparse.
fn atom_str(port: u16, doc: &str) -> Option<String> {
    let v = op(
        port,
        None,
        &format!(r#"{{"op":"retrieve_v","specs":[{{"doc":"{doc}","span":{{"start":"1.1","width":"0.1"}}}}]}}"#),
    );
    let items = v.get("items")?.as_array()?;
    items
        .iter()
        .find_map(|it| it.get("atom").and_then(Value::as_str))
        .map(str::to_string)
}

/// The parsed head record at `doc`, or `None` when absent.
fn head_record(port: u16, doc: &str) -> Option<Value> {
    atom_str(port, doc).and_then(|s| serde_json::from_str(&s).ok())
}

/// The latest head (bare `H`), asserting it is present and well-formed:
/// `type: "skep-head"`, `position` a number, `chain` 64 lowercase hex, no
/// `sig`.
fn expect_latest_head(port: u16) -> Value {
    let rec = head_record(port, H).expect("H has a head member");
    assert_eq!(rec["type"].as_str(), Some("skep-head"), "kind: {rec}");
    assert_eq!(rec["format"].as_str(), Some(FORMAT), "the stamp in force: {rec}");
    assert!(rec.get("sig").is_none(), "the head is UNSIGNED: {rec}");
    assert!(rec["position"].is_u64(), "position is a number: {rec}");
    let chain = rec["chain"].as_str().expect("chain string");
    assert_eq!(chain.len(), 64, "chain is 64 hex: {chain}");
    assert!(
        chain.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
        "chain is lowercase hex: {chain}"
    );
    rec
}

/// Force ONE head via the time bound: jump the clock past the hour, then
/// commit — that commit's turn (`take_turn`) finds the position moved and the
/// hour elapsed, and writes the head naming the committed pair. Returns the
/// head's `position` (the committed op's own position, which the head names).
fn force_head(sd: &Skepd, session: &str, account: &str, clock: &mut u64) -> u64 {
    *clock += WELL_PAST_THE_HOUR_MILLIS;
    sd.daemon().set_head_writer_clock_millis(*clock);
    commit(sd.port(), session, account)
}

/// A test clock's origin: the wall clock now, in unix milliseconds — the
/// writer's own domain, whose hour is resumed from the feed's recorded times
/// (wall-clock) or from open-time (wall-clock) — so readings set through the
/// seam are relative to now rather than small numbers a resumed origin would
/// dwarf into "not yet an hour".
fn clock_origin() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after the epoch")
        .as_millis() as u64
}

/// Two hours, in the sidecar's own milliseconds.
const TWO_HOURS_MILLIS: u64 = 2 * 60 * 60 * 1000;

/// One hour, restated from PUB-6.65's time bound ("one hour has passed since
/// the last head") rather than read off the writer's private constant.
const HOUR_MILLIS: u64 = 60 * 60 * 1000;

/// Rewrite every recorded `time` at a position AT OR BELOW `through` `age`
/// milliseconds into the past — the feed's testimony (AUTH-4.56: a
/// rewritable sidecar), which the head writer's resume reads its hour's
/// origin from. Every time at or below `through` moves alike and every time
/// above it stays, so the file stays monotone; the digit count is kept, so
/// every line keeps its length and the derived offset array stays true.
fn age_sidecar(dir: &Path, age: u64, through: u64) {
    let path = dir.join("commits.log");
    let text = std::fs::read_to_string(&path).expect("commits.log");
    let mut out = String::with_capacity(text.len());
    let (mut aged, mut kept) = (0, 0);
    for line in text.lines() {
        let mut line = line.to_string();
        // An entry line is `{"at":N,…}` — the codec sorts `at` first.
        let at: Option<u64> = line
            .strip_prefix("{\"at\":")
            .map(|rest| rest.chars().take_while(|c| c.is_ascii_digit()).collect::<String>())
            .and_then(|digits| digits.parse().ok());
        if let (Some(start), Some(at)) = (line.find("\"time\":"), at) {
            if at > through {
                kept += 1;
            } else {
                let digits = start + "\"time\":".len();
                let end = line[digits..]
                    .find(|c: char| !c.is_ascii_digit())
                    .map_or(line.len(), |i| digits + i);
                let time: u64 = line[digits..end].parse().expect("a recorded time");
                let older = (time - age).to_string();
                assert_eq!(older.len(), end - digits, "the rewrite keeps every line's length");
                line.replace_range(digits..end, &older);
                aged += 1;
            }
        }
        out.push_str(&line);
        out.push('\n');
    }
    assert!(aged > 0, "the sidecar recorded the head's own commits");
    assert!(kept > 0, "a commit above `through` keeps its time — the origin the resume must NOT read");
    std::fs::write(&path, out).expect("rewrite commits.log");
}

fn copy_dir(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).expect("create dst");
    for entry in std::fs::read_dir(src).expect("read src") {
        let entry = entry.expect("dir entry");
        let to = dst.join(entry.file_name());
        if entry.file_type().expect("file type").is_dir() {
            copy_dir(&entry.path(), &to);
        } else {
            std::fs::copy(entry.path(), &to).expect("copy file");
        }
    }
}

fn wipe_dir(dir: &Path) {
    for entry in std::fs::read_dir(dir).expect("read dir") {
        let entry = entry.expect("dir entry");
        if entry.file_type().expect("file type").is_dir() {
            std::fs::remove_dir_all(entry.path()).expect("rm dir");
        } else {
            std::fs::remove_file(entry.path()).expect("rm file");
        }
    }
}

// ── (i) THE CADENCE ────────────────────────────────────────────────────────

/// (i)(a) — after 64 non-head commits since the last head, a head is written
/// naming the pair as of the 64th commit (its own committed position). Durable
/// daemon.
#[test]
fn the_count_trigger_writes_a_head_at_the_64th_non_head_commit() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let mut clock = clock_origin();

    // A head off the time bound (`H.2` — `H.1` is the claim's) gives a known
    // reset point: the count trigger is then exactly 64 commits from here.
    force_head(&sd, &owner, CLAIMANT_ACCOUNT, &mut clock);
    let head1 = head_record(port, H).expect("a first head").clone();
    let p1 = head1["position"].as_u64().unwrap();

    // Exactly 64 non-head commits, the clock frozen (so trigger (c) cannot
    // fire) and no checkpoint (well inside the 1024 window, so (b) cannot):
    // only the count trigger can write the head, and only on the 64th.
    let mut last_at = 0;
    for i in 1..=64u64 {
        last_at = commit(port, &owner, CLAIMANT_ACCOUNT);
        if i < 64 {
            let rec = head_record(port, H).expect("the first head still stands");
            assert_eq!(
                rec["position"].as_u64().unwrap(),
                p1,
                "no new head before the 64th commit (at commit {i})"
            );
        }
    }
    let rec = expect_latest_head(port);
    assert_eq!(
        rec["position"].as_u64().unwrap(),
        last_at,
        "the count trigger's head names the pair as of the 64th commit"
    );
    sd.shutdown();
}

/// (i) — a checkpoint moves the head, and ONCE: with the checkpoint seq moved
/// since the last head, the next commit writes one (trigger (b)) naming it as
/// its `base`, and the commits after it write none — the head attested it.
/// And a quiet board (no count, no checkpoint, no clock) writes none.
#[test]
fn a_checkpoint_moves_the_head_once_and_a_quiet_board_writes_none() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let mut clock = clock_origin();

    force_head(&sd, &owner, CLAIMANT_ACCOUNT, &mut clock);
    let head1 = head_record(port, H).expect("a head").clone();
    let p1 = head1["position"].as_u64().unwrap();

    // QUIET: a handful of commits, no checkpoint, clock frozen — no new head.
    for _ in 0..5 {
        commit(port, &owner, CLAIMANT_ACCOUNT);
        assert_eq!(
            head_record(port, H).unwrap()["position"].as_u64().unwrap(),
            p1,
            "a quiet board (no count, no checkpoint, no clock) writes no head"
        );
    }

    // A CHECKPOINT: now the next commit's turn (`take_turn`) sees the
    // checkpoint seq moved since the last head and writes one.
    sd.daemon().checkpoint_now();
    let at = commit(port, &owner, CLAIMANT_ACCOUNT);
    let rec = expect_latest_head(port);
    assert!(
        rec["position"].as_u64().unwrap() > p1,
        "the checkpoint trigger wrote a newer head"
    );
    assert_eq!(rec["position"].as_u64().unwrap(), at, "naming the pair as of that commit");
    // Its `base` names the checkpoint that moved (seq ≤ position).
    let base = &rec["base"];
    assert!(base.is_object(), "a head after a checkpoint names a base: {rec}");
    assert!(
        base["seq"].as_u64().unwrap() <= rec["position"].as_u64().unwrap(),
        "base.seq is at or below the head's position: {rec}"
    );
    // …named by the checkpoint's OWN chain — the kernel's recomputation at
    // that seq — and not by the body hash beside it: both are 64 hex, so a
    // transposed pair passes every shape check above.
    let base_seq = base["seq"].as_u64().unwrap();
    assert_eq!(
        base["chain"].as_str().map(str::to_string),
        chain_at(port, base_seq),
        "base.chain is the chain AT base.seq: {rec}"
    );
    assert_ne!(base["chain"], base["body_hash"], "and is not the body hash: {rec}");

    // …and it moves the head ONCE. The head just written ATTESTED that
    // checkpoint, so a quiet board after it writes none. This run, not the
    // one above, sees trigger (b)'s comparison: before any checkpoint the
    // trigger has nothing to attest whatever it compares, and a trigger that
    // asked only "is there a checkpoint?" would write a head on every commit
    // after the board's first.
    let attesting = rec["position"].as_u64().unwrap();
    for i in 1..=5 {
        commit(port, &owner, CLAIMANT_ACCOUNT);
        assert_eq!(
            head_record(port, H).unwrap()["position"].as_u64().unwrap(),
            attesting,
            "a checkpoint the last head attested moves no further head (commit {i} after it)"
        );
    }
    sd.shutdown();
}

/// (i) — the time bound writes one at the next commit and never a duplicate: a
/// second commit with the clock unchanged and the position moved writes no
/// second head for it.
#[test]
fn the_time_bound_writes_one_and_never_a_duplicate() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let mut clock = clock_origin();

    let p1 = force_head(&sd, &owner, CLAIMANT_ACCOUNT, &mut clock);
    let head1 = expect_latest_head(port);
    assert_eq!(head1["position"].as_u64().unwrap(), p1);

    // Another commit, clock UNCHANGED: the hour has not passed since the last
    // head, so no head — never a duplicate for a moved position.
    commit(port, &owner, CLAIMANT_ACCOUNT);
    assert_eq!(
        head_record(port, H).unwrap()["position"].as_u64().unwrap(),
        p1,
        "no head while under the hour, even though the position moved"
    );

    // Advance the clock again: the next commit writes the next head.
    let p2 = force_head(&sd, &owner, CLAIMANT_ACCOUNT, &mut clock);
    assert!(p2 > p1, "the second head's position advanced");
    assert_eq!(expect_latest_head(port)["position"].as_u64().unwrap(), p2);
    sd.shutdown();
}

/// (i) — THE TIME BOUND IS ONE HOUR, TO THE MILLISECOND (PUB-6.65; the bound
/// is `>=`): a landed commit a millisecond short of an hour past the last
/// head's reading writes no head, and one at the hour exactly does. Both
/// readings are exact because the last head took its time from the seam.
/// Every other time-bound test jumps ten million milliseconds, which pins
/// the bound only to somewhere under 2.8 hours: a bound of one minute, of
/// two hours, or `>` for `>=`, passes all of them.
#[test]
fn the_time_bound_is_one_hour_to_the_millisecond() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let mut clock = clock_origin();
    // The head takes `clock` — the seam's reading — as its own time.
    let p = force_head(&sd, &owner, CLAIMANT_ACCOUNT, &mut clock);

    sd.daemon().set_head_writer_clock_millis(clock + HOUR_MILLIS - 1);
    commit(port, &owner, CLAIMANT_ACCOUNT);
    assert_eq!(
        head_record(port, H).unwrap()["position"].as_u64(),
        Some(p),
        "a millisecond short of the hour: no head"
    );
    sd.daemon().set_head_writer_clock_millis(clock + HOUR_MILLIS);
    let at = commit(port, &owner, CLAIMANT_ACCOUNT);
    assert_eq!(
        expect_latest_head(port)["position"].as_u64(),
        Some(at),
        "at the hour exactly: the head"
    );
    sd.shutdown();
}

/// (i) — A CLOCK THAT STEPS BACK IS TOLERATED (the writer's `Clock`: "a wall
/// clock that steps is tolerated by the trigger's `saturating_sub` … never a
/// duplicate"): with the reading an hour BEHIND the last head's, a landed
/// commit acks as ever and writes no head — the time since the last head is
/// zero, not an underflow — and the step leaves the writer as it was: once
/// the reading is past the hour again, the time bound fires. A subtraction
/// that did not saturate panics under the gate's overflow checks in the turn
/// AFTER the triggering write committed, answering that write
/// `500 internal_panic`; wrapping instead, it writes a head on the step.
#[test]
fn a_clock_that_steps_back_writes_no_head_and_costs_the_write_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let mut clock = clock_origin();
    let p = force_head(&sd, &owner, CLAIMANT_ACCOUNT, &mut clock);

    sd.daemon().set_head_writer_clock_millis(clock - HOUR_MILLIS);
    commit(port, &owner, CLAIMANT_ACCOUNT); // `commit` asserts the 200 and the ack
    assert_eq!(
        head_record(port, H).unwrap()["position"].as_u64(),
        Some(p),
        "a clock behind the last head's reading brings no head"
    );
    // WELL past the hour, so this cell reads what the step left behind and
    // not the bound's exact value, which the test above pins.
    sd.daemon().set_head_writer_clock_millis(clock + WELL_PAST_THE_HOUR_MILLIS);
    let at = commit(port, &owner, CLAIMANT_ACCOUNT);
    assert_eq!(
        expect_latest_head(port)["position"].as_u64(),
        Some(at),
        "the step left the writer as it was: past the hour, the head"
    );
    sd.shutdown();
}

/// (i) — the clock seam is the HEAD WRITER's reading alone: a reading set hours
/// past the wall clock drives the published head's time bound, while every
/// commit's `time` — and so `/health`'s `head_time` — stays the change feed's
/// own reading of the wall clock. The head's own publish is the last recorded
/// commit here, so a seam that stamped commits would put `head_time` at or
/// past the reading.
#[test]
fn the_head_writer_clock_seam_moves_no_commit_time() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let mut clock = clock_origin();

    let p = force_head(&sd, &owner, CLAIMANT_ACCOUNT, &mut clock);
    assert_eq!(
        expect_latest_head(port)["position"].as_u64().unwrap(),
        p,
        "the seam's reading drove the head's time bound"
    );
    let (st, body) = get(port, "/health");
    assert_eq!(st, 200, "/health");
    let head_time =
        json(&body)["head_time"].as_u64().expect("the head's own commit recorded a time");
    assert!(
        head_time < clock,
        "head_time {head_time} is the wall clock's reading, not the seam's {clock}"
    );
    sd.shutdown();
}

/// (i) — an ack that LANDED nothing is not a commit. An idempotent replay (the
/// same frame and `id` on the same session) is answered from M10's memo and
/// rides `commit_under` like a commit, but the kernel's position does not
/// move: 64 of them count nothing toward the cadence and write no head, and
/// the count trigger still fires on the 64th commit that DID land.
#[test]
fn an_idempotent_replay_lands_nothing_and_counts_nothing_toward_a_head() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let mut clock = clock_origin();
    let p1 = force_head(&sd, &owner, CLAIMANT_ACCOUNT, &mut clock);

    // One landed commit under an idempotency id…
    let frame = format!(
        r#"{{"op":"create_new_document","id":"head-replay","account":"{CLAIMANT_ACCOUNT}"}}"#
    );
    let original = op(port, Some(&owner), &frame);
    let at = acked_at(&original);
    let (position, _) = health(port);
    // …replayed 64 times: the original ack each time, the position unmoved.
    for i in 1..=64 {
        let replay = op(port, Some(&owner), &frame);
        assert_eq!(replay, original, "replay {i} answers the original ack");
        assert_eq!(health(port).0, position, "replay {i} landed nothing");
    }
    assert_eq!(
        head_record(port, H).unwrap()["position"].as_u64().unwrap(),
        p1,
        "64 replays are not 64 commits: no head"
    );

    // The one landed commit counted once, so 63 more reach the 64th — and
    // only the 64th writes the head.
    let mut last_at = at;
    for i in 1..=63u64 {
        last_at = commit(port, &owner, CLAIMANT_ACCOUNT);
        if i < 63 {
            assert_eq!(
                head_record(port, H).unwrap()["position"].as_u64().unwrap(),
                p1,
                "no head before the 64th LANDED commit (at landed commit {})",
                i + 1
            );
        }
    }
    assert_eq!(
        expect_latest_head(port)["position"].as_u64().unwrap(),
        last_at,
        "the count trigger fires on the 64th landed commit"
    );
    sd.shutdown();
}

/// (i) — THE HEAD'S OWN COMMITS NEVER BRING THE NEXT HEAD. They move the
/// position past the one the head named, but only a commit that is not the
/// writer's own makes the next head due. Pinned at the one cell that tells
/// the two apart: the first write after a head LANDS NOTHING (an insert M10
/// refuses) and the hour has passed — no head. What keeps the head's own
/// commits from reading as that write's landing is the writer's look at the
/// kernel's seq after them; without it this refusal would write a head
/// naming the last head's own publish. The replay test cannot see this: a
/// landed commit stands between its head and its replays.
#[test]
fn the_heads_own_commits_never_bring_the_next_head() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let mut clock = clock_origin();
    let p = force_head(&sd, &owner, CLAIMANT_ACCOUNT, &mut clock);
    let (after_head, _) = health(port);
    assert!(after_head > p, "the head's own commits landed above the position it names");

    // The hour passes, and the first write after the head lands nothing.
    clock += WELL_PAST_THE_HOUR_MILLIS;
    sd.daemon().set_head_writer_clock_millis(clock);
    let never = format!("{CLAIMANT_ACCOUNT}.0.99");
    let refused = op(
        port,
        Some(&owner),
        &format!(
            r#"{{"op":"insert","doc":"{never}","at":{{"subspace":"1","ordinal":"1"}},"values":["x"]}}"#
        ),
    );
    // M10's own refusal, so the frame passed every daemon gate and rode the
    // session door — which gives the head writer its turn — before M10
    // refused it.
    assert_eq!(
        expect_resp(&refused, "rejected")["code"].as_str(),
        Some("doc_not_registered"),
        "M10 refuses it, inside the door: {refused}"
    );
    assert_eq!(
        head_record(port, H).unwrap()["position"].as_u64(),
        Some(p),
        "no head: nothing but the head writer's own commits landed since the last head"
    );
    // Read AFTER the head, not before it: a head written here would move the
    // log by its own commits, and the cause would be misnamed as the refusal.
    assert_eq!(
        health(port).0,
        after_head,
        "and the log stands where the head's own commits left it: the refusal landed nothing"
    );
    sd.shutdown();
}

/// RESUME — trigger (b)'s reference is read off the head itself (its `base`),
/// so it survives a restart: a checkpoint taken after the last head, with no
/// commit between it and the shutdown, is attested by the FIRST commit after
/// the reopen — a head whose `base` names that checkpoint. The clock is left
/// alone and the count is one, so no other trigger can be what fired.
#[test]
fn a_checkpoint_taken_before_a_restart_is_attested_by_the_first_head_after_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut clock = clock_origin();

    let checkpoint_seq = {
        let sd = spawn(dir.path());
        let port = sd.port();
        let owner = open_session(port, CLAIMANT_PRINCIPAL);
        force_head(&sd, &owner, CLAIMANT_ACCOUNT, &mut clock);
        assert!(
            head_record(port, H).unwrap()["base"].is_null(),
            "no checkpoint yet: the head names base null"
        );
        let (seq, _) = health(port);
        sd.daemon().checkpoint_now(); // at `seq`: nothing committed between
        sd.shutdown();
        seq
    };

    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let at = commit(port, &owner, CLAIMANT_ACCOUNT);
    let rec = expect_latest_head(port);
    assert_eq!(
        rec["position"].as_u64().unwrap(),
        at,
        "the first commit after the reopen wrote a head: the checkpoint moved since the last head"
    );
    assert_eq!(
        rec["base"]["seq"].as_u64(),
        Some(checkpoint_seq),
        "its base names the checkpoint the last head did not: {rec}"
    );
    sd.shutdown();
}

/// RESUME — the other direction of the test above: trigger (b)'s reference is
/// the last head's `base` AS RESUMED, so a checkpoint that head already
/// attested moves no head after a restart. The first commit after the reopen
/// writes none: the newest checkpoint is the one `H`'s latest member names,
/// the count is one, and the hour is resumed from the head's own entries. A
/// reference the restart forgot would re-attest it, one head per reopen.
#[test]
fn a_checkpoint_the_last_head_attested_moves_no_head_after_a_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut clock = clock_origin();

    let attesting = {
        let sd = spawn(dir.path());
        let port = sd.port();
        let owner = open_session(port, CLAIMANT_PRINCIPAL);
        force_head(&sd, &owner, CLAIMANT_ACCOUNT, &mut clock);
        sd.daemon().checkpoint_now();
        let at = commit(port, &owner, CLAIMANT_ACCOUNT);
        let rec = expect_latest_head(port);
        assert_eq!(rec["position"].as_u64(), Some(at), "the checkpoint's own head");
        assert!(rec["base"].is_object(), "which attests it: {rec}");
        sd.shutdown();
        at
    };

    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    commit(port, &owner, CLAIMANT_ACCOUNT);
    assert_eq!(
        head_record(port, H).unwrap()["position"].as_u64(),
        Some(attesting),
        "a checkpoint the last head attested moves no head after the restart"
    );
    sd.shutdown();
}

/// RESUME — the COUNT survives a restart (the chain's open items, item 2;
/// PUB-6.65's "64 commits that are not the head writer's own have landed
/// since the last head" — of the board, not of the process): 40 commits after
/// a head, a restart, 24 more — and the 64th landed commit since that head
/// writes the next, on the second uptime, with the clock left alone and no
/// checkpoint taken, so no other trigger can be what fired. Without the
/// resume a restarted board would count from zero, and one restarted every
/// fewer than 64 commits would write heads at checkpoints alone.
#[test]
fn the_commit_count_since_the_last_head_survives_a_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut clock = clock_origin();

    let head_position = {
        let sd = spawn(dir.path());
        let port = sd.port();
        let owner = open_session(port, CLAIMANT_PRINCIPAL);
        let p = force_head(&sd, &owner, CLAIMANT_ACCOUNT, &mut clock);
        for _ in 0..40 {
            commit(port, &owner, CLAIMANT_ACCOUNT);
        }
        assert_eq!(
            head_record(port, H).unwrap()["position"].as_u64().unwrap(),
            p,
            "40 commits since the head: no head yet"
        );
        sd.shutdown();
        p
    };

    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let mut last_at = 0;
    for i in 1..=24u64 {
        last_at = commit(port, &owner, CLAIMANT_ACCOUNT);
        if i < 24 {
            assert_eq!(
                head_record(port, H).unwrap()["position"].as_u64().unwrap(),
                head_position,
                "no head before the 64th landed commit since the last head (restart + {i})"
            );
        }
    }
    let rec = expect_latest_head(port);
    assert_eq!(
        rec["position"].as_u64().unwrap(),
        last_at,
        "the 64th commit since the last head — 40 before the restart, 24 after — wrote the head"
    );
    assert!(rec["base"].is_null(), "no checkpoint was taken: the count is what fired: {rec}");
    sd.shutdown();
}

/// RESUME — the HOUR survives a restart (item 2; PUB-6.65's "one hour has
/// passed since the last head"): the last head's own commits are the feed's
/// entries testifying `"system"` above the position it named, and their
/// recorded `time` is the head's, so the writer resumes the hour's origin
/// there. Pinned by moving the RECORD rather than the clock: the sidecar —
/// rewritable testimony, AUTH-4.56 — is rewritten with every `time` through
/// the head's own work two hours older and the commit after it left as
/// recorded, so only an origin read off the head's OWN entries finds the hour
/// passed; the daemon is restarted with its clock left alone, and the first
/// commit writes a head (an hour has passed since the last head AS RECORDED,
/// though not since open) while the second, under the hour since the new
/// head, writes none. Measured from open instead, the hour would leave this
/// board no time-bound head for its first hour up.
#[test]
fn the_hour_since_the_last_head_survives_a_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut clock = clock_origin();

    let (head_position, head_work_through) = {
        let sd = spawn(dir.path());
        let port = sd.port();
        let owner = open_session(port, CLAIMANT_PRINCIPAL);
        let p = force_head(&sd, &owner, CLAIMANT_ACCOUNT, &mut clock);
        // The head's own last commit — its publish — is where the request
        // that wrote it leaves the board.
        let (through, _) = health(port);
        // One more commit, so the head's own entries are not the feed's last
        // — and this one keeps its REAL time below, so an origin read off the
        // feed's last entry rather than the head's OWN "system" entries would
        // find the hour not yet passed.
        commit(port, &owner, CLAIMANT_ACCOUNT);
        assert_eq!(head_record(port, H).unwrap()["position"].as_u64().unwrap(), p);
        sd.shutdown();
        (p, through)
    };
    age_sidecar(dir.path(), TWO_HOURS_MILLIS, head_work_through);

    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let at = commit(port, &owner, CLAIMANT_ACCOUNT);
    let rec = expect_latest_head(port);
    assert_eq!(
        rec["position"].as_u64().unwrap(),
        at,
        "the first commit after the reopen wrote a head: an hour has passed since the last head \
         as the feed records it, and the writer's hour is the board's"
    );
    assert!(rec["prev"]["position"].as_u64() == Some(head_position), "its prev is the head before: {rec}");
    assert!(rec["base"].is_null(), "no checkpoint was taken, and two commits are not 64: {rec}");
    let again = commit(port, &owner, CLAIMANT_ACCOUNT);
    assert!(again > at);
    assert_eq!(
        head_record(port, H).unwrap()["position"].as_u64().unwrap(),
        at,
        "the second commit, under the hour since the new head, writes none"
    );
    sd.shutdown();
}

/// RESUME — a LOST sidecar counts what the journal shows landed (PUB-6.65:
/// "64 commits that are not the writer's own have landed since the last
/// head", of the board): `commits.log` deleted, the reopen walk re-covers
/// every retained position as a BARE entry, and a bare entry COUNTS — the
/// head's own among them, since with their `"system"` testimony gone nothing
/// tells them from the rest. So the next head comes EARLY by at most the
/// head's own commits (three at a first head: the staging draft's mint, the
/// insert, the publish; two after it) and never late: 40 commits after a head, the loss, a
/// restart, and the next head comes no sooner than the 21st commit after it
/// and no later than the 24th — never at the 64th, where a resume that
/// started the count at zero would put it, 104 commits past the last head.
/// The heads' own chain is the journal's and survives the loss: the new
/// head's `prev` is the head before it.
#[test]
fn a_lost_sidecar_counts_the_commits_the_journal_shows_landed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut clock = clock_origin();

    let head_position = {
        let sd = spawn(dir.path());
        let port = sd.port();
        let owner = open_session(port, CLAIMANT_PRINCIPAL);
        let p = force_head(&sd, &owner, CLAIMANT_ACCOUNT, &mut clock);
        for _ in 0..40 {
            commit(port, &owner, CLAIMANT_ACCOUNT);
        }
        assert_eq!(
            head_record(port, H).unwrap()["position"].as_u64().unwrap(),
            p,
            "40 commits since the head: no head yet"
        );
        sd.shutdown();
        p
    };
    // The testimony lost; the journal, and `H` in it, untouched.
    std::fs::remove_file(dir.path().join("commits.log")).expect("lose the testimony");

    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let mut next = None;
    for i in 1..=24u64 {
        let at = commit(port, &owner, CLAIMANT_ACCOUNT);
        if head_record(port, H).unwrap()["position"].as_u64() != Some(head_position) {
            next = Some((i, at));
            break;
        }
    }
    let (i, at) = next.expect("a head by the 24th commit after the loss: a bare entry counts");
    assert!(
        i >= 64 - 40 - 3,
        "early by at most the head's own three commits, never more: the head came at +{i}"
    );
    let rec = expect_latest_head(port);
    assert_eq!(rec["position"].as_u64(), Some(at), "it names the commit that brought it: {rec}");
    assert_eq!(
        rec["prev"]["position"].as_u64(),
        Some(head_position),
        "its prev is the head before: {rec}"
    );
    assert!(rec["base"].is_null(), "no checkpoint was taken: the count is what fired: {rec}");
    sd.shutdown();
}

/// The staging draft is minted ONCE — doc 3 of the system account — and found
/// again after a restart (PUB-6.65: the head reaches `H` and the system
/// account's own staging draft and NO other document; the writer resumes by
/// reading). Pinned by the journal's own arithmetic, in RECORDS as `/health`
/// counts them: the board's FIRST head — the claim's own, `H.1` (s1), which
/// mints the draft — costs exactly one document mint more than a head that
/// found it, on the same uptime and on the next, and a document mint's cost
/// is measured here on this build rather than assumed.
#[test]
fn a_restarted_writer_finds_the_staging_draft_it_minted_and_mints_no_other() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut clock = clock_origin();

    let (first_head_cost, later_head_cost, mint_cost) = {
        // The claim made by hand, so `H.1`'s own records — the draft's mint,
        // the atom's insert, the publish shot — are measured off the claim's
        // ack: everything the claim's request committed above the claim.
        let sd = spawn_unclaimed(dir.path());
        let port = sd.port();
        ceremony_before_the_claim(port);
        let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
        let claim_at = acked_at(&op(port, Some(&signed), &claim_frame(CLAIMANT_DOC1, CLAIMANT_ACCOUNT)));
        let first_head_cost = health(port).0 - claim_at;
        // One plain document mint, measured: what one `create_new_document`
        // adds to the position on this build.
        let owner = open_session(port, CLAIMANT_PRINCIPAL);
        let before = health(port).0;
        commit(port, &owner, CLAIMANT_ACCOUNT);
        let mint_cost = health(port).0 - before;
        // A later head on the SAME uptime, measured off its trigger's ack:
        // the atom's insert and the publish shot, the draft found.
        let trigger = force_head(&sd, &owner, CLAIMANT_ACCOUNT, &mut clock);
        let later_head_cost = health(port).0 - trigger;
        sd.shutdown();
        (first_head_cost, later_head_cost, mint_cost)
    };
    assert_eq!(
        later_head_cost + mint_cost,
        first_head_cost,
        "the claim's H.1 minted the draft; the next head on the same uptime reused it"
    );

    // The second uptime's head: the same, the draft found at open.
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let trigger = force_head(&sd, &owner, CLAIMANT_ACCOUNT, &mut clock);
    let second_uptime_head_cost = health(port).0 - trigger;
    assert_eq!(
        second_uptime_head_cost, later_head_cost,
        "the second uptime's head minted no draft: it reused the one the claim's head minted"
    );
    sd.shutdown();
}

/// The staging draft is minted ONCE FOR THE LIFE OF THE BOARD — the half the
/// restart test above cannot see, since it writes one head per uptime: four
/// heads in ONE uptime — the claim's `H.1` and three forced — leave exactly
/// one document under the system account beyond the seed's two.
/// `1.1.0.1.0.3` is the draft — registered and private, so the guest is
/// `withheld` — and `1.1.0.1.0.4` was never minted, so the guest is told
/// `doc_not_registered`. Named rather than measured: a writer that forgot the
/// draft it minted this uptime would mint a private document per head for as
/// long as it runs, and no guest-visible entry would name one.
#[test]
fn every_head_in_one_uptime_reuses_the_one_staging_draft() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let mut clock = clock_origin();

    for _ in 0..3 {
        force_head(&sd, &owner, CLAIMANT_ACCOUNT, &mut clock);
    }
    assert!(head_record(port, &head_member(4)).is_some(), "four heads were written: the claim's and three");
    assert_withheld(&doc_metadata(port, None, STAGING_DRAFT), STAGING_DRAFT);
    let next = doc_metadata(port, None, "1.1.0.1.0.4");
    assert_eq!(
        expect_resp(&next, "rejected")["code"].as_str(),
        Some("doc_not_registered"),
        "the heads minted no second document under the system account: {next}"
    );
    sd.shutdown();
}

// ── (ii) THE RECURSION ───────────────────────────────────────────────────────

/// (ii) — each head's position is strictly below its own commit's position;
/// consecutive positions strictly increase; the second head's `prev` is the
/// first's pair; and `chain_head()` right after a head differs from the head's
/// own `chain` (it names a coordinate before its own commits). The first head
/// is the claim's `H.1` (s1), read as `spawn` left it; the second is forced.
#[test]
fn a_head_names_a_coordinate_strictly_below_its_own_commit() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let mut clock = clock_origin();

    let head1 = expect_latest_head(port);
    assert_eq!(head1, head_record(port, &head_member(1)).expect("H.1"), "the latest head is the claim's H.1");
    let p1 = head1["position"].as_u64().unwrap();
    assert_eq!(p1, CLAIM_POSITION, "H.1 names the claim's position");
    assert!(head1["prev"].is_null(), "the first head's prev is null: {head1}");
    let chain1 = head1["chain"].as_str().unwrap().to_string();

    // The head's own commits advanced the log past the position it named,
    // and advanced the chain off the value it named.
    let (pos_after, chain_after) = health(port);
    assert!(pos_after > p1, "the head's own commits land strictly above the position it names");
    assert_ne!(chain_after, chain1, "chain_head after the head differs from the head's own chain");

    let p2 = force_head(&sd, &owner, CLAIMANT_ACCOUNT, &mut clock);
    let head2 = expect_latest_head(port);
    assert!(p2 > p1, "consecutive head positions strictly increase");
    assert_eq!(head2["position"].as_u64(), Some(p2), "the second head names its trigger");
    let prev = &head2["prev"];
    assert_eq!(prev["position"].as_u64(), Some(p1), "the second head's prev.position is the first's");
    assert_eq!(prev["chain"].as_str(), Some(chain1.as_str()), "prev.chain is the first head's chain");
    sd.shutdown();
}

// ── (iii) EXTENDS, GREEN ─────────────────────────────────────────────────────

/// (iii) — a peer saves `H.k`, more commits and heads land, it re-reads `H.k`
/// byte-equal, and walks `prev` from the latest head down to k.
#[test]
fn a_peer_re_reads_a_saved_head_byte_equal_and_walks_prev() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let mut clock = clock_origin();

    // Three forced heads after the claim's H.1: H.2, H.3, H.4.
    for _ in 0..3 {
        force_head(&sd, &owner, CLAIMANT_ACCOUNT, &mut clock);
    }
    // The peer saves H.2 — its address and its exact bytes (a guest read).
    let saved = atom_str(port, &head_member(2)).expect("H.2 exists");

    // More history: two further heads, H.5 and H.6.
    for _ in 0..2 {
        force_head(&sd, &owner, CLAIMANT_ACCOUNT, &mut clock);
    }

    // H.2 re-reads byte-equal — a version member is immutable.
    assert_eq!(atom_str(port, &head_member(2)).as_deref(), Some(saved.as_str()), "H.2 is byte-equal");

    // Walk `prev` from the latest head down to H.2, each step landing on the
    // member one lower and matching the (position, chain) its successor names.
    let latest = expect_latest_head(port); // H.6: the claim's H.1 and five forced
    assert_eq!(latest, head_record(port, &head_member(6)).expect("H.6"), "the latest head is H.6");
    let mut k = 6u64;
    let mut cur = latest;
    while k > 2 {
        let prev = cur["prev"].clone();
        let lower = head_record(port, &head_member(k - 1)).expect("the member below exists");
        assert_eq!(prev["position"].as_u64(), lower["position"].as_u64(), "prev.position walks to H.{}", k - 1);
        assert_eq!(prev["chain"].as_str(), lower["chain"].as_str(), "prev.chain walks to H.{}", k - 1);
        cur = lower;
        k -= 1;
    }
    sd.shutdown();
}

/// (iii′) — EVERY HEAD'S OWN PAIR IS WHAT THE BOARD RECOMPUTES (wire.md §The
/// other endpoints: "a saved pair — a head's own `(position, chain)` … — is
/// checked against the board's RECOMPUTATION at `GET /chain?at=<position>`"):
/// for every member `H.k`, `/chain?at=` its `position` answers its `chain`,
/// and `/chain?at=` its `base.seq` answers its `base.chain`. Every other pin
/// on a head's OWN chain is relational and blind to a wrong value: two boards
/// under one seed name one wrong value, two seeds two, `prev` copies it
/// faithfully, and it still differs from `/health` after the head's commits.
/// `H.1` is in the set on purpose — that head alone mints the staging draft
/// between reading its pair and writing its record, and it is the CLAIM's own
/// (s1), written inside the claim's request.
#[test]
fn every_head_names_the_pair_the_boards_recomputation_answers() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path()); // H.1: the claim's, minting the draft
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let mut clock = clock_origin();

    sd.daemon().checkpoint_now();
    commit(port, &owner, CLAIMANT_ACCOUNT); // H.2: the checkpoint's, naming a base
    force_head(&sd, &owner, CLAIMANT_ACCOUNT, &mut clock); // H.3
    for k in 1..=3u64 {
        let rec = head_record(port, &head_member(k)).unwrap_or_else(|| panic!("H.{k} exists"));
        let position = rec["position"].as_u64().expect("position");
        assert_eq!(
            rec["chain"].as_str().map(str::to_string),
            chain_at(port, position),
            "H.{k} names the chain the board recomputes AT its position: {rec}"
        );
        if let Some(seq) = rec["base"]["seq"].as_u64() {
            assert_eq!(
                rec["base"]["chain"].as_str().map(str::to_string),
                chain_at(port, seq),
                "H.{k}'s base names the chain the board recomputes at its seq: {rec}"
            );
        }
    }
    assert!(
        head_record(port, &head_member(2)).expect("H.2")["base"].is_object(),
        "the set includes a head that names a base"
    );
    sd.shutdown();
}

// ── (iv) EXTENDS, RED — the tail cut ─────────────────────────────────────────

/// (iv) — copy the data dir at head k−1, commit on through head k, restore the
/// copy, reopen: the newest member is older than k and `H.k` is absent; regrow
/// past k's position and the head at that height differs.
#[test]
fn a_restored_tail_cut_drops_the_later_head_and_regrows_a_different_one() {
    let live = tempfile::tempdir().expect("tempdir");
    let backup = tempfile::tempdir().expect("tempdir");
    let mut clock = clock_origin();

    // Head k−1 = H.1 — the claim's own (s1) — then snapshot the data dir.
    {
        let sd = spawn(live.path());
        assert!(head_record(sd.port(), &head_member(1)).is_some(), "H.1 exists");
        assert!(head_record(sd.port(), &head_member(2)).is_none(), "and no H.2 yet");
        sd.shutdown();
    }
    copy_dir(live.path(), backup.path());

    // Commit on through head k = H.2, saving its record, then stop.
    let (cut_k2_position, cut_k2_chain) = {
        let sd = spawn(live.path());
        let owner = open_session(sd.port(), CLAIMANT_PRINCIPAL);
        force_head(&sd, &owner, CLAIMANT_ACCOUNT, &mut clock); // H.2
        let k2 = head_record(sd.port(), &head_member(2)).expect("H.2 exists in the live dir");
        let saved = (k2["position"].as_u64().unwrap(), k2["chain"].as_str().unwrap().to_string());
        sd.shutdown();
        saved
    };

    // Restore the k−1 copy over the live dir and reopen: H.2 never happened.
    wipe_dir(live.path());
    copy_dir(backup.path(), live.path());
    {
        let sd = spawn(live.path());
        let port = sd.port();
        let owner = open_session(port, CLAIMANT_PRINCIPAL);
        let newest = expect_latest_head(port);
        assert_eq!(
            newest["position"].as_u64().unwrap(),
            head_record(port, &head_member(1)).unwrap()["position"].as_u64().unwrap(),
            "the newest head is H.1 — older than the cut H.2"
        );
        assert!(head_record(port, &head_member(2)).is_none(), "H.2 is absent after the tail cut");

        // Regrow past k's position with DIFFERENT work than the cut timeline did
        // — an extra commit before the head — so the head at height 2 lands at a
        // different position and chain than the H.2 the cut discarded. A peer
        // holding the cut H.2 sees the board's H.2 differ.
        commit(port, &owner, CLAIMANT_ACCOUNT);
        force_head(&sd, &owner, CLAIMANT_ACCOUNT, &mut clock); // a new, different H.2
        let regrown = head_record(port, &head_member(2)).expect("a regrown H.2");
        let differs = regrown["position"].as_u64().unwrap() != cut_k2_position
            || regrown["chain"].as_str().unwrap() != cut_k2_chain;
        assert!(differs, "the regrown head at height 2 differs from the cut one");
        sd.shutdown();
    }
}

// ── (v) EXTENDS, RED — the re-chain ──────────────────────────────────────────

/// (v) — a second daemon over the same op sequence with ONE altered op writes
/// its head at the same position with a different `chain` and, once a
/// checkpoint exists, a different `base.body_hash` (the canonical body carries
/// the altered bytes) under the same `base.seq`; a peer's saved `H.k` from the
/// first differs.
#[test]
fn one_altered_op_re_chains_the_head_at_the_same_position() {
    // Two independent boards. Each: claim (identical ops), one insert into a
    // fresh draft, a checkpoint, then a forced head — same commit COUNT so the
    // head lands at the same position and the checkpoint at the same seq,
    // different insert BYTES so the chain diverges from that op onward and the
    // checkpoint's body with it.
    fn board(dir: &Path, text: &str) -> Value {
        let sd = spawn(dir);
        let port = sd.port();
        let owner = open_session(port, CLAIMANT_PRINCIPAL);
        // one draft, one insert of `text` at position 1
        let v = op(
            port,
            Some(&owner),
            &format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"}}"#),
        );
        let draft = v["addr"].as_str().expect("draft addr").to_string();
        op(
            port,
            Some(&owner),
            &format!(r#"{{"op":"insert","doc":"{draft}","at":{{"subspace":"1","ordinal":"1"}},"values":["{text}"]}}"#),
        );
        sd.daemon().checkpoint_now();
        let mut clock = clock_origin();
        force_head(&sd, &owner, CLAIMANT_ACCOUNT, &mut clock);
        let rec = expect_latest_head(port);
        sd.shutdown();
        rec
    }

    let a = tempfile::tempdir().expect("tempdir");
    let b = tempfile::tempdir().expect("tempdir");
    let head_a = board(a.path(), "aaaa");
    let head_b = board(b.path(), "bbbb");
    assert_eq!(
        head_a["position"].as_u64(),
        head_b["position"].as_u64(),
        "the same op sequence lands the head at the same position"
    );
    assert_ne!(
        head_a["chain"].as_str(),
        head_b["chain"].as_str(),
        "one altered op re-chains the head — the saved H.k differs"
    );
    let (base_a, base_b) = (&head_a["base"], &head_b["base"]);
    assert!(base_a.is_object() && base_b.is_object(), "both heads name a base: {head_a} {head_b}");
    assert_eq!(base_a["seq"].as_u64(), base_b["seq"].as_u64(), "the checkpoints sit at one seq");
    assert_ne!(
        base_a["body_hash"].as_str(),
        base_b["body_hash"].as_str(),
        "the altered op is in the canonical body: base.body_hash differs"
    );
    assert_ne!(base_a["chain"].as_str(), base_b["chain"].as_str(), "and the base's chain with it");
}

// ── (vi) THE FLOOR ───────────────────────────────────────────────────────────

/// (vi) — the honest claim admits with the seeded system account present (the
/// floor stays zero under node 1); and `delegate` refuses the system
/// principal's id as not fresh.
#[test]
fn the_claim_floor_is_untouched_and_the_system_id_is_not_fresh() {
    // The claim ceremony admits: `spawn` runs it (an unclaimed daemon runs
    // nothing else), so a claimed board here IS the honest claim admitting
    // over the seeded genesis — the floor stayed zero under node 1.
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let (st, body) = get(port, "/health");
    assert_eq!(st, 200);
    assert_eq!(
        json(&body)["auth"]["claimant"].as_str(),
        Some(CLAIMANT_ACCOUNT),
        "the honest claim admitted with the seeded account present"
    );

    // `delegate` with the system principal's own id is refused `duplicate_id`:
    // genesis already registered it. The id sits under the wire's 2⁵³ − 1
    // cap, so the frame parses and reaches the freshness gate.
    let boot = open_session(port, 0);
    let prefix = {
        let v = op(port, Some(&boot), r#"{"op":"next_account_prefix","parent":"1"}"#);
        v["addr"].as_str().expect("a delegable prefix under node 1").to_string()
    };
    let v = op(
        port,
        Some(&boot),
        &format!(
            r#"{{"op":"delegate","new_prefix":"{prefix}","new_id":{}}}"#,
            SYSTEM_PRINCIPAL.0
        ),
    );
    assert_eq!(v["resp"].as_str(), Some("rejected"), "the system id cannot be re-seated: {v}");
    assert_eq!(v["code"].as_str(), Some("duplicate_id"), "refused as not fresh: {v}");
    sd.shutdown();
}

/// (vi) — THE CLAIM'S OWN TURN CAN WRITE A HEAD, and the claim still
/// completes — AND THEN THE CLAIM WRITES NO SECOND ONE. PUB-6.65's cadence
/// gates nothing on the claim, so the claim's `commit_under` gives the head
/// writer its turn like any session write's, and where the hour has passed
/// before the ceremony's last step the head's own commits land between the
/// claim and the claim flip's tail — the one kind of commit that can, as
/// `Daemon::on_claim_flip` states. The claim answers its own ack at its own
/// position and the board is claimed: the fold's post-commit step reads a
/// world holding the head's commits and honours the deposit its gate
/// honoured (`IdentityFold::step_committed`'s premise — a firing assert would
/// answer this claim `500 internal_panic` in a debug build). The flip's own
/// `H.1` (s1) then finds a head standing and writes nothing: `H.1` is the
/// cadence's, at the claim's position, and there is no `H.2`.
#[test]
fn the_claims_own_turn_can_write_a_head_and_the_claim_still_completes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn_unclaimed(dir.path());
    let port = sd.port();
    ceremony_before_the_claim(port);
    // The hour passes before the ceremony's last step.
    sd.daemon().set_head_writer_clock_millis(clock_origin() + WELL_PAST_THE_HOUR_MILLIS);
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let at = acked_at(&op(port, Some(&signed), &claim_frame(CLAIMANT_DOC1, CLAIMANT_ACCOUNT)));
    assert!(claimed(port), "the claim link flips the board claimed");
    let rec = expect_latest_head(port);
    assert_eq!(
        rec["position"].as_u64(),
        Some(at),
        "the claim's own turn wrote the head, naming the claim: {rec}"
    );
    let (live, _) = health(port);
    assert!(live > at, "the head's own commits landed past the claim's position: {live} > {at}");
    assert_eq!(rec, head_record(port, &head_member(1)).expect("H.1"), "the cadence's head IS H.1");
    assert!(head_record(port, &head_member(2)).is_none(), "the claim's step wrote no second head");
    assert_eq!(live, at + H1_RECORDS, "one head's records above the claim, not two heads'");
    sd.shutdown();
}

/// (vi) — THE CLAIM WRITES `H.1` (signed ops, s1; RULED 2026-09-25), EXACTLY
/// ONE, AT THE CLAIM'S OWN POSITION, AND THE CADENCE COUNTS FROM IT. A board
/// `spawn` claims has its first head at the claim's ack — `H.1` naming the
/// claim link's position, `prev` null, `base` null — and no `H.2`; the head's
/// three commits (the staging draft's mint, the record's insert, the publish
/// shot: eight records) are the whole distance from the claim to the live
/// head; and with the clock frozen and no checkpoint taken, the 64th commit
/// after the claim writes `H.2` naming itself, with `prev` the claim's head —
/// the count trigger resumed at zero by the claim's head, not by anything a
/// test forced.
#[test]
fn the_claim_writes_exactly_one_head_at_its_own_position_and_the_cadence_counts_from_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();

    let h1 = head_record(port, &head_member(1)).expect("H.1 at the claim");
    assert_eq!(h1["position"].as_u64(), Some(CLAIM_POSITION), "H.1 names the claim's position: {h1}");
    assert!(h1["prev"].is_null(), "the first head: prev null: {h1}");
    assert!(h1["base"].is_null(), "no checkpoint yet: base null: {h1}");
    assert_eq!(expect_latest_head(port), h1, "the latest head IS H.1");
    assert!(head_record(port, &head_member(2)).is_none(), "exactly one head");
    let (live, _) = health(port);
    assert_eq!(live, CLAIM_POSITION + H1_RECORDS, "the head's three commits above the claim, and nothing else");

    // The cadence from H.1: the clock frozen at the claim's own reading (so
    // trigger (c) cannot fire), no checkpoint (so (b) cannot) — only the
    // count, and only on the 64th landed commit after the claim.
    sd.daemon().set_head_writer_clock_millis(clock_origin());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let mut last_at = 0;
    for i in 1..=64u64 {
        last_at = commit(port, &owner, CLAIMANT_ACCOUNT);
        if i < 64 {
            assert!(
                head_record(port, &head_member(2)).is_none(),
                "no H.2 before the 64th commit after the claim (at commit {i})"
            );
        }
    }
    let h2 = head_record(port, &head_member(2)).expect("H.2 at the 64th commit since the claim's head");
    assert_eq!(h2["position"].as_u64(), Some(last_at), "H.2 names the 64th commit: {h2}");
    assert_eq!(h2["prev"]["position"].as_u64(), Some(CLAIM_POSITION), "its prev is the claim's head: {h2}");
    assert_eq!(h2["prev"]["chain"], h1["chain"], "…by chain too");
    assert_eq!(expect_latest_head(port), h2);
    sd.shutdown();
}

/// (vi) — THE UNCLAIMED BOARD WRITES NO HEAD AT STARTUP (A1/A5: no head by a
/// claim that did not happen): a fresh board, the same board after the
/// ceremony's first four steps, and that board restarted have no member of
/// `H` — the open's crash-window repair keys on the claim, and the cadence on
/// its triggers, neither of which the unclaimed board has met. The claim
/// then writes it, at the claim's position — the one transition the rule
/// keys on.
#[test]
fn the_unclaimed_board_writes_no_head_at_startup() {
    let dir = tempfile::tempdir().expect("tempdir");
    {
        let sd = spawn_unclaimed(dir.path());
        let port = sd.port();
        assert!(head_record(port, H).is_none(), "a fresh board: no head");
        ceremony_before_the_claim(port);
        assert!(head_record(port, H).is_none(), "four steps of the ceremony: no head");
        sd.shutdown();
    }
    let sd = spawn_unclaimed(dir.path());
    let port = sd.port();
    assert!(!claimed(port), "still unclaimed after the restart");
    assert!(head_record(port, H).is_none(), "restarted unclaimed: the open wrote no head");
    assert_eq!(health(port).0, CLAIM_POSITION - 3, "the four steps' records, and no more");
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let at = acked_at(&op(port, Some(&signed), &claim_frame(CLAIMANT_DOC1, CLAIMANT_ACCOUNT)));
    assert_eq!(at, CLAIM_POSITION);
    assert_eq!(
        head_record(port, &head_member(1)).expect("H.1")["position"].as_u64(),
        Some(at),
        "the claim wrote H.1 at its own position"
    );
    sd.shutdown();
}

// ── (ix) THE CLASS ───────────────────────────────────────────────────────────

/// (ix) — `H` reads at guest class with no token, its `/changes` entry shows
/// `key: "system"`, and the staging draft's inserts are masked at every class.
#[test]
fn the_head_is_guest_readable_its_feed_entry_is_system_and_the_draft_is_masked() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let mut clock = clock_origin();

    let (before, _) = health(port);
    force_head(&sd, &owner, CLAIMANT_ACCOUNT, &mut clock);

    // GUEST reads H: no token, published, a well-formed head.
    let _ = expect_latest_head(port);

    // The feed: since `before`, the head's publish entry is present with
    // key "system"; the staging draft's insert entry is masked at guest class
    // (never present with nulled fields, PUB-6.45), and every `key: "system"`
    // entry the guest sees is a publish of H's own member (docs under H).
    let (st, body) = get(port, &format!("/changes?since={before}"));
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&body));
    let page = json(&body);
    let changes = page["changes"].as_array().expect("changes array");
    let system_entries: Vec<&Value> =
        changes.iter().filter(|e| e["key"].as_str() == Some("system")).collect();
    assert!(!system_entries.is_empty(), "the head's publish carries key: system: {page}");
    for e in &system_entries {
        assert_eq!(e["op"].as_str(), Some("publish"), "a guest-visible system entry is the publish: {e}");
        for d in e["docs"].as_array().expect("docs") {
            let doc = d.as_str().expect("doc");
            assert!(
                doc == H || doc.starts_with(&format!("{H}.")),
                "a guest-visible system entry names only H or its members, never the private draft: {e}"
            );
        }
    }
    // No guest-visible entry names the staging draft (1.1.0.1.0.3+), the
    // insert into which is masked.
    for e in changes {
        for d in e["docs"].as_array().into_iter().flatten() {
            let doc = d.as_str().unwrap_or("");
            assert!(
                !(doc.starts_with("1.1.0.1.0.") && doc != H && !doc.starts_with(&format!("{H}."))),
                "the staging draft's insert is masked at guest class: {e}"
            );
        }
    }
    sd.shutdown();
}

// ── (vii) GENESIS, (viii) DETERMINISM ────────────────────────────────────────

/// (vii) — the golden's three pins and `check_hints` at Σ₀ are the kernel and
/// engine suites' (`skep-kernel` golden, `skep-engine` genesis); here the
/// daemon's own witness is that a fresh board carries the seed: the system
/// account's doc 1 and doc 2 are registered and published (guest-readable),
/// and `H` is present as a document from the first commit onward.
#[test]
fn genesis_seeds_the_system_account_documents_born_published() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn_unclaimed(dir.path());
    let port = sd.port();
    // doc-metadata on H, as the guest: registered, published, owned by the
    // system account — before any head has been written (unclaimed, so the
    // claim's own H.1 has not: the seed alone).
    let v = op(port, None, &format!(r#"{{"op":"doc_metadata","doc":"{H}"}}"#));
    assert_eq!(v["resp"].as_str(), Some("doc_metadata"), "H is a registered document at genesis: {v}");
    assert_eq!(v["published"].as_bool(), Some(true), "H is born published: {v}");
    assert_eq!(v["owner"].as_str(), Some("1.1.0.1"), "H is owned by the system account: {v}");
    // doc 1 (the ghost home doc / commons registry's home) likewise.
    let v1 = op(port, None, r#"{"op":"doc_metadata","doc":"1.1.0.1.0.1"}"#);
    assert_eq!(v1["published"].as_bool(), Some(true), "doc 1 is born published: {v1}");
    sd.shutdown();
}

/// The one seed the determinism pin's two boards share, and the two seeds
/// the salt's pin keeps apart.
const ONE_SEED: u64 = 0x11;
const OTHER_SEED: u64 = 0x22;

/// `GET /chain?at=N` → the value, or `None` where `N` is not a committed
/// position (a composite's interior seq).
fn chain_at(port: u16, at: u64) -> Option<String> {
    let (st, body) = get(port, &format!("/chain?at={at}"));
    let v = json(&body);
    match st {
        200 => Some(v["chain"].as_str().expect("chain string").to_string()),
        400 if v["error"].as_str() == Some("not_a_position") => None,
        _ => panic!("/chain?at={at}: {st} {v}"),
    }
}

/// One board's witness for the three pins below: the same three commits then
/// a forced head — through the seeded seam under `Some(seed)`, through the
/// production door (`spawn`, OS entropy) under `None`.
struct Board {
    /// The triggering commit's acked position — what the head names.
    trigger: u64,
    /// The live head once the head's own two commits have landed.
    live_head: u64,
    /// `/chain?at=N` at every committed position from 1 to the live head.
    chains: Vec<(u64, String)>,
    /// The head's raw bytes.
    bytes: String,
}

fn board_under(dir: &Path, seed: Option<u64>) -> Board {
    let sd = match seed {
        Some(seed) => spawn_seeded(dir, seed),
        None => spawn(dir),
    };
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let mut clock = clock_origin();
    for _ in 0..3 {
        commit(port, &owner, CLAIMANT_ACCOUNT);
    }
    let trigger = force_head(&sd, &owner, CLAIMANT_ACCOUNT, &mut clock);
    let (live_head, _) = health(port);
    let chains: Vec<(u64, String)> =
        (1..=live_head).filter_map(|at| chain_at(port, at).map(|chain| (at, chain))).collect();
    let bytes = atom_str(port, H).expect("a head");
    sd.shutdown();
    Board { trigger, live_head, chains, bytes }
}

/// The claim link's position on a fresh board — the ceremony's fifth commit
/// (wire.md §A first board: positions 2, 3, 6, 9, 12) — and `H.1`'s records
/// above it: the staging draft's mint (1), the head record's insert (3), the
/// publish shot into `H` (4). `H.1` is the claim's own (signed ops, s1).
const CLAIM_POSITION: u64 = 12;
const H1_RECORDS: u64 = 8;

/// THE POSITIONS, pinned: the head names the triggering commit — the
/// ceremony's commits (12), the claim's own `H.1` (8 records: 20), three
/// creates and the fourth (24) — and the live head is that plus the head's own
/// insert and publish (31; the staging draft was minted at `H.1`). The salt
/// adds no record and moves no coordinate: the same ops produced 16 and 24 at
/// `d77bfa4`, before it, and again after it, until s1 (2026-09-25) moved the
/// first head into the claim's own step — the one re-pin, by `H.1`'s eight
/// records ahead of the creates, the forced head being `H.2` with the draft
/// already minted. A position moving here is a STOP, not a number to update.
const TRIGGER_POSITION: u64 = CLAIM_POSITION + H1_RECORDS + 4;
const LIVE_HEAD_POSITION: u64 = TRIGGER_POSITION + 7;

/// (viii) — two daemons over ONE op sequence write byte-identical heads. The
/// head record carries no timestamp and no board-unique term, so identical
/// histories yield identical head bytes — under ONE SALT SEED: the chain's
/// per-transaction salt (`SKJ4`) is the one board-unique term a history now
/// carries, in the preimage and never in the record, and the seeded source
/// (`spawn_seeded`, the daemon's test seam) makes it a function of the
/// position alone. Under the production door's OS entropy two boards write
/// two chains, which `two_production_daemons_over_one_sequence_write_two_chains`
/// pins — the next test pins two SEEDS, through the seam. The positions are
/// what they were before the salt: it adds no record.
#[test]
fn two_daemons_over_one_sequence_write_byte_identical_heads() {
    let a = tempfile::tempdir().expect("tempdir");
    let b = tempfile::tempdir().expect("tempdir");
    let a = board_under(a.path(), Some(ONE_SEED));
    let b = board_under(b.path(), Some(ONE_SEED));
    assert_eq!(a.bytes, b.bytes, "one op sequence under one seed writes one head byte string");
    assert_eq!((a.trigger, a.live_head), (b.trigger, b.live_head), "one pair of positions");
    assert_eq!(a.chains, b.chains, "one chain at every committed position");
    // The head names the position of the commit that triggered it — the
    // fourth create after the ceremony — strictly below its own commit, and
    // both figures are what they were before the salt.
    let rec: Value = serde_json::from_str(&a.bytes).expect("a head record");
    assert_eq!(rec["format"].as_str(), Some(FORMAT));
    assert_eq!(rec["position"].as_u64(), Some(a.trigger), "the head names the triggering commit");
    assert!(a.trigger < a.live_head, "a head names a coordinate strictly below its own commit");
    assert_eq!(
        (a.trigger, a.live_head),
        (TRIGGER_POSITION, LIVE_HEAD_POSITION),
        "a position moved: STOP"
    );
}

/// (viii′) — THE SALT'S EFFECT, pinned from the wire: two daemons over ONE op
/// sequence under TWO seeds write chains that DIFFER at every committed
/// position from the first, and heads that differ in their `chain` — while
/// every position, the head's included, is the same, since the salt adds no
/// record and moves no coordinate. Position 0 is the seed on both and is not
/// a difference.
#[test]
fn two_daemons_under_two_seeds_differ_in_every_chain_value_and_in_the_head() {
    let a = tempfile::tempdir().expect("tempdir");
    let b = tempfile::tempdir().expect("tempdir");
    let a = board_under(a.path(), Some(ONE_SEED));
    let b = board_under(b.path(), Some(OTHER_SEED));
    assert_eq!((a.trigger, a.live_head), (b.trigger, b.live_head), "the salt moves no position");
    assert_eq!(
        (a.trigger, a.live_head),
        (TRIGGER_POSITION, LIVE_HEAD_POSITION),
        "a position moved: STOP"
    );
    let positions_a: Vec<u64> = a.chains.iter().map(|(at, _)| *at).collect();
    let positions_b: Vec<u64> = b.chains.iter().map(|(at, _)| *at).collect();
    assert_eq!(positions_a, positions_b, "the same committed positions on both boards");
    assert!(positions_a.len() >= 4, "the ceremony, three creates and the head: {positions_a:?}");
    for ((at, x), (_, y)) in a.chains.iter().zip(&b.chains) {
        assert_ne!(x, y, "two seeds, two chain values at position {at}");
    }
    assert_ne!(a.bytes, b.bytes, "two seeds, two head byte strings");
    let (ra, rb): (Value, Value) = (
        serde_json::from_str(&a.bytes).expect("a head record"),
        serde_json::from_str(&b.bytes).expect("a head record"),
    );
    assert_eq!(ra["position"].as_u64(), Some(TRIGGER_POSITION), "the heads name one position");
    assert_eq!(ra["position"], rb["position"]);
    assert_eq!(ra["format"], rb["format"], "one stamp");
    assert_ne!(ra["chain"], rb["chain"], "the heads' chains differ: the salt is in the preimage");
}

/// (viii″) — THE PRODUCTION DOOR DRAWS ITS SALT FROM THE OS (`SKJ4`;
/// `Daemon::open_with`, which takes no source): two daemons spawned through
/// it and driven through ONE op sequence write two chains, differing at
/// every committed position, at the positions the salt never moves. The
/// seam's two pins cannot see this cell — a door that opened under a FIXED
/// seed still writes one chain under one seed and two under two — and a
/// fixed seed defeats the salt outright: a chain that is a function of its
/// position alone confirms guesses at a transaction's bytes to any reader of
/// the token-blind `/chain?at=N` (wire.md §Reading history).
#[test]
fn two_production_daemons_over_one_sequence_write_two_chains() {
    let a = tempfile::tempdir().expect("tempdir");
    let b = tempfile::tempdir().expect("tempdir");
    let a = board_under(a.path(), None);
    let b = board_under(b.path(), None);
    assert_eq!(
        (a.trigger, a.live_head),
        (TRIGGER_POSITION, LIVE_HEAD_POSITION),
        "a position moved: STOP"
    );
    assert_eq!(
        (b.trigger, b.live_head),
        (TRIGGER_POSITION, LIVE_HEAD_POSITION),
        "a position moved: STOP"
    );
    let positions = |board: &Board| board.chains.iter().map(|(at, _)| *at).collect::<Vec<u64>>();
    assert_eq!(positions(&a), positions(&b), "the same committed positions on both boards");
    for ((at, x), (_, y)) in a.chains.iter().zip(&b.chains) {
        assert_ne!(x, y, "two production boards wrote one chain value at position {at}");
    }
    assert_ne!(a.bytes, b.bytes, "two production boards, two head byte strings");
}
