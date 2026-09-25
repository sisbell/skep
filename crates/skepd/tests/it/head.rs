//! The PUBLISHED HEAD, against a served DURABLE daemon (PUB-6.65, RES-304;
//! QUEUE item 10 piece 2). Every daemon here is `common::spawn`'s — `Fsync`
//! durability (there is no in-memory daemon), so the head document `H` =
//! `1.1.0.1.0.2` is journalled and survives restart, which the tail-cut and
//! re-chain checks below rest on.
//!
//! The cadence's clock and its checkpoint are driven through the daemon's test
//! seams (`head_set_clock_millis`, `checkpoint_now`) — never a `sleep`.
//! The clock seam's readings are wall-clock unix milliseconds (the writer's
//! domain since its resume seeds the hour from the feed's recorded times —
//! the chain's open items, item 2), so every reading here is set relative to
//! [`clock_origin`]; the hour-survives-a-restart test moves the RECORD, not
//! the clock.

use crate::common;

use std::path::Path;

use common::{
    acked_at, get, json, op, open_session, spawn, spawn_seeded, CLAIMANT_ACCOUNT,
    CLAIMANT_PRINCIPAL,
};
use serde_json::Value;
use skepd::Skepd;

/// The head document `H` — doc 2 of the system account (PUB-6.65).
const H: &str = "1.1.0.1.0.2";

/// The head record's `format` member — the journal stamp in force, `SKJ4`
/// since the chain's salt. The one head member that moved at the bump.
const FORMAT: &str = "SKJ4";

/// The k-th head — the k-th version member of `H`'s trunk chain, `H·k`.
fn head_member(k: u64) -> String {
    format!("{H}.{k}")
}

/// A well past-the-hour clock jump, so a commit after it drives the head's
/// time bound (trigger (c)); the real bound is one hour and this is many.
const A_LONG_WHILE_MILLIS: u64 = 10_000_000;

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
/// commit — that commit's `after_commit` finds the position moved and the hour
/// elapsed, and writes the head naming the committed pair. Returns the head's
/// `position` (the committed op's own position, which the head names).
fn force_head(sd: &Skepd, session: &str, account: &str, clock: &mut u64) -> u64 {
    *clock += A_LONG_WHILE_MILLIS;
    sd.daemon().head_set_clock_millis(*clock);
    commit(sd.port(), session, account)
}

/// A test clock's origin: the wall clock now, in unix milliseconds — the
/// writer's own domain, whose hour is seeded from the feed's recorded times
/// (wall-clock) or from open-time (wall-clock) — so readings set through the
/// seam are relative to now rather than small numbers a seeded origin would
/// dwarf into "not yet an hour".
fn clock_origin() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after the epoch")
        .as_millis() as u64
}

/// Two hours, in the sidecar's own milliseconds.
const TWO_HOURS_MILLIS: u64 = 2 * 60 * 60 * 1000;

/// Rewrite every recorded `time` in the sidecar `age` milliseconds into the
/// past — the feed's testimony (AUTH-4.56: a rewritable sidecar), which the
/// head writer's resume reads its hour's origin from. Every time moves
/// alike, so the file stays monotone; the digit count is kept, so every
/// line keeps its length and the derived offset array stays true.
fn age_sidecar(dir: &Path, age: u64) {
    let path = dir.join("commits.log");
    let text = std::fs::read_to_string(&path).expect("commits.log");
    let mut out = String::with_capacity(text.len());
    let mut aged = 0;
    for line in text.lines() {
        let mut line = line.to_string();
        if let Some(start) = line.find("\"time\":") {
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
        out.push_str(&line);
        out.push('\n');
    }
    assert!(aged > 0, "the sidecar recorded the head's own commits");
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

    // A first head off the time bound gives a known reset point: the count
    // trigger is then exactly 64 commits from here.
    force_head(&sd, &owner, CLAIMANT_ACCOUNT, &mut clock);
    let after_first = head_record(port, H).expect("a first head").clone();
    let first_k_position = after_first["position"].as_u64().unwrap();

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
                first_k_position,
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

/// (i) — a checkpoint moves the head: with the checkpoint seq moved since the
/// last head, the next commit writes one (trigger (b)); and a quiet board (no
/// count, no checkpoint, no clock) writes none.
#[test]
fn a_checkpoint_moves_the_head_and_a_quiet_board_writes_none() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let mut clock = clock_origin();

    force_head(&sd, &owner, CLAIMANT_ACCOUNT, &mut clock);
    let base = head_record(port, H).expect("a head").clone();
    let base_position = base["position"].as_u64().unwrap();

    // QUIET: a handful of commits, no checkpoint, clock frozen — no new head.
    for _ in 0..5 {
        commit(port, &owner, CLAIMANT_ACCOUNT);
        assert_eq!(
            head_record(port, H).unwrap()["position"].as_u64().unwrap(),
            base_position,
            "a quiet board (no count, no checkpoint, no clock) writes no head"
        );
    }

    // A CHECKPOINT: now the next commit's `after_commit` sees the checkpoint
    // seq moved since the last head and writes one.
    sd.daemon().checkpoint_now();
    let at = commit(port, &owner, CLAIMANT_ACCOUNT);
    let rec = expect_latest_head(port);
    assert!(
        rec["position"].as_u64().unwrap() > base_position,
        "the checkpoint trigger wrote a newer head"
    );
    assert_eq!(rec["position"].as_u64().unwrap(), at, "naming the pair as of that commit");
    // Its `base` names the checkpoint that moved (seq ≤ position).
    let base_member = &rec["base"];
    assert!(base_member.is_object(), "a head after a checkpoint names a base: {rec}");
    assert!(
        base_member["seq"].as_u64().unwrap() <= rec["position"].as_u64().unwrap(),
        "base.seq is at or below the head's position: {rec}"
    );
    // …named by the checkpoint's OWN chain — the kernel's recomputation at
    // that seq — and not by the body hash beside it: both are 64 hex, so a
    // transposed pair passes every shape check above.
    let base_seq = base_member["seq"].as_u64().unwrap();
    assert_eq!(
        base_member["chain"].as_str().map(str::to_string),
        chain_at(port, base_seq),
        "base.chain is the chain AT base.seq: {rec}"
    );
    assert_ne!(base_member["chain"], base_member["body_hash"], "and is not the body hash: {rec}");
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

/// RESUME — the COUNT survives a restart (the chain's open items, item 2;
/// PUB-6.65's "64 commits that are not the head writer's own have landed
/// since the last head" — of the board, not of the process): 40 commits after
/// a head, a restart, 24 more — and the 64th landed commit since that head
/// writes the next, on the second uptime, with the clock left alone and no
/// checkpoint taken, so no other trigger can be what fired. Before the seed a
/// restarted board counted from zero, and a board restarted every fewer than
/// 64 commits wrote heads at checkpoints alone.
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
/// `"system"`-keyed entries above the position it named, and their recorded
/// `time` is the head's, so the writer seeds the hour's origin there. Pinned
/// by moving the RECORD rather than the clock: the sidecar — rewritable
/// testimony, AUTH-4.56 — is rewritten with every `time` two hours older,
/// the daemon restarted with its clock left alone, and the first commit
/// writes a head (an hour has passed since the last head AS RECORDED, though
/// not since open) while the second, under the hour since the new head,
/// writes none. Before the seed the hour was measured from open, and this
/// board would have written no time-bound head for its first hour up.
#[test]
fn the_hour_since_the_last_head_survives_a_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut clock = clock_origin();

    let head_position = {
        let sd = spawn(dir.path());
        let port = sd.port();
        let owner = open_session(port, CLAIMANT_PRINCIPAL);
        let p = force_head(&sd, &owner, CLAIMANT_ACCOUNT, &mut clock);
        // One more commit, so the head's own entries are not the feed's last:
        // the origin is read off the head's OWN "system" entry, not the head
        // position's time.
        commit(port, &owner, CLAIMANT_ACCOUNT);
        assert_eq!(head_record(port, H).unwrap()["position"].as_u64().unwrap(), p);
        sd.shutdown();
        p
    };
    age_sidecar(dir.path(), TWO_HOURS_MILLIS);

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

/// The staging draft is minted ONCE — doc 3 of the system account — and found
/// again after a restart (PUB-6.65: the head reaches `H` and the system
/// account's own staging draft and NO other document; the writer resumes by
/// reading). Pinned by the journal's own arithmetic, in RECORDS as `/health`
/// counts them: a head that had to mint the draft costs exactly one document
/// mint more than a head that found it, and a document mint's cost is measured
/// here on this build rather than assumed.
#[test]
fn a_restarted_writer_finds_the_staging_draft_it_minted_and_mints_no_other() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut clock = clock_origin();

    let (first_head_cost, mint_cost) = {
        let sd = spawn(dir.path());
        let port = sd.port();
        let owner = open_session(port, CLAIMANT_PRINCIPAL);
        // One plain document mint, measured: what one `create_new_document`
        // adds to the position on this build.
        let before = health(port).0;
        commit(port, &owner, CLAIMANT_ACCOUNT);
        let mint_cost = health(port).0 - before;
        // The board's FIRST head: the triggering mint, the draft's mint, the
        // atom's insert, the publish shot.
        let before = health(port).0;
        force_head(&sd, &owner, CLAIMANT_ACCOUNT, &mut clock);
        let first_head_cost = health(port).0 - before;
        sd.shutdown();
        (first_head_cost, mint_cost)
    };

    // The second uptime's head: the same, LESS the draft's mint — the writer
    // found doc 3 at open.
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let before = health(port).0;
    force_head(&sd, &owner, CLAIMANT_ACCOUNT, &mut clock);
    let second_head_cost = health(port).0 - before;
    assert_eq!(
        second_head_cost + mint_cost,
        first_head_cost,
        "the second uptime's head minted no draft: it reused the one the first minted"
    );
    sd.shutdown();
}

// ── (ii) THE RECURSION ───────────────────────────────────────────────────────

/// (ii) — each head's position is strictly below its own commit's position;
/// consecutive positions strictly increase; the second head's `prev` is the
/// first's pair; and `chain_head()` right after a head differs from the head's
/// own `chain` (it names a coordinate before its own commits).
#[test]
fn a_head_names_a_coordinate_strictly_below_its_own_commit() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let mut clock = clock_origin();

    let p1 = force_head(&sd, &owner, CLAIMANT_ACCOUNT, &mut clock);
    let head1 = expect_latest_head(port);
    assert_eq!(head1["position"].as_u64().unwrap(), p1);
    assert!(head1["prev"].is_null(), "the first head's prev is null: {head1}");
    let chain1 = head1["chain"].as_str().unwrap().to_string();

    // The head's own two commits advanced the log past the position it named,
    // and advanced the chain off the value it named.
    let (pos_after, chain_after) = health(port);
    assert!(pos_after > p1, "the head's own commits land strictly above the position it names");
    assert_ne!(chain_after, chain1, "chain_head after the head differs from the head's own chain");

    let p2 = force_head(&sd, &owner, CLAIMANT_ACCOUNT, &mut clock);
    let head2 = expect_latest_head(port);
    assert!(p2 > p1, "consecutive head positions strictly increase");
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

    for _ in 0..3 {
        force_head(&sd, &owner, CLAIMANT_ACCOUNT, &mut clock);
    }
    // The peer saves H.2 — its address and its exact bytes (a guest read).
    let saved = atom_str(port, &head_member(2)).expect("H.2 exists");

    // More history: two further heads.
    for _ in 0..2 {
        force_head(&sd, &owner, CLAIMANT_ACCOUNT, &mut clock);
    }

    // H.2 re-reads byte-equal — a version member is immutable.
    assert_eq!(atom_str(port, &head_member(2)).as_deref(), Some(saved.as_str()), "H.2 is byte-equal");

    // Walk `prev` from the latest head down to H.2, each step landing on the
    // member one lower and matching the (position, chain) its successor names.
    let latest = expect_latest_head(port); // H.5
    let mut k = 5u64;
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

// ── (iv) EXTENDS, RED — the tail cut ─────────────────────────────────────────

/// (iv) — copy the data dir at head k−1, commit on through head k, restore the
/// copy, reopen: the newest member is older than k and `H.k` is absent; regrow
/// past k's position and the head at that height differs.
#[test]
fn a_restored_tail_cut_drops_the_later_head_and_regrows_a_different_one() {
    let live = tempfile::tempdir().expect("tempdir");
    let backup = tempfile::tempdir().expect("tempdir");
    let mut clock = clock_origin();

    // Head k−1 = H.1, then snapshot the data dir.
    {
        let sd = spawn(live.path());
        let owner = open_session(sd.port(), CLAIMANT_PRINCIPAL);
        force_head(&sd, &owner, CLAIMANT_ACCOUNT, &mut clock); // H.1
        assert!(head_record(sd.port(), &head_member(1)).is_some(), "H.1 exists");
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

    // `delegate` with the system principal's id (u64::MAX) is refused
    // `duplicate_id` — genesis already registered it.
    let boot = open_session(port, 0);
    let prefix = {
        let v = op(port, Some(&boot), r#"{"op":"next_account_prefix","parent":"1"}"#);
        v["addr"].as_str().expect("a delegable prefix under node 1").to_string()
    };
    let v = op(
        port,
        Some(&boot),
        &format!(r#"{{"op":"delegate","new_prefix":"{prefix}","new_id":9000000000000000}}"#),
    );
    assert_eq!(v["resp"].as_str(), Some("rejected"), "the system id cannot be re-seated: {v}");
    assert_eq!(v["code"].as_str(), Some("duplicate_id"), "refused as not fresh: {v}");
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

    let before = head_position_via_changes_baseline(port);
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

/// The guest feed head before the work — a `since` baseline.
fn head_position_via_changes_baseline(port: u16) -> u64 {
    health(port).0
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
    let sd = spawn(dir.path());
    let port = sd.port();
    // doc-metadata on H, as the guest: registered, published, owned by the
    // system account — before any head has been written.
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

/// One board's witness for the two pins below: the same three commits then a
/// forced head, under `seed`.
struct Board {
    /// The triggering commit's acked position — what the head names.
    trigger: u64,
    /// The live head once the head's own two commits have landed.
    head: u64,
    /// `/chain?at=N` at every committed position from 1 to the head.
    chains: Vec<(u64, String)>,
    /// The head's raw bytes.
    bytes: String,
}

fn board_under(dir: &Path, seed: u64) -> Board {
    let sd = spawn_seeded(dir, seed);
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let mut clock = clock_origin();
    for _ in 0..3 {
        commit(port, &owner, CLAIMANT_ACCOUNT);
    }
    let trigger = force_head(&sd, &owner, CLAIMANT_ACCOUNT, &mut clock);
    let (head, _) = health(port);
    let chains: Vec<(u64, String)> =
        (1..=head).filter_map(|at| chain_at(port, at).map(|chain| (at, chain))).collect();
    let bytes = atom_str(port, H).expect("a head");
    sd.shutdown();
    Board { trigger, head, chains, bytes }
}

/// THE POSITIONS AS THEY WERE BEFORE THE SALT, pinned: the head names the
/// triggering commit — the ceremony's commits, three creates and the fourth —
/// and the live head is that plus the head's own insert and publish. The
/// salt adds no record and moves no coordinate, and these are the figures
/// the same ops produced at `d77bfa4`, before it; a position moving here is
/// a STOP, not a number to update.
const TRIGGER_POSITION: u64 = 16;
const HEAD_POSITION: u64 = 24;

/// (viii) — two daemons over ONE op sequence write byte-identical heads. The
/// head record carries no timestamp and no board-unique term, so identical
/// histories yield identical head bytes — under ONE SALT SEED: the chain's
/// per-transaction salt (`SKJ4`) is the one board-unique term a history now
/// carries, in the preimage and never in the record, and the seeded source
/// (`spawn_seeded`, the daemon's test seam) makes it a function of the
/// position alone. Under the production door's OS entropy two boards write
/// two chains, which the next test pins. The positions are what they were
/// before the salt: it adds no record.
#[test]
fn two_daemons_over_one_sequence_write_byte_identical_heads() {
    let a = tempfile::tempdir().expect("tempdir");
    let b = tempfile::tempdir().expect("tempdir");
    let a = board_under(a.path(), ONE_SEED);
    let b = board_under(b.path(), ONE_SEED);
    assert_eq!(a.bytes, b.bytes, "one op sequence under one seed writes one head byte string");
    assert_eq!((a.trigger, a.head), (b.trigger, b.head), "one pair of positions");
    assert_eq!(a.chains, b.chains, "one chain at every committed position");
    // The head names the position of the commit that triggered it — the
    // fourth create after the ceremony — strictly below its own commit, and
    // both figures are what they were before the salt.
    let rec: Value = serde_json::from_str(&a.bytes).expect("a head record");
    assert_eq!(rec["format"].as_str(), Some(FORMAT));
    assert_eq!(rec["position"].as_u64(), Some(a.trigger), "the head names the triggering commit");
    assert!(a.trigger < a.head, "a head names a coordinate strictly below its own commit");
    assert_eq!((a.trigger, a.head), (TRIGGER_POSITION, HEAD_POSITION), "a position moved: STOP");
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
    let a = board_under(a.path(), ONE_SEED);
    let b = board_under(b.path(), OTHER_SEED);
    assert_eq!((a.trigger, a.head), (b.trigger, b.head), "the salt moves no position");
    assert_eq!((a.trigger, a.head), (TRIGGER_POSITION, HEAD_POSITION), "a position moved: STOP");
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
