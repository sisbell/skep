//! A LINK'S OR A MEMBER'S AGE, at any age (skep #516; the permanence record's
//! D1 (b), D3 (a)+(c), D6 (2)), against a served durable daemon.
//!
//! The position of the commit that minted a document, a member or a link is
//! kept IN THE WORLD — the name space's position map, folded at the record
//! that mints the address, carried by every checkpoint — and answered by
//! `read_link` and `doc_metadata` as `at`, beside the daemon's testimony of
//! when that position committed: `time` off the change feed's own row where
//! the feed holds it (`time_from: "feed"`), else off the hourly `skep-time`
//! record the time writer keeps in the time document `T` = `1.1.0.1.0.4`
//! (`time_from: "anchor"`), which survives a lost feed and the journal's
//! reclaim floor alike. The time writer's hour is the head writer's clock,
//! driven through the daemon's clock seam (`set_head_writer_clock_millis`)
//! or by aging the feed's recorded times the resume reads its origin from —
//! never a `sleep`; the head record itself carries no timestamp and is
//! untouched by the time record (wire.md §The other endpoints).

use std::path::Path;
use std::time::Instant;

use crate::common::{
    self, acked_addr, acked_at, create_doc, device_key, doc_metadata, doc_metadata_frame,
    expect_resp, get, ghost_ty, http, insert_text, json, link_frame, op, op_at, open_session,
    open_signed_session, run, shot, spawn, spawn_seeded, version_of, CLAIMANT_ACCOUNT,
    CLAIMANT_DOC1, CLAIMANT_PRINCIPAL,
};
use serde_json::Value;
use skepd::Skepd;

/// The head document `H` and the time document `T` (wire.md §The other
/// endpoints): docs 2 and 4 of the system account.
const H: &str = "1.1.0.1.0.2";
const T: &str = "1.1.0.1.0.4";

/// The claim atom's I-address in the claimant's doc 1, the one run a shot
/// re-supplies (the publish suite's).
const ATOM: &str = "1.0.1.0.1.0.1.1";

/// One hour, restated from the time bound ("an hour has passed"), and the
/// minute a seam step clears it by: the writers' origins are the board's own
/// recorded times — the claim's head's for the head writer, the first
/// commit's for the time writer — a few seconds apart and a few seconds
/// after a test's origin, so a step of an hour and a minute passes both.
const HOUR_MILLIS: u64 = 60 * 60 * 1000;
const MINUTE_MILLIS: u64 = 60 * 1000;

/// The wall clock now, in unix milliseconds — the writer's own domain, whose
/// hour is measured from the feed's recorded times, so every seam reading
/// here is set relative to now.
fn clock_origin() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after the epoch")
        .as_millis() as u64
}

/// The five feed files (wire.md §The change feed), the daemon's testimony;
/// the attest store beside them is the journal's and stays.
const FEED_FILES: [&str; 5] =
    ["commits.log", "feed-index.log", "feed-offsets.log", "feed-masked.log", "feed-streams.log"];

/// Loses the feed: every file of the daemon's testimony removed, as a lost
/// log is.
fn lose_the_feed(dir: &Path) {
    for name in FEED_FILES {
        std::fs::remove_file(dir.join(name)).unwrap_or_else(|e| panic!("remove {name}: {e}"));
    }
}

/// Rewrites every recorded `time` in `commits.log` `age` milliseconds into
/// the past — the feed's testimony (AUTH-4.56: a rewritable sidecar), which
/// the two writers' resumes read their hours' origins from, so the next
/// open's first write finds an hour passed on the wall clock itself and no
/// seam set: the records then carry the wall clock, the reading the feed
/// stamps every later line with. The digit count is kept, so every line
/// keeps its length and the derived offsets stay true (the head suite's
/// `age_sidecar`, whole).
fn age_the_feed(dir: &Path, age: u64) {
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
            if let Ok(time) = line[digits..end].parse::<u64>() {
                let older = (time - age).to_string();
                assert_eq!(older.len(), end - digits, "the rewrite keeps every line's length");
                line.replace_range(digits..end, &older);
                aged += 1;
            }
        }
        out.push_str(&line);
        out.push('\n');
    }
    assert!(aged > 0, "the feed recorded the board's commits");
    std::fs::write(&path, out).expect("rewrite commits.log");
}

/// The age an answer carries: `(at, time, time_from)`.
fn age(v: &Value) -> (Option<u64>, Option<u64>, Option<String>) {
    for key in ["at", "time", "time_from"] {
        assert!(v.get(key).is_some(), "`{key}` is always present: {v}");
    }
    (v["at"].as_u64(), v["time"].as_u64(), v["time_from"].as_str().map(str::to_string))
}

/// `frame`'s answer at the committed position just below `at`: at `at − 1`
/// where the commit at `at` is one record, else at the boundary the history
/// door names for a composite's interior coordinate (`not_a_position`'s
/// `nearest`, wire.md §Reading history) — the state before the commit
/// either way.
fn position_below(port: u16, token: Option<&str>, at: u64, frame: &str) -> Value {
    let (st, v) = op_at(port, token, at - 1, frame);
    if st == 200 {
        return v;
    }
    assert_eq!(v["error"].as_str(), Some("not_a_position"), "{v}");
    let nearest = v["nearest"].as_u64().expect("the boundary below");
    assert!(nearest < at);
    let (st, v) = op_at(port, token, nearest, frame);
    assert_eq!(st, 200, "{v}");
    v
}

/// The whole `link_value` answer for `a`, as `token`.
fn link_value(port: u16, token: Option<&str>, a: &str) -> Value {
    let v = op(port, token, &common::read_link_frame(a));
    expect_resp(&v, "link_value");
    v
}

/// The `/changes` row at `at`, read as `token`'s class.
fn row_at(port: u16, token: Option<&str>, at: u64) -> Value {
    let (st, body) = http(port, "GET", &format!("/changes?since={}&limit=1", at - 1), token, b"");
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&body));
    let page = json(&body);
    let row = page["changes"].as_array().expect("changes").first().cloned().expect("a row");
    assert_eq!(row["at"].as_u64(), Some(at), "the row at {at}: {row}");
    row
}

/// The raw atom string at content position 1 of `doc`, read as the guest, or
/// `None` where no member or atom stands there.
fn atom_str(port: u16, doc: &str) -> Option<String> {
    let v = op(
        port,
        None,
        &format!(
            r#"{{"op":"retrieve_v","specs":[{{"doc":"{doc}","span":{{"start":"1.1","width":"0.1"}}}}]}}"#
        ),
    );
    let items = v.get("items")?.as_array()?;
    items.iter().find_map(|it| it.get("atom").and_then(Value::as_str)).map(str::to_string)
}

/// The latest time record off the bare `T`, parsed; `None` while `T` has no
/// member.
fn time_record(port: u16) -> Option<Value> {
    atom_str(port, T).and_then(|s| serde_json::from_str(&s).ok())
}

/// A link in `home` under a fresh ghost type: its address and the position
/// its commit acknowledged.
fn link_in(port: u16, session: &str, home: &str, n: u64) -> (String, u64) {
    let v = op(
        port,
        Some(session),
        &link_frame(home, r#"{"addrs":[]}"#, r#"{"addrs":[]}"#, &ghost_ty(home, n)),
    );
    (acked_addr(&v), acked_at(&v))
}

/// One committing write as `session`: a private draft; its position.
fn commit(port: u16, session: &str) -> u64 {
    acked_at(&op(
        port,
        Some(session),
        &format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"}}"#),
    ))
}

/// Drives the writers' hour through the seam: the clock at `clock`, then one
/// committing write, whose turn writes the head and the time record.
fn pass_the_hour(sd: &Skepd, session: &str, clock: u64) -> u64 {
    sd.daemon().set_head_writer_clock_millis(clock);
    commit(sd.port(), session)
}

// ── P1 THE POSITION IS THE JOURNAL'S ────────────────────────────────────────

/// (P1; D1) A document, a member minted by `version`, a member minted by a
/// shot and a link each answer `at` equal to the `/changes` row's `at` for
/// the commit that minted it — the commit's own coordinate, a composite's
/// terminal position included — and `/op-at` at `at − 1` answers the
/// address unregistered where at `at` it answers it. A member answers its
/// OWN mint, not its document's; an absent link carries no age; the
/// system account's seeded documents answer the genesis coordinate.
#[test]
fn every_minted_address_answers_the_position_of_the_commit_that_minted_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());

    // A document: one record, its commit's position.
    let created = op(port, Some(&owner), &common::create_frame(CLAIMANT_ACCOUNT, None));
    let (doc, doc_at) = (acked_addr(&created), acked_at(&created));
    let md = doc_metadata(port, Some(&owner), &doc);
    assert_eq!(age(&md).0, Some(doc_at), "the document's `at` is its commit's: {md}");
    let row = row_at(port, Some(&owner), doc_at);
    assert_eq!(row["op"].as_str(), Some("create_new_document"));
    assert_eq!(age(&md).1, row["time"].as_u64(), "the time is the row's own: {md} vs {row}");
    assert_eq!(age(&md).2.as_deref(), Some("feed"));

    // A member minted by `version` of the owner's published doc 1: a
    // two-record commit, the member's `at` its terminal position; the
    // document still answers its own.
    let versioned = version_of(port, &signed, CLAIMANT_DOC1, None);
    let (member, member_at) = (acked_addr(&versioned), acked_at(&versioned));
    assert_eq!(member, format!("{CLAIMANT_DOC1}.1"));
    let md = doc_metadata(port, None, &member);
    assert_eq!(age(&md).0, Some(member_at), "the member's `at` is its own mint's: {md}");
    let row = row_at(port, None, member_at);
    assert_eq!(row["op"].as_str(), Some("version"));
    assert_eq!(age(&md).1, row["time"].as_u64(), "{md} vs {row}");
    let doc1 = doc_metadata(port, None, CLAIMANT_DOC1);
    assert!(
        age(&doc1).0.is_some_and(|at| at < member_at),
        "the document dates its own creation: {doc1}"
    );

    // A member minted by a publish shot off that member: the shot's records
    // and the member's mint in one commit, the member's `at` the commit's.
    let shotted = op(
        port,
        Some(&signed),
        &common::publish_frame(
            CLAIMANT_DOC1,
            Some((&member, 1)),
            None,
            &[run(CLAIMANT_DOC1, ATOM, 1)],
        ),
    );
    let (shot_member, shot_at) = (acked_addr(&shotted), acked_at(&shotted));
    assert_eq!(shot_member, format!("{CLAIMANT_DOC1}.2"));
    let md = doc_metadata(port, None, &shot_member);
    assert_eq!(age(&md).0, Some(shot_at), "the shot member's `at` is the shot's commit: {md}");
    let row = row_at(port, None, shot_at);
    assert_eq!(row["op"].as_str(), Some("publish"));
    assert_eq!(row["docs"], serde_json::json!([shot_member]));
    assert_eq!(age(&md).1, row["time"].as_u64(), "{md} vs {row}");

    // A link: a composite commit, the link's `at` its terminal position.
    let (link, link_at) = link_in(port, &owner, &doc, 7);
    let lv = link_value(port, Some(&owner), &link);
    assert!(lv["link"].is_object(), "the link is read: {lv}");
    let (at, time, from) = age(&lv);
    assert_eq!(at, Some(link_at), "the link's `at` is its commit's: {lv}");
    let row = row_at(port, Some(&owner), link_at);
    assert_eq!(row["op"].as_str(), Some("make_link"));
    assert_eq!(row["link"].as_str(), Some(link.as_str()));
    assert_eq!(time, row["time"].as_u64(), "the time is the row's own: {lv} vs {row}");
    assert_eq!(from.as_deref(), Some("feed"));

    // `/op-at`: unregistered at the position below — `at − 1` where the
    // commit is one record, else the boundary the history door names for
    // the composite's interior coordinate — and answered at `at`.
    let below = position_below(port, Some(&owner), link_at, &common::read_link_frame(&link));
    assert!(below["link"].is_null() && below["at"].is_null(), "below its commit: {below}");
    let (_, at_it) = op_at(port, Some(&owner), link_at, &common::read_link_frame(&link));
    assert!(at_it["link"].is_object(), "at its commit: {at_it}");
    assert_eq!(at_it["at"].as_u64(), Some(link_at));
    let below = position_below(port, Some(&owner), doc_at, &doc_metadata_frame(&doc));
    assert_eq!(below["code"].as_str(), Some("doc_not_registered"), "below its commit: {below}");
    let (_, at_it) = op_at(port, Some(&owner), doc_at, &doc_metadata_frame(&doc));
    assert_eq!(at_it["at"].as_u64(), Some(doc_at), "at its commit: {at_it}");
    let below = position_below(port, None, shot_at, &doc_metadata_frame(&shot_member));
    assert_eq!(below["code"].as_str(), Some("doc_not_registered"), "below its commit: {below}");
    let below = position_below(port, None, member_at, &doc_metadata_frame(&member));
    assert_eq!(below["code"].as_str(), Some("doc_not_registered"), "below its commit: {below}");

    // An absent link carries no age: the guest cannot read the draft's
    // link, and absence says nothing a position would.
    let hidden = link_value(port, None, &link);
    assert!(hidden["link"].is_null(), "{hidden}");
    assert_eq!(age(&hidden), (None, None, None), "absence carries no age: {hidden}");

    // The seeded documents: the genesis coordinate, no testimony.
    let seeded = doc_metadata(port, None, H);
    assert_eq!(age(&seeded), (Some(0), None, None), "H was minted at genesis: {seeded}");
    sd.shutdown();
}

// ── P2 THE POSITION SURVIVES THE FLOOR ──────────────────────────────────────

/// (P2; D6) A board driven past three landings so the journal reclaims
/// below its floor, then restarted from its newest checkpoint, still answers
/// `at` for a link minted before the reclaimed segment — the position is
/// state the checkpoint carries, never an index over the journal — while
/// `/op-at` at that position answers `history_reclaimed`.
#[test]
fn the_position_survives_the_reclaim_floor_and_a_restart_from_the_newest_checkpoint() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (link, link_at, link_time) = {
        let sd = spawn(dir.path());
        let port = sd.port();
        let owner = open_session(port, CLAIMANT_PRINCIPAL);
        let doc = create_doc(port, &owner, CLAIMANT_ACCOUNT);
        let (link, link_at) = link_in(port, &owner, &doc, 7);
        let link_time = age(&link_value(port, Some(&owner), &link)).1.expect("the feed's time");
        let bulk = "z".repeat(262_144);
        for _ in 0..3 {
            for _ in 0..6 {
                acked_at(&op(
                    port,
                    Some(&owner),
                    &format!(
                        r#"{{"op":"insert","doc":"{doc}","at":{{"subspace":"1","ordinal":"1"}},"values":["{bulk}"]}}"#
                    ),
                ));
            }
            sd.daemon().checkpoint_now();
        }
        assert!(
            sd.daemon().last_reclaimed_bytes().is_some_and(|bytes| bytes > 0),
            "the third landing reclaimed the journal below its floor"
        );
        let (st, v) = op_at(port, Some(&owner), link_at, &common::read_link_frame(&link));
        assert_eq!((st, v["error"].as_str()), (410, Some("history_reclaimed")), "{v}");
        sd.shutdown();
        (link, link_at, link_time)
    };

    let sd = spawn(dir.path());
    let port = sd.port();
    let recovery = sd.daemon().recovery().expect("a journaled open reports");
    assert!(
        recovery.start_point.0 > link_at,
        "the restart loaded a base above the link: {recovery:?}"
    );
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let lv = link_value(port, Some(&owner), &link);
    assert!(lv["link"].is_object(), "the link is read after the restart: {lv}");
    assert_eq!(age(&lv).0, Some(link_at), "the position survived the floor: {lv}");
    assert_eq!(age(&lv).1, Some(link_time), "the feed, kept whole, still dates it: {lv}");
    let (st, v) = op_at(port, Some(&owner), link_at, &common::read_link_frame(&link));
    assert_eq!((st, v["error"].as_str()), (410, Some("history_reclaimed")), "{v}");
    sd.shutdown();
}

// ── P3 THE TIME, EXACT AND ANCHORED ─────────────────────────────────────────

/// (P3; D3) Where the feed holds the row, `time` is the row's own and
/// `time_from` is `"feed"`; with the feed lost and a time record standing
/// below the link, `time_from` is `"anchor"` and `time` is the record's —
/// at or below the recorded time, within the hour; and with no record yet
/// (a board younger than an hour), `time` and `time_from` are `null` while
/// `at` is still answered. The hour passes on the wall clock: the feed's
/// recorded times are aged two hours before a reopen, so the first write's
/// turn writes the record with the clock the feed stamps the link with.
#[test]
fn the_time_is_the_feeds_row_where_held_and_the_hours_anchor_where_lost() {
    let dir = tempfile::tempdir().expect("tempdir");
    {
        let sd = spawn(dir.path());
        assert!(
            time_record(sd.port()).is_none(),
            "a board younger than an hour holds no time record"
        );
        sd.shutdown();
    }
    age_the_feed(dir.path(), 2 * HOUR_MILLIS);
    let (link, link_at, recorded, anchor_time) = {
        let sd = spawn(dir.path());
        let port = sd.port();
        let owner = open_session(port, CLAIMANT_PRINCIPAL);
        // An hour and more on the wall clock since the board's first commit,
        // as the feed now testifies: the first write's turn writes the head
        // and then the time record, at the wall clock.
        let before = clock_origin();
        commit(port, &owner);
        let record = time_record(port).expect("the hour's record stands");
        assert_eq!(record["type"].as_str(), Some("skep-time"), "{record}");
        let anchor_time = record["time"].as_u64().expect("the record's time");
        assert!(
            anchor_time >= before,
            "the record carries the daemon's clock at the write: {record}"
        );
        let doc = create_doc(port, &owner, CLAIMANT_ACCOUNT);
        let (link, link_at) = link_in(port, &owner, &doc, 7);
        let lv = link_value(port, Some(&owner), &link);
        let (at, time, from) = age(&lv);
        let recorded =
            row_at(port, Some(&owner), link_at)["time"].as_u64().expect("the row's time");
        assert_eq!(
            (at, time, from.as_deref()),
            (Some(link_at), Some(recorded), Some("feed")),
            "{lv}"
        );
        sd.shutdown();
        (link, link_at, recorded, anchor_time)
    };

    lose_the_feed(dir.path());
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let lv = link_value(port, Some(&owner), &link);
    let (at, time, from) = age(&lv);
    assert_eq!(at, Some(link_at), "the position survived the lost feed: {lv}");
    assert_eq!(from.as_deref(), Some("anchor"), "the feed's row is gone: {lv}");
    let time = time.expect("the anchor's time");
    assert_eq!(time, anchor_time, "the newest record at or below the link: {lv}");
    assert!(
        time <= recorded,
        "the anchor stands at or below the recorded time: {time} vs {recorded}"
    );
    assert!(recorded - time < HOUR_MILLIS, "within the hour: {time} vs {recorded}");
    sd.shutdown();

    // No record yet: `at` answered, the time unknown.
    let young = tempfile::tempdir().expect("tempdir");
    let (link, link_at) = {
        let sd = spawn(young.path());
        let port = sd.port();
        let owner = open_session(port, CLAIMANT_PRINCIPAL);
        let doc = create_doc(port, &owner, CLAIMANT_ACCOUNT);
        let (link, link_at) = link_in(port, &owner, &doc, 7);
        sd.shutdown();
        (link, link_at)
    };
    lose_the_feed(young.path());
    let sd = spawn(young.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let lv = link_value(port, Some(&owner), &link);
    assert!(lv["link"].is_object(), "{lv}");
    assert_eq!(age(&lv), (Some(link_at), None, None), "no testimony holds a reading: {lv}");
    sd.shutdown();
}

// ── P4 THE HEAD UNCHANGED ───────────────────────────────────────────────────

/// (P4; D3 (c), the owner's "b") Two daemons under one seed and one op
/// sequence, their clocks driven through the seam to one reading, each
/// writing three hour records, write byte-identical heads and chains: the
/// time rides its own record and never `H`. The record carries its three
/// members in order and `type: "skep-time"`; it is written at most once an
/// hour, never while the position stands still, and never twice for one
/// position; its document is published from birth and guest-readable.
#[test]
fn the_head_is_untouched_by_the_hour_record_which_lands_hourly_and_only_when_the_position_moved() {
    const ONE_SEED: u64 = 0x11;
    let origin = clock_origin();
    let a = tempfile::tempdir().expect("tempdir");
    let b = tempfile::tempdir().expect("tempdir");
    let board = |dir: &Path| -> (String, Vec<Value>, Vec<(u64, String)>) {
        let sd = spawn_seeded(dir, ONE_SEED);
        let port = sd.port();
        let owner = open_session(port, CLAIMANT_PRINCIPAL);
        let mut records = Vec::new();
        for k in 1..=3u64 {
            let position = pass_the_hour(&sd, &owner, origin + k * (HOUR_MILLIS + MINUTE_MILLIS));
            let raw = atom_str(port, T).expect("the record stands");
            assert!(
                raw.starts_with(r#"{"type":"skep-time","position":"#) && raw.ends_with('}'),
                "the members in schema order: {raw}"
            );
            let record: Value = serde_json::from_str(&raw).expect("one JSON object");
            assert_eq!(record.as_object().map(|m| m.len()), Some(3), "three members: {raw}");
            assert!(record.get("sig").is_none(), "unsigned: {raw}");
            assert!(
                record["position"].as_u64().expect("position") > position,
                "the record names the head after the head's own commits: {raw}"
            );
            assert_eq!(
                record["time"].as_u64(),
                Some(origin + k * (HOUR_MILLIS + MINUTE_MILLIS)),
                "{raw}"
            );
            records.push(record);
        }
        // At most once an hour: half an hour on, a commit writes none.
        let before = atom_str(port, T);
        pass_the_hour(&sd, &owner, origin + 3 * (HOUR_MILLIS + MINUTE_MILLIS) + HOUR_MILLIS / 2);
        assert_eq!(atom_str(port, T), before, "no record under the hour");
        // Never while the position stands still: an hour on, a read moves
        // nothing and writes nothing; the next commit writes one.
        sd.daemon().set_head_writer_clock_millis(origin + 5 * (HOUR_MILLIS + MINUTE_MILLIS));
        let _ = doc_metadata(port, None, T);
        assert_eq!(atom_str(port, T), before, "a read brings no record");
        pass_the_hour(&sd, &owner, origin + 5 * (HOUR_MILLIS + MINUTE_MILLIS));
        assert_ne!(atom_str(port, T), before, "the commit after the hour brings one");
        // Published from birth, guest-readable: the document and its members.
        let md = doc_metadata(port, None, T);
        assert_eq!(md["published"].as_bool(), Some(true), "{md}");
        assert_eq!(md["owner"].as_str(), Some("1.1.0.1"), "{md}");
        assert_eq!(md["birth"].as_str(), Some(&*format!("{T}.1")), "{md}");
        assert!(atom_str(port, &format!("{T}.4")).is_some(), "four records, each its own member");
        assert!(atom_str(port, &format!("{T}.5")).is_none(), "and no fifth");
        let head = atom_str(port, H).expect("a head");
        let live_head = common::head_position(port);
        let chains: Vec<(u64, String)> = (1..=live_head)
            .filter_map(|at| {
                let (st, body) = get(port, &format!("/chain?at={at}"));
                (st == 200).then(|| (at, json(&body)["chain"].as_str().expect("chain").to_string()))
            })
            .collect();
        sd.shutdown();
        (head, records, chains)
    };
    let (head_a, records_a, chains_a) = board(a.path());
    let (head_b, records_b, chains_b) = board(b.path());
    assert_eq!(head_a, head_b, "one op sequence under one seed writes one head byte string");
    assert_eq!(chains_a, chains_b, "one chain at every committed position");
    let head: Value = serde_json::from_str(&head_a).expect("a head record");
    assert!(head.get("time").is_none(), "no timestamp rides the head: {head}");
    assert_eq!(head["type"].as_str(), Some("skep-head"));
    assert_eq!(records_a, records_b, "the records are one sequence on both boards");
}

// ── P5 DETERMINISM ──────────────────────────────────────────────────────────

/// (P5) The map `world_at(head)` folds from genesis equals the live world's
/// entry for entry — every `at` of `/op-at` at the head is `/op`'s, byte for
/// byte — and a checkpoint written and reloaded reproduces it.
#[test]
fn the_position_map_is_the_same_live_from_genesis_and_from_a_checkpoint() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let doc = create_doc(port, &owner, CLAIMANT_ACCOUNT);
    let member = acked_addr(&version_of(port, &signed, CLAIMANT_DOC1, None));
    let shot_member = shot(
        port,
        &signed,
        CLAIMANT_DOC1,
        Some((&member, 1)),
        None,
        &[run(CLAIMANT_DOC1, ATOM, 1)],
    );
    let (link, _) = link_in(port, &owner, &doc, 7);
    let (link2, _) = link_in(port, &owner, &doc, 8);
    let frames: Vec<String> = vec![
        doc_metadata_frame(&doc),
        doc_metadata_frame(&member),
        doc_metadata_frame(&shot_member),
        doc_metadata_frame(H),
        common::read_link_frame(&link),
        common::read_link_frame(&link2),
    ];
    let head = common::head_position(port);
    let live_and_derived = |port: u16, owner: &str| -> Vec<String> {
        frames
            .iter()
            .map(|frame| {
                let live = op(port, Some(owner), frame);
                let (st, derived) = op_at(port, Some(owner), head, frame);
                assert_eq!(st, 200, "{derived}");
                assert_eq!(live, derived, "`/op-at` at the head is `/op`: {frame}");
                assert!(live["at"].is_u64(), "every address answers its position: {live}");
                live.to_string()
            })
            .collect()
    };
    let first = live_and_derived(port, &owner);
    sd.daemon().checkpoint_now();
    sd.shutdown();

    let sd = spawn(dir.path());
    let port = sd.port();
    let recovery = sd.daemon().recovery().expect("a journaled open reports");
    assert_eq!(recovery.start_point.0, head, "the restart loaded the checkpoint at the head");
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    assert_eq!(live_and_derived(port, &owner), first, "the checkpoint reproduces every position");
    sd.shutdown();
}

// ── P8 #516'S CASE ──────────────────────────────────────────────────────────

/// (P8; skep #516) A client session that opens on a board of three thousand
/// positions reads `read_link` on the first link made and is answered its
/// `at` and a `time` — one read, no feed walk.
#[test]
fn a_session_opening_on_a_board_of_three_thousand_positions_dates_the_first_link_in_one_read() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let doc = create_doc(port, &owner, CLAIMANT_ACCOUNT);
    let (link, link_at) = link_in(port, &owner, &doc, 7);
    let recorded = row_at(port, Some(&owner), link_at)["time"].as_u64().expect("the row's time");
    let mut ordinal = 1;
    while common::head_position(port) < 3_000 {
        expect_resp(&insert_text(port, &owner, &doc, ordinal, "x"), "ack_addr");
        ordinal += 1;
    }
    assert!(common::head_position(port) >= 3_000);

    // The client opens: a fresh session, holding no feed, reads the link.
    let client = open_session(port, CLAIMANT_PRINCIPAL);
    let began = Instant::now();
    let lv = link_value(port, Some(&client), &link);
    let took = began.elapsed();
    let (at, time, from) = age(&lv);
    assert_eq!((at, time, from.as_deref()), (Some(link_at), Some(recorded), Some("feed")), "{lv}");
    assert!(took.as_secs() < 2, "one read, no feed walk: {took:?}");
    sd.shutdown();
}
