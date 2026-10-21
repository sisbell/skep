//! THE PRUNER over the wire (`media.md` Op inventory 1, "Unreferenced blobs
//! … are prunable sidecar garbage … pruning checks reference absence, in
//! the cell index"; Op inventory 2, "ONE FILE PER ACQUISITION — re-read,
//! unlink, release"; the rulings ms5-R and ms5-T4): THE PASS and what it
//! takes, keeps and halts on, driven through the daemon's hook rather than
//! its cadence; THE DRAIN under the credential lock's exclusive arm, a
//! retirement committing while a pass runs; and the drain's timing,
//! reported.
//!
//! Every test names the register's clause it holds: M-I5 (b) NO
//! HOUSEKEEPING ACT CREATES AN R59 HOLE; M-I5 (f) PICTURES NEVER STARVE OR
//! STALL THE JOURNAL; M-I6 (a) RECORD-DERIVED, ONCE, IDENTICAL EVERYWHERE;
//! M-I6 (c) EVERY BYTE UNDER `blobs/` IS SOMEONE'S; ms5-T4, DOCTRINE D13's
//! carve-out — the pruner halts on a schema it does not know.

use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use skep_blobs::{HashFunction, Store};
use skep_identity::{encode_retire, Fingerprint};

use crate::common;
use crate::media::{seed_pre_fence_draft, unknown_schema_value};
use common::*;

/// The lease interval the fixtures' daemon runs under, seven days.
const LEASE_MS: u64 = 7 * 24 * 3600 * 1000;

/// The blobs directory of the pinned designation.
fn blobs_dir(dir: &Path) -> std::path::PathBuf {
    dir.join("blobs").join("blake3")
}

/// The deposit read's two figures, `(base, pending)`.
fn usage_of(port: u16, token: &str) -> (u64, u64) {
    let (st, _, body) = blob_deposit_read(port, Some(token));
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&body));
    let v = json(&body);
    (v["base"].as_u64().expect("base"), v["pending"].as_u64().expect("pending"))
}

/// A retire record naming `fps`, as its atom JSON fragment.
fn retire_atom(fps: &[&str]) -> String {
    let parsed: Vec<Fingerprint> =
        fps.iter().map(|h| Fingerprint::parse_hex(h).expect("64 hex")).collect();
    json_atom(&encode_retire(&parsed))
}

/// ONE CREDENTIAL RETIREMENT from the anchor's session: the device key's
/// retire record landed in the claimant's doc 1 and deposited — the
/// `make_link` the credential sequence runs under the credential lock's
/// WRITE arm. Answers the deposit's answer.
fn retire_the_device_key(port: u16, anchor: &str) -> serde_json::Value {
    let device_fp = Fingerprint::of(&public_key_of(&device_key())).to_hex();
    let ordinal = next_content_ordinal(port, Some(anchor), CLAIMANT_DOC1);
    let atom = signed_atom(port, anchor, CLAIMANT_DOC1, T_RETIRE, &[CLAIMANT_ACCOUNT], &retire_atom(&[&device_fp]));
    let v = op(
        port,
        Some(anchor),
        &format!(
            r#"{{"op":"insert","doc":"{CLAIMANT_DOC1}","at":{{"subspace":"1","ordinal":"{ordinal}"}},"values":[{{"atom":{atom}}}],"deposit":"{T_RETIRE}"}}"#
        ),
    );
    expect_resp(&v, "ack_addr");
    let atom_addr = format!("{CLAIMANT_DOC1}.0.1.{ordinal}");
    op(
        port,
        Some(anchor),
        &format!(
            r#"{{"op":"make_link","home":"{CLAIMANT_DOC1}","from":{{"addrs":["{atom_addr}"]}},"to":{{"addrs":["{CLAIMANT_ACCOUNT}"]}},"ty":{{"addrs":["{T_RETIRE}"]}}}}"#
        ),
    )
}

/// M-I5 (b), M-I6 (c) — THE PASS's THREE VERDICTS: a lapsed, unreferenced
/// file goes; a lapsed file a cell names stays — a reference, kept by no
/// lease; a live, unreferenced file stays — held by its lease; and the
/// deposit read's two figures move with them: the named hash in the base
/// and not the pending, the live lease in the pending. A second pass
/// unlinks nothing more. The pass is the hook's, the cadence's twin.
#[test]
fn a_pass_unlinks_the_lapsed_unreferenced_files_alone() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let token = open_session(port, CLAIMANT_PRINCIPAL);
    let referenced = seeded_bytes(3_000, 1);
    let unreferenced = seeded_bytes(4_000, 2);
    let live = seeded_bytes(5_000, 3);
    put_whole(port, &token, &referenced);
    put_whole(port, &token, &unreferenced);
    let draft = owner_draft(port, &token);
    assert_eq!(insert_cell(port, &token, &draft, &referenced, 3_000), "ok");
    assert_eq!(usage_of(port, &token), (3_000, 4_000), "the named hash in the base, the other lease pending");
    sd.daemon().advance_media_clock_ms(LEASE_MS);
    put_whole(port, &token, &live);
    assert_eq!(usage_of(port, &token), (3_000, 5_000), "the lapsed lease counts nothing; the live one pends");
    let pass = sd.daemon().prune_now().expect("the index is ready");
    assert_eq!(pass.unlinked, 1, "{pass:?}");
    assert_eq!(pass.kept, 2, "{pass:?}");
    assert_eq!(pass.halted, None, "{pass:?}");
    assert_eq!(pass.asides, 0, "the pass's own aside is unlinked after the arm, counted as the file's unlink: {pass:?}");
    assert_eq!(pass.freed, 4_000, "the unlinked file's bytes, what the pass reclaimed: {pass:?}");
    assert!(pass.to_string().starts_with("pruner: 0 expired partials removed, 1 files unlinked, 2 kept, 0 asides removed, 4000 bytes freed"), "{pass}");
    let blobs = blobs_dir(dir.path());
    assert!(blobs.join(blob_hex(&referenced)).is_file(), "named by a cell: kept past its lease");
    assert!(!blobs.join(blob_hex(&unreferenced)).exists(), "lapsed and unreferenced: gone");
    assert!(!fs::read_dir(&blobs).unwrap().any(|e| e.unwrap().file_name().to_string_lossy().starts_with(".retired-")), "renamed aside under the arm, unlinked after it: no aside stands");
    assert!(blobs.join(blob_hex(&live)).is_file(), "held by a live lease: kept");
    let again = sd.daemon().prune_now().expect("the index is ready");
    assert_eq!((again.unlinked, again.kept, again.freed), (0, 2, 0), "{again:?}");
    assert_eq!(usage_of(port, &token), (3_000, 5_000), "the scopes read the record, never the directory");
    // The owner's cell over the kept file is admitted still — the index
    // arm, the lease long lapsed.
    assert_eq!(insert_cell(port, &token, &owner_draft(port, &token), &referenced, 3_000), "ok");
    sd.shutdown();
}

/// (4) REMOVED ON EXPIRY, while the daemon serves (M-I6 (c)): an expired
/// upload's partial goes at the pass and a standing one survives it with
/// its offset; the pass reads the record's expiry and the hold, and no
/// reference.
#[test]
fn a_pass_removes_the_expired_partials_and_keeps_the_standing_ones() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let token = open_session(port, CLAIMANT_PRINCIPAL);
    let (st, _, resp) = blob_create(port, Some(&token), 10, b"hello");
    assert_eq!(st, 200);
    let standing = json(&resp)["upload"].as_str().unwrap().to_string();
    sd.daemon().install_media_limits(None, None, Some(1_000), None, None).expect("installs");
    let (st, _, resp) = blob_create(port, Some(&token), 10, b"hello");
    assert_eq!(st, 200);
    let expiring = json(&resp)["upload"].as_str().unwrap().to_string();
    sd.daemon().install_media_limits(None, None, None, None, None).expect("installs");
    sd.daemon().advance_media_clock_ms(2_000);
    let blobs = blobs_dir(dir.path());
    assert!(blobs.join(format!(".upload-{expiring}")).is_file(), "stands until a pass");
    let pass = sd.daemon().prune_now().expect("the index is ready");
    assert_eq!(pass.expired_partials, 1, "{pass:?}");
    assert_eq!(pass.freed, 5, "the expired partial's five bytes freed, the line's figure: {pass:?}");
    assert_eq!(pass.unlinked, 0);
    assert!(!blobs.join(format!(".upload-{expiring}")).exists(), "the expired partial is gone");
    assert!(blobs.join(format!(".upload-{standing}")).is_file(), "the standing one survives");
    let (st, _, resp) = blob_progress(port, Some(&token), &standing);
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&resp));
    assert_eq!(json(&resp)["offset"].as_u64(), Some(5));
    let (st, _, _) = blob_progress(port, Some(&token), &expiring);
    assert_eq!(st, 404, "the expired identifier answers no upload");
    let (st, _, resp) = blob_resume(port, Some(&token), &standing, 5, b"world");
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&resp));
    sd.shutdown();
}

/// ms5-T4, D13's carve-out — A FOREIGN DESIGNATION DIRECTORY under `blobs/`
/// halts the unlink pass before its first unlink, the report naming the
/// directory, while the expired partials go regardless; the directory
/// removed, the next pass unlinks.
#[test]
fn a_foreign_designation_directory_halts_the_unlink_pass_and_the_partials_still_go() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let token = open_session(port, CLAIMANT_PRINCIPAL);
    let lapsing = seeded_bytes(2_000, 7);
    put_whole(port, &token, &lapsing);
    sd.daemon().install_media_limits(None, None, Some(1_000), None, None).expect("installs");
    let (st, _, resp) = blob_create(port, Some(&token), 10, b"hello");
    assert_eq!(st, 200);
    let expiring = json(&resp)["upload"].as_str().unwrap().to_string();
    sd.daemon().install_media_limits(None, None, None, None, None).expect("installs");
    let foreign = dir.path().join("blobs").join("sha256-tree");
    fs::create_dir_all(&foreign).expect("the planted directory");
    sd.daemon().advance_media_clock_ms(LEASE_MS);
    let pass = sd.daemon().prune_now().expect("the index is ready");
    let why = pass.halted.clone().expect("halted on the foreign directory");
    assert!(why.contains("blobs/sha256-tree/"), "{why}");
    assert!(why.contains("blake3"), "names the pinned set: {why}");
    assert_eq!(pass.unlinked, 0, "nothing unlinked under a halt: {pass:?}");
    assert_eq!(pass.expired_partials, 1, "the partials go regardless: {pass:?}");
    let blobs = blobs_dir(dir.path());
    assert!(blobs.join(blob_hex(&lapsing)).is_file(), "the lapsed file stands under the halt");
    assert!(!blobs.join(format!(".upload-{expiring}")).exists());
    fs::remove_dir(&foreign).expect("the directory removed");
    let pass = sd.daemon().prune_now().expect("the index is ready");
    assert_eq!(pass.halted, None, "{pass:?}");
    assert_eq!(pass.unlinked, 1, "{pass:?}");
    assert!(!blobs.join(blob_hex(&lapsing)).exists());
    sd.shutdown();
}

/// ms5-T4, D13's carve-out — A HALT MARK: a value naming the kind under no
/// schema this build reads, which the door refuses at its own insert and so
/// reaches a board only from another build's writing — planted through the
/// engine with the daemon stopped — is entered at the reopen's walk as a
/// halt mark, counts in no base, and halts the unlink pass, the report
/// naming the schema; the lapsed file stands; a cell beside it is indexed
/// and keeps its own file.
#[test]
fn a_value_naming_the_kind_under_no_schema_halts_the_unlink_pass() {
    let dir = tempfile::tempdir().expect("tempdir");
    let lapsing = seeded_bytes(2_500, 9);
    let referenced = seeded_bytes(2_600, 10);
    {
        let sd = spawn(dir.path());
        let port = sd.port();
        let token = open_session(port, CLAIMANT_PRINCIPAL);
        put_whole(port, &token, &lapsing);
        put_whole(port, &token, &referenced);
        let draft = owner_draft(port, &token);
        assert_eq!(insert_cell(port, &token, &draft, &referenced, 2_600), "ok");
        assert_eq!(usage_of(port, &token), (2_600, 2_500));
        sd.shutdown();
    }
    seed_pre_fence_draft(dir.path(), CLAIMANT_PRINCIPAL, CLAIMANT_ACCOUNT, unknown_schema_value().as_bytes());
    let sd = spawn(dir.path());
    let port = sd.port();
    let token = open_session(port, CLAIMANT_PRINCIPAL);
    assert_eq!(sd.daemon().index_counts(), (1, 1, 1), "one cell, one hash, one halt mark");
    assert_eq!(usage_of(port, &token), (2_600, 2_500), "a halt mark counts in no base");
    sd.daemon().advance_media_clock_ms(LEASE_MS);
    let pass = sd.daemon().prune_now().expect("the index is ready");
    let why = pass.halted.clone().expect("halted on the halt mark");
    assert!(why.contains("unknown_cell_schema") && why.contains("1.1.0.1.0.1.0.3.89"), "{why}");
    assert_eq!(pass.unlinked, 0, "{pass:?}");
    let blobs = blobs_dir(dir.path());
    assert!(blobs.join(blob_hex(&lapsing)).is_file(), "the lapsed file stands under the halt");
    assert!(blobs.join(blob_hex(&referenced)).is_file());
    sd.shutdown();
}

/// M-I5 (f) — THE DRAIN UNDER THE ARM, untimed: a pass over a lapsed tail of
/// files holds the credential lock's exclusive arm one file at a time, so
/// a credential retirement from another thread commits while the pass
/// runs, and plain inserts from a third go on; every unreferenced file is
/// gone when the pass ends, the referenced one stands.
#[test]
fn a_retirement_commits_while_a_pass_drains() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let anchor = open_signed_session(port, CLAIMANT_PRINCIPAL, &anchor_key());
    let referenced = seeded_bytes(1_000, 100);
    put_whole(port, &bare, &referenced);
    let draft = owner_draft(port, &bare);
    assert_eq!(insert_cell(port, &bare, &draft, &referenced, 1_000), "ok");
    let tail: Vec<Vec<u8>> = (0..60).map(|i| seeded_bytes(20_000 + i, 200 + i as u64)).collect();
    for bytes in &tail {
        put_whole(port, &bare, bytes);
    }
    sd.daemon().advance_media_clock_ms(LEASE_MS);
    let daemon = sd.daemon();
    let (pass, retirement, inserts) = thread::scope(|s| {
        let pass = s.spawn(|| daemon.prune_now().expect("ready"));
        let retirement = s.spawn(|| retire_the_device_key(port, &anchor));
        let inserts = s.spawn(|| {
            let d = owner_draft(port, &bare);
            (1..=20).map(|i| verdict(&insert_text(port, &bare, &d, i, "x"))).collect::<Vec<_>>()
        });
        (pass.join().expect("the pass"), retirement.join().expect("the retirement"), inserts.join().expect("the inserts"))
    });
    expect_resp(&retirement, "ack_addr");
    assert!(inserts.iter().all(|v| v == "ok"), "{inserts:?}");
    assert_eq!(pass.unlinked, 60, "{pass:?}");
    assert_eq!(pass.kept, 1, "{pass:?}");
    let blobs = blobs_dir(dir.path());
    assert!(blobs.join(blob_hex(&referenced)).is_file());
    assert!(tail.iter().all(|b| !blobs.join(blob_hex(b)).exists()));
    // The retirement landed: `key_set` lists the device key as retired.
    let device_fp = Fingerprint::of(&public_key_of(&device_key())).to_hex();
    let v = op(port, None, &format!(r#"{{"op":"key_set","account":"{CLAIMANT_ACCOUNT}"}}"#));
    let retired: Vec<String> = v["retired"]
        .as_array()
        .unwrap_or_else(|| panic!("retired: {v}"))
        .iter()
        .map(|e| e["fingerprint"].as_str().expect("fp").to_string())
        .collect();
    assert!(retired.contains(&device_fp), "the retirement committed under the drain: {v}");
    sd.shutdown();
}

/// THE REPLACE's DEFERRED STEP (mb-K2) meets the pass: a replace over the
/// wire answers with the old instance still linked at its aside name,
/// which the transport's deferred step unlinks after the answer; an aside
/// that step did not reach — planted, as a crash between the answer and
/// the unlink leaves one — is removed by the pass under its arm, named by
/// nothing; the file at the hash is the new bytes throughout.
#[test]
fn a_pass_sweeps_an_aside_the_deferred_step_did_not_reach() {
    let dir = tempfile::tempdir().expect("tempdir");
    let blobs = blobs_dir(dir.path());
    let right = seeded_bytes(1_234, 11);
    let hex = blob_hex(&right);
    {
        // Planted with the daemon stopped: the wrong bytes at the right name.
        let store = Store::open(dir.path().join("blobs"), Duration::from_millis(1), 0).expect("the store opens");
        store.install("blake3", &hex, b"the wrong bytes under the right name").unwrap();
    }
    let sd = spawn(dir.path());
    let port = sd.port();
    let token = open_session(port, CLAIMANT_PRINCIPAL);
    put_whole(port, &token, &right);
    assert_eq!(fs::read(blobs.join(&hex)).unwrap(), right, "replaced: the right bytes at the name");
    let aside_stands = || {
        fs::read_dir(&blobs).unwrap().any(|e| e.unwrap().file_name().to_string_lossy().starts_with(".retired-"))
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    while aside_stands() {
        assert!(Instant::now() < deadline, "the transport's deferred step did not unlink the aside");
        thread::sleep(Duration::from_millis(10));
    }
    // An aside the deferred step did not reach.
    fs::write(blobs.join(format!(".retired-{hex}-99")), b"the wrong bytes under the right name").unwrap();
    assert!(aside_stands());
    let pass = sd.daemon().prune_now().expect("ready");
    assert_eq!(pass.asides, 1, "{pass:?}");
    assert_eq!(pass.freed, 36, "the aside's 36 bytes freed, the line's figure: {pass:?}");
    assert_eq!(pass.unlinked, 0, "the leased file stands: {pass:?}");
    assert!(!aside_stands(), "swept by the pass");
    assert_eq!(fs::read(blobs.join(&hex)).unwrap(), right);
    assert_eq!(deposits_of(port, &token), vec![(hex.clone(), 1_234, false)]);
    sd.shutdown();
}

/// THE LOGS' COMPACTION BY THE PASS (P22; M-I5 (f); `media.md` §The media
/// stores, "the pruner's pass rewrites either store the same way once its
/// log has passed a size trigger"; s6-lam-f): one file re-PUT 1,030 times
/// leaves a lease log of 1,030 lines over one lease (each line replacing
/// the last) and a records' log of 2,063 lines over 3 standing uploads
/// (each PUT a creation and a retirement) — both past 1,024 and past four
/// times their records — and the next pass rewrites each to its current
/// records, under no arm, its line naming both by their names under the
/// data directory, each log's size after and the size it was rewritten
/// from, every figure the file's own; a record appended after the rewrite
/// lands in the new file, so the reopen lists every standing upload; a log
/// under the minimum is left alone by the pass after, whatever its ratio,
/// its line saying the logs' sizes and no compaction; and no log has
/// stopped.
#[test]
fn a_pass_compacts_a_log_past_its_trigger_and_leaves_a_small_one_alone() {
    let dir = tempfile::tempdir().expect("tempdir");
    let logs = dir.path().join("blobs");
    let lines = |name: &str| fs::read_to_string(logs.join(name)).unwrap().lines().count();
    let log_bytes = |name: &str| fs::metadata(logs.join(name)).unwrap().len();
    let standing: Vec<String> = {
        let sd = spawn(dir.path());
        let port = sd.port();
        let token = open_session(port, CLAIMANT_PRINCIPAL);
        let mut standing = Vec::new();
        for _ in 0..3 {
            let (st, _, resp) = blob_create(port, Some(&token), 10, b"");
            assert_eq!(st, 200);
            standing.push(json(&resp)["upload"].as_str().unwrap().to_string());
        }
        // One file re-PUT 1,030 times: 1,030 lease lines over one lease,
        // and 2,060 record lines — each PUT's creation and retirement —
        // that fold to nothing.
        let bytes = seeded_bytes(100, 5);
        for _ in 0..1_030 {
            put_whole(port, &token, &bytes);
        }
        assert_eq!(lines("uploads.log"), 3 + 2 * 1_030, "the records' log before the pass");
        assert_eq!(lines("leases.log"), 1_030, "the lease log before the pass");
        let (uploads_before, leases_before) = (log_bytes("uploads.log"), log_bytes("leases.log"));
        let pass = sd.daemon().prune_now().expect("ready");
        let from = |s: &Option<skep_blobs::LogSize>| s.as_ref().map(|s| (s.lines, s.bytes));
        assert_eq!(from(&pass.compacted.0), Some((2_063, uploads_before)), "rewritten from the file: {pass:?}");
        assert_eq!(from(&pass.compacted.1), Some((1_030, leases_before)), "rewritten from the file: {pass:?}");
        assert_eq!(pass.compaction_failed, None, "{pass:?}");
        assert_eq!(pass.stopped, (None, None), "{pass:?}");
        assert_eq!(lines("uploads.log"), 3, "rewritten to the standing records");
        assert_eq!(lines("leases.log"), 1, "rewritten to the one lease");
        let size = |s: &skep_blobs::LogSize| (s.name.clone(), s.lines, s.bytes);
        assert_eq!(size(&pass.logs.0), ("blobs/uploads.log".into(), 3, log_bytes("uploads.log")), "{pass:?}");
        assert_eq!(size(&pass.logs.1), ("blobs/leases.log".into(), 1, log_bytes("leases.log")), "{pass:?}");
        assert!(
            pass.to_string().ends_with(&format!(
                "; blobs/uploads.log 3 lines ({} bytes) — compacted from 2063 lines ({uploads_before} bytes); \
                 blobs/leases.log 1 lines ({} bytes) — compacted from 1030 lines ({leases_before} bytes)",
                log_bytes("uploads.log"),
                log_bytes("leases.log")
            )),
            "the line names each log, its size and the size it was rewritten from: {pass}"
        );
        // An append after the rewrite lands in the new file.
        let (st, _, resp) = blob_create(port, Some(&token), 10, b"");
        assert_eq!(st, 200);
        standing.push(json(&resp)["upload"].as_str().unwrap().to_string());
        assert_eq!(lines("uploads.log"), 4);
        let again = sd.daemon().prune_now().expect("ready");
        assert_eq!(again.compacted, (None, None), "under the minimum, left alone: {again:?}");
        assert!(!again.to_string().contains("compacted"), "{again}");
        assert!(
            again.to_string().ends_with(&format!(
                "; blobs/uploads.log 4 lines ({} bytes); blobs/leases.log 1 lines ({} bytes)",
                log_bytes("uploads.log"),
                log_bytes("leases.log")
            )),
            "every pass says the logs' sizes: {again}"
        );
        assert_eq!(deposits_of(port, &token).len(), 1);
        sd.shutdown();
        standing
    };
    let sd = spawn(dir.path());
    let port = sd.port();
    let token = open_session(port, CLAIMANT_PRINCIPAL);
    let (st, _, body) = blob_deposit_read(port, Some(&token));
    assert_eq!(st, 200);
    let listed: Vec<String> = json(&body)["uploads"].as_array().unwrap().iter().map(|u| u["upload"].as_str().unwrap().to_string()).collect();
    let mut want = standing.clone();
    want.sort();
    let mut got = listed;
    got.sort();
    assert_eq!(got, want, "every standing upload, the one appended after the rewrite among them, listed after the reopen");
    sd.shutdown();
}

/// The row 35 lines the daemon has said — `failure: pruner: the pass
/// failed: …` — in order, each with the pass's duration read off its end
/// ([`without_the_pass_duration`]).
fn pass_failures(sd: &skepd::Skepd) -> Vec<String> {
    sd.daemon()
        .lines_said()
        .into_iter()
        .filter(|l| l.starts_with("failure: pruner: the pass failed: "))
        .map(|l| without_the_pass_duration(&l))
        .collect()
}

/// A row 35 line with the pass's duration — `; the pass took {d} ms`, its
/// end, the one figure no test can fix — read off and judged a whole number
/// of milliseconds, and the rest of the line handed back for its pin.
fn without_the_pass_duration(line: &str) -> String {
    let (rest, took) = line
        .rsplit_once("; the pass took ")
        .unwrap_or_else(|| panic!("the pass's line says how long the pass took: {line}"));
    let ms = took.strip_suffix(" ms").unwrap_or_else(|| panic!("…in milliseconds, last: {line}"));
    ms.parse::<u128>()
        .unwrap_or_else(|e| panic!("{ms:?} is no whole number of milliseconds ({e}): {line}"));
    rest.to_string()
}

/// `dir` made UNREADABLE — mode `0300`, searched and written but never read
/// — for the guard's life, its mode restored as the guard drops, a failing
/// claim's unwind included, so no directory under the temp dir is left
/// unreadable. The jsonl suite's own injection: a compaction's twin is
/// created and renamed over the log, and the directory's open for its fsync
/// fails, so the compaction fails PAST its rename and the log stops.
#[cfg(unix)]
struct Unreadable<'a> {
    dir: &'a Path,
    mode: fs::Permissions,
}

#[cfg(unix)]
impl<'a> Unreadable<'a> {
    fn new(dir: &'a Path) -> Unreadable<'a> {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(dir).expect("the directory").permissions();
        fs::set_permissions(dir, fs::Permissions::from_mode(0o300)).expect("the mode set");
        Unreadable { dir, mode }
    }
}

#[cfg(unix)]
impl Drop for Unreadable<'_> {
    fn drop(&mut self) {
        let _ = fs::set_permissions(self.dir, self.mode.clone());
    }
}

/// Checks that a failed step never skips the compaction that lifts a stop.
///
/// `operations.md` §4 row 5; §1.1 row 35: every step runs past another's
/// failure — but (c) past (b)'s, which halts the unlink pass — and step (d)
/// on every exit, so no failure costs the pass another step's room.
///
/// **The stop.** The records' log is driven past its trigger (512 creations
/// each ended — 1,024 retired lines over one standing record, past the
/// minimum and past four times its records), beside a deposit no cell names
/// on a one-second lease, lapsed by the clock once the cadence's first pass
/// has ended; then a pass runs with `blobs/` unreadable. That pass fails at
/// step (b)'s read of the designation directories, so its unlink pass halts
/// on the halts unread and the lapsed deposit stands; its (d) runs
/// regardless and the compaction fails past its rename, so `uploads.log`
/// stops. Its line 35 names the failure, the halt, each log's size — the
/// records' log the rewrite's, the file at its name — and the stop with its
/// cause, the rewrite's failed fsync, its age and no append refused yet.
///
/// **The standing expired upload.** Created before the stop on a ten-minute
/// interval and lapsed by the clock after it, it makes step (a)'s retirement
/// an append the stopped log refuses.
///
/// **The pass that lifts.** It fails at (a), the step named, and runs on:
/// its (c) unlinks the lapsed deposit, the room a full volume needs most,
/// and its (d) rewrites the stopped log whatever its count, so the stop
/// lifts. The report's members agree (`failed` step (a)'s alone, `unlinked`
/// and `freed` the deposit's, `compacted` the size the log was rewritten
/// from, `stopped` clear, `lifted` the stop as it stood, its cause and the
/// two appends it refused, the creation and the retirement), and its line
/// 35 names the failure, what the pass did past it, the compaction and the
/// stop it lifted, with its figures. A creation resumes without a restart,
/// and the pass after owes nothing, under line 34: the store's retirement
/// had dropped the record in this process before the append the stopped
/// log refused (its partial removed first), so the compaction wrote the log
/// to the records as they stand.
#[cfg(unix)]
#[test]
fn a_failed_step_never_skips_the_compaction_that_lifts_a_stop() {
    use skep_media::limits::{COMPACTION_MIN_LINES, COMPACTION_TRIGGER};
    use skep_media::pruner::PassStep;
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let token = open_session(port, CLAIMANT_PRINCIPAL);
    let logs = dir.path().join("blobs");
    let lines = |name: &str| fs::read_to_string(logs.join(name)).unwrap().lines().count();
    let bytes = |name: &str| fs::metadata(logs.join(name)).unwrap().len();
    // The deposit no cell names, on a one-second lease.
    sd.daemon().install_media_limits(None, None, Some(1_000), None, None).expect("installs");
    let lapsing = seeded_bytes(4_000, 11);
    put_whole(port, &token, &lapsing);
    let deposit = blobs_dir(dir.path()).join(blob_hex(&lapsing));
    // The upload that will stand expired under the stop.
    sd.daemon().install_media_limits(None, None, Some(600_000), None, None).expect("installs");
    let (st, _, resp) = blob_create(port, Some(&token), 10, b"hello");
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&resp));
    let expiring = json(&resp)["upload"].as_str().unwrap().to_string();
    sd.daemon().install_media_limits(None, None, None, None, None).expect("installs");
    // The records' log past its trigger: the expiring upload's creation and
    // its settle's offset line, then a creation and a retirement per pair.
    for _ in 0..512 {
        let (st, _, resp) = blob_create(port, Some(&token), 10, b"");
        assert_eq!(st, 200, "{}", String::from_utf8_lossy(&resp));
        let id = json(&resp)["upload"].as_str().unwrap().to_string();
        let (st, _, _) = blob_end(port, Some(&token), &id);
        assert_eq!(st, 204);
    }
    let written = lines("uploads.log");
    assert!(written >= COMPACTION_MIN_LINES, "past the minimum: {written} lines");
    assert!(written > COMPACTION_TRIGGER, "four times its one record: {written} lines");
    assert!(pass_failures(&sd).is_empty(), "no pass has failed yet");
    // The cadence's first pass, run as the index readied, has ended: the
    // clock moves only after it, so the passes below are the ones that judge
    // the lapsed deposit.
    let deadline = Instant::now() + Duration::from_secs(60);
    while sd.daemon().prune_passes_completed() == 0 {
        assert!(Instant::now() < deadline, "the cadence's first pass did not complete");
        thread::sleep(Duration::from_millis(20));
    }
    sd.daemon().advance_media_clock_ms(2_000);
    // THE STOP: one pass with the directory unreadable.
    let stopping = {
        let _unreadable = Unreadable::new(&logs);
        sd.daemon().prune_now().expect("ready")
    };
    let Some(failed) = stopping.failed.first().cloned() else {
        // A privileged process reads any directory: step (b)'s read passed
        // under the mode, so nothing was injected and the claim is not run.
        eprintln!("the directory's mode refused nothing: a privileged process; the claim is not run");
        sd.shutdown();
        return;
    };
    assert_eq!(stopping.failed, std::slice::from_ref(&failed), "one failure, step (b)'s: {stopping:?}");
    assert_eq!(failed.step, PassStep::Halts, "{stopping:?}");
    // (b) gates (c): halts unread halt the unlink pass as halts read do.
    assert_eq!(
        stopping.halted.as_deref(),
        Some("the halts are unread, so no file is judged"),
        "{stopping:?}"
    );
    assert_eq!((stopping.unlinked, stopping.kept), (0, 0), "no file judged: {stopping:?}");
    assert!(deposit.is_file(), "the lapsed deposit stands under the halts unread");
    assert!(
        stopping.compaction_failed.is_some(),
        "FINDING (§4 row 5): the failed step skipped the compaction — no stop was met: {stopping:?}"
    );
    let stop = stopping.stopped.0.clone().expect("the records' log stopped past its rename");
    assert_eq!(stopping.stopped.1, None, "the lease log takes appends: {stopping:?}");
    let cause = stop.cause.clone();
    assert!(
        cause.starts_with("its rewrite failed past its rename (blobs/: fsync: "),
        "the stop's cause names the act that failed past the rename: {cause}"
    );
    assert_eq!(stop.refused, 0, "no append refused yet: {stop:?}");
    assert_eq!(stopping.compacted, (None, None), "{stopping:?}");
    let rewrite = bytes("uploads.log");
    assert_eq!(
        (stopping.logs.0.lines, stopping.logs.0.bytes),
        (1, rewrite),
        "the records' log's size the rewrite's, the file at its name: {stopping:?}"
    );
    let lease_log = bytes("leases.log");
    let said = pass_failures(&sd);
    assert_eq!(said.len(), 1, "{said:?}");
    assert_eq!(
        said[0],
        format!(
            "failure: pruner: the pass failed: {failed}; 0 expired partials removed, 0 files unlinked, 0 \
             kept, 0 asides removed, 0 bytes freed — the unlink pass halted: the halts are unread, so no file \
             is judged; blobs/uploads.log 1 lines ({rewrite} bytes); blobs/leases.log 1 lines ({lease_log} \
             bytes); a compaction FAILED: {}; STOPPED: blobs/uploads.log takes no append until a compaction \
             completes — {cause}; stopped {} ms, 0 appends refused",
            stopping.compaction_failed.as_ref().unwrap(),
            stop.age.as_millis()
        ),
        "line 35 names the failure, what the pass did past it — the unlink pass halted on the halts unread — \
         the logs' sizes AND the stopped log, by its cause, its age and its count"
    );
    assert!(said[0].contains("step (b), the halts' read: "), "the step named: {}", said[0]);
    // THE STOP IN FORCE: a creation's record is an append the log refuses.
    let (st, _, body) = blob_create(port, Some(&token), 10, b"");
    assert_eq!(st, 500, "{}", String::from_utf8_lossy(&body));
    assert_eq!(json(&body)["error"].as_str(), Some("blob_io"), "{}", String::from_utf8_lossy(&body));
    // The expired upload stands, its retirement owed.
    sd.daemon().advance_media_clock_ms(700_000);
    // THE PASS THAT LIFTS: (a) fails at the retirement, (d) runs regardless.
    let lifting = sd.daemon().prune_now().expect("ready");
    let [failed] = lifting.failed.as_slice() else {
        panic!("one failure, step (a)'s retirement the stopped log refused: {lifting:?}")
    };
    let failed = failed.clone();
    assert_eq!(failed.step, PassStep::ExpiredPartials, "{lifting:?}");
    assert!(failed.cause.contains("blobs/uploads.log takes no append until a compaction completes"), "{failed}");
    assert!(
        failed.cause.ends_with(&format!(": {cause}")),
        "the refused append names the stop's cause alone, no figure of the operator's: {failed}"
    );
    assert_eq!(lifting.expired_partials, 0, "{lifting:?}");
    // (a)'s failure leaves (c) to run: the lapsed deposit goes, its bytes the
    // room the pass made.
    assert_eq!(lifting.halted, None, "{lifting:?}");
    assert_eq!(
        (lifting.unlinked, lifting.kept, lifting.freed),
        (1, 0, 4_000),
        "FINDING (#415): the failed expiry skipped the unreferenced files: {lifting:?}"
    );
    assert!(!deposit.exists(), "unlinked in the pass whose step (a) failed");
    let from = lifting.compacted.0.clone();
    assert_eq!(
        from.map(|from| (from.lines, from.bytes)),
        Some((1, rewrite)),
        "FINDING (§4 row 5): the failed step skipped the compaction — or it says no size it rewrote from: \
         {lifting:?}"
    );
    assert_eq!(lifting.compaction_failed, None, "{lifting:?}");
    assert_eq!(lifting.stopped, (None, None), "the stop lifted by this pass: {lifting:?}");
    let lifted = lifting.lifted.0.clone().expect("said lifted");
    assert_eq!(lifting.lifted.1, None, "{lifting:?}");
    assert_eq!(
        (lifted.cause.as_str(), lifted.refused),
        (cause.as_str(), 2),
        "lifted as it stood: its cause, and the creation and the retirement it refused"
    );
    let said = pass_failures(&sd);
    assert_eq!(said.len(), 2, "{said:?}");
    assert_eq!(
        said[1],
        format!(
            "failure: pruner: the pass failed: {failed}; 0 expired partials removed, 1 files unlinked, 0 \
             kept, 0 asides removed, 4000 bytes freed; blobs/uploads.log 0 lines (0 bytes) — compacted from \
             1 lines ({rewrite} bytes); blobs/leases.log 1 lines ({lease_log} bytes); blobs/uploads.log's stop \
             lifted, rewritten whole after {cause}; stopped {} ms, 2 appends refused",
            lifted.age.as_millis()
        ),
        "line 35 names the failure AND what the pass did past it AND the compaction that lifted the stop, \
         with the stop's figures"
    );
    // The store's retirement drops the record from its map BEFORE the
    // append the stopped log refused, its partial removed before that
    // (`Store::expire_upload`), so the compaction rewrote the log to the
    // records as they stand in this process: none.
    assert_eq!(lines("uploads.log"), 0, "rewritten to its current records");
    assert!(!blobs_dir(dir.path()).join(format!(".upload-{expiring}")).exists(), "the expired partial went before the refused append");
    // CREATIONS RESUME, without a restart.
    let (st, _, body) = blob_create(port, Some(&token), 10, b"");
    assert_eq!(st, 200, "a creation resumes: {}", String::from_utf8_lossy(&body));
    assert_eq!(lines("uploads.log"), 1, "the creation's record lands in the rewritten log");
    // The pass after owes nothing and says line 34.
    let after = sd.daemon().prune_now().expect("ready");
    assert!(after.failed.is_empty(), "{after:?}");
    assert_eq!(after.expired_partials, 0, "the refused retirement had already retired the record in this process: {after:?}");
    assert_eq!(pass_failures(&sd).len(), 2, "a pass that failed nothing says line 34");
    let pruner_lines: Vec<String> =
        sd.daemon().lines_said().into_iter().filter(|l| l.contains("pruner: ")).collect();
    let line_34 = pruner_lines.last().expect("the pass after says its line");
    assert!(
        line_34.starts_with("landing: pruner: 0 expired partials removed, 0 files unlinked, 0 kept, 0 asides removed"),
        "{pruner_lines:?}"
    );
    // Line 34 carries the pass's duration, then a reading of the resident set.
    let (_, took) = line_34
        .rsplit_once("; the pass took ")
        .unwrap_or_else(|| panic!("line 34 says how long the pass took: {line_34}"));
    let (ms, resident) =
        took.split_once(" ms; ").unwrap_or_else(|| panic!("…in milliseconds: {line_34}"));
    ms.parse::<u128>()
        .unwrap_or_else(|e| panic!("{ms:?} is no whole number of milliseconds ({e}): {line_34}"));
    assert!(
        resident.starts_with("the process's resident set ")
            && resident.contains(", the largest of this uptime's readings "),
        "the pass reads the resident set beside the uptime's largest reading: {line_34}"
    );
    sd.shutdown();
}

/// `operations.md` §1.1 row 36 RETIRED (RULED: the standalone write inside
/// the pass dropped; line 34 carries the halt, its reason and the expired
/// partials removed) — THE HALT IS SAID IN ONE LINE: the real binary over a
/// board with a foreign designation directory planted before its start, its
/// stderr piped: the cadence's first pass halts, and the stream carries
/// exactly ONE pruner line for it — row 34, a `landing:`, with " — the
/// unlink pass halted: a designation directory blobs/sha256-tree/ …" — and
/// no `pruner: the unlink pass is halted` line; the halt claims above pin
/// the report's `halted`, and stand. The stream is the binary's own: the
/// standalone write, were it restored, would go to the operator stream and
/// no record a suite reads in-process.
#[cfg(unix)]
#[test]
fn the_halt_is_said_in_one_line_on_the_stream() {
    use std::os::unix::fs::DirBuilderExt;

    use crate::open::{after_the_head, serving_port, skepd, Spawned, Stderr, PATIENCE};
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("data");
    // The board's directory as the daemon would make it — owner-only — with
    // a sidecar of another build's schema already under blobs/.
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder.create(dir.join("blobs").join("sha256-tree")).expect("the planted directory");
    let workers = skepd::MIN_WORKERS.to_string();
    let mut cmd = skepd(&dir, &["--port", "0", "--workers", workers.as_str()]);
    let mut child = Spawned::launch(&mut cmd);
    let mut stderr = Stderr::of(&mut child.child);
    let _port = serving_port(&mut child.child, PATIENCE);
    let first = stderr.wait_for("the first pass's line", PATIENCE, |l| l.contains("pruner: "));
    // A second pruner line, were one coming, came with the first: the
    // standalone write sat inside the pass, before its report returned. A
    // settling wait, then the whole stream.
    thread::sleep(Duration::from_millis(500));
    child.kill();
    let lines = stderr.whole();
    let pruner: Vec<&String> = lines.iter().filter(|l| l.contains("pruner: ")).collect();
    assert_eq!(pruner.len(), 1, "FINDING (row 36): the pass said more than one line:\n{}", lines.join("\n"));
    let said = after_the_head(&first, "landing").unwrap_or_else(|| panic!("row 34 is a landing: {first}"));
    assert!(
        said.starts_with(
            "pruner: 0 expired partials removed, 0 files unlinked, 0 kept, 0 asides removed, 0 bytes \
             freed — the unlink pass halted: a designation directory blobs/sha256-tree/ is outside the \
             set this build pins (blake3): a sidecar of another build's schema"
        ),
        "line 34 carries the halt and its reason: {said}"
    );
    assert!(
        !lines.iter().any(|l| l.contains("the unlink pass is halted")),
        "FINDING (row 36): the standalone line is retired:\n{}",
        lines.join("\n")
    );
}

/// §3.2 — THE DRAIN's TIMING (M-I5 (f); `#[ignore]`, the gate's timing
/// partition; REPORTED, with a sanity bound alone): N files under leases
/// lapsed by the test clock — two tiers, 2,000 at 1 MiB and as many at the
/// per-file cap as a quarter of the volume's free space holds, at most 200
/// — the pass started, plain inserts posted from one thread and one
/// credential retirement from another; the plain-write p50/p99, the
/// retirement's commit latency and the pass's total printed. The lock the
/// arm is taken on is `parking_lot::RwLock`, TASK-FAIR: a waiting writer
/// blocks new readers, so an insert that arrives while the pass holds a
/// file waits that file's work and no more. `DRAIN_TIERS=small|cap|both`
/// narrows the run.
#[test]
#[ignore = "timing test - gate-full only"]
fn pruner_drain_keeps_plain_writes_and_a_retirement_inside_e2() {
    let tiers = std::env::var("DRAIN_TIERS").unwrap_or_else(|_| "both".into());
    let dir = tempfile::tempdir().expect("tempdir");
    let free = {
        let store = Store::open(dir.path().join("blobs"), Duration::from_millis(1), 0).expect("the store opens");
        store.free_space().expect("statvfs")
    };
    let cap = 64 * 1024 * 1024usize;
    let at_cap = ((free / 4) / cap as u64).min(200) as usize;
    let mut plans: Vec<(&str, usize, usize)> = Vec::new();
    if tiers != "cap" {
        plans.push(("2,000 at 1 MiB", 2_000, 1024 * 1024));
    }
    if tiers != "small" {
        plans.push(("at the cap (64 MiB)", at_cap, cap));
    }
    println!("drain: {free} bytes free on the volume; the cap tier runs {at_cap} files");
    for (label, n, size) in plans {
        let dir = tempfile::tempdir().expect("tempdir");
        // The board claimed and the referenced file placed, then the daemon
        // stopped and the tail written through the store's own door — each
        // file leased to lapse under the test clock.
        let referenced = seeded_bytes(777, 1);
        {
            let sd = spawn(dir.path());
            let port = sd.port();
            let bare = open_session(port, CLAIMANT_PRINCIPAL);
            put_whole(port, &bare, &referenced);
            let draft = owner_draft(port, &bare);
            assert_eq!(insert_cell(port, &bare, &draft, &referenced, 777), "ok");
            sd.shutdown();
        }
        let seeding = Instant::now();
        {
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
            let store = Store::open(dir.path().join("blobs"), Duration::from_millis(30 * 24 * 3600 * 1000), now).expect("the store opens");
            let key = CLAIMANT_PRINCIPAL.to_string();
            // Leased an hour out — past the seeding's own duration, so the
            // cadence's first pass finds every lease live and keeps the tail;
            // the test clock lapses them afterward.
            let lease = Duration::from_millis(3_600_000);
            let mut buf = seeded_bytes(size, 5);
            for i in 0..n {
                // One distinct file per lease: the first bytes carry the index.
                buf[..8].copy_from_slice(&(i as u64).to_le_bytes());
                let rec = store.create_upload(&key, HashFunction::Blake3, size as u64, lease, now).unwrap();
                let mut stream = store.resume(&key, &rec.id, 0, now).unwrap();
                stream.append(&buf, now).unwrap();
                stream.finish(lease, now).unwrap();
            }
        }
        println!("drain {label}: {n} files seeded in {:?}", seeding.elapsed());
        let sd = spawn(dir.path());
        let port = sd.port();
        let bare = open_session(port, CLAIMANT_PRINCIPAL);
        let anchor = open_signed_session(port, CLAIMANT_PRINCIPAL, &anchor_key());
        // The cadence's first pass walks the seeded tail under live leases
        // and keeps every file; the clock moves only once it has ended, so
        // the timed pass below is the one pass over the lapsed tail.
        let deadline = Instant::now() + Duration::from_secs(300);
        while sd.daemon().prune_passes_completed() == 0 {
            assert!(Instant::now() < deadline, "the cadence's first pass did not complete");
            thread::sleep(Duration::from_millis(20));
        }
        sd.daemon().advance_media_clock_ms(2 * 3_600_000);
        let daemon = sd.daemon();
        let done = AtomicBool::new(false);
        let (pass, retirement, writes) = thread::scope(|s| {
            let pass = s.spawn(|| {
                let started = Instant::now();
                let report = daemon.prune_now().expect("ready");
                let total = started.elapsed();
                done.store(true, Ordering::Release);
                (report, total)
            });
            let retirement = s.spawn(|| {
                thread::sleep(Duration::from_millis(20));
                let started = Instant::now();
                let v = retire_the_device_key(port, &anchor);
                (v, started.elapsed())
            });
            let writes = s.spawn(|| {
                let d = owner_draft(port, &bare);
                let mut latencies = Vec::new();
                let mut ordinal = 1;
                while !done.load(Ordering::Acquire) {
                    let started = Instant::now();
                    let v = insert_text(port, &bare, &d, ordinal, "x");
                    latencies.push(started.elapsed());
                    assert_eq!(verdict(&v), "ok");
                    ordinal += 1;
                }
                latencies
            });
            (pass.join().expect("the pass"), retirement.join().expect("the retirement"), writes.join().expect("the writes"))
        });
        let (report, total) = pass;
        let (answer, retirement_latency) = retirement;
        expect_resp(&answer, "ack_addr");
        assert_eq!(report.unlinked, n, "{report:?}");
        assert_eq!(report.kept, 1, "{report:?}");
        let mut sorted = writes.clone();
        sorted.sort();
        let q = |p: f64| sorted[((sorted.len() - 1) as f64 * p).round() as usize];
        println!(
            "drain {label}: the pass unlinked {} in {total:?} ({:?} per file); {} plain inserts during it, p50 {:?}, p99 {:?}, max {:?}; the retirement committed in {retirement_latency:?}; the lock task-fair",
            report.unlinked,
            total / (n.max(1) as u32),
            sorted.len(),
            q(0.5),
            q(0.99),
            sorted.last().unwrap()
        );
        assert!(q(0.99) < Duration::from_secs(5), "sanity: a plain insert answers under a drain");
        assert!(retirement_latency < Duration::from_secs(30), "sanity: the retirement commits under a drain");
        assert!(blobs_dir(dir.path()).join(blob_hex(&referenced)).is_file());
        sd.shutdown();
    }
}
