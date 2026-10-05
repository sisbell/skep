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
    let (st, _, body) = blob_read(port, Some(token));
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
    let blobs = blobs_dir(dir.path());
    assert!(blobs.join(blob_hex(&referenced)).is_file(), "named by a cell: kept past its lease");
    assert!(!blobs.join(blob_hex(&unreferenced)).exists(), "lapsed and unreferenced: gone");
    assert!(blobs.join(blob_hex(&live)).is_file(), "held by a live lease: kept");
    let again = sd.daemon().prune_now().expect("the index is ready");
    assert_eq!((again.unlinked, again.kept), (0, 2), "{again:?}");
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
    sd.daemon().install_media_limits(None, None, Some(1_000), None);
    let (st, _, resp) = blob_create(port, Some(&token), 10, b"hello");
    assert_eq!(st, 200);
    let expiring = json(&resp)["upload"].as_str().unwrap().to_string();
    sd.daemon().install_media_limits(None, None, None, None);
    sd.daemon().advance_media_clock_ms(2_000);
    let blobs = blobs_dir(dir.path());
    assert!(blobs.join(format!(".upload-{expiring}")).is_file(), "stands until a pass");
    let pass = sd.daemon().prune_now().expect("the index is ready");
    assert_eq!(pass.expired_partials, 1, "{pass:?}");
    assert_eq!(pass.unlinked, 0);
    assert!(!blobs.join(format!(".upload-{expiring}")).exists(), "the expired partial is gone");
    assert!(blobs.join(format!(".upload-{standing}")).is_file(), "the standing one survives");
    let (st, _, resp) = blob_progress(port, Some(&token), &standing);
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&resp));
    assert_eq!(json(&resp)["offset"].as_u64(), Some(5));
    let (st, _, _) = blob_progress(port, Some(&token), &expiring);
    assert_eq!(st, 404, "the expired identifier answers no upload");
    let (st, _, resp) = blob_append(port, Some(&token), &standing, 5, b"world");
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
    sd.daemon().install_media_limits(None, None, Some(1_000), None);
    let (st, _, resp) = blob_create(port, Some(&token), 10, b"hello");
    assert_eq!(st, 200);
    let expiring = json(&resp)["upload"].as_str().unwrap().to_string();
    sd.daemon().install_media_limits(None, None, None, None);
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
    assert_eq!(pass.unlinked, 0, "the leased file stands: {pass:?}");
    assert!(!aside_stands(), "swept by the pass");
    assert_eq!(fs::read(blobs.join(&hex)).unwrap(), right);
    assert_eq!(deposits_of(port, &token), vec![(hex.clone(), 1_234, false)]);
    sd.shutdown();
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
