//! WHAT OPEN MAKES OF THE RECORDS AND THE PARTIALS (M-I5 (c); `media.md` the
//! resumable upload's clauses (1), (4); §The media stores): the
//! reconciliation both ways at open, an offset set back keeping its expiry,
//! and the sweep of the asides beside it; a partial that cannot be read
//! failing the open and retiring nothing; a record line read as no record
//! where it lacks its interval, where its offset passes its length, and
//! where its designation climbs out of the root, nothing beside the root
//! touched; and the compaction, down to nothing where nothing stands, over
//! the twin a kill mid-compaction left beside each log.

use std::fs::{self, OpenOptions};
use std::time::Duration;

use skep_blobs::{BlobError, Store, UploadId};

use crate::{every_deposit_unplaced, hex_of, open, put_whole, standing, HORIZON, HORIZON_MS, INTERVAL, INTERVAL_MS};

/// (1) A RECORD LINE WITHOUT ITS INTERVAL IS NO RECORD: the store holds no
/// interval of its own to put in its place, so the line reads as a lost
/// record does — no upload, its partial an orphan open removes, the resume
/// starting afresh — while the same line carrying its interval stands.
#[test]
fn a_record_line_without_its_interval_reads_as_no_upload() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("blobs");
    let without = UploadId::parse("0123456789abcdef0123456789abcdef").unwrap();
    let with = UploadId::parse("fedcba9876543210fedcba9876543210").unwrap();
    let partial = |id: &UploadId| root.join("blake3").join(format!(".upload-{}", id.to_hex()));
    fs::create_dir_all(root.join("blake3")).unwrap();
    fs::write(partial(&without), b"abc").unwrap();
    fs::write(partial(&with), b"abc").unwrap();
    let line = |id: &UploadId, interval: &str| {
        format!(
            "{{\"designation\":\"blake3\",\"expires\":9999,\"id\":\"{}\",{interval}\"key\":\"k\",\"length\":10,\"offset\":3}}\n",
            id.to_hex()
        )
    };
    fs::write(root.join("uploads.log"), line(&without, "") + &line(&with, "\"interval\":1000,")).unwrap();
    let store = open(&root, 1);
    assert!(store.upload("k", &without, 1).is_none(), "no interval, no record");
    assert!(!partial(&without).exists(), "its partial an orphan open removes");
    assert!(matches!(store.resume("k", &without, 3, 1), Err(BlobError::NoUpload)));
    let r = store.upload("k", &with, 1).expect("the line carrying its interval stands");
    assert_eq!((r.offset, r.interval), (3, Duration::from_millis(1_000)));
    assert!(partial(&with).is_file());
}

/// (4) A RECORD LINE WHOSE DESIGNATION CLIMBS OUT OF THE ROOT IS NO RECORD
/// (`Store`: "THE STORE CHECKS EVERY NAME IT IS HANDED", a log's names at
/// open as a caller's): a log restored from elsewhere is read through the
/// name check a creation's designation meets, so a line whose designation
/// would carry its partial's path out of the root — above it through `..`,
/// anywhere as an absolute path — reads as a lost record does. Open's
/// reconciliation, which cuts a standing upload's partial back to its
/// record's offset and removes an expired one's, then touches no file
/// beside the root; the same line naming a designation a creation admits
/// stands, and the compaction keeps it alone.
#[test]
fn a_record_line_whose_designation_climbs_out_of_the_root_is_no_record() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("blobs");
    let elsewhere = dir.path().join("elsewhere");
    fs::create_dir_all(root.join("blake3")).unwrap();
    fs::create_dir_all(&elsewhere).unwrap();
    let absolute = elsewhere.to_str().expect("a UTF-8 tempdir").to_string();
    // Each escape, the directory its partial's name lands in, and its
    // expiry: standing at the open below, so cut back, or past, so removed.
    let escapes = [
        ("..".to_string(), dir.path().to_path_buf(), 9_999),
        ("..".to_string(), dir.path().to_path_buf(), 5),
        ("../elsewhere".to_string(), elsewhere.clone(), 9_999),
        (absolute.clone(), elsewhere.clone(), 9_999),
        (absolute, elsewhere.clone(), 5),
    ];
    let id = |n: usize| UploadId::parse(&hex_of(&[n as u8])[..32]).expect("32 lowercase hex");
    let line = |id: &UploadId, designation: &str, expires: u64| {
        let v = serde_json::json!({
            "designation": designation, "expires": expires, "id": id.to_hex(),
            "interval": 1_000, "key": "k", "length": 100, "offset": 3,
        });
        format!("{v}\n")
    };
    let mut log = String::new();
    for (n, (designation, at, expires)) in escapes.iter().enumerate() {
        fs::write(at.join(format!(".upload-{}", id(n).to_hex())), b"beside the root").unwrap();
        log += &line(&id(n), designation, *expires);
    }
    let kept = id(escapes.len());
    fs::write(root.join("blake3").join(format!(".upload-{}", kept.to_hex())), b"abc").unwrap();
    log += &line(&kept, "blake3", 9_999);
    fs::write(root.join("uploads.log"), log).unwrap();
    let store = open(&root, 10);
    for (n, (designation, at, _)) in escapes.iter().enumerate() {
        assert_eq!(
            fs::read(at.join(format!(".upload-{}", id(n).to_hex()))).ok().as_deref(),
            Some(b"beside the root".as_slice()),
            "{designation:?}: the file beside the root neither cut back nor removed"
        );
        assert_eq!(store.upload("k", &id(n), 10), None, "{designation:?}: no record");
    }
    let stand: Vec<UploadId> = store.uploads_of("k", 10).into_iter().map(|r| r.id).collect();
    assert_eq!(stand, vec![kept], "the line naming a designation a creation admits stands alone");
    assert_eq!(fs::read_to_string(root.join("uploads.log")).unwrap().lines().count(), 1, "compacted to it");
}

/// (1) A RECORD LINE WHOSE OFFSET PASSES ITS LENGTH IS NO RECORD
/// (`UploadRecord`: "ITS OFFSET NEVER PASSES ITS LENGTH", the log's line the
/// one gate of that invariant a line from disk meets): no act writes one,
/// and standing, its upload would refuse every resume and never reach a
/// finish, counted past its length in its principal's pending bytes. It
/// reads as a lost record does — its partial an orphan open removes — while
/// the same line with its offset AT its length stands.
#[test]
fn a_record_line_whose_offset_passes_its_length_is_no_record() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("blobs");
    let past = UploadId::parse("0123456789abcdef0123456789abcdef").unwrap();
    let at = UploadId::parse("fedcba9876543210fedcba9876543210").unwrap();
    let partial = |id: &UploadId| root.join("blake3").join(format!(".upload-{}", id.to_hex()));
    fs::create_dir_all(root.join("blake3")).unwrap();
    fs::write(partial(&past), [b'x'; 11]).unwrap();
    fs::write(partial(&at), [b'x'; 10]).unwrap();
    let line = |id: &UploadId, offset: u64| {
        let v = serde_json::json!({
            "designation": "blake3", "expires": 9_999, "id": id.to_hex(),
            "interval": 1_000, "key": "k", "length": 10, "offset": offset,
        });
        format!("{v}\n")
    };
    fs::write(root.join("uploads.log"), line(&past, 11) + &line(&at, 10)).unwrap();
    let store = open(&root, 1);
    assert_eq!(store.upload("k", &past, 1), None, "an offset past its length: no record");
    assert!(!partial(&past).exists(), "its partial an orphan open removes");
    let r = store.upload("k", &at, 1).expect("an offset at its length stands");
    assert_eq!((r.offset, r.length), (10, 10));
    assert_eq!(store.pending_bytes("k", 1, every_deposit_unplaced), 10, "the standing one's bytes alone");
}

/// (4) AT OPEN THE TWO ARE RECONCILED BOTH WAYS, and their lengths: a
/// partial no record names is removed, in every designation directory; a
/// record whose partial is gone is retired; a partial longer than its
/// record's offset is cut back; a record whose offset passes its partial's
/// length is set back to the length, its expiry kept (a copy that took the
/// partial before its record); an expired upload is retired and its partial
/// removed; and the records log is compacted to the current records. Beside
/// them, every aside a crash left is removed — and a name that only begins
/// as an aside's is none, and is left.
#[test]
fn open_reconciles_the_partials_and_the_records_both_ways() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("blobs");
    let (kept, longer, shorter, gone, expired) = {
        let store = open(&root, 0);
        let kept = standing(&store, "k", 100, b"kept", 10);
        let longer = standing(&store, "k", 100, b"longer", 10);
        let shorter = standing(&store, "k", 100, b"shorter-shorter", 10);
        let gone = standing(&store, "k", 100, b"gone", 10);
        // Settled EARLIER than the rest, so its expiry comes first.
        let expired = standing(&store, "k", 100, b"expired", 0);
        (kept, longer, shorter, gone, expired)
    };
    let partial = |id: &UploadId| root.join("blake3").join(format!(".upload-{}", id.to_hex()));
    // Mutilations with no store open.
    fs::write(partial(&longer.id), b"longer plus a tail").unwrap();
    OpenOptions::new().write(true).open(partial(&shorter.id)).unwrap().set_len(3).unwrap();
    fs::remove_file(partial(&gone.id)).unwrap();
    fs::write(root.join("blake3").join(".upload-ffffffffffffffffffffffffffffffff"), b"orphan").unwrap();
    fs::create_dir_all(root.join("sha256-tree")).unwrap();
    fs::write(root.join("sha256-tree").join(".upload-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"), b"orphan too").unwrap();
    // An aside a replace left — a crash between the answer and the deferred
    // unlink — named by nothing; and a file whose name only begins as an
    // aside's, which no replace made.
    fs::write(root.join("blake3").join(format!(".retired-{}-0", hex_of(b"old"))), b"old").unwrap();
    fs::write(root.join("blake3").join(".retired-x"), b"not an aside").unwrap();
    let lines_before = fs::read_to_string(root.join("uploads.log")).unwrap().lines().count();
    assert!(lines_before > 5, "each standing upload wrote more than one line");
    // Reopened past `expired`'s expiry alone.
    let now = expired.expires;
    let store = open(&root, now);
    let r = store.upload("k", &kept.id, now).expect("kept stands");
    assert_eq!(r.offset, 4);
    assert_eq!(fs::metadata(partial(&kept.id)).unwrap().len(), 4);
    let r = store.upload("k", &longer.id, now).expect("longer stands");
    assert_eq!(r.offset, 6);
    assert_eq!(fs::metadata(partial(&longer.id)).unwrap().len(), 6, "cut back to the record's offset");
    let r = store.upload("k", &shorter.id, now).expect("shorter stands");
    assert_eq!(r.offset, 3, "set back to the partial's length");
    assert_eq!(r.expires, shorter.expires, "its expiry kept: a set-back receives no byte");
    assert!(store.upload("k", &gone.id, now).is_none(), "a record with no partial is retired");
    assert!(store.upload("k", &expired.id, now).is_none(), "an expired upload is retired");
    assert!(!partial(&expired.id).exists(), "and its partial removed");
    assert!(!root.join("blake3").join(".upload-ffffffffffffffffffffffffffffffff").exists(), "an orphan is removed");
    assert!(!root.join("sha256-tree").join(".upload-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee").exists(), "in every designation directory");
    assert!(store.asides_of("blake3").unwrap().is_empty(), "an aside is removed at open");
    assert!(root.join("blake3").join(".retired-x").is_file(), "a name no aside has is left");
    assert!(!store.remove_aside("blake3", ".retired-x").unwrap(), "and is no aside to remove");
    assert_eq!(store.designations().unwrap(), vec!["blake3".to_string(), "sha256-tree".to_string()], "every directory under the root, the foreign one included");
    let lines_after = fs::read_to_string(root.join("uploads.log")).unwrap().lines().count();
    assert_eq!(lines_after, 3, "compacted to the three current records");
    assert_eq!(store.pending_bytes("k", now, every_deposit_unplaced), 4 + 6 + 3);
    // The expired upload's partial would be a resume into nothing; the
    // standing ones resume at their reconciled offsets and finish whole.
    for (rec, head, tail) in [(&kept, b"kept".as_slice(), b"".as_slice()), (&longer, b"longer", b""), (&shorter, b"sho", b"rter")] {
        let r = store.upload("k", &rec.id, now).unwrap();
        let mut stream = store.resume("k", &r.id, r.offset, now).unwrap();
        let fill = vec![b'x'; 100 - head.len() - tail.len()];
        stream.append(tail, now).unwrap();
        stream.append(&fill, now).unwrap();
        let fin = stream.finish(INTERVAL, now).unwrap();
        let mut whole = head.to_vec();
        whole.extend_from_slice(tail);
        whole.extend(fill);
        assert_eq!(fin.hex, hex_of(&whole));
    }
}

/// (4) A PARTIAL THAT CANNOT BE READ FAILS THE OPEN AND RETIRES NOTHING
/// (clause (4) retires "a record that names no temp file", and a record
/// naming one that cannot be read still names it): the reconciliation
/// answers the failure rather than reading it as an absence, writing no
/// retirement a later open would remove the partial as an orphan for; once
/// the partial can be read again, the upload stands where its record left
/// it, its bytes whole.
#[cfg(unix)]
#[test]
fn a_partial_that_cannot_be_read_fails_the_open_and_retires_nothing() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("blobs");
    let rec = standing(&open(&root, 0), "k", 100, b"abc", 1);
    let designation_dir = root.join("blake3");
    let mode = fs::metadata(&designation_dir).unwrap().permissions();
    // Read and written, never searched: no partial in it can be stat'ed.
    fs::set_permissions(&designation_dir, fs::Permissions::from_mode(0o600)).unwrap();
    let opened = Store::open(&root, HORIZON, 2).map(drop).map_err(|e| e.kind());
    fs::set_permissions(&designation_dir, mode).unwrap();
    if opened.is_ok() {
        return; // a privileged process searches any directory: nothing to inject
    }
    assert_eq!(opened, Err(std::io::ErrorKind::PermissionDenied), "the open answers the failure");
    let store = open(&root, 3);
    assert_eq!(store.upload("k", &rec.id, 3).map(|r| r.offset), Some(3), "the upload stands where its record left it");
    assert_eq!(fs::read(designation_dir.join(format!(".upload-{}", rec.id.to_hex()))).unwrap(), b"abc", "its partial whole");
}

/// OPEN COMPACTS EACH LOG TO ITS CURRENT RECORDS — NONE AMONG THEM — OVER
/// WHAT A KILL MID-COMPACTION LEFT BESIDE IT: a board whose uploads have all
/// finished or ended and whose every lease has lapsed past the horizon
/// reopens to two empty logs, and a half-written `.compact` twin a kill left
/// beside each is read by nothing and written over.
#[test]
fn open_compacts_both_logs_to_nothing_over_a_stale_compaction_twin() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("blobs");
    {
        let store = open(&root, 0);
        put_whole(&store, "k", b"finished", 1);
        let ended = standing(&store, "k", 10, b"ended", 1);
        store.end_upload("k", &ended.id, 2).unwrap();
    }
    for twin in ["uploads.compact", "leases.compact"] {
        fs::write(root.join(twin), b"{\"half\":\"writ").unwrap();
    }
    let now = 1 + INTERVAL_MS + HORIZON_MS;
    let store = open(&root, now);
    for log in ["uploads.log", "leases.log"] {
        assert_eq!(fs::read_to_string(root.join(log)).unwrap(), "", "{log}: no current record, no line");
    }
    for twin in ["uploads.compact", "leases.compact"] {
        assert!(!root.join(twin).exists(), "{twin}: written over and renamed onto its log");
    }
    assert_eq!((store.uploads_of("k", now), store.live_leases_of("k", now)), (vec![], vec![]));
}
