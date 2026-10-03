//! THE UPLOAD RECORDS and THE PARTIALS (M-I5 (c) THE DEPOSIT RECORD IS THE
//! PRINCIPAL'S, READABLE, EXACT; M-I2 (e) THE REQUESTER'S OWN RECORD BEFORE
//! ANY SHARED FACT; `media.md` the resumable upload's clauses (1), (3), (4),
//! (5), (6)): the identifier's form and its one answer per key, the durable
//! offset and the cut-back, the reconciliation both ways at open, the
//! expiry, the end, and compaction.

use std::fs::{self, OpenOptions};

use skep_blobs::{BlobError, UploadId, SYNC_GRAIN};

use crate::{hex_of, open, standing, INTERVAL};

/// (1) THE IDENTIFIER: 32 lowercase hex of 128 OS bits, never a sequence —
/// two mints differ; the parse admits exactly the spelling; and an
/// identifier is answered to its key ALONE: another key's lookup, a resume,
/// an end and a finish each answer `NoUpload`, exactly as a never-minted
/// identifier does (M-I2 (e)).
#[test]
fn the_identifier_is_unpredictable_and_answers_to_its_key_alone() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open(&dir.path().join("blobs"), 0);
    let a = store.create_upload("a", "blake3", 5, INTERVAL, None).unwrap();
    let b = store.create_upload("a", "blake3", 5, INTERVAL, None).unwrap();
    assert_ne!(a.id, b.id);
    assert_eq!(a.id.to_hex().len(), 32);
    assert!(a.id.to_hex().bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)));
    assert_eq!(UploadId::parse(&a.id.to_hex()), Some(a.id));
    assert_eq!(UploadId::parse(&a.id.to_hex().to_uppercase()), None);
    assert_eq!(UploadId::parse(&a.id.to_hex()[..31]), None);
    let never = UploadId::parse("00000000000000000000000000000000").unwrap();
    for (key, id) in [("b", a.id), ("a", never)] {
        assert!(store.upload(key, &id, 1).is_none());
        assert!(matches!(store.resume(key, &id, 0, 1), Err(BlobError::NoUpload)));
        assert!(matches!(store.end_upload(key, &id, 1), Err(BlobError::NoUpload)));
    }
    assert_eq!(store.uploads_of("b", 1), vec![]);
    assert_eq!(store.uploads_of("a", 1).len(), 2);
}

/// (3) ONE EXPIRY, fixed from the LAST BYTE RECEIVED and durable with it:
/// an append past the grain writes the record's offset and re-fixes its
/// expiry; a settle does the same at any length; bytes written but not yet
/// settled are not received — a resume in this process cuts the partial
/// back to the record's offset and continues from there — and a resume
/// stating any other offset is refused naming the record's (5).
#[test]
fn a_byte_is_received_once_durable_and_a_resume_continues_from_the_records_offset() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("blobs");
    let store = open(&root, 0);
    let length = SYNC_GRAIN + 100;
    let rec = store.create_upload("k", "blake3", length, INTERVAL, None).unwrap();
    store.resume("k", &rec.id, 0, 10).unwrap();
    // Short of the grain: written, not received.
    store.append("k", &rec.id, &[1u8; 100], 10, INTERVAL).unwrap();
    assert_eq!(store.upload("k", &rec.id, 10).unwrap().offset, 0);
    assert_eq!(store.written("k", &rec.id, 10), Some(100));
    // Up to the grain: received, the expiry re-fixed from this byte.
    let rest = vec![2u8; SYNC_GRAIN as usize - 100];
    store.append("k", &rec.id, &rest, 20, INTERVAL).unwrap();
    let r = store.upload("k", &rec.id, 20).unwrap();
    assert_eq!(r.offset, SYNC_GRAIN);
    assert_eq!(r.expires, 20 + INTERVAL);
    // Written past it, unsettled: the record stands; a resume at the
    // record's offset cuts the tail; one at the written length is refused
    // naming the record's.
    store.append("k", &rec.id, &[3u8; 50], 30, INTERVAL).unwrap();
    assert_eq!(store.written("k", &rec.id, 30), Some(SYNC_GRAIN + 50));
    assert!(matches!(
        store.resume("k", &rec.id, SYNC_GRAIN + 50, 30),
        Err(BlobError::Offset { recorded }) if recorded == SYNC_GRAIN
    ));
    store.resume("k", &rec.id, SYNC_GRAIN, 30).unwrap();
    assert_eq!(store.written("k", &rec.id, 30), Some(SYNC_GRAIN));
    let partial = root.join("blake3").join(format!(".upload-{}", rec.id.to_hex()));
    assert_eq!(fs::metadata(&partial).unwrap().len(), SYNC_GRAIN);
    // The last bytes, settled at the request's end: received, the length
    // reached, the hash the whole file's.
    store.append("k", &rec.id, &[4u8; 100], 40, INTERVAL).unwrap();
    let r = store.settle("k", &rec.id, 40, INTERVAL).unwrap();
    assert_eq!(r.offset, length);
    assert_eq!(r.expires, 40 + INTERVAL);
    // One byte more is refused, nothing written.
    assert!(matches!(store.append("k", &rec.id, &[5u8], 41, INTERVAL), Err(BlobError::Length { .. })));
    let fin = store.finish("k", &rec.id, 50, 50 + INTERVAL).unwrap();
    let mut whole = vec![1u8; 100];
    whole.extend(rest);
    whole.extend([4u8; 100]);
    assert_eq!(fin.hex, hex_of(&whole), "the hash covers the bytes as cut back and continued");
    assert_eq!(fs::read(store.blob_path("blake3", &fin.hex)).unwrap(), whole);
    assert!(!partial.exists());
}

/// (4) AT OPEN THE TWO ARE RECONCILED BOTH WAYS, and their lengths: a
/// partial no record names is removed, in every designation directory; a
/// record whose partial is gone is retired; a partial longer than its
/// record's offset is cut back; a record whose offset passes its partial's
/// length is set back to the length (a copy that took the partial before
/// its record); an expired upload is retired and its partial removed; and
/// the records log is compacted to the current records.
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
    // unlink — named by nothing.
    fs::write(root.join("blake3").join(format!(".retired-{}-0", hex_of(b"old"))), b"old").unwrap();
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
    assert!(store.upload("k", &gone.id, now).is_none(), "a record with no partial is retired");
    assert!(store.upload("k", &expired.id, now).is_none(), "an expired upload is retired");
    assert!(!partial(&expired.id).exists(), "and its partial removed");
    assert!(!root.join("blake3").join(".upload-ffffffffffffffffffffffffffffffff").exists(), "an orphan is removed");
    assert!(!root.join("sha256-tree").join(".upload-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee").exists(), "in every designation directory");
    assert!(store.asides_of("blake3").unwrap().is_empty(), "an aside is removed at open");
    assert_eq!(store.designations().unwrap(), vec!["blake3".to_string(), "sha256-tree".to_string()], "every directory under the root, the foreign one included");
    let lines_after = fs::read_to_string(root.join("uploads.log")).unwrap().lines().count();
    assert_eq!(lines_after, 3, "compacted to the three current records");
    assert_eq!(store.pending_bytes("k", now), 4 + 6 + 3);
    // The expired upload's partial would be a resume into nothing; the
    // standing ones resume at their reconciled offsets and finish whole.
    for (rec, head, tail) in [(&kept, b"kept".as_slice(), b"".as_slice()), (&longer, b"longer", b""), (&shorter, b"sho", b"rter")] {
        let r = store.upload("k", &rec.id, now).unwrap();
        store.resume("k", &r.id, r.offset, now).unwrap();
        let fill = vec![b'x'; 100 - head.len() - tail.len()];
        store.append("k", &r.id, tail, now, INTERVAL).unwrap();
        store.append("k", &r.id, &fill, now, INTERVAL).unwrap();
        store.settle("k", &r.id, now, INTERVAL).unwrap();
        let fin = store.finish("k", &r.id, now, now + INTERVAL).unwrap();
        let mut whole = head.to_vec();
        whole.extend_from_slice(tail);
        whole.extend(fill);
        assert_eq!(fin.hex, hex_of(&whole));
    }
}

/// (4) REMOVED ON EXPIRY, while the store serves — the pruner's door:
/// [`Store::expired_uploads`] lists every record past its expiry, whatever
/// key minted it, reading no reference; [`Store::expire_upload`] removes
/// the partial and retires the record, and leaves a standing upload as it
/// is, so a clock that moved between the read and the act costs nothing.
///
/// [`Store::expired_uploads`]: skep_blobs::Store::expired_uploads
/// [`Store::expire_upload`]: skep_blobs::Store::expire_upload
#[test]
fn the_expired_uploads_are_listed_and_removed_while_the_store_serves() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("blobs");
    let store = open(&root, 0);
    let early = standing(&store, "a", 100, b"early", 0);
    let late = standing(&store, "b", 100, b"late", 50);
    let partial = |id: &UploadId| root.join("blake3").join(format!(".upload-{}", id.to_hex()));
    assert!(store.expired_uploads(10).is_empty());
    let now = early.expires;
    let expired: Vec<UploadId> = store.expired_uploads(now).into_iter().map(|r| r.id).collect();
    assert_eq!(expired, vec![early.id], "the one past its expiry, whoever minted it");
    assert!(!store.expire_upload(&late.id, now).unwrap(), "a standing upload is left as it is");
    assert!(partial(&late.id).is_file());
    assert!(store.expire_upload(&early.id, now).unwrap());
    assert!(!partial(&early.id).exists(), "its partial removed");
    assert!(store.upload("a", &early.id, 1).is_none(), "its record retired, at any clock");
    assert!(!store.expire_upload(&early.id, now).unwrap(), "retired once");
    assert_eq!(store.pending_bytes("a", 1), 0);
    assert_eq!(store.pending_bytes("b", now), 4, "the standing one counts");
}

/// (6) THE END keeps nothing: the partial removed, the record retired, the
/// key's pending bytes falling at once; a second end, and a resume, answer
/// `NoUpload`; the identifier is never re-minted. And a torn tail of the
/// records log is truncated at open, trust ending at the first torn line.
#[test]
fn an_ended_upload_keeps_nothing_and_a_torn_log_tail_is_cut() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("blobs");
    let id = {
        let store = open(&root, 0);
        let a = standing(&store, "k", 100, b"abc", 1);
        let b = standing(&store, "k", 100, b"def", 1);
        assert_eq!(store.pending_bytes("k", 2), 6);
        store.end_upload("k", &a.id, 2).unwrap();
        assert_eq!(store.pending_bytes("k", 2), 3);
        assert!(!root.join("blake3").join(format!(".upload-{}", a.id.to_hex())).exists());
        assert!(matches!(store.end_upload("k", &a.id, 2), Err(BlobError::NoUpload)));
        assert!(matches!(store.resume("k", &a.id, 0, 2), Err(BlobError::NoUpload)));
        b.id
    };
    // A torn line appended to the log: the next open cuts it and reads the
    // rest as before.
    let log = root.join("uploads.log");
    let whole = fs::read_to_string(&log).unwrap();
    fs::write(&log, format!("{whole}{{\"id\":\"{}\",\"offset\":99", id.to_hex())).unwrap();
    let store = open(&root, 3);
    let r = store.upload("k", &id, 3).expect("the untorn record stands");
    assert_eq!(r.offset, 3, "the torn line moved nothing");
    assert!(fs::read_to_string(&log).unwrap().ends_with('\n'), "the tail was cut");
}
