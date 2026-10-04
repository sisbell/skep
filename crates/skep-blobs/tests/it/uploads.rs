//! THE UPLOAD RECORDS and THE PARTIALS (M-I5 (c) THE DEPOSIT RECORD IS THE
//! PRINCIPAL'S, READABLE, EXACT; M-I2 (e) THE REQUESTER'S OWN RECORD BEFORE
//! ANY SHARED FACT; `media.md` the resumable upload's clauses (1), (3), (4),
//! (5), (6)): the identifier's form and its one answer per principal, the
//! durable offset and the cut-back, the upload's own interval, the
//! reconciliation both ways at open, the expiry, the end, and compaction.

use std::fs::{self, OpenOptions};
use std::time::Duration;

use skep_blobs::{BlobError, NotAnUploadId, UploadId, SYNC_GRAIN};

use crate::{every_deposit_unplaced, hex_of, open, standing, INTERVAL, INTERVAL_MS};

/// (1) THE IDENTIFIER: 32 lowercase hex of 128 OS bits, never a sequence —
/// two mints differ; the parse admits exactly the spelling, through
/// `UploadId::parse` and through `FromStr` alike, and the spelling is the
/// identifier's `Display`; identifiers order as their spellings do; and an
/// identifier is answered to its principal ALONE: another principal's
/// lookup, a resume, an end, an append and the count of bytes written each
/// answer as for a never-minted identifier, even while the upload is open
/// in this process (M-I2 (e)).
#[test]
fn the_identifier_is_unpredictable_and_answers_to_its_principal_alone() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open(&dir.path().join("blobs"), 0);
    let a = store.create_upload("a", "blake3", 5, INTERVAL, 0).unwrap();
    let b = store.create_upload("a", "blake3", 5, INTERVAL, 0).unwrap();
    assert_ne!(a.id, b.id);
    assert_eq!(a.id.to_hex().len(), 32);
    assert!(a.id.to_hex().bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)));
    assert_eq!(UploadId::parse(&a.id.to_hex()), Some(a.id));
    assert_eq!(UploadId::parse(&a.id.to_hex().to_uppercase()), None);
    assert_eq!(UploadId::parse(&a.id.to_hex()[..31]), None);
    assert_eq!(a.id.to_hex().parse::<UploadId>(), Ok(a.id));
    assert_eq!(a.id.to_hex().to_uppercase().parse::<UploadId>(), Err(NotAnUploadId));
    assert_eq!(a.id.to_hex()[..31].parse::<UploadId>(), Err(NotAnUploadId));
    assert_eq!(a.id.to_string(), a.id.to_hex());
    assert_eq!(format!("{:?}", a.id), format!("UploadId({})", a.id.to_hex()));
    assert_eq!(a.id < b.id, a.id.to_hex() < b.id.to_hex(), "an identifier orders as its spelling");
    let never = UploadId::parse("00000000000000000000000000000000").unwrap();
    for (principal, id) in [("b", a.id), ("a", never)] {
        assert!(store.upload(principal, &id, 1).is_none());
        assert!(matches!(store.resume(principal, &id, 0, 1), Err(BlobError::NoUpload)));
        assert!(matches!(store.end_upload(principal, &id, 1), Err(BlobError::NoUpload)));
    }
    assert_eq!(store.uploads_of("b", 1), vec![]);
    let listed: Vec<String> = store.uploads_of("a", 1).iter().map(|r| r.id.to_hex()).collect();
    let mut ordered = listed.clone();
    ordered.sort();
    assert_eq!(listed.len(), 2);
    assert_eq!(listed, ordered, "in identifier order");
    // Open in this process, the upload still answers its own principal alone.
    store.resume("a", &a.id, 0, 1).unwrap();
    assert_eq!(store.written("a", &a.id, 1), Some(0));
    assert_eq!(store.written("b", &a.id, 1), None, "another principal's count is no upload's");
    assert!(matches!(store.append("b", &a.id, b"x", 1), Err(BlobError::NoUpload)));
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
    let rec = store.create_upload("k", "blake3", length, INTERVAL, 0).unwrap();
    store.resume("k", &rec.id, 0, 10).unwrap();
    // Short of the grain: written, not received.
    store.append("k", &rec.id, &[1u8; 100], 10).unwrap();
    assert_eq!(store.upload("k", &rec.id, 10).unwrap().offset, 0);
    assert_eq!(store.written("k", &rec.id, 10), Some(100));
    // Up to the grain: received, the expiry re-fixed from this byte.
    let rest = vec![2u8; SYNC_GRAIN as usize - 100];
    store.append("k", &rec.id, &rest, 20).unwrap();
    let r = store.upload("k", &rec.id, 20).unwrap();
    assert_eq!(r.offset, SYNC_GRAIN);
    assert_eq!(r.expires, 20 + INTERVAL_MS);
    // Written past it, unsettled: the record stands; a resume at the
    // record's offset cuts the tail; one at the written length is refused
    // naming the record's.
    store.append("k", &rec.id, &[3u8; 50], 30).unwrap();
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
    store.append("k", &rec.id, &[4u8; 100], 40).unwrap();
    let r = store.settle("k", &rec.id, 40).unwrap();
    assert_eq!(r.offset, length);
    assert_eq!(r.expires, 40 + INTERVAL_MS);
    // The settle ended that request; the next resumes at the length, and
    // one byte more is refused, nothing written.
    store.resume("k", &rec.id, length, 41).unwrap();
    assert!(matches!(store.append("k", &rec.id, &[5u8], 41), Err(BlobError::Length { .. })));
    let fin = store.finish("k", &rec.id, INTERVAL, 50).unwrap();
    let mut whole = vec![1u8; 100];
    whole.extend(rest);
    whole.extend([4u8; 100]);
    assert_eq!(fin.hex, hex_of(&whole), "the hash covers the bytes as cut back and continued");
    assert_eq!(fs::read(store.blob_path("blake3", &fin.hex).unwrap()).unwrap(), whole);
    assert!(!partial.exists());
}

/// (3) THE UPLOAD's OWN INTERVAL: fixed at its creation from the interval
/// handed in then, held in its record and read back at open, and the one
/// every later byte received re-fixes the expiry by — a later upload's
/// interval, however different, reaches that upload alone ("a venue's
/// later record reaches the next upload and never a standing one"). An
/// interval finer than the line's whole milliseconds is held as the line
/// spells it, so the record open reads back is the record the creation
/// answered.
#[test]
fn the_interval_is_the_uploads_own_from_its_creation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("blobs");
    let (first, later, fine) = {
        let store = open(&root, 0);
        let first = store.create_upload("k", "blake3", 10, Duration::from_millis(1_000), 0).unwrap();
        assert_eq!((first.interval, first.expires), (Duration::from_millis(1_000), 1_000));
        store.resume("k", &first.id, 0, 10).unwrap();
        store.append("k", &first.id, b"a", 10).unwrap();
        assert_eq!(store.settle("k", &first.id, 10).unwrap().expires, 1_010);
        // A later upload, created under another interval: its own alone.
        let later = store.create_upload("k", "blake3", 10, Duration::from_millis(5_000), 10).unwrap();
        assert_eq!(later.expires, 5_010);
        let fine = store.create_upload("k", "blake3", 10, Duration::from_micros(2_500), 10).unwrap();
        assert_eq!((fine.interval, fine.expires), (Duration::from_millis(2), 12), "held in whole milliseconds");
        (first.id, later.id, fine)
    };
    // Reopened: each interval is read back off its record's line, and each
    // upload's next byte received re-fixes its expiry by its own.
    let store = open(&root, 11);
    assert_eq!(store.upload("k", &first, 11).unwrap().interval, Duration::from_millis(1_000));
    assert_eq!(store.upload("k", &later, 11).unwrap().interval, Duration::from_millis(5_000));
    assert_eq!(store.upload("k", &fine.id, 11), Some(fine), "read back as the creation answered it");
    store.resume("k", &first, 1, 20).unwrap();
    store.append("k", &first, b"b", 20).unwrap();
    assert_eq!(store.settle("k", &first, 20).unwrap().expires, 1_020, "re-fixed by its own interval");
    store.resume("k", &later, 0, 30).unwrap();
    store.append("k", &later, b"c", 30).unwrap();
    assert_eq!(store.settle("k", &later, 30).unwrap().expires, 5_030, "and the later upload by its own");
}

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

/// (3) ONE HANDLE PER REQUEST: a resume opens the partial for the request
/// that resumes it, and the request's end closes it — a settle short of the
/// length, a finish, an end, a `close_handle` for a request cut short — so
/// no file stays open for an upload no request is streaming. Another
/// principal's settle closes nothing of this principal's; and past its
/// settle a request appends nothing until the next resume opens the partial
/// again.
#[test]
fn no_handle_outlives_the_request_that_opened_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open(&dir.path().join("blobs"), 0);
    let rec = store.create_upload("k", "blake3", 10, INTERVAL, 0).unwrap();
    store.resume("k", &rec.id, 0, 1).unwrap();
    store.append("k", &rec.id, b"first", 1).unwrap();
    assert_eq!(store.handles_open(), 1, "the request streaming holds one");
    assert!(matches!(store.settle("other", &rec.id, 1), Err(BlobError::NoUpload)));
    assert_eq!(store.handles_open(), 1, "another principal's settle closes nothing of this principal's");
    let r = store.settle("k", &rec.id, 1).unwrap();
    assert_eq!(r.offset, 5);
    assert_eq!(store.handles_open(), 0, "a settle short of the length closes it");
    assert!(matches!(store.append("k", &rec.id, b"-", 1), Err(BlobError::NotResumed)));
    store.resume("k", &rec.id, 5, 2).unwrap();
    store.append("k", &rec.id, b"-last", 2).unwrap();
    let fin = store.finish("k", &rec.id, INTERVAL, 2).unwrap();
    assert_eq!(fin.hex, hex_of(b"first-last"));
    assert_eq!(store.handles_open(), 0, "and so does a finish");
    // An end, and a `close_handle` for a request cut short, close theirs too.
    let ended = standing(&store, "k", 10, b"", 3);
    store.resume("k", &ended.id, 0, 3).unwrap();
    store.end_upload("k", &ended.id, 3).unwrap();
    assert_eq!(store.handles_open(), 0, "an end closes it");
    let cut = standing(&store, "k", 10, b"", 3);
    store.resume("k", &cut.id, 0, 3).unwrap();
    store.append("k", &cut.id, b"cut", 3).unwrap();
    store.close_handle(&cut.id);
    assert_eq!(store.handles_open(), 0, "a close_handle closes it");
    assert_eq!(store.upload("k", &cut.id, 3).unwrap().offset, 0, "unsettled: nothing received");
}

/// (4) AT OPEN THE TWO ARE RECONCILED BOTH WAYS, and their lengths: a
/// partial no record names is removed, in every designation directory; a
/// record whose partial is gone is retired; a partial longer than its
/// record's offset is cut back; a record whose offset passes its partial's
/// length is set back to the length (a copy that took the partial before
/// its record); an expired upload is retired and its partial removed; and
/// the records log is compacted to the current records. Beside them, every
/// aside a crash left is removed — and a name that only begins as an
/// aside's is none, and is left.
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
        store.resume("k", &r.id, r.offset, now).unwrap();
        let fill = vec![b'x'; 100 - head.len() - tail.len()];
        store.append("k", &r.id, tail, now).unwrap();
        store.append("k", &r.id, &fill, now).unwrap();
        store.settle("k", &r.id, now).unwrap();
        let fin = store.finish("k", &r.id, INTERVAL, now).unwrap();
        let mut whole = head.to_vec();
        whole.extend_from_slice(tail);
        whole.extend(fill);
        assert_eq!(fin.hex, hex_of(&whole));
    }
}

/// (4) REMOVED ON EXPIRY, while the store serves — the pruner's act:
/// [`Store::expired_uploads`] lists every record past its expiry, whatever
/// principal minted it, reading no reference; [`Store::expire_upload`]
/// removes the partial and retires the record, and leaves a standing upload
/// as it is, so a clock that moved between the read and the act costs
/// nothing.
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
    assert_eq!(store.pending_bytes("a", 1, every_deposit_unplaced), 0);
    assert_eq!(store.pending_bytes("b", now, every_deposit_unplaced), 4, "the standing one counts");
}

/// (6) THE END keeps nothing: the partial removed, the record retired, the
/// principal's pending bytes falling at once; a second end, and a resume,
/// answer `NoUpload`; the identifier is never re-minted. And a torn tail of
/// the records log is truncated at open, trust ending at the first torn
/// line.
#[test]
fn an_ended_upload_keeps_nothing_and_a_torn_log_tail_is_cut() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("blobs");
    let id = {
        let store = open(&root, 0);
        let a = standing(&store, "k", 100, b"abc", 1);
        let b = standing(&store, "k", 100, b"def", 1);
        assert_eq!(store.pending_bytes("k", 2, every_deposit_unplaced), 6);
        store.end_upload("k", &a.id, 2).unwrap();
        assert_eq!(store.pending_bytes("k", 2, every_deposit_unplaced), 3);
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
