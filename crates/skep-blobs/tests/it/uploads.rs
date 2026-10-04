//! THE UPLOAD RECORDS and THE PARTIALS (M-I5 (c) THE DEPOSIT RECORD IS THE
//! PRINCIPAL'S, READABLE, EXACT; M-I2 (e) THE REQUESTER'S OWN RECORD BEFORE
//! ANY SHARED FACT; `media.md` the resumable upload's clauses (1), (3), (4),
//! (5), (6)): the identifier — never a sequence, parsed from exactly its
//! spelling, ordered as it is spelled — and the one "no upload" every act
//! answers for an identifier the asker does not hold; the durable offset,
//! the cut-back, and every other offset refused; one expiry, moved by a
//! byte received and by nothing else, fixed from the upload's own interval
//! and saturating at the last instant; one handle per request; the
//! reconciliation both ways at open, and a record line whose designation
//! climbs out of the root read as no record, nothing beside the root
//! touched; the expiry, an expired upload's handle closed with it; the end;
//! the listings in identifier order; and the compaction, down to nothing
//! where nothing stands.

use std::fs::{self, OpenOptions};
use std::time::Duration;

use skep_blobs::{BlobError, LeaseState, NotAnUploadId, UploadId, UploadRecord, SYNC_GRAIN};

use crate::{every_deposit_unplaced, hex_of, open, put_whole, standing, HORIZON_MS, INTERVAL, INTERVAL_MS};

/// (1) THE IDENTIFIER: 32 lowercase hex of 128 OS bits — two mints differ
/// (that no run of mints is a sequence is
/// `consecutive_identifiers_stand_in_no_order_and_differ_in_most_bits`'s
/// claim); the parse admits exactly the spelling, through `UploadId::parse`
/// and through `FromStr` alike, and the spelling is the identifier's
/// `Display`; identifiers order as their spellings do; and an identifier is
/// answered to its principal ALONE: another principal's lookup, a resume,
/// an end, an append and the count of bytes written each answer as for a
/// never-minted identifier, even while the upload is open in this process
/// (M-I2 (e)).
#[test]
fn the_identifier_is_32_lowercase_hex_and_answers_to_its_principal_alone() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open(&dir.path().join("blobs"), 0);
    let first = store.create_upload("a", "blake3", 5, INTERVAL, 0).unwrap();
    let second = store.create_upload("a", "blake3", 5, INTERVAL, 0).unwrap();
    assert_ne!(first.id, second.id);
    assert_eq!(first.id.to_hex().len(), 32);
    assert!(first.id.to_hex().bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)));
    assert_eq!(UploadId::parse(&first.id.to_hex()), Some(first.id));
    assert_eq!(UploadId::parse(&first.id.to_hex().to_uppercase()), None);
    assert_eq!(UploadId::parse(&first.id.to_hex()[..31]), None);
    assert_eq!(first.id.to_hex().parse::<UploadId>(), Ok(first.id));
    assert_eq!(first.id.to_hex().to_uppercase().parse::<UploadId>(), Err(NotAnUploadId));
    assert_eq!(first.id.to_hex()[..31].parse::<UploadId>(), Err(NotAnUploadId));
    assert_eq!(first.id.to_string(), first.id.to_hex());
    assert_eq!(format!("{:?}", first.id), format!("UploadId({})", first.id.to_hex()));
    assert_eq!(
        first.id < second.id,
        first.id.to_hex() < second.id.to_hex(),
        "an identifier orders as its spelling"
    );
    let never = UploadId::parse("00000000000000000000000000000000").unwrap();
    for (principal, id) in [("b", first.id), ("a", never)] {
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
    store.resume("a", &first.id, 0, 1).unwrap();
    assert_eq!(store.written("a", &first.id, 1), Some(0));
    assert_eq!(store.written("b", &first.id, 1), None, "another principal's count is no upload's");
    assert!(matches!(store.append("b", &first.id, b"x", 1), Err(BlobError::NoUpload)));
}

/// (1) AN IDENTIFIER IS NEVER A SEQUENCE: sixteen consecutive mints stand in
/// no order, rising or falling, and each differs from the one before in at
/// least 24 of its 128 bits — a counter, a clock or a monotonic identifier
/// rises; one stepped in its low bits differs from the one before in a few.
/// Sixteen OS draws fall in order, or hold a consecutive pair this alike,
/// about once in 10^12.
#[test]
fn consecutive_identifiers_stand_in_no_order_and_differ_in_most_bits() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open(&dir.path().join("blobs"), 0);
    let ids: Vec<UploadId> =
        (0..16).map(|_| store.create_upload("k", "blake3", 1, INTERVAL, 0).unwrap().id).collect();
    assert!(!ids.windows(2).all(|w| w[0] < w[1]), "the mints rise: {ids:?}");
    assert!(!ids.windows(2).all(|w| w[0] > w[1]), "the mints fall: {ids:?}");
    let bits = |id: &UploadId| u128::from_str_radix(&id.to_hex(), 16).expect("32 hex");
    for w in ids.windows(2) {
        let differ = (bits(&w[0]) ^ bits(&w[1])).count_ones();
        assert!(differ >= 24, "{:?} then {:?}: {differ} of 128 bits differ", w[0], w[1]);
    }
}

/// (1) THE PARSE ADMITS EXACTLY THE SPELLING, AND AN IDENTIFIER ORDERS AS
/// ITS SPELLING: over sixty-four spellings, each parses back to itself by
/// both parses; any one character changed to one outside lowercase hex —
/// the uppercase of a hex letter among them — or the spelling cut or grown
/// by one, is no identifier; and every pair orders as its spellings do.
#[test]
fn the_parse_admits_exactly_the_spelling_and_identifiers_order_as_spelled() {
    let spellings: Vec<String> = (0u8..64).map(|i| hex_of(&[i])[..32].to_string()).collect();
    let ids: Vec<UploadId> = spellings.iter().map(|s| UploadId::parse(s).expect("32 lowercase hex")).collect();
    for (s, id) in spellings.iter().zip(&ids) {
        assert_eq!((id.to_hex(), s.parse::<UploadId>()), (s.clone(), Ok(*id)), "{s}");
        for at in 0..32 {
            for bad in ['g', 'x', 'A', 'F', ' ', '-', 'é'] {
                let mut near = s.clone();
                near.replace_range(at..at + 1, bad.encode_utf8(&mut [0; 4]));
                assert_eq!((UploadId::parse(&near), near.parse::<UploadId>()), (None, Err(NotAnUploadId)), "{near:?}");
            }
        }
        for near in [s[..31].to_string(), format!("{s}0"), format!("0{s}")] {
            assert_eq!(UploadId::parse(&near), None, "{near:?}");
        }
    }
    for (a, sa) in ids.iter().zip(&spellings) {
        for (b, sb) in ids.iter().zip(&spellings) {
            assert_eq!(a.cmp(b), sa.cmp(sb), "{sa} against {sb}");
        }
    }
}

/// (1) ONE ANSWER FOR ALL FOUR (`BlobError::NoUpload`: "expired, retired,
/// another principal's, or never minted — ONE answer for all four"; M-I2
/// (e)): for every way an identifier can fail to name the asking
/// principal's standing upload, every act answers that one "no upload" —
/// the read, the listing, a resume stating an offset not the record's (so a
/// leaked offset would show), a settle, a finish, an end — and moves
/// nothing. The upload behind the first and third causes is whole and
/// settled, so a principal-blind or expiry-blind finish would land it.
#[test]
fn every_act_answers_no_upload_for_every_identifier_the_asker_does_not_hold() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("blobs");
    let store = open(&root, 0);
    let whole = |bytes: &[u8]| {
        let rec = store.create_upload("a", "blake3", bytes.len() as u64, Duration::from_millis(1_000), 0).unwrap();
        store.resume("a", &rec.id, 0, 0).unwrap();
        store.append("a", &rec.id, bytes, 0).unwrap();
        store.settle("a", &rec.id, 0).unwrap()
    };
    let held = whole(b"held by a");
    let ended = whole(b"ended by a");
    store.end_upload("a", &ended.id, 1).unwrap();
    let finished = whole(b"finished by a");
    store.finish("a", &finished.id, INTERVAL, 1).unwrap();
    let never = UploadId::parse("00000000000000000000000000000000").unwrap();
    for (cause, asker, id, now) in [
        ("another principal's", "b", held.id, 1),
        ("never minted", "a", never, 1),
        ("expired, at its expiry", "a", held.id, held.expires),
        ("retired by its end", "a", ended.id, 1),
        ("retired by its finish", "a", finished.id, 1),
    ] {
        assert_eq!(store.upload(asker, &id, now), None, "{cause}: the read");
        assert!(store.uploads_of(asker, now).iter().all(|r| r.id != id), "{cause}: the listing");
        assert!(matches!(store.resume(asker, &id, 3, now), Err(BlobError::NoUpload)), "{cause}: the resume");
        assert!(matches!(store.settle(asker, &id, now), Err(BlobError::NoUpload)), "{cause}: the settle");
        assert!(matches!(store.finish(asker, &id, INTERVAL, now), Err(BlobError::NoUpload)), "{cause}: the finish");
        assert!(matches!(store.end_upload(asker, &id, now), Err(BlobError::NoUpload)), "{cause}: the end");
    }
    assert_eq!(store.upload("a", &held.id, 1), Some(held.clone()), "the held upload stands as it was");
    assert!(root.join("blake3").join(format!(".upload-{}", held.id.to_hex())).is_file(), "its partial on disk");
    assert_eq!(store.blob_size("blake3", &hex_of(b"held by a")), None, "no finish named its bytes");
    assert_eq!(store.live_leases_of("b", 1), vec![], "no lease is b's");
    assert_eq!(store.pending_bytes("b", 1, every_deposit_unplaced), 0, "nothing counts as b's");
    assert_eq!(fs::read_to_string(root.join("leases.log")).unwrap().lines().count(), 1, "one finish, one lease line");
}

/// (3) ONE EXPIRY, fixed from the LAST BYTE RECEIVED and durable with it:
/// an append past the grain writes the record's offset and re-fixes its
/// expiry; a settle does the same at any length; bytes written but not yet
/// settled are not received — a resume in this process cuts the partial
/// back to the record's offset and continues from there — and a resume
/// stating any other offset, below the record's or past it, is refused
/// naming the record's (5), the partial as it stood.
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
    // Written past it, unsettled: the record stands; a resume stating any
    // offset but the record's — below it, past it, at the bytes written —
    // is refused naming the record's and cuts nothing; one at the record's
    // offset cuts the tail.
    store.append("k", &rec.id, &[3u8; 50], 30).unwrap();
    assert_eq!(store.written("k", &rec.id, 30), Some(SYNC_GRAIN + 50));
    let partial = root.join("blake3").join(format!(".upload-{}", rec.id.to_hex()));
    for stated in [0, 1, SYNC_GRAIN - 1, SYNC_GRAIN + 1, SYNC_GRAIN + 50, length, u64::MAX] {
        assert!(
            matches!(store.resume("k", &rec.id, stated, 30), Err(BlobError::Offset { recorded }) if recorded == SYNC_GRAIN),
            "a resume stating {stated}"
        );
    }
    assert_eq!(fs::metadata(&partial).unwrap().len(), SYNC_GRAIN + 50, "no refusal cut the partial");
    store.resume("k", &rec.id, SYNC_GRAIN, 30).unwrap();
    assert_eq!(store.written("k", &rec.id, 30), Some(SYNC_GRAIN));
    assert_eq!(fs::metadata(&partial).unwrap().len(), SYNC_GRAIN);
    // The last bytes, settled at the request's end: received, the length
    // reached, the hash the whole file's.
    store.append("k", &rec.id, &[4u8; 100], 40).unwrap();
    let r = store.settle("k", &rec.id, 40).unwrap();
    assert_eq!(r.offset, length);
    assert_eq!(r.expires, 40 + INTERVAL_MS);
    // The settle ended that request; the next resumes at the length, and
    // one byte more is refused, naming the length and the offset it would
    // start at, nothing written.
    store.resume("k", &rec.id, length, 41).unwrap();
    assert!(matches!(
        store.append("k", &rec.id, &[5u8], 41),
        Err(BlobError::Length { length: l, offset: o }) if (l, o) == (length, length)
    ));
    let fin = store.finish("k", &rec.id, INTERVAL, 50).unwrap();
    let mut whole = vec![1u8; 100];
    whole.extend(rest);
    whole.extend([4u8; 100]);
    assert_eq!(fin.hex, hex_of(&whole), "the hash covers the bytes as cut back and continued");
    assert_eq!(fs::read(store.blob_path("blake3", &fin.hex).unwrap()).unwrap(), whole);
    assert!(!partial.exists());
}

/// (3) ONE EXPIRY, MOVED BY NOTHING ELSE: a request that receives nothing —
/// a resume and its settle with no body, a resume cut short, an append
/// refused at the length — writes no record and leaves the expiry where the
/// last byte received put it, so no client holds an upload past its
/// interval without sending a byte.
#[test]
fn a_request_that_receives_nothing_moves_no_expiry_and_writes_no_record() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("blobs");
    let store = open(&root, 0);
    let rec = store.create_upload("k", "blake3", 10, INTERVAL, 0).unwrap();
    store.resume("k", &rec.id, 0, 10).unwrap();
    store.append("k", &rec.id, b"abc", 10).unwrap();
    let fixed = store.settle("k", &rec.id, 10).unwrap().expires;
    assert_eq!(fixed, 10 + INTERVAL_MS, "the last byte received fixes it");
    let lines = || fs::read_to_string(root.join("uploads.log")).unwrap().lines().count();
    let lines_before = lines();
    store.resume("k", &rec.id, 3, 20).unwrap();
    assert_eq!(store.settle("k", &rec.id, 20).unwrap().expires, fixed, "a resume and its settle with no body");
    store.resume("k", &rec.id, 3, 30).unwrap();
    store.close_handle(&rec.id);
    store.resume("k", &rec.id, 3, 40).unwrap();
    assert!(matches!(store.append("k", &rec.id, &[0; 8], 40), Err(BlobError::Length { .. })));
    assert_eq!(store.settle("k", &rec.id, 40).unwrap().expires, fixed, "an append refused at the length");
    assert_eq!(store.upload("k", &rec.id, 50).map(|r| r.expires), Some(fixed), "a resume cut short, too");
    assert_eq!(lines(), lines_before, "none of them wrote a record");
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

/// THE ONE EXPIRY RULE SATURATES: an interval past what a `u64` of
/// milliseconds holds — a venue's "forever" as a caller spells it — is held
/// as the most a line spells and fixes every expiry at the last instant,
/// the upload's at its creation and at its last byte received and the
/// lease's at its finish, never wrapping to one already past.
#[test]
fn an_interval_past_u64_milliseconds_saturates_at_the_last_instant() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("blobs");
    let forever = Duration::from_secs(u64::MAX);
    let rec = open(&root, 0).create_upload("k", "blake3", 5, forever, 7).unwrap();
    assert_eq!((rec.interval, rec.expires), (Duration::from_millis(u64::MAX), u64::MAX));
    let store = open(&root, u64::MAX - 1);
    assert_eq!(store.upload("k", &rec.id, u64::MAX - 1), Some(rec.clone()), "read back as answered, standing");
    store.resume("k", &rec.id, 0, 8).unwrap();
    store.append("k", &rec.id, b"bytes", 8).unwrap();
    assert_eq!(store.settle("k", &rec.id, 8).unwrap().expires, u64::MAX, "re-fixed at the last instant");
    let fin = store.finish("k", &rec.id, forever, 9).unwrap();
    assert_eq!(store.lease_state("k", "blake3", &fin.hex, u64::MAX - 1), LeaseState::Live { size: 5, expires: u64::MAX });
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

/// AN EXPIRED UPLOAD's HANDLE CLOSES WITH IT (`Store::expire_upload`: "its
/// handle closed, its partial removed, its record retired"): a request cut
/// short with no `close_handle` leaves its handle open; the pruner's act
/// leaves a standing upload's as it is and closes an expired one's — after
/// which no resume, end or expiry finds the upload to close it.
#[test]
fn an_expired_uploads_handle_closes_with_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open(&dir.path().join("blobs"), 0);
    let rec = store.create_upload("k", "blake3", 10, INTERVAL, 0).unwrap();
    store.resume("k", &rec.id, 0, 1).unwrap();
    store.append("k", &rec.id, b"abc", 1).unwrap();
    assert!(!store.expire_upload(&rec.id, rec.expires - 1).unwrap());
    assert_eq!(store.handles_open(), 1, "a standing upload's handle left as it is");
    assert!(store.expire_upload(&rec.id, rec.expires).unwrap());
    assert_eq!(store.handles_open(), 0, "the expired upload's handle closed with it");
}

/// THE UPLOAD LISTINGS ANSWER IN IDENTIFIER ORDER (`Store::uploads_of`,
/// `Store::expired_uploads`): eight uploads, listed standing and again
/// expired, come back sorted by identifier — eight in a random order fall
/// sorted once in 40,320.
#[test]
fn the_upload_listings_answer_in_identifier_order() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open(&dir.path().join("blobs"), 0);
    let mut ids: Vec<UploadId> =
        (0..8).map(|_| store.create_upload("k", "blake3", 1, Duration::from_millis(10), 0).unwrap().id).collect();
    ids.sort();
    let listed = |records: Vec<UploadRecord>| records.into_iter().map(|r| r.id).collect::<Vec<_>>();
    assert_eq!(listed(store.uploads_of("k", 5)), ids, "standing");
    assert_eq!(listed(store.expired_uploads(10)), ids, "expired");
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
        assert_ne!(store.create_upload("k", "blake3", 100, INTERVAL, 2).unwrap().id, a.id, "never minted again");
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
