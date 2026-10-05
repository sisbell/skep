//! THE PUT's ORDER (M-I5 (a) DURABLE BEFORE NAMED, ANSWERED AFTER RECORDED;
//! `media.md` Op inventory 1, the lease's crash story): the fsync order
//! observed through a SEEDED FAILURE INJECTION at each step of the finish —
//! never a mock of the filesystem — and what each failure leaves; the root's
//! fsync owed until a finish pays it, by every designation directory made
//! after the open whatever made it; a finish short of its length stopped as
//! its caller's bug; the finishes run one at a time, a hold parking its own
//! finish alone, and a held finish keeping no other upload's acts waiting;
//! and past a finish that failed after its rename, no handle left on the
//! hash's file, and the record it leaves over no partial leaving by its
//! end, its expiry and the next open past it.

use std::fs;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Barrier};
use std::thread;
use std::time::Duration;

use skep_blobs::{BlobError, HashFunction, LeaseState, Step, Stream};

use crate::{every_deposit_unplaced, hex_of, open, panic_message, put_whole, standing, INTERVAL, INTERVAL_MS};

/// THE ORDER, STEP BY STEP (M-I5 (a)): for every step of the finish, a
/// finish that FAILS at that step — the seeded injection, one trial per
/// step, the store reopened after each — leaves the invariants the order
/// exists for: before the lease's sync, NO lease names the file whatever
/// the directory holds; before the rename, the file is absent and the
/// partial stands with its record; at a failure after the lease, the lease
/// stands over a whole file and the record — the finish's one residue — is
/// retired by open's reconciliation. Never a lease naming bytes that are
/// not there.
#[test]
fn a_failure_at_each_step_of_the_finish_leaves_what_the_order_promises() {
    let steps = [
        Step::PartialSync,
        Step::Rename,
        Step::DirSync,
        Step::RootSync,
        Step::LeaseSync,
        Step::RecordRetire,
    ];
    for (i, step) in steps.iter().enumerate() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("blobs");
        let now = 1_000 + i as u64;
        let bytes = format!("file for step {step:?}").into_bytes();
        let hex = hex_of(&bytes);
        let (id, state, present) = {
            let store = open(&root, now);
            store.fail_at(Some(*step));
            let rec = store.create_upload("k", HashFunction::Blake3, bytes.len() as u64, INTERVAL, now).unwrap();
            let mut stream = store.resume("k", &rec.id, 0, now).unwrap();
            stream.append(&bytes, now).unwrap();
            stream.settle(now).unwrap();
            let stream = store.resume("k", &rec.id, bytes.len() as u64, now).unwrap();
            let err = stream.finish(INTERVAL, now).expect_err("the injected failure");
            assert!(matches!(err, BlobError::Io(_)), "{step:?}: {err}");
            // Before the lease's sync, the principal holds NO lease —
            // whatever the directory holds — and the file is present only
            // from the rename on.
            let state = store.lease_state("k", "blake3", &hex, now);
            let present = store.blob_size("blake3", &hex).unwrap_or_else(|e| panic!("{step:?}: {e}")).is_some();
            (rec.id, state, present)
        };
        match step {
            Step::PartialSync | Step::Rename => {
                assert_eq!(state, LeaseState::None, "{step:?}");
                assert!(!present, "{step:?}: the file is absent before the rename");
            }
            Step::DirSync | Step::RootSync | Step::LeaseSync => {
                assert_eq!(state, LeaseState::None, "{step:?}: no lease before its sync");
                assert!(present, "{step:?}: the file stands, leaseless and prunable");
            }
            Step::RecordRetire => {
                assert_eq!(
                    state,
                    LeaseState::Live { size: bytes.len() as u64, expires: now + INTERVAL_MS },
                    "{step:?}: the lease synced before the failure stands"
                );
                assert!(present, "{step:?}: over the file");
            }
            // The replace's two steps: a fresh finish never meets them
            // (`replace.rs`'s `a_failure_at_each_step_of_a_replace_…` drives them).
            Step::LinkAside | Step::UnlinkAside => unreachable!("not a step of a fresh finish"),
        }
        // Reopen: the reconciliation. A record whose partial was renamed
        // away is retired; one whose partial stands is kept; a lease never
        // names bytes that are not there.
        let store = open(&root, now + 1);
        let record = store.upload("k", &id, now + 1);
        let partial = root.join("blake3").join(format!(".upload-{}", id.to_hex()));
        match step {
            Step::PartialSync | Step::Rename => {
                let r = record.unwrap_or_else(|| panic!("{step:?}: the upload stands with its partial"));
                assert_eq!(r.offset, bytes.len() as u64, "{step:?}: at the offset its settle received");
                assert!(partial.is_file(), "{step:?}: its partial on disk");
                assert_eq!(
                    store.pending_bytes("k", now + 1, every_deposit_unplaced),
                    bytes.len() as u64,
                    "{step:?}: its bytes received pending"
                );
            }
            _ => {
                assert!(record.is_none(), "{step:?}: a record with no partial is retired at open");
                assert!(!partial.exists(), "{step:?}: and no partial stands");
            }
        }
        for lease in store.live_leases_of("k", now + 1) {
            assert_eq!(
                store.blob_size(&lease.designation, &lease.hex).unwrap_or_else(|e| panic!("{step:?}: {e}")),
                Some(lease.size),
                "{step:?}: a lease names a whole file"
            );
        }
        // The same bytes PUT again, the injection cleared: whole, leased,
        // and the answer the one shape (REPLACE over a file the failed
        // finish left, or a fresh install).
        let fin = put_whole(&store, "k", &bytes, now + 2);
        assert_eq!(fin.hex, hex, "{step:?}");
        assert_eq!(fin.size, bytes.len() as u64, "{step:?}");
        assert_eq!(fs::read(store.blob_path("blake3", &hex).unwrap()).unwrap(), bytes, "{step:?}: the file whole");
        assert_eq!(
            store.lease_state("k", "blake3", &hex, now + 2),
            LeaseState::Live { size: bytes.len() as u64, expires: now + 2 + INTERVAL_MS },
            "{step:?}: leased"
        );
    }
}

/// THE ROOT's FSYNC IS OWED UNTIL A FINISH PAYS IT (M-I5 (a): "and `blobs/`
/// where the designation directory is new"; `Step::RootSync`): no lease
/// names a file in a new designation directory before the root's fsync; a
/// finish whose root fsync failed leaves it owed, so the next finish into
/// that directory meets it again before its lease; once paid, no finish
/// takes it again.
#[test]
fn the_roots_fsync_is_owed_until_a_finish_pays_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open(&dir.path().join("blobs"), 0);
    let put = |bytes: &[u8], now: u64| {
        let rec = store.create_upload("k", HashFunction::Blake3, bytes.len() as u64, INTERVAL, now).unwrap();
        let mut stream = store.resume("k", &rec.id, 0, now).unwrap();
        stream.append(bytes, now).unwrap();
        stream.finish(INTERVAL, now)
    };
    store.fail_at(Some(Step::RootSync));
    for (bytes, now) in [(b"first".as_slice(), 1), (b"second", 2)] {
        assert!(matches!(put(bytes, now), Err(BlobError::Io(_))), "at {now}: the root's fsync still owed, and met");
        assert_eq!(store.lease_state("k", "blake3", &hex_of(bytes), now), LeaseState::None, "at {now}: no lease before it");
    }
    store.fail_at(None);
    assert!(put(b"third", 3).is_ok(), "paid");
    store.fail_at(Some(Step::RootSync));
    assert!(put(b"fourth", 4).is_ok(), "once paid, never taken again");
}

/// A DESIGNATION DIRECTORY MADE AFTER THE OPEN OWES THE ROOT's FSYNC,
/// WHATEVER MADE IT (M-I5 (a); `Step::RootSync`): a creation that fails past
/// its directory's mkdir leaves the directory standing with no upload in it
/// — made on disk here — and the first finish into it still meets the
/// root's fsync before its lease; a directory that stood when the store
/// opened, which the open's own root fsync made durable, owes none.
#[test]
fn a_designation_directory_made_after_the_open_owes_the_roots_fsync_whatever_made_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("blobs");
    let store = open(&root, 0);
    fs::create_dir(root.join("blake3")).unwrap();
    store.fail_at(Some(Step::RootSync));
    let rec = store.create_upload("k", HashFunction::Blake3, 5, INTERVAL, 1).unwrap();
    let mut stream = store.resume("k", &rec.id, 0, 1).unwrap();
    stream.append(b"bytes", 1).unwrap();
    assert!(matches!(stream.finish(INTERVAL, 1), Err(BlobError::Io(_))), "the root's fsync owed, and met");
    assert_eq!(store.lease_state("k", "blake3", &hex_of(b"bytes"), 1), LeaseState::None, "no lease before it");
    drop(store);
    let store = open(&root, 2);
    store.fail_at(Some(Step::RootSync));
    assert_eq!(put_whole(&store, "k", b"bytes", 3).hex, hex_of(b"bytes"), "a directory standing at the open owes none");
}

/// (7) A FINISH IS OWED THE WHOLE LENGTH (`Stream::finish`'s precondition:
/// the stream's bytes written reach the upload's declared length): short of
/// it — over unsettled bytes, and on a stream resumed at a settled short
/// offset — the finish STOPS as its caller's bug, a panic naming the bytes
/// held, the length and the obligation, never a refusal an honest caller
/// would have to answer; its stream dropped with the panic, nothing is named
/// — no file at the hash of the bytes held, no lease — and the upload stands
/// to be resumed; the bytes that complete it finish it whole.
#[test]
fn a_finish_short_of_the_declared_length_stops_as_its_callers_bug_and_names_nothing() {
    fn short_finish(stream: Stream<'_>, now: u64) -> String {
        let stopped = catch_unwind(AssertUnwindSafe(move || stream.finish(INTERVAL, now)));
        panic_message(stopped.expect_err("a short finish stops"))
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open(&dir.path().join("blobs"), 0);
    let rec = store.create_upload("k", HashFunction::Blake3, 10, INTERVAL, 1).unwrap();
    let held_hex = hex_of(b"half-");
    let mut stream = store.resume("k", &rec.id, 0, 1).unwrap();
    stream.append(b"half-", 1).unwrap();
    let message = short_finish(stream, 1);
    assert!(message.contains("at 5 of its 10 bytes") && message.contains("precondition"), "{message}");
    let mut stream = store.resume("k", &rec.id, 0, 2).unwrap();
    stream.append(b"half-", 2).unwrap();
    stream.settle(2).unwrap();
    let message = short_finish(store.resume("k", &rec.id, 5, 3).unwrap(), 3);
    assert!(message.contains("at 5 of its 10 bytes"), "resumed at the settled offset: {message}");
    assert_eq!(store.blob_size("blake3", &held_hex).unwrap(), None, "no file named by the bytes held");
    assert_eq!(store.lease_state("k", "blake3", &held_hex, 3), LeaseState::None, "and no lease");
    assert_eq!(store.upload("k", &rec.id, 3).map(|r| r.offset), Some(5), "the upload stands, to be resumed");
    let mut stream = store.resume("k", &rec.id, 5, 4).unwrap();
    stream.append(b"whole", 4).unwrap();
    let fin = stream.finish(INTERVAL, 4).unwrap();
    assert_eq!((fin.hex, fin.size), (hex_of(b"half-whole"), 10));
}

/// A HOLD PARKS ITS OWN FINISH AND NOTHING ELSE: the seam runs a hold with
/// none of its own state locked, so while one finish is parked a deferred
/// unlink on another thread — which passes the seam's hook before each
/// aside — meets no lock of the seam's and unlinks the aside an answered
/// replace queued; the held finish then answers.
#[test]
fn a_hold_parks_its_own_finish_and_nothing_else() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open(&dir.path().join("blobs"), 0);
    let right = b"the picture's bytes".to_vec();
    store.install("blake3", &hex_of(&right), b"garbage under the right name").unwrap();
    put_whole(&store, "k", &right, 5); // a replace: its aside queued
    assert_eq!(store.asides_queued(), 1);
    let parked = Arc::new(Barrier::new(2));
    let resumed = Arc::new(Barrier::new(2));
    let (at_hold, after) = (parked.clone(), resumed.clone());
    store.hold_at(Step::RecordRetire, move || {
        at_hold.wait();
        after.wait();
    });
    let store = &store;
    let (unlinked, finished) = thread::scope(|s| {
        let finishing = s.spawn(|| put_whole(store, "k", b"other bytes", 10));
        parked.wait();
        let (tx, rx) = mpsc::channel();
        s.spawn(move || tx.send(store.unlink_asides().map_err(|e| e.to_string())));
        // No assertion while the finish is held: a failed one would leave it
        // parked, the scope waiting on it.
        let unlinked = rx.recv_timeout(Duration::from_secs(5));
        resumed.wait();
        (unlinked, finishing.join())
    });
    assert_eq!(unlinked, Ok(Ok(1)), "the deferred unlink met no lock of the seam's while a finish was parked");
    assert_eq!(finished.expect("the held finish answers").hex, hex_of(b"other bytes"));
    assert!(store.asides_of("blake3").unwrap().is_empty());
}

/// A HELD FINISH KEEPS NO OTHER UPLOAD's ACTS WAITING (`Store`'s finish lock:
/// "No other shipped act takes it, so no append waits on another upload's
/// finish; the store's other locks are taken under it, briefly"): one finish
/// parked past its rename — where its syncs fall, the slowest stretch of any
/// PUT — another principal's creation, resume, append and settle answer,
/// and so do the reads beside them. (The deferred unlink's freedom from the
/// seam is `a_hold_parks_its_own_finish_and_nothing_else`'s claim.)
#[test]
fn a_held_finish_keeps_no_other_uploads_acts_waiting() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open(&dir.path().join("blobs"), 0);
    let held = b"the held finish's bytes";
    let rec = store.create_upload("a", HashFunction::Blake3, held.len() as u64, INTERVAL, 1).unwrap();
    let mut stream = store.resume("a", &rec.id, 0, 1).unwrap();
    stream.append(held, 1).unwrap();
    let parked = Arc::new(Barrier::new(2));
    let resumed = Arc::new(Barrier::new(2));
    let (at_hold, after) = (parked.clone(), resumed.clone());
    store.hold_at(Step::DirSync, move || {
        at_hold.wait();
        after.wait();
    });
    let store = &store;
    let (others, finished) = thread::scope(|s| {
        let finishing = s.spawn(move || stream.finish(INTERVAL, 2));
        parked.wait();
        let (tx, rx) = mpsc::channel();
        s.spawn(move || {
            let settled = standing(store, "b", 10, b"abc", 2);
            tx.send((
                store.upload("b", &settled.id, 2).map(|r| r.offset),
                store.pending_bytes("b", 2, every_deposit_unplaced),
                store.lease_state("a", "blake3", &hex_of(held), 2),
            ))
        });
        // No assertion while the finish is held: a failed one would leave it
        // parked, the scope waiting on it.
        let others = rx.recv_timeout(Duration::from_secs(5));
        resumed.wait();
        (others, finishing.join())
    });
    assert_eq!(
        others,
        Ok((Some(3), 3, LeaseState::None)),
        "another upload's acts, or the reads beside them, waited on the held finish"
    );
    assert_eq!(finished.expect("the held finish's thread").expect("the held finish answers").hex, hex_of(held));
}

/// THE FINISHES RUN ONE AT A TIME (`Store`'s finish lock, held by every
/// finish from its first act to its answer, "so two finishes of one hash
/// never interleave the replace's check, link and rename"): with one replace
/// held between its link and its rename, a second finish of the same hash
/// meets none of the seam's hooks until the first has answered. The seam
/// runs a hold with none of its own state locked, so only the store's finish
/// lock keeps the second out. A finish not held back meets its first hook
/// within milliseconds and the window here is half a second, so this test
/// can err only toward passing.
#[test]
fn the_finishes_run_one_at_a_time() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open(&dir.path().join("blobs"), 0);
    let bytes = b"one hash, two finishes".to_vec();
    let hex = hex_of(&bytes);
    store.install("blake3", &hex, b"garbage under the right name").unwrap();
    let first = standing(&store, "a", bytes.len() as u64, &bytes, 1);
    let second = standing(&store, "b", bytes.len() as u64, &bytes, 1);
    let stream_a = store.resume("a", &first.id, first.offset, 1).unwrap();
    let stream_b = store.resume("b", &second.id, second.offset, 1).unwrap();
    let parked = Arc::new(Barrier::new(2));
    let resumed = Arc::new(Barrier::new(2));
    let (met_tx, met_rx) = mpsc::channel();
    let (at_hold, after, arrivals) = (parked.clone(), resumed.clone(), AtomicUsize::new(0));
    store.hold_at(Step::Rename, move || {
        if arrivals.fetch_add(1, Ordering::SeqCst) == 0 {
            at_hold.wait();
            after.wait();
        } else {
            let _ = met_tx.send(());
        }
    });
    let (met, a, b) = thread::scope(|s| {
        let a = s.spawn(move || stream_a.finish(INTERVAL, 2));
        parked.wait();
        let b = s.spawn(move || stream_b.finish(INTERVAL, 2));
        // No assertion while the first finish is held: a failed one would
        // leave it parked, the scope waiting on it.
        let met = met_rx.recv_timeout(Duration::from_millis(500));
        resumed.wait();
        (met, a.join(), b.join())
    });
    assert_eq!(
        met,
        Err(mpsc::RecvTimeoutError::Timeout),
        "the second finish met a seam hook while the first was held inside its replace"
    );
    assert_eq!(a.expect("the first thread").expect("the first finish answers").hex, hex);
    assert_eq!(b.expect("the second thread").expect("the second finish answers, after it").hex, hex);
    assert_eq!(store.asides_queued(), 2, "each a replace, each queued its aside at its answer");
}

/// A FINISH THAT FAILED PAST ITS RENAME TAKES ITS HANDLE WITH IT (clause
/// (7)): from the rename on, the partial's open file IS the hash's file, so
/// a handle kept there would let the next resume cut the hash's bytes back
/// to the record's offset and stream the next request's bytes into them.
/// The finish consumes its stream, handle and all; the bytes here were
/// never settled — the record's offset stands at 0 — and the resume after
/// the failure finds no partial, answering I/O, the hash's bytes untouched.
#[test]
fn a_finish_that_failed_past_its_rename_leaves_no_handle_on_the_hashs_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open(&dir.path().join("blobs"), 0);
    let bytes = b"the bytes the rename named".to_vec();
    let hex = hex_of(&bytes);
    let rec = store.create_upload("k", HashFunction::Blake3, bytes.len() as u64, INTERVAL, 1).unwrap();
    let mut stream = store.resume("k", &rec.id, 0, 1).unwrap();
    stream.append(&bytes, 1).unwrap();
    assert_eq!(store.upload("k", &rec.id, 1).unwrap().offset, 0, "short of the grain: written, not received");
    store.fail_at(Some(Step::DirSync));
    assert!(matches!(stream.finish(INTERVAL, 1), Err(BlobError::Io(_))));
    let at_hash = store.blob_path("blake3", &hex).unwrap();
    assert_eq!(fs::read(&at_hash).unwrap(), bytes, "the rename named the bytes");
    store.fail_at(None);
    assert!(matches!(store.resume("k", &rec.id, 0, 2), Err(BlobError::Io(_))), "the partial was renamed away");
    assert_eq!(fs::read(&at_hash).unwrap(), bytes, "the hash's file untouched");
}

/// A RECORD OVER THE PARTIAL A FAILED FINISH TOOK LEAVES BY EVERY EXIT ITS
/// DOC NAMES (`Stream::finish`, what an `Io` leaves past the rename: "the
/// record stands in this process over a partial the rename took … until the
/// upload is ended, expires, or the next open retires it"; `partials::remove`:
/// "absent is fine"): three finishes fail past their renames, each record
/// left standing over no partial — the first ended, as a client's
/// termination ends it; the second expired by the pruner's act at its
/// expiry; the third outliving its expiry to the next open, as a crash
/// leaves a retirement line the OS never wrote beside a partial already
/// gone. Each exit answers as it would over a partial — the end `Ok`, the
/// expiry `true`, the open whole — and leaves no record, every file a rename
/// named standing.
#[test]
fn a_record_over_the_partial_a_failed_finish_took_leaves_by_every_exit() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("blobs");
    let store = open(&root, 0);
    store.fail_at(Some(Step::DirSync));
    let mut failed = Vec::new();
    for exit in ["ended", "expired", "reopened"] {
        let bytes = format!("the {exit} upload's bytes").into_bytes();
        let rec = store.create_upload("k", HashFunction::Blake3, bytes.len() as u64, INTERVAL, 1).unwrap();
        let mut stream = store.resume("k", &rec.id, 0, 1).unwrap();
        stream.append(&bytes, 1).unwrap();
        assert!(matches!(stream.finish(INTERVAL, 1), Err(BlobError::Io(_))), "{exit}: failed past its rename");
        assert!(
            matches!(store.resume("k", &rec.id, 0, 1), Err(BlobError::Io(_))),
            "{exit}: its record stands over no partial"
        );
        failed.push((rec, hex_of(&bytes)));
    }
    store.fail_at(None);
    let (ended, expired, reopened) = (&failed[0].0, &failed[1].0, &failed[2].0);
    store.end_upload("k", &ended.id, 2).expect("the end answers over no partial");
    assert_eq!(store.upload("k", &ended.id, 2), None, "ended: retired");
    let removed = store.expire_upload(&expired.id, expired.expires).expect("the pruner's act answers over no partial");
    assert!(removed, "expired: removed");
    assert!(store.expired_uploads(expired.expires).iter().all(|r| r.id != expired.id), "expired: retired");
    drop(store);
    // The third exit's check is the open itself: the helper panics where it fails.
    let store = open(&root, reopened.expires);
    assert_eq!(store.expired_uploads(reopened.expires), vec![], "the next open retired the record left over nothing");
    assert_eq!(fs::read_to_string(root.join("uploads.log")).unwrap(), "", "and compacted every record away");
    for (_, hex) in &failed {
        assert!(store.blob_size("blake3", hex).unwrap().is_some(), "{hex}: the file its rename named stands");
    }
}
