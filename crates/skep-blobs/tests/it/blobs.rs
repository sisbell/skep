//! THE FILES and THE PUT's ORDER (M-I5 (a) DURABLE BEFORE NAMED, ANSWERED
//! AFTER RECORDED; `media.md` Op inventory 1, the REPLACE paragraph and the
//! lease's crash story): the fsync order observed through a SEEDED FAILURE
//! INJECTION at each step of the finish — never a mock of the filesystem —
//! and what each failure leaves; the root's fsync owed until a finish pays
//! it; a finish short of its length refused; the finishes run one at a
//! time, and a hold parking its own finish alone; REPLACE's answer, the one
//! a PUT gives where no file stood, and its repair of a corrupt file; an
//! aside name of its own for every replace, and the deferred unlink's queue
//! — an aside queued only at its finish's answer, one already gone counted
//! unlinked, a failure leaving it and every one after it queued; the name
//! check at every entry point; the directory listings, each naming its own
//! class in name order; and the floor's read of the space available on the
//! volume.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Barrier};
use std::thread;
use std::time::Duration;

use skep_blobs::{BlobError, LeaseState, Step};

use crate::{every_deposit_unplaced, hex_of, open, put_whole, standing, INTERVAL, INTERVAL_MS};

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
        let outcome = {
            let store = open(&root, now);
            store.fail_at(Some(*step));
            let rec = store.create_upload("k", "blake3", bytes.len() as u64, INTERVAL, now).unwrap();
            store.resume("k", &rec.id, 0, now).unwrap();
            store.append("k", &rec.id, &bytes, now).unwrap();
            store.settle("k", &rec.id, now).unwrap();
            let err = store.finish("k", &rec.id, INTERVAL, now).expect_err("the injected failure");
            assert!(matches!(err, BlobError::Io(_)), "{step:?}: {err}");
            // Before the lease's sync, the principal holds NO lease —
            // whatever the directory holds — and the file is present only
            // from the rename on.
            let state = store.lease("k", "blake3", &hex, now);
            let present = store.blob_size("blake3", &hex).is_some();
            (rec.id, state, present)
        };
        let (id, state, present) = outcome;
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
            // (`a_failure_at_each_step_of_a_replace_…` drives them).
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
                store.blob_size(&lease.designation, &lease.hex),
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
            store.lease("k", "blake3", &hex, now + 2),
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
        let rec = store.create_upload("k", "blake3", bytes.len() as u64, INTERVAL, now).unwrap();
        store.resume("k", &rec.id, 0, now).unwrap();
        store.append("k", &rec.id, bytes, now).unwrap();
        store.finish("k", &rec.id, INTERVAL, now)
    };
    store.fail_at(Some(Step::RootSync));
    for (bytes, now) in [(b"first".as_slice(), 1), (b"second", 2)] {
        assert!(matches!(put(bytes, now), Err(BlobError::Io(_))), "at {now}: the root's fsync still owed, and met");
        assert_eq!(store.lease("k", "blake3", &hex_of(bytes), now), LeaseState::None, "at {now}: no lease before it");
    }
    store.fail_at(None);
    assert!(put(b"third", 3).is_ok(), "paid");
    store.fail_at(Some(Step::RootSync));
    assert!(put(b"fourth", 4).is_ok(), "once paid, never taken again");
}

/// (7) A FINISH IS OWED THE WHOLE LENGTH (`Store::finish`: "the upload's
/// bytes must reach its length"): short of it — with the request's handle
/// open over unsettled bytes, and with none over a settled short offset —
/// the finish is refused `Incomplete`, naming the bytes held and the
/// length, its handle gone whatever it answered; nothing is named, no file
/// at the hash of the bytes held and no lease, and the upload stands to be
/// resumed; the bytes that complete it finish it whole.
#[test]
fn a_finish_short_of_the_declared_length_is_refused_and_names_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open(&dir.path().join("blobs"), 0);
    let rec = store.create_upload("k", "blake3", 10, INTERVAL, 1).unwrap();
    let held = hex_of(b"half-");
    store.resume("k", &rec.id, 0, 1).unwrap();
    store.append("k", &rec.id, b"half-", 1).unwrap();
    assert!(matches!(store.finish("k", &rec.id, INTERVAL, 1), Err(BlobError::Incomplete { offset: 5, length: 10 })));
    assert_eq!(store.handles_open(), 0, "the handle left with the refused finish");
    store.resume("k", &rec.id, 0, 2).unwrap();
    store.append("k", &rec.id, b"half-", 2).unwrap();
    store.settle("k", &rec.id, 2).unwrap();
    assert!(matches!(store.finish("k", &rec.id, INTERVAL, 3), Err(BlobError::Incomplete { offset: 5, length: 10 })));
    assert_eq!(store.blob_size("blake3", &held), None, "no file named by the bytes held");
    assert_eq!(store.lease("k", "blake3", &held, 3), LeaseState::None, "and no lease");
    assert_eq!(store.upload("k", &rec.id, 3).map(|r| r.offset), Some(5), "the upload stands, to be resumed");
    store.resume("k", &rec.id, 5, 4).unwrap();
    store.append("k", &rec.id, b"whole", 4).unwrap();
    let fin = store.finish("k", &rec.id, INTERVAL, 4).unwrap();
    assert_eq!((fin.hex, fin.size), (hex_of(b"half-whole"), 10));
}

/// THE REPLACE's ORDER, STEP BY STEP (M-I5 (a); "NO ANSWER OF THE UPLOAD
/// SAYS WHETHER THE FILE WAS ALREADY HERE" — the old instance's aside
/// unlinked after the answer): over a file planted with the WRONG bytes at
/// the right name, a finish that fails at each step of a replace — the two
/// aside steps among them — leaves the hash holding the OLD bytes whole
/// before the rename and the NEW bytes whole after it, never an absent
/// name; the aside stands from the link until the deferred unlink and is
/// gone or present, never a third state; a finish that fails past its link
/// queues no aside, leaving it to the pruner's pass and to open; a failure
/// at the deferred unlink itself leaves the answer given and the aside
/// queued for the next drain; and the reopen removes every aside a failure
/// left, the hash's bytes as the step left them.
#[test]
fn a_failure_at_each_step_of_a_replace_leaves_the_new_bytes_past_the_rename() {
    let steps = [
        Step::PartialSync,
        Step::LinkAside,
        Step::Rename,
        Step::DirSync,
        Step::LeaseSync,
        Step::RecordRetire,
        Step::UnlinkAside,
    ];
    let right = b"the picture's bytes, right".to_vec();
    let hex = hex_of(&right);
    let wrong = b"garbage under the right name".to_vec();
    for (i, step) in steps.iter().enumerate() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("blobs");
        let now = 1_000 + i as u64;
        let (aside_after, partial) = {
            let store = open(&root, now);
            store.install("blake3", &hex, &wrong).unwrap();
            store.fail_at(Some(*step));
            let rec = store.create_upload("k", "blake3", right.len() as u64, INTERVAL, now).unwrap();
            store.resume("k", &rec.id, 0, now).unwrap();
            store.append("k", &rec.id, &right, now).unwrap();
            store.settle("k", &rec.id, now).unwrap();
            let finish = store.finish("k", &rec.id, INTERVAL, now);
            let at_hash = fs::read(store.blob_path("blake3", &hex).unwrap())
                .unwrap_or_else(|e| panic!("{step:?}: the hash is never without a file: {e}"));
            let asides = store.asides_of("blake3").unwrap();
            match step {
                Step::PartialSync | Step::LinkAside => {
                    assert!(matches!(finish, Err(BlobError::Io(_))), "{step:?}");
                    assert_eq!(at_hash, wrong, "{step:?}: the old bytes stand before the rename");
                    assert!(asides.is_empty(), "{step:?}: no aside before the link");
                }
                Step::Rename => {
                    assert!(matches!(finish, Err(BlobError::Io(_))), "{step:?}");
                    assert_eq!(at_hash, wrong, "{step:?}: the old bytes stand at the hash, the rename having failed");
                    assert_eq!(asides.len(), 1, "{step:?}: the aside stands beside them");
                    assert_eq!(fs::read(root.join("blake3").join(&asides[0])).unwrap(), wrong);
                }
                Step::DirSync | Step::LeaseSync | Step::RecordRetire => {
                    assert!(matches!(finish, Err(BlobError::Io(_))), "{step:?}");
                    assert_eq!(at_hash, right, "{step:?}: the new bytes stand past the rename");
                    assert_eq!(asides.len(), 1, "{step:?}: the aside stands beside them");
                    assert_eq!(
                        store.asides_queued(),
                        0,
                        "{step:?}: left to the pruner's pass and to open — only an answered replace is queued"
                    );
                }
                Step::UnlinkAside => {
                    // The finish ANSWERS: the unlink is no step of it.
                    let fin = finish.expect("the deferred step fails nothing of the finish");
                    assert_eq!(fin.hex, hex);
                    assert_eq!(at_hash, right);
                    assert_eq!(asides.len(), 1);
                    assert!(store.unlink_asides().is_err(), "the injected failure at the deferred step");
                    assert_eq!(store.asides_queued(), 1, "re-queued for the next drain");
                    assert_eq!(store.asides_of("blake3").unwrap().len(), 1, "present, never a third state");
                    store.fail_at(None);
                    assert_eq!(store.unlink_asides().unwrap(), 1, "the next drain takes it");
                    assert!(store.asides_of("blake3").unwrap().is_empty(), "gone");
                    assert_eq!(fs::read(store.blob_path("blake3", &hex).unwrap()).unwrap(), right);
                }
                Step::RootSync => unreachable!("the designation directory exists before every replace"),
            }
            (store.asides_of("blake3").unwrap(), root.join("blake3").join(format!(".upload-{}", rec.id.to_hex())))
        };
        // THE REOPEN: every aside a failure left is removed, nothing naming
        // it; the hash's bytes stand as the step left them; a record whose
        // partial was renamed away is retired.
        let store = open(&root, now + 1);
        assert!(store.asides_of("blake3").unwrap().is_empty(), "{step:?}: open removes the aside ({aside_after:?})");
        let expected = if matches!(step, Step::PartialSync | Step::LinkAside | Step::Rename) { &wrong } else { &right };
        assert_eq!(&fs::read(store.blob_path("blake3", &hex).unwrap()).unwrap(), expected, "{step:?}");
        if matches!(step, Step::PartialSync | Step::LinkAside | Step::Rename) {
            assert!(partial.is_file(), "{step:?}: the partial stands with its record");
        } else {
            assert!(!partial.exists(), "{step:?}");
        }
        for lease in store.live_leases_of("k", now + 1) {
            assert_eq!(
                store.blob_size(&lease.designation, &lease.hex),
                Some(lease.size),
                "{step:?}: a lease names a whole file"
            );
        }
        // A re-PUT of the right bytes with the injection cleared: whole,
        // leased, one answer — a replace of whatever the step left.
        let fin = put_whole(&store, "k", &right, now + 2);
        assert_eq!(fin.hex, hex, "{step:?}");
        assert_eq!(fs::read(store.blob_path("blake3", &hex).unwrap()).unwrap(), right, "{step:?}: the file whole");
        assert_eq!(store.unlink_asides().unwrap(), 1, "{step:?}: one aside per replace, whatever the bytes replaced");
        assert!(store.asides_of("blake3").unwrap().is_empty(), "{step:?}: none left");
    }
}

/// AN ASIDE NAME IS NEVER TAKEN TWICE (`Store`'s count of its asides: "so
/// two replaces of one hash before the first's unlink take two names"): a
/// replace linking onto a name an aside already holds would fail — an I/O
/// error a create never meets — so every replace takes a name of its own,
/// whether the aside before it is queued or was left on disk by a finish
/// that failed past its link.
#[test]
fn every_replace_of_a_hash_takes_an_aside_name_of_its_own() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open(&dir.path().join("blobs"), 0);
    let bytes = b"the same bytes, again and again".to_vec();
    put_whole(&store, "a", &bytes, 1);
    store.fail_at(Some(Step::DirSync));
    let rec = store.create_upload("b", "blake3", bytes.len() as u64, INTERVAL, 2).unwrap();
    store.resume("b", &rec.id, 0, 2).unwrap();
    store.append("b", &rec.id, &bytes, 2).unwrap();
    assert!(matches!(store.finish("b", &rec.id, INTERVAL, 2), Err(BlobError::Io(_))));
    store.fail_at(None);
    assert_eq!((store.asides_of("blake3").unwrap().len(), store.asides_queued()), (1, 0), "left on disk, never queued");
    put_whole(&store, "c", &bytes, 3);
    put_whole(&store, "d", &bytes, 4);
    assert_eq!(store.asides_of("blake3").unwrap().len(), 3, "three asides, three names");
    assert_eq!(store.unlink_asides().unwrap(), 2, "the two answered replaces'");
    assert_eq!(store.asides_of("blake3").unwrap().len(), 1, "the failed finish's left to the pass and to open");
}

/// AN ASIDE IS QUEUED ONLY WHEN ITS FINISH ANSWERS ("NO ANSWER OF THE
/// UPLOAD SAYS WHETHER THE FILE WAS ALREADY HERE"): the queue is drained on
/// whichever thread asks, so an aside it held between the link and the
/// answer could be unlinked there, leaving the old file one link for the
/// rename to free inside the answer. A replace held before its last step
/// has linked its aside and queued nothing; answered, it has queued the one.
#[test]
fn an_aside_is_queued_only_when_its_finish_answers() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open(&dir.path().join("blobs"), 0);
    let right = b"the picture's bytes".to_vec();
    let hex = hex_of(&right);
    store.install("blake3", &hex, b"garbage under the right name").unwrap();
    let parked = Arc::new(Barrier::new(2));
    let resumed = Arc::new(Barrier::new(2));
    let (at_hold, after) = (parked.clone(), resumed.clone());
    store.hold_at(Step::RecordRetire, move || {
        at_hold.wait();
        after.wait();
    });
    let (linked, queued, finished) = thread::scope(|s| {
        let finishing = s.spawn(|| put_whole(&store, "k", &right, 10));
        parked.wait();
        // Reads alone while the finish is held, and no assertion: a failed
        // assertion here would leave the finish parked, the scope waiting on
        // it.
        let seen = (store.asides_of("blake3").unwrap().len(), store.asides_queued());
        resumed.wait();
        (seen.0, seen.1, finishing.join())
    });
    assert_eq!(linked, 1, "held before its last step, the replace has linked its aside");
    assert_eq!(queued, 0, "and queued nothing before its answer");
    assert_eq!(finished.expect("the held finish answers").hex, hex);
    assert_eq!(store.asides_queued(), 1, "answered: queued for the drain");
    assert_eq!(store.unlink_asides().unwrap(), 1);
    assert!(store.asides_of("blake3").unwrap().is_empty());
}

/// THE DRAIN COUNTS AN ASIDE ALREADY GONE AS UNLINKED
/// (`Store::unlink_asides`: "an aside already gone counted with them"): the
/// pruner's pass holds the finish's exclusion and not the drain's, so it
/// may take a queued aside first; the drain then answers it done and leaves
/// nothing queued — where a failure would leave it at the queue's head for
/// every later drain.
#[test]
fn an_aside_the_pass_took_first_is_done_for_the_drain() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open(&dir.path().join("blobs"), 0);
    let right = b"the picture's bytes".to_vec();
    store.install("blake3", &hex_of(&right), b"garbage under the right name").unwrap();
    put_whole(&store, "k", &right, 1);
    let aside = store.asides_of("blake3").unwrap().pop().expect("the replace's aside");
    assert!(store.remove_aside("blake3", &aside).unwrap(), "the pass's act takes it first");
    assert_eq!(store.unlink_asides().map_err(|e| e.kind()), Ok(1), "the drain counts it unlinked");
    assert_eq!(store.asides_queued(), 0, "and leaves nothing queued");
}

/// A FAILED UNLINK LEAVES THAT ASIDE AND EVERY ONE AFTER IT QUEUED, IN ORDER
/// (`Store::unlink_asides`: "A failure leaves that aside and the rest queued
/// for the next call"): three answered replaces queue three asides; the
/// second made un-removable — a directory at its name, which no unlink
/// removes — the drain unlinks the first, fails at the second and leaves the
/// third, two queued; with the obstacle gone, the next drain takes both.
#[test]
fn a_failed_unlink_leaves_that_aside_and_every_one_after_it_queued() {
    let dir = tempfile::tempdir().expect("tempdir");
    let designation_dir = dir.path().join("blobs").join("blake3");
    let store = open(&dir.path().join("blobs"), 0);
    let mut asides = Vec::new();
    for (bytes, now) in [(b"first".as_slice(), 1), (b"second", 2), (b"third", 3)] {
        let hex = hex_of(bytes);
        store.install("blake3", &hex, b"garbage").unwrap();
        put_whole(&store, "k", bytes, now);
        let prefix = format!(".retired-{hex}-");
        let name = store.asides_of("blake3").unwrap().into_iter().find(|a| a.starts_with(&prefix)).expect("its aside");
        asides.push(designation_dir.join(name));
    }
    fs::remove_file(&asides[1]).unwrap();
    fs::create_dir(&asides[1]).unwrap();
    assert!(store.unlink_asides().is_err(), "the drain fails at the second");
    assert_eq!(store.asides_queued(), 2, "that aside and the one after it stay queued");
    assert!(!asides[0].exists(), "the first, before the failure, is unlinked");
    assert!(asides[2].is_file(), "the third waits behind the second");
    fs::remove_dir(&asides[1]).unwrap();
    assert_eq!(store.unlink_asides().map_err(|e| e.kind()), Ok(2), "the next drain takes both, the second already gone");
    assert!(store.asides_of("blake3").unwrap().is_empty());
}

/// A HOLD PARKS ITS OWN FINISH AND NOTHING ELSE: the seam runs a hold with
/// none of its own state locked, so while one finish is parked a drain on
/// another thread — which passes the seam's gate before each unlink —
/// meets no lock of the seam's and unlinks the aside an answered replace
/// queued; the held finish then answers.
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
    let (drained, finished) = thread::scope(|s| {
        let finishing = s.spawn(|| put_whole(store, "k", b"other bytes", 10));
        parked.wait();
        let (tx, rx) = mpsc::channel();
        s.spawn(move || tx.send(store.unlink_asides().map_err(|e| e.to_string())));
        // No assertion while the finish is held: a failed one would leave it
        // parked, the scope waiting on it.
        let drained = rx.recv_timeout(Duration::from_secs(5));
        resumed.wait();
        (drained, finishing.join())
    });
    assert_eq!(drained, Ok(Ok(1)), "the drain met no lock of the seam's while a finish was parked");
    assert_eq!(finished.expect("the held finish answers").hex, hex_of(b"other bytes"));
    assert!(store.asides_of("blake3").unwrap().is_empty());
}

/// THE FINISHES RUN ONE AT A TIME (`Store`'s lock on its handles, "held
/// through the whole of a finish … so two finishes of one hash never
/// interleave the replace's check, link and rename"): with one replace held
/// between its link and its rename, a second finish of the same hash meets
/// none of its gates until the first has answered. The seam runs a hold
/// with none of its own state locked, so only the store's lock — or a lock
/// of the finish's own, were that one narrowed — keeps the second out. A
/// finish not held back meets its gate within milliseconds and the window
/// here is half a second, so this test can err only toward passing.
#[test]
fn the_finishes_run_one_at_a_time() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open(&dir.path().join("blobs"), 0);
    let bytes = b"one hash, two finishes".to_vec();
    let hex = hex_of(&bytes);
    store.install("blake3", &hex, b"garbage under the right name").unwrap();
    let first = standing(&store, "a", bytes.len() as u64, &bytes, 1);
    let second = standing(&store, "b", bytes.len() as u64, &bytes, 1);
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
    let store = &store;
    let (met, a, b) = thread::scope(|s| {
        let a = s.spawn(|| store.finish("a", &first.id, INTERVAL, 2));
        parked.wait();
        let b = s.spawn(|| store.finish("b", &second.id, INTERVAL, 2));
        // No assertion while the first finish is held: a failed one would
        // leave it parked, the scope waiting on it.
        let met = met_rx.recv_timeout(Duration::from_millis(500));
        resumed.wait();
        (met, a.join(), b.join())
    });
    assert_eq!(
        met,
        Err(mpsc::RecvTimeoutError::Timeout),
        "the second finish met its gate while the first was held inside its replace"
    );
    assert_eq!(a.expect("the first thread").expect("the first finish answers").hex, hex);
    assert_eq!(b.expect("the second thread").expect("the second finish answers, after it").hex, hex);
    assert_eq!(store.asides_queued(), 2, "each a replace, each queued its aside at its answer");
}

/// A FINISH THAT FAILED PAST ITS RENAME CLOSES ITS HANDLE (clause (7)): from
/// the rename on, the partial's open file IS the hash's file, so a handle
/// kept there would let the next resume cut the hash's bytes back to the
/// record's offset and stream the next request's bytes into them. The
/// bytes here were never settled — the record's offset stands at 0 — and
/// the resume after the failure finds no partial, answering I/O, the
/// hash's bytes untouched.
#[test]
fn a_finish_that_failed_past_its_rename_leaves_no_handle_on_the_hashs_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open(&dir.path().join("blobs"), 0);
    let bytes = b"the bytes the rename named".to_vec();
    let hex = hex_of(&bytes);
    let rec = store.create_upload("k", "blake3", bytes.len() as u64, INTERVAL, 1).unwrap();
    store.resume("k", &rec.id, 0, 1).unwrap();
    store.append("k", &rec.id, &bytes, 1).unwrap();
    assert_eq!(store.upload("k", &rec.id, 1).unwrap().offset, 0, "short of the grain: written, not received");
    store.fail_at(Some(Step::DirSync));
    assert!(matches!(store.finish("k", &rec.id, INTERVAL, 1), Err(BlobError::Io(_))));
    assert_eq!(store.handles_open(), 0, "the finish's handle closed with its failure");
    let at_hash = store.blob_path("blake3", &hex).unwrap();
    assert_eq!(fs::read(&at_hash).unwrap(), bytes, "the rename named the bytes");
    store.fail_at(None);
    assert!(matches!(store.resume("k", &rec.id, 0, 2), Err(BlobError::Io(_))), "the partial was renamed away");
    assert_eq!(store.handles_open(), 0);
    assert_eq!(fs::read(&at_hash).unwrap(), bytes, "the hash's file untouched");
}

/// REPLACE, NOT NO-OP (Op inventory 1): a file holding the WRONG bytes
/// under the right name — the corrupt case — is repaired by a PUT of the
/// right bytes, and the PUT's answer is the very answer a PUT of the same
/// bytes gives where no file stood: the same designation, hex and size, one
/// shape; no answer of the store says whether the file was here. The old
/// instance's name goes with the deferred step, after the answer: the
/// finish leaves it as an aside the drain unlinks, and a fresh PUT leaves
/// none.
#[test]
fn replace_repairs_a_corrupt_file_and_answers_as_a_fresh_put_does() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open(&dir.path().join("blobs"), 0);
    let right = b"the picture's bytes".to_vec();
    let hex = hex_of(&right);
    // Planted: the right name, the wrong bytes.
    store.install("blake3", &hex, b"garbage under the right name").unwrap();
    assert_eq!(store.blob_size("blake3", &hex), Some(28));
    let fresh_bytes = b"another picture".to_vec();
    let fresh = put_whole(&store, "k", &fresh_bytes, 10);
    assert_eq!(store.asides_queued(), 0, "a fresh PUT links nothing aside");
    let replaced = put_whole(&store, "k", &right, 20);
    assert_eq!(
        replaced,
        put_whole(&open(&dir.path().join("elsewhere"), 0), "k", &right, 20),
        "the replace answers exactly as a PUT of the same bytes where no file stood"
    );
    assert_eq!(replaced.designation, fresh.designation);
    assert_eq!(replaced.hex, hex);
    assert_eq!(replaced.size, right.len() as u64);
    assert_eq!(fs::read(store.blob_path("blake3", &hex).unwrap()).unwrap(), right, "repaired");
    // The old instance's second name stands until the deferred step, and
    // holds the old bytes; the drain unlinks it.
    let asides = store.asides_of("blake3").unwrap();
    assert_eq!(asides.len(), 1, "the replace left one aside");
    assert!(asides[0].starts_with(&format!(".retired-{hex}-")), "{}", asides[0]);
    assert_eq!(fs::read(dir.path().join("blobs").join("blake3").join(&asides[0])).unwrap(), b"garbage under the right name");
    assert_eq!(store.unlink_asides().unwrap(), 1);
    assert!(store.asides_of("blake3").unwrap().is_empty());
    assert_eq!(store.unlink_asides().unwrap(), 0, "nothing queued twice");
    // And a second PUT of the same bytes over the whole file: the same
    // answer again, the file the same.
    let again = put_whole(&store, "k2", &right, 30);
    assert_eq!(again, replaced);
    assert_eq!(fs::read(store.blob_path("blake3", &hex).unwrap()).unwrap(), right);
    assert_eq!(store.unlink_asides().unwrap(), 1, "one aside per replace, whatever the bytes");
    // Each principal holds its own lease; neither answer named the other's.
    assert!(matches!(store.lease("k", "blake3", &hex, 31), LeaseState::Live { .. }));
    assert!(matches!(store.lease("k2", "blake3", &hex, 31), LeaseState::Live { .. }));
    assert_eq!(store.lease("k3", "blake3", &hex, 31), LeaseState::None, "a third principal holds none, whatever the directory holds");
    // The directory as the pruner reads it: the one file at its hex name,
    // the two blobs, no aside.
    let mut blobs = store.blobs_of("blake3").unwrap();
    blobs.sort();
    let mut want = vec![hex.clone(), hex_of(&fresh_bytes)];
    want.sort();
    assert_eq!(blobs, want);
    assert_eq!(store.designations().unwrap(), vec!["blake3".to_string()]);
    assert!(store.unlink_blob("blake3", &hex_of(&fresh_bytes)).unwrap());
    assert!(!store.unlink_blob("blake3", &hex_of(&fresh_bytes)).unwrap(), "absent: nothing to unlink");
    assert_eq!(store.blobs_of("blake3").unwrap(), vec![hex]);
}

/// THE DIRECTORY LISTINGS NAME EACH CLASS ALONE, IN NAME ORDER
/// (`Store::blobs_of`: "the files at HEX NAMES …, in name order — … a
/// partial or an aside excluded by its name"; `Store::asides_of`,
/// `Store::designations`: "in name order"): beside eight files at hex names
/// stand eight asides, eight partials, a directory at a hex name and eight
/// more designation directories; each listing names its own class alone,
/// sorted — eight names in a random order fall sorted once in 40,320.
#[test]
fn the_directory_listings_name_each_class_alone_in_name_order() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("blobs");
    let store = open(&root, 0);
    let designation_dir = root.join("blake3");
    fs::create_dir(&designation_dir).unwrap();
    let mut hexes: Vec<String> = (0u8..8).map(|i| hex_of(&[i])).collect();
    for (i, hex) in hexes.iter().enumerate() {
        fs::write(designation_dir.join(hex), b"a file").unwrap();
        fs::write(designation_dir.join(format!(".retired-{hex}-{i}")), b"an aside").unwrap();
        fs::write(designation_dir.join(format!(".upload-{}", &hex[..32])), b"a partial").unwrap();
        fs::create_dir(root.join(format!("d{i}"))).unwrap();
    }
    fs::create_dir(designation_dir.join(hex_of(b"a directory"))).unwrap();
    hexes.sort();
    assert_eq!(store.blobs_of("blake3").unwrap(), hexes, "the files at hex names alone, sorted");
    let asides = store.asides_of("blake3").unwrap();
    assert_eq!(asides.len(), 8, "the asides alone: {asides:?}");
    assert!(asides.windows(2).all(|w| w[0] < w[1]), "sorted: {asides:?}");
    let mut dirs: Vec<String> = (0..8).map(|i| format!("d{i}")).chain(["blake3".to_string()]).collect();
    dirs.sort();
    assert_eq!(store.designations().unwrap(), dirs, "every directory under the root, sorted");
}

/// The size check's read: present with its size, absent as `None`, and a
/// name that is no hex — a partial's, a path's — as absent too. And the
/// name check it reads through: a path is answered for well-formed names
/// alone, so no name a caller hands in reaches past its designation
/// directory.
#[test]
fn blob_size_answers_the_files_size_and_nothing_for_a_name_that_is_no_hex() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("blobs");
    let store = open(&root, 0);
    let fin = put_whole(&store, "k", b"12345", 1);
    assert_eq!(store.blob_size("blake3", &fin.hex), Some(5));
    assert_eq!(store.blob_size("blake3", &hex_of(b"other")), None);
    assert_eq!(store.blob_size("blake3", "../leases.log"), None);
    assert_eq!(store.blob_size("blake3", "ABCDEF"), None, "uppercase is no hex here");
    assert_eq!(store.blob_size("BLAKE3", &fin.hex), None, "a designation is lowercase");
    assert_eq!(store.blob_size("blake3", ".upload-00000000000000000000000000000000"), None);
    assert_eq!(store.blob_path("blake3", &fin.hex), Some(root.join("blake3").join(&fin.hex)));
    assert_eq!(store.blob_path("blake3", "../leases.log"), None, "no path out of the directory");
    assert_eq!(store.blob_path("BLAKE3", &fin.hex), None);
    assert_eq!(store.blob_path("..", &fin.hex), None);
}

/// Every entry under `at` by its path relative to `at` — a directory as
/// `None`, a file as its bytes — sorted: what "touches nothing" compares.
fn tree(at: &Path) -> Vec<(PathBuf, Option<Vec<u8>>)> {
    let mut out = Vec::new();
    let mut dirs = vec![at.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        for entry in fs::read_dir(&dir).expect("read_dir") {
            let path = entry.expect("entry").path();
            let rel = path.strip_prefix(at).expect("under at").to_path_buf();
            if path.is_dir() {
                out.push((rel, None));
                dirs.push(path);
            } else {
                out.push((rel, Some(fs::read(&path).expect("read"))));
            }
        }
    }
    out.sort();
    out
}

/// THE STORE CHECKS EVERY NAME IT IS HANDED (`Store`: "a malformed one is
/// answered as absent by every read and act … and refused as
/// `InvalidInput` by `create_upload`"): over families of malformed names —
/// escapes that reach a file that stands, the wrong case, each length just
/// past its bound, a partial's, a blob's and near-aside spellings where an
/// aside's belongs — every entry point answers absent and nothing under the
/// root or beside it is touched; the names AT each bound are well-formed.
#[test]
fn every_entry_point_answers_a_malformed_name_as_absent_and_touches_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("blobs");
    let store = open(&root, 0);
    let blob = put_whole(&store, "k", b"a blob an escape could reach", 1).hex;
    let replaced = hex_of(b"a replaced blob");
    store.install("blake3", &replaced, b"its wrong bytes").unwrap();
    put_whole(&store, "k", b"a replaced blob", 2);
    let aside = store.asides_of("blake3").unwrap().pop().expect("the replace's aside, queued");
    let partial = format!(".upload-{}", standing(&store, "k", 100, b"part", 3).id.to_hex());
    let long_count = format!(".retired-{replaced}-{}", "9".repeat(21));
    fs::write(root.join("blake3").join(&long_count), b"no aside's").unwrap();
    let before = tree(dir.path());
    let designations = ["", ".", "..", "../blobs/blake3", "blake3/.", "BLAKE3", "blake_3", "blåke3"]
        .map(String::from)
        .into_iter()
        .chain(["a".repeat(33)]);
    for d in designations {
        assert_eq!(store.blob_path(&d, &blob), None, "{d:?}");
        assert_eq!(store.blob_size(&d, &blob), None, "{d:?}");
        assert!(matches!(store.blobs_of(&d).as_deref(), Ok([])), "{d:?}: listed");
        assert!(matches!(store.asides_of(&d).as_deref(), Ok([])), "{d:?}: listed");
        assert!(matches!(store.unlink_blob(&d, &blob), Ok(false)), "{d:?}: unlinked");
        assert!(matches!(store.remove_aside(&d, &aside), Ok(false)), "{d:?}: removed");
        let created = store.create_upload("k", &d, 1, INTERVAL, 4).map(|r| r.id).map_err(|e| e.kind());
        assert_eq!(created, Err(io::ErrorKind::InvalidInput), "{d:?}: created");
    }
    let hexes = ["", "a", "abc", "gg", "..", "../leases.log", "../uploads.log"].map(String::from).into_iter().chain([
        blob.to_uppercase(),
        blob[..63].to_string(),
        format!("{blob}/"),
        "a".repeat(129),
        "a".repeat(130),
        partial.clone(),
        aside.clone(),
    ]);
    for h in hexes {
        assert_eq!(store.blob_path("blake3", &h), None, "{h:?}");
        assert_eq!(store.blob_size("blake3", &h), None, "{h:?}");
        assert!(matches!(store.unlink_blob("blake3", &h), Ok(false)), "{h:?}: unlinked");
    }
    let near_asides = [
        ".retired-x".to_string(),
        format!("{aside}/../{aside}"),
        long_count,
        blob.clone(),
        partial,
        format!(".retired-{}-0", replaced.to_uppercase()),
    ];
    for name in near_asides {
        assert!(matches!(store.remove_aside("blake3", &name), Ok(false)), "{name:?}: removed");
    }
    assert_eq!(tree(dir.path()), before, "no malformed name touched a file, under the root or beside it");
    for (d, h) in [("a".repeat(32), "ab".to_string()), ("-".to_string(), "a".repeat(128))] {
        assert_eq!(store.blob_path(&d, &h), Some(root.join(&d).join(&h)), "{d:?}/{h:?}: well-formed at its bound");
    }
}

/// THE FLOOR's ONE READ OF THE HOST: the space available on the volume at
/// the root, in whole fragments — more than nothing, and short of the
/// volume's size, part of which the files this test made already use.
#[test]
fn free_space_reads_the_space_available_never_the_volumes_size() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("blobs");
    let store = open(&root, 0);
    let free = store.free_space().expect("statvfs");
    let volume = rustix::fs::statvfs(&root).expect("statvfs");
    let size = volume.f_blocks.saturating_mul(volume.f_frsize);
    assert!(0 < free && free < size, "{free} bytes free of a {size}-byte volume, which this test's files already use");
    assert_eq!(free % volume.f_frsize, 0, "{free}: whole {}-byte fragments", volume.f_frsize);
}
