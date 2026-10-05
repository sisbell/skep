//! REPLACE, NOT NO-OP (M-I5 (a); `media.md` Op inventory 1, the REPLACE
//! paragraph, "NO ANSWER OF THE UPLOAD SAYS WHETHER THE FILE WAS ALREADY
//! HERE"): its order under a seeded failure injection at each step, the
//! hash never without a file; REPLACE's answer, the one a PUT gives where
//! no file stood, and its repair of a corrupt file; an aside name of its
//! own for every replace, and the deferred unlink's queue — an aside queued
//! only at its finish's answer, one already gone counted unlinked, a
//! failure leaving it and every one after it queued.

use std::fs;
use std::sync::{Arc, Barrier};
use std::thread;

use skep_blobs::{BlobError, LeaseState, Step};

use crate::{hex_of, open, put_whole, INTERVAL};

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
        let (asides_after, partial) = {
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
                Step::RootSync => unreachable!("the plant's install paid the root's fsync before every replace"),
            }
            (store.asides_of("blake3").unwrap(), root.join("blake3").join(format!(".upload-{}", rec.id.to_hex())))
        };
        // THE REOPEN: every aside a failure left is removed, nothing naming
        // it; the hash's bytes stand as the step left them; a record whose
        // partial was renamed away is retired.
        let store = open(&root, now + 1);
        assert!(store.asides_of("blake3").unwrap().is_empty(), "{step:?}: open removes the aside ({asides_after:?})");
        let expected = if matches!(step, Step::PartialSync | Step::LinkAside | Step::Rename) { &wrong } else { &right };
        assert_eq!(&fs::read(store.blob_path("blake3", &hex).unwrap()).unwrap(), expected, "{step:?}");
        if matches!(step, Step::PartialSync | Step::LinkAside | Step::Rename) {
            assert!(partial.is_file(), "{step:?}: the partial stands with its record");
        } else {
            assert!(!partial.exists(), "{step:?}");
        }
        for lease in store.live_leases_of("k", now + 1) {
            assert_eq!(
                store.blob_size(&lease.designation, &lease.hex).unwrap_or_else(|e| panic!("{step:?}: {e}")),
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

/// AN ASIDE NAME IS NEVER TAKEN TWICE (`Store`'s aside serial: "so two
/// replaces of one hash before the first's unlink take two names"): a
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
    assert_eq!(store.blob_size("blake3", &hex).unwrap(), Some(28));
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
    assert!(matches!(store.lease_state("k", "blake3", &hex, 31), LeaseState::Live { .. }));
    assert!(matches!(store.lease_state("k2", "blake3", &hex, 31), LeaseState::Live { .. }));
    assert_eq!(store.lease_state("k3", "blake3", &hex, 31), LeaseState::None, "a third principal holds none, whatever the directory holds");
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
