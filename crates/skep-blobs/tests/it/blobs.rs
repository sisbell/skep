//! THE FILES and THE PUT's ORDER (M-I5 (a) DURABLE BEFORE NAMED, ANSWERED
//! AFTER RECORDED; `media.md` Op inventory 1, the REPLACE paragraph and the
//! lease's crash story): the fsync order observed through a SEEDED FAILURE
//! INJECTION at each step of the finish — never a mock of the filesystem —
//! and what each failure leaves; REPLACE's byte-identical answer and its
//! repair of a corrupt file; the one answer for a present and an absent
//! target; the free-space read.

use std::fs;

use skep_blobs::{BlobError, LeaseState, Step};

use crate::{hex_of, open, put_whole, INTERVAL};

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
        Step::TempSync,
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
            let rec = store.create_upload("k", "blake3", bytes.len() as u64, now + INTERVAL, None).unwrap();
            store.resume("k", &rec.id, 0, now).unwrap();
            store.append("k", &rec.id, &bytes, now, INTERVAL).unwrap();
            store.settle("k", &rec.id, now, INTERVAL).unwrap();
            let err = store.finish("k", &rec.id, now, now + INTERVAL).expect_err("the injected failure");
            assert!(matches!(err, BlobError::Io(_)), "{step:?}: {err}");
            // Before the lease's sync, the key holds NO lease — whatever
            // the directory holds — and the file is present only from the
            // rename on.
            let state = store.lease("k", "blake3", &hex, now);
            let present = store.blob_len("blake3", &hex).is_some();
            (rec.id, state, present)
        };
        let (id, state, present) = outcome;
        match step {
            Step::TempSync | Step::Rename => {
                assert_eq!(state, LeaseState::None, "{step:?}");
                assert!(!present, "{step:?}: the file is absent before the rename");
            }
            Step::DirSync | Step::RootSync | Step::LeaseSync => {
                assert_eq!(state, LeaseState::None, "{step:?}: no lease before its sync");
                assert!(present, "{step:?}: the file stands, leaseless and prunable");
            }
            Step::RecordRetire => {
                assert_eq!(state, LeaseState::Live { size: bytes.len() as u64, expires: now + INTERVAL });
                assert!(present);
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
            Step::TempSync | Step::Rename => {
                let r = record.expect("{step:?}: the upload stands with its partial");
                assert_eq!(r.offset, bytes.len() as u64);
                assert!(partial.is_file());
                assert_eq!(store.pending_bytes("k", now + 1), bytes.len() as u64);
            }
            _ => {
                assert!(record.is_none(), "{step:?}: a record with no partial is retired at open");
                assert!(!partial.exists());
            }
        }
        for lease in store.leases_of("k", now + 1) {
            assert_eq!(store.blob_len(&lease.designation, &lease.hex), Some(lease.size), "a lease names a whole file");
        }
        // The same bytes PUT again, the injection cleared: whole, leased,
        // and the answer the one shape (REPLACE over a file the failed
        // finish left, or a fresh install).
        let fin = put_whole(&store, "k", &bytes, now + 2);
        assert_eq!(fin.hex, hex);
        assert_eq!(fin.size, bytes.len() as u64);
        assert_eq!(fs::read(store.blob_path("blake3", &hex).unwrap()).unwrap(), bytes);
        assert_eq!(store.lease("k", "blake3", &hex, now + 2), LeaseState::Live { size: bytes.len() as u64, expires: now + 2 + INTERVAL });
    }
}

/// THE REPLACE's ORDER, STEP BY STEP (M-I5 (a); "NO ANSWER OF THE UPLOAD
/// SAYS WHETHER THE FILE WAS ALREADY HERE" — the old instance retired after
/// the answer): over a file planted with the WRONG bytes at the right name,
/// a finish that fails at each step of a replace — the two aside steps
/// among them — leaves the hash holding the OLD bytes whole before the
/// rename and the NEW bytes whole after it, never an absent name; the
/// aside stands from the link until the deferred unlink and is gone or
/// present, never a third state; a failure at the deferred unlink itself
/// leaves the answer given and the aside queued for the next drain; and
/// the reopen removes every aside a failure left, the hash's bytes as the
/// step left them.
#[test]
fn a_failure_at_each_step_of_a_replace_leaves_the_new_bytes_past_the_rename() {
    let steps = [
        Step::TempSync,
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
            let rec = store.create_upload("k", "blake3", right.len() as u64, now + INTERVAL, None).unwrap();
            store.resume("k", &rec.id, 0, now).unwrap();
            store.append("k", &rec.id, &right, now, INTERVAL).unwrap();
            store.settle("k", &rec.id, now, INTERVAL).unwrap();
            let finish = store.finish("k", &rec.id, now, now + INTERVAL);
            let at_hash = fs::read(store.blob_path("blake3", &hex).unwrap()).expect("the hash is never without a file");
            let asides = store.asides_of("blake3").unwrap();
            match step {
                Step::TempSync | Step::LinkAside => {
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
                    assert_eq!(asides.len(), 1, "{step:?}: the aside stands until the deferred unlink");
                    assert_eq!(store.asides_pending(), 1, "{step:?}: queued for the drain");
                }
                Step::UnlinkAside => {
                    // The finish ANSWERS: the unlink is no step of it.
                    let fin = finish.expect("the deferred step fails nothing of the finish");
                    assert_eq!(fin.hex, hex);
                    assert_eq!(at_hash, right);
                    assert_eq!(asides.len(), 1);
                    assert!(store.retire_asides().is_err(), "the injected failure at the deferred step");
                    assert_eq!(store.asides_pending(), 1, "re-queued for the next drain");
                    assert_eq!(store.asides_of("blake3").unwrap().len(), 1, "present, never a third state");
                    store.fail_at(None);
                    assert_eq!(store.retire_asides().unwrap(), 1, "the next drain takes it");
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
        let expected = if matches!(step, Step::TempSync | Step::LinkAside | Step::Rename) { &wrong } else { &right };
        assert_eq!(&fs::read(store.blob_path("blake3", &hex).unwrap()).unwrap(), expected, "{step:?}");
        if matches!(step, Step::TempSync | Step::LinkAside | Step::Rename) {
            assert!(partial.is_file(), "{step:?}: the partial stands with its record");
        } else {
            assert!(!partial.exists(), "{step:?}");
        }
        for lease in store.leases_of("k", now + 1) {
            assert_eq!(store.blob_len(&lease.designation, &lease.hex), Some(lease.size), "a lease names a whole file");
        }
        // A re-PUT of the right bytes with the injection cleared: whole,
        // leased, one answer — a replace of whatever the step left.
        let fin = put_whole(&store, "k", &right, now + 2);
        assert_eq!(fin.hex, hex);
        assert_eq!(fs::read(store.blob_path("blake3", &hex).unwrap()).unwrap(), right);
        assert_eq!(store.retire_asides().unwrap(), 1, "one aside per replace, whatever the bytes replaced");
        assert!(store.asides_of("blake3").unwrap().is_empty());
    }
}

/// REPLACE, NOT NO-OP (Op inventory 1): a file holding the WRONG bytes
/// under the right name — the corrupt case — is repaired by a PUT of the
/// right bytes, and the PUT's answer is byte-identical to a PUT of a fresh
/// file: the same designation, hex and size, one shape; no answer of the
/// store says whether the file was here. The old instance's name goes
/// with the deferred step, after the answer: the finish leaves it as an
/// aside the drain unlinks, and a fresh PUT leaves none.
#[test]
fn replace_repairs_a_corrupt_file_and_answers_as_a_fresh_put_does() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open(&dir.path().join("blobs"), 0);
    let right = b"the picture's bytes".to_vec();
    let hex = hex_of(&right);
    // Planted: the right name, the wrong bytes.
    store.install("blake3", &hex, b"garbage under the right name").unwrap();
    assert_eq!(store.blob_len("blake3", &hex), Some(28));
    let fresh_bytes = b"another picture".to_vec();
    let fresh = put_whole(&store, "k", &fresh_bytes, 10);
    assert_eq!(store.asides_pending(), 0, "a fresh PUT links nothing aside");
    let replaced = put_whole(&store, "k", &right, 20);
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
    assert_eq!(store.retire_asides().unwrap(), 1);
    assert!(store.asides_of("blake3").unwrap().is_empty());
    assert_eq!(store.retire_asides().unwrap(), 0, "nothing queued twice");
    // And a second PUT of the same bytes over the whole file: the same
    // answer again, the file the same.
    let again = put_whole(&store, "k2", &right, 30);
    assert_eq!(again, replaced);
    assert_eq!(fs::read(store.blob_path("blake3", &hex).unwrap()).unwrap(), right);
    assert_eq!(store.retire_asides().unwrap(), 1, "one aside per replace, whatever the bytes");
    // Each key holds its own lease; neither answer named the other's.
    assert!(matches!(store.lease("k", "blake3", &hex, 31), LeaseState::Live { .. }));
    assert!(matches!(store.lease("k2", "blake3", &hex, 31), LeaseState::Live { .. }));
    assert_eq!(store.lease("k3", "blake3", &hex, 31), LeaseState::None, "a third key holds none, whatever the directory holds");
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

/// The size check's read: present with its length, absent as `None`, and a
/// name that is no hex — a partial's, a path's — as absent too. And the
/// door it reads through: a path is answered for well-formed names alone,
/// so no name a caller hands in reaches past its designation directory.
#[test]
fn blob_len_answers_the_files_length_and_nothing_for_a_name_that_is_no_hex() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("blobs");
    let store = open(&root, 0);
    let fin = put_whole(&store, "k", b"12345", 1);
    assert_eq!(store.blob_len("blake3", &fin.hex), Some(5));
    assert_eq!(store.blob_len("blake3", &hex_of(b"other")), None);
    assert_eq!(store.blob_len("blake3", "../leases.log"), None);
    assert_eq!(store.blob_len("blake3", "ABCDEF"), None, "uppercase is no hex here");
    assert_eq!(store.blob_len("BLAKE3", &fin.hex), None, "a designation is lowercase");
    assert_eq!(store.blob_len("blake3", ".upload-00000000000000000000000000000000"), None);
    assert_eq!(store.blob_path("blake3", &fin.hex), Some(root.join("blake3").join(&fin.hex)));
    assert_eq!(store.blob_path("blake3", "../leases.log"), None, "no path out of the directory");
    assert_eq!(store.blob_path("BLAKE3", &fin.hex), None);
    assert_eq!(store.blob_path("..", &fin.hex), None);
}

/// The floor's read answers the volume's free space — a positive figure on
/// any machine that could run this test.
#[test]
fn free_space_reads_the_volume() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open(&dir.path().join("blobs"), 0);
    assert!(store.free_space().expect("statvfs") > 0);
}
