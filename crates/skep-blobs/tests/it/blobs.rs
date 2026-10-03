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
        assert_eq!(fs::read(store.blob_path("blake3", &hex)).unwrap(), bytes);
        assert_eq!(store.lease("k", "blake3", &hex, now + 2), LeaseState::Live { size: bytes.len() as u64, expires: now + 2 + INTERVAL });
    }
}

/// REPLACE, NOT NO-OP (Op inventory 1): a file holding the WRONG bytes
/// under the right name — the corrupt case — is repaired by a PUT of the
/// right bytes, and the PUT's answer is byte-identical to a PUT of a fresh
/// file: the same designation, hex and size, one shape; no answer of the
/// store says whether the file was here. The old instance's bytes are gone
/// with it.
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
    let replaced = put_whole(&store, "k", &right, 20);
    assert_eq!(replaced.designation, fresh.designation);
    assert_eq!(replaced.hex, hex);
    assert_eq!(replaced.size, right.len() as u64);
    assert_eq!(fs::read(store.blob_path("blake3", &hex)).unwrap(), right, "repaired");
    // And a second PUT of the same bytes over the whole file: the same
    // answer again, the file the same.
    let again = put_whole(&store, "k2", &right, 30);
    assert_eq!(again, replaced);
    assert_eq!(fs::read(store.blob_path("blake3", &hex)).unwrap(), right);
    // Each key holds its own lease; neither answer named the other's.
    assert!(matches!(store.lease("k", "blake3", &hex, 31), LeaseState::Live { .. }));
    assert!(matches!(store.lease("k2", "blake3", &hex, 31), LeaseState::Live { .. }));
    assert_eq!(store.lease("k3", "blake3", &hex, 31), LeaseState::None, "a third key holds none, whatever the directory holds");
}

/// The size check's read: present with its length, absent as `None`, and a
/// name that is no hex — a partial's, a path's — as absent too.
#[test]
fn blob_len_answers_the_files_length_and_nothing_for_a_name_that_is_no_hex() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open(&dir.path().join("blobs"), 0);
    let fin = put_whole(&store, "k", b"12345", 1);
    assert_eq!(store.blob_len("blake3", &fin.hex), Some(5));
    assert_eq!(store.blob_len("blake3", &hex_of(b"other")), None);
    assert_eq!(store.blob_len("blake3", "../leases.log"), None);
    assert_eq!(store.blob_len("blake3", "ABCDEF"), None, "uppercase is no hex here");
    assert_eq!(store.blob_len("BLAKE3", &fin.hex), None, "a designation is lowercase");
    assert_eq!(store.blob_len("blake3", ".upload-00000000000000000000000000000000"), None);
}

/// The floor's read answers the volume's free space — a positive figure on
/// any machine that could run this test.
#[test]
fn free_space_reads_the_volume() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open(&dir.path().join("blobs"), 0);
    assert!(store.free_space().expect("statvfs") > 0);
}
