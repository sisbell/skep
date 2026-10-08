//! Unwind safety (§3): a panic in the closure, in the commit region, and in a
//! superseded root's destructor, each leaving the kernel where its contract
//! says.

use std::io;
use std::panic::{catch_unwind, AssertUnwindSafe};

use super::*;
use skep_kernel::{CheckpointError, TxnError};
use tempfile::tempdir;

#[test]
fn panic_inside_the_commit_region_rolls_back_and_leaves_the_kernel_usable() {
    // §3 unwind guard, pre-barrier arm: an unwind out of the commit region
    // with nothing durably appended is repaired to a TRUE no-op — staging
    // discarded, the high-water rolled back per BurnedSeqPolicy, NO poison —
    // and the coordinates the failed txn drew are reused by the next commit.
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    commit(&k, 10);

    let unwound = catch_unwind(AssertUnwindSafe(|| {
        let _ = k.transact::<(), ()>(&[], |stg| {
            // Staged fine; it panics in the commit region, where the closure
            // phase's own guard no longer covers it.
            stg.push(TestRec::PanicOnSerialize(PanicsOnSerialize));
            Ok(())
        });
    }));
    assert!(unwound.is_err(), "the panic must propagate to the caller");
    assert_eq!(k.current_seq(), Seq(1));

    // Not poisoned: the write path still works, gap-free.
    assert_eq!(commit(&k, 20), Seq(2));
    assert_eq!(items(&k), vec![10, 20]);
    drop(k);
    // Nothing of the panicking txn is on disk to recover.
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    assert_eq!(items(&k), vec![10, 20]);
    assert_eq!(k.current_seq(), Seq(2));
}

/// §3: the unwind guard's pre-barrier arm, reached ON CUE: a panic armed at
/// the append — inside the commit region, after the mark, before a byte of
/// the transaction is on disk — propagates to the caller, and the repair
/// truncates the segment to a TRUE no-op: the kernel not poisoned, the
/// order rolled back so the next commit reuses the coordinate, and the
/// reopen holding nothing of the unwound transaction. The claim above,
/// through the seam.
#[test]
fn a_panic_armed_at_the_append_is_repaired_to_a_true_no_op() {
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    commit(&k, 10);
    k.panic_at_the_next(Step::JournalAppend);
    let unwound = catch_unwind(AssertUnwindSafe(|| {
        let _ = k.transact::<(), ()>(&[], |stg| {
            stg.push(TestRec::Append(20));
            Ok(())
        });
    }));
    let payload = unwound.expect_err("the panic propagates to the caller");
    assert_eq!(panic_message(&*payload), "injected panic at JournalAppend");
    assert!(!k.is_poisoned(), "the repair was sound");
    assert!(k.armed_steps().is_empty(), "the arm fired once");
    assert_eq!(k.current_seq(), Seq(1));
    assert_eq!(commit(&k, 20), Seq(2), "the coordinate the unwound txn drew is reused");
    assert_eq!(items(&k), vec![10, 20]);
    drop(k);
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    assert_eq!(items(&k), vec![10, 20]);
    assert_eq!(k.current_seq(), Seq(2));
}

/// §3: AN UNWIND WHOSE REPAIR FAILS POISONS — the guard's one halt: the
/// same panic at the append with the repair armed to fail `StorageFull`
/// propagates all the same AND poisons the kernel — every later write is
/// refused `Poisoned` before its closure runs, a checkpoint is refused the
/// same, and reads serve the last consistent root. Nothing of the
/// transaction reached the file, so the reopen is clean, and poison does
/// not persist across it.
#[test]
fn an_unwind_whose_repair_fails_poisons_the_kernel() {
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    commit(&k, 10);
    k.panic_at_the_next(Step::JournalAppend);
    k.fail_the_next(Step::JournalRepair, io::ErrorKind::StorageFull);
    let unwound = catch_unwind(AssertUnwindSafe(|| {
        let _ = k.transact::<(), ()>(&[], |stg| {
            stg.push(TestRec::Append(20));
            Ok(())
        });
    }));
    let payload = unwound.expect_err("the panic propagates, poison or not");
    assert_eq!(panic_message(&*payload), "injected panic at JournalAppend");
    assert!(k.is_poisoned(), "the repair's failure halts the kernel");
    assert!(k.armed_steps().is_empty(), "both arms fired");

    let ran = std::cell::Cell::new(false);
    let out = k.transact::<(), ()>(&[], |stg| {
        ran.set(true);
        stg.push(TestRec::Append(30));
        Ok(())
    });
    assert!(matches!(out, Err(TxnError::Poisoned)), "got {out:?}");
    assert!(!ran.get(), "the refusal precedes the closure");
    assert!(matches!(k.checkpoint(), Err(CheckpointError::Poisoned)));
    assert_eq!(items(&k), vec![10], "reads serve the last consistent root");
    assert_eq!(k.current_seq(), Seq(1));

    drop(k);
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    assert!(!k.is_poisoned(), "poison does not persist");
    assert_eq!(items(&k), vec![10]);
    assert_eq!(commit(&k, 20), Seq(2));
}

#[test]
fn panic_in_closure_leaves_kernel_usable_and_gap_free() {
    let k = Kernel::open(cfg_in_memory(), genesis()).unwrap();
    // A panic in f unwinds before any Seq is drawn: staging is discarded, the
    // panic propagates, the kernel is NOT poisoned, and the order stays
    // gap-free (§3).
    let unwound = catch_unwind(AssertUnwindSafe(|| {
        let _ = k.transact::<(), ()>(&[], |stg| {
            stg.push(TestRec::Append(1));
            panic!("boom");
        });
    }));
    assert!(unwound.is_err());
    assert_eq!(k.current_seq(), Seq(0));
    assert_eq!(items(&k), Vec::<u64>::new());
    assert_eq!(commit(&k, 7), Seq(1));
    assert_eq!(items(&k), vec![7]);
}

/// A world whose GENESIS value carries a probe that panics when the last
/// reference to it drops — every value `apply` builds carries none — so the
/// one destructor that unwinds is the superseded genesis root's, and a test
/// sees exactly where M2 releases it.
#[derive(Clone, Serialize, Deserialize)]
struct ProbedWorld {
    items: Vec<u64>,
    /// Held for its `Drop`, never read.
    #[serde(skip)]
    _probe: Option<std::sync::Arc<PanicsOnDrop>>,
}

struct PanicsOnDrop;

impl Drop for PanicsOnDrop {
    fn drop(&mut self) {
        panic!("a superseded root's destructor unwound");
    }
}

impl WorldState for ProbedWorld {
    type Record = u64;

    fn apply(&self, record: &u64) -> Self {
        let mut items = self.items.clone();
        items.push(*record);
        ProbedWorld {
            items,
            _probe: None,
        }
    }
}

#[test]
fn a_superseded_root_is_released_after_the_commit_region_never_inside_it() {
    // `WorldState`'s drop obligation, from the side M2 fixes: `transact`
    // holds the superseded root until it returns, so the install releases
    // only a reference, and a destructor that unwinds does so AFTER the
    // transaction committed and installed — the lost-ack case, the kernel not
    // poisoned and its order intact. Released inside the commit region
    // instead, the unwind would be repaired as a pre-install failure, rolling
    // the order back below a root already installed.
    let genesis = ProbedWorld {
        items: Vec::new(),
        _probe: Some(std::sync::Arc::new(PanicsOnDrop)),
    };
    let k = Kernel::open(cfg_in_memory(), genesis).unwrap();
    let unwound = catch_unwind(AssertUnwindSafe(|| {
        let _ = k.transact::<(), ()>(&[], |stg| {
            stg.push(10);
            Ok(())
        });
    }));
    assert!(unwound.is_err(), "the superseded root's destructor unwound out of transact");
    assert!(!k.is_poisoned());
    assert_eq!(k.current_seq(), Seq(1), "the transaction committed and installed");
    let (_, seq) = k
        .transact::<(), ()>(&[], |stg| {
            stg.push(20);
            Ok(())
        })
        .unwrap();
    assert_eq!(seq, Seq(2), "the order was rolled back below an installed root");
    assert_eq!(k.snapshot().world().items, vec![10, 20]);
}
