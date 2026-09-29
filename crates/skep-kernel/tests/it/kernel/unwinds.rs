//! Unwind safety (§3): a panic in the closure, in the commit region, and in a
//! superseded root's destructor, each leaving the kernel where its contract
//! says.

use std::panic::{catch_unwind, AssertUnwindSafe};

use super::*;
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
