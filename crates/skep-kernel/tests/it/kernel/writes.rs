//! The commit path's claims: what `transact` returns and refuses, what its
//! closure may see and do, the snapshots readers pin, the lock-key seam, and
//! one gap-free order under concurrent writers (§2–§5, §8).

use std::panic::{catch_unwind, AssertUnwindSafe};

use super::*;
use crate::mutilate::{ckpt_file, seg_file};
use skep_kernel::{
    Attestation, AttestationError, CheckpointError, CheckpointHeader, HistoryError, LockKey,
    OpenError, Snapshot, Space, Staging, TxnError, MAX_TXN_BYTES,
};
use tempfile::tempdir;

#[test]
fn transact_commits_and_returns_last_seq() {
    let k = Kernel::open(cfg_in_memory(), genesis()).unwrap();
    // A multi-record composite returns its terminal last_seq — the one
    // observable coordinate (§2); interior seqs are M2-internal.
    let (_, seq) = k
        .transact(&[], |stg| {
            stg.push(TestRec::Append(1));
            stg.push(TestRec::Append(2));
            stg.push(TestRec::Append(3));
            Ok::<(), ()>(())
        })
        .unwrap();
    assert_eq!(seq, Seq(3));
    assert_eq!(k.current_seq(), Seq(3));
    let (_, seq) = k
        .transact(&[], |stg| {
            stg.push(TestRec::Append(4));
            stg.push(TestRec::Append(5));
            Ok::<(), ()>(())
        })
        .unwrap();
    assert_eq!(seq, Seq(5));
    assert_eq!(items(&k), vec![1, 2, 3, 4, 5]);
    assert_eq!(k.snapshot().world().sum, 15); // hint maintained by apply on every commit
}

#[test]
fn a_composites_intermediates_are_invisible_to_external_readers() {
    // §3: Σᵢ belongs to the executing closure; external readers see only the
    // single atomic install (A0/A4; "none-or-all to external readers"). A
    // lock-free read from inside the closure is exactly what an external
    // reader would take mid-composite — `snapshot`/`current_seq` take no
    // applier lock, which `transact`'s precondition states as a permission.
    let k = Kernel::open(cfg_in_memory(), genesis()).unwrap();
    commit(&k, 1);
    let pinned = k.snapshot();
    k.transact(&[], |stg| {
        stg.push(TestRec::Append(2));
        assert_eq!(items(&k), vec![1], "a reader observed Σᵢ, not Σ");
        assert_eq!(k.current_seq(), Seq(1));
        stg.push(TestRec::Append(3));
        assert_eq!(items(&k), vec![1], "a reader observed Σᵢ, not Σ");
        assert_eq!(stg.working().items.len(), 3); // the closure DOES see them
        Ok::<(), ()>(())
    })
    .unwrap();
    // …and then all at once, at the install.
    assert_eq!(items(&k), vec![1, 2, 3]);
    assert_eq!(k.current_seq(), Seq(3));
    assert_eq!(world_items(pinned.world()), vec![1]);
}

/// The panic message of a caught unwind, whichever way the payload was boxed.
fn panic_message(payload: &(dyn std::any::Any + Send)) -> &str {
    payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| payload.downcast_ref::<&str>().copied())
        .unwrap_or("<non-string panic payload>")
}

#[test]
fn a_nested_transact_is_answered_as_the_callers_bug_it_is() {
    // `transact` holds the applier lock for the whole of `f`, so a nested
    // write can never proceed. That is a precondition violation — a caller's
    // bug — and it arrives as a panic naming the broken obligation rather
    // than as the permanent wedge a non-reentrant lock would otherwise give,
    // which no operator can act on and no supervisor can distinguish from a
    // slow fsync.
    let k = Kernel::open(cfg_in_memory(), genesis()).unwrap();
    commit(&k, 1);
    let unwound = catch_unwind(AssertUnwindSafe(|| {
        let _ = k.transact::<(), ()>(&[], |stg| {
            stg.push(TestRec::Append(2));
            let _ = k.transact::<(), ()>(&[], |inner| {
                inner.push(TestRec::Append(3));
                Ok(())
            });
            Ok(())
        });
    }));
    let payload = unwound.expect_err("a nested transact must not proceed");
    let msg = panic_message(&*payload);
    assert!(msg.contains("not reentrant"), "got {msg:?}");

    // The refusal precedes the lock and the guard clears its owner on the way
    // out, so the kernel is left usable and gap-free: neither transaction
    // drew a `Seq`.
    assert_eq!(k.current_seq(), Seq(1));
    assert_eq!(commit(&k, 4), Seq(2));
    assert_eq!(items(&k), vec![1, 4]);
}

#[test]
fn the_reentrancy_refusal_is_scoped_to_the_one_kernel_holding_the_lock() {
    // One thread transacting on two DISTINCT kernels is honest input: the
    // second kernel's applier is free, so its write proceeds. Refusing here
    // would panic on a program that has nothing wrong with it.
    let a = Kernel::open(cfg_in_memory(), genesis()).unwrap();
    let b = Kernel::open(cfg_in_memory(), genesis()).unwrap();
    let (_, seq) = a
        .transact(&[], |stg| {
            stg.push(TestRec::Append(1));
            b.transact(&[], |inner| {
                inner.push(TestRec::Append(2));
                Ok::<(), ()>(())
            })
        })
        .unwrap();
    assert_eq!(seq, Seq(1));
    assert_eq!(items(&a), vec![1]);
    assert_eq!(items(&b), vec![2]);
}

#[test]
fn the_closure_may_read_and_checkpoint_the_kernel_it_is_committing_to() {
    // The other half of the precondition: only nested WRITES are forbidden.
    // The reads take no applier lock, and `checkpoint()` takes only its own
    // mutex — so each answers from Σ, the installed root, and none of them
    // observes the transaction in flight.
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    commit(&k, 10);
    k.transact(&[], |stg| {
        stg.push(TestRec::Append(20));
        assert_eq!(k.current_seq(), Seq(1));
        assert_eq!(world_items(k.snapshot().world()), vec![10]);
        // A history read derives from the journal, which holds Σ and nothing
        // of the transaction in flight.
        assert_eq!(world_items(&k.world_at(Seq(1)).unwrap()), vec![10]);
        // …and a checkpoint taken here embodies Σ, at Σ's own coordinate.
        assert_eq!(k.checkpoint().unwrap(), Seq(1));
        Ok::<(), ()>(())
    })
    .unwrap();
    assert!(ckpt_file(dir.path(), 1).exists());
    assert_eq!(items(&k), vec![10, 20]);
    // That mid-composite checkpoint is a real base: reopening onto it and
    // replaying the tail lands on the whole world, the composite included.
    drop(k);
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    assert_eq!(items(&k), vec![10, 20]);
    assert_eq!(k.current_seq(), Seq(2));
}

#[test]
fn zero_step_returns_base_seq_and_commits_nothing() {
    let k = Kernel::open(cfg_in_memory(), genesis()).unwrap();
    // A1 zero-step: Ok with zero staged records → no commit; the returned Seq
    // is the base Committed's seq — the committed index the op evaluated
    // against (A2/V1).
    let (v, seq) = k.transact(&[], |_| Ok::<_, ()>(42)).unwrap();
    assert_eq!((v, seq), (42, Seq(0)));
    commit(&k, 9);
    let (v, seq) = k.transact(&[], |_| Ok::<_, ()>(43)).unwrap();
    assert_eq!((v, seq), (43, Seq(1)));
    assert_eq!(k.current_seq(), Seq(1));
}

#[test]
fn rejected_leaves_state_untouched() {
    let k = Kernel::open(cfg_in_memory(), genesis()).unwrap();
    // f → Err is a clean typed rejection: nothing committed, no dangling
    // state — even when records were pushed before the Err (§3).
    let out: Result<((), Seq), TxnError<&str>> = k.transact(&[], |stg| {
        stg.push(TestRec::Append(99));
        Err("precondition failed")
    });
    assert!(matches!(out, Err(TxnError::Rejected("precondition failed"))));
    assert_eq!(k.current_seq(), Seq(0));
    assert_eq!(items(&k), Vec::<u64>::new());
    // The rejected txn drew no Seq: the next commit is Seq(1).
    assert_eq!(commit(&k, 1), Seq(1));
}

#[test]
fn a_rejection_travels_as_the_cause_it_is() {
    // A store's typed refusal is the transaction's cause: a reporter holding
    // the `TxnError` walks `source` to it and downcasts to the store's own
    // type — the one the store documents and a caller branches on.
    #[derive(Debug)]
    struct Refused;
    impl std::fmt::Display for Refused {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("the store refused")
        }
    }
    impl std::error::Error for Refused {}

    let k = Kernel::open(cfg_in_memory(), genesis()).unwrap();
    let err = k
        .transact::<(), _>(&[], |_| Err(Refused))
        .expect_err("the closure refused");
    let cause = std::error::Error::source(&err).expect("the rejection is its cause");
    assert!(cause.downcast_ref::<Refused>().is_some(), "got {cause}");
    // The variants that carry nothing carry no cause.
    assert!(std::error::Error::source(&TxnError::<Refused>::Poisoned).is_none());
    assert!(std::error::Error::source(&TxnError::<Refused>::OverBudget { bytes: 1 }).is_none());
}

#[test]
fn splitting_beneath_the_published_budget_commits() {
    // `OverBudget`'s remedy is a size decision the caller makes, and
    // `MAX_TXN_BYTES` is the figure M2 publishes for it. Everything that pins
    // the two together reaches the constant by its crate-private path; from
    // out here the export could vanish and the suite would not notice.
    let k = Kernel::open(cfg_in_memory(), genesis()).unwrap();
    let piece = (MAX_TXN_BYTES / 2) as usize;
    let out = k.transact::<(), ()>(&[], |stg| {
        stg.push(TestRec::Blob(vec![0u8; piece]));
        stg.push(TestRec::Blob(vec![0u8; piece]));
        Ok(())
    });
    let bytes = match out {
        Err(TxnError::OverBudget { bytes }) => bytes,
        other => panic!("expected OverBudget, got {other:?}"),
    };
    assert!(bytes > MAX_TXN_BYTES, "the report is the accounted size");
    // The remedy, followed literally: each split's records fall beneath the
    // published figure, and each commits.
    for i in 0..2u64 {
        let (_, seq) = k
            .transact::<(), ()>(&[], |stg| {
                stg.push(TestRec::Blob(vec![0u8; piece]));
                Ok(())
            })
            .expect("a split beneath the published budget commits");
        assert_eq!(seq, Seq(i + 1));
    }
}

#[test]
fn staging_working_folds_pushes_and_base_stays() {
    let k = Kernel::open(cfg_in_memory(), genesis()).unwrap();
    commit(&k, 5);
    k.transact(&[], |stg| {
        assert_eq!(stg.base().items.len(), 1);
        assert_eq!(stg.working().items.len(), 1); // == base before the first push
        // The multi-atom frontier pattern (§3/§4, W2 at M2's granularity):
        // each atom reads the frontier the prior atoms left on working(),
        // never the unchanging base().
        for _ in 0..3 {
            let frontier = stg.working().items.len() as u64;
            stg.push(TestRec::Append(frontier * 100));
        }
        assert_eq!(
            stg.working().items.iter().copied().collect::<Vec<_>>(),
            vec![5, 100, 200, 300]
        );
        assert_eq!(stg.base().items.len(), 1); // Σ untouched
        Ok::<(), ()>(())
    })
    .unwrap();
    assert_eq!(items(&k), vec![5, 100, 200, 300]);
}

#[test]
fn snapshot_pins_one_committed_state() {
    let k = Kernel::open(cfg_in_memory(), genesis()).unwrap();
    commit(&k, 10);
    let s = k.snapshot();
    assert_eq!(s.seq(), Seq(1));
    commit(&k, 20);
    // The pinned view is stable across later installs (MIC-4/6; V0/V2)…
    assert_eq!(s.seq(), Seq(1));
    assert_eq!(s.world().items.iter().copied().collect::<Vec<_>>(), vec![10]);
    // …while a fresh snapshot and current_seq see the new root (§5).
    let s2 = k.snapshot();
    assert_eq!(s2.seq(), Seq(2));
    assert_eq!(k.current_seq(), Seq(2));
}

#[test]
fn a_cloned_snapshot_is_the_same_pinned_state() {
    // A clone is a refcount bump on ONE root, so a multi-read verdict split
    // across places still reads one committed state (MIC-4/6; V2) — which
    // taking a second `snapshot()` would not give.
    let k = Kernel::open(cfg_in_memory(), genesis()).unwrap();
    commit(&k, 10);
    let s = k.snapshot();
    let also = s.clone();
    commit(&k, 20);
    assert_eq!((s.seq(), also.seq()), (Seq(1), Seq(1)));
    assert_eq!(world_items(s.world()), world_items(also.world()));
    // A clone outlives the value it came from, and stays pinned to its state.
    drop(s);
    assert_eq!(also.seq(), Seq(1));
    assert_eq!(world_items(also.world()), vec![10]);
    assert_eq!(k.current_seq(), Seq(2));
}

#[test]
fn the_kernel_and_its_handles_carry_the_traits_callers_build_on() {
    // Send + Sync is a promise a private field can silently revoke, so it is
    // asserted rather than inferred: every consumer shares one `Kernel`
    // across threads, and a `Snapshot` is a value they move.
    fn shareable<T: Send + Sync>() {}
    shareable::<Kernel<TestWorld>>();
    shareable::<Snapshot<TestWorld>>();
    // Debug is what lets a consumer derive it on a struct that holds these.
    fn debuggable<T: std::fmt::Debug>() {}
    debuggable::<Kernel<TestWorld>>();
    debuggable::<Snapshot<TestWorld>>();
    debuggable::<Staging<TestWorld>>();

    // The empty coordinate a consumer derives `Default` around: genesis, the
    // boundary before anything is committed — the value, not the trait, is
    // the promise, so it is the value that is pinned.
    assert_eq!(Seq::default(), Seq(0));
    // A configuration compares, so a consumer can hold one and detect a
    // change; every knob it carries already does.
    assert_eq!(cfg_in_memory(), cfg_in_memory());
    assert_ne!(cfg_in_memory(), cfg_fsync(std::path::Path::new("/tmp/x")));

    // The rendering names the coordinate, never the world (`TestWorld` is
    // large and is not required to be `Debug` at all).
    let k = Kernel::open(cfg_in_memory(), genesis()).unwrap();
    commit(&k, 10);
    let rendered = format!("{:?}", k.snapshot());
    assert!(rendered.contains("Seq(1)"), "got {rendered}");
    let rendered = format!("{k:?}");
    assert!(rendered.contains("poisoned: false"), "got {rendered}");
}

#[test]
fn every_failure_is_a_std_error_that_crosses_threads() {
    // A caller boxes an M2 failure as `Box<dyn Error + Send + Sync>` — the
    // shape `?` converts any such error into — and each account inside one is
    // a box a private field could loosen, so the promise is asserted rather
    // than inferred.
    fn crossing<T: std::error::Error + Send + Sync + 'static>() {}
    crossing::<OpenError>();
    crossing::<HistoryError>();
    crossing::<CheckpointError>();
    crossing::<TxnError<std::fmt::Error>>();
    crossing::<AttestationError>();
    // A caller keeps an attestation or a checkpoint header as a value: in a
    // set, as a map key, or across threads.
    fn kept<T: Clone + Eq + std::hash::Hash + std::fmt::Debug + Send + Sync>() {}
    kept::<Attestation>();
    kept::<CheckpointHeader>();
}

#[test]
fn lock_key_order_is_bytewise_and_the_space_tag_leads() {
    // Within one space, LockKey order is bytewise over the caller's own bytes
    // (never tumbler order) (§4).
    let ns = |b: &[u8]| LockKey::new(Space::Namespace, b);
    assert!(ns(&[1, 2]) < ns(&[2, 1]));
    assert!(ns(&[1]) < ns(&[1, 0]));
    // The space tag leads, so keys in distinct spaces cannot interleave —
    // which is what the ordering owes the seam, not merely that it is total.
    assert!(ns(&[0xFF]) < LockKey::new(Space::CoverageClass, &[0x00]));
}

#[test]
fn no_two_spaces_share_a_tag_or_alias_on_identical_bytes() {
    assert_eq!(Space::Namespace.tag(), 0x01);
    assert_eq!(Space::CoverageClass.tag(), 0x02);
    assert_eq!(Space::Principals.tag(), 0x03);
    assert_eq!(Space::Nodes.tag(), 0x04);
    // Every key space in the system draws its tag here, so the uniqueness
    // that keeps two stores' keys from aliasing is checkable in one place
    // (§4) — which is the whole reason the enum is central. Two stores that
    // pick the same bytes in different spaces still get different keys,
    // because the tag is prefixed by the constructor and not by them.
    let tags = [
        Space::Namespace.tag(),
        Space::CoverageClass.tag(),
        Space::Principals.tag(),
        Space::Nodes.tag(),
    ];
    for i in 0..tags.len() {
        for j in (i + 1)..tags.len() {
            assert_ne!(tags[i], tags[j], "space tags {i} and {j} alias");
        }
    }
    let spaces = [
        Space::Namespace,
        Space::CoverageClass,
        Space::Principals,
        Space::Nodes,
    ];
    for i in 0..spaces.len() {
        for j in (i + 1)..spaces.len() {
            assert_ne!(
                LockKey::new(spaces[i], b"same bytes"),
                LockKey::new(spaces[j], b"same bytes"),
                "spaces {i} and {j} alias on identical payloads"
            );
        }
    }
}

#[test]
fn transact_accepts_the_seam_keys_and_returns_a_copyable_seq() {
    let by_value: Seq = Seq(7); // Copy
    assert_eq!(by_value, Seq(7));

    // Keys pass through transact (the v1 seam — subsumed by the global lock).
    let k = Kernel::open(cfg_in_memory(), genesis()).unwrap();
    let (_, seq) = k
        .transact(&[LockKey::new(Space::Namespace, b"home")], |stg| {
            stg.push(TestRec::Append(1));
            Ok::<(), ()>(())
        })
        .unwrap();
    assert_eq!(seq, Seq(1));
}

#[test]
fn an_unencodable_record_is_a_no_op_that_re_invoking_cannot_fix() {
    // A transaction that never becomes frames leaves exactly what a failed
    // barrier leaves (§1): nothing installed, the Seqs it drew burned per
    // BurnedSeqPolicy, no poison, and nothing on disk to recover — while
    // saying the one thing the barrier arm must not, namely that the records
    // themselves are the refusal, so the same call fails the same way.
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    commit(&k, 10);
    let attempt = || -> Result<((), Seq), TxnError<()>> {
        k.transact(&[], |stg| {
            stg.push(TestRec::FailsToSerialize(RefusesSerialization));
            Ok(())
        })
    };
    let out = attempt();
    assert!(
        matches!(out, Err(TxnError::Unencodable(_))),
        "expected an unencodable-record failure, got {out:?}"
    );
    // Nothing installed: the install follows a barrier that was never reached.
    assert_eq!(k.current_seq(), Seq(1));
    assert_eq!(items(&k), vec![10]);
    // Re-invoking is what the disposition would have a client do, and it
    // lands in exactly the same place — which is why this is not `Durability`.
    assert!(matches!(attempt(), Err(TxnError::Unencodable(_))));
    assert_eq!(k.current_seq(), Seq(1));
    // Not poisoned, and the burned coordinate is REUSED — gap-free (§1/§3).
    assert_eq!(commit(&k, 20), Seq(2));
    drop(k);
    // Nothing of the failed txn is on disk to recover.
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    assert_eq!(items(&k), vec![10, 20]);
    assert_eq!(k.current_seq(), Seq(2));
}

#[test]
fn a_durability_failure_is_a_true_no_op_the_caller_may_re_invoke() {
    // §1/§3: an `io::Error` from the append path BEFORE the barrier is a TRUE
    // no-op — nothing installed, no durable marker, the Seqs burned per
    // `BurnedSeqPolicy` — and, unlike `Unencodable`, one the caller may safely
    // re-invoke: the refusal was the environment's, not the records'.
    // Injected at the one point in that path a test can reach deterministically
    // and without root-dependent permissions: rotation opens the next segment
    // BY NAME, so a directory squatting on that name fails the open (EISDIR).
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    for _ in 0..4 {
        commit_blob(&k); // past the 1 MiB threshold: txn 5 is the one that rotates
    }
    assert_eq!(k.current_seq(), Seq(4));
    fs::create_dir(seg_file(dir.path(), 5)).unwrap();

    let attempt = || -> Result<((), Seq), TxnError<()>> {
        k.transact(&[], |stg| {
            stg.push(TestRec::Blob(vec![7u8; BLOB]));
            Ok(())
        })
    };
    let out = attempt();
    assert!(
        matches!(out, Err(TxnError::Durability(_))),
        "expected a pre-barrier append failure, got {out:?}"
    );
    // Nothing installed: the install follows a barrier that was never reached.
    assert_eq!(k.current_seq(), Seq(4));
    assert_eq!(items(&k).len(), 4);

    // Re-invoking is what the disposition has a caller do, and with the
    // environment repaired it SUCCEEDS — the one thing separating this from
    // `Unencodable`, which fails the same way forever.
    fs::remove_dir(seg_file(dir.path(), 5)).unwrap();
    let (_, seq) = attempt().expect("a true no-op is safe to re-invoke");
    // The burned coordinate was REUSED: the order stayed gap-free (§1).
    assert_eq!(seq, Seq(5));
    // …and the retry re-entered rotation, as the writer's own contract says.
    assert!(seg_file(dir.path(), 5).is_file());
    assert_eq!(items(&k).len(), 5);
    drop(k);
    // Nothing of the failed attempt is on disk to recover.
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    assert_eq!(items(&k).len(), 5);
    assert_eq!(k.current_seq(), Seq(5));
}

#[test]
fn a_records_own_refusal_precedes_the_environments() {
    // Both refusals hold at once here — the record cannot be journaled AND the
    // next segment cannot be created — and the record's must speak, because
    // `Durability` says "a TRUE no-op the caller may safely re-invoke" and a
    // client honouring that retries a record that can never succeed, forever,
    // each turn cloning `W` under the applier lock.
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    for _ in 0..4 {
        commit_blob(&k); // past the threshold: txn 5 is the one that rotates
    }
    fs::create_dir(seg_file(dir.path(), 5)).unwrap();

    // The environment is genuinely broken: an encodable txn fails on it.
    let out = k.transact::<(), ()>(&[], |stg| {
        stg.push(TestRec::Blob(vec![7u8; BLOB]));
        Ok(())
    });
    assert!(matches!(out, Err(TxnError::Durability(_))), "got {out:?}");
    // …and on that same broken environment, a record that cannot be journaled
    // is reported as the records' refusal, which re-invoking cannot fix.
    let out = k.transact::<(), ()>(&[], |stg| {
        stg.push(TestRec::FailsToSerialize(RefusesSerialization));
        Ok(())
    });
    assert!(matches!(out, Err(TxnError::Unencodable(_))), "got {out:?}");
    assert_eq!(k.current_seq(), Seq(4), "neither refusal installed anything");
}

#[test]
fn under_tolerate_gap_a_failed_txn_leaves_the_high_water_advanced() {
    // The knob's other setting: the burned Seq is NOT rolled back, the order
    // relaxes to monotone-only, and recovery folds the gap harmlessly — no
    // contiguity is required over the replayed range (§1/§7).
    let dir = tempdir().unwrap();
    let cfg = KernelConfig {
        durability: Durability::Fsync {
            journal_path: dir.path().to_path_buf(),
            retain_checkpoints: 2,
            burned_seq: BurnedSeqPolicy::TolerateGap,
        },
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(TEST_SEED),
    };
    let k = Kernel::open(cfg.clone(), genesis()).unwrap();
    commit(&k, 10);
    let out: Result<((), Seq), TxnError<()>> = k.transact(&[], |stg| {
        stg.push(TestRec::FailsToSerialize(RefusesSerialization));
        Ok(())
    });
    assert!(
        matches!(out, Err(TxnError::Unencodable(_))),
        "expected a failed txn, got {out:?}"
    );
    assert_eq!(commit(&k, 20), Seq(3), "Seq 2 was burned and must not be reused");
    drop(k);
    let k = Kernel::open(cfg, genesis()).unwrap();
    assert_eq!(items(&k), vec![10, 20]);
    assert_eq!(k.current_seq(), Seq(3));
}

#[test]
fn concurrent_writers_serialize_into_one_gap_free_order() {
    let k = Kernel::open(cfg_in_memory(), genesis()).unwrap();
    let mut all: Vec<u64> = Vec::new();
    std::thread::scope(|s| {
        let mut handles = Vec::new();
        for t in 0..4u64 {
            let k = &k;
            handles.push(s.spawn(move || {
                let mut seqs = Vec::new();
                for i in 0..25u64 {
                    let (_, seq) = k
                        .transact(&[], |stg| {
                            stg.push(TestRec::Append(t * 1000 + i));
                            Ok::<(), ()>(())
                        })
                        .unwrap();
                    seqs.push(seq.0);
                }
                seqs
            }));
        }
        // A reader alongside: the installed index never regresses (§5) and
        // every snapshot is a whole committed state (its hint matches its
        // items — no torn read; MIC-4).
        let reader = s.spawn(|| {
            let mut prev = 0u64;
            for _ in 0..500 {
                let cur = k.current_seq().0;
                assert!(cur >= prev, "current_seq regressed");
                prev = cur;
                let snap = k.snapshot();
                let sum: u64 = snap.world().items.iter().sum();
                assert_eq!(sum, snap.world().sum, "torn read: hint diverged");
            }
        });
        for h in handles {
            all.extend(h.join().unwrap());
        }
        reader.join().unwrap();
    });
    all.sort_unstable();
    assert_eq!(all, (1..=100).collect::<Vec<u64>>());
    assert_eq!(k.current_seq(), Seq(100));
    let snap = k.snapshot();
    assert_eq!(snap.world().items.len(), 100);
}
