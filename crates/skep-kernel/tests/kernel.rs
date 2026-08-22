//! Integration tests for M2's public surface. Each test states a claim the
//! design/interface actually makes (§-references inline); the toy `TestWorld`
//! follows the composition contract's shape — an `im` slice, a non-idempotent
//! `apply` that also maintains a derived hint, and a `#[serde(skip)]` hint
//! reseeded by `rebuild_derived`.

#[path = "common/mutilate.rs"]
mod mutilate;

use std::fs;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use mutilate::{append_bytes, ckpt_file, flip_byte, seg_file, truncate_file};
use serde::{Deserialize, Serialize};
use skep_kernel::{
    BurnedSeqPolicy, CheckpointError, CheckpointPolicy, Durability, HistoryError, Kernel,
    KernelConfig, LockKey, OpenError, Seq, Snapshot, Space, Staging, TxnError, WorldState,
    MAX_TXN_BYTES,
};
use tempfile::tempdir;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TestWorld {
    items: im::Vector<u64>,
    /// Derived hint: maintained incrementally in `apply` (mandatory — §1/§7),
    /// skip-serialized so checkpoints exercise `rebuild_derived`.
    #[serde(skip)]
    sum: u64,
    /// Instrumentation: how many times `rebuild_derived` ran on this value's
    /// history ("ONCE at load, NEVER on a live commit").
    #[serde(skip)]
    rebuilds: u32,
}

#[derive(Debug, Serialize, Deserialize)]
enum TestRec {
    Append(u64),
    Blob(Vec<u8>),
    /// Stages and folds like any record and then panics when the commit
    /// region serializes it — the one way a test can unwind INSIDE that
    /// region, where the §3 guard rather than the closure phase answers.
    PanicOnSerialize(PanicsOnSerialize),
    /// Stages and folds like any record and then FAILS to serialize in the
    /// commit region — a record the journal cannot frame, whatever the disk
    /// is doing.
    FailsToSerialize(RefusesSerialization),
}

#[derive(Debug)]
struct PanicsOnSerialize;

impl Serialize for PanicsOnSerialize {
    fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
        panic!("record serialization panicked inside the commit region");
    }
}

impl<'de> Deserialize<'de> for PanicsOnSerialize {
    fn deserialize<D: serde::Deserializer<'de>>(_: D) -> Result<Self, D::Error> {
        // Nothing that panics on the way out ever reaches the journal.
        unreachable!("never serialized, so never journaled, so never read back")
    }
}

/// Returns a serializer ERROR rather than panicking. `transact` serializes
/// each staged record inside the commit region, so a refusal there is a
/// transaction that never becomes frames — the [`TxnError::Unencodable`] arm,
/// which shares the no-op discipline of §1's barrier failure and differs from
/// it in exactly one thing: no retry can succeed.
#[derive(Debug)]
struct RefusesSerialization;

impl Serialize for RefusesSerialization {
    fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
        Err(serde::ser::Error::custom("record refused to serialize"))
    }
}

impl<'de> Deserialize<'de> for RefusesSerialization {
    fn deserialize<D: serde::Deserializer<'de>>(_: D) -> Result<Self, D::Error> {
        unreachable!("never serialized, so never journaled, so never read back")
    }
}

impl WorldState for TestWorld {
    type Record = TestRec;

    fn apply(&self, r: &TestRec) -> Self {
        let mut next = self.clone();
        match r {
            // Non-idempotent on purpose: double-application is visible, so
            // recovery equality proves exactly-once replay (§6/§7).
            TestRec::Append(x) => {
                next.items.push_back(*x);
                next.sum += *x;
            }
            TestRec::Blob(b) => {
                next.items.push_back(b.len() as u64);
                next.sum += b.len() as u64;
            }
            // Fold like any other record; the refusal waits for the journal.
            // A staged 0 leaves `sum` alone, so `rebuild_derived` agrees with
            // `apply` on it — and a leaked commit is still visible in `items`.
            TestRec::PanicOnSerialize(_) | TestRec::FailsToSerialize(_) => {
                next.items.push_back(0);
            }
        }
        next
    }

    fn rebuild_derived(self) -> Self {
        let sum = self.items.iter().sum();
        TestWorld {
            sum,
            rebuilds: self.rebuilds + 1,
            items: self.items,
        }
    }
}

fn genesis() -> TestWorld {
    TestWorld {
        items: im::Vector::new(),
        sum: 0,
        rebuilds: 0,
    }
}

/// A world that refuses to serialize once a record has broken it. M2 never
/// inspects `W`, so `W`'s own serializer is the only thing that can fail a
/// checkpoint — which makes this the only route to
/// [`CheckpointError::Serialize`] and to §3/§6's logged-and-dropped rule.
#[derive(Clone, Debug, Default, Deserialize)]
struct FragileWorld {
    commits: u64,
    broken: bool,
}

impl Serialize for FragileWorld {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if self.broken {
            return Err(serde::ser::Error::custom("world refused to serialize"));
        }
        use serde::ser::SerializeStruct;
        let mut st = s.serialize_struct("FragileWorld", 2)?;
        st.serialize_field("commits", &self.commits)?;
        st.serialize_field("broken", &self.broken)?;
        st.end()
    }
}

/// What a record does to [`FragileWorld`]'s serializer. The record itself
/// always encodes either way; which one a call stages is the whole of what
/// the checkpoint tests turn on, so it is said at the call rather than
/// carried there as a `bool` a reader has to look up.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
enum Fragility {
    /// Leaves the world encodable.
    Sound,
    /// Breaks the world's serializer, permanently.
    Break,
}

impl WorldState for FragileWorld {
    type Record = Fragility;

    fn apply(&self, record: &Fragility) -> Self {
        FragileWorld {
            commits: self.commits + 1,
            broken: self.broken || matches!(record, Fragility::Break),
        }
    }
}

fn cfg_fsync(dir: &Path) -> KernelConfig {
    cfg_retain(dir, 2)
}

/// A journal-backed configuration keeping `retain` checkpoint bases — the
/// knob rides on the journal, so a test that varies it names the journal.
fn cfg_retain(dir: &Path, retain: usize) -> KernelConfig {
    KernelConfig {
        durability: Durability::Fsync {
            journal_path: dir.to_path_buf(),
            retain_checkpoints: retain,
            burned_seq: BurnedSeqPolicy::Rollback,
        },
        checkpoint: CheckpointPolicy::Manual,
    }
}

fn cfg_in_memory() -> KernelConfig {
    KernelConfig {
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::Manual,
    }
}

/// One whole committed transaction staging one record, answering its
/// boundary `Seq` — distinct from `Staging::push`, which stages one record
/// inside a closure and commits nothing.
fn commit(k: &Kernel<TestWorld>, x: u64) -> Seq {
    k.transact(&[], |stg| {
        stg.push(TestRec::Append(x));
        Ok::<(), ()>(())
    })
    .unwrap()
    .1
}

fn world_items(w: &TestWorld) -> Vec<u64> {
    w.items.iter().copied().collect()
}

fn items(k: &Kernel<TestWorld>) -> Vec<u64> {
    world_items(k.snapshot().world())
}

// ---- physical-layer helpers (the on-disk format the design fixes: §1/§6) ----

/// The journal's frame header: magic + len + crc. Restated here because this
/// tier reads the format as bytes rather than through the crate's own parser.
const FRAME_HEADER_LEN: u64 = 12;

fn checkpoint_count(dir: &Path) -> usize {
    fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.unwrap().file_name().into_string().ok())
        .filter(|n| {
            n.strip_prefix("checkpoint.")
                .is_some_and(|s| s.parse::<u64>().is_ok())
        })
        .count()
}

/// `(offset, total frame length)` per frame, walking `[magic][len][crc][payload]`
/// on a clean journal segment.
fn frame_spans(path: &Path) -> Vec<(u64, u64)> {
    let buf = fs::read(path).unwrap();
    let mut spans = Vec::new();
    let mut pos = 0usize;
    let header = FRAME_HEADER_LEN as usize;
    while pos + header <= buf.len() {
        assert_eq!(&buf[pos..pos + 4], b"SKJ1", "expected a clean frame stream");
        let len = u32::from_le_bytes(buf[pos + 4..pos + 8].try_into().unwrap()) as usize;
        spans.push((pos as u64, (header + len) as u64));
        pos += header + len;
    }
    spans
}

fn segment_count(dir: &Path) -> usize {
    fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.unwrap().file_name().into_string().ok())
        .filter(|n| n.starts_with("seg-") && n.ends_with(".wal"))
        .count()
}

// ---- writes & reads ----

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
        // A bounded read derives from the journal, which holds Σ and nothing
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

// ---- recovery (§7) ----

#[test]
fn recovery_replays_journal_exactly_once() {
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    // Fsync-path open runs rebuild_derived once on the loaded base (genesis
    // here) — and never again on live commits.
    assert_eq!(k.snapshot().world().rebuilds, 1);
    commit(&k, 1);
    commit(&k, 2);
    commit(&k, 3);
    assert_eq!(k.snapshot().world().rebuilds, 1);
    k.flush().unwrap(); // no-op Ok under per-commit Fsync
    drop(k);

    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    // apply is non-idempotent, so equality proves each committed record was
    // folded exactly once, in Seq order (A6).
    assert_eq!(items(&k), vec![1, 2, 3]);
    assert_eq!(k.snapshot().world().sum, 6);
    assert_eq!(k.snapshot().world().rebuilds, 1);
    assert_eq!(k.current_seq(), Seq(3));
    drop(k);
    // Recovery is idempotent.
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    assert_eq!(items(&k), vec![1, 2, 3]);
    assert_eq!(k.current_seq(), Seq(3));
}

#[test]
fn recovery_with_checkpoint_replays_only_the_tail() {
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    commit(&k, 1);
    commit(&k, 2);
    commit(&k, 3);
    assert_eq!(k.checkpoint().unwrap(), Seq(3));
    commit(&k, 4);
    commit(&k, 5);
    drop(k);

    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    // Checkpoint embodies Seq ≤ 3; replay covers exactly (3, 5] — no record
    // twice, none skipped (§6 complementarity). The skip-serialized hint was
    // reseeded by rebuild_derived for the prefix and folded by apply for the
    // tail: sum == 15 proves both paths agree (§7 trait contract).
    assert_eq!(items(&k), vec![1, 2, 3, 4, 5]);
    assert_eq!(k.snapshot().world().sum, 15);
    assert_eq!(k.snapshot().world().rebuilds, 1);
    assert_eq!(k.current_seq(), Seq(5));
}

#[test]
fn torn_tail_is_physically_truncated_and_seqs_reused() {
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    commit(&k, 10);
    commit(&k, 20);
    commit(&k, 30);
    drop(k);
    let seg = seg_file(dir.path(), 1);
    let spans = frame_spans(&seg);
    assert_eq!(spans.len(), 6); // T1 rec/marker, T2 rec/marker, T3 rec/marker
    // Crash mid-append of T3's marker: no committed marker → un-acked tail.
    truncate_file(&seg, spans[5].0 + 3);

    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    assert_eq!(items(&k), vec![10, 20]);
    assert_eq!(k.current_seq(), Seq(2));
    // The tail (T3's intact record included — its txn holds no committed
    // marker) was DURABLY removed before writes were served (§7), cutting at
    // T2's marker frame end.
    assert_eq!(fs::metadata(&seg).unwrap().len(), spans[4].0);
    // Under Rollback the next session reuses the discarded coordinates —
    // safe exactly because the stale tail is gone (§1/§7 Txn uniqueness).
    assert_eq!(commit(&k, 30), Seq(3));
    drop(k);
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    assert_eq!(items(&k), vec![10, 20, 30]);
    assert_eq!(k.current_seq(), Seq(3));
}

#[test]
fn corruption_in_replayed_range_halts_with_marker_landing_payload() {
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    commit(&k, 10);
    commit(&k, 20);
    commit(&k, 30);
    drop(k);
    let seg = seg_file(dir.path(), 1);
    let spans = frame_spans(&seg);
    // Corrupt T2's record (an INTERIOR committed txn): the resync lands on
    // T2's marker, so at = last_seq + 1 = 3 and inferred max = 2 ∈ (0, 3] —
    // durable committed data the recovered state needs: halt, never drop (§7).
    flip_byte(&seg, spans[2].0 + FRAME_HEADER_LEN + 1);
    // A torn tail past the last committed marker, so there IS something a
    // truncation would take — without it the cut lands at end-of-file and no
    // assertion could tell a halt from a truncation.
    append_bytes(&seg, &[0xAB, 0xCD, 0xEF]);
    let before = fs::read(&seg).unwrap();

    let err = Kernel::open(cfg_fsync(dir.path()), genesis()).err().unwrap();
    assert!(
        matches!(err, OpenError::Corruption { at: Seq(3), .. }),
        "got {err:?}"
    );
    // A halt cuts nothing: the classification precedes the tail truncation, so
    // the store an operator images after a `Corruption` is the store that was
    // there (§7 — destroying evidence ahead of intervention would be wrong).
    assert_eq!(
        fs::read(&seg).unwrap(),
        before,
        "a halted open truncated the journal"
    );
}

#[test]
fn corruption_below_s_load_is_harmless_including_the_boundary_frame() {
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    commit(&k, 10);
    commit(&k, 20);
    commit(&k, 30);
    assert_eq!(k.checkpoint().unwrap(), Seq(3));
    commit(&k, 40);
    drop(k);
    let seg = seg_file(dir.path(), 1);
    let spans = frame_spans(&seg);
    assert_eq!(spans.len(), 8);
    // Corrupt T3's record. The resync lands on T3's marker: inferred max =
    // last_seq = 3 = S_load → HARMLESS (already embodied in the checkpoint),
    // even though the payload coordinate is S_load + 1 — classifying by `at`
    // instead of the inferred max would spuriously halt on exactly this
    // boundary frame (§7).
    flip_byte(&seg, spans[4].0 + FRAME_HEADER_LEN + 1);
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    assert_eq!(items(&k), vec![10, 20, 30, 40]);
    assert_eq!(k.snapshot().world().sum, 100);
    assert_eq!(k.current_seq(), Seq(4));
}

#[test]
fn an_unreadable_segment_fails_the_open_as_io_not_as_corruption() {
    // `Corruption` says the durable data itself is bad and an operator must
    // intervene; `Io` says this process could not read it. A segment the
    // process cannot READ is the second — and it must never be read AROUND,
    // which answers `Ok` with a world missing every record it held.
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    for _ in 0..5 {
        commit_blob(&k); // four fill seg-1 past the threshold; the fifth rotates
    }
    drop(k);
    assert_eq!(segment_count(dir.path()), 2, "the fixture must rotate");

    // Unreadable, deterministically and without depending on privileges: a
    // directory bearing a segment's name. `list_segments` parses names and not
    // file types, which the `journal_path` caller contract already says. The
    // CLOSED segment, so a scan that read around it would answer `Ok` with a
    // world missing its four records rather than failing at the cut.
    let seg1 = seg_file(dir.path(), 1);
    fs::remove_file(&seg1).unwrap();
    fs::create_dir(&seg1).unwrap();

    let err = Kernel::open(cfg_fsync(dir.path()), genesis())
        .expect_err("an unreadable segment is not something to recover around");
    assert!(matches!(err, OpenError::Io(_)), "got {err:?}");
    // The cause travels, and it is the environment's — not the media's.
    assert!(std::error::Error::source(&err).is_some());
}

#[test]
fn post_commit_rot_of_the_final_txn_demotes_w_silently() {
    // The documented §7 blind spot, asserted as specified: rot in the LAST
    // committed txn's record leaves its marker intact but checksum-failing,
    // W demotes to the prior marker, and the acked txn is silently discarded
    // as tail — no Corruption signal (out of scope for v1).
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    commit(&k, 10);
    commit(&k, 20);
    commit(&k, 30);
    drop(k);
    let seg = seg_file(dir.path(), 1);
    let spans = frame_spans(&seg);
    flip_byte(&seg, spans[4].0 + FRAME_HEADER_LEN + 1); // T3's record
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    assert_eq!(items(&k), vec![10, 20]);
    assert_eq!(k.current_seq(), Seq(2));
    assert_eq!(fs::metadata(&seg).unwrap().len(), spans[4].0); // physically discarded
}

#[test]
fn bad_newest_checkpoint_falls_back_to_older_retained_base() {
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap(); // retain 2
    commit(&k, 10);
    commit(&k, 20);
    assert_eq!(k.checkpoint().unwrap(), Seq(2));
    commit(&k, 30);
    commit(&k, 40);
    assert_eq!(k.checkpoint().unwrap(), Seq(4));
    drop(k);
    // Corrupt the newest checkpoint's body: its header checksum fails, and
    // recovery falls back to the older RETAINED base and replays more (§6/§7).
    let cp = ckpt_file(dir.path(), 4);
    let len = fs::metadata(&cp).unwrap().len();
    flip_byte(&cp, len - 1);
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    assert_eq!(items(&k), vec![10, 20, 30, 40]);
    assert_eq!(k.snapshot().world().sum, 100);
    assert_eq!(k.current_seq(), Seq(4));
}

#[test]
fn world_at_falls_back_down_the_same_base_chain_recovery_uses() {
    // Bounded replay derives its world the way recovery does, so it inherits
    // the whole fallback chain: a base that fails its checksum is skipped for
    // the next-older RETAINED one, then for genesis while reachable, and the
    // answer is the same world whichever base carries it (§6/§7).
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap(); // retain 2
    commit(&k, 10);
    commit(&k, 20);
    assert_eq!(k.checkpoint().unwrap(), Seq(2));
    commit(&k, 30);
    commit(&k, 40);
    assert_eq!(k.checkpoint().unwrap(), Seq(4));
    commit(&k, 50);
    let whole = vec![10, 20, 30, 40, 50];
    assert_eq!(world_items(&k.world_at(Seq(5)).unwrap()), whole);

    // Newest base unusable → the older retained one carries the answer.
    let cp4 = ckpt_file(dir.path(), 4);
    let len = fs::metadata(&cp4).unwrap().len();
    flip_byte(&cp4, len - 1);
    assert_eq!(world_items(&k.world_at(Seq(4)).unwrap()), vec![10, 20, 30, 40]);
    assert_eq!(world_items(&k.world_at(Seq(5)).unwrap()), whole);

    // Both bases unusable → genesis carries it, replaying everything.
    let cp2 = ckpt_file(dir.path(), 2);
    let len = fs::metadata(&cp2).unwrap().len();
    flip_byte(&cp2, len - 1);
    assert_eq!(world_items(&k.world_at(Seq(2)).unwrap()), vec![10, 20]);
    assert_eq!(world_items(&k.world_at(Seq(5)).unwrap()), whole);
    // The hint arrives seeded whichever base was chosen (§7 seam contract 2).
    assert_eq!(k.world_at(Seq(5)).unwrap().sum, 150);
}

#[test]
fn world_at_answers_the_base_boundary_without_consulting_the_journal() {
    // Bit-rot above the base: every boundary that must fold over the damaged
    // region halts, and the base's own boundary — answered wholly from the
    // checkpoint that embodies it — does not.
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    commit(&k, 10);
    commit(&k, 20);
    commit(&k, 30);
    assert_eq!(k.checkpoint().unwrap(), Seq(3));
    commit(&k, 40);
    let seg = seg_file(dir.path(), 1);
    let spans = frame_spans(&seg);
    assert_eq!(spans.len(), 8);
    // Rot in T4's record while the kernel lives — `world_at` reads the
    // journal under the appender, which is where at-rest damage meets it.
    // The resync lands on T4's marker: a run whose inferred max (4) is above
    // the base, so a fold that must cross it could answer from a hole (§7).
    flip_byte(&seg, spans[6].0 + FRAME_HEADER_LEN + 1);
    match k.world_at(Seq(4)) {
        Err(HistoryError::Corruption { at, .. }) => assert_eq!(at, Seq(5)),
        other => panic!("expected Corruption, got {other:?}"),
    }
    assert_eq!(world_items(&k.world_at(Seq(3)).unwrap()), vec![10, 20, 30]);
}

#[test]
fn world_at_halts_on_at_rest_damage_before_judging_the_boundary() {
    // §7 refusal precedence: a corrupt run makes the boundary SET itself
    // underivable — the damage can swallow a marker — so `Corruption` speaks
    // before `NotABoundary`. Here Seq(2) IS a boundary `transact` returned and
    // the damage merely hides it; judging membership first would tell a caller
    // that their own committed coordinate was never a boundary at all.
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    assert_eq!(commit(&k, 10), Seq(1));
    assert_eq!(commit(&k, 20), Seq(2)); // a real boundary, about to be hidden
    assert_eq!(commit(&k, 30), Seq(3));
    let seg = seg_file(dir.path(), 1);
    let spans = frame_spans(&seg);
    assert_eq!(spans.len(), 6);
    // Rot T2's MARKER: its txn stops being committed, so Seq(2) drops out of
    // the boundary set, and the resync lands on T3's record (inferred max 2).
    flip_byte(&seg, spans[3].0 + FRAME_HEADER_LEN + 1);
    match k.world_at(Seq(2)) {
        Err(HistoryError::Corruption { at, .. }) => assert_eq!(at, Seq(3)),
        other => panic!("expected Corruption before the boundary judgment, got {other:?}"),
    }
}

#[test]
fn world_at_halts_when_the_frame_stream_cannot_be_enumerated() {
    // A record whose own bytes plant frame headers, with the frame carrying
    // them broken: every planted header is then a resync candidate, and the
    // scan gives up rather than spending work quadratic in a size the record's
    // author chose. Nothing is derived, so there is no boundary set and no
    // committed head to answer from — a halt at the base's own coordinate (§7).
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    let mut evil = Vec::new();
    while evil.len() < 256 * 1024 {
        evil.extend_from_slice(b"SKJ1");
        evil.extend_from_slice(&(64 * 1024u32).to_le_bytes()); // a len that fits
        evil.extend_from_slice(&0u32.to_le_bytes()); // a crc that will not
        evil.extend_from_slice(&[0u8; 4]);
    }
    k.transact::<_, ()>(&[], |stg| {
        stg.push(TestRec::Blob(evil));
        Ok(())
    })
    .unwrap();
    assert_eq!(commit(&k, 20), Seq(2));
    let seg = seg_file(dir.path(), 1);
    flip_byte(&seg, FRAME_HEADER_LEN + 1); // T1's record: sync is lost here
    match k.world_at(Seq(2)) {
        Err(HistoryError::Corruption { at, .. }) => assert_eq!(at, Seq(0)),
        other => panic!("expected Corruption at the base, got {other:?}"),
    }
}

#[test]
fn world_at_reports_an_unreadable_segment_rather_than_reading_around_it() {
    // The read path's half of the same claim, and the sharper one: a scan that
    // skipped the segment would answer from what is left — here, by reporting
    // a boundary `transact` really returned as one that never existed. `Io` is
    // what the doc promises, and it promises it as TRANSIENT: a retry
    // re-derives from the file as it then stands.
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    commit(&k, 10);
    assert_eq!(commit(&k, 20), Seq(2)); // a boundary in the segment that breaks
    for _ in 0..5 {
        commit_blob(&k); // four fill seg-1 past the threshold; the fifth rotates
    }
    assert_eq!(segment_count(dir.path()), 2, "the fixture must rotate");

    // seg-1 is closed, so the live appender is elsewhere; stash it rather than
    // destroy it, so the retry half is checkable. `seg-1.stashed` fails the
    // segment name parse and is invisible to recovery.
    let seg1 = seg_file(dir.path(), 1);
    let stash = dir.path().join("seg-1.stashed");
    fs::rename(&seg1, &stash).unwrap();
    fs::create_dir(&seg1).unwrap();
    match k.world_at(Seq(2)) {
        Err(HistoryError::Io(_)) => {}
        other => panic!("expected a transient Io, got {other:?}"),
    }

    // …and the retry re-derives from the file as it now stands.
    fs::remove_dir(&seg1).unwrap();
    fs::rename(&stash, &seg1).unwrap();
    assert_eq!(world_items(&k.world_at(Seq(2)).unwrap()), vec![10, 20]);
}

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

// ---- checkpoint failure (§3/§6) ----

#[test]
fn checkpoint_surfaces_the_serializers_account_of_an_unencodable_world() {
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), FragileWorld::default()).unwrap();
    k.transact::<_, ()>(&[], |stg| {
        stg.push(Fragility::Break);
        Ok(())
    })
    .unwrap();
    let err = k
        .checkpoint()
        .expect_err("an unencodable world cannot be checkpointed");
    assert!(matches!(err, CheckpointError::Serialize(_)), "got {err:?}");
    // The cause travels: M2 never inspects `W`, so the serializer's own
    // account is the only thing that identifies the failure.
    assert!(std::error::Error::source(&err).is_some());
    // Nothing half-written, not even a stray tmp (§6's crash argument).
    assert_eq!(checkpoint_count(dir.path()), 0);
    assert!(!dir.path().join("checkpoint.tmp").exists());
    // A failed checkpoint is not a poison: the write path still works.
    k.transact::<_, ()>(&[], |stg| {
        stg.push(Fragility::Sound);
        Ok(())
    })
    .unwrap();
    assert_eq!(k.current_seq(), Seq(2));
}

#[test]
fn a_checkpoint_io_failure_is_retryable_and_never_poisons() {
    // §6: a failed checkpoint leaves at most an ignored `.tmp` and an
    // unreclaimed journal, so it is safe to retry — the opposite disposition
    // from `Serialize`, which repeats until `W` itself encodes. The two share
    // one two-arm match, and only one arm was exercised.
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    commit(&k, 10);
    // The write builds through the FIXED `checkpoint.tmp`, so a directory on
    // that name fails `File::create` (EISDIR).
    fs::create_dir(dir.path().join("checkpoint.tmp")).unwrap();
    let err = k
        .checkpoint()
        .expect_err("a checkpoint that cannot be written fails");
    assert!(matches!(err, CheckpointError::Io(_)), "got {err:?}");
    // The cause travels, and it is the environment's — not `W`'s.
    assert!(std::error::Error::source(&err).is_some());
    assert_eq!(checkpoint_count(dir.path()), 0);
    // Never a poison, and never a disturbance to the write path.
    assert!(!k.is_poisoned());
    assert_eq!(commit(&k, 20), Seq(2));

    // "Safe to retry, and a retry re-does the whole sequence from a fresh
    // root": the base it then writes is at the NEW head, and it is a base a
    // reopen actually loads.
    fs::remove_dir(dir.path().join("checkpoint.tmp")).unwrap();
    assert_eq!(k.checkpoint().unwrap(), Seq(2));
    assert!(ckpt_file(dir.path(), 2).exists());
    drop(k);
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    assert_eq!(items(&k), vec![10, 20]);
    assert_eq!(k.current_seq(), Seq(2));
}

#[test]
fn an_auto_triggered_checkpoint_failure_never_fails_the_committed_txn() {
    // §3/§6: the txn is already durable and installed, so there is no sound
    // path for the checkpoint's error through TxnError — surfacing it would
    // un-acknowledge a real effect. It is logged and dropped.
    let dir = tempdir().unwrap();
    let mut cfg = cfg_fsync(dir.path());
    cfg.checkpoint = CheckpointPolicy::EveryN(1);
    let k = Kernel::open(cfg, FragileWorld::default()).unwrap();
    k.transact::<_, ()>(&[], |stg| {
        stg.push(Fragility::Sound);
        Ok(())
    })
    .unwrap();
    assert!(ckpt_file(dir.path(), 1).exists(), "the auto-trigger is live");
    let (_, seq) = k
        .transact::<_, ()>(&[], |stg| {
            stg.push(Fragility::Break);
            Ok(())
        })
        .expect("the commit is durable and installed; its checkpoint's failure is not its own");
    assert_eq!(seq, Seq(2));
    assert!(!ckpt_file(dir.path(), 2).exists()); // the checkpoint did fail
    assert_eq!(k.current_seq(), Seq(2));
}

// ---- segments, retention & reclamation (§1/§6) ----

/// ~300 KiB per record against the 1 MiB rotation threshold: four commits fill
/// a segment past the threshold, the fifth rotates.
const BLOB: usize = 300 * 1024;

/// [`commit`] staging one [`BLOB`]-sized record instead — the fat commit the
/// rotation, reclamation and byte-trigger fixtures are built from.
fn commit_blob(k: &Kernel<TestWorld>) -> Seq {
    k.transact(&[], |stg| {
        stg.push(TestRec::Blob(vec![7u8; BLOB]));
        Ok::<(), ()>(())
    })
    .unwrap()
    .1
}

#[test]
fn reclamation_floor_is_the_oldest_retained_checkpoint() {
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap(); // retain 2
    for _ in 0..4 {
        commit_blob(&k);
    }
    assert_eq!(k.checkpoint().unwrap(), Seq(4));
    for _ in 0..4 {
        commit_blob(&k);
    }
    assert_eq!(k.checkpoint().unwrap(), Seq(8));
    // Rotation at the txn boundary: txn 5 opened seg-5 (§1 name-by-firstSeq).
    assert!(seg_file(dir.path(), 5).exists());
    // Reclamation dropped only the closed segment wholly below the OLDEST
    // retained checkpoint (S_old = 4) — not below the newest (§6).
    assert!(!seg_file(dir.path(), 1).exists());
    drop(k);
    // That floor is what makes the fallback real: corrupt the newest
    // checkpoint and recovery still has journal above S_old to replay.
    let cp = ckpt_file(dir.path(), 8);
    let len = fs::metadata(&cp).unwrap().len();
    flip_byte(&cp, len - 1);
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    assert_eq!(items(&k).len(), 8);
    assert_eq!(k.snapshot().world().sum, 8 * BLOB as u64);
    assert_eq!(k.current_seq(), Seq(8));
}

#[test]
fn recovery_skips_only_the_segments_the_base_already_embodies() {
    // §7's skip, which no other test reaches: every multi-segment fixture in
    // the suite recovers from genesis, and every checkpoint fixture has one
    // segment. A skip that is one segment too greedy loses the records in
    // (S_load, that segment's last] and answers `Ok` with a short world.
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap(); // retain 2
    assert_eq!(commit_blob(&k), Seq(1)); // seg-1
    assert_eq!(k.checkpoint().unwrap(), Seq(1)); // holds the reclamation floor at 1
    for _ in 0..3 {
        commit_blob(&k); // Seqs 2..=4, filling seg-1 past the threshold
    }
    assert_eq!(commit_blob(&k), Seq(5)); // rotates into seg-5
    assert_eq!(commit_blob(&k), Seq(6));
    assert_eq!(k.checkpoint().unwrap(), Seq(6)); // S_load on reopen; S_old is still 1
    for _ in 0..2 {
        commit_blob(&k); // Seqs 7..=8, filling seg-5 past the threshold
    }
    assert_eq!(commit_blob(&k), Seq(9)); // rotates into seg-9
    drop(k);
    assert_eq!(segment_count(dir.path()), 3, "the fixture must rotate twice");
    assert!(
        seg_file(dir.path(), 1).exists(),
        "…and keep the segment below the base"
    );

    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    // seg-1's inferred lastSeq is 4 ≤ 6, so it is skipped unopened; seg-5
    // STRADDLES the base (it covers 5..=8) and must be scanned for 7 and 8;
    // seg-9 is active and is always scanned.
    assert_eq!(k.current_seq(), Seq(9));
    assert_eq!(items(&k).len(), 9);
    assert_eq!(k.snapshot().world().sum, 9 * BLOB as u64);
}

/// Every regular file of `src` into a fresh `dst`, so one built fixture can be
/// damaged two ways without rebuilding it.
fn copy_store(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).unwrap();
    for entry in fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            fs::copy(entry.path(), dst.join(entry.file_name())).unwrap();
        }
    }
}

#[test]
fn an_absent_segment_shortens_the_world_where_a_damaged_one_halts() {
    // Recovery's damage model is FRAMES THAT FAIL THEIR CRC. Damaging a
    // segment's bytes opens a corrupt run that classifies inside the replayed
    // range and halts. REMOVING that segment leaves no run to classify and no
    // gap to detect — §7 requires no `Seq` contiguity, so a missing segment is
    // indistinguishable from a burned range — and recovery answers `Ok` with a
    // world short by exactly that segment's records, at the true head.
    //
    // The `journal_path` caller contract is what keeps this out of reach:
    // nothing in this module detects it. Asserting both on one fixture is what
    // makes the ASYMMETRY the subject rather than either behaviour alone.
    let tmp = tempdir().unwrap();
    let fixture = tmp.path().join("fixture");
    let k = Kernel::open(cfg_fsync(&fixture), genesis()).unwrap();
    for _ in 0..5 {
        commit_blob(&k); // four fill seg-1; the fifth rotates into seg-5
    }
    for _ in 0..4 {
        commit_blob(&k); // three fill seg-5; the fourth rotates into seg-9
    }
    drop(k);
    assert_eq!(segment_count(&fixture), 3, "the fixture must rotate twice");

    // Damaged: the middle segment's frames stop passing their CRC, so the
    // resync opens a run inside (S_load, W] — a loud halt, nothing folded.
    let damaged = tmp.path().join("damaged");
    copy_store(&fixture, &damaged);
    let mid = seg_file(&damaged, 5);
    let len = fs::metadata(&mid).unwrap().len() as usize;
    fs::write(&mid, vec![0u8; len]).unwrap();
    let err = Kernel::<TestWorld>::open(cfg_fsync(&damaged), genesis())
        .expect_err("a corrupt run in the replayed range is a halt");
    assert!(matches!(err, OpenError::Corruption { .. }), "got {err:?}");

    // Absent: the same records, unreachable the other way — and this one is
    // silent. The head is the true head, so nothing about the answer looks
    // wrong; only the four records seg-5 held are missing.
    let absent = tmp.path().join("absent");
    copy_store(&fixture, &absent);
    fs::remove_file(seg_file(&absent, 5)).unwrap();
    let k = Kernel::<TestWorld>::open(cfg_fsync(&absent), genesis())
        .expect("a missing segment is not something this module detects");
    assert_eq!(k.current_seq(), Seq(9), "the head is the true head");
    assert_eq!(items(&k).len(), 5, "…and the world is short by seg-5's records");
}

#[test]
fn recovery_deletes_the_wholly_later_segments_the_tail_spans() {
    // §7's tail truncation is two acts: cut the segment holding the last
    // committed marker, and DELETE every wholly-later segment. Only the first
    // is exercised elsewhere — every other fixture's tail sits in the segment
    // it cuts.
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    for _ in 0..5 {
        commit_blob(&k); // four fill seg-1 past the threshold; the fifth rotates
    }
    drop(k);
    assert_eq!(segment_count(dir.path()), 2, "the fixture must rotate");
    let seg5 = seg_file(dir.path(), 5);
    let spans = frame_spans(&seg5);
    assert_eq!(spans.len(), 2); // T5's record and its marker
    // Crash mid-append of T5's marker: seg-5 holds no committed marker, so the
    // whole segment is tail and the cut lands at seg-1's end.
    truncate_file(&seg5, spans[1].0 + 3);

    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    assert_eq!(k.current_seq(), Seq(4));
    assert_eq!(items(&k).len(), 4);
    // DURABLY REMOVED, not merely filtered out of the fold: the appender
    // reopens the LAST segment on disk, so a survivor is the file the next
    // session appends into (§1/§7).
    assert!(!seg5.exists(), "the tail's later segment survived recovery");

    // …which is what makes reusing the discarded coordinate safe: the next
    // commit takes Seq(5) again, and the session after it recovers rather than
    // meeting one Seq presented twice.
    assert_eq!(commit_blob(&k), Seq(5));
    drop(k);
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    assert_eq!(items(&k).len(), 5);
    assert_eq!(k.current_seq(), Seq(5));
}

#[test]
fn retention_keeps_the_newest_n_checkpoints() {
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap(); // retain 2
    for x in 1..=3u64 {
        commit(&k, x);
        assert_eq!(k.checkpoint().unwrap(), Seq(x));
    }
    // The third checkpoint pushes the first out (§6).
    assert_eq!(checkpoint_count(dir.path()), 2);
    assert!(!ckpt_file(dir.path(), 1).exists());
    assert!(ckpt_file(dir.path(), 2).exists());
    assert!(ckpt_file(dir.path(), 3).exists());
    drop(k);
    // What retention keeps is a REAL fallback base: destroy the newest and
    // recovery lands on the whole world from the one below it.
    let cp = ckpt_file(dir.path(), 3);
    let len = fs::metadata(&cp).unwrap().len();
    flip_byte(&cp, len - 1);
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    assert_eq!(items(&k), vec![1, 2, 3]);
    assert_eq!(k.snapshot().world().sum, 6);
    assert_eq!(k.current_seq(), Seq(3));
}

#[test]
fn an_exhausted_fallback_chain_refuses_to_open() {
    let dir = tempdir().unwrap();
    // Retain 1: newest is the sole base — no fallback (§6).
    let cfg = cfg_retain(dir.path(), 1);
    let k = Kernel::open(cfg.clone(), genesis()).unwrap();
    for _ in 0..8 {
        commit_blob(&k);
    }
    assert_eq!(k.checkpoint().unwrap(), Seq(8));
    drop(k);
    // Reclamation dropped seg-1, so the earliest surviving segment's firstSeq
    // is no longer Seq(1): genesis is unreachable. Destroy the sole retained
    // checkpoint → the whole fallback chain is exhausted (§6/§7).
    assert!(!seg_file(dir.path(), 1).exists());
    fs::remove_file(ckpt_file(dir.path(), 8)).unwrap();
    let err = Kernel::open(cfg, genesis()).err().unwrap();
    assert!(matches!(err, OpenError::BadCheckpoint), "got {err:?}");
}

#[test]
fn world_at_refuses_a_boundary_below_the_reclamation_floor() {
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_retain(dir.path(), 1), genesis()).unwrap();
    for _ in 0..8 {
        commit_blob(&k);
    }
    assert_eq!(k.checkpoint().unwrap(), Seq(8));
    // Reclamation dropped seg-1: genesis is no longer reachable, and every
    // retained checkpoint sits above these boundaries, so no base at or below
    // them remains derivable (§6/§7). Refusing is the only honest answer —
    // folding a partial journal onto genesis would serve a wrong world.
    assert!(!seg_file(dir.path(), 1).exists());
    for at in [Seq(4), Seq(5)] {
        match k.world_at(at) {
            Err(HistoryError::Reclaimed { floor }) => assert_eq!(floor, Some(Seq(8))),
            other => panic!("expected Reclaimed at {at}, got {other:?}"),
        }
    }
    // The floor the error names IS answerable — from the base embodying it.
    assert_eq!(k.world_at(Seq(8)).unwrap().items.len(), 8);
}

#[test]
fn world_at_answers_the_same_world_under_a_live_appender() {
    // The read path takes no kernel lock and opens the journal files while
    // the appender is writing them and rotation is adding new ones. Every
    // frame at or below the head is durable before that head was installed
    // (§1 durable-before-visible), so a boundary answered under a live writer
    // answers exactly as it does at rest — including reaching back past a
    // rotation for a boundary in an older segment. Nothing reclaims here
    // (Manual), so no transient is licensed: a refusal is as much a finding
    // as a wrong answer.
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    commit(&k, 10);
    commit(&k, 20); // boundary Seq(2), below everything the writer adds
    let writing = AtomicBool::new(true);
    std::thread::scope(|s| {
        let k = &k;
        let writing = &writing;
        s.spawn(move || {
            // Fat records, so the appends straddle rotations.
            for _ in 0..20 {
                commit_blob(k);
            }
            writing.store(false, Ordering::Release);
        });
        let mut reads = 0u32;
        while writing.load(Ordering::Acquire) || reads < 20 {
            assert_eq!(
                world_items(&k.world_at(Seq(2)).expect("a live appender never refuses a read")),
                vec![10, 20],
                "history diverged under a concurrent appender"
            );
            reads += 1;
        }
    });
    assert!(
        segment_count(dir.path()) > 1,
        "the fixture must rotate, so the reads reach back past a rotation"
    );
    assert_eq!(world_items(&k.world_at(Seq(2)).unwrap()), vec![10, 20]);
}

#[test]
fn world_at_ignores_the_suffix_a_racing_append_can_leave() {
    // What a racing append can leave, injected deterministically at rest: a
    // record frame that landed without its marker, then a frame torn
    // mid-write. Neither belongs to a committed transaction; the torn one
    // classifies as an EOF run — the un-acked/torn tail, which the last
    // committed marker precedes — so a bounded read ignores it rather than
    // halting on it (§7), and answers the boundary it was asked for.
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    commit(&k, 10);
    commit(&k, 20);
    let seg = seg_file(dir.path(), 1);
    let spans = frame_spans(&seg);
    assert_eq!(spans.len(), 4); // T1 rec/marker, T2 rec/marker
    let full_len = fs::metadata(&seg).unwrap().len();

    // A record frame that landed while its marker had not: intact, its txn
    // uncommitted, so it is never folded into an answer.
    let buf = fs::read(&seg).unwrap();
    let (offset, len) = (spans[2].0 as usize, spans[2].1 as usize);
    append_bytes(&seg, &buf[offset..offset + len]);
    assert_eq!(world_items(&k.world_at(Seq(2)).unwrap()), vec![10, 20]);

    // A frame torn mid-write: a header claiming a payload that never landed.
    let mut torn = b"SKJ1".to_vec();
    torn.extend_from_slice(&4096u32.to_le_bytes()); // a length…
    torn.extend_from_slice(&0u32.to_le_bytes()); // …a crc…
    torn.extend_from_slice(b"xyz"); // …and the payload stops here
    append_bytes(&seg, &torn);
    assert_eq!(world_items(&k.world_at(Seq(2)).unwrap()), vec![10, 20]);
    assert_eq!(world_items(&k.world_at(Seq(1)).unwrap()), vec![10]);

    // A bounded read writes nothing: the suffix it ignored is still there.
    assert!(fs::metadata(&seg).unwrap().len() > full_len);
}

// ---- checkpoint trigger discipline (§6) ----

#[test]
fn every_n_trigger_fires_on_commit_and_manual_calls_do_not_reset_it() {
    let dir = tempdir().unwrap();
    let mut cfg = cfg_retain(dir.path(), 3);
    cfg.checkpoint = CheckpointPolicy::EveryN(3);
    let k = Kernel::open(cfg, genesis()).unwrap();
    commit(&k, 1);
    commit(&k, 2);
    assert_eq!(checkpoint_count(dir.path()), 0); // threshold not crossed
    assert_eq!(k.checkpoint().unwrap(), Seq(2)); // caller-invoked
    assert!(ckpt_file(dir.path(), 2).exists());
    // A caller-invoked checkpoint() cannot touch the applier-locked cadence
    // counters, so the third commit still crosses EveryN(3) and auto-fires.
    commit(&k, 3);
    assert!(ckpt_file(dir.path(), 3).exists(), "auto-trigger did not fire");
}

#[test]
fn every_n_restarts_its_window_at_the_crossing() {
    // §6: a crossing resets the counters, so the next window starts at that
    // commit — which is what makes `EveryN(n)` "every n" rather than "every
    // commit from the nth on", a degeneration nothing else would report.
    let dir = tempdir().unwrap();
    let mut cfg = cfg_retain(dir.path(), 4);
    cfg.checkpoint = CheckpointPolicy::EveryN(3);
    let k = Kernel::open(cfg, genesis()).unwrap();
    for x in 1..=6u64 {
        commit(&k, x);
    }
    assert!(
        ckpt_file(dir.path(), 3).exists(),
        "the first window did not fire"
    );
    assert!(
        !ckpt_file(dir.path(), 4).exists(),
        "the window did not restart"
    );
    assert!(!ckpt_file(dir.path(), 5).exists());
    assert!(
        ckpt_file(dir.path(), 6).exists(),
        "the second window did not fire"
    );
    assert_eq!(checkpoint_count(dir.path()), 2);
}

#[test]
fn manual_policy_never_auto_checkpoints() {
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap(); // Manual
    for x in 0..5 {
        commit(&k, x);
    }
    assert_eq!(checkpoint_count(dir.path()), 0);
}

#[test]
fn journal_bytes_trigger_counts_bytes_not_commits() {
    // The threshold is one no count of commits can reach, so the trigger
    // fires only on the commit that actually appends that many bytes (§6).
    let dir = tempdir().unwrap();
    let mut cfg = cfg_fsync(dir.path());
    cfg.checkpoint = CheckpointPolicy::JournalBytes(4096);
    let k = Kernel::open(cfg, genesis()).unwrap();
    for x in 1..=5u64 {
        commit(&k, x); // a few dozen journal bytes each
    }
    assert_eq!(checkpoint_count(dir.path()), 0);
    commit_blob(&k); // one commit, far past the threshold
    assert!(ckpt_file(dir.path(), 6).exists(), "the byte trigger did not fire");
}

#[test]
fn a_zero_step_op_neither_journals_nor_advances_the_cadence() {
    // §6: a zero-step op installs nothing, so it never advances a counter or
    // trips the trigger — which is also what keeps `Interval` measuring from
    // real work rather than from read traffic.
    let dir = tempdir().unwrap();
    let mut cfg = cfg_retain(dir.path(), 3);
    cfg.checkpoint = CheckpointPolicy::EveryN(2);
    let k = Kernel::open(cfg, genesis()).unwrap();
    let seg = seg_file(dir.path(), 1);
    for _ in 0..3 {
        assert_eq!(k.transact(&[], |_| Ok::<_, ()>(())).unwrap().1, Seq(0));
    }
    assert_eq!(
        fs::metadata(&seg).unwrap().len(),
        0,
        "a zero-step op journals nothing"
    );
    assert_eq!(checkpoint_count(dir.path()), 0);
    commit(&k, 1); // the FIRST commit: 1 of 2
    assert_eq!(
        checkpoint_count(dir.path()),
        0,
        "the zero-step ops advanced the cadence"
    );
    k.transact(&[], |_| Ok::<_, ()>(())).unwrap();
    commit(&k, 2); // the second commit crosses
    assert!(
        ckpt_file(dir.path(), 2).exists(),
        "the trigger counts commits, not calls"
    );
}

#[test]
fn interval_is_evaluated_on_commit_never_on_a_clock() {
    // Duration::ZERO: the window is always elapsed, so the first COMMIT
    // crosses — while a quiescent kernel fires nothing at all, which is what
    // lets §6 do without a timer thread and its shutdown coordination.
    let dir = tempdir().unwrap();
    let mut cfg = cfg_fsync(dir.path());
    cfg.checkpoint = CheckpointPolicy::Interval(Duration::ZERO);
    let k = Kernel::open(cfg, genesis()).unwrap();
    k.transact(&[], |_| Ok::<_, ()>(())).unwrap(); // a read: nothing new to persist
    assert_eq!(
        checkpoint_count(dir.path()),
        0,
        "a quiescent kernel fired the trigger"
    );
    commit(&k, 1);
    assert!(
        ckpt_file(dir.path(), 1).exists(),
        "the first commit past the window did not fire"
    );
}

#[test]
fn interval_does_not_fire_before_its_window_elapses() {
    let dir = tempdir().unwrap();
    let mut cfg = cfg_fsync(dir.path());
    cfg.checkpoint = CheckpointPolicy::Interval(Duration::from_secs(3600));
    let k = Kernel::open(cfg, genesis()).unwrap();
    for x in 1..=5 {
        commit(&k, x);
    }
    assert_eq!(checkpoint_count(dir.path()), 0);
}

// ---- lifecycle & modes ----

#[test]
fn open_creates_the_journal_directory_it_was_pointed_at() {
    // The `journal_path` caller contract: `open()` creates it if absent, which
    // is what lets a first run of a fresh install start at all.
    let tmp = tempdir().unwrap();
    let dir = tmp.path().join("not-yet");
    assert!(!dir.exists());
    let k = Kernel::open(cfg_fsync(&dir), genesis()).unwrap();
    assert_eq!(commit(&k, 1), Seq(1));
    drop(k);
    // …and what it created is a journal a reopen recovers from.
    let k = Kernel::open(cfg_fsync(&dir), genesis()).unwrap();
    assert_eq!(items(&k), vec![1]);
}

#[test]
fn a_journal_admits_one_live_kernel_at_a_time() {
    let dir = tempdir().unwrap();
    let k1 = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    // Exclusive advisory ownership (Lifecycle): appender OR recoverer, never
    // both — a second open() fails with the acquisition error.
    let err = Kernel::open(cfg_fsync(dir.path()), genesis()).err().unwrap();
    assert!(matches!(err, OpenError::Io(_)), "got {err:?}");
    // …and the exclusion ends with the kernel that held it, so the journal is
    // reopenable rather than owned for the life of the process.
    drop(k1);
    Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
}

#[test]
fn in_memory_mode_starts_from_genesis_and_recovers_nothing() {
    // The mode names no journal — [`Durability::InMemory`] carries no path
    // and no retention count — so "it writes nothing" needs no assertion
    // here; there is nothing to point a stray write at. What remains
    // checkable is the behaviour: genesis directly, an auto-trigger that
    // evaluates over a `checkpoint()` that is a no-op, and no recovery.
    let cfg = KernelConfig {
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::EveryN(1), // trigger evaluates; checkpoint() is a no-op
    };
    let k = Kernel::open(cfg.clone(), genesis()).unwrap();
    // "Directly from genesis": no load, no rebuild_derived (Lifecycle).
    assert_eq!(k.snapshot().world().rebuilds, 0);
    assert_eq!(commit(&k, 1), Seq(1));
    assert_eq!(commit(&k, 2), Seq(2));
    assert_eq!(k.checkpoint().unwrap(), Seq(2)); // no-op returning current_seq (§6)
    k.flush().unwrap();
    drop(k);
    // No journal → no recovery story: a reopen starts from genesis.
    let k = Kernel::open(cfg, genesis()).unwrap();
    assert_eq!(k.current_seq(), Seq(0));
    assert_eq!(items(&k), Vec::<u64>::new());
}

// ---- unwind safety (§3) ----

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

// ---- concurrency (§4/§5/§8) ----

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
