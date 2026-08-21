//! Integration tests for M2's public surface. Each test states a claim the
//! design/interface actually makes (§-references inline); the toy `TestWorld`
//! follows the composition contract's shape — an `im` slice, a non-idempotent
//! `apply` that also maintains a derived hint, and a `#[serde(skip)]` hint
//! reseeded by `rebuild_derived`.

use std::fs::{self, OpenOptions};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use skep_kernel::{
    BurnedSeqPolicy, CheckpointError, CheckpointPolicy, Durability, HistoryError, Kernel,
    KernelConfig, LockKey, OpenError, Seq, Snapshot, Space, Staging, TxnError, WorldState,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
enum TestRec {
    Push(u64),
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

#[derive(Clone, Debug)]
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
#[derive(Clone, Debug)]
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
            TestRec::Push(x) => {
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

impl WorldState for FragileWorld {
    /// `true` breaks the world's serializer; the record itself always encodes.
    type Record = bool;

    fn apply(&self, break_it: &bool) -> Self {
        FragileWorld {
            commits: self.commits + 1,
            broken: self.broken || *break_it,
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

fn cfg_mem() -> KernelConfig {
    KernelConfig {
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::Manual,
    }
}

fn push(k: &Kernel<TestWorld>, x: u64) -> Seq {
    k.transact(&[], |stg| {
        stg.push(TestRec::Push(x));
        Ok::<(), ()>(())
    })
    .unwrap()
    .1
}

fn item_list(w: &TestWorld) -> Vec<u64> {
    w.items.iter().copied().collect()
}

fn items(k: &Kernel<TestWorld>) -> Vec<u64> {
    item_list(k.snapshot().world())
}

// ---- physical-layer helpers (the on-disk format the design fixes: §1/§6) ----

fn seg_file(dir: &Path, first_seq: u64) -> PathBuf {
    dir.join(format!("seg-{first_seq}.wal"))
}

fn ckpt_file(dir: &Path, seq: u64) -> PathBuf {
    dir.join(format!("checkpoint.{seq}"))
}

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
    while pos + 12 <= buf.len() {
        assert_eq!(&buf[pos..pos + 4], b"SKJ1", "expected a clean frame stream");
        let len = u32::from_le_bytes(buf[pos + 4..pos + 8].try_into().unwrap()) as usize;
        spans.push((pos as u64, (12 + len) as u64));
        pos += 12 + len;
    }
    spans
}

fn flip_byte(path: &Path, off: u64) {
    let mut data = fs::read(path).unwrap();
    data[off as usize] ^= 0xFF;
    fs::write(path, data).unwrap();
}

fn truncate_file(path: &Path, len: u64) {
    let f = OpenOptions::new().write(true).open(path).unwrap();
    f.set_len(len).unwrap();
}

fn append_bytes(path: &Path, bytes: &[u8]) {
    use std::io::Write as _;
    let mut f = OpenOptions::new().append(true).open(path).unwrap();
    f.write_all(bytes).unwrap();
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
    let k = Kernel::open(cfg_mem(), genesis()).unwrap();
    // A multi-record composite returns its terminal last_seq — the one
    // observable coordinate (§2); interior seqs are M2-internal.
    let (_, seq) = k
        .transact(&[], |stg| {
            stg.push(TestRec::Push(1));
            stg.push(TestRec::Push(2));
            stg.push(TestRec::Push(3));
            Ok::<(), ()>(())
        })
        .unwrap();
    assert_eq!(seq, Seq(3));
    assert_eq!(k.current_seq(), Seq(3));
    let (_, seq) = k
        .transact(&[], |stg| {
            stg.push(TestRec::Push(4));
            stg.push(TestRec::Push(5));
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
    let k = Kernel::open(cfg_mem(), genesis()).unwrap();
    push(&k, 1);
    let pinned = k.snapshot();
    k.transact(&[], |stg| {
        stg.push(TestRec::Push(2));
        assert_eq!(items(&k), vec![1], "a reader observed Σᵢ, not Σ");
        assert_eq!(k.current_seq(), Seq(1));
        stg.push(TestRec::Push(3));
        assert_eq!(items(&k), vec![1], "a reader observed Σᵢ, not Σ");
        assert_eq!(stg.working().items.len(), 3); // the closure DOES see them
        Ok::<(), ()>(())
    })
    .unwrap();
    // …and then all at once, at the install.
    assert_eq!(items(&k), vec![1, 2, 3]);
    assert_eq!(k.current_seq(), Seq(3));
    assert_eq!(item_list(pinned.world()), vec![1]);
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
    let k = Kernel::open(cfg_mem(), genesis()).unwrap();
    push(&k, 1);
    let unwound = catch_unwind(AssertUnwindSafe(|| {
        let _ = k.transact::<(), ()>(&[], |stg| {
            stg.push(TestRec::Push(2));
            let _ = k.transact::<(), ()>(&[], |inner| {
                inner.push(TestRec::Push(3));
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
    assert_eq!(push(&k, 4), Seq(2));
    assert_eq!(items(&k), vec![1, 4]);
}

#[test]
fn the_reentrancy_refusal_is_scoped_to_the_one_kernel_holding_the_lock() {
    // One thread transacting on two DISTINCT kernels is honest input: the
    // second kernel's applier is free, so its write proceeds. Refusing here
    // would panic on a program that has nothing wrong with it.
    let a = Kernel::open(cfg_mem(), genesis()).unwrap();
    let b = Kernel::open(cfg_mem(), genesis()).unwrap();
    let (_, seq) = a
        .transact(&[], |stg| {
            stg.push(TestRec::Push(1));
            b.transact(&[], |inner| {
                inner.push(TestRec::Push(2));
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
    push(&k, 10);
    k.transact(&[], |stg| {
        stg.push(TestRec::Push(20));
        assert_eq!(k.current_seq(), Seq(1));
        assert_eq!(item_list(k.snapshot().world()), vec![10]);
        // A bounded read derives from the journal, which holds Σ and nothing
        // of the transaction in flight.
        assert_eq!(item_list(&k.world_at(Seq(1)).unwrap()), vec![10]);
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
    let k = Kernel::open(cfg_mem(), genesis()).unwrap();
    // A1 zero-step: Ok with zero staged records → no commit; the returned Seq
    // is the base Committed's seq — the committed index the op evaluated
    // against (A2/V1).
    let (v, seq) = k.transact(&[], |_| Ok::<_, ()>(42)).unwrap();
    assert_eq!((v, seq), (42, Seq(0)));
    push(&k, 9);
    let (v, seq) = k.transact(&[], |_| Ok::<_, ()>(43)).unwrap();
    assert_eq!((v, seq), (43, Seq(1)));
    assert_eq!(k.current_seq(), Seq(1));
}

#[test]
fn rejected_leaves_state_untouched() {
    let k = Kernel::open(cfg_mem(), genesis()).unwrap();
    // f → Err is a clean typed rejection: nothing committed, no dangling
    // state — even when records were pushed before the Err (§3).
    let out: Result<((), Seq), TxnError<&str>> = k.transact(&[], |stg| {
        stg.push(TestRec::Push(99));
        Err("precondition failed")
    });
    assert!(matches!(out, Err(TxnError::Rejected("precondition failed"))));
    assert_eq!(k.current_seq(), Seq(0));
    assert_eq!(items(&k), Vec::<u64>::new());
    // The rejected txn drew no Seq: the next commit is Seq(1).
    assert_eq!(push(&k, 1), Seq(1));
}

#[test]
fn staging_working_folds_pushes_and_base_stays() {
    let k = Kernel::open(cfg_mem(), genesis()).unwrap();
    push(&k, 5);
    k.transact(&[], |stg| {
        assert_eq!(stg.base().items.len(), 1);
        assert_eq!(stg.working().items.len(), 1); // == base before the first push
        // The multi-atom frontier pattern (§3/§4, W2 at M2's granularity):
        // each atom reads the slot the prior atoms left on working(), never
        // the unchanging base().
        for _ in 0..3 {
            let slot = stg.working().items.len() as u64;
            stg.push(TestRec::Push(slot * 100));
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
    let k = Kernel::open(cfg_mem(), genesis()).unwrap();
    push(&k, 10);
    let s = k.snapshot();
    assert_eq!(s.seq(), Seq(1));
    push(&k, 20);
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
    let k = Kernel::open(cfg_mem(), genesis()).unwrap();
    push(&k, 10);
    let s = k.snapshot();
    let also = s.clone();
    push(&k, 20);
    assert_eq!((s.seq(), also.seq()), (Seq(1), Seq(1)));
    assert_eq!(item_list(s.world()), item_list(also.world()));
    // A clone outlives the value it came from, and stays pinned to its state.
    drop(s);
    assert_eq!(also.seq(), Seq(1));
    assert_eq!(item_list(also.world()), vec![10]);
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

    // The rendering names the coordinate, never the world (`TestWorld` is
    // large and is not required to be `Debug` at all).
    let k = Kernel::open(cfg_mem(), genesis()).unwrap();
    push(&k, 10);
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
    let k = Kernel::open(cfg_mem(), genesis()).unwrap();
    let (_, seq) = k
        .transact(&[LockKey::new(Space::Namespace, b"home")], |stg| {
            stg.push(TestRec::Push(1));
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
    push(&k, 1);
    push(&k, 2);
    push(&k, 3);
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
    push(&k, 1);
    push(&k, 2);
    push(&k, 3);
    assert_eq!(k.checkpoint().unwrap(), Seq(3));
    push(&k, 4);
    push(&k, 5);
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
    push(&k, 10);
    push(&k, 20);
    push(&k, 30);
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
    assert_eq!(push(&k, 30), Seq(3));
    drop(k);
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    assert_eq!(items(&k), vec![10, 20, 30]);
    assert_eq!(k.current_seq(), Seq(3));
}

#[test]
fn corruption_in_replayed_range_halts_with_marker_landing_payload() {
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    push(&k, 10);
    push(&k, 20);
    push(&k, 30);
    drop(k);
    let seg = seg_file(dir.path(), 1);
    let spans = frame_spans(&seg);
    // Corrupt T2's record (an INTERIOR committed txn): the resync lands on
    // T2's marker, so at = last_seq + 1 = 3 and inferred max = 2 ∈ (0, 3] —
    // durable committed data the recovered state needs: halt, never drop (§7).
    flip_byte(&seg, spans[2].0 + 12 + 1);
    let err = Kernel::open(cfg_fsync(dir.path()), genesis()).err().unwrap();
    assert!(
        matches!(err, OpenError::Corruption { at: Seq(3) }),
        "got {err:?}"
    );
}

#[test]
fn corruption_below_s_load_is_harmless_including_the_boundary_frame() {
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    push(&k, 10);
    push(&k, 20);
    push(&k, 30);
    assert_eq!(k.checkpoint().unwrap(), Seq(3));
    push(&k, 40);
    drop(k);
    let seg = seg_file(dir.path(), 1);
    let spans = frame_spans(&seg);
    assert_eq!(spans.len(), 8);
    // Corrupt T3's record. The resync lands on T3's marker: inferred max =
    // last_seq = 3 = S_load → HARMLESS (already embodied in the checkpoint),
    // even though the payload coordinate is S_load + 1 — classifying by `at`
    // instead of the inferred max would spuriously halt on exactly this
    // boundary frame (§7).
    flip_byte(&seg, spans[4].0 + 12 + 1);
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    assert_eq!(items(&k), vec![10, 20, 30, 40]);
    assert_eq!(k.snapshot().world().sum, 100);
    assert_eq!(k.current_seq(), Seq(4));
}

#[test]
fn post_commit_rot_of_the_final_txn_demotes_w_silently() {
    // The documented §7 blind spot, asserted as specified: rot in the LAST
    // committed txn's record leaves its marker intact but checksum-failing,
    // W demotes to the prior marker, and the acked txn is silently discarded
    // as tail — no Corruption signal (out of scope for v1).
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    push(&k, 10);
    push(&k, 20);
    push(&k, 30);
    drop(k);
    let seg = seg_file(dir.path(), 1);
    let spans = frame_spans(&seg);
    flip_byte(&seg, spans[4].0 + 12 + 1); // T3's record
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    assert_eq!(items(&k), vec![10, 20]);
    assert_eq!(k.current_seq(), Seq(2));
    assert_eq!(fs::metadata(&seg).unwrap().len(), spans[4].0); // physically discarded
}

#[test]
fn bad_newest_checkpoint_falls_back_to_older_retained_base() {
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap(); // retain 2
    push(&k, 10);
    push(&k, 20);
    assert_eq!(k.checkpoint().unwrap(), Seq(2));
    push(&k, 30);
    push(&k, 40);
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
    push(&k, 10);
    push(&k, 20);
    assert_eq!(k.checkpoint().unwrap(), Seq(2));
    push(&k, 30);
    push(&k, 40);
    assert_eq!(k.checkpoint().unwrap(), Seq(4));
    push(&k, 50);
    let whole = vec![10, 20, 30, 40, 50];
    assert_eq!(item_list(&k.world_at(Seq(5)).unwrap()), whole);

    // Newest base unusable → the older retained one carries the answer.
    let cp4 = ckpt_file(dir.path(), 4);
    let len = fs::metadata(&cp4).unwrap().len();
    flip_byte(&cp4, len - 1);
    assert_eq!(item_list(&k.world_at(Seq(4)).unwrap()), vec![10, 20, 30, 40]);
    assert_eq!(item_list(&k.world_at(Seq(5)).unwrap()), whole);

    // Both bases unusable → genesis carries it, replaying everything.
    let cp2 = ckpt_file(dir.path(), 2);
    let len = fs::metadata(&cp2).unwrap().len();
    flip_byte(&cp2, len - 1);
    assert_eq!(item_list(&k.world_at(Seq(2)).unwrap()), vec![10, 20]);
    assert_eq!(item_list(&k.world_at(Seq(5)).unwrap()), whole);
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
    push(&k, 10);
    push(&k, 20);
    push(&k, 30);
    assert_eq!(k.checkpoint().unwrap(), Seq(3));
    push(&k, 40);
    let seg = seg_file(dir.path(), 1);
    let spans = frame_spans(&seg);
    assert_eq!(spans.len(), 8);
    // Rot in T4's record while the kernel lives — `world_at` reads the
    // journal under the appender, which is where at-rest damage meets it.
    // The resync lands on T4's marker: a run whose inferred max (4) is above
    // the base, so a fold that must cross it could answer from a hole (§7).
    flip_byte(&seg, spans[6].0 + 12 + 1);
    match k.world_at(Seq(4)) {
        Err(HistoryError::Corruption { at }) => assert_eq!(at, Seq(5)),
        other => panic!("expected Corruption, got {other:?}"),
    }
    assert_eq!(item_list(&k.world_at(Seq(3)).unwrap()), vec![10, 20, 30]);
}

#[test]
fn panic_inside_the_commit_region_rolls_back_and_leaves_the_kernel_usable() {
    // §3 unwind guard, pre-barrier arm: an unwind out of the commit region
    // with nothing durably appended is repaired to a TRUE no-op — staging
    // discarded, the high-water rolled back per BurnedSeqPolicy, NO poison —
    // and the coordinates the failed txn drew are reused by the next commit.
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    push(&k, 10);

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
    assert_eq!(push(&k, 20), Seq(2));
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
    push(&k, 10);
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
    assert_eq!(push(&k, 20), Seq(2));
    drop(k);
    // Nothing of the failed txn is on disk to recover.
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    assert_eq!(items(&k), vec![10, 20]);
    assert_eq!(k.current_seq(), Seq(2));
}

#[test]
fn under_tolerate_gap_a_failed_txn_leaves_the_high_water_advanced() {
    // The knob's other setting: the burned Seq is NOT reclaimed, the order
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
    push(&k, 10);
    let out: Result<((), Seq), TxnError<()>> = k.transact(&[], |stg| {
        stg.push(TestRec::FailsToSerialize(RefusesSerialization));
        Ok(())
    });
    assert!(
        matches!(out, Err(TxnError::Unencodable(_))),
        "expected a failed txn, got {out:?}"
    );
    assert_eq!(push(&k, 20), Seq(3), "Seq 2 was burned and must not be reused");
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
        stg.push(true);
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
        stg.push(false);
        Ok(())
    })
    .unwrap();
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
        stg.push(false);
        Ok(())
    })
    .unwrap();
    assert!(ckpt_file(dir.path(), 1).exists(), "the auto-trigger is live");
    let (_, seq) = k
        .transact::<_, ()>(&[], |stg| {
            stg.push(true);
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

fn push_blob(k: &Kernel<TestWorld>) -> Seq {
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
        push_blob(&k);
    }
    assert_eq!(k.checkpoint().unwrap(), Seq(4));
    for _ in 0..4 {
        push_blob(&k);
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
fn retention_keeps_the_newest_n_checkpoints() {
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap(); // retain 2
    for x in 1..=3u64 {
        push(&k, x);
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
fn bad_checkpoint_when_chain_exhausted_and_genesis_unreachable() {
    let dir = tempdir().unwrap();
    // Retain 1: newest is the sole base — no fallback (§6).
    let cfg = cfg_retain(dir.path(), 1);
    let k = Kernel::open(cfg.clone(), genesis()).unwrap();
    for _ in 0..8 {
        push_blob(&k);
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
        push_blob(&k);
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
    push(&k, 10);
    push(&k, 20); // boundary Seq(2), below everything the writer adds
    let writing = AtomicBool::new(true);
    std::thread::scope(|s| {
        let kw = &k;
        let flag = &writing;
        s.spawn(move || {
            // Fat records, so the appends straddle rotations.
            for _ in 0..20 {
                push_blob(kw);
            }
            flag.store(false, Ordering::Release);
        });
        let mut reads = 0u32;
        while writing.load(Ordering::Acquire) || reads < 20 {
            assert_eq!(
                item_list(&k.world_at(Seq(2)).expect("a live appender never refuses a read")),
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
    assert_eq!(item_list(&k.world_at(Seq(2)).unwrap()), vec![10, 20]);
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
    push(&k, 10);
    push(&k, 20);
    let seg = seg_file(dir.path(), 1);
    let spans = frame_spans(&seg);
    assert_eq!(spans.len(), 4); // T1 rec/marker, T2 rec/marker
    let full = fs::metadata(&seg).unwrap().len();

    // A record frame that landed while its marker had not: intact, its txn
    // uncommitted, so it is never folded into an answer.
    let buf = fs::read(&seg).unwrap();
    let (off, len) = (spans[2].0 as usize, spans[2].1 as usize);
    append_bytes(&seg, &buf[off..off + len]);
    assert_eq!(item_list(&k.world_at(Seq(2)).unwrap()), vec![10, 20]);

    // A frame torn mid-write: a header claiming a payload that never landed.
    let mut torn = b"SKJ1".to_vec();
    torn.extend_from_slice(&4096u32.to_le_bytes()); // a length…
    torn.extend_from_slice(&0u32.to_le_bytes()); // …a crc…
    torn.extend_from_slice(b"xyz"); // …and the payload stops here
    append_bytes(&seg, &torn);
    assert_eq!(item_list(&k.world_at(Seq(2)).unwrap()), vec![10, 20]);
    assert_eq!(item_list(&k.world_at(Seq(1)).unwrap()), vec![10]);

    // A bounded read writes nothing: the suffix it ignored is still there.
    assert!(fs::metadata(&seg).unwrap().len() > full);
}

// ---- checkpoint trigger discipline (§6) ----

#[test]
fn every_n_trigger_fires_on_commit_and_manual_calls_do_not_reset_it() {
    let dir = tempdir().unwrap();
    let mut cfg = cfg_retain(dir.path(), 3);
    cfg.checkpoint = CheckpointPolicy::EveryN(3);
    let k = Kernel::open(cfg, genesis()).unwrap();
    push(&k, 1);
    push(&k, 2);
    assert_eq!(checkpoint_count(dir.path()), 0); // threshold not crossed
    assert_eq!(k.checkpoint().unwrap(), Seq(2)); // caller-invoked
    assert!(ckpt_file(dir.path(), 2).exists());
    // A caller-invoked checkpoint() cannot touch the applier-locked cadence
    // counters, so the third commit still crosses EveryN(3) and auto-fires.
    push(&k, 3);
    assert!(ckpt_file(dir.path(), 3).exists(), "auto-trigger did not fire");
}

#[test]
fn manual_policy_never_auto_checkpoints() {
    let dir = tempdir().unwrap();
    let k = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap(); // Manual
    for x in 0..5 {
        push(&k, x);
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
        push(&k, x); // a few dozen journal bytes each
    }
    assert_eq!(checkpoint_count(dir.path()), 0);
    push_blob(&k); // one commit, far past the threshold
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
    push(&k, 1); // the FIRST commit: 1 of 2
    assert_eq!(
        checkpoint_count(dir.path()),
        0,
        "the zero-step ops advanced the cadence"
    );
    k.transact(&[], |_| Ok::<_, ()>(())).unwrap();
    push(&k, 2); // the second commit crosses
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
    push(&k, 1);
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
        push(&k, x);
    }
    assert_eq!(checkpoint_count(dir.path()), 0);
}

// ---- lifecycle & modes ----

#[test]
fn second_open_of_a_live_journal_fails() {
    let dir = tempdir().unwrap();
    let k1 = Kernel::open(cfg_fsync(dir.path()), genesis()).unwrap();
    // Exclusive advisory ownership (Lifecycle): appender OR recoverer, never
    // both — a second open() fails with the acquisition error.
    let err = Kernel::open(cfg_fsync(dir.path()), genesis()).err().unwrap();
    assert!(matches!(err, OpenError::Io(_)), "got {err:?}");
    drop(k1); // the lock dies with the kernel
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
    assert_eq!(push(&k, 1), Seq(1));
    assert_eq!(push(&k, 2), Seq(2));
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
    let k = Kernel::open(cfg_mem(), genesis()).unwrap();
    // A panic in f unwinds before any Seq is drawn: staging is discarded, the
    // panic propagates, the kernel is NOT poisoned, and the order stays
    // gap-free (§3).
    let unwound = catch_unwind(AssertUnwindSafe(|| {
        let _ = k.transact::<(), ()>(&[], |stg| {
            stg.push(TestRec::Push(1));
            panic!("boom");
        });
    }));
    assert!(unwound.is_err());
    assert_eq!(k.current_seq(), Seq(0));
    assert_eq!(items(&k), Vec::<u64>::new());
    assert_eq!(push(&k, 7), Seq(1));
    assert_eq!(items(&k), vec![7]);
}

// ---- concurrency (§4/§5/§8) ----

#[test]
fn concurrent_writers_serialize_into_one_gap_free_order() {
    let k = Kernel::open(cfg_mem(), genesis()).unwrap();
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
                            stg.push(TestRec::Push(t * 1000 + i));
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
