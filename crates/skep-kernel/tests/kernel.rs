//! Integration tests for M2's public surface. Each test states a claim the
//! design/interface actually makes (§-references inline); the toy `TestWorld`
//! follows the composition contract's shape — an `im` slice, a non-idempotent
//! `apply` that also maintains a derived hint, and a `#[serde(skip)]` hint
//! reseeded by `rebuild_derived`.

use std::fs::{self, OpenOptions};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use skep_kernel::{
    BurnedSeqPolicy, CheckpointPolicy, Durability, HistoryError, Kernel, KernelCfg, LockKey,
    OpenError, Seq, Snapshot, Space, Staging, TxnError, WorldState,
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
    PanicOnSerialize(Unserializable),
}

#[derive(Clone, Debug)]
struct Unserializable;

impl Serialize for Unserializable {
    fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
        panic!("record serialization panicked inside the commit region");
    }
}

impl<'de> Deserialize<'de> for Unserializable {
    fn deserialize<D: serde::Deserializer<'de>>(_: D) -> Result<Self, D::Error> {
        // Nothing that panics on the way out ever reaches the journal.
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
            // Folds like any other record; the panic waits for the journal.
            TestRec::PanicOnSerialize(_) => {
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

fn cfg_fsync(dir: &Path) -> KernelCfg {
    cfg_retain(dir, 2)
}

/// A journal-backed configuration keeping `retain` checkpoint bases — the
/// knob rides on the journal, so a test that varies it names the journal.
fn cfg_retain(dir: &Path, retain: usize) -> KernelCfg {
    KernelCfg {
        durability: Durability::Fsync {
            journal_path: dir.to_path_buf(),
            retain_checkpoints: retain,
            burned_seq: BurnedSeqPolicy::Rollback,
        },
        checkpoint: CheckpointPolicy::Manual,
    }
}

fn cfg_mem() -> KernelCfg {
    KernelCfg {
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
fn lock_key_space_and_seq_basics() {
    // Within one space, LockKey order is bytewise over the caller's own bytes
    // (never tumbler order) (§4).
    let ns = |b: &[u8]| LockKey::new(Space::Namespace, b);
    assert!(ns(&[1, 2]) < ns(&[2, 1]));
    assert!(ns(&[1]) < ns(&[1, 0]));
    // The space tag leads, so keys in distinct spaces cannot interleave —
    // which is what the ordering owes the seam, not merely that it is total.
    assert!(ns(&[0xFF]) < LockKey::new(Space::CoverageClass, &[0x00]));
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
            stg.push(TestRec::PanicOnSerialize(Unserializable));
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
fn journal_bytes_trigger_fires_once_crossed() {
    let dir = tempdir().unwrap();
    let mut cfg = cfg_fsync(dir.path());
    cfg.checkpoint = CheckpointPolicy::JournalBytes(1);
    let k = Kernel::open(cfg, genesis()).unwrap();
    push(&k, 1); // any commit appends ≥ 1 byte
    assert!(ckpt_file(dir.path(), 1).exists());
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
fn in_memory_mode_touches_no_disk_and_recovers_nothing() {
    // The mode names no journal — [`Durability::InMemory`] carries no path
    // and no retention count — so "it writes nothing" needs no assertion
    // here; there is nothing to point a stray write at. What remains
    // checkable is the behaviour: genesis directly, an auto-trigger that
    // evaluates over a `checkpoint()` that is a no-op, and no recovery.
    let cfg = KernelCfg {
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
