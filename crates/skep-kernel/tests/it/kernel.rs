//! Integration tests for M2's public surface. Each test states a claim the
//! design/interface actually makes (§-references inline); the toy `TestWorld`
//! follows the composition contract's shape — an `im` slice, a non-idempotent
//! `apply` that also maintains a derived hint, and a `#[serde(skip)]` hint
//! reseeded by `rebuild_derived`.
//!
//! This file holds the worlds, configurations and helpers the claims share;
//! the claims live in its children, one concern each: `writes` (the commit
//! path), `unwinds` (unwind safety), `recovery` (recovery and lifecycle),
//! `history` (bounded replay) and `checkpoints` (checkpoints and their
//! trigger).

mod checkpoints;
mod history;
mod recovery;
mod unwinds;
mod writes;

use std::fs;
use std::path::Path;

use crate::mutilate::FRAME_MAGIC;
use serde::{Deserialize, Serialize};
use skep_kernel::{
    Attestation, BurnedSeqPolicy, CheckpointPolicy, Durability, Kernel, KernelConfig, Reclaim,
    SaltSource, Seq, Step, TxnError, WorldState,
};

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

    fn apply(&self, _at: Seq, r: &TestRec) -> Self {
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

    fn rebuild_derived(self) -> Result<Self, skep_kernel::RebuildError> {
        let sum = self.items.iter().sum();
        Ok(TestWorld {
            sum,
            rebuilds: self.rebuilds + 1,
            items: self.items,
        })
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

    fn apply(&self, _at: Seq, record: &Fragility) -> Self {
        FragileWorld {
            commits: self.commits + 1,
            broken: self.broken || matches!(record, Fragility::Break),
        }
    }
}

/// The seeded salt source this suite's kernels write under (`SKJ4`):
/// deterministic, so a fixture's bytes are the same on every run.
const TEST_SEED: u64 = 0x4B;

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
            reclaim: Reclaim::BelowOldestRetained,
            burned_seq: BurnedSeqPolicy::Rollback,
            cut_damaged_tail: false,
        },
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(TEST_SEED),
    }
}

fn cfg_in_memory() -> KernelConfig {
    KernelConfig {
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(TEST_SEED),
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

/// [`commit`] with `attestation` in the marker's slot (signed ops): one
/// record, the slot filled for that transaction alone, answering its
/// boundary.
fn commit_attested(k: &Kernel<TestWorld>, x: u64, attestation: &Attestation) -> Seq {
    k.transact_attested(&[], Some(attestation), |stg| {
        stg.push(TestRec::Append(x));
        Ok::<(), ()>(())
    })
    .unwrap()
    .1
}

/// One committed transaction staging every record of `xs` — a composite,
/// whose boundary is its LAST record's `Seq` and whose interior seqs are no
/// boundary at all (§3).
fn commit_all(k: &Kernel<TestWorld>, xs: &[u64]) -> Seq {
    k.transact(&[], |stg| {
        for &x in xs {
            stg.push(TestRec::Append(x));
        }
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

/// The panic message of a caught unwind, whichever way the payload was boxed
/// — what the claims that drive a panic through the seam, and the one that
/// drives a nested `transact`, read the unwind by.
fn panic_message(payload: &(dyn std::any::Any + Send)) -> &str {
    payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| payload.downcast_ref::<&str>().copied())
        .unwrap_or("<non-string panic payload>")
}

/// Every step of the write-fault seam, as a claim that arms them all walks.
///
/// The checkpoint write's and the journal's come in the order their write
/// paths reach them, then the open's tail keep.
const EVERY_STEP: [Step; 7] = [
    Step::CheckpointCreate,
    Step::CheckpointSync,
    Step::CheckpointDirSync,
    Step::JournalAppend,
    Step::JournalBarrier,
    Step::JournalRepair,
    Step::TailKeep,
];

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
        assert_eq!(&buf[pos..pos + 4], FRAME_MAGIC, "expected a clean frame stream");
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

// ---- the position the fold is handed (D1: a position, never a clock) ----

/// A world that keeps, for every record, the position the fold was handed
/// beside the record itself — the shape a store keeping a fact's commit
/// position takes, reduced to its pin.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct PositionedWorld {
    log: im::Vector<(u64, u64)>,
}

impl WorldState for PositionedWorld {
    type Record = u64;

    fn apply(&self, at: Seq, record: &u64) -> Self {
        let mut log = self.log.clone();
        log.push_back((at.0, *record));
        PositionedWorld { log }
    }
}

/// The position `apply` is handed is the journal's own coordinate for the
/// transaction that commits the record — its marker's `last_seq`, the one
/// every record of a composite shares and the one its acknowledgment names:
/// on the write path the transaction's first position plus its records
/// less one, folded again at that number once the closure has staged them
/// all, and at every derivation — recovery from genesis, bounded replay, and
/// a load from a checkpoint — the marker's. Under `TolerateGap` a burned range
/// is skipped live exactly as recovery skips it, so the live world and every
/// derived one agree entry for entry.
#[test]
fn the_position_folded_is_the_journals_own_commit_position_live_and_derived() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = KernelConfig {
        durability: Durability::Fsync {
            journal_path: dir.path().to_path_buf(),
            retain_checkpoints: 2,
            reclaim: Reclaim::BelowOldestRetained,
            burned_seq: BurnedSeqPolicy::TolerateGap,
            cut_damaged_tail: false,
        },
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(TEST_SEED),
    };
    let genesis = PositionedWorld { log: im::Vector::new() };
    let k = Kernel::open(cfg.clone(), genesis.clone()).unwrap();
    let push = |k: &Kernel<PositionedWorld>, xs: &[u64]| {
        k.transact(&[], |stg| {
            for &x in xs {
                stg.push(x);
            }
            Ok::<(), ()>(())
        })
        .unwrap()
        .1
    };
    // One record at 1; a composite committing at 4, every record of it
    // folded at 4; a rejected closure draws no position; a burned range
    // under TolerateGap is skipped.
    assert_eq!(push(&k, &[10]), Seq(1));
    assert_eq!(push(&k, &[20, 30, 40]), Seq(4));
    let rejected: Result<((), Seq), TxnError<&str>> = k.transact(&[], |stg| {
        stg.push(99);
        Err("rejected: the staged position is discarded with the staging")
    });
    assert!(matches!(rejected, Err(TxnError::Rejected(_))));
    k.fail_the_next(Step::JournalAppend, std::io::ErrorKind::StorageFull);
    let burned: Result<((), Seq), TxnError<()>> = k.transact(&[], |stg| {
        stg.push(98);
        Ok(())
    });
    assert!(matches!(burned, Err(TxnError::Durability(_))), "got {burned:?}");
    assert_eq!(push(&k, &[50, 60]), Seq(7), "position 5 was burned and is not reused");
    let live = k.snapshot().world().clone();
    assert_eq!(
        live.log.iter().copied().collect::<Vec<_>>(),
        vec![(1, 10), (4, 20), (4, 30), (4, 40), (7, 50), (7, 60)],
        "live, each record was folded at the coordinate of the transaction that committed it"
    );
    assert_eq!(k.world_at(Seq(7)).unwrap(), live, "bounded replay folds the journal's seqs");
    assert_eq!(k.checkpoint().unwrap(), Seq(7));
    assert_eq!(push(&k, &[70]), Seq(8));
    let live = k.snapshot().world().clone();
    drop(k);
    let k = Kernel::open(cfg, genesis).unwrap();
    assert_eq!(k.snapshot().world(), &live, "a load from the checkpoint keeps every position");
    assert_eq!(k.world_at(Seq(8)).unwrap(), live);
    assert_eq!(
        k.snapshot().world().log.back().copied(),
        Some((8, 70)),
        "the record replayed above the checkpoint folds at its own seq"
    );
}
