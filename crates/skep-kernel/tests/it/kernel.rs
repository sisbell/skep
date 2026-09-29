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

use serde::{Deserialize, Serialize};
use skep_kernel::{
    BurnedSeqPolicy, CheckpointPolicy, Durability, Kernel, KernelConfig, SaltSource, Seq,
    WorldState,
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
            burned_seq: BurnedSeqPolicy::Rollback,
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

fn world_items(w: &TestWorld) -> Vec<u64> {
    w.items.iter().copied().collect()
}

fn items(k: &Kernel<TestWorld>) -> Vec<u64> {
    world_items(k.snapshot().world())
}

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
        assert_eq!(&buf[pos..pos + 4], b"SKJ4", "expected a clean frame stream");
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
