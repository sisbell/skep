//! Shared plumbing for the dirty-crash hazard suite (hardening H3): the
//! mixed-op engine fixture with its capture-and-compare oracle, the file
//! mutilation helpers, wedge-bounded opens, and a deterministic RNG.
//!
//! The oracle discipline: while the store is healthy, capture every
//! committed boundary's `Seq`, the journal byte length once that commit was
//! durable, and the `WorldDump` of `world_at` that boundary — all through
//! the PUBLIC engine surface. After fault + reopen there are exactly three
//! honest outcomes (full recovery, bounded rollback to the last boundary
//! the intact prefix supports, loud refusal); silent divergence and wedged
//! opens are findings, and the judges here panic on them with the full
//! reproduction in the message.
//!
//! Compiled twice by design: as `mod hazard_util` from `hazard.rs`, and as
//! a standalone zero-test target (cargo builds every `tests/*.rs`); the
//! `dead_code` allow covers the second build.

#![allow(dead_code)]

#[path = "common/mutilate.rs"]
mod mutilate;

pub use mutilate::*;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use skep_address::{validate, Address, Nat, Span, Tumbler};
use skep_arrangement::{Caller, VPos, VSpec};
use skep_content::Val;
use skep_engine::dump::WorldDump;
use skep_engine::{Engine, EngineError};
use skep_kernel::{BurnedSeqPolicy, CheckpointPolicy, Durability, KernelConfig, Seq};
use skep_links::SlotArg;
use skep_namespace::{HasM3, PrincipalId, BOOTSTRAP_PRINCIPAL};

pub const USER: PrincipalId = PrincipalId(7);

/// [`USER`] as the stores' ω-gated caller — the owner of everything the
/// fixture creates.
pub const OWNER: Caller = Caller::Principal(USER);

/// `HAZARD_EXHAUSTIVE=1` unlocks the full sweeps; the default grids keep
/// the whole suite inside the ~5 minute budget.
pub fn exhaustive() -> bool {
    std::env::var_os("HAZARD_EXHAUSTIVE").is_some_and(|v| v == "1")
}

// ── address/value constructors (the engine test fixtures' shapes) ──

pub fn t(comps: &[u32]) -> Tumbler {
    Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("test tumblers are nonempty")
}

pub fn a(comps: &[u32]) -> Address {
    validate(t(comps)).unwrap_or_else(|_| panic!("test addresses are T4-valid"))
}

pub fn n(x: u32) -> Nat {
    Nat::from(x)
}

/// The genesis bootstrap node `[1]`.
pub fn node1() -> Address {
    a(&[1])
}

pub fn vp(subspace: u32, ordinal: u32) -> VPos {
    VPos { subspace: n(subspace), ordinal: n(ordinal) }
}

/// An ordinal-level depth-2 V-span `[subspace, ord] w [0, width]`.
pub fn vspan(subspace: u32, ord: u32, width: u32) -> Span {
    Span::new(t(&[subspace, ord]), t(&[0, width]))
        .unwrap_or_else(|_| panic!("well-formed test span"))
}

/// A content V-spec over `doc`'s content subspace.
pub fn vspec(doc: &Address, ord: u32, width: u32) -> VSpec {
    VSpec { source: doc.clone(), span: vspan(1, ord, width) }
}

/// `1.0.1.0.1` — dotted decimal, the tumbler's own canonical rendering.
pub fn tum_str(t: &Tumbler) -> String {
    t.to_string()
}

/// Parse [`tum_str`]'s output back (fixture components fit `u32`).
pub fn parse_addr(s: &str) -> Address {
    let comps: Vec<u32> = s
        .split('.')
        .map(|c| c.parse().unwrap_or_else(|_| panic!("dotted-decimal component in {s:?}")))
        .collect();
    a(&comps)
}

// ── kernel configurations ──

pub fn cfg(dir: &Path, checkpoint: CheckpointPolicy, retain: usize) -> KernelConfig {
    KernelConfig {
        durability: Durability::Fsync {
            journal_path: dir.to_path_buf(),
            retain_checkpoints: retain,
            burned_seq: BurnedSeqPolicy::Rollback,
        },
        checkpoint,
    }
}

pub fn cfg_manual(dir: &Path) -> KernelConfig {
    cfg(dir, CheckpointPolicy::Manual, 2)
}

// ── wedge-bounded opens (a reopen that hangs is a finding) ──

pub const OPEN_TIMEOUT: Duration = Duration::from_secs(30);

/// `Engine::open` under a generous deadline; a hang panics as a wedge
/// finding rather than hanging the suite.
pub fn timed_open_result(dir: &Path, ctx: &str) -> Result<Engine, EngineError> {
    let dir = dir.to_path_buf();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(Engine::open(cfg_manual(&dir)));
    });
    match rx.recv_timeout(OPEN_TIMEOUT) {
        Ok(r) => r,
        Err(_) => panic!("FINDING (wedge): Engine::open hung past {OPEN_TIMEOUT:?} — {ctx}"),
    }
}

/// [`timed_open_result`] where recovery is REQUIRED to succeed: a refusal
/// here is a finding (the fault injected does not license refusing).
pub fn timed_open(dir: &Path, ctx: &str) -> Engine {
    timed_open_result(dir, ctx)
        .unwrap_or_else(|e| panic!("FINDING: open refused where recovery was required — {ctx}: {e}"))
}

// ── file mutilation ──

/// Copy every regular file of `src` into a fresh `dst` (fixture → case).
pub fn copy_dir(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).expect("case dir");
    for entry in fs::read_dir(src).expect("fixture dir lists") {
        let entry = entry.expect("dir entry");
        if entry.file_type().expect("file type").is_file() {
            fs::copy(entry.path(), dst.join(entry.file_name())).expect("copy fixture file");
        }
    }
}

/// Overwrite `[from, from+junk.len())` in place, clamped to the file end.
pub fn overwrite_range(path: &Path, from: u64, junk: &[u8]) {
    let mut data = fs::read(path).expect("read for overwrite");
    let start = from as usize;
    let end = (start + junk.len()).min(data.len());
    data[start..end].copy_from_slice(&junk[..end - start]);
    fs::write(path, data).expect("write overwritten");
}

// ── deterministic junk / RNG (seeds ride in the panic contexts) ──

/// SplitMix64 — deterministic, dependency-free; the seed is the whole
/// reproduction.
pub struct SplitMix64(u64);

impl SplitMix64 {
    pub fn new(seed: u64) -> SplitMix64 {
        SplitMix64(seed ^ 0x9E37_79B9_7F4A_7C15)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    pub fn next_range(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }

    pub fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next_u64() as u8).collect()
    }
}

#[derive(Clone, Copy)]
pub enum Junk {
    Zeros,
    Ones,
    Rand(u64),
}

impl Junk {
    pub fn bytes(self, len: usize) -> Vec<u8> {
        match self {
            Junk::Zeros => vec![0x00; len],
            Junk::Ones => vec![0xFF; len],
            Junk::Rand(seed) => SplitMix64::new(seed).bytes(len),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Junk::Zeros => "zeros",
            Junk::Ones => "ones",
            Junk::Rand(_) => "rand",
        }
    }
}

// ── the mixed-op fixture and its oracle ──

/// One committed boundary of the fixture: its `Seq`, the journal byte
/// length once it was durable (per-commit fsync makes the length final at
/// capture), and the pure-fold oracle dump of the world at it.
pub struct BoundaryOracle {
    pub seq: u64,
    pub journal_len: u64,
    pub dump: WorldDump,
}

/// The mixed-op fixture the ruling names — delegate, create, inserts
/// (multi-record composites), two links, a supersession claim, a nullify, a
/// version, a delete — built through the public engine drivers only.
pub struct Fixture {
    pub dir: PathBuf,
    pub genesis_dump: WorldDump,
    pub boundaries: Vec<BoundaryOracle>,
    pub doc: Address,
    pub full_len: u64,
}

impl Fixture {
    /// Build at `dir`. `ckpt_after` lists 1-based op indices after which
    /// `Kernel::checkpoint()` runs (empty ⇒ pure-journal fixture). Every
    /// oracle dump is captured BEFORE any checkpoint exists at or above it,
    /// so the oracle is always the pure genesis fold — recovered dumps
    /// judged against it prove fold ≡ checkpoint+replay under the fault.
    pub fn build(dir: &Path, ckpt_after: &[usize]) -> Fixture {
        let engine =
            Engine::open(cfg_manual(dir)).expect("fixture open");
        let genesis_dump =
            engine.dump_of(&engine.world_at(Seq(0)).expect("genesis boundary answers"));
        let seg = seg_file(dir, 1);
        let mut boundaries: Vec<BoundaryOracle> = Vec::new();

        let capture = |engine: &Engine, boundaries: &mut Vec<BoundaryOracle>| {
            let seq = engine.kernel().current_seq();
            let journal_len = fs::metadata(&seg).expect("active segment exists").len();
            if let Some(prev) = boundaries.last() {
                assert!(
                    seq.0 > prev.seq && journal_len > prev.journal_len,
                    "fixture commits must advance"
                );
            }
            let world = engine.world_at(seq).expect("live boundary answers");
            boundaries.push(BoundaryOracle {
                seq: seq.0,
                journal_len,
                dump: engine.dump_of(&world),
            });
            if ckpt_after.contains(&boundaries.len()) {
                engine.kernel().checkpoint().expect("fixture checkpoint");
            }
        };

        // 1: delegate an account to USER under the genesis node.
        let prefix = {
            let snap = engine.kernel().snapshot();
            snap.world()
                .m3()
                .next_account_prefix(&node1())
                .expect("the genesis node has a delegable next-form prefix")
        };
        let (acct, _) = engine
            .namespace()
            .delegate(BOOTSTRAP_PRINCIPAL, prefix.tumbler().clone(), USER)
            .expect("delegate");
        capture(&engine, &mut boundaries);

        // 2: create the document.
        let (doc, _) =
            engine.namespace().create_new_document(USER, &acct).expect("create document");
        capture(&engine, &mut boundaries);

        // 3–4: content (multi-value insert = a multi-record composite).
        engine
            .vstream()
            .insert(OWNER, &doc, vp(1, 1), vec![Val::new(vec![b'a']), Val::new(vec![b'b'])])
            .expect("insert ab");
        capture(&engine, &mut boundaries);
        engine
            .vstream()
            .insert(OWNER, &doc, vp(1, 3), vec![Val::new(vec![b'c'])])
            .expect("insert c");
        capture(&engine, &mut boundaries);

        // 5–6: two links (reversed endsets, so no idem dedup collapses them).
        let (link1, _) = engine
            .linkstore()
            .makelink(
                OWNER,
                &doc,
                SlotArg::Resolve(vec![vspec(&doc, 1, 1)]),
                SlotArg::Resolve(vec![vspec(&doc, 2, 1)]),
                SlotArg::Resolve(vec![vspec(&doc, 1, 2)]),
            )
            .expect("makelink link1");
        capture(&engine, &mut boundaries);
        let (link2, _) = engine
            .linkstore()
            .makelink(
                OWNER,
                &doc,
                SlotArg::Resolve(vec![vspec(&doc, 2, 1)]),
                SlotArg::Resolve(vec![vspec(&doc, 1, 1)]),
                SlotArg::Resolve(vec![vspec(&doc, 1, 2)]),
            )
            .expect("makelink link2");
        capture(&engine, &mut boundaries);

        // 7–8: a supersession claim, then a retraction.
        let _ = engine.linkstore().assert_sup(OWNER, &doc, &link1, &link2).expect("assert_sup");
        capture(&engine, &mut boundaries);
        let _ = engine.linkstore().nullify(OWNER, &doc, &link1).expect("nullify");
        capture(&engine, &mut boundaries);

        // 9: a version (the copy-on-write fork).
        let _ = engine.vstream().version(USER, &doc).expect("version");
        capture(&engine, &mut boundaries);

        // 10: a delete.
        engine.vstream().delete(OWNER, &doc, vp(1, 1), n(1)).expect("delete");
        capture(&engine, &mut boundaries);

        drop(engine); // journal lock released; the fixture is now files.

        assert_eq!(boundaries.len(), 10, "the mixed fixture is ten commits");
        let full_len = fs::metadata(&seg).expect("segment").len();
        assert_eq!(
            full_len,
            boundaries.last().expect("boundaries").journal_len,
            "journal length settles at the final commit"
        );
        let segs = fs::read_dir(dir)
            .expect("fixture dir")
            .filter_map(|e| e.expect("entry").file_name().into_string().ok())
            .filter(|n| n.starts_with("seg-") && n.ends_with(".wal"))
            .count();
        assert_eq!(segs, 1, "the mixed fixture stays inside one journal segment");
        Fixture { dir: dir.to_path_buf(), genesis_dump, boundaries, doc, full_len }
    }

    /// The boundary rule: the greatest committed boundary whose bytes lie
    /// wholly inside an intact prefix of length `prefix_len` (0 = genesis).
    pub fn expected_boundary(&self, prefix_len: u64) -> u64 {
        self.boundaries
            .iter()
            .rev()
            .find(|b| b.journal_len <= prefix_len)
            .map(|b| b.seq)
            .unwrap_or(0)
    }

    pub fn dump_for(&self, seq: u64) -> &WorldDump {
        if seq == 0 {
            return &self.genesis_dump;
        }
        &self
            .boundaries
            .iter()
            .find(|b| b.seq == seq)
            .unwrap_or_else(|| panic!("no oracle at boundary {seq}"))
            .dump
    }

    pub fn last_seq(&self) -> u64 {
        self.boundaries.last().expect("boundaries").seq
    }
}

/// How far a recovered case is judged.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Depth {
    /// The recovered head, and the world at it.
    Head,
    /// …and every boundary ≤ head answering `world_at` byte-equal, and the
    /// hints against a from-scratch rebuild.
    Full,
}

/// Open a mutilated copy and hold it to the honest outcomes: head EXACTLY
/// at the boundary the intact prefix supports, world byte-equal to the
/// oracle there. [`Depth::Full`] additionally proves every boundary ≤ head
/// answers `world_at` byte-equal and the hints match a from-scratch rebuild.
/// Returns the recovered head for the caller's outcome tally.
pub fn judge_prefix(
    fixture: &Fixture,
    case_dir: &Path,
    prefix_len: u64,
    depth: Depth,
    ctx: &str,
) -> u64 {
    let engine = timed_open(case_dir, ctx);
    let head = engine.kernel().current_seq().0;
    let expected = fixture.expected_boundary(prefix_len);
    assert_eq!(
        head, expected,
        "FINDING ({ctx}): boundary rule violated — recovered head {head}, the intact prefix \
         supports exactly {expected}"
    );
    let recovered = engine.world_dump();
    assert_eq!(
        &recovered,
        fixture.dump_for(head),
        "FINDING ({ctx}): SILENT DIVERGENCE — recovered world ≠ ground truth at boundary {head}"
    );
    if depth == Depth::Full {
        let at_genesis = engine.dump_of(&engine.world_at(Seq(0)).expect("genesis answers"));
        assert_eq!(
            at_genesis, fixture.genesis_dump,
            "FINDING ({ctx}): genesis boundary diverged"
        );
        for boundary in fixture.boundaries.iter().filter(|b| b.seq <= head) {
            let world = engine.world_at(Seq(boundary.seq)).unwrap_or_else(|e| {
                panic!(
                    "FINDING ({ctx}): boundary {} ≤ head unanswerable: {e}",
                    boundary.seq
                )
            });
            assert_eq!(
                engine.dump_of(&world),
                boundary.dump,
                "FINDING ({ctx}): history at boundary {} diverges from ground truth",
                boundary.seq
            );
        }
        engine
            .check_hints()
            .unwrap_or_else(|e| panic!("FINDING ({ctx}): hint divergence after recovery: {e}"));
    }
    head
}

/// [`judge_prefix`] where FULL recovery is the only acceptable outcome
/// (checkpoint faults: the journal is intact, so no rollback is licensed).
pub fn judge_full_recovery(fixture: &Fixture, case_dir: &Path, ctx: &str) {
    let head = judge_prefix(fixture, case_dir, fixture.full_len, Depth::Full, ctx);
    assert_eq!(head, fixture.last_seq(), "FINDING ({ctx}): full recovery was required");
}
