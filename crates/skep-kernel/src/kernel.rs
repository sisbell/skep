//! The kernel: single-applier transaction commit (§3), lock-free snapshot
//! reads (§5), on-commit checkpointing (§6), and two-pass recovery (§7).

use std::cell::Cell;
use std::fs::{self, File};
use std::io;
use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwap;
use parking_lot::Mutex;

use crate::checkpoint;
use crate::config::{BurnedSeqPolicy, CheckpointPolicy, Durability, KernelCfg};
use crate::error::{CheckpointError, OpenError, TxnError};
use crate::journal::{self, JournalWriter, RunEnd};
use crate::{LockKey, Seq, WorldState};

/// One installed committed state: the root's identity IS the version
/// coordinate (§Core data model). M2-internal; reached only through
/// [`Snapshot`].
pub(crate) struct Committed<W> {
    pub(crate) seq: Seq,
    pub(crate) world: W,
}

/// A pinned, consistent view of one committed state (MIC clauses 4 & 6;
/// A3/V0). A NEWTYPE over the loaded root `Arc` — not a bare `Arc`, so it can
/// carry the inherent [`seq`]/[`world`] the orphan rule would forbid on a
/// foreign `Arc` (§Public interface). Read EVERY constituent of a multi-read
/// verdict off ONE `Snapshot` — that discharges clause 6 / V2 by
/// construction — and stamp the verdict with THIS snapshot's [`seq`] (V1),
/// never a later [`Kernel::current_seq`].
///
/// [`seq`]: Snapshot::seq
/// [`world`]: Snapshot::world
pub struct Snapshot<W: WorldState>(Arc<Committed<W>>);

impl<W: WorldState> Snapshot<W> {
    /// The committed index this view is OF (V1 retrospective); by value
    /// (`Seq: Copy`).
    pub fn seq(&self) -> Seq {
        self.0.seq
    }

    /// Read your store's slice off this (through your `HasX` accessor trait,
    /// per the composition contract — never concrete-field access).
    pub fn world(&self) -> &W {
        &self.0.world
    }
}

/// The in-flight state of one transaction's closure (§3): `base` = Σ (the
/// installed root at txn start), `working` = Σᵢ (base folded with the records
/// staged so far — ASN-0047's "observable intermediate states", visible ONLY
/// to the executing closure, never to external readers), `records` = the
/// staged authoritative deltas.
pub struct Staging<W: WorldState> {
    base: Arc<Committed<W>>,
    working: W,
    records: Vec<W::Record>,
}

impl<W: WorldState> Staging<W> {
    fn new(base: Arc<Committed<W>>) -> Self {
        let working = base.world.clone();
        Staging {
            base,
            working,
            records: Vec::new(),
        }
    }

    /// Σ — the installed root at txn start. (This `&W` carries no `seq()`;
    /// the base *index* is `transact`'s to report — §Public interface.)
    pub fn base(&self) -> &W {
        &self.base.world
    }

    /// Σᵢ — base folded with the records pushed so far. Frontier/allocation
    /// math MUST read here (via the store's `HasX` accessor), so each atom of
    /// a multi-atom run mints at the slot the prior atoms left — reading the
    /// unchanging `base()` would recompute one address m times and collide
    /// (§3/§4, W2).
    pub fn working(&self) -> &W {
        &self.working
    }

    /// Fold `r` into `working` and append it to the txn's records. Stage your
    /// store's OWN record type lifted via `.into()` — never the central
    /// `Record` (composition contract).
    pub fn push(&mut self, r: W::Record) {
        self.working = self.working.apply(&r);
        self.records.push(r);
    }
}

/// State owned by the single applier lock (§3/§8): the `Seq` high-water, the
/// journal appender, and the §6 on-commit checkpoint-trigger counters
/// (advanced, read, and reset ONLY under the applier lock — `checkpoint()`
/// never touches them).
struct ApplierState {
    seq_hi: u64,
    journal: Option<JournalWriter>,
    commits_since: u64,
    bytes_since: u64,
    last_checkpoint: Instant,
}

/// The transactional kernel over an engine-supplied `W` (§Public interface).
/// v1 concurrency realization: the single applier (§8) — every write runs to
/// completion under one global lock, subsuming the `LockKey` seam; the
/// `transact`/`snapshot` signatures are invariant across realizations.
pub struct Kernel<W: WorldState> {
    root: ArcSwap<Committed<W>>,
    applier: Mutex<ApplierState>,
    /// §6: serializes `checkpoint()` against itself (caller calls and the
    /// on-commit auto-trigger); distinct from the applier lock so persisting
    /// and reclaiming never block writers.
    ckpt: Mutex<()>,
    poisoned: AtomicBool,
    cfg: KernelCfg,
    /// The `open()`-held exclusive advisory lock (Lifecycle); `None` under
    /// `Durability::InMemory`. Held for the kernel's lifetime.
    _journal_lock: Option<File>,
}

impl<W: WorldState> Kernel<W> {
    /// Recover or init (Lifecycle, §7).
    ///
    /// Under [`Durability::Fsync`]: take the exclusive advisory journal lock
    /// (a second `open()` of the same journal fails with [`OpenError::Io`]);
    /// load the latest valid RETAINED checkpoint @`S_load` — on a bad one fall
    /// back to the next-older retained checkpoint, then to genesis while still
    /// reachable (earliest surviving segment's `firstSeq` still `Seq(1)`;
    /// chain exhausted ⟹ [`OpenError::BadCheckpoint`]) — run
    /// [`WorldState::rebuild_derived`], scan the journal (Pass 1: derive `W`
    /// = the last committed marker's `last_seq`, classify corrupt runs by
    /// inferred `Seq` max — in `(S_load, W]` ⟹ [`OpenError::Corruption`],
    /// halt, never drop), durably TRUNCATE the un-acked/torn tail beyond `W`
    /// before any write is served (skipped on the halt paths; a truncation
    /// failure fails `open()` with `Io` — idempotent, retried next `open()`),
    /// then replay exactly `S_load < Seq ≤ W` through [`WorldState::apply`]
    /// in `Seq` order (Pass 2 — no contiguity required: `TolerateGap` burns
    /// fold harmlessly). A committed-but-unacked tail marker is REPLAYED — the
    /// lost-ack case is the client's (ASN-0134 SAFE(b)(iii)), not a phantom.
    ///
    /// Under [`Durability::InMemory`]: ignores `journal_path`, runs no
    /// recovery, and initializes the root directly from `genesis`
    /// (`S_load = 0`).
    ///
    /// CALLER CONTRACT — `genesis` (= Σ₀) MUST be byte-identical on every
    /// `open()` of a given journal: recovery folds journaled DELTAS onto it,
    /// never onto a journaled root; a drifting `genesis` silently
    /// mis-recovers. M2 cannot check this (ASN-0047's fixed Σ₀ satisfies it
    /// by construction).
    pub fn open(cfg: KernelCfg, genesis: W) -> Result<Self, OpenError> {
        match cfg.durability {
            // "Directly from genesis" (Lifecycle): no journal, no recovery,
            // no rebuild_derived — the caller's live value is the root.
            Durability::InMemory => Ok(Self::assemble(cfg, Seq(0), genesis, None, None)),
            Durability::Fsync { .. } => Self::open_durable(cfg, genesis),
        }
    }

    fn open_durable(cfg: KernelCfg, genesis: W) -> Result<Self, OpenError> {
        if cfg.retain_checkpoints == 0 {
            // The interface requires N ≥ 1 (§Public interface); surface the
            // violation rather than silently clamping.
            return Err(OpenError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "retain_checkpoints must be >= 1",
            )));
        }
        fs::create_dir_all(&cfg.journal_path)?;
        let lock = journal::acquire_dir_lock(&cfg.journal_path)?;
        let segs = journal::list_segments(&cfg.journal_path)?;
        let cps = checkpoint::list(&cfg.journal_path)?;

        // Base selection: newest valid retained checkpoint, else older, else
        // genesis while reachable (§6/§7).
        let mut base: Option<(u64, W)> = None;
        for cp in cps.iter().rev() {
            if let Some(w) = checkpoint::load::<W>(&cp.path, cp.seq) {
                base = Some((cp.seq, w));
                break;
            }
        }
        let (s_load, world) = match base {
            Some(b) => b,
            None => {
                let genesis_reachable = segs.is_empty() || segs[0].first_seq == 1;
                if !genesis_reachable {
                    return Err(OpenError::BadCheckpoint);
                }
                (0, genesis)
            }
        };
        // Seed skip-serialized hints from the loaded base, BEFORE replay;
        // apply then keeps them current across the replayed tail (§7).
        let world = world.rebuild_derived();

        // Pass 1: find W and classify (§7).
        let scan = journal::scan(&segs, s_load)?;
        for run in &scan.runs {
            if let RunEnd::Landed { inferred_max, at } = *run {
                if inferred_max > s_load && inferred_max <= scan.w {
                    return Err(OpenError::Corruption { at: Seq(at) });
                }
            }
            // Landed beyond W and Eof runs are the un-acked/torn tail —
            // physically discarded below; runs at or below S_load are
            // harmless (already embodied in the loaded base) — skipped by
            // the Pass-2 filter (§7).
        }

        // Tail truncation — before any write is served (§7).
        journal::truncate_tail(&cfg.journal_path, &segs, &scan)?;

        // Pass 2: fold exactly (S_load, W], in Seq order (§6/§7 — apply is
        // NOT idempotent; each committed record folds exactly once).
        let mut recs = scan.committed_records;
        recs.sort_by_key(|(seq, _)| *seq);
        let mut world = world;
        for (seq, bytes) in recs {
            if seq <= s_load || seq > scan.w {
                continue;
            }
            // A committed, CRC-intact record that fails to decode as
            // W::Record is corrupt committed data the recovered state needs:
            // halt, never drop (§7). `at` here is the record's own readable
            // seq (unlike a CRC run, whose seqs are unreadable).
            let rec: W::Record =
                bincode::deserialize(&bytes).map_err(|_| OpenError::Corruption { at: Seq(seq) })?;
            world = world.apply(&rec);
        }

        let writer = JournalWriter::open_active(&cfg.journal_path, scan.w + 1)?;
        Ok(Self::assemble(cfg, Seq(scan.w), world, Some(writer), Some(lock)))
    }

    fn assemble(
        cfg: KernelCfg,
        seq: Seq,
        world: W,
        journal: Option<JournalWriter>,
        lock: Option<File>,
    ) -> Self {
        Kernel {
            root: ArcSwap::from_pointee(Committed { seq, world }),
            applier: Mutex::new(ApplierState {
                // The single Seq high-water is the WHOLE of the recovered
                // sequencer state: Txn is a transaction's first Seq, so the
                // next session's first Txn = W + 1 needs no second counter
                // (§1/§7).
                seq_hi: seq.0,
                journal,
                commits_since: 0,
                bytes_since: 0,
                last_checkpoint: Instant::now(),
            }),
            ckpt: Mutex::new(()),
            poisoned: AtomicBool::new(false),
            cfg,
            _journal_lock: lock,
        }
    }

    /// Hold `keys` for the txn's duration, run `f` against a consistent base
    /// state, and — iff `f` returns `Ok` with ≥1 staged record — commit them
    /// atomically & durably under one commit marker, INSTALL the root, then
    /// return (A7 commit-before-acknowledge; MIC clauses 1/2/3/5/7). Returns
    /// `(T, Seq)`: the closure's value and the committed `last_seq` — a
    /// write's exact V1 retrospective coordinate (for a multi-record
    /// composite the interior `Seq`s are M2-internal; the terminal `last_seq`
    /// is the one observable boundary — §2).
    ///
    /// `f` → `Err(e)`: clean typed rejection ([`TxnError::Rejected`]),
    /// nothing committed, no dangling state. `f` → `Ok` with zero records:
    /// zero-step op (A1: read-only / idem-hit / nullify-hit), no commit; the
    /// returned `Seq` is the base `Committed`'s seq — the committed index the
    /// op evaluated against (A2/V1; under per-commit `Fsync` that base is
    /// durable, so a zero-step op never waits).
    ///
    /// NON-REENTRANT: `f` MUST NOT call `transact` (or any kernel write path)
    /// — the applier lock is held, so a nested write DEADLOCKS. A composite
    /// composes neighbors' PURE math inside ONE closure (§3; seam contract 3).
    ///
    /// Under the v1 single applier the global lock subsumes `keys` (§4):
    /// callers still pass the keys they would need under the deferred per-key
    /// realization, so it slots in later without changing any call shape.
    ///
    /// A panic unwinding out of `f` or the commit path is handled by the §3
    /// unwind guard (pre-barrier: discard staging, durably truncate any
    /// partial append, roll the high-water back per [`BurnedSeqPolicy`] —
    /// poisoning if the truncation cannot complete durably; post-barrier
    /// pre-install: poison — the committed-but-uninstalled txn replays at the
    /// next `open()` as a lost-ack op); the panic propagates to the caller.
    pub fn transact<T, E>(
        &self,
        keys: &[LockKey],
        f: impl FnOnce(&mut Staging<W>) -> Result<T, E>,
    ) -> Result<(T, Seq), TxnError<E>> {
        let _ = keys; // §4: subsumed by the single applier's global lock in v1.
        let mut applier = self.applier.lock();
        if self.poisoned.load(Ordering::Acquire) {
            return Err(TxnError::Poisoned);
        }
        let base = self.root.load_full();
        let mut stg = Staging::new(Arc::clone(&base));

        // Closure phase. Nothing is allocated or appended yet, so an unwind
        // here needs no repair: staging is discarded, the lock releases on
        // unwind, no Seq was drawn (§3).
        let v = match catch_unwind(AssertUnwindSafe(|| f(&mut stg))) {
            Err(payload) => resume_unwind(payload),
            Ok(Err(e)) => return Err(TxnError::Rejected(e)),
            Ok(Ok(v)) => v,
        };
        if stg.records.is_empty() {
            return Ok((v, base.seq)); // zero-step (A1); V1 = the base index read.
        }
        let Staging {
            base: _,
            working,
            records,
        } = stg;

        // Linearization (§2): Seqs assigned under the applier lock, so the
        // order is gap-free (under Rollback) and a composite's records are
        // Seq-contiguous.
        let st = &mut *applier;
        let n = records.len() as u64;
        let first = st.seq_hi + 1;
        let last = st.seq_hi + n;
        st.seq_hi = last;
        let committed = Committed {
            seq: Seq(last),
            world: working,
        };
        let rollback = match self.cfg.durability {
            Durability::Fsync {
                burned_seq: BurnedSeqPolicy::Rollback,
            }
            | Durability::InMemory => true,
            Durability::Fsync {
                burned_seq: BurnedSeqPolicy::TolerateGap,
            } => false,
        };

        #[derive(Clone, Copy)]
        enum Phase {
            PreAppend,
            Appended { pre: u64 },
            Barriered,
        }
        enum CommitFail {
            /// Nothing of this txn reached the file (serialize / rotation
            /// failure): no truncation needed.
            PreAppend(io::Error),
            /// The append or the barrier failed with frames possibly on disk.
            Append(io::Error),
        }
        let phase = Cell::new(Phase::PreAppend);

        // The commit region (§1: append records → marker → ONE fsync). Run
        // under catch_unwind so the §3 guard can repair a mid-commit unwind;
        // it fires only on unwind — the error returns below run the §1
        // discipline themselves.
        let commit_out: std::thread::Result<Result<u64, CommitFail>> = {
            let st_in = &mut *st;
            let phase = &phase;
            let records = &records;
            catch_unwind(AssertUnwindSafe(move || {
                let Some(j) = st_in.journal.as_mut() else {
                    // InMemory (§1): no journal legs; Seq allocation and the
                    // atomic install still run.
                    phase.set(Phase::Barriered);
                    return Ok(0u64);
                };
                let mut rec_bytes: Vec<Vec<u8>> = Vec::with_capacity(records.len());
                for r in records.iter() {
                    rec_bytes.push(bincode::serialize(r).map_err(|e| {
                        CommitFail::PreAppend(io::Error::new(io::ErrorKind::InvalidData, e))
                    })?);
                }
                let buf = journal::encode_txn(first, &rec_bytes).map_err(CommitFail::PreAppend)?;
                j.maybe_rotate(first).map_err(CommitFail::PreAppend)?;
                phase.set(Phase::Appended { pre: j.len() });
                j.append(&buf).map_err(CommitFail::Append)?;
                j.barrier().map_err(CommitFail::Append)?;
                phase.set(Phase::Barriered);
                Ok(buf.len() as u64)
            }))
        };
        match commit_out {
            // §3 unwind guard: repair, then let the panic propagate.
            Err(payload) => {
                match phase.get() {
                    Phase::PreAppend => {
                        if rollback {
                            st.seq_hi = base.seq.0; // absolute set — idempotent (§3)
                        }
                    }
                    Phase::Appended { pre } => {
                        let truncated = st
                            .journal
                            .as_mut()
                            .map(|j| j.truncate_to(pre).is_ok())
                            .unwrap_or(false);
                        if truncated {
                            if rollback {
                                st.seq_hi = base.seq.0;
                            }
                        } else {
                            // A surviving un-acked marker would let a
                            // successor collide on recovery: poison; the
                            // high-water is NOT rolled back over the
                            // surviving frames (§1/§3).
                            self.poisoned.store(true, Ordering::Release);
                        }
                    }
                    Phase::Barriered => {
                        if st.journal.is_some() {
                            // Durably committed but uninstalled: continuing
                            // would fold later txns off a root missing a
                            // committed effect. Poison; it replays at the
                            // next open() as a lost-ack op (§3, SAFE(b)(iii)).
                            self.poisoned.store(true, Ordering::Release);
                        } else if rollback {
                            // InMemory has no barrier: pre-install unwind.
                            st.seq_hi = base.seq.0;
                        }
                    }
                }
                drop(applier);
                resume_unwind(payload)
            }
            // §1/§3: a non-unwind failure before the barrier completed.
            Ok(Err(CommitFail::PreAppend(e))) => {
                if rollback {
                    st.seq_hi = base.seq.0;
                }
                Err(TxnError::Durability(e))
            }
            Ok(Err(CommitFail::Append(e))) => {
                let pre = match phase.get() {
                    Phase::Appended { pre } => pre,
                    _ => unreachable!("append failure implies the appended phase"),
                };
                let truncated = st
                    .journal
                    .as_mut()
                    .map(|j| j.truncate_to(pre).is_ok())
                    .unwrap_or(false);
                if truncated {
                    if rollback {
                        st.seq_hi = base.seq.0;
                    }
                    Err(TxnError::Durability(e)) // TRUE no-op: caller may re-invoke (§1)
                } else {
                    self.poisoned.store(true, Ordering::Release);
                    Err(TxnError::Poisoned)
                }
            }
            Ok(Ok(bytes)) => {
                // Atomic install AFTER durability (A0/A4; durable-before-
                // visible §1): external readers see none-or-all.
                self.root.store(Arc::new(committed));
                // §6 on-commit trigger: increment, test, and reset all under
                // the applier lock; checkpoint() never touches these.
                st.commits_since += 1;
                st.bytes_since += bytes;
                let crossed = match self.cfg.checkpoint {
                    CheckpointPolicy::EveryN(every) => st.commits_since >= every,
                    CheckpointPolicy::JournalBytes(b) => st.bytes_since >= b,
                    CheckpointPolicy::Interval(d) => st.last_checkpoint.elapsed() >= d,
                    CheckpointPolicy::Manual => false,
                };
                if crossed {
                    st.commits_since = 0;
                    st.bytes_since = 0;
                    st.last_checkpoint = Instant::now();
                }
                drop(applier);
                if crossed {
                    // §3/§6: the auto-triggered checkpoint's error is
                    // logged-and-dropped, never failing the already-committed
                    // txn. v1 has no logging seam (the design's dependency
                    // list), so "dropped" is the whole of it; safe by §6's
                    // crash argument (at most an ignored .tmp and an
                    // unreclaimed journal).
                    let _ = self.checkpoint();
                }
                Ok((v, Seq(last))) // commit-before-acknowledge (A7, MIC-3)
            }
        }
    }

    /// One committed state, pinned (MIC clauses 4 & 6; A3/V0/V2). One
    /// lock-free `ArcSwap` load. INFALLIBLE, and continues to serve the last
    /// in-memory root even on a POISONED kernel: the poison paths (§1/§3)
    /// leave that root a consistent committed state, so reads stay sound;
    /// only write/checkpoint paths fail with `Poisoned`.
    pub fn snapshot(&self) -> Snapshot<W> {
        Snapshot(self.root.load_full())
    }

    /// The currently installed root's seq — equal AT THE INSTANT OF CALL to a
    /// `snapshot()` taken then, but NOT a substitute for it across calls, and
    /// NOT the stamp for a snapshot-computed verdict (a write may land
    /// between; stamp with the one `Snapshot`'s [`Snapshot::seq`] instead —
    /// V1, §5). Install is serialized, so this never regresses. Infallible,
    /// including when poisoned.
    pub fn current_seq(&self) -> Seq {
        self.root.load().seq
    }

    /// Persist a checkpoint embodying all records with `Seq ≤ s`, keep the
    /// most recent `retain_checkpoints`, and reclaim whole *closed* journal
    /// segments lying wholly BELOW the OLDEST retained checkpoint
    /// (segment-granular space reclamation, never a correctness mechanism —
    /// recovery's `Seq > S_load` filter handles straddler leftovers; §6).
    /// Non-blocking to writers (grabs a lock-free `Snapshot`, never the
    /// applier lock) and serialized against itself by the dedicated
    /// checkpoint mutex. Cadence counters live in `transact`'s applier-locked
    /// state — a caller-invoked `checkpoint()` does NOT reset them (§6).
    /// Returns the checkpointed seq, or [`CheckpointError::Poisoned`] if a
    /// prior failure halted the kernel. Under [`Durability::InMemory`] it is
    /// a no-op returning [`current_seq`].
    ///
    /// [`current_seq`]: Kernel::current_seq
    pub fn checkpoint(&self) -> Result<Seq, CheckpointError> {
        if self.poisoned.load(Ordering::Acquire) {
            return Err(CheckpointError::Poisoned);
        }
        if matches!(self.cfg.durability, Durability::InMemory) {
            return Ok(self.current_seq()); // nothing to persist or reclaim (§6)
        }
        let _serial = self.ckpt.lock();
        let snap = self.root.load_full();
        let s = snap.seq;
        // Authoritative state serialized; hints may #[serde(skip)] and be
        // reseeded by rebuild_derived at load (§6/§7).
        let body = bincode::serialize(&snap.world).map_err(|_| CheckpointError::Serialize)?;
        checkpoint::write(&self.cfg.journal_path, s.0, &body)?;
        // Retention: newest N kept; S_old = the oldest retained — the
        // journal-reclamation floor and the BadCheckpoint fallback base (§6).
        let mut cps = checkpoint::list(&self.cfg.journal_path)?;
        while cps.len() > self.cfg.retain_checkpoints {
            let victim = cps.remove(0);
            fs::remove_file(&victim.path)?;
        }
        let s_old = cps.first().map(|c| c.seq).unwrap_or(s.0);
        // Reclaim closed segments whose inferred lastSeq (successor's
        // firstSeq − 1 — an upper bound, so only ever conservative) ≤ S_old.
        // Qualifying segments form a prefix; the active (last) segment is
        // never touched (§1/§6).
        let segs = journal::list_segments(&self.cfg.journal_path)?;
        for i in 0..segs.len().saturating_sub(1) {
            if segs[i + 1].first_seq.saturating_sub(1) <= s_old {
                fs::remove_file(&segs[i].path)?;
            } else {
                break;
            }
        }
        journal::fsync_dir(&self.cfg.journal_path)?;
        Ok(s)
    }

    /// Shutdown/checkpoint hook. Under per-commit `Fsync` every commit
    /// already fsyncs its records+marker barrier, so there is nothing pending
    /// and this is a no-op returning `Ok(())`; under the in-memory mode it is
    /// likewise a no-op, and on a POISONED kernel it is a no-op returning
    /// `Ok`. Retained as the slot-in point for the deferred group-commit
    /// (`FsyncBatch`) durability mode, where it would flush the pending batch
    /// and advance the `Clean` watermark (Open build decisions) — the API is
    /// invariant across durability modes.
    pub fn flush(&self) -> Result<(), io::Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::{encode_txn, JournalWriter};

    // A minimal world for kernel-internal tests. WorldState is a local trait,
    // so the impl on a foreign type is fine inside the crate's test cfg.
    impl WorldState for Vec<u64> {
        type Record = u64;
        fn apply(&self, r: &u64) -> Self {
            let mut v = self.clone();
            v.push(*r); // non-idempotent, as the design's replay argument assumes
            v
        }
    }

    fn cfg(dir: &std::path::Path, burned_seq: BurnedSeqPolicy) -> KernelCfg {
        KernelCfg {
            journal_path: dir.to_path_buf(),
            durability: Durability::Fsync { burned_seq },
            checkpoint: CheckpointPolicy::Manual,
            retain_checkpoints: 1,
        }
    }

    #[test]
    fn gapped_journal_replays_without_contiguity_check() {
        // §7: under TolerateGap the replayed range may contain burned-Seq
        // gaps; each present record folds exactly once, in order — a missing
        // Seq is never corruption.
        let dir = tempfile::tempdir().unwrap();
        {
            let mut w = JournalWriter::open_active(dir.path(), 1).unwrap();
            let r = |x: u64| bincode::serialize(&x).unwrap();
            w.append(&encode_txn(1, &[r(10)]).unwrap()).unwrap();
            w.append(&encode_txn(5, &[r(50), r(60)]).unwrap()).unwrap(); // burned 2..=4
            w.barrier().unwrap();
        }
        let k = Kernel::<Vec<u64>>::open(
            cfg(dir.path(), BurnedSeqPolicy::TolerateGap),
            Vec::new(),
        )
        .unwrap();
        assert_eq!(k.current_seq(), Seq(6));
        assert_eq!(k.snapshot().world().as_slice(), &[10, 50, 60]);
    }

    #[test]
    fn retain_checkpoints_zero_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = cfg(dir.path(), BurnedSeqPolicy::Rollback);
        c.retain_checkpoints = 0;
        let err = Kernel::<Vec<u64>>::open(c, Vec::new()).err().unwrap();
        assert!(matches!(err, OpenError::Io(_)));
    }
}
