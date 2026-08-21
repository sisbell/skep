//! The kernel: single-applier transaction commit (§3), lock-free snapshot
//! reads (§5), on-commit checkpointing (§6), and two-pass recovery (§7).

use std::fmt;
use std::fs::{self, File};
use std::io;
use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwap;
use parking_lot::Mutex;

use crate::checkpoint;
use crate::config::{CheckpointPolicy, Durability, KernelConfig};
use crate::error::{CheckpointError, HistoryError, OpenError, TxnError};
use crate::journal::{self, CommitFail, Journal, JournalWriter, UnwindRepair};
use crate::replay;
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

impl<W: WorldState> Clone for Snapshot<W> {
    /// A refcount bump on the pinned root — never a copy of `W`. Clone freely
    /// to read ONE committed state from several places; that is what keeps a
    /// multi-read verdict on one snapshot (MIC clause 6 / V2) where taking a
    /// second [`Kernel::snapshot`] would silently read a later state.
    fn clone(&self) -> Self {
        Snapshot(Arc::clone(&self.0))
    }
}

impl<W: WorldState> fmt::Debug for Snapshot<W> {
    /// The coordinate, not the world: `W` is the whole engine state and is
    /// not required to be `Debug` (§Public interface).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Snapshot")
            .field("seq", &self.0.seq)
            .finish_non_exhaustive()
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

    /// Fold `record` into `working` and append it to the txn's records. Stage
    /// your store's OWN record type lifted via `.into()` — never the central
    /// `Record` (composition contract).
    pub fn push(&mut self, record: W::Record) {
        self.working = self.working.apply(&record);
        self.records.push(record);
    }
}

impl<W: WorldState> fmt::Debug for Staging<W> {
    /// The base coordinate and how many records are staged against it — the
    /// two facts that place a transaction in flight. Neither world is printed:
    /// `W` is the whole engine state and is not required to be `Debug`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Staging")
            .field("base_seq", &self.base.seq)
            .field("staged", &self.records.len())
            .finish_non_exhaustive()
    }
}

/// The §6 auto-checkpoint trigger: the cadence policy together with the
/// counters it is evaluated against. The mechanism is fixed — the trigger is
/// tested ON COMMIT, there is no timer thread — and only the policy is the
/// open knob. Lives in the applier-locked state and is advanced, tested and
/// reset only from there, so a caller-invoked `checkpoint()` cannot disturb
/// the cadence it never asked for (§6).
struct Cadence {
    policy: CheckpointPolicy,
    commits_since_reset: u64,
    bytes_since_reset: u64,
    /// When the counters were last reset — by the trigger crossing, which is
    /// what `Interval` measures from.
    last_reset: Instant,
}

impl Cadence {
    fn new(policy: CheckpointPolicy) -> Cadence {
        Cadence {
            policy,
            commits_since_reset: 0,
            bytes_since_reset: 0,
            last_reset: Instant::now(),
        }
    }

    /// Charge one commit of `bytes` journal bytes and answer whether it
    /// crossed the threshold. A crossing resets the counters, so the next
    /// window starts at this commit. A quiescent kernel — nothing new to
    /// charge — correctly never crosses, `Interval` included (§6).
    fn charge_commit(&mut self, bytes: u64) -> bool {
        self.commits_since_reset += 1;
        self.bytes_since_reset += bytes;
        let crossed = match self.policy {
            CheckpointPolicy::EveryN(every) => self.commits_since_reset >= every,
            CheckpointPolicy::JournalBytes(threshold) => self.bytes_since_reset >= threshold,
            CheckpointPolicy::Interval(window) => self.last_reset.elapsed() >= window,
            CheckpointPolicy::Manual => false,
        };
        if crossed {
            self.commits_since_reset = 0;
            self.bytes_since_reset = 0;
            self.last_reset = Instant::now();
        }
        crossed
    }
}

/// State owned by the single applier lock (§3/§8): the `Seq` high-water, the
/// journal, and the §6 on-commit checkpoint trigger.
struct ApplierState {
    seq_hi: u64,
    journal: Journal,
    cadence: Cadence,
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
    checkpoint_mutex: Mutex<()>,
    poisoned: AtomicBool,
    cfg: KernelConfig,
    /// Σ₀ — the genesis world this kernel was opened under, kept because it
    /// is the base every derivation falls back to when no checkpoint covers
    /// the boundary ([`Kernel::world_at`]).
    genesis: W,
    /// The `open()`-held exclusive advisory lock (Lifecycle); `None` under
    /// `Durability::InMemory`. Held for the kernel's lifetime.
    _journal_lock: Option<File>,
}

impl<W: WorldState> fmt::Debug for Kernel<W> {
    /// The installed head, whether the write paths are halted, and the
    /// configuration — read lock-free, so this is safe to call from anywhere,
    /// including a `Drop` under the applier lock. The world itself is not
    /// printed: `W` is the whole engine state and is not required to be
    /// `Debug`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Kernel")
            .field("seq", &self.current_seq())
            .field("poisoned", &self.poisoned.load(Ordering::Relaxed))
            .field("cfg", &self.cfg)
            .finish_non_exhaustive()
    }
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
    /// Under [`Durability::InMemory`]: no journal to name, no recovery, and
    /// the root is initialized directly from `genesis` (`S_load = 0`).
    ///
    /// CALLER CONTRACT — `genesis` (= Σ₀) MUST be byte-identical on every
    /// `open()` of a given journal: recovery folds journaled DELTAS onto it,
    /// never onto a journaled root; a drifting `genesis` silently
    /// mis-recovers. M2 cannot check this (ASN-0047's fixed Σ₀ satisfies it
    /// by construction).
    pub fn open(cfg: KernelConfig, genesis: W) -> Result<Self, OpenError> {
        cfg.validate()?;
        let (root, journal, lock) = match &cfg.durability {
            // "Directly from genesis" (Lifecycle): no journal, no recovery,
            // no rebuild_derived — the caller's live value is the root.
            Durability::InMemory => (
                Committed {
                    seq: Seq(0),
                    world: genesis.clone(),
                },
                Journal::InMemory,
                None,
            ),
            Durability::Fsync { journal_path, .. } => {
                let (root, journal, lock) = Self::recover(journal_path, &genesis)?;
                (root, journal, Some(lock))
            }
        };
        Ok(Self::assemble(cfg, root, genesis, journal, lock))
    }

    /// Recover the journal at `dir` into the root it commits from, its live
    /// appender, and the exclusion lock the kernel holds for its lifetime
    /// (§7).
    fn recover(dir: &Path, genesis: &W) -> Result<(Committed<W>, Journal, File), OpenError> {
        fs::create_dir_all(dir)?;
        let lock = journal::acquire_journal_lock(dir)?;
        let segs = journal::list_segments(dir)?;
        let checkpoints = checkpoint::list(dir)?;

        // The base, with its whole fallback chain: newest valid retained
        // checkpoint → next-older retained → genesis-while-reachable; an
        // exhausted chain is the operator-intervention condition (§6/§7).
        let base = replay::select_base(&checkpoints, &segs, None, genesis)
            .map_err(|_| OpenError::BadCheckpoint)?;
        let s_load = base.s_load;

        // Pass 1: derive W and classify the corrupt runs (§7). Runs beyond W
        // and EOF runs are the un-acked/torn tail, physically discarded
        // below; runs at or below S_load are already embodied in the base.
        let scan = journal::scan(&segs, s_load)?;
        if let Some(at) = scan.fatal_run(Some(scan.committed_head)) {
            return Err(OpenError::Corruption { at: Seq(at) });
        }

        // The coordinate this session would commit at. A journal whose head
        // leaves none is one this kernel's sequencer cannot have written, and
        // an unaccountable durable head is the operator-intervention
        // condition — halt, before the tail is touched (§1/§2/§7).
        let head = scan.committed_head;
        let next_seq = head
            .checked_add(1)
            .ok_or(OpenError::Corruption { at: Seq(head) })?;

        // Tail truncation — before any write is served (§7).
        journal::truncate_tail(dir, &scan)?;

        // Pass 2: fold exactly (S_load, W], in Seq order (§6/§7).
        let world = replay::fold_to(base, scan, head)
            .map_err(|seq| OpenError::Corruption { at: Seq(seq) })?;

        let writer = JournalWriter::open_active(dir, next_seq)?;
        Ok((
            Committed {
                seq: Seq(head),
                world,
            },
            Journal::Segments(writer),
            lock,
        ))
    }

    /// This kernel's journal configuration — where its files live and how many
    /// checkpoint bases it retains — or `None` under [`Durability::InMemory`],
    /// which has no journal at all (Lifecycle). Every path that touches files
    /// goes through here, so the mode question is asked in one place.
    fn journal_cfg(&self) -> Option<(&Path, usize)> {
        match &self.cfg.durability {
            Durability::InMemory => None,
            Durability::Fsync {
                journal_path,
                retain_checkpoints,
                ..
            } => Some((journal_path, *retain_checkpoints)),
        }
    }

    fn assemble(
        cfg: KernelConfig,
        root: Committed<W>,
        genesis: W,
        journal: Journal,
        lock: Option<File>,
    ) -> Self {
        let cadence = Cadence::new(cfg.checkpoint);
        // The single Seq high-water is the WHOLE of the recovered sequencer
        // state: Txn is a transaction's first Seq, so the next session's
        // first Txn = W + 1 needs no second counter (§1/§7).
        let seq_hi = root.seq.0;
        Kernel {
            root: ArcSwap::from_pointee(root),
            applier: Mutex::new(ApplierState {
                seq_hi,
                journal,
                cadence,
            }),
            checkpoint_mutex: Mutex::new(()),
            poisoned: AtomicBool::new(false),
            cfg,
            genesis,
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
    /// Staged records that cannot be journaled — a serializer that refuses,
    /// or a record past the journal's frame size — are
    /// [`TxnError::Unencodable`]: a no-op like [`TxnError::Durability`], and
    /// unlike it, one that re-invoking with the same records cannot fix.
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
    ///
    /// [`BurnedSeqPolicy`]: crate::BurnedSeqPolicy
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
        let value = match f(&mut stg) {
            Err(e) => return Err(TxnError::Rejected(e)),
            Ok(value) => value,
        };
        if stg.records.is_empty() {
            return Ok((value, base.seq)); // zero-step (A1); V1 = the base index read.
        }
        let Staging {
            base: _,
            working,
            records,
        } = stg;

        // Linearization (§2): Seqs assigned under the applier lock, so the
        // order is gap-free (under Rollback) and a composite's records are
        // Seq-contiguous. This is the ONE site a `Seq` is minted, so it is
        // where the order's ceiling is answered for: a sequencer with no room
        // left for this transaction cannot commit it and cannot renumber it
        // over a predecessor, which leaves halting as the only sound answer.
        let state = &mut *applier;
        let n = records.len() as u64;
        let Some(last) = state.seq_hi.checked_add(n) else {
            self.poisoned.store(true, Ordering::Release);
            return Err(TxnError::Poisoned);
        };
        let first = state.seq_hi + 1; // n ≥ 1, so this is at most `last`
        state.seq_hi = last;
        let committed = Committed {
            seq: Seq(last),
            world: working,
        };
        let rollback = self.cfg.durability.rolls_back_burned_seqs();

        // The commit region: serialize, then commit through the journal (§1:
        // append records → marker → ONE fsync → install). Run under
        // catch_unwind so the §3 guard can repair a mid-commit unwind; it
        // fires only on unwind — the error returns below carry the journal's
        // own verdict on what its failure left behind.
        //
        // A transaction's serialized bytes live here twice for the length of
        // the region — once as records, once as the frames they become — and
        // all of it under the applier lock, so it is also the length of time
        // every other writer waits. The journal caps a FRAME, not a
        // transaction; how many bytes one transaction may stage is the
        // caller's to bound.
        let commit_out: std::thread::Result<Result<u64, CommitFail>> = {
            let state = &mut *state;
            let root = &self.root;
            let records = &records;
            catch_unwind(AssertUnwindSafe(move || {
                let mut record_bytes: Vec<Vec<u8>> = Vec::with_capacity(records.len());
                for record in records.iter() {
                    record_bytes.push(bincode::serialize(record).map_err(|e| {
                        CommitFail::Unencodable(io::Error::new(io::ErrorKind::InvalidData, e))
                    })?);
                }
                state.journal.commit_txn(first, record_bytes, move || {
                    // Atomic install AFTER durability (A0/A4; durable-before-
                    // visible §1): external readers see none-or-all.
                    root.store(Arc::new(committed));
                })
            }))
        };
        match commit_out {
            // §3 unwind guard: repair, then let the panic propagate.
            Err(payload) => {
                match state.journal.repair_after_unwind() {
                    UnwindRepair::Clean => {
                        if rollback {
                            state.seq_hi = base.seq.0; // absolute set — idempotent (§3)
                        }
                    }
                    // A surviving un-acked marker would let a successor
                    // collide on recovery, and a durably committed txn whose
                    // effect never installed would have later txns folding
                    // off a root missing it. Either way: poison, and leave
                    // the high-water advanced over what survives. The
                    // committed one replays at the next open() as a lost-ack
                    // op (§1/§3, SAFE(b)(iii)).
                    UnwindRepair::Unrepaired | UnwindRepair::AfterBarrier => {
                        self.poisoned.store(true, Ordering::Release);
                    }
                }
                drop(applier);
                resume_unwind(payload)
            }
            // §1/§3: the barrier never completed and the journal is durably
            // back where this txn found it — a TRUE no-op the caller may
            // re-invoke.
            Ok(Err(CommitFail::Clean(e))) => {
                if rollback {
                    state.seq_hi = base.seq.0;
                }
                Err(TxnError::Durability(e))
            }
            // Nothing ever became frames, so the journal is where this txn
            // found it — the same no-op, burning the same Seqs, and a
            // different answer to "retry?" (§1/§3).
            Ok(Err(CommitFail::Unencodable(e))) => {
                if rollback {
                    state.seq_hi = base.seq.0;
                }
                Err(TxnError::Unencodable(e))
            }
            // The truncation itself could not complete durably (§1).
            Ok(Err(CommitFail::Unrepaired)) => {
                self.poisoned.store(true, Ordering::Release);
                Err(TxnError::Poisoned)
            }
            Ok(Ok(bytes)) => {
                // §6 on-commit trigger: charged and tested under the applier
                // lock; checkpoint() never touches the cadence.
                let crossed = state.cadence.charge_commit(bytes);
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
                Ok((value, Seq(last))) // commit-before-acknowledge (A7, MIC-3)
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
    /// journal's `retain_checkpoints` most recent, and reclaim whole *closed*
    /// journal segments lying wholly BELOW the OLDEST retained checkpoint
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
        let Some((dir, retain_checkpoints)) = self.journal_cfg() else {
            return Ok(self.current_seq()); // nothing to persist or reclaim (§6)
        };
        let _serial = self.checkpoint_mutex.lock();
        let snap = self.root.load_full();
        let s = snap.seq;
        // Authoritative state serialized; hints may #[serde(skip)] and be
        // reseeded by rebuild_derived at load (§6/§7).
        let body = bincode::serialize(&snap.world).map_err(|e| CheckpointError::Serialize(e))?;
        checkpoint::write(dir, s.0, &body)?;
        // Retention policy — how many bases to keep — applied to the
        // checkpoint set, which answers with the oldest survivor.
        let s_old = checkpoint::retain(dir, retain_checkpoints)?.unwrap_or(s.0);
        // Reclaim the journal below the OLDEST retained checkpoint — that
        // floor, not the newest, is what keeps the BadCheckpoint fallback
        // real (§6).
        let segs = journal::list_segments(dir)?;
        journal::reclaim_below(dir, &segs, s_old)?;
        Ok(s)
    }

    /// The committed world as of boundary `at` — READ-ONLY bounded replay
    /// over this kernel's own journal directory (observation-surface API;
    /// the journal already holds every committed state, this makes a prefix
    /// of it answerable). Base = the newest retained checkpoint at or below
    /// `at` (else `genesis` while the journal still reaches back to `Seq(1)`),
    /// seeded through [`WorldState::rebuild_derived`], then folded over
    /// exactly `(base, at]` — recovery's Pass 2 with `W := at`. Deterministic:
    /// the same `at` yields a value-equal world on every call, across
    /// processes and regardless of which base is selected (a checkpoint
    /// embodies the same fold it stands in for — §6/§7).
    ///
    /// `at` must be a committed transaction boundary — one of the `Seq`
    /// values `transact` has returned (or 0 = genesis); a composite's
    /// interior `Seq` names a state that was never externally observable
    /// (§3) and is refused with [`HistoryError::NotABoundary`].
    ///
    /// A corrupt run at rest anywhere in the scanned region is a halt
    /// ([`HistoryError::Corruption`]), independently of where `at` sits: a
    /// run's own seqs are unreadable, so answering around it could answer
    /// from a hole. A boundary that IS the base — a retained checkpoint's seq,
    /// or 0 — is answered from that base without consulting the journal, and
    /// so never halts.
    ///
    /// The Σ₀ the fold starts from is the one this kernel was opened under,
    /// so the bounded fold applies journaled deltas onto exactly the genesis
    /// recovery would.
    ///
    /// COST, per call, uncached: one whole checkpoint file read and
    /// deserialized into a `W`, [`WorldState::rebuild_derived`] run over all
    /// of it, every journal segment above that base read, and every committed
    /// record in them materialized before the fold begins. Nothing here is
    /// memoized and nothing here is bounded by the size of `at` — a caller
    /// choosing `at` chooses the base and the fold length, and peak memory is
    /// that figure times the number of calls in flight. Admission and
    /// concurrency are the caller's to gate; this method gates neither.
    ///
    /// Safe concurrently with the live appender and with `checkpoint()`:
    /// takes no kernel lock and writes nothing. Every frame of a commit
    /// `≤ current_seq()` is fully durable before that head was installed
    /// (§1 durable-before-visible), so the bounded region is stable under
    /// the reader; a racing append can contribute at most a torn suffix,
    /// which classifies as an EOF run beyond the last committed marker and
    /// is ignored here. Two things a concurrent writer can still make this
    /// call refuse with, both transient and neither a wrong world: a
    /// checkpoint's retention removing a file between listing and reading
    /// ([`HistoryError::Io`]/[`HistoryError::Reclaimed`]), and a commit whose
    /// barrier fails truncating its tail while a read is mid-file, which
    /// leaves the read holding a discontinuity that classifies as at-rest
    /// [`HistoryError::Corruption`]. A retry re-derives from the file as it
    /// now stands.
    pub fn world_at(&self, at: Seq) -> Result<W, HistoryError> {
        let head = self.current_seq();
        if at > head {
            return Err(HistoryError::BeyondHead { head });
        }
        let Some((dir, _)) = self.journal_cfg() else {
            return Err(HistoryError::Unjournaled);
        };
        // The same base selection recovery runs, capped at `at` so a later
        // checkpoint cannot stand in for an earlier boundary.
        let checkpoints = checkpoint::list(dir)?;
        let segs = journal::list_segments(dir)?;
        let base = replay::select_base(&checkpoints, &segs, Some(at.0), &self.genesis).map_err(|u| {
            HistoryError::Reclaimed {
                floor: u.floor.map(Seq),
            }
        })?;
        let s_load = base.s_load;
        // A boundary that IS the base is answered wholly from that base:
        // checkpoint seqs are committed boundaries (a checkpoint serializes an
        // installed root) and 0 is genesis, so there is nothing to fold, and
        // consulting the journal could only refuse a question the base already
        // answers — the corruption sweep below is what it would refuse with.
        if at.0 == s_load {
            return Ok(base.world);
        }
        let scan = journal::scan(&segs, s_load)?;
        // Any at-rest corrupt run not wholly embodied in the base is a halt,
        // even beyond `at` — hence the open ceiling: a run's own seqs are
        // unreadable, so its reach below `inferred_max` is unknowable, and
        // answering around it could answer from a hole. (A racing live append
        // never produces a Landed run: it can tear only the file's suffix,
        // after the last committed marker, which reaches EOF.)
        if let Some(run_at) = scan.fatal_run(None) {
            return Err(HistoryError::Corruption { at: Seq(run_at) });
        }
        if let Err(nearest) = scan.require_boundary(at.0) {
            return Err(HistoryError::NotABoundary {
                nearest: Seq(nearest),
            });
        }
        // Recovery's fold, bounded at `at` (§6/§7).
        replay::fold_to(base, scan, at.0).map_err(|seq| HistoryError::Corruption { at: Seq(seq) })
    }

    /// Shutdown/checkpoint hook. Under per-commit `Fsync` every commit
    /// already fsyncs its records+marker barrier, so there is nothing pending
    /// and this is a no-op returning `Ok(())`; under the in-memory mode it is
    /// likewise a no-op, and on a POISONED kernel it is a no-op returning
    /// `Ok`. Retained as the slot-in point for the deferred group-commit
    /// (`FsyncBatch`) durability mode, where it would flush the pending batch
    /// and advance the `Clean` watermark (Open build decisions) — the API is
    /// invariant across durability modes.
    pub fn flush(&self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BurnedSeqPolicy;
    use crate::journal::JournalWriter;

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

    fn cfg(dir: &std::path::Path, burned_seq: BurnedSeqPolicy) -> KernelConfig {
        KernelConfig {
            durability: Durability::Fsync {
                journal_path: dir.to_path_buf(),
                retain_checkpoints: 1,
                burned_seq,
            },
            checkpoint: CheckpointPolicy::Manual,
        }
    }

    #[test]
    fn gapped_journal_replays_without_contiguity_check() {
        // §7: under TolerateGap the replayed range may contain burned-Seq
        // gaps; each present record folds exactly once, in order — a missing
        // Seq is never corruption.
        let dir = tempfile::tempdir().unwrap();
        {
            let mut writer = JournalWriter::open_active(dir.path(), 1).unwrap();
            let rec = |x: u64| bincode::serialize(&x).unwrap();
            // A journal built without a kernel: no root to install into.
            assert!(writer.commit_txn(1, vec![rec(10)], || {}).is_ok());
            assert!(writer.commit_txn(5, vec![rec(50), rec(60)], || {}).is_ok()); // burned 2..=4
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
    fn two_committed_txns_at_one_seq_halt_rather_than_fold_twice() {
        // Two transactions, each committed, each claiming `Seq(1)`. The
        // sequencer mints a coordinate once, so this is a journal no kernel
        // wrote — and `apply` is not idempotent, so folding both is the one
        // outcome recovery may not have. Halt (§7).
        let dir = tempfile::tempdir().unwrap();
        {
            let mut writer = JournalWriter::open_active(dir.path(), 1).unwrap();
            let rec = |x: u64| bincode::serialize(&x).unwrap();
            assert!(writer.commit_txn(1, vec![rec(10)], || {}).is_ok());
            assert!(writer.commit_txn(1, vec![rec(20)], || {}).is_ok());
        }
        let err = Kernel::<Vec<u64>>::open(cfg(dir.path(), BurnedSeqPolicy::Rollback), Vec::new())
            .expect_err("a repeated Seq is not something to fold twice");
        assert!(
            matches!(err, OpenError::Corruption { at: Seq(1) }),
            "got {err:?}"
        );
    }

    #[test]
    fn a_head_at_the_seq_ceiling_refuses_to_open() {
        // The committed head is the coordinate the next transaction is minted
        // above. A journal whose head leaves none cannot be committed onto
        // without renumbering over it, so opening it is refused rather than
        // wrapped (§2/§7).
        let dir = tempfile::tempdir().unwrap();
        {
            let mut writer = JournalWriter::open_active(dir.path(), 1).unwrap();
            let record = bincode::serialize(&10u64).unwrap();
            assert!(writer.commit_txn(u64::MAX, vec![record], || {}).is_ok());
        }
        let err = Kernel::<Vec<u64>>::open(cfg(dir.path(), BurnedSeqPolicy::Rollback), Vec::new())
            .expect_err("a head with no successor coordinate is unaccountable");
        assert!(
            matches!(err, OpenError::Corruption { at: Seq(u64::MAX) }),
            "got {err:?}"
        );
    }

    #[test]
    fn a_sequencer_with_no_room_left_halts_instead_of_wrapping() {
        // The mint site's own door, reached from a live kernel: with the
        // high-water at the ceiling there is no coordinate to commit at, and
        // the order cannot be renumbered over a committed predecessor —
        // so the kernel halts, and its reads keep serving (§1/§2/§3).
        let cfg = KernelConfig {
            durability: Durability::InMemory,
            checkpoint: CheckpointPolicy::Manual,
        };
        let k = Kernel::<Vec<u64>>::open(cfg, Vec::new()).unwrap();
        k.applier.lock().seq_hi = u64::MAX;
        let out = k.transact::<_, ()>(&[], |s| {
            s.push(10);
            Ok(())
        });
        assert!(matches!(out, Err(TxnError::Poisoned)), "got {out:?}");
        assert!(k.poisoned.load(Ordering::Acquire));
        assert_eq!(k.snapshot().world().as_slice(), &[] as &[u64]);
    }

    #[test]
    fn retain_checkpoints_zero_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = KernelConfig {
            durability: Durability::Fsync {
                journal_path: dir.path().to_path_buf(),
                retain_checkpoints: 0,
                burned_seq: BurnedSeqPolicy::Rollback,
            },
            checkpoint: CheckpointPolicy::Manual,
        };
        let err = Kernel::<Vec<u64>>::open(cfg, Vec::new()).err().unwrap();
        assert!(matches!(err, OpenError::Io(_)));
    }

    #[test]
    fn a_poisoned_kernel_halts_writes_and_keeps_serving_reads() {
        // §1/§3's halt, staged directly: the transitions into it need a
        // failing fs, while what poison MEANS is four documented promises
        // (§5/Invariants). Fsync mode, so no precedence between `Poisoned`
        // and the in-memory no-ops is pinned by accident.
        let dir = tempfile::tempdir().unwrap();
        let k = Kernel::<Vec<u64>>::open(cfg(dir.path(), BurnedSeqPolicy::Rollback), Vec::new())
            .unwrap();
        k.transact::<_, ()>(&[], |s| {
            s.push(10);
            Ok(())
        })
        .unwrap();
        k.poisoned.store(true, Ordering::Release);

        // Writes halt — and `f` never runs: the refusal precedes it.
        let ran = std::cell::Cell::new(false);
        let out = k.transact::<(), ()>(&[], |s| {
            ran.set(true);
            s.push(20);
            Ok(())
        });
        assert!(matches!(out, Err(TxnError::Poisoned)));
        assert!(!ran.get(), "a poisoned transact must not run the closure");
        // Checkpoints halt.
        assert!(matches!(k.checkpoint(), Err(CheckpointError::Poisoned)));
        // Reads keep serving the last consistent committed root: the poison
        // paths leave it a whole committed state, so reads stay sound.
        assert_eq!(k.current_seq(), Seq(1));
        assert_eq!(k.snapshot().seq(), Seq(1));
        assert_eq!(k.snapshot().world().as_slice(), &[10]);
        // flush stays a no-op Ok.
        k.flush().unwrap();
    }

    #[test]
    fn concurrent_checkpoints_each_leave_a_loadable_base() {
        // §6: the API permits concurrent calls — an explicit caller call
        // racing the on-commit auto-trigger, or two callers — and the
        // dedicated checkpoint mutex is what keeps two of them off one
        // `checkpoint.tmp`. A base that fails its own header checksum is
        // useless, and under `N = 1` it would be the only one.
        let dir = tempfile::tempdir().unwrap();
        let cfg = KernelConfig {
            durability: Durability::Fsync {
                journal_path: dir.path().to_path_buf(),
                retain_checkpoints: 64, // keep every base a racing call wrote
                burned_seq: BurnedSeqPolicy::Rollback,
            },
            checkpoint: CheckpointPolicy::Manual,
        };
        let k = Kernel::<Vec<u64>>::open(cfg, Vec::new()).unwrap();
        std::thread::scope(|s| {
            for _ in 0..4 {
                let k = &k;
                s.spawn(move || {
                    for _ in 0..8 {
                        k.checkpoint().expect("concurrent checkpoint");
                    }
                });
            }
            let k = &k;
            s.spawn(move || {
                for x in 0..32u64 {
                    k.transact::<_, ()>(&[], |st| {
                        st.push(x);
                        Ok(())
                    })
                    .unwrap();
                }
            });
        });
        let checkpoints = checkpoint::list(dir.path()).unwrap();
        assert!(!checkpoints.is_empty(), "the fixture writes checkpoints");
        for cp in &checkpoints {
            assert!(
                checkpoint::load::<Vec<u64>>(&cp.path, cp.seq).is_some(),
                "checkpoint {} does not load — two writers shared checkpoint.tmp",
                cp.seq
            );
        }
    }

    #[test]
    fn world_at_answers_every_boundary_and_refuses_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        let k =
            Kernel::<Vec<u64>>::open(cfg(dir.path(), BurnedSeqPolicy::Rollback), Vec::new())
                .unwrap();
        let (_, s1) = k.transact::<_, ()>(&[], |s| {
            s.push(10);
            Ok(())
        })
        .unwrap();
        let (_, s2) = k.transact::<_, ()>(&[], |s| {
            s.push(20);
            s.push(30); // a composite: seqs 2..=3, boundary 3
            Ok(())
        })
        .unwrap();
        let (_, s3) = k.transact::<_, ()>(&[], |s| {
            s.push(40);
            Ok(())
        })
        .unwrap();
        assert_eq!((s1, s2, s3), (Seq(1), Seq(3), Seq(4)));

        // Every boundary answers its exact prefix; 0 is genesis.
        assert_eq!(k.world_at(Seq(0)).unwrap(), Vec::<u64>::new());
        assert_eq!(k.world_at(Seq(1)).unwrap(), vec![10]);
        assert_eq!(k.world_at(Seq(3)).unwrap(), vec![10, 20, 30]);
        assert_eq!(k.world_at(Seq(4)).unwrap(), vec![10, 20, 30, 40]);

        // The composite's interior seq was never an observable state.
        match k.world_at(Seq(2)) {
            Err(HistoryError::NotABoundary { nearest }) => assert_eq!(nearest, Seq(1)),
            other => panic!("expected NotABoundary, got {other:?}"),
        }
        match k.world_at(Seq(9)) {
            Err(HistoryError::BeyondHead { head }) => assert_eq!(head, Seq(4)),
            other => panic!("expected BeyondHead, got {other:?}"),
        }
        // head + 1 — the commonest caller mistake, asking for the commit that
        // has not happened yet — answers the same way, rather than falling
        // through to the boundary machinery.
        match k.world_at(Seq(5)) {
            Err(HistoryError::BeyondHead { head }) => assert_eq!(head, Seq(4)),
            other => panic!("expected BeyondHead at head + 1, got {other:?}"),
        }
    }

    #[test]
    fn world_at_selects_the_base_below_the_boundary() {
        // A checkpoint above `at` must be skipped (boundaries before it still
        // fold from genesis); a checkpoint at/below `at` is a valid base and
        // yields the same value the genesis fold would (§6 consistency).
        let dir = tempfile::tempdir().unwrap();
        let k =
            Kernel::<Vec<u64>>::open(cfg(dir.path(), BurnedSeqPolicy::Rollback), Vec::new())
                .unwrap();
        for x in [10u64, 20, 30] {
            k.transact::<_, ()>(&[], |s| {
                s.push(x);
                Ok(())
            })
            .unwrap();
        }
        assert_eq!(k.checkpoint().unwrap(), Seq(3));
        k.transact::<_, ()>(&[], |s| {
            s.push(40);
            Ok(())
        })
        .unwrap();
        assert_eq!(k.world_at(Seq(1)).unwrap(), vec![10]);
        assert_eq!(k.world_at(Seq(3)).unwrap(), vec![10, 20, 30]);
        assert_eq!(k.world_at(Seq(4)).unwrap(), vec![10, 20, 30, 40]);
    }

    #[test]
    fn world_at_is_unjournaled_in_memory() {
        let cfg = KernelConfig {
            durability: Durability::InMemory,
            checkpoint: CheckpointPolicy::Manual,
        };
        let k = Kernel::<Vec<u64>>::open(cfg, Vec::new()).unwrap();
        assert!(matches!(
            k.world_at(Seq(0)),
            Err(HistoryError::Unjournaled)
        ));
    }
}
