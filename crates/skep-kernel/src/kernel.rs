//! The kernel: single-applier transaction commit (§3), lock-free snapshot
//! reads (§5), on-commit checkpointing (§6), and two-pass recovery (§7).

use std::fmt;
use std::fs::{self, File};
use std::io;
use std::num::NonZeroU64;
use std::ops::{Deref, DerefMut};
use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwap;
use parking_lot::{Mutex, MutexGuard};

use crate::checkpoint;
use crate::config::{BurnedSeqPolicy, CheckpointPolicy, Durability, KernelConfig};
use crate::error::{CheckpointError, HistoryError, OpenError, TxnError};
use crate::journal::{self, CommitFail, Journal, JournalWriter, ScanFail, UnwindRepair};
use crate::replay;
use crate::{LockKey, Seq, WorldState};

/// One installed committed state: the root's identity IS the version
/// coordinate (§Core data model). Reached only through [`Snapshot`], and
/// private to this module, where the three sites that mint one each pair a
/// coordinate with the world that embodies it — a world at a coordinate it
/// does not embody folds records it already holds, and since
/// [`WorldState::apply`] need not be idempotent, that is silent double
/// application answered `Ok`.
struct Committed<W> {
    seq: Seq,
    world: W,
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
    /// a multi-atom run mints at the frontier the prior atoms left — reading the
    /// unchanging `base()` would recompute one address m times and collide
    /// (§3/§4, W2).
    pub fn working(&self) -> &W {
        &self.working
    }

    /// Fold `record` into `working` and append it to the txn's records. Stage
    /// your store's OWN record type lifted via `.into()` — never the central
    /// `Record` (composition contract).
    ///
    /// This is where [`WorldState::apply`] runs on the write path: once per
    /// staged record, inside the [`Kernel::transact`] closure and therefore
    /// on the applier lock's critical section — which is why a composite's
    /// record count is a cost that method's TRANSACTION BUDGET accounts for.
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

/// The `Seq` order's high-water and the two operations that move it (§2):
/// minting the contiguous `Seq` range a transaction commits at, and rolling
/// back a failed transaction's burned range. Lives in the applier-locked
/// state, so the order is drawn under the same lock that installs — which is
/// what makes it gap-free under [`BurnedSeqPolicy::Rollback`] and a
/// composite's records `Seq`-contiguous. The burned-`Seq` policy is captured
/// here at `open`, so the commit path asks the configuration nothing.
///
/// [`BurnedSeqPolicy::Rollback`]: crate::BurnedSeqPolicy::Rollback
struct Sequencer {
    high_water: u64,
    burned_seq: BurnedSeqPolicy,
}

impl Sequencer {
    /// The order a recovery hands over. The single `Seq` high-water is the
    /// WHOLE of the recovered sequencer state: `Txn` is a transaction's first
    /// `Seq`, so the next session's first `Txn` = W + 1 needs no second
    /// counter (§1/§7).
    fn recovered(head: Seq, burned_seq: BurnedSeqPolicy) -> Sequencer {
        Sequencer {
            high_water: head.0,
            burned_seq,
        }
    }

    /// Draw the contiguous range `first..=last` this transaction commits at —
    /// the ONE site a `Seq` is minted (§2). `None` when the order has no room
    /// left for it: the coordinates are exhausted and renumbering over a
    /// committed predecessor is not an option, so there is nothing this order
    /// can answer with, and what to do about that is the kernel's to decide.
    ///
    /// `n ≥ 1` is carried by the TYPE, which is what makes `high_water + 1`
    /// below sound without a second site agreeing to it: a `checked_add` that
    /// succeeded with `n ≥ 1` leaves the high-water strictly below `last`, so
    /// the increment is in range. A zero-record transaction cannot be spelled
    /// here, which is the whole of the precondition.
    fn mint(&mut self, n: NonZeroU64) -> Option<(u64, u64)> {
        let last = self.high_water.checked_add(n.get())?;
        let first = self.high_water + 1; // n ≥ 1, so this is at most `last`
        self.high_water = last;
        Some((first, last))
    }

    /// Roll back a failed transaction's burned range — an absolute set back to
    /// the last committed marker's `last_seq`, hence idempotent — iff
    /// [`BurnedSeqPolicy::Rollback`] is in force. Under
    /// [`BurnedSeqPolicy::TolerateGap`] this does nothing and the order relaxes
    /// to monotone-only, with recovery tolerating the gap (§1/§3).
    ///
    /// [`BurnedSeqPolicy::Rollback`]: crate::BurnedSeqPolicy::Rollback
    /// [`BurnedSeqPolicy::TolerateGap`]: crate::BurnedSeqPolicy::TolerateGap
    fn roll_back_to(&mut self, base_seq: Seq) {
        if self.burned_seq == BurnedSeqPolicy::Rollback {
            self.high_water = base_seq.0;
        }
    }
}

/// State owned by the single applier lock (§3/§8): the `Seq` order, the
/// journal, and the §6 on-commit checkpoint trigger.
struct ApplierState {
    seq: Sequencer,
    journal: Journal,
    cadence: Cadence,
}

/// A process-unique, non-zero token per thread. `0` is issued to no thread, so
/// it doubles as "the applier is held by nobody".
fn applier_token() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    thread_local! {
        static TOKEN: u64 = NEXT.fetch_add(1, Ordering::Relaxed);
    }
    TOKEN.with(|token| *token)
}

/// The applier lock and the token of the thread holding it, kept as ONE value
/// because they must agree: the token is what lets [`ApplierLock::acquire`]
/// answer a nested acquisition as the precondition failure it is rather than
/// as the deadlock it would otherwise be. Held together so no write path can
/// reach the state without passing the door that refuses.
///
/// `Relaxed` suffices throughout: the only value ever compared is the reading
/// thread's OWN token, which no other thread stores, and a thread's own store
/// precedes its own load in program order. Other threads' stores are invisible
/// to the comparison because they can only be `0` or a token belonging to
/// somebody else.
struct ApplierLock {
    state: Mutex<ApplierState>,
    /// The token of the thread currently inside the locked region, or `0` for
    /// none. Scoped per kernel, not per thread: one thread transacting on two
    /// DISTINCT kernels is honest input and must not be refused.
    owner: AtomicU64,
}

impl ApplierLock {
    fn new(state: ApplierState) -> ApplierLock {
        ApplierLock {
            state: Mutex::new(state),
            owner: AtomicU64::new(0),
        }
    }

    /// Take the applier lock, refusing a nested acquisition by the thread
    /// that already holds it (§3). That is a caller's bug — the closure of a
    /// [`Kernel::transact`] in progress calling `transact` on the same kernel
    /// — and it is answered as one, with a panic naming the broken
    /// obligation, rather than as the permanent wedge a non-reentrant lock
    /// would otherwise give: a wedge no operator can act on and no supervisor
    /// can tell from a slow fsync. The lock is reachable only through here, so
    /// no write path can take it without the refusal.
    fn acquire(&self) -> Applier<'_> {
        let me = applier_token();
        assert!(
            self.owner.load(Ordering::Relaxed) != me,
            "transact is not reentrant: the closure called `transact` on this kernel, \
             which holds the applier lock for the whole of `f` (§3)"
        );
        let state = self.state.lock();
        self.owner.store(me, Ordering::Relaxed);
        Applier {
            owner: &self.owner,
            state,
        }
    }
}

/// The held applier lock. The owner is cleared BEFORE the lock is released (a
/// value's own `Drop::drop` runs before its fields drop), so no thread
/// observes a stale owner while another holds the lock.
struct Applier<'k> {
    owner: &'k AtomicU64,
    state: MutexGuard<'k, ApplierState>,
}

impl Drop for Applier<'_> {
    fn drop(&mut self) {
        self.owner.store(0, Ordering::Relaxed);
    }
}

impl Deref for Applier<'_> {
    type Target = ApplierState;
    fn deref(&self) -> &ApplierState {
        &self.state
    }
}

impl DerefMut for Applier<'_> {
    fn deref_mut(&mut self) -> &mut ApplierState {
        &mut self.state
    }
}

/// The transactional kernel over an engine-supplied `W` (§Public interface).
/// v1 concurrency realization: the single applier (§8) — every write runs to
/// completion under one global lock, subsuming the `LockKey` seam; the
/// `transact`/`snapshot` signatures are invariant across realizations.
pub struct Kernel<W: WorldState> {
    root: ArcSwap<Committed<W>>,
    applier: ApplierLock,
    /// §6: serializes `checkpoint()` against itself (caller calls and the
    /// on-commit auto-trigger); distinct from the applier lock so persisting
    /// and reclaiming never block writers.
    ///
    /// LOCK ORDER — this is taken while the applier lock is held (from inside
    /// a [`Kernel::transact`] closure, which that precondition permits) or
    /// with no lock held at all, and NEVER the reverse: [`Kernel::checkpoint`]
    /// must acquire no applier lock, or a closure-invoked checkpoint deadlocks
    /// against a concurrent writer — silently, and indistinguishably from a
    /// slow fsync.
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
            .field("poisoned", &self.is_poisoned())
            .field("cfg", &self.cfg)
            .finish_non_exhaustive()
    }
}

impl<W: WorldState> Kernel<W> {
    /// Recover or init (Lifecycle, §7).
    ///
    /// The configuration is validated FIRST — a rule this kernel does not
    /// offer is refused with [`OpenError::InvalidConfig`] before the journal
    /// lock is taken and before any file is read.
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
    /// halt, never drop), replay exactly `S_load < Seq ≤ W` through
    /// [`WorldState::apply`] in `Seq` order (Pass 2 — no contiguity required:
    /// `TolerateGap` burns fold harmlessly), then durably TRUNCATE the
    /// un-acked/torn tail beyond `W` before any write is served (skipped on
    /// every halt path; a truncation failure fails `open()` with `Io` —
    /// idempotent, retried next `open()`). A committed-but-unacked tail marker
    /// is REPLAYED — the lost-ack case is the client's (ASN-0134
    /// SAFE(b)(iii)), not a phantom.
    ///
    /// Under [`Durability::InMemory`]: no journal to name, no recovery, and
    /// the root is initialized directly from `genesis` (`S_load = 0`).
    ///
    /// DAMAGE MODEL — what recovery detects is FRAMES THAT FAIL THEIR CRC. A
    /// segment that is ABSENT leaves no run to classify and no gap to detect:
    /// §7 requires no `Seq` contiguity over the replayed range, so a missing
    /// segment is indistinguishable from a burned range, and this answers `Ok`
    /// with a world short by exactly that segment's records — at the true
    /// head, so nothing about the answer looks wrong. The `journal_path`
    /// caller contract is what keeps that out of reach; nothing here detects
    /// it, and `an_absent_segment_shortens_the_world_where_a_damaged_one_halts`
    /// is what pins the asymmetry.
    ///
    /// REFUSAL PRECEDENCE — the steps above are the order in which refusals
    /// speak: [`OpenError::InvalidConfig`] precedes the lock, the lock
    /// precedes any read of the journal, [`OpenError::BadCheckpoint`]
    /// precedes [`OpenError::Corruption`], and EVERY route to `Corruption` —
    /// the classified corrupt run, the exhausted `Seq` order, and the fold's
    /// own verdict on an undecodable or repeated record — precedes the tail
    /// truncation, which is why a halt never cuts anything.
    ///
    /// CALLER CONTRACT — `genesis` (= Σ₀) MUST be byte-identical on every
    /// `open()` of a given journal: recovery folds journaled DELTAS onto it,
    /// never onto a journaled root; a drifting `genesis` silently
    /// mis-recovers. M2 cannot check this (ASN-0047's fixed Σ₀ satisfies it
    /// by construction).
    pub fn open(cfg: KernelConfig, genesis: W) -> Result<Self, OpenError> {
        cfg.validate().map_err(OpenError::InvalidConfig)?;
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

        // Pass 1: derive W and classify the corrupt runs (§7). A scan that
        // could not enumerate the frame stream produces no outcome at all and
        // halts here. Of the runs it does report, those beyond W and the EOF
        // ones are the un-acked/torn tail, physically discarded below, and
        // those at or below S_load are already embodied in the base.
        let scan = base.scan(&segs, None).map_err(|fail| match fail {
            ScanFail::Io(e) => OpenError::Io(e),
            ScanFail::Unbounded { at } => OpenError::Corruption {
                at: Seq(at),
                cause: None,
            },
        })?;
        if let Some(at) = scan.fatal_run_to_head() {
            return Err(OpenError::Corruption {
                at: Seq(at),
                cause: None,
            });
        }

        // The coordinate this session would commit at. A journal whose head
        // leaves none is one this kernel's sequencer cannot have written, and
        // an unaccountable durable head is the operator-intervention
        // condition (§1/§2/§7).
        let committed_head = scan.committed_head;
        let next_seq = committed_head.checked_add(1).ok_or(OpenError::Corruption {
            at: Seq(committed_head),
            cause: None,
        })?;

        // Pass 2: fold exactly (S_load, W], in Seq order (§6/§7).
        let world = replay::fold_to(base, &scan, committed_head).map_err(|fail| {
            OpenError::Corruption {
                at: Seq(fail.at),
                cause: fail.cause,
            }
        })?;

        // Tail truncation: after every refusal, and before any write is
        // served (§7). The fold serves none, so the §7 obligation is kept
        // while an `open()` that refuses leaves the journal exactly as it
        // found it — which is what an operator images after a halt. It is
        // also before the appender is opened over that segment, whose length
        // this cut settles and which the appender reads once.
        journal::truncate_tail(dir, &scan)?;

        let writer = JournalWriter::open_active(dir, next_seq)?;
        Ok((
            Committed {
                seq: Seq(committed_head),
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
        let seq = Sequencer::recovered(root.seq, cfg.durability.burned_seq_policy());
        Kernel {
            root: ArcSwap::from_pointee(root),
            applier: ApplierLock::new(ApplierState {
                seq,
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
    /// durable, so a zero-step op never waits on the durability barrier —
    /// but like every transaction it waits for the applier lock and then
    /// clones `W` to stage against, both of which a zero-step op pays in
    /// full, which is why [`Kernel::snapshot`] and not a zero-step `transact`
    /// is the read path, §5).
    ///
    /// Staged records that cannot be journaled — a serializer that refuses,
    /// or a record past the journal's frame cap — are
    /// [`TxnError::Unencodable`]: a no-op like [`TxnError::Durability`], and
    /// unlike it, one that re-invoking with the same records cannot fix. A
    /// transaction whose records all encode but whose whole encoded form —
    /// frames, marker and headers — exceeds the journal's per-transaction
    /// budget, [`crate::MAX_TXN_BYTES`], is [`TxnError::OverBudget`]: the
    /// same no-op with a different remedy — no
    /// record is at fault, the staging is, and the caller splits the
    /// transaction where fixing a value cannot help. Both size limits are
    /// judged ABOVE the durability-mode branch, so an in-memory kernel
    /// refuses exactly what a journaled one refuses — a store that passes an
    /// in-memory test does not meet a size refusal only in production.
    ///
    /// On a POISONED kernel the refusal PRECEDES `f`: the call returns
    /// [`TxnError::Poisoned`] without running the closure, so a closure with
    /// effects of its own does not run for a transaction that cannot commit.
    ///
    /// REFUSAL PRECEDENCE — several of these can hold at once, and this is the
    /// order in which they speak: the reentrancy panic first, being a caller's
    /// bug and answered before the applier lock is even taken; then
    /// [`TxnError::Poisoned`], before `f` runs; then `f`'s own
    /// [`TxnError::Rejected`]; then the zero-step `Ok`; then
    /// [`TxnError::Poisoned`] again where the `Seq` order has no room left for
    /// this transaction, which is judged before the journal is consulted and
    /// poisons on the way out; and inside the commit
    /// region [`TxnError::Unencodable`] before [`TxnError::OverBudget`]
    /// before [`TxnError::Durability`]: the encode and the size accounting
    /// precede the first file operation, a refusal that belongs to the
    /// records must not be reported on the channel a caller retries, and a
    /// record's own refusal precedes the transaction's, so a caller fixing a
    /// value is not first told to split. `Poisoned` displaces `Durability`
    /// where the tail truncation itself cannot complete durably, which
    /// [`TxnError::Durability`] states.
    ///
    /// PRECONDITION — `f` MUST NOT call `transact` on this kernel; this call
    /// holds the applier lock for the whole of `f`, so a nested write can
    /// never proceed. The violation is a caller's bug and is answered as one
    /// — a panic naming the broken obligation — not as the deadlock it would
    /// otherwise be. `f` MAY take this kernel's reads
    /// ([`Kernel::snapshot`], [`Kernel::current_seq`], [`Kernel::world_at`]):
    /// they acquire no applier lock and observe Σ, the base, never the staged
    /// Σᵢ — which is what makes a composite's intermediates invisible to
    /// external readers (§3). [`Kernel::checkpoint`] likewise acquires no
    /// applier lock; one taken from inside `f` embodies Σ, not the
    /// transaction in flight. A composite composes neighbors' PURE math
    /// inside ONE closure (§3; seam contract 3).
    ///
    /// TRANSACTION BUDGET — one transaction's encoded form is bounded by
    /// [`crate::MAX_TXN_BYTES`], and a transaction past it is REFUSED with
    /// [`TxnError::OverBudget`], in both durability modes, before the journal
    /// is touched. The budget bounds four costs, the first three transient
    /// and the fourth durable. Three scale with a transaction's BYTES: the
    /// whole transaction is serialized under the applier lock, so every other
    /// writer in the process waits behind it; its serialized bytes live twice
    /// for the length of the commit region, once as records and once as the
    /// frames they become; and — because a transaction never spans a segment
    /// — the segment holding it is at least that large, and recovery reads a
    /// segment WHOLE, so the budget is what keeps the memory floor of every
    /// later `open()` and every [`Kernel::world_at`] bounded, and identical
    /// on every replica. The fourth scales with the record COUNT instead:
    /// [`Staging::push`] folds each staged record through
    /// [`WorldState::apply`], which builds a new world per record, and it
    /// runs inside `f` and therefore on that same critical section — so a
    /// composite of `m` records costs `m` folds of `W` there, over and above
    /// the one clone every transaction pays. The budget bounds `m` only at
    /// [`crate::MAX_TXN_BYTES`] over the 40 journal bytes a record occupies
    /// at minimum — over a million and a half — so a caller batching small
    /// records is choosing that figure rather than inheriting one from here. A composite too large for the budget is split by the caller;
    /// atomicity of the split is then the caller's, as it already is for
    /// every multi-`transact` batch (ASN-0134 A5).
    ///
    /// Under the v1 single applier the global lock subsumes `keys` (§4):
    /// callers still pass the keys they would need under the deferred per-key
    /// realization, so it slots in later without changing any call shape.
    /// `keys` is a SET as far as this kernel is concerned — order and
    /// duplicates are the kernel's to normalize under any realization, never
    /// the caller's to arrange — so no store invents an ordering discipline
    /// the deferred per-key realization would then have to honour.
    ///
    /// A committing call may additionally take a checkpoint before it
    /// returns: the §6 on-commit trigger is evaluated under the applier lock
    /// and, when it crosses, [`Kernel::checkpoint`] runs to completion on
    /// this thread — serializing `W`, writing and fsyncing a file, applying
    /// retention, reclaiming segments — after the commit is durable and
    /// installed. Its failure is DISCARDED: the transaction is already
    /// acknowledged, so there is no sound path for that error through
    /// [`TxnError`], and v1 has no logging seam. A caller who needs to know
    /// whether checkpointing is succeeding must call [`Kernel::checkpoint`]
    /// itself and read the result; a store that has stopped checkpointing
    /// goes on committing and says nothing.
    ///
    /// A panic out of `f` propagates with nothing of the transaction
    /// surviving, and needs no guard to do so: no `Seq` was drawn and nothing
    /// was appended, so the staging drop and the applier lock's release are
    /// the whole repair. The kernel is not poisoned and the order stays
    /// gap-free.
    ///
    /// A panic out of the commit path is what the §3 unwind guard answers
    /// (pre-barrier: durably truncate any partial append and roll the
    /// high-water back per [`BurnedSeqPolicy`] — poisoning if the truncation
    /// cannot complete durably; post-barrier pre-install: poison — the
    /// committed-but-uninstalled txn replays at the next `open()` as a
    /// lost-ack op); the panic then propagates to the caller.
    ///
    /// [`BurnedSeqPolicy`]: crate::BurnedSeqPolicy
    pub fn transact<T, E>(
        &self,
        keys: &[LockKey],
        f: impl FnOnce(&mut Staging<W>) -> Result<T, E>,
    ) -> Result<(T, Seq), TxnError<E>> {
        let _ = keys; // §4: subsumed by the single applier's global lock in v1.
        let mut applier = self.applier.acquire();
        if self.poisoned.load(Ordering::Acquire) {
            return Err(TxnError::Poisoned);
        }
        let base = self.root.load_full();
        // The staging owns the root for the length of the closure; what
        // outlives it here is the coordinate, which is all the zero-step
        // return and the burned-`Seq` rollbacks below need.
        let base_seq = base.seq;
        let mut stg = Staging::new(base);

        // Closure phase. Nothing is allocated or appended yet, so an unwind
        // here needs no repair: staging is discarded, the lock releases on
        // unwind, no Seq was drawn (§3).
        let value = match f(&mut stg) {
            Err(e) => return Err(TxnError::Rejected(e)),
            Ok(value) => value,
        };
        let Staging {
            base: _,
            working,
            records,
        } = stg;
        // Zero-step (A1: read-only / idem-hit / nullify-hit): nothing staged,
        // so no coordinate is drawn — and the non-emptiness the sequencer
        // needs is that same fact, spelled once and carried to it by the type.
        let Some(n) = NonZeroU64::new(records.len() as u64) else {
            return Ok((value, base_seq)); // V1 = the base index read.
        };

        // Linearization (§2): the range is drawn under the applier lock, so the
        // order is gap-free (under Rollback) and a composite's records are
        // Seq-contiguous. An order with no room left for this transaction
        // cannot commit it and cannot renumber it over a committed
        // predecessor, which leaves halting as the only sound answer.
        let state = &mut *applier;
        let Some((first, last)) = state.seq.mint(n) else {
            self.poisoned.store(true, Ordering::Release);
            return Err(TxnError::Poisoned);
        };
        let committed = Committed {
            seq: Seq(last),
            world: working,
        };

        // The commit region: one call into the journal, which serializes the
        // records, judges the size limits no mode may skip, and commits
        // (§1: append records → marker → ONE fsync → install). Run under
        // catch_unwind so the §3 guard can repair a mid-commit unwind — the
        // encode is where a record's own `Serialize` can panic, so it must
        // sit inside the guard; the guard fires only on unwind, and the error
        // returns below carry the journal's own verdict on what its failure
        // left behind.
        //
        // A transaction's serialized bytes live inside that call twice for
        // the length of the region — once as records, once as the frames they
        // become — and all of it under the applier lock, so it is also the
        // length of time every other writer waits. The staging is MOVED in, so
        // it is that pair and not a third copy: each record is released as the
        // journal encodes it. The journal is what bounds both, refusing above
        // its own mode branch: the frame cap per record and `MAX_TXN_BYTES` per
        // transaction, identically in both durability modes.
        let commit_out: std::thread::Result<Result<u64, CommitFail>> = {
            let state = &mut *state;
            let root = &self.root;
            catch_unwind(AssertUnwindSafe(move || {
                state.journal.commit_txn(first, records, move || {
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
                    UnwindRepair::Clean => state.seq.roll_back_to(base_seq),
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
                state.seq.roll_back_to(base_seq);
                Err(TxnError::Durability(e))
            }
            // Nothing ever became frames, so the journal is where this txn
            // found it — the same no-op, burning the same Seqs, and a
            // different remedy: fix the record (§1/§3).
            Ok(Err(CommitFail::Unencodable(e))) => {
                state.seq.roll_back_to(base_seq);
                Err(TxnError::Unencodable(e))
            }
            // The same no-op with the third remedy: no record refused, the
            // staging as a whole is past the transaction budget, and only
            // splitting it changes that (§1/§3).
            Ok(Err(CommitFail::OverBudget { bytes })) => {
                state.seq.roll_back_to(base_seq);
                Err(TxnError::OverBudget { bytes })
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

    /// Whether an unrecoverable failure has halted this kernel's write paths
    /// (§1/§3) — the state [`TxnError::Poisoned`] and
    /// [`CheckpointError::Poisoned`] report. Lock-free and infallible, like
    /// the other reads, so a supervisor can ask without taking the applier
    /// lock, cloning `W`, or writing a checkpoint file.
    ///
    /// NOT a gate: a kernel healthy at this call may poison before the next
    /// write, so the authoritative answer is the refusal [`Kernel::transact`]
    /// returns. Poison is terminal in the other direction, so a `true` here is
    /// actionable without a race.
    pub fn is_poisoned(&self) -> bool {
        self.poisoned.load(Ordering::Acquire)
    }

    /// Persist a checkpoint embodying all records with `Seq ≤ s`, keep the
    /// journal's `retain_checkpoints` most recent, and reclaim whole *closed*
    /// journal segments lying wholly BELOW the OLDEST retained checkpoint
    /// (segment-granular space reclamation, never a correctness mechanism —
    /// recovery's `Seq > S_load` filter handles straddler leftovers; §6).
    /// Non-blocking to writers (grabs a lock-free `Snapshot`, never the
    /// applier lock — which is a rule, not an economy: a closure inside
    /// [`Kernel::transact`] may call this while holding that lock, so
    /// reaching for it here would deadlock against a concurrent writer) and
    /// serialized against itself by the dedicated checkpoint mutex, whose
    /// lock order states the same rule from the other side. Cadence counters
    /// live in `transact`'s applier-locked
    /// state — a caller-invoked `checkpoint()` does NOT reset them (§6).
    /// Returns the checkpointed seq. [`CheckpointError::Poisoned`] — a prior
    /// failure halted the kernel — outranks every other answer, the
    /// in-memory no-op included, so a halted kernel takes no checkpoint in
    /// either mode. Under [`Durability::InMemory`] and unpoisoned it is a
    /// no-op returning [`current_seq`].
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
        checkpoint::write(dir, s.0, &snap.world).map_err(|fail| match fail {
            checkpoint::WriteFail::Serialize(e) => CheckpointError::Serialize(e),
            checkpoint::WriteFail::Io(e) => CheckpointError::Io(e),
        })?;
        // Retention policy — how many bases to keep — applied to the
        // checkpoint set, which answers with the oldest survivor. There is
        // always one: `retain_checkpoints ≥ 1` is validated at `open`, and
        // this call has just added to the set the retention is applied to.
        let s_old = checkpoint::retain(dir, retain_checkpoints)?
            .expect("retention keeps N ≥ 1 of a set this call just added to");
        // Reclaim the journal below the OLDEST retained checkpoint — that
        // floor, not the newest, is what keeps the BadCheckpoint fallback
        // real (§6).
        journal::reclaim_below(dir, s_old)?;
        Ok(s)
    }

    /// The committed world as of boundary `at` — READ-ONLY bounded replay
    /// over this kernel's own journal directory (the journal already holds
    /// every committed state; this makes a prefix of it answerable). Base =
    /// the newest retained checkpoint at or below `at` (else `genesis` while
    /// the journal still reaches back to `Seq(1)`),
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
    /// so the bounded replay applies journaled deltas onto exactly the genesis
    /// recovery would.
    ///
    /// REFUSAL PRECEDENCE — several of these can hold at once, and this is
    /// the order in which they speak: [`HistoryError::Unjournaled`] first,
    /// being a property of the kernel that no choice of `at` can avoid; then
    /// [`HistoryError::BeyondHead`]; then [`HistoryError::Reclaimed`], since
    /// with no base the journal's contents cannot matter; then
    /// [`HistoryError::Corruption`], since a corrupt run makes the boundary
    /// set itself underivable; and last [`HistoryError::NotABoundary`].
    /// [`HistoryError::Io`] speaks wherever the read that failed sits.
    ///
    /// COST, per call, uncached: one whole checkpoint file read and
    /// deserialized into a `W`, [`WorldState::rebuild_derived`] run over all
    /// of it, every journal segment above that base READ, and every committed
    /// record in `(base, at]` materialized before the fold begins. Segments
    /// above `at` are read and not collected — the corrupt-run sweep is at any
    /// height, so they must be read, and nothing above `at` is folded — so a
    /// caller choosing `at` chooses the base, the fold length and the records
    /// held, but not the bytes read. Nothing here is memoized, and peak memory
    /// is that figure times the number of calls in flight. Admission and
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
        // A kernel with no journal can answer no boundary, so that refusal
        // precedes every question about `at`: a caller told `BeyondHead` here
        // would walk `at` down to genesis before learning that none of it was
        // ever answerable.
        let Some((dir, _)) = self.journal_cfg() else {
            return Err(HistoryError::Unjournaled);
        };
        let installed_head = self.current_seq();
        if at > installed_head {
            return Err(HistoryError::BeyondHead {
                head: installed_head,
            });
        }
        // The same base selection recovery runs, capped at `at` so a later
        // checkpoint cannot stand in for an earlier boundary.
        let checkpoints = checkpoint::list(dir)?;
        let segs = journal::list_segments(dir)?;
        let base = replay::select_base(&checkpoints, &segs, Some(at.0), &self.genesis).map_err(|u| {
            HistoryError::Reclaimed {
                floor: u.floor.map(Seq),
            }
        })?;
        // A boundary that IS the base is answered wholly from that base:
        // checkpoint seqs are committed boundaries (a checkpoint serializes an
        // installed root) and 0 is genesis, so there is nothing to fold, and
        // consulting the journal could only refuse a question the base already
        // answers — the corruption sweep below is what it would refuse with.
        if at.0 == base.s_load() {
            return Ok(base.into_world());
        }
        let scan = base.scan(&segs, Some(at.0)).map_err(|fail| match fail {
            ScanFail::Io(e) => HistoryError::Io(e),
            ScanFail::Unbounded { at } => HistoryError::Corruption {
                at: Seq(at),
                cause: None,
            },
        })?;
        // Any at-rest corrupt run not wholly embodied in the base is a halt,
        // even beyond `at`. (A racing live append never produces a Landed run:
        // it can tear only the file's suffix, after the last committed marker,
        // which reaches EOF.)
        if let Some(run_at) = scan.fatal_run_anywhere() {
            return Err(HistoryError::Corruption {
                at: Seq(run_at),
                cause: None,
            });
        }
        if let Err(nearest) = scan.require_boundary(at.0) {
            return Err(HistoryError::NotABoundary {
                nearest: Seq(nearest),
            });
        }
        // Recovery's fold, bounded at `at` (§6/§7).
        replay::fold_to(base, &scan, at.0).map_err(|fail| HistoryError::Corruption {
            at: Seq(fail.at),
            cause: fail.cause,
        })
    }

    /// Shutdown/checkpoint hook. Under per-commit `Fsync` every commit
    /// already fsyncs its records+marker barrier, so there is nothing pending
    /// and this is a no-op returning `Ok(())`; under the in-memory mode it is
    /// likewise a no-op, and on a POISONED kernel it is a no-op returning
    /// `Ok`. Retained as the slot-in point for the deferred group-commit
    /// (`FsyncBatch`) durability mode, where it would flush the pending batch
    /// and advance that mode's `Clean{through}` durability watermark (Open
    /// build decisions) — the API is invariant across durability modes.
    pub fn flush(&self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

    // A world of raw byte records, for the size-refusal tests: `Vec<u64>`'s
    // fixed 8-byte records cannot reach the frame cap or the budget.
    impl WorldState for Vec<Vec<u8>> {
        type Record = Vec<u8>;
        fn apply(&self, r: &Vec<u8>) -> Self {
            let mut v = self.clone();
            v.push(r.clone());
            v
        }
    }

    /// Run one size-refusal test under BOTH durability modes: the limits are
    /// judged above the journal's mode branch, and the parity — not either
    /// mode alone — is what these tests pin (F3).
    fn in_each_mode(f: impl Fn(Kernel<Vec<Vec<u8>>>, &str)) {
        let dir = tempfile::tempdir().unwrap();
        f(
            Kernel::open(cfg(dir.path(), BurnedSeqPolicy::Rollback), Vec::new()).unwrap(),
            "Fsync",
        );
        let mem = KernelConfig {
            durability: Durability::InMemory,
            checkpoint: CheckpointPolicy::Manual,
        };
        f(Kernel::open(mem, Vec::new()).unwrap(), "InMemory");
    }

    #[test]
    fn a_txn_at_the_budget_commits_and_one_past_is_refused_in_both_modes() {
        // The budget is judged above the mode branch (F1): a transaction at
        // MAX_TXN_BYTES commits — the refusal begins one past the budget, not
        // at it — and one byte past is OverBudget in BOTH modes, with
        // identical accounting.
        let overhead = journal::txn_encoded_len(&[
            journal::encode_record(&Vec::<u8>::new()).unwrap(),
            journal::encode_record(&Vec::<u8>::new()).unwrap(),
        ]);
        // A record's encoded length grows byte-for-byte with its body, so
        // these two bodies land the accounted total exactly on the budget.
        let body = journal::MAX_TXN_BYTES - overhead;
        let (len1, len2) = ((body / 2) as usize, (body - body / 2) as usize);
        in_each_mode(|k, mode| {
            let (_, seq) = k
                .transact::<_, ()>(&[], |stg| {
                    stg.push(vec![7u8; len1]);
                    stg.push(vec![7u8; len2]);
                    Ok(())
                })
                .unwrap_or_else(|e| panic!("{mode}: at-budget txn must commit: {e:?}"));
            assert_eq!(seq, Seq(2), "{mode}");
            let out = k.transact::<_, ()>(&[], |stg| {
                stg.push(vec![7u8; len1]);
                stg.push(vec![7u8; len2 + 1]);
                Ok(())
            });
            match out {
                Err(TxnError::OverBudget { bytes }) => {
                    assert_eq!(bytes, journal::MAX_TXN_BYTES + 1, "{mode}")
                }
                other => panic!("{mode}: expected OverBudget, got {other:?}"),
            }
        });
    }

    #[test]
    fn a_record_past_the_frame_cap_is_unencodable_in_both_modes() {
        // F3: the frame cap used to live only in the journal's frame builder,
        // which the in-memory mode never reaches — a store whose values can
        // exceed it passed every in-memory test and met the refusal in
        // production. The cap is now judged above the mode branch; the
        // InMemory arm here is red without that.
        //
        // The record also busts the whole-txn budget, and the record's own
        // refusal speaks first: a caller fixing a value is not told to split.
        let prefix = journal::encode_record(&Vec::<u8>::new()).unwrap().len();
        let over = journal::MAX_FRAME_LEN as usize
            - journal::RECORD_PAYLOAD_OVERHEAD as usize
            - prefix
            + 1;
        in_each_mode(|k, mode| {
            let out = k.transact::<_, ()>(&[], |stg| {
                stg.push(vec![7u8; over]);
                Ok(())
            });
            assert!(
                matches!(out, Err(TxnError::Unencodable(_))),
                "{mode}: expected Unencodable, got {out:?}"
            );
        });
    }

    #[test]
    fn a_size_refusal_is_a_true_no_op_in_both_modes() {
        // The refusal leaves what the contract already promises for
        // `Durability`: nothing installed, no Seq burned (Rollback), and the
        // caller may re-invoke — here split into two transactions, since one
        // oversized record cannot be split in place.
        let overhead =
            journal::txn_encoded_len(&[journal::encode_record(&Vec::<u8>::new()).unwrap()]);
        let over = (journal::MAX_TXN_BYTES - overhead) as usize + 1;
        in_each_mode(|k, mode| {
            k.transact::<_, ()>(&[], |stg| {
                stg.push(vec![1u8]);
                Ok(())
            })
            .unwrap();
            let before = k.snapshot();
            let out = k.transact::<_, ()>(&[], |stg| {
                stg.push(vec![7u8; over]);
                Ok(())
            });
            assert!(
                matches!(out, Err(TxnError::OverBudget { .. })),
                "{mode}: got {out:?}"
            );
            // State unchanged, seq not advanced.
            assert_eq!(k.current_seq(), Seq(1), "{mode}");
            assert_eq!(k.snapshot().seq(), before.seq(), "{mode}");
            assert_eq!(k.snapshot().world().len(), 1, "{mode}");
            // The caller re-invokes split, and commits at the next Seqs: the
            // refused transaction burned nothing.
            for i in 0..2u64 {
                let (_, seq) = k
                    .transact::<_, ()>(&[], |stg| {
                        stg.push(vec![7u8; over / 2]);
                        Ok(())
                    })
                    .unwrap_or_else(|e| panic!("{mode}: split half must commit: {e:?}"));
                assert_eq!(seq, Seq(2 + i), "{mode}");
            }
        });
    }

    #[test]
    fn the_budget_does_not_bite_a_txn_of_many_small_records() {
        // The budget exists for pathological stagings; a composite of a
        // thousand small records is the honest shape §3 recommends and stays
        // far under it, in both modes.
        in_each_mode(|k, mode| {
            let (_, seq) = k
                .transact::<_, ()>(&[], |stg| {
                    for i in 0..1000u32 {
                        stg.push(i.to_le_bytes().to_vec());
                    }
                    Ok(())
                })
                .unwrap_or_else(|e| panic!("{mode}: {e:?}"));
            assert_eq!(seq, Seq(1000), "{mode}");
        });
    }

    #[test]
    fn gapped_journal_replays_without_contiguity_check() {
        // §7: under TolerateGap the replayed range may contain burned-Seq
        // gaps; each present record folds exactly once, in order — a missing
        // Seq is never corruption.
        let dir = tempfile::tempdir().unwrap();
        {
            let mut writer = JournalWriter::open_active(dir.path(), 1).unwrap();
            let rec = |x: u64| journal::encode_record(&x).unwrap();
            // A journal built without a kernel: no root to install into.
            writer
                .commit_txn(1, vec![rec(10)], || {})
                .expect("fixture commit");
            // burned 2..=4
            writer
                .commit_txn(5, vec![rec(50), rec(60)], || {})
                .expect("fixture commit");
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
            let rec = |x: u64| journal::encode_record(&x).unwrap();
            writer
                .commit_txn(1, vec![rec(10)], || {})
                .expect("fixture commit");
            writer
                .commit_txn(1, vec![rec(20)], || {})
                .expect("fixture commit");
        }
        // A torn tail past the last committed marker, so there IS something a
        // truncation would take — without it the cut lands at end-of-file and
        // the assertion below could not tell a halt from a truncation.
        let seg = journal::segment_path(dir.path(), 1);
        {
            use std::io::Write as _;
            let mut f = std::fs::OpenOptions::new().append(true).open(&seg).unwrap();
            f.write_all(&[0xAB, 0xCD, 0xEF]).unwrap();
        }
        let before = fs::read(&seg).unwrap();

        let err = Kernel::<Vec<u64>>::open(cfg(dir.path(), BurnedSeqPolicy::Rollback), Vec::new())
            .expect_err("a repeated Seq is not something to fold twice");
        assert!(
            matches!(err, OpenError::Corruption { at: Seq(1), .. }),
            "got {err:?}"
        );
        // A halt cuts nothing: the fold's refusal precedes the tail
        // truncation, so the store an operator images after a `Corruption` is
        // the store that was there.
        assert_eq!(
            fs::read(&seg).unwrap(),
            before,
            "a halted open truncated the journal"
        );
        // A repeat carries no account: the journal is malformed rather than
        // unreadable, so the coordinate is the whole of what there is to say.
        assert!(std::error::Error::source(&err).is_none());
    }

    /// A world whose records are a four-variant enum — the narrow reader in
    /// the skew below.
    #[derive(Clone, serde::Serialize, serde::Deserialize)]
    struct NarrowWorld(Vec<u8>);

    #[derive(serde::Serialize, serde::Deserialize)]
    enum Narrow {
        A,
        B,
        C,
        D,
    }

    impl WorldState for NarrowWorld {
        type Record = Narrow;
        fn apply(&self, _: &Narrow) -> Self {
            self.clone()
        }
    }

    #[test]
    fn an_undecodable_record_carries_the_serializers_own_account() {
        // A committed, CRC-intact record that does not decode as this
        // `W::Record`: bad media, or a binary rolled back over a record
        // format. The coordinate cannot tell those apart and the serializer's
        // account can, so it travels — this is the one of the four
        // `Corruption` conditions that has an account at all (§7).
        let dir = tempfile::tempdir().unwrap();
        {
            let mut writer = JournalWriter::open_active(dir.path(), 1).unwrap();
            // Variant index 5, written where `Narrow` has four.
            writer
                .commit_txn(1, vec![journal::encode_record(&5u32).unwrap()], || {})
                .expect("fixture commit");
        }
        let err = Kernel::<NarrowWorld>::open(
            cfg(dir.path(), BurnedSeqPolicy::Rollback),
            NarrowWorld(Vec::new()),
        )
        .expect_err("an undecodable committed record is not something to fold");
        assert!(
            matches!(err, OpenError::Corruption { at: Seq(1), .. }),
            "got {err:?}"
        );
        let cause = std::error::Error::source(&err)
            .expect("the account is the only thing that separates a skew from rot")
            .to_string();
        assert!(cause.contains("variant index"), "got {cause}");
        // …and it reaches an operator reading the error, not only one walking
        // the chain.
        assert!(err.to_string().contains("variant index"), "got {err}");
    }

    #[test]
    fn a_journal_whose_frame_stream_cannot_be_enumerated_refuses_to_open() {
        // A record whose own bytes plant frame headers, and a lost sync
        // before it: the scan cannot enumerate the stream inside its
        // resynchronization budget, so it produces no outcome at all. There
        // is nothing partial for recovery to fold from and no coordinate that
        // localizes the damage, so the halt is reported at the base's own
        // coordinate — genesis here (§7).
        let dir = tempfile::tempdir().unwrap();
        {
            let mut writer = JournalWriter::open_active(dir.path(), 1).unwrap();
            let mut evil = Vec::new();
            while evil.len() < 256 * 1024 {
                evil.extend_from_slice(b"SKJ1");
                evil.extend_from_slice(&(64 * 1024u32).to_le_bytes()); // a len that fits
                evil.extend_from_slice(&0u32.to_le_bytes()); // a crc that will not
                evil.extend_from_slice(&[0u8; 4]);
            }
            writer
                .commit_txn(1, vec![evil], || {})
                .expect("fixture commit");
            writer
                .commit_txn(2, vec![journal::encode_record(&20u64).unwrap()], || {})
                .expect("fixture commit");
        }
        // Break the frame carrying those bytes, so the scan resynchronizes
        // into them: every planted header is then a candidate whose CRC must
        // be computed.
        let seg = journal::segment_path(dir.path(), 1);
        let mut data = fs::read(&seg).unwrap();
        data[journal::FRAME_HEADER_LEN + 1] ^= 0xFF;
        fs::write(&seg, &data).unwrap();

        let err = Kernel::<Vec<u64>>::open(cfg(dir.path(), BurnedSeqPolicy::Rollback), Vec::new())
            .expect_err("a stream that cannot be enumerated is not one to recover from");
        assert!(
            matches!(err, OpenError::Corruption { at: Seq(0), .. }),
            "got {err:?}"
        );
        // A halt cuts nothing — and here there is not even an outcome a
        // truncation could be aimed with.
        assert_eq!(
            fs::read(&seg).unwrap(),
            data,
            "a halted open truncated the journal"
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
            let record = journal::encode_record(&10u64).unwrap();
            writer
                .commit_txn(u64::MAX, vec![record], || {})
                .expect("fixture commit");
        }
        // A torn tail past the last committed marker, so there IS something a
        // truncation would take — without it the cut lands at end-of-file and
        // the assertion below could not tell a halt from a truncation.
        let seg = journal::segment_path(dir.path(), 1);
        {
            use std::io::Write as _;
            let mut f = std::fs::OpenOptions::new().append(true).open(&seg).unwrap();
            f.write_all(&[0xAB, 0xCD, 0xEF]).unwrap();
        }
        let before = fs::read(&seg).unwrap();

        let err = Kernel::<Vec<u64>>::open(cfg(dir.path(), BurnedSeqPolicy::Rollback), Vec::new())
            .expect_err("a head with no successor coordinate is unaccountable");
        assert!(
            matches!(err, OpenError::Corruption { at: Seq(u64::MAX), .. }),
            "got {err:?}"
        );
        // A halt cuts nothing: the exhausted order is judged before the tail
        // truncation, so the store an operator images after a `Corruption` is
        // the store that was there.
        assert_eq!(
            fs::read(&seg).unwrap(),
            before,
            "a halted open truncated the journal"
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
        k.applier.state.lock().seq.high_water = u64::MAX;
        let out = k.transact::<_, ()>(&[], |stg| {
            stg.push(10);
            Ok(())
        });
        assert!(matches!(out, Err(TxnError::Poisoned)), "got {out:?}");
        assert!(k.is_poisoned());
        assert_eq!(k.snapshot().world().as_slice(), &[] as &[u64]);
    }

    #[test]
    fn retain_checkpoints_zero_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let bad_cfg = KernelConfig {
            durability: Durability::Fsync {
                journal_path: dir.path().to_path_buf(),
                retain_checkpoints: 0,
                burned_seq: BurnedSeqPolicy::Rollback,
            },
            checkpoint: CheckpointPolicy::Manual,
        };
        let err = Kernel::<Vec<u64>>::open(bad_cfg.clone(), Vec::new())
            .err()
            .unwrap();
        // A configuration this kernel does not offer, not an environmental
        // failure: it says so on its own channel, so a caller backing off and
        // retrying `Io` does not retry a caller's bug forever.
        assert!(
            matches!(err, OpenError::InvalidConfig("retain_checkpoints must be >= 1")),
            "got {err:?}"
        );

        // …and it precedes the journal lock. With a kernel already holding this
        // journal, a validation done later would answer `Io` — the acquisition
        // failure — and a caller backing off on `Io` would retry a config bug
        // forever, looking for a second process that is the wrong culprit.
        let live = Kernel::<Vec<u64>>::open(cfg(dir.path(), BurnedSeqPolicy::Rollback), Vec::new())
            .expect("the first open holds the journal lock");
        let err = Kernel::<Vec<u64>>::open(bad_cfg, Vec::new()).err().unwrap();
        assert!(matches!(err, OpenError::InvalidConfig(_)), "got {err:?}");
        drop(live);
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
        k.transact::<_, ()>(&[], |stg| {
            stg.push(10);
            Ok(())
        })
        .unwrap();
        // A healthy kernel says so, which is what makes the answer below a
        // report of the flag the three refusals are built from rather than a
        // constant.
        assert!(!k.is_poisoned());
        k.poisoned.store(true, Ordering::Release);
        assert!(k.is_poisoned());

        // Writes halt — and `f` never runs: the refusal precedes it.
        let ran = std::cell::Cell::new(false);
        let out = k.transact::<(), ()>(&[], |stg| {
            ran.set(true);
            stg.push(20);
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
        // …and the bounded read too: it is neither a write nor a checkpoint,
        // so the poison has no refusal to offer it (§5/Invariants).
        assert_eq!(k.world_at(Seq(1)).unwrap().as_slice(), &[10]);
        // flush stays a no-op Ok.
        k.flush().unwrap();
    }

    #[test]
    fn a_poisoned_in_memory_kernel_refuses_a_checkpoint_rather_than_answering_the_no_op() {
        // §6: `Poisoned` outranks every other answer, "the in-memory no-op
        // included". Its sibling pins what poison MEANS and stays under
        // `Fsync` on purpose, so this precedence rides on no other test.
        let cfg = KernelConfig {
            durability: Durability::InMemory,
            checkpoint: CheckpointPolicy::Manual,
        };
        let k = Kernel::<Vec<u64>>::open(cfg, Vec::new()).unwrap();
        k.transact::<_, ()>(&[], |stg| {
            stg.push(10);
            Ok(())
        })
        .unwrap();
        // A healthy in-memory kernel DOES answer the no-op, which is what
        // makes the refusal below a precedence rather than a constant.
        assert_eq!(k.checkpoint().unwrap(), Seq(1));

        k.poisoned.store(true, Ordering::Release);
        let out = k.checkpoint();
        assert!(matches!(out, Err(CheckpointError::Poisoned)), "got {out:?}");
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
                    k.transact::<_, ()>(&[], |stg| {
                        stg.push(x);
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
                cp.load::<Vec<u64>>().is_some(),
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
        let (_, s1) = k.transact::<_, ()>(&[], |stg| {
            stg.push(10);
            Ok(())
        })
        .unwrap();
        let (_, s2) = k.transact::<_, ()>(&[], |stg| {
            stg.push(20);
            stg.push(30); // a composite: seqs 2..=3, boundary 3
            Ok(())
        })
        .unwrap();
        let (_, s3) = k.transact::<_, ()>(&[], |stg| {
            stg.push(40);
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
            k.transact::<_, ()>(&[], |stg| {
                stg.push(x);
                Ok(())
            })
            .unwrap();
        }
        assert_eq!(k.checkpoint().unwrap(), Seq(3));
        k.transact::<_, ()>(&[], |stg| {
            stg.push(40);
            Ok(())
        })
        .unwrap();
        assert_eq!(k.world_at(Seq(1)).unwrap(), vec![10]);
        assert_eq!(k.world_at(Seq(3)).unwrap(), vec![10, 20, 30]);
        assert_eq!(k.world_at(Seq(4)).unwrap(), vec![10, 20, 30, 40]);
    }

    #[test]
    fn world_at_is_unjournaled_in_memory_at_every_boundary() {
        // `Unjournaled` is a property of the kernel that no choice of `at`
        // can avoid, so it outranks every question about `at` — including
        // the boundary judgment, which would otherwise answer `BeyondHead`
        // above the head and send a caller walking `at` down to genesis
        // before learning that no boundary here was ever answerable.
        let cfg = KernelConfig {
            durability: Durability::InMemory,
            checkpoint: CheckpointPolicy::Manual,
        };
        let k = Kernel::<Vec<u64>>::open(cfg, Vec::new()).unwrap();
        for x in [10u64, 20] {
            k.transact::<_, ()>(&[], |stg| {
                stg.push(x);
                Ok(())
            })
            .unwrap();
        }
        for at in [Seq(0), Seq(1), Seq(2), Seq(3), Seq(99)] {
            assert!(
                matches!(k.world_at(at), Err(HistoryError::Unjournaled)),
                "at {at} answered something other than Unjournaled"
            );
        }
    }
}
