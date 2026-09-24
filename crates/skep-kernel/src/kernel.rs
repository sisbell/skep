//! The kernel: single-applier transaction commit (§3), lock-free snapshot
//! reads (§5), on-commit checkpointing (§6), and two-pass recovery (§7).

use std::fmt;
use std::fs::{self, File};
use std::io;
use std::num::NonZeroU64;
use std::ops::{Deref, DerefMut};
use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwap;
use parking_lot::{Mutex, MutexGuard};

use crate::checkpoint;
use crate::config::{BurnedSeqPolicy, CheckpointPolicy, Durability, KernelConfig, SaltSource};
use crate::error::{CheckpointError, HistoryError, OpenError, TxnError};
use crate::journal::{
    self, CommitFail, FirstSyncWord, Journal, JournalWriter, ScanFail, UnwindRepair,
};
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
    /// The commit chain's value at `seq`: what the transaction that installed
    /// this root carried in its marker, or what recovery derived for the
    /// committed head. Paired with the coordinate for the reason the world
    /// is — a checkpoint taken off this root writes it as the header's
    /// `chain_head`, and a chain read apart from the root it names would
    /// commit a later world under an earlier boundary.
    /// [`journal::CHAIN_GENESIS`] at `Seq(0)` and, under
    /// [`Durability::InMemory`], at every coordinate: there are no frames to
    /// hash, and nothing reads it there.
    chain: [u8; 32],
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
#[must_use = "a snapshot does nothing unless read; taking one and dropping it \
              leaves the kernel exactly as it was"]
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

    /// The commit chain's value AT this view's coordinate — the third
    /// constituent the root carries, beside [`Snapshot::seq`] and
    /// [`Snapshot::world`]: the `chain` the marker closing that coordinate's
    /// transaction carries on disk, or what recovery derived for the
    /// committed head. The seed (`journal::CHAIN_GENESIS`, thirty-two zero
    /// bytes) at `Seq(0)` and, under [`Durability::InMemory`], at every
    /// coordinate: there are no frames to hash. By value (`[u8; 32]: Copy`).
    ///
    /// Read it off the SAME snapshot as the [`Snapshot::seq`] it is paired
    /// with — the multi-read rule above — and `(seq(), chain())` names one
    /// committed state: the chain OF that position. [`Kernel::current_seq`]
    /// and [`Kernel::chain_head`] read the same two fields lock-free, but in
    /// two loads, between which a commit may land. `/health`'s pair (QUEUE
    /// item 10, piece (c)) is read here, through one root load.
    pub fn chain(&self) -> [u8; 32] {
        self.0.chain
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

/// What a JOURNALED kernel has and an in-memory one does not: where its files
/// live, how many checkpoint bases its `BadCheckpoint` fallback chain keeps,
/// the Σ₀ its derivations fold onto when no checkpoint covers a boundary, and
/// the `open()`-held exclusion lock it holds for its lifetime (Lifecycle, §6).
///
/// One value rather than several optional fields, so "is there a journal?" is
/// one question with one answer: under [`Durability::InMemory`] there is no
/// directory, no fallback chain, nothing to derive and nothing to exclude, and
/// the caller's `genesis` is consumed into the root rather than kept.
struct Journaled<W> {
    dir: PathBuf,
    retain_checkpoints: usize,
    /// Σ₀ — the genesis world this kernel was opened under, kept because it is
    /// the base every derivation falls back to when no checkpoint covers the
    /// boundary ([`Kernel::world_at`]).
    genesis: W,
    /// The `open()`-held exclusive advisory lock, kept for its `Drop`: the
    /// flock releases when this file closes (Lifecycle).
    _lock: File,
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
    /// The journaled half, or `None` under [`Durability::InMemory`]: every
    /// path that touches files asks here, so the mode question is one question
    /// with one answer. LAST, so the exclusion lock it carries drops after the
    /// applier's appender — a kernel releases its journal only once it has
    /// stopped writing to it.
    journaled: Option<Journaled<W>>,
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
    /// the root is initialized directly from `genesis` (`S_load = 0`);
    /// [`WorldState::rebuild_derived`] is NOT run, so `genesis` is installed
    /// exactly as given — which is why that value must already carry its own
    /// derived hints ([`WorldState::rebuild_derived`]'s genesis obligation).
    ///
    /// DAMAGE MODEL — three outcomes, pinned case by case by the chain's
    /// tamper matrix (`tests/it/chain.rs`; QUEUE item 10, piece (b)) against
    /// a FILE-LEVEL WRITER of the data directory who can rewrite any byte and
    /// re-fix any CRC. What recovery detects is FRAMES THAT FAIL THEIR CRC —
    /// the corrupt-run verdict, which speaks first where there is one — and,
    /// since `SKJ3`, LINKS THAT FAIL THE CHAIN, the base's own link and the
    /// transaction its marker does not close among them (the chain's open
    /// items, 2026-09-23).
    ///
    /// CAUGHT — a chain break: [`OpenError::Corruption`] naming the
    /// `last_seq` of the first committed transaction above the base whose
    /// marker's chain is not the recomputation over its predecessor's value
    /// and its own record frames, the cause travelling and nothing cut. A
    /// record payload rewritten with every CRC re-fixed, at that transaction;
    /// a marker's chain field edited, at that transaction, the next never
    /// masking it; two transactions swapped, at the one now sitting first; a
    /// transaction deleted and the file closed up, a closed segment rolled
    /// back to an older copy of itself, a closed segment ABSENT — each at the
    /// next transaction, the one chaining from a predecessor the scan never
    /// saw (§7 requires no `Seq` contiguity, so by coordinates alone each of
    /// these was once a shorter world answered `Ok` at the true head); two
    /// damages, at the first only — the chain cannot see past a break. A
    /// checkpoint's `chain_head` edited, at the base's own coordinate where
    /// the marker closing it is scanned — AT THE HEAD always, the head's
    /// marker being in the active segment — and at the first transaction
    /// above it otherwise: nothing in the header covers that field, so the
    /// base loads and the journal contradicts it, at its own marker where
    /// that marker is read, else at the first link judged against it. A
    /// marker's `records_checksum` or `last_seq` edited, AT that
    /// transaction, as an intact transaction its marker does not close — a
    /// shape no writer of this format leaves, so the marker was rewritten;
    /// on the LAST transaction too, where un-committing it would otherwise
    /// have been the torn tail recovery cuts. The signature slot is NOT a
    /// chain input, by design: a filled slot opens. The SALT IS one (`SKJ4`,
    /// the matrix's case 16): a marker's salt edited, its CRC re-fixed, is
    /// caught at that transaction — and being drawn at random per
    /// transaction and served by no route, it is what keeps a served chain
    /// value from confirming a guess at a transaction's bytes, while against
    /// a party holding the journal, who holds the bytes, it protects nothing.
    ///
    /// REFUSED — the checkpoint's own door: a body rewritten with its CRC
    /// re-fixed fails `body_hash`, the fallback reaches an older base or
    /// genesis, and the journal above it re-verifies.
    ///
    /// NOT CAUGHT BY DESIGN — histories the chain alone accepts, which the
    /// ruling assigns to piece 2, the PUBLISHED HEAD ([`Kernel::chain_head`]
    /// is its input; a peer holding an older head checks that the new
    /// history EXTENDS it — against the board's recomputation through
    /// [`Kernel::chain_at`], which the daemon serves as `GET /chain?at=N`).
    /// A CLEAN TAIL CUT — the last transactions removed at a boundary —
    /// opens at the shorter head. A CONSISTENT RE-CHAIN — a rewrite at any
    /// point with every later link recomputed, from genesis or mid-history,
    /// the retained checkpoints' heads rewritten with it — passes: the chain
    /// has no anchor but its seed and the base's header, and a base's BODY,
    /// which nothing compares to the journal below it, the forger re-mints
    /// with this kernel's own `checkpoint()` over the forged replay. A
    /// checkpoint BODY forged with its CRC and `body_hash` re-fixed loads as
    /// the base. The base's own link has three residues: (i) the header AND
    /// the marker closing its seq edited consistently, every link above
    /// re-chained from the edit — the open passes, and a bounded read below
    /// the base recomputes the link at the base's seq over its predecessor
    /// and fails it, unless the forger re-chained from below that too,
    /// which is the consistent re-chain; (ii) the base's marker segment
    /// RECLAIMED or SKIPPED — a closed segment ending exactly at the base's
    /// seq, the boundary coincidence — where the check is vacuous and the
    /// open behaves as before: the first link above the base is judged
    /// against the header, and a header edited with nothing above it opens
    /// on the edit; (iii) two retained checkpoints edited consistently with
    /// the journal re-chained between them, the consistent re-chain again.
    /// And the ruling's "any rewrite", as the owner reads it (the matrix's
    /// case 12, 2026-09-23): the chain is verified for transactions above
    /// the base a replay selects, so a rewrite BELOW a standing base is
    /// unseen at `open` while that base stands, seen by any bounded read
    /// below the base — which verifies every link from the base it selects
    /// to the journal's end — and beyond any replay once reclamation drops
    /// the segment. The `journal_path` caller contract still keeps the
    /// files whole; what it no longer has to keep is the silence.
    ///
    /// REFUSAL PRECEDENCE — the steps above are the order in which refusals
    /// speak: [`OpenError::InvalidConfig`] precedes the lock, the lock
    /// precedes any read of the journal, [`OpenError::BadCheckpoint`]
    /// precedes the first-sync-word probe — the first scanned segment's
    /// opening is read once the base has said where the scan begins, and
    /// before a byte of the scan — which answers [`OpenError::ForeignFormat`]
    /// for a journal of another format and [`OpenError::Corruption`] for one
    /// damaged sync word; and EVERY route to `Corruption`, in the order they
    /// speak — the damaged sync word, an unenumerable or oversized segment,
    /// the classified corrupt run, the base's own link, the intact
    /// transaction its marker does not close, the chain break, the exhausted
    /// `Seq` order, and the fold's own verdict on an undecodable or repeated
    /// record — precedes the tail truncation, which is why a halt never cuts
    /// anything.
    ///
    /// CALLER CONTRACT — `genesis` (= Σ₀) MUST be byte-identical on every
    /// `open()` of a given journal: recovery folds journaled DELTAS onto it,
    /// never onto a journaled root; a drifting `genesis` silently
    /// mis-recovers. M2 cannot check this (ASN-0047's fixed Σ₀ satisfies it
    /// by construction).
    pub fn open(cfg: KernelConfig, genesis: W) -> Result<Self, OpenError> {
        cfg.validate().map_err(OpenError::InvalidConfig)?;
        let (root, journal, journaled) = match &cfg.durability {
            // "Directly from genesis" (Lifecycle): no journal, no recovery,
            // no rebuild_derived — the caller's live value BECOMES the root,
            // and nothing else here wants it, so it is moved rather than kept.
            Durability::InMemory => (
                Committed {
                    seq: Seq(0),
                    world: genesis,
                    chain: journal::CHAIN_GENESIS,
                },
                Journal::InMemory,
                None,
            ),
            Durability::Fsync {
                journal_path,
                retain_checkpoints,
                ..
            } => {
                let (root, journal, lock) = Self::recover(journal_path, &genesis, cfg.salt)?;
                (
                    root,
                    journal,
                    Some(Journaled {
                        dir: journal_path.clone(),
                        retain_checkpoints: *retain_checkpoints,
                        genesis,
                        _lock: lock,
                    }),
                )
            }
        };
        Ok(Self::assemble(cfg, root, journal, journaled))
    }

    /// Recover the journal at `dir` into the root it commits from, its live
    /// appender — handed `salt`, the configured [`SaltSource`] every
    /// transaction it commits draws from (`SKJ4`); recovery itself draws
    /// nothing, reading each salt off its marker — and the exclusion lock the
    /// kernel holds for its lifetime (§7).
    fn recover(
        dir: &Path,
        genesis: &W,
        salt: SaltSource,
    ) -> Result<(Committed<W>, Journal, File), OpenError> {
        fs::create_dir_all(dir)?;
        let lock = journal::acquire_journal_lock(dir)?;
        let segs = journal::list_segments(dir)?;
        let checkpoints = checkpoint::list(dir)?;

        // The base, with its whole fallback chain: newest valid retained
        // checkpoint → next-older retained → genesis-while-reachable; an
        // exhausted chain is the operator-intervention condition (§6/§7).
        let base = replay::select_base(&checkpoints, &segs, None, genesis).map_err(|fail| {
            OpenError::BadCheckpoint { cause: fail.cause }
        })?;

        // THE FIRST-SYNC-WORD PROBE, ahead of the scan (the encoding report's
        // §8; the owner's ruling of 2026-09-23). A segment written under
        // another format holds no frame this build's sync word anchors, so
        // the scan would read the whole of it as one corrupt run reaching
        // end-of-file — the un-acked tail — and the cut below would TRUNCATE
        // it to nothing and serve an empty board over a journal it had just
        // erased. Refused by name instead, before a byte is scanned and
        // before anything is written: the files stay as they were found. A
        // single damaged sync word — foreign-shaped, before a frame of this
        // build's — is refused as early, and as the damage it is: its remedy
        // is to restore the segment, where a format's discards the board.
        match journal::first_sync_word(&segs, base.s_load())? {
            FirstSyncWord::Scan => {}
            FirstSyncWord::Foreign(found) => {
                return Err(OpenError::ForeignFormat {
                    found,
                    expected: journal::MAGIC,
                });
            }
            // The probe reads a frame header and no `Seq`, so the coordinate
            // is the base's own: where the scan would have begun.
            FirstSyncWord::Damaged(found) => {
                return Err(OpenError::Corruption {
                    at: Seq(base.s_load()),
                    cause: Some(journal::damaged_sync_word_cause(found)),
                });
            }
        }

        // Pass 1: derive W, classify the corrupt runs and verify the chain
        // (§7). A scan that could not take a segment in within its bounds —
        // enumerate its frame stream in bounded work, or read it in bounded
        // memory — produces no outcome at all and halts here. Of the runs it
        // does report, those beyond W and the EOF ones are the un-acked/torn
        // tail, physically discarded below, and those at or below S_load are
        // already embodied in the base. The run verdict speaks before the
        // chain's: a run that swallowed a transaction breaks the chain at the
        // next one, and the run names the cause.
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
        // The chain's verdicts, in the scan's own order: the base's own link
        // (a header edited at the head, where no link above would judge it),
        // the intact transaction its marker does not close (the edited
        // transaction, named before the next one's link fails on it), the
        // chain break. Each halts here with its account and cuts nothing.
        if let Some((at, cause)) = scan.chain_verdict() {
            return Err(OpenError::Corruption {
                at: Seq(at),
                cause: Some(cause),
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
        // The chain at that head: what the appender continues from and the
        // root carries, so a checkpoint off this root names the right link.
        let chain_head = scan.chain_head;

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

        let writer = JournalWriter::open_active(dir, next_seq, chain_head, salt)?;
        Ok((
            Committed {
                seq: Seq(committed_head),
                world,
                chain: chain_head,
            },
            Journal::Segments(writer),
            lock,
        ))
    }

    fn assemble(
        cfg: KernelConfig,
        root: Committed<W>,
        journal: Journal,
        journaled: Option<Journaled<W>>,
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
            journaled,
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
    /// itself and read the result; a kernel that has stopped checkpointing
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
                state.journal.commit_txn(first, records, move |chain| {
                    // Atomic install AFTER durability (A0/A4; durable-before-
                    // visible §1): external readers see none-or-all. The
                    // root carries the chain the durable marker does.
                    root.store(Arc::new(Committed {
                        seq: Seq(last),
                        world: working,
                        chain,
                    }));
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

    /// The commit chain's value at the installed head: the `chain` the
    /// marker closing [`Kernel::current_seq`]'s transaction carries on disk,
    /// or what recovery derived for that head — the last committed marker's
    /// above the base, else the base's own (the `SKC4` header's
    /// `chain_head`, or the seed at genesis). The seed at every coordinate
    /// under [`Durability::InMemory`], where there are no frames to hash.
    /// Read lock-free off the root, like [`Kernel::current_seq`] and with
    /// the same caveat: equal AT THE INSTANT OF CALL to the value for that
    /// coordinate, and no substitute for reading the two together — a commit
    /// may land between two calls.
    ///
    /// PIECE (c)'S INPUT (QUEUE item 10, the PUBLISHED HEAD; `/health`): what
    /// a periodically published head carries, and what a peer holding an
    /// older head checks the new history EXTENDS — the closer for the
    /// histories the chain alone accepts, which [`Kernel::open`]'s damage
    /// model names.
    pub fn chain_head(&self) -> [u8; 32] {
        self.root.load().chain
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
        let Some(journaled) = &self.journaled else {
            return Ok(self.current_seq()); // nothing to persist or reclaim (§6)
        };
        let _serial = self.checkpoint_mutex.lock();
        let snap = self.root.load_full();
        let s = snap.seq;
        // The seq, the world and the chain head off ONE root: a checkpoint
        // names the chain at its own coordinate, never a later root's.
        checkpoint::write(&journaled.dir, s.0, &snap.world, &snap.chain).map_err(|fail| {
            match fail {
                checkpoint::WriteFail::Serialize(e) => CheckpointError::Serialize(e),
                checkpoint::WriteFail::Io(e) => CheckpointError::Io(e),
            }
        })?;
        // Retention policy — how many bases to keep — applied to the
        // checkpoint set, which answers with the oldest survivor. There is
        // always one: `retain_checkpoints ≥ 1` is validated at `open`, and
        // this call has just added to the set the retention is applied to.
        let s_old = checkpoint::retain(&journaled.dir, journaled.retain_checkpoints)?
            .expect("retention keeps N ≥ 1 of a set this call just added to");
        // Reclaim the journal below the OLDEST retained checkpoint — that
        // floor, not the newest, is what keeps the BadCheckpoint fallback
        // real (§6).
        journal::reclaim_below(&journaled.dir, s_old)?;
        Ok(s)
    }

    /// The NEWEST RETAINED checkpoint's coordinate and the two hashes its
    /// `SKC4` header carries — `(seq, chain_head, body_hash)` — or `None` under
    /// [`Durability::InMemory`] and before the first checkpoint. ADDITIVE
    /// (QUEUE item 10 piece 2, the PUBLISHED HEAD): what a head record's `base`
    /// member names (PUB-6.65), so a peer that copies a checkpoint file has its
    /// coordinate attested, a full replica verifies the base's canonical body
    /// by `body_hash`, and the coordinate survives the retention
    /// (`retain_checkpoints`) that drops the file — the base is the one durable
    /// record of a reclaimed checkpoint's coordinate.
    ///
    /// Reads the newest file's HEADER ALONE — its fixed 88 bytes, never the
    /// body, which is the whole serialized world — so it costs one directory
    /// list and one short read whatever the world's size. The header is read
    /// through the checkpoint module's one header parse and held to every
    /// check a header can pass without its body: this build's stamp, and a
    /// seq agreeing with the file's name. A header either check refuses names
    /// no base: `None`, as on any I/O error or a file shorter than its own
    /// header — FAIL-QUIET, because the head writer that reads this must never
    /// fail a commit over it, and writes `base: null` instead. The body is NOT
    /// verified: its checksum and hash need the body, and `body_hash` is what
    /// a party holding the file verifies it by. Lock-free, like
    /// [`Kernel::chain_head`]: it consults the directory, not the applier, so a
    /// checkpoint racing this read is at worst not-yet-seen — or, removed by a
    /// racing retention between the listing and the read, `None` — and never a
    /// torn one (a checkpoint is renamed into place whole).
    pub fn newest_checkpoint(&self) -> Option<(Seq, [u8; 32], [u8; 32])> {
        let journaled = self.journaled.as_ref()?;
        // `list` is ascending by seq (§6), so the last entry is the newest.
        let newest = checkpoint::list(&journaled.dir).ok()?.pop()?;
        let header = newest.header().ok()?;
        Some((Seq(newest.seq), header.chain_head, header.body_hash))
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
        let Some(journaled) = &self.journaled else {
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
        let checkpoints = checkpoint::list(&journaled.dir)?;
        let segs = journal::list_segments(&journaled.dir)?;
        let base = replay::select_base(&checkpoints, &segs, Some(at.0), &journaled.genesis)
            .map_err(|fail| HistoryError::Reclaimed {
                floor: fail.floor.map(Seq),
                cause: fail.cause,
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
        // The chain's verdicts — the base's own link, the intact transaction
        // its marker does not close, the chain break — anywhere above the
        // base are at-rest damage for the reason a run anywhere is: the link
        // that failed may sit above `at`, and what it says is that the
        // region is not the history it claims.
        if let Some((verdict_at, cause)) = scan.chain_verdict() {
            return Err(HistoryError::Corruption {
                at: Seq(verdict_at),
                cause: Some(cause),
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

    /// The commit chain's value AS OF boundary `at` — the `chain` the marker
    /// closing `at`'s transaction carries, READ-ONLY off this kernel's own
    /// journal directory under the verification [`Kernel::world_at`] runs,
    /// with no world folded and none kept (QUEUE item 10, the chain's open
    /// items: `chain_at(N)`). What a peer holding a saved `(position,
    /// chain)` pair — a `/health` reading, a published head's members —
    /// checks against the board's RECOMPUTATION rather than against the
    /// board's stored claim: a re-chained journal answers the forgery here,
    /// which the saved value contradicts, where the claim it left untouched
    /// would still byte-compare. At the installed head this equals
    /// [`Kernel::chain_head`]; at `0` it is the seed.
    ///
    /// THE SAME DERIVATION as `world_at`, bound for bound: the same base
    /// selection capped at `at`, the same scan above it — which verifies
    /// every committed link from that base to the journal's END, not to
    /// `at`, so a boundary below the newest checkpoint is a full
    /// verification of the surviving journal from the base it selects — the
    /// same refusals in the same order ([`HistoryError::Unjournaled`],
    /// [`HistoryError::BeyondHead`], [`HistoryError::Reclaimed`],
    /// [`HistoryError::Corruption`] — the corrupt run, then the chain's own
    /// verdicts — then [`HistoryError::NotABoundary`]), and the same answer
    /// for a boundary that IS the base: the base's own chain, the `SKC4`
    /// header's `chain_head` or the seed at genesis, answered without
    /// consulting the journal and so never halting. Deterministic in `at`
    /// across calls, processes and base choices, since a checkpoint's header
    /// carries the very marker value it stands in for.
    ///
    /// COST, per call, uncached: `world_at`'s minus the fold and the resident
    /// world — the base is still LOADED, since its body hash is the base's
    /// door and the header is read through it, and every segment above the
    /// base is still READ and its committed records at or below `at` still
    /// collected; the world is dropped unfolded. Admission and concurrency
    /// are the caller's to gate, as they are there; safe beside the live
    /// appender and `checkpoint()` for the same reasons, with the same two
    /// transient refusals.
    pub fn chain_at(&self, at: Seq) -> Result<[u8; 32], HistoryError> {
        let Some(journaled) = &self.journaled else {
            return Err(HistoryError::Unjournaled);
        };
        let installed_head = self.current_seq();
        if at > installed_head {
            return Err(HistoryError::BeyondHead {
                head: installed_head,
            });
        }
        let checkpoints = checkpoint::list(&journaled.dir)?;
        let segs = journal::list_segments(&journaled.dir)?;
        let base = replay::select_base(&checkpoints, &segs, Some(at.0), &journaled.genesis)
            .map_err(|fail| HistoryError::Reclaimed {
                floor: fail.floor.map(Seq),
                cause: fail.cause,
            })?;
        let scan_failed = |fail| match fail {
            ScanFail::Io(e) => HistoryError::Io(e),
            ScanFail::Unbounded { at } => HistoryError::Corruption {
                at: Seq(at),
                cause: None,
            },
        };
        // A boundary that IS the base is the base's own chain — what
        // `select_base` read off the header (or the seed) and `Base` keeps
        // behind its one seam. A scan over NO segments commits nothing above
        // the base, so its running value is exactly that, at no I/O and with
        // nothing to halt on: the journal is not consulted, as `world_at`
        // does not consult it for the base's own world.
        if at.0 == base.s_load() {
            return base.scan(&[], None).map(|nothing_above| nothing_above.chain_head).map_err(scan_failed);
        }
        let scan = base.scan(&segs, Some(at.0)).map_err(scan_failed)?;
        if let Some(run_at) = scan.fatal_run_anywhere() {
            return Err(HistoryError::Corruption {
                at: Seq(run_at),
                cause: None,
            });
        }
        if let Some((verdict_at, cause)) = scan.chain_verdict() {
            return Err(HistoryError::Corruption {
                at: Seq(verdict_at),
                cause: Some(cause),
            });
        }
        // The scan was collected to exactly `at`, above its base, so the chain
        // it captured there answers both whether `at` is a boundary and the
        // value at it.
        scan.chain_at_boundary(at.0).map_err(|nearest| HistoryError::NotABoundary {
            nearest: Seq(nearest),
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
        fn apply(&self, record: &u64) -> Self {
            let mut v = self.clone();
            v.push(*record); // non-idempotent, as the design's replay argument assumes
            v
        }
    }

    /// The seeded salt source these fixtures write under, named once.
    const TEST_SEED: u64 = 0x2B;

    fn cfg(dir: &std::path::Path, burned_seq: BurnedSeqPolicy) -> KernelConfig {
        KernelConfig {
            durability: Durability::Fsync {
                journal_path: dir.to_path_buf(),
                retain_checkpoints: 1,
                burned_seq,
            },
            checkpoint: CheckpointPolicy::Manual,
            salt: SaltSource::Seeded(TEST_SEED),
        }
    }

    /// A fresh appender at genesis, for the journals these tests build
    /// without a kernel.
    fn fresh_writer(dir: &std::path::Path) -> JournalWriter {
        JournalWriter::open_active(dir, 1, journal::CHAIN_GENESIS, SaltSource::Seeded(TEST_SEED))
            .unwrap()
    }

    /// [`Kernel::newest_checkpoint`] (QUEUE item 10 piece 2, the head's `base`):
    /// `None` until a checkpoint exists, then the header's triple — the
    /// checkpointed seq, the chain at it (equal to [`Kernel::chain_head`]), and
    /// the SHA-256 of the body `checkpoint()` wrote. Read off the header alone:
    /// a file cut to its header answers the same, and a header under another
    /// format's stamp names no base.
    #[test]
    fn newest_checkpoint_is_none_then_the_header_triple() {
        let dir = tempfile::tempdir().unwrap();
        let kernel =
            Kernel::<Vec<u64>>::open(cfg(dir.path(), BurnedSeqPolicy::Rollback), Vec::new()).unwrap();
        assert_eq!(kernel.newest_checkpoint(), None, "no checkpoint has been taken yet");

        kernel
            .transact::<_, ()>(&[], |stg| {
                stg.push(7u64);
                Ok(())
            })
            .unwrap();
        let s = kernel.checkpoint().expect("one checkpoint");

        let (seq, chain_head, body_hash) =
            kernel.newest_checkpoint().expect("a checkpoint now exists");
        assert_eq!(seq, s, "the newest checkpoint's own seq");
        assert_eq!(
            chain_head,
            kernel.chain_head(),
            "the header's chain_head is the chain at the checkpointed head"
        );
        // 88: the header length the checkpoint layout test pins.
        let path = dir.path().join(format!("checkpoint.{}", s.0));
        let full = fs::read(&path).unwrap();
        assert_eq!(
            body_hash,
            <[u8; 32]>::from(<sha2::Sha256 as sha2::Digest>::digest(&full[88..])),
            "the body hash is the SHA-256 of the body written"
        );

        // Read off the header ALONE: cut to its first 88 bytes, the file
        // answers the same triple — where a read through `load` would read,
        // hash and decode a body that is no longer there, and refuse.
        fs::write(&path, &full[..88]).unwrap();
        assert_eq!(
            kernel.newest_checkpoint(),
            Some((seq, chain_head, body_hash)),
            "the triple is the header's, whatever follows it"
        );

        // …and held to what a header can be checked for without its body: under
        // another format's stamp, its bytes 24..88 are not this format's hashes,
        // and the newest checkpoint names no base at all.
        let mut foreign = full[..88].to_vec();
        foreign[..4].copy_from_slice(b"SKC3");
        fs::write(&path, &foreign).unwrap();
        assert_eq!(kernel.newest_checkpoint(), None, "another format's header names no base");
    }

    #[test]
    fn a_journal_under_another_format_is_refused_by_name_and_left_untouched() {
        // The encoding report's §8: under `SKJ2` a foreign-stamp journal was
        // not refused but WIPED — scanned as one corrupt run reaching
        // end-of-file, classified as the un-acked tail, truncated to zero
        // bytes and served as an empty board. Under `SKJ3` it is refused
        // before the scan, naming the stamp found, the stamp expected and the
        // ruled remedy, and every byte is as it was found. The fixture is
        // this build's own journal with every sync word rewritten to `SKJ2`:
        // the frame CRC does not cover the sync word, so this is byte for
        // byte what an old-format file looks like to the parser.
        let dir = tempfile::tempdir().unwrap();
        {
            let k = Kernel::<Vec<u64>>::open(cfg(dir.path(), BurnedSeqPolicy::Rollback), Vec::new())
                .unwrap();
            for x in [10u64, 20] {
                k.transact::<_, ()>(&[], |stg| {
                    stg.push(x);
                    Ok(())
                })
                .unwrap();
            }
        }
        let seg = journal::segment_path(dir.path(), 1);
        let mut data = fs::read(&seg).unwrap();
        let mut pos = 0usize;
        while pos + journal::FRAME_HEADER_LEN <= data.len() {
            assert_eq!(&data[pos..pos + 4], b"SKJ4", "a clean frame stream");
            data[pos..pos + 4].copy_from_slice(b"SKJ2");
            let len = u32::from_le_bytes(data[pos + 4..pos + 8].try_into().unwrap()) as usize;
            pos += journal::FRAME_HEADER_LEN + len;
        }
        fs::write(&seg, &data).unwrap();

        let err = Kernel::<Vec<u64>>::open(cfg(dir.path(), BurnedSeqPolicy::Rollback), Vec::new())
            .expect_err("another format's journal is not this build's to open");
        assert!(
            matches!(
                err,
                OpenError::ForeignFormat {
                    found: [b'S', b'K', b'J', b'2'],
                    expected: [b'S', b'K', b'J', b'4'],
                }
            ),
            "got {err:?}"
        );
        let rendered = err.to_string();
        for named in ["`SKJ2`", "`SKJ4`", "not this build's format", "delete the data directory"] {
            assert!(rendered.contains(named), "{named} missing from: {rendered}");
        }
        assert!(std::error::Error::source(&err).is_none());
        assert_eq!(fs::read(&seg).unwrap(), data, "the refused journal was touched");
        // …and it keeps refusing: a halt writes nothing, so nothing repairs it.
        assert!(matches!(
            Kernel::<Vec<u64>>::open(cfg(dir.path(), BurnedSeqPolicy::Rollback), Vec::new()),
            Err(OpenError::ForeignFormat { .. })
        ));
        assert_eq!(fs::read(&seg).unwrap(), data);

        // Damage at offset 0 is NOT a format event: it stays the scan's — here
        // a torn first frame with nothing committed after it, which is the
        // un-acked tail, cut and served empty, as the dirty-crash suite pins.
        let mut junk = data.clone();
        junk[..4].copy_from_slice(&[0xAB, 0xCD, 0xEF, 0x01]);
        // Every frame back to this build's stamp but the first, which is junk.
        let mut pos = 0usize;
        while pos + journal::FRAME_HEADER_LEN <= junk.len() {
            if pos > 0 {
                junk[pos..pos + 4].copy_from_slice(b"SKJ4");
            }
            let len = u32::from_le_bytes(junk[pos + 4..pos + 8].try_into().unwrap()) as usize;
            pos += journal::FRAME_HEADER_LEN + len;
        }
        fs::write(&seg, &junk).unwrap();
        let out = Kernel::<Vec<u64>>::open(cfg(dir.path(), BurnedSeqPolicy::Rollback), Vec::new());
        assert!(
            !matches!(out, Err(OpenError::ForeignFormat { .. })),
            "junk at offset 0 was read as a format stamp: {out:?}"
        );
    }

    #[test]
    fn one_damaged_sync_word_is_refused_as_damage_not_as_another_format() {
        // Every one-bit flip of this build's numeral keeps the `SKJ` prefix,
        // and the frame CRC does not cover the sync word — so one flipped bit
        // at byte 3 of the first frame reads, by its word alone, as a board of
        // another format, whose ruled remedy is to delete the data directory.
        // The frame after it still opens with this build's stamp, which no
        // other format's journal does: the open refuses it as the damage it
        // is, before the scan and before any write, with a remedy that keeps
        // the board.
        let dir = tempfile::tempdir().unwrap();
        {
            let k = Kernel::<Vec<u64>>::open(cfg(dir.path(), BurnedSeqPolicy::Rollback), Vec::new())
                .unwrap();
            for x in [10u64, 20] {
                k.transact::<_, ()>(&[], |stg| {
                    stg.push(x);
                    Ok(())
                })
                .unwrap();
            }
        }
        let seg = journal::segment_path(dir.path(), 1);
        let mut data = fs::read(&seg).unwrap();
        data[3] ^= 0x01; // `SKJ4` → `SKJ5`
        fs::write(&seg, &data).unwrap();

        let err = Kernel::<Vec<u64>>::open(cfg(dir.path(), BurnedSeqPolicy::Rollback), Vec::new())
            .expect_err("a damaged sync word is not a board to open");
        assert!(
            matches!(err, OpenError::Corruption { at: Seq(0), cause: Some(_) }),
            "got {err:?}"
        );
        let rendered = err.to_string();
        for named in ["damaged sync word", "`SKJ5`", "`SKJ4`"] {
            assert!(rendered.contains(named), "{named} missing from: {rendered}");
        }
        assert!(
            !rendered.contains("delete the data directory"),
            "one damaged word was answered with the remedy for another format: {rendered}"
        );
        assert!(std::error::Error::source(&err).is_some(), "the account travels");
        assert_eq!(fs::read(&seg).unwrap(), data, "a halted open touched the segment");
        // …and it keeps refusing: a halt writes nothing, so nothing repairs it.
        assert!(matches!(
            Kernel::<Vec<u64>>::open(cfg(dir.path(), BurnedSeqPolicy::Rollback), Vec::new()),
            Err(OpenError::Corruption { at: Seq(0), .. })
        ));
        assert_eq!(fs::read(&seg).unwrap(), data);
    }

    #[test]
    fn a_chain_break_halts_the_open_and_the_bounded_read_and_cuts_nothing() {
        // Three commits; the second's marker rewritten consistently with its
        // frame CRC. Every frame is intact and every group commits, so
        // nothing but the chain can see it — and the open halts on it, at
        // the coordinate the rewritten transaction closes, with an account,
        // truncating nothing; the bounded read halts the same way.
        let dir = tempfile::tempdir().unwrap();
        // The chain at 3 as the writer left it, for the base below: a
        // checkpoint at the head carries the marker's own chain, and the
        // open judges that link.
        let chain_at_3 = {
            let k = Kernel::<Vec<u64>>::open(cfg(dir.path(), BurnedSeqPolicy::Rollback), Vec::new())
                .unwrap();
            for x in [10u64, 20, 30] {
                k.transact::<_, ()>(&[], |stg| {
                    stg.push(x);
                    Ok(())
                })
                .unwrap();
            }
            k.chain_head()
        };
        let seg = journal::segment_path(dir.path(), 1);
        let mut data = fs::read(&seg).unwrap();
        // Frames: 0=T1 rec, 1=T1 marker, 2=T2 rec, 3=T2 marker, …
        let mut starts = Vec::new();
        let mut pos = 0usize;
        while pos + journal::FRAME_HEADER_LEN <= data.len() {
            starts.push(pos);
            let len = u32::from_le_bytes(data[pos + 4..pos + 8].try_into().unwrap()) as usize;
            pos += journal::FRAME_HEADER_LEN + len;
        }
        let marker = starts[3];
        let len = u32::from_le_bytes(data[marker + 4..marker + 8].try_into().unwrap()) as usize;
        let payload = marker + journal::FRAME_HEADER_LEN..marker + journal::FRAME_HEADER_LEN + len;
        data[payload.start + 24] ^= 0xFF; // the chain's first byte
        let crc = crc32c::crc32c_append(
            crc32c::crc32c(&data[marker + 4..marker + 8]),
            &data[payload.clone()],
        );
        data[marker + 8..marker + 12].copy_from_slice(&crc.to_le_bytes());
        // A torn tail past the last committed marker, so there IS something a
        // truncation would take.
        data.extend_from_slice(&[0xAB, 0xCD, 0xEF]);
        fs::write(&seg, &data).unwrap();

        let err = Kernel::<Vec<u64>>::open(cfg(dir.path(), BurnedSeqPolicy::Rollback), Vec::new())
            .expect_err("a broken chain is not something to fold");
        assert!(
            matches!(err, OpenError::Corruption { at: Seq(2), .. }),
            "got {err:?}"
        );
        assert!(err.to_string().contains("chain break"), "got {err}");
        assert!(std::error::Error::source(&err).is_some());
        assert_eq!(fs::read(&seg).unwrap(), data, "a halted open truncated the journal");

        // The bounded read, off a kernel opened over a checkpoint ABOVE the
        // break — the base embodies the rewrite, so the open succeeds — halts
        // on the same break when asked for a boundary below the base.
        fs::write(&seg, &data[..data.len() - 3]).unwrap();
        checkpoint::write(dir.path(), 3, &vec![10u64, 20, 30], &chain_at_3).expect("fixture base");
        let k = Kernel::<Vec<u64>>::open(cfg(dir.path(), BurnedSeqPolicy::Rollback), Vec::new())
            .expect("the base embodies the rewritten transaction");
        assert_eq!(k.current_seq(), Seq(3));
        let err = k
            .world_at(Seq(1))
            .expect_err("a genesis replay meets the break at 2, above the boundary asked");
        assert!(
            matches!(err, HistoryError::Corruption { at: Seq(2), .. }),
            "got {err:?}"
        );
        assert!(err.to_string().contains("chain break"), "got {err}");
    }

    // A world of raw byte records, for the size-refusal tests: `Vec<u64>`'s
    // fixed 8-byte records cannot reach the frame cap or the budget.
    impl WorldState for Vec<Vec<u8>> {
        type Record = Vec<u8>;
        fn apply(&self, record: &Vec<u8>) -> Self {
            let mut v = self.clone();
            v.push(record.clone());
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
            salt: SaltSource::Seeded(TEST_SEED),
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
            let mut writer = fresh_writer(dir.path());
            let rec = |x: u64| journal::encode_record(&x).unwrap();
            // A journal built without a kernel: no root to install into.
            writer
                .commit_txn(1, vec![rec(10)], |_| {})
                .expect("fixture commit");
            // burned 2..=4
            writer
                .commit_txn(5, vec![rec(50), rec(60)], |_| {})
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
            let mut writer = fresh_writer(dir.path());
            let rec = |x: u64| journal::encode_record(&x).unwrap();
            writer
                .commit_txn(1, vec![rec(10)], |_| {})
                .expect("fixture commit");
            writer
                .commit_txn(1, vec![rec(20)], |_| {})
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
        // truncation, so the journal an operator images after a `Corruption`
        // is the journal that was there.
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
            let mut writer = fresh_writer(dir.path());
            // Variant index 5, written where `Narrow` has four.
            writer
                .commit_txn(1, vec![journal::encode_record(&5u32).unwrap()], |_| {})
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
    fn world_at_carries_the_serializers_account_of_a_record_only_history_reaches() {
        // `open()` folds only above its newest base, so a committed record
        // BELOW that base is never decoded by recovery: a journal whose binary
        // retired a record variant opens cleanly, and only a bounded replay
        // from an older base meets the record. `HistoryError::Corruption`
        // promises the account `OpenError::Corruption` carries, and this is
        // the route that reaches it through `world_at`'s own mapping.
        let dir = tempfile::tempdir().unwrap();
        // The base at 2 carries the chain the marker closing 2 carries — the
        // install closure hands it over — as a checkpoint off the root would.
        let mut chain_at_2 = journal::CHAIN_GENESIS;
        {
            let mut writer = fresh_writer(dir.path());
            // Variant index 5, written where `Narrow` has four…
            writer
                .commit_txn(1, vec![journal::encode_record(&5u32).unwrap()], |_| {})
                .expect("fixture commit");
            // …then a record this build reads, and a base embodying both.
            writer
                .commit_txn(2, vec![journal::encode_record(&Narrow::A).unwrap()], |chain| {
                    chain_at_2 = chain
                })
                .expect("fixture commit");
        }
        checkpoint::write(dir.path(), 2, &NarrowWorld(Vec::new()), &chain_at_2)
            .expect("fixture base");

        let k = Kernel::<NarrowWorld>::open(
            cfg(dir.path(), BurnedSeqPolicy::Rollback),
            NarrowWorld(Vec::new()),
        )
        .expect("the newest base embodies the record this build cannot read");
        assert_eq!(k.current_seq(), Seq(2));
        assert!(
            k.world_at(Seq(2)).is_ok(),
            "the base's own boundary answers from the base"
        );
        // `NarrowWorld` is not `Debug`, so not `expect_err`.
        let err = k
            .world_at(Seq(1))
            .err()
            .expect("an undecodable committed record is not something to fold");
        assert!(
            matches!(err, HistoryError::Corruption { at: Seq(1), .. }),
            "got {err:?}"
        );
        let cause = std::error::Error::source(&err)
            .expect("the account is what separates a retired variant from rot")
            .to_string();
        assert!(cause.contains("variant index"), "got {cause}");
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
            let mut writer = fresh_writer(dir.path());
            let mut evil = Vec::new();
            while evil.len() < 256 * 1024 {
                evil.extend_from_slice(b"SKJ4");
                evil.extend_from_slice(&(64 * 1024u32).to_le_bytes()); // a len that fits
                evil.extend_from_slice(&0u32.to_le_bytes()); // a crc that will not
                evil.extend_from_slice(&[0u8; 4]);
            }
            writer
                .commit_txn(1, vec![evil], |_| {})
                .expect("fixture commit");
            writer
                .commit_txn(2, vec![journal::encode_record(&20u64).unwrap()], |_| {})
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
    fn an_exhausted_chain_says_why_its_newest_base_refused() {
        // With the chain exhausted, the refusal's account is the WHOLE of what
        // names the remedy: a base whose body will not decode is a binary on
        // the wrong side of a `W` format change — roll it forward — where a
        // failed checksum or a short file is damage. A bare "no retained
        // checkpoint loads" sends an operator to their disk for both.
        //
        // This is the only tier that can reach both halves of the fixture:
        // `checkpoint::write` mints the unusable base, and the reclamation
        // that makes genesis unreachable needs the kernel that performs it.
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg(dir.path(), BurnedSeqPolicy::Rollback); // retain 1: no fallback
        {
            let k = Kernel::<Vec<Vec<u8>>>::open(cfg.clone(), Vec::new()).unwrap();
            for _ in 0..8 {
                k.transact::<_, ()>(&[], |stg| {
                    stg.push(vec![7u8; 300 * 1024]);
                    Ok(())
                })
                .unwrap();
            }
            assert_eq!(k.checkpoint().unwrap(), Seq(8));
        }
        // The checkpoint's reclamation dropped the segment that begins the
        // journal, so genesis can no longer stand in.
        assert!(!journal::segment_path(dir.path(), 1).exists());
        // Replace the sole retained base with one whose header checksum is
        // VALID and whose body is not this world: everything the header can
        // prove passes, and the decode still refuses.
        checkpoint::write(dir.path(), 8, &"not this world".to_string(), &journal::CHAIN_GENESIS)
            .expect("fixture base");

        let err = Kernel::<Vec<Vec<u8>>>::open(cfg, Vec::new())
            .expect_err("an exhausted chain refuses");
        let OpenError::BadCheckpoint { cause: Some(_) } = &err else {
            panic!("the skew must travel, or an operator restores media over a rolled binary: {err:?}")
        };
        // …and reaches a reporter walking the chain as well as one reading the
        // sentence, which are two different consumers.
        assert!(std::error::Error::source(&err).is_some());
        assert!(err.to_string().contains("the newest refused"), "got {err}");
    }

    #[test]
    fn a_head_at_the_seq_ceiling_refuses_to_open() {
        // The committed head is the coordinate the next transaction is minted
        // above. A journal whose head leaves none cannot be committed onto
        // without renumbering over it, so opening it is refused rather than
        // wrapped (§2/§7).
        let dir = tempfile::tempdir().unwrap();
        {
            let mut writer = fresh_writer(dir.path());
            let record = journal::encode_record(&10u64).unwrap();
            writer
                .commit_txn(u64::MAX, vec![record], |_| {})
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
        // truncation, so the journal an operator images after a `Corruption`
        // is the journal that was there.
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
            salt: SaltSource::Seeded(TEST_SEED),
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
    fn an_interval_restarts_its_window_at_the_crossing() {
        // §6: a crossing resets `last_reset`, so `Interval(d)` is "every d"
        // rather than "every commit once d has first passed". No test can see
        // that through checkpoint files without sleeping, so the cadence is
        // driven directly, its window opened in the past rather than waited
        // for. The only timing this depends on: two consecutive calls take
        // under five seconds.
        let window = std::time::Duration::from_secs(5);
        let mut cadence = Cadence::new(CheckpointPolicy::Interval(window));
        cadence.last_reset = Instant::now()
            .checked_sub(window * 2)
            .expect("the monotonic clock has run for ten seconds");
        assert!(
            cadence.charge_commit(0),
            "a window opened ten seconds ago has elapsed"
        );
        assert!(
            !cadence.charge_commit(0),
            "the crossing did not restart the window"
        );
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
            salt: SaltSource::Seeded(TEST_SEED),
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
            salt: SaltSource::Seeded(TEST_SEED),
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
    fn concurrent_checkpoints_each_leave_the_base_their_name_claims() {
        // §6: the API permits concurrent calls — an explicit caller call
        // racing the on-commit auto-trigger, or two callers — and the
        // dedicated checkpoint mutex is what keeps two of them off one
        // `checkpoint.tmp`. A base that fails its own header checksum is
        // useless, and under `N = 1` it would be the only one. A base that
        // loads must also be the one its name claims: the writer below pushes
        // 0, 1, 2, … one record per commit, so the world at `Seq(s)` is
        // exactly `0..s`, and a coordinate read apart from the root it names
        // publishes a later world under an earlier boundary.
        let dir = tempfile::tempdir().unwrap();
        let cfg = KernelConfig {
            durability: Durability::Fsync {
                journal_path: dir.path().to_path_buf(),
                retain_checkpoints: 64, // keep every base a racing call wrote
                burned_seq: BurnedSeqPolicy::Rollback,
            },
            checkpoint: CheckpointPolicy::Manual,
            salt: SaltSource::Seeded(TEST_SEED),
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
            let loaded = cp.load::<Vec<u64>>().unwrap_or_else(|refused| {
                panic!(
                    "checkpoint {} does not load — two writers shared checkpoint.tmp: {refused}",
                    cp.seq
                )
            });
            assert_eq!(
                loaded.world,
                (0..cp.seq).collect::<Vec<u64>>(),
                "checkpoint {} does not embody the fold its name claims",
                cp.seq
            );
            // …and names the chain at its own coordinate — the value the
            // marker closing that boundary carries on disk, which is what a
            // base at `cp.seq` hands the scan above it. Genesis's is the seed.
            assert_eq!(
                loaded.chain_head,
                chain_at(dir.path(), cp.seq),
                "checkpoint {} names a chain value that is not the one at its coordinate",
                cp.seq
            );
        }
    }

    /// The chain value at boundary `seq`, read off the journal's own bytes:
    /// the `chain` field of the marker whose `last_seq` is `seq`, in the one
    /// segment these fixtures write — what a checkpoint at `seq` must carry
    /// as its `chain_head`. The seed at genesis, which no marker closes.
    fn chain_at(dir: &std::path::Path, seq: u64) -> [u8; 32] {
        if seq == 0 {
            return journal::CHAIN_GENESIS;
        }
        let buf = fs::read(journal::segment_path(dir, 1)).unwrap();
        let mut pos = 0usize;
        while pos + journal::FRAME_HEADER_LEN <= buf.len() {
            let len = u32::from_le_bytes(buf[pos + 4..pos + 8].try_into().unwrap()) as usize;
            let payload =
                &buf[pos + journal::FRAME_HEADER_LEN..pos + journal::FRAME_HEADER_LEN + len];
            // A marker payload (`SKJ4`): tag 1 (4), txn (8), last_seq (8),
            // checksum (4), the salt (32), then the chain (32).
            if payload[..4] == 1u32.to_le_bytes()
                && u64::from_le_bytes(payload[12..20].try_into().unwrap()) == seq
            {
                return payload[56..88].try_into().unwrap();
            }
            pos += journal::FRAME_HEADER_LEN + len;
        }
        panic!("no committed marker closes {seq}")
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
            salt: SaltSource::Seeded(TEST_SEED),
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
