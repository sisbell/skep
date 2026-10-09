//! The kernel: single-applier transaction commit (§3), lock-free snapshot
//! reads (§5), on-commit checkpointing (§6), and two-pass recovery (§7).
//! Beneath it, `applier` is the applier lock and the one door to the write
//! state it guards, and `history` is the reads of the world, the commit chain
//! and the signature slot as of a past boundary (§6/§7).

mod applier;
mod history;

use std::fmt;
use std::fs::{self, File};
use std::io;
use std::num::NonZeroU64;
use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use arc_swap::{ArcSwap, ArcSwapOption};
use parking_lot::Mutex;

use crate::checkpoint::{self, CheckpointHeader};
use crate::config::{BurnedSeqPolicy, CheckpointPolicy, Durability, KernelConfig, SaltSource};
use crate::error::{CheckpointError, LandedStep, OpenError, TxnError};
use crate::journal::{
    self, Attestation, CommitFail, FirstSyncWord, Journal, JournalWriter, ScanFail, UnwindRepair,
};
use crate::replay::{self, SkippedBase};
#[cfg(feature = "test-hooks")]
use crate::Step;
use crate::{LockKey, Seam, Seq, WorldState};
use applier::ApplierLock;

/// What a journaled [`Kernel::open`] FOUND AND DID (§7): the start point its
/// derivation resolved from, and every retained checkpoint it passed over on
/// the way there, each with the refusal that passed it over — the account
/// `open` owes its caller under the AUTH spec's M2 seam delta ("`open` …
/// reports the start point it resolved from", AUTH-2.85), so the daemon above
/// can log at startup which checkpoint it did NOT start from and where it did
/// (AUTH-2.86) — and the two acts of the open itself: how many commits it
/// replayed above that start point, and how many bytes of un-acked tail it
/// cut, so the open's own landing can be said in figures rather than left to
/// the silence between two lines. A report and never a verdict: a skipped
/// base is no failure of the open — the derivation succeeded from an older
/// one — and the chain's one failure, the exhausted chain, is
/// [`OpenError::BadCheckpoint`]'s. Absent under [`Durability::InMemory`],
/// which loads nothing, replays nothing and cuts nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recovery {
    /// `S_load` — the coordinate of the base the recovered world was folded
    /// from: a retained checkpoint's seq, or `Seq(0)` where genesis stood in.
    pub start_point: Seq,
    /// The retained checkpoints above the start point that could not stand
    /// in, newest first, each with why — a header or body that failed its
    /// checks, a body that would not decode, or a seed
    /// [`WorldState::rebuild_derived`] refused.
    pub skipped: Vec<SkippedBase>,
    /// The COMMITS the open replayed above the start point — the
    /// transactions whose markers the scan closed in `(S_load, W]`, counted
    /// as the scan took them, never the records they carry: a composite of
    /// `m` records is one. `0` where the start point IS the committed head —
    /// a base taken at the head with nothing committed since — and the whole
    /// journal's count where genesis stood in.
    pub replayed: u64,
    /// The BYTES the open's tail truncation removed: the active segment's
    /// length above the last committed marker, plus every wholly-later
    /// segment it discarded — §7's un-acked / torn tail, physically cut
    /// before any write is served. `0` where the last committed marker ended
    /// the journal, as it does after every clean shutdown. A count and not an
    /// option: a cut that took nothing and no cut leave the same journal, so
    /// the two are one fact, and every journaled open runs the cut.
    pub tail_cut: u64,
}

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
    /// hash, and the genesis value is what [`Kernel::chain_head`] and
    /// [`Snapshot::chain`] answer there.
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
    /// committed head. The chain's genesis value (`journal::CHAIN_GENESIS`,
    /// thirty-two zero bytes) at `Seq(0)` and, under
    /// [`Durability::InMemory`], at every coordinate: there are no frames to
    /// hash. By value (`[u8; 32]: Copy`).
    ///
    /// Read it off the SAME snapshot as the [`Snapshot::seq`] it is paired
    /// with — the multi-read rule above — and `(seq(), chain())` names one
    /// committed state: the chain OF that coordinate. [`Kernel::current_seq`]
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
/// the cadence it never asked for (§6). The one part of it a running kernel
/// moves is the byte bound ([`Kernel::set_cadence_bytes`]), replaced under
/// the same lock.
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
    /// window starts at this commit — every counter, whichever half of a
    /// composite crossed. A quiescent kernel — nothing new to charge —
    /// correctly never crosses, `Interval` included (§6).
    fn charge_commit(&mut self, bytes: u64) -> bool {
        self.commits_since_reset += 1;
        self.bytes_since_reset += bytes;
        let crossed = self.crossed(&self.policy);
        if crossed {
            self.commits_since_reset = 0;
            self.bytes_since_reset = 0;
            self.last_reset = Instant::now();
        }
        crossed
    }

    /// The crossing test of `policy` against the counters as they stand —
    /// a read of them, never an advance, so a composite tests both halves
    /// against the same figures and the order of the two tests cannot
    /// matter: `EitherOf` crosses when either does, and `Deferred` crosses
    /// exactly when its inner policy does (WHERE the checkpoint then runs is
    /// [`Kernel::transact`]'s to decide, off [`CheckpointPolicy::deferred`]).
    fn crossed(&self, policy: &CheckpointPolicy) -> bool {
        match policy {
            CheckpointPolicy::EveryN(every) => self.commits_since_reset >= *every,
            CheckpointPolicy::JournalBytes(threshold) => self.bytes_since_reset >= *threshold,
            CheckpointPolicy::Interval(window) => self.last_reset.elapsed() >= *window,
            CheckpointPolicy::Manual => false,
            CheckpointPolicy::EitherOf(a, b) => self.crossed(a) || self.crossed(b),
            CheckpointPolicy::Deferred(inner) => self.crossed(inner),
        }
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
    /// left for it: `last` would overflow, or would be the top coordinate
    /// itself, which leaves no coordinate for a successor — the invariant
    /// recovery checks of every committed head ([`Kernel::open`] refuses a
    /// head with no successor as [`OpenError::Corruption`]), established here,
    /// where every head is made, so a kernel never commits a journal it cannot
    /// reopen. Renumbering over a committed predecessor is not an option, so
    /// there is nothing this order can answer with, and what to do about that
    /// is the kernel's to decide.
    ///
    /// `n ≥ 1` is carried by the TYPE, which is what makes `high_water + 1`
    /// below sound without a second site agreeing to it: a `checked_add` that
    /// succeeded with `n ≥ 1` leaves the high-water strictly below `last`, so
    /// the increment is in range. A zero-record transaction cannot be spelled
    /// here, which is the whole of the precondition.
    fn mint(&mut self, n: NonZeroU64) -> Option<(u64, u64)> {
        let last = self
            .high_water
            .checked_add(n.get())
            .filter(|&last| last < u64::MAX)?;
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
/// journal, and the §6 on-commit checkpoint trigger. Reached only through
/// [`ApplierLock::acquire`]: the lock's fields are private to `applier`, so
/// the door that refuses a nested acquisition is the only way in.
struct ApplierState {
    sequencer: Sequencer,
    journal: Journal,
    cadence: Cadence,
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
    /// the base every history read falls back to when no checkpoint covers
    /// the boundary ([`Kernel::world_at`], [`Kernel::chain_at`],
    /// [`Kernel::attestation_at`]) or the position
    /// ([`Kernel::boundaries_above`]).
    genesis: W,
    /// What the open found and did: the start point, the bases it passed
    /// over, the commits it replayed and the tail it cut
    /// ([`Kernel::recovery`]).
    recovery: Recovery,
    /// The `checkpoint.tmp` the open REMOVED, by its length in bytes — a
    /// checkpoint a crash or a failed write left half-written, which the
    /// kernel's own directory contract makes the kernel's to delete
    /// ([`Kernel::stray_checkpoint_removed`]); `None` where none stood.
    stray_checkpoint_removed: Option<u64>,
    /// The names the open passed over that may still stand on disk — the
    /// seqs of `recovery.skipped`, less any a later checkpoint wrote over —
    /// which retention passes over when it counts the bases to keep and
    /// removes as excess (`checkpoint::retain`); emptied once a landing has
    /// removed them. Taken inside [`Kernel::checkpoint`] alone, under its
    /// mutex, so the lock is a formality the type asks for.
    skipped_bases: Mutex<Vec<u64>>,
    /// The journal bytes the LAST landing reclaimed
    /// ([`Kernel::last_reclaimed_bytes`]): the lengths of the segments
    /// `reclaim_below` removed, summed before each removal — or
    /// [`NO_LANDING`] before the first landing of this uptime. Stored by
    /// [`Kernel::checkpoint`] after its reclamation step, read lock-free.
    last_reclaimed: AtomicU64,
    /// The `open()`-held exclusive advisory lock, kept for its `Drop`: the
    /// flock releases when this file closes (Lifecycle).
    _lock: File,
}

/// [`Journaled::last_reclaimed`]'s value before any landing: a figure no
/// landing reclaims, since the segments one removes together fit a volume.
/// A landing that reclaimed nothing stores `0`, which is an answer.
const NO_LANDING: u64 = u64::MAX;

/// What a journaled recovery hands [`Kernel::open`]: the root it commits
/// from, the live appender, the exclusion lock, the account of the open, and
/// the stray `checkpoint.tmp` it removed — five values one call produces,
/// named so the open reads each by what it is rather than by its place in a
/// tuple.
struct Recovered<W> {
    root: Committed<W>,
    journal: Journal,
    lock: File,
    recovery: Recovery,
    stray_checkpoint_removed: Option<u64>,
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
    /// THE DUE FLAG (§6, the deferred arm): set by a crossing under
    /// [`CheckpointPolicy::Deferred`] in place of an inline checkpoint, read
    /// lock-free by [`Kernel::checkpoint_due`], and CLEARED FIRST by every
    /// [`Kernel::checkpoint`]. Its one other reader is the crossing itself:
    /// a crossing that finds it already set runs the checkpoint inline, the
    /// backstop. The `poisoned` flag's shape, and like it never a gate — a
    /// flag read false may be set by the next commit.
    checkpoint_due: AtomicBool,
    /// THE INLINE COUNT (§6): how many checkpoints [`Kernel::transact`] has
    /// run on a committing thread this uptime — the inline arms' at every
    /// crossing, and the backstop's at a crossing that found the due flag
    /// set — read lock-free by [`Kernel::inline_checkpoints`]. Moved after
    /// each such run returns, landed or failed; a run that unwinds moves it
    /// not, the unwind being the caller's.
    inline_checkpoints: AtomicU64,
    /// THE LAST INLINE RUN's FAILURE, as text: `None` where that run landed
    /// (or none has run), the error rendered where it failed — never the
    /// error value, which does not clone. Stored before the count moves, so
    /// a reader that sees the count move reads a text at least as new as
    /// that run's ([`Kernel::last_inline_checkpoint_failure`]).
    last_inline_failure: ArcSwapOption<String>,
    cfg: KernelConfig,
    /// The write-fault seam this kernel's two write paths hook before
    /// [their steps](crate::Step): under `test-hooks` the state the
    /// `#[doc(hidden)]` doors arm, shared with the journal appender, which
    /// holds a second handle; without the feature a no-op. One per kernel,
    /// never the process's.
    seam: Seam,
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
            .field("checkpoint_due", &self.checkpoint_due())
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
    /// load the latest valid RETAINED checkpoint @`S_load` and seed it through
    /// [`WorldState::rebuild_derived`] — on a bad one, or one whose seed
    /// REFUSES ([`RebuildError`](crate::RebuildError): a base that is not a
    /// start point, AUTH-2.84/2.85), fall back to the next-older retained
    /// checkpoint, then to genesis while still reachable (earliest surviving
    /// segment's `firstSeq` still `Seq(1)`; chain exhausted ⟹
    /// [`OpenError::BadCheckpoint`]), and report the start point and every
    /// base passed over as [`Kernel::recovery`] — scan the journal (Pass 1: derive `W`
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
    /// REFUSAL PRECEDENCE — the steps above are the order in which refusals
    /// speak: [`OpenError::InvalidConfig`] precedes the lock, the lock
    /// precedes any read of the journal, [`OpenError::BadCheckpoint`]
    /// precedes the first-sync-word probe — the first scanned segment's
    /// opening is read once the base has said where the scan begins, and
    /// before a byte of the scan — which answers [`OpenError::ForeignFormat`]
    /// for a journal of another format and [`OpenError::Corruption`] for one
    /// damaged sync word; and EVERY route to `Corruption` —
    /// [`OpenError::Corruption`] lists them in the order they speak —
    /// precedes the tail truncation, which is why a halt never cuts anything.
    ///
    /// CALLER CONTRACT — `genesis` (= Σ₀) MUST be byte-identical on every
    /// `open()` of a given journal: recovery folds journaled DELTAS onto it,
    /// never onto a journaled root; a drifting `genesis` silently
    /// mis-recovers. M2 cannot check this (ASN-0047's fixed Σ₀ satisfies it
    /// by construction).
    ///
    /// DAMAGE MODEL — three outcomes, pinned case by case by the chain's
    /// tamper matrix (`tests/it/chain.rs`; QUEUE item 10, piece (b)) against
    /// a FILE-LEVEL WRITER of the journal directory who can rewrite any byte
    /// and re-fix any CRC. What recovery detects is FRAMES THAT FAIL THEIR CRC
    /// — the corrupt-run verdict, which speaks first where there is one — and,
    /// since `SKJ3`, CHAIN LINKS THAT FAIL, the base mismatch and the intact
    /// transaction no intact marker closes among them (the chain's open
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
    /// damages of one kind, at the first only — the halt names the first of
    /// each kind, and a chain link above a break is judged from the marker's
    /// own claim, so one edit is one verdict; of two kinds, at the one
    /// [`OpenError::Corruption`] lists first, whatever their coordinates — an
    /// edited transaction speaks before an earlier, independent chain break,
    /// as a corrupt run speaks before both. A checkpoint's `chain_head`
    /// edited, at the base's own coordinate where the marker closing it is
    /// scanned — at the head whenever the active segment holds the head's
    /// marker, which it does unless that segment is EMPTY after a rotation
    /// whose transaction failed or never landed, when
    /// the head's marker ends the closed segment before it and is skipped
    /// (residue (ii)'s boundary coincidence below; the matrix's case 15) —
    /// and at the first transaction above it otherwise: nothing in the header
    /// covers that field, so the base loads and the journal contradicts it,
    /// at its own marker where that marker is read, else at the first chain
    /// link judged against it. A marker's `txn`, `records_checksum` or
    /// `last_seq` edited, AT that transaction, as an intact transaction no
    /// intact marker closes — its own refusing it, or naming another
    /// transaction as its own — a shape no writer of this format leaves, so
    /// the marker was rewritten; on the LAST transaction too, where
    /// un-committing it would otherwise have been the torn tail recovery
    /// cuts; and at any height in a segment the scan reads, below a standing
    /// base as well, since that verdict compares a marker with its own
    /// records and needs no chain link from the base. The SIGNATURE SLOT is
    /// a chain input by digest (the board's r6-2c, 2026-09-29; the matrix's
    /// case 4): a slot filled, stripped or altered after its commit, its CRC
    /// re-fixed, is caught at that transaction. The SALT IS one too
    /// (`SKJ4`, the matrix's case 16): a marker's salt edited, its CRC
    /// re-fixed, is caught at that transaction — and being drawn at random
    /// per transaction and served by no route, it is what keeps a served
    /// chain value from confirming a guess at a transaction's bytes, while
    /// against a party holding the journal, who holds the bytes, it protects
    /// nothing.
    ///
    /// REFUSED — the checkpoint's own door: a body rewritten with its CRC
    /// re-fixed fails `body_hash`, the fallback reaches an older base or
    /// genesis, and the journal above it re-verifies.
    ///
    /// NOT CAUGHT BY DESIGN — histories the chain alone accepts, which the
    /// ruling assigns to piece 2, the PUBLISHED HEAD ([`Kernel::chain_head`]
    /// is its input; a peer holding an older head checks that the new
    /// history EXTENDS it — against this kernel's recomputation through
    /// [`Kernel::chain_at`], which the daemon serves as `GET /chain?at=N`).
    /// A CLEAN TAIL CUT — the last transactions removed at a boundary —
    /// opens at the shorter head. A CONSISTENT RE-CHAIN — a rewrite at any
    /// point with every later chain link recomputed, from genesis or
    /// mid-history, the retained checkpoints' heads rewritten with it —
    /// passes: the chain has no anchor but its genesis value and the base's
    /// header, and a base's BODY, which nothing compares to the journal below
    /// it, the forger re-mints with this kernel's own `checkpoint()` over the
    /// forged replay. A checkpoint BODY forged with its CRC and `body_hash`
    /// re-fixed loads as the base. The base-mismatch check has three
    /// residues: (i) the header AND the marker closing its seq edited
    /// consistently, every chain link above re-chained from the edit — the
    /// open passes, and a history read below the base recomputes the chain
    /// link at the base's seq over its predecessor and fails it, unless the
    /// forger re-chained from below that too, which is the consistent
    /// re-chain; (ii) the base's marker segment RECLAIMED or SKIPPED — a
    /// closed segment ending exactly at the base's seq, the boundary
    /// coincidence — where the check is vacuous: the first chain link above
    /// the base is judged against the header, and a header edited with
    /// nothing above it opens on the edit; (iii) two retained checkpoints
    /// edited consistently with the journal re-chained between them, the
    /// consistent re-chain again. And the ruling's "any rewrite", as the
    /// owner reads it (the matrix's case 12, 2026-09-23): the chain is
    /// verified for transactions above the base a replay selects, so a
    /// CONSISTENT rewrite below a standing base — its CRCs and
    /// `records_checksum` re-fixed, so it commits — is unseen at `open` while
    /// that base stands, seen by any history read below the base — which
    /// verifies every chain link from the base it selects to the journal's
    /// end — and beyond any replay once reclamation drops the segment; an
    /// edited transaction there is caught, as above. The `journal_path`
    /// caller contract still keeps the files whole; what it no longer has to
    /// keep is the silence.
    ///
    /// NOT CAUGHT, AND NOT BY DESIGN — an open item, the owner's (the
    /// matrix's case 17, standing `#[ignore]`d as a STOP): a frame of the
    /// LAST transaction rewritten so it no longer decodes — a payload tag, a
    /// length prefix, the signature slot's one spelling of empty — its CRC
    /// re-fixed. Mid-history the corrupt run it opens halts at the next
    /// intact frame (case 4); in the last transaction the run lies above the
    /// committed head, §7's torn tail, and the transaction is cut without a
    /// word, though its CRC proves these are the bytes that were written.
    /// Closing it amends §7's tail rule.
    pub fn open(cfg: KernelConfig, genesis: W) -> Result<Self, OpenError> {
        cfg.validate().map_err(OpenError::InvalidConfig)?;
        // The seam is made here, before the appender it is handed to and
        // the kernel that holds it exist, so one state serves both.
        let seam = Seam::default();
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
                let recovered = Self::recover(journal_path, &genesis, cfg.salt, seam.clone())?;
                // The names the open passed over, for retention to pass over
                // in turn, until the first landing has removed them.
                let skipped_bases = recovered.recovery.skipped.iter().map(|b| b.seq.0).collect();
                (
                    recovered.root,
                    recovered.journal,
                    Some(Journaled {
                        dir: journal_path.clone(),
                        retain_checkpoints: *retain_checkpoints,
                        genesis,
                        recovery: recovered.recovery,
                        stray_checkpoint_removed: recovered.stray_checkpoint_removed,
                        skipped_bases: Mutex::new(skipped_bases),
                        last_reclaimed: AtomicU64::new(NO_LANDING),
                        _lock: recovered.lock,
                    }),
                )
            }
        };
        Ok(Self::assemble(cfg, root, journal, journaled, seam))
    }

    /// Recover the journal at `dir` into the root it commits from, its live
    /// appender — handed `salt_source`, the configured [`SaltSource`] every
    /// transaction it commits draws from (`SKJ4`); recovery itself draws
    /// nothing, reading each salt off its marker — and `seam`, the kernel's
    /// write-fault seam, which the appender's append, barrier and repair
    /// hook before they run — the exclusion lock the kernel holds for its
    /// lifetime, the account of the base it stood on and the bases it passed
    /// over (§7), and the stray `checkpoint.tmp` it removed, if one stood
    /// ([`Recovered`]). Recovery's own writes — the stray's removal, the
    /// tail cut, the first segment's creation — run no step of the seam.
    fn recover(
        dir: &Path,
        genesis: &W,
        salt_source: SaltSource,
        seam: Seam,
    ) -> Result<Recovered<W>, OpenError> {
        // THE DIRECTORY, OWNER-ONLY: every component this creates is born
        // `0700` on unix, the mode set at creation so the process umask can
        // only tighten it — as every file the kernel creates in it is born
        // `0600` (the lock, a segment, `checkpoint.tmp`). A reader of the
        // directory holds the board whole, and a umask is the one thing no
        // caller can be relied on to have set. A directory that already
        // stands is left exactly as found: nothing here chmods.
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(dir)?;
        let lock = journal::acquire_journal_lock(dir)?;
        // THE STRAY TEMP FILE, removed under the flock before anything is
        // listed: a checkpoint a crash or a failed write left half-written
        // under the fixed temp name is no base (`checkpoint::list` would skip
        // it by name) and keeps its room on the volume — which, after a
        // write the volume's room failed, is the room the next checkpoint
        // needs. The directory is the kernel's alone, so the file is the
        // kernel's to delete; the caller is told it was, and how large it
        // was, through [`Kernel::stray_checkpoint_removed`].
        let stray_checkpoint_removed = checkpoint::remove_stray_tmp(dir)?;
        let segs = journal::list_segments(dir)?;
        let checkpoints = checkpoint::list(dir)?;

        // The base, with its whole fallback chain: newest retained checkpoint
        // that loads and seeds → next-older retained → genesis-while-reachable;
        // an exhausted chain is the operator-intervention condition (§6/§7).
        // What the chain passed over is reported, never a failure.
        let base = replay::select_base(&checkpoints, &segs, None, genesis).map_err(|fail| {
            OpenError::BadCheckpoint { cause: fail.cause }
        })?;
        // The report's first two members, read off the base before the fold
        // consumes it; its other two are the scan's count and the cut's,
        // known once each has run.
        let start_point = Seq(base.s_load());
        let skipped = base.skipped().to_vec();

        // THE FIRST-SYNC-WORD PROBE, ahead of the scan (the encoding report's
        // §8; the owner's ruling of 2026-09-23). A segment written under
        // another format holds no frame this build's sync word anchors, so
        // the scan would read the whole of it as one corrupt run reaching
        // end-of-file — the un-acked tail — and the cut below would TRUNCATE
        // it to nothing and serve an empty world over a journal it had just
        // erased. Refused by name instead, before a byte is scanned and
        // before anything is written: the files stay as they were found. A
        // single damaged sync word — foreign-shaped, before a frame of this
        // build's — is refused as early, and as the damage it is: its remedy
        // is to restore the segment, where a format's discards the journal.
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
        // already embodied in the base.
        let scan = base.scan(&segs, None).map_err(|fail| match fail {
            ScanFail::Io(e) => OpenError::Io(e),
            ScanFail::Unscannable { at } => OpenError::Corruption {
                at: Seq(at),
                cause: None,
            },
        })?;
        // Every at-rest verdict, in the order it speaks
        // (`ScanOutcome::halt_to_head`): the corrupt run first, then the base
        // mismatch, the intact transaction no intact marker closes, and the
        // chain break. Each halts here with its coordinate and whatever account
        // it has, and cuts nothing.
        if let Some((at, cause)) = scan.halt_to_head() {
            return Err(OpenError::Corruption {
                at: Seq(at),
                cause,
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
        // root carries, so a checkpoint off this root names the right chain
        // value.
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
        // this cut settles and which the appender reads once. What it cut, in
        // bytes, is the open's to report, as the commits the fold replayed
        // are: the scan counted those as it closed their markers.
        let tail_cut = journal::truncate_tail(dir, &scan)?;
        let recovery =
            Recovery { start_point, skipped, replayed: scan.commits_above_base, tail_cut };

        let writer =
            JournalWriter::open_active(dir, next_seq, chain_head, salt_source)?.with_seam(seam);
        Ok(Recovered {
            root: Committed {
                seq: Seq(committed_head),
                world,
                chain: chain_head,
            },
            journal: Journal::Segments(writer),
            lock,
            recovery,
            stray_checkpoint_removed,
        })
    }

    fn assemble(
        cfg: KernelConfig,
        root: Committed<W>,
        journal: Journal,
        journaled: Option<Journaled<W>>,
        seam: Seam,
    ) -> Self {
        let cadence = Cadence::new(cfg.checkpoint.clone());
        let sequencer = Sequencer::recovered(root.seq, cfg.durability.burned_seq_policy());
        Kernel {
            root: ArcSwap::from_pointee(root),
            applier: ApplierLock::new(ApplierState {
                sequencer,
                journal,
                cadence,
            }),
            checkpoint_mutex: Mutex::new(()),
            poisoned: AtomicBool::new(false),
            checkpoint_due: AtomicBool::new(false),
            inline_checkpoints: AtomicU64::new(0),
            last_inline_failure: ArcSwapOption::empty(),
            cfg,
            seam,
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
    /// and, when it crosses under an INLINE arm of the policy,
    /// [`Kernel::checkpoint`] runs to completion on this thread —
    /// serializing `W`, writing and fsyncing a file, applying retention,
    /// reclaiming segments — after the commit is durable and installed. Its
    /// failure is NOT THE TRANSACTION's: the transaction is already
    /// acknowledged, so there is no sound path for that error through
    /// [`TxnError`], and the kernel has no logging seam — but every such run
    /// is COUNTED and the last one's failure KEPT AS TEXT
    /// ([`Kernel::inline_checkpoints`], [`Kernel::last_inline_checkpoint_failure`]),
    /// the two facts a caller above reads and says. Under
    /// [`CheckpointPolicy::Deferred`] the
    /// crossing SETS THE DUE FLAG instead ([`Kernel::checkpoint_due`]) and
    /// this thread runs nothing — the caller's own thread runs
    /// [`Kernel::checkpoint`] and reads the result — unless the flag is
    /// ALREADY set, the last crossing unserviced, when the checkpoint runs
    /// inline here after all, the backstop that keeps the window bounded,
    /// counted as every inline run is. A caller who needs to know whether
    /// checkpointing is succeeding calls [`Kernel::checkpoint`] itself and
    /// reads the result, or reads the count and the text; a kernel that has
    /// stopped checkpointing inline goes on committing.
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
    /// A panic AFTER the commit region — the on-commit checkpoint's own (`W`'s
    /// `Serialize`, or a world's destructor run inside it), or the superseded
    /// root's destructor, run as this call returns and releases what may be
    /// the last reference to it ([`WorldState`]'s drop obligation) —
    /// propagates with the transaction committed and installed: the lost-ack
    /// case (§3), the kernel not poisoned and its order intact.
    ///
    /// [`BurnedSeqPolicy`]: crate::BurnedSeqPolicy
    pub fn transact<T, E>(
        &self,
        keys: &[LockKey],
        f: impl FnOnce(&mut Staging<W>) -> Result<T, E>,
    ) -> Result<(T, Seq), TxnError<E>> {
        self.transact_attested(keys, None, f)
    }

    /// [`Kernel::transact`] with THE SIGNATURE SLOT of this transaction's
    /// commit marker filled (signed ops; the design record §2.4's inbound
    /// route): where `attestation` is `Some`, the marker `encode_txn` writes for
    /// THIS transaction carries its tag and blob in the slot X2 reserved, and
    /// nothing else about the commit moves but its CHAIN — the records, their
    /// frames, the salt and the accounting the TRANSACTION BUDGET names are
    /// as `transact` leaves them, the blob's bytes sitting OUTSIDE that budget
    /// (the design record §4.4 (b)) and bounded instead by
    /// [`crate::MAX_SIG_BYTES`], which [`Attestation::new`] holds every value
    /// to — so the marker's own frame stays inside the frame cap at any width
    /// an attestation can have, and an attested commit meets no refusal its
    /// unattested twin would not — while the link closes over the slot's
    /// digest (the board's r6-2c), so an attested transaction's chain value is
    /// not its unattested twin's.
    /// `None` is `transact` exactly: the slot written EMPTY, in its one
    /// spelling. A zero-step transaction writes no marker and so no slot, and
    /// under [`Durability::InMemory`] no marker exists at all — the value is
    /// dropped with the frames it would have ridden.
    ///
    /// The kernel verifies nothing about an attestation and restricts no
    /// caller: which transactions may carry one, and whether its blob
    /// verifies, are the caller's to decide and the verifier's to check. It
    /// writes the bytes it is handed, opaquely, for the transaction it is
    /// handed them with, which is the whole of the seam.
    ///
    /// [`Kernel::attestation_at`] reads the slot back at a committed
    /// boundary; the fold never does (the slot is fold-inert).
    pub fn transact_attested<T, E>(
        &self,
        keys: &[LockKey],
        attestation: Option<&Attestation>,
        f: impl FnOnce(&mut Staging<W>) -> Result<T, E>,
    ) -> Result<(T, Seq), TxnError<E>> {
        let _ = keys; // §4: subsumed by the single applier's global lock in v1.
        let mut applier = self.applier.acquire();
        if self.poisoned.load(Ordering::Acquire) {
            return Err(TxnError::Poisoned);
        }
        let base = self.root.load_full();
        // The staging holds the root for the WHOLE of this call — the
        // destructure below binds `base: _`, which moves nothing — so the
        // install releases only a reference: no world's destructor runs
        // between a root's store and the end of the commit region, and every
        // unwind out of that region precedes the store, which is what the
        // in-memory journal's `Clean` repair rests on (`WorldState`'s drop
        // obligation). What the code below reads of the root is its
        // coordinate.
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
            // Load-bearing: `_` moves nothing, so the superseded root stays
            // in `stg` until this call returns (above).
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
        let Some((first, last)) = state.sequencer.mint(n) else {
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
                state.journal.commit_txn(first, records, attestation, move |chain| {
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
                    UnwindRepair::Clean => state.sequencer.roll_back_to(base_seq),
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
                state.sequencer.roll_back_to(base_seq);
                Err(TxnError::Durability(e))
            }
            // Nothing ever became frames, so the journal is where this txn
            // found it — the same no-op, burning the same Seqs, and a
            // different remedy: fix the record (§1/§3).
            Ok(Err(CommitFail::Unencodable(e))) => {
                state.sequencer.roll_back_to(base_seq);
                Err(TxnError::Unencodable(e))
            }
            // The same no-op with the third remedy: no record refused, the
            // staging as a whole is past the transaction budget, and only
            // splitting it changes that (§1/§3).
            Ok(Err(CommitFail::OverBudget { bytes })) => {
                state.sequencer.roll_back_to(base_seq);
                Err(TxnError::OverBudget { bytes })
            }
            // The truncation itself could not complete durably (§1).
            Ok(Err(CommitFail::Unrepaired)) => {
                self.poisoned.store(true, Ordering::Release);
                Err(TxnError::Poisoned)
            }
            Ok(Ok(bytes)) => {
                // §6 on-commit trigger: charged and tested under the applier
                // lock, and whether its crossing is deferred read beside it;
                // checkpoint() never touches the cadence.
                let crossed = state.cadence.charge_commit(bytes);
                let deferred = state.cadence.policy.deferred();
                drop(applier);
                if crossed {
                    // THE DEFERRED ARM: the crossing sets the due flag for the
                    // caller's thread to service, and runs nothing here —
                    // unless the flag was ALREADY set, the last crossing not
                    // yet serviced, when THE BACKSTOP runs the checkpoint
                    // inline exactly as the inline arms do: a caller that
                    // never services the flag, or a board whose writes outrun
                    // its checkpointer, gets a checkpoint at every second
                    // crossing and never an unbounded window. `checkpoint()`
                    // clears the flag first, so the inline run leaves it
                    // clear and the next crossing is a deferred one again.
                    let run_inline =
                        !deferred || self.checkpoint_due.swap(true, Ordering::AcqRel);
                    if run_inline {
                        // §3/§6: the auto-triggered checkpoint's error never
                        // fails the already-committed txn, and the kernel has
                        // no logging seam (the design's dependency list) — so
                        // the run is COUNTED and its failure kept as text,
                        // for the caller above to read and say; safe by §6's
                        // crash argument (at most a .tmp the write or the
                        // next open removes, and an unreclaimed journal).
                        let outcome = self.checkpoint();
                        self.note_inline_run(outcome);
                    }
                }
                Ok((value, Seq(last))) // commit-before-acknowledge (A7, MIC-3)
            }
        }
    }

    /// Record one checkpoint [`Kernel::transact`] ran inline on a committing
    /// thread: the run's failure as text — `None` where it landed — stored
    /// FIRST, then the count moved, so a reader that sees the count move
    /// reads a text at least as new as that run's. The error value itself
    /// goes no further: it is not `Clone`, and the caller above wants the
    /// sentence.
    fn note_inline_run(&self, outcome: Result<Seq, CheckpointError>) {
        self.last_inline_failure.store(outcome.err().map(|e| Arc::new(e.to_string())));
        self.inline_checkpoints.fetch_add(1, Ordering::AcqRel);
    }

    /// One committed state, pinned (MIC clauses 4 & 6; A3/V0/V2). One
    /// lock-free `ArcSwap` load. INFALLIBLE, and continues to serve the last
    /// in-memory root even on a POISONED kernel: the poison paths (§1/§3)
    /// leave that root a consistent committed state, so reads stay sound;
    /// only write/checkpoint paths fail with `Poisoned`.
    pub fn snapshot(&self) -> Snapshot<W> {
        Snapshot(self.root.load_full())
    }

    /// How many checkpoints [`Kernel::transact`] has run INLINE on a
    /// committing thread this uptime (§6): under an inline arm of the
    /// policy, every crossing's; under [`CheckpointPolicy::Deferred`], the
    /// backstop's alone — a crossing that found the due flag still set, the
    /// last crossing unserviced, and ran the checkpoint on the writer's
    /// thread, its result read by nobody. A caller's own
    /// [`Kernel::checkpoint`] moves it not, nor does a run that unwinds; a
    /// run counts whether it landed or failed, and under
    /// [`Durability::InMemory`], where the run is the no-op, it counts as
    /// landed. Lock-free, like [`Kernel::checkpoint_due`]: the caller above
    /// reads it once per commit beside that flag, and where it moved reads
    /// [`Kernel::last_inline_checkpoint_failure`] and says so — the kernel
    /// still has no logging seam; it answers a fact. The count and the text
    /// are two loads, between which a run may land.
    pub fn inline_checkpoints(&self) -> u64 {
        self.inline_checkpoints.load(Ordering::Acquire)
    }

    /// How the LAST checkpoint [`Kernel::transact`] ran inline FAILED, as
    /// text — the error rendered, never the error value, which does not
    /// clone — or `None` where that run landed, or no run has happened.
    /// Written at each inline run, so a landing after a failure clears it:
    /// the answer is the last run's and not the last failure's, which is what
    /// a line saying "the last landed" or "the last failed" needs. Read
    /// lock-free, with the count's caveat ([`Kernel::inline_checkpoints`]).
    pub fn last_inline_checkpoint_failure(&self) -> Option<String> {
        self.last_inline_failure.load_full().map(|text| String::clone(&text))
    }

    /// The journal bytes the LAST landed [`Kernel::checkpoint`] RECLAIMED:
    /// the lengths of the closed segments its reclamation removed below the
    /// oldest kept base, each read before its removal and summed. `Some(0)`
    /// where the landing removed no segment — a landing that reclaims
    /// nothing says so — and `None` before any landing of this uptime, and
    /// under [`Durability::InMemory`], which has no journal to reclaim. A
    /// failed call stores nothing: the figure is a landing's, and a call
    /// that failed before or after its base landed is not one, whatever its
    /// reclamation removed before failing. Lock-free, in
    /// [`Kernel::stray_checkpoint_removed`]'s shape, read after `Ok`; the
    /// landing's `Ok` type carries the seq alone, as it did.
    pub fn last_reclaimed_bytes(&self) -> Option<u64> {
        let journaled = self.journaled.as_ref()?;
        match journaled.last_reclaimed.load(Ordering::Acquire) {
            NO_LANDING => None,
            bytes => Some(bytes),
        }
    }

    /// What this kernel's [`Kernel::open`] found in its journal directory and
    /// did there — the start point it resolved from, the retained
    /// checkpoints it passed over, the commits it replayed and the tail it
    /// cut ([`Recovery`]; §7; AUTH-2.85) — or `None` under
    /// [`Durability::InMemory`], which loaded nothing. Fixed at `open`: a
    /// checkpoint taken since neither adds to it nor retires an entry, since
    /// the report is of the open and not of the directory as it now stands —
    /// retention removing a skipped base retires nothing here either.
    /// Lock-free, like every other read.
    pub fn recovery(&self) -> Option<&Recovery> {
        self.journaled.as_ref().map(|journaled| &journaled.recovery)
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
    /// `chain_head`, or the chain's genesis value at genesis). The genesis
    /// value at every coordinate under [`Durability::InMemory`], where there
    /// are no frames to hash.
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

    /// Whether a checkpoint is DUE (§6, the deferred arm): a commit has
    /// crossed the cadence under [`CheckpointPolicy::Deferred`] since the last
    /// [`Kernel::checkpoint`] began, and the checkpoint it calls for has not
    /// been started. Lock-free and infallible, like [`Kernel::is_poisoned`]:
    /// the caller's checkpoint thread reads it to decide whether to run
    /// [`Kernel::checkpoint`], which clears it FIRST and then runs — so a
    /// `true` read after that call returns is a crossing during the run,
    /// which the thread services by running once more. Never set under any
    /// other arm, whose crossings run inline; never a gate, since the next
    /// commit may set it; and never cleared by anything but a call to
    /// `checkpoint`, so a caller that reads it true and runs nothing leaves
    /// the next crossing to the backstop ([`Kernel::transact`]).
    pub fn checkpoint_due(&self) -> bool {
        self.checkpoint_due.load(Ordering::Acquire)
    }

    /// Move the cadence's BYTE BOUND — every [`CheckpointPolicy::JournalBytes`]
    /// threshold the policy holds, wherever its arms nest one — to `bytes`,
    /// answering whether the policy held one to move. The one knob of the
    /// cadence a running kernel changes, for a caller that sizes the bound by
    /// the newest checkpoint and re-reads it as each lands
    /// ([`Kernel::newest_checkpoint`] answers the size). Taken under the
    /// applier lock, where the cadence lives and is tested: the next commit
    /// tests the new bound against the counters as they stand — the window
    /// in progress is neither reset nor re-charged — and a crossing it makes
    /// resets them as any crossing does. `n ≥ 1` is the type's, so the rule
    /// [`Kernel::open`] validates holds after every call. Never from inside a
    /// [`Kernel::transact`] closure, which holds the lock this takes.
    pub fn set_cadence_bytes(&self, bytes: NonZeroU64) -> bool {
        let mut applier = self.applier.acquire();
        applier.cadence.policy.set_bytes(bytes)
    }

    /// Move the cadence's COMMIT BOUND — every [`CheckpointPolicy::EveryN`]
    /// count the policy holds, wherever its arms nest one — to `commits`,
    /// answering whether the policy held one to move: [`Kernel::set_cadence_bytes`]'s
    /// twin, under the same lock and the same rules (the window in progress
    /// is neither reset nor re-charged; never from inside a transact
    /// closure). A caller that moves BOTH bounds past any count it will
    /// commit holds the cadence off for its life, which is what a suite
    /// measuring a board that must reclaim nothing does.
    pub fn set_cadence_commits(&self, commits: NonZeroU64) -> bool {
        let mut applier = self.applier.acquire();
        applier.cadence.policy.set_commits(commits)
    }

    /// The `checkpoint.tmp` this kernel's [`Kernel::open`] FOUND AND REMOVED,
    /// by its length in bytes — a checkpoint a crash or a failed write left
    /// half-written under the fixed temp name, which is no base and keeps its
    /// room on the volume until something deletes it; the directory belongs
    /// to the kernel alone, so that something is the open, under the flock.
    /// `None` where none stood, and under [`Durability::InMemory`], which
    /// opens no directory. Fixed at `open`, like [`Kernel::recovery`], and
    /// kept apart from it: the report is of the directory as found, not of
    /// the derivation, and the daemon above renders it as its own startup
    /// line. A `.tmp` a FAILED [`Kernel::checkpoint`] leaves is removed by
    /// that call itself, best-effort, and never reaches here.
    pub fn stray_checkpoint_removed(&self) -> Option<u64> {
        self.journaled.as_ref().and_then(|journaled| journaled.stray_checkpoint_removed)
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
    /// THE DUE FLAG IS CLEARED FIRST, before any of that — whichever caller
    /// this is, the deferred arm's thread, the backstop or a caller of its
    /// own ([`Kernel::checkpoint_due`]): a crossing during the run then sets
    /// it again and the thread runs once more after, where a flag cleared
    /// after the run would send every crossing during it to the backstop,
    /// an inline checkpoint queued behind this one's mutex. A failure clears
    /// it the same, so the next attempt is the next crossing's: a kernel
    /// that cannot checkpoint is not asked again until there is something
    /// new to persist.
    ///
    /// A failed write leaves NO `checkpoint.tmp`: the file is removed before
    /// the error is answered, best-effort, the removal's own failure folded
    /// into the account ([`CheckpointError::Io`]).
    ///
    /// RETENTION KEEPS THE BASES THAT LOAD: the `retain_checkpoints` kept are
    /// counted among the bases that loaded — the names this kernel's open
    /// passed over ([`Kernel::recovery`]'s `skipped`) are passed over by the
    /// count and removed as excess, whatever their age — so the first
    /// landing after an open that skipped a base keeps the base the open
    /// loaded from beside the new one and removes the skipped one; the
    /// reclamation floor is the oldest base KEPT. A base this call writes
    /// over a skipped name is a base again and is counted. With nothing
    /// skipped the rule is the one it was: the newest `retain_checkpoints`
    /// stand.
    ///
    /// A FAILURE AFTER THE BASE LANDED — the rename ran, then the directory's
    /// fsync, retention or the journal's reclamation failed — is
    /// [`CheckpointError::Landed`], naming the step ([`LandedStep`]) and
    /// carrying the cause; a failure before it is [`CheckpointError::Io`]
    /// and leaves no base. The journal bytes a landing reclaimed are read
    /// after `Ok` through [`Kernel::last_reclaimed_bytes`].
    ///
    /// [`current_seq`]: Kernel::current_seq
    pub fn checkpoint(&self) -> Result<Seq, CheckpointError> {
        self.checkpoint_due.store(false, Ordering::Release);
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
        checkpoint::write(&journaled.dir, s.0, &snap.world, &snap.chain, &self.seam).map_err(
            |fail| match fail {
                checkpoint::WriteFail::Serialize(e) => CheckpointError::Serialize(e),
                checkpoint::WriteFail::Io(e) => CheckpointError::Io(e),
                checkpoint::WriteFail::Landed(cause) => {
                    CheckpointError::Landed { step: LandedStep::DirectorySync, cause }
                }
            },
        )?;
        // The name `checkpoint.<s>` now holds the base this call wrote: a
        // file of that name the open passed over is a base again, and
        // retention counts it. What the open skipped and still stands is
        // what retention passes over.
        let skipped: Vec<u64> = {
            let mut standing = journaled.skipped_bases.lock();
            standing.retain(|&seq| seq != s.0);
            standing.clone()
        };
        // Retention policy — how many bases to keep — applied to the bases
        // that load, which answers with the oldest survivor. This kernel
        // leaves one: `retain_checkpoints ≥ 1` is validated at `open`, and this
        // call has just added to the set the retention is applied to. Another
        // process can still take it between the rename and the listing — the
        // flock excludes other kernels and nothing else (the `journal_path`
        // contract) — and an auto-triggered call runs after its commit is
        // acknowledged, so that is answered as the I/O failure it is, over a
        // base that landed, never as a panic in place of the commit's `Ok`.
        let landed = |step: LandedStep| move |cause| CheckpointError::Landed { step, cause };
        let s_old = checkpoint::retain(&journaled.dir, journaled.retain_checkpoints, &skipped)
            .map_err(landed(LandedStep::Retention))?
            .ok_or_else(|| {
                landed(LandedStep::Retention)(io::Error::new(
                    io::ErrorKind::NotFound,
                    "the checkpoint this call wrote was gone before retention listed it: \
                     something other than this kernel removed it from the journal directory",
                ))
            })?;
        // Every file retention passed over is gone, so nothing stands to
        // pass over at the next landing.
        journaled.skipped_bases.lock().clear();
        // Reclaim the journal below the OLDEST kept checkpoint — that floor,
        // not the newest, is what keeps the BadCheckpoint fallback real (§6)
        // — and keep what it reclaimed for the landing's reader.
        let reclaimed = journal::reclaim_below(&journaled.dir, s_old)
            .map_err(landed(LandedStep::Reclamation))?;
        journaled.last_reclaimed.store(reclaimed.min(NO_LANDING - 1), Ordering::Release);
        Ok(s)
    }

    /// What the checkpoint at `seq` claims by its `SKC4` header —
    /// [`Kernel::newest_checkpoint`]'s read, for ONE base named by its
    /// coordinate rather than for the newest: the START POINT's, which
    /// loaded ([`Kernel::recovery`]'s `start_point`), is what a caller sizes
    /// a floor or a byte bound by after an open that skipped a newer base,
    /// since the newest file's header is then the skipped base's claim. The
    /// file is named directly from `seq` — one short read, no listing — and
    /// held to the checks a header passes without its body. FAIL-QUIET as
    /// the newest read is: `None` where no file of that name stands — a seq
    /// no checkpoint was taken at, or one retention has since removed —
    /// where its header refuses, and under [`Durability::InMemory`]. The body
    /// is NOT verified, so a base whose body is damaged still answers its
    /// header, as the newest read answers it; `Seq(0)` names no file, genesis
    /// being no checkpoint. Lock-free: it consults the directory.
    pub fn checkpoint_header(&self, seq: Seq) -> Option<CheckpointHeader> {
        let journaled = self.journaled.as_ref()?;
        checkpoint::header_at(&journaled.dir, seq.0)
    }

    /// What the NEWEST RETAINED checkpoint's `SKC4` header claims — its
    /// coordinate, the commit chain's value there, its body's hash and its
    /// file's length, as a [`CheckpointHeader`] — or `None` under
    /// [`Durability::InMemory`] and before the first checkpoint. ADDITIVE
    /// (QUEUE item 10 piece 2, the PUBLISHED HEAD): what a head record's `base`
    /// member names (PUB-6.65), so a peer that copies a checkpoint file has its
    /// coordinate confirmed, a full replica verifies the base's canonical body
    /// by `body_hash`, and the coordinate survives the retention
    /// (`retain_checkpoints`) that drops the file — the base is the one durable
    /// record of a reclaimed checkpoint's coordinate. The length is the
    /// figure a caller SIZES by: the room the next checkpoint takes on the
    /// volume, and the byte bound a cadence relative to it holds the journal
    /// to ([`Kernel::set_cadence_bytes`]).
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
    pub fn newest_checkpoint(&self) -> Option<CheckpointHeader> {
        let journaled = self.journaled.as_ref()?;
        checkpoint::newest_header(&journaled.dir)
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

/// THE WRITE-FAULT SEAM's DOORS (`test-hooks` builds only; `hooks.rs` is the
/// seam): how a test makes the next step of this kernel's write paths fail
/// or unwind on cue — and reads the one count the seam keeps, the bases
/// this kernel's history reads loaded. Each door arms or reads THIS
/// kernel's seam alone.
#[cfg(feature = "test-hooks")]
impl<W: WorldState> Kernel<W> {
    /// TEST HOOK (`test-hooks`): FAIL the next `step` this kernel's write
    /// paths reach with an `io::Error` of `kind`, in the step's place — a
    /// full volume is [`io::ErrorKind::StorageFull`] — ONCE: the arm fires
    /// and disarms, and the next call of the same step runs the real step.
    /// One arm per step; arming a step again replaces its arm. What each
    /// failure leaves and how it is answered is the step's own card
    /// ([`Step`]): the journal's three reach the caller through
    /// [`TxnError::Durability`] — [`TxnError::Poisoned`] for the repair's —
    /// with the kind unchanged, the checkpoint's two before the rename
    /// through [`CheckpointError::Io`] and the directory's fsync after it
    /// through [`CheckpointError::Landed`]. On an in-memory kernel the arm stands
    /// unfired: that kernel appends nothing and its [`Kernel::checkpoint`]
    /// is the no-op, so it reaches no step.
    #[doc(hidden)]
    pub fn fail_the_next(&self, step: Step, kind: io::ErrorKind) {
        self.seam.fail_the_next(step, kind);
    }

    /// TEST HOOK (`test-hooks`): PANIC at the next `step` this kernel's
    /// write paths reach, in the step's place, ONCE — the checkpoint write's
    /// three steps, whose unwind the backstop's inline checkpoint carries out
    /// of [`Kernel::transact`] after the commit landed, and the journal's
    /// append, the unwind out of the commit region the §3 guard repairs. The
    /// barrier and the repair take no panic arm (`hooks.rs` says why), and
    /// naming one here is a caller's bug answered as one. Replaces any arm
    /// at the step; an in-memory kernel reaches no step, as
    /// [`Kernel::fail_the_next`] says.
    #[doc(hidden)]
    pub fn panic_at_the_next(&self, step: Step) {
        self.seam.panic_at_the_next(step);
    }

    /// TEST HOOK (`test-hooks`): the steps an arm still stands at, in arming
    /// order — empty once every arm has fired, which is how a test reads
    /// that a step was reached.
    #[doc(hidden)]
    pub fn armed_steps(&self) -> Vec<Step> {
        self.seam.armed_steps()
    }

    /// TEST HOOK (`test-hooks`): THE BASES THIS KERNEL's HISTORY READS HAVE
    /// LOADED since the open — one per base a read's selection stood on, a
    /// retained checkpoint's whole body read, hashed, deserialized and
    /// seeded, or genesis cloned and seeded: "the base LOADED" every
    /// history read's COST paragraph opens with ([`Kernel::world_at`],
    /// [`Kernel::boundaries_above`]), counted at its one site, the reads'
    /// base selection — so a suite fences what a caller costs in BASES,
    /// which no clock can on a loaded machine: a consumer asking once over
    /// a window and one asking once per boundary read the same slots and
    /// differ here alone (§3.3 step 2 of the operations design). Not
    /// counted: recovery's base at the open, which runs the selection
    /// directly; a candidate the fallback chain passed over; a selection
    /// that refused `Reclaimed`. Monotone over the kernel's life and read
    /// lock-free; a suite reads it twice and pins the difference.
    #[doc(hidden)]
    pub fn bases_loaded(&self) -> u64 {
        self.seam.bases_loaded()
    }
}

#[cfg(test)]
mod tests;
