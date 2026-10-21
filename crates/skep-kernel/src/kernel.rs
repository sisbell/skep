//! The kernel, which commits, serves snapshots, checkpoints and recovers.
//!
//! Single-applier transaction commit (§3), lock-free snapshot reads (§5),
//! on-commit checkpointing (§6), and two-pass recovery (§7). Beneath it,
//! `applier` is the applier lock and the one door to the write state it
//! guards, and `history` is the reads of the world, the commit chain and the
//! signature slot as of a past boundary, and of the committed boundaries above
//! a position (§6/§7).

mod applier;
mod history;

use std::any::Any;
use std::fmt;
use std::fs::File;
use std::io;
use std::num::NonZeroU64;
use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use arc_swap::{ArcSwap, ArcSwapOption};
use parking_lot::Mutex;

use crate::checkpoint::{self, CheckpointHeader};
use crate::config::{BurnedSeqPolicy, CheckpointPolicy, Durability, KernelConfig, SaltSource};
use crate::error::{at_file, CheckpointError, LandedStep, OpenError, TxnError};
use crate::journal::{
    self, Attestation, CommitFail, FirstSyncWord, Journal, JournalWriter, ScanFail, UnwindRepair,
};
use crate::replay::{self, SkippedBase};
#[cfg(feature = "test-hooks")]
use crate::Step;
use crate::{LockKey, Seam, Seq, WorldState};
use applier::ApplierLock;

/// What a journaled [`Kernel::open`] found in its directory and did (§7).
///
/// It is the start point the open's derivation resolved from, and every
/// retained checkpoint it passed over on the way there, each with the refusal
/// that passed it over — the account `open` owes its caller under the AUTH
/// spec's M2 seam delta ("`open` … reports the start point it resolved
/// from", AUTH-2.85), so the daemon above can log at startup which checkpoint
/// it did not start from and where it did (AUTH-2.86) — and the two acts of
/// the open itself: how many commits it replayed above that start point, and
/// how many bytes of un-acked tail it cut, so the open's own landing can be
/// said in figures rather than left to the silence between two lines — with
/// the facts that tell an operator what those figures do not: where the cut
/// began and what position an intact marker in it claimed, whether the cut
/// tail held intact frames no torn write leaves and the files its bytes were
/// then kept in, whether any journal stood in the directory at all, and the
/// corrupt runs below the start point the open read and passed over, which
/// the next fallback past that start point meets.
///
/// A report and never a verdict: a skipped base is no failure of the open —
/// the derivation succeeded from an older one — and the chain's one failure,
/// the exhausted chain, is [`OpenError::BadCheckpoint`]'s. Absent under
/// [`Durability::InMemory`], which loads nothing, replays nothing and cuts
/// nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recovery {
    /// `S_load`: the base coordinate the recovered world was folded from.
    ///
    /// A retained checkpoint's seq, or `Seq(0)` where genesis stood in.
    pub start_point: Seq,
    /// The retained checkpoints above the start point that were passed over.
    ///
    /// None of them could stand in. Newest first, each with why — a file that
    /// could not be read, a header or body that failed its checks, a body that
    /// would not decode, or a seed [`WorldState::rebuild_derived`] refused.
    pub skipped: Vec<SkippedBase>,
    /// The commits the open replayed above the start point.
    ///
    /// They are the transactions whose markers the scan closed in
    /// `(S_load, W]`, counted as the scan took them, never the records they
    /// carry: a composite of `m` records is one. `0` where the start point is
    /// the committed head — a base taken at the head with nothing committed
    /// since — and the whole journal's count where genesis stood in.
    pub replayed: u64,
    /// The bytes the open's tail truncation removed from the journal.
    ///
    /// They are the cut segment's bytes past the last committed marker — the
    /// whole first scanned segment where the scan found none — plus every
    /// wholly-later segment it discarded — §7's un-acked / torn tail,
    /// physically cut before any write is served. A crash's tail, which is
    /// what every open cuts of its own accord: a write caught before its
    /// commit was durable, and so never acknowledged. A tail that is not a
    /// crash's — damage, [`crate::DamagedTail`] — is cut only by an open
    /// told to ([`Durability::Fsync`]'s `cut_damaged_tail`), every one of its
    /// bytes first kept beside the journal ([`Recovery::tail_cut_kept`]); an
    /// open not told refuses and cuts nothing. `0` where the last committed
    /// marker ended the journal, as it does after every clean shutdown. A
    /// count and not an option: a cut that took nothing and no cut leave the
    /// same journal, so the two are one fact, and every journaled open runs
    /// the cut.
    pub tail_cut: u64,
    /// Of the frames the cut removed, the intact ones no torn write leaves.
    ///
    /// They are a commit marker that commits nothing, or a frame whose CRC
    /// passes and that does not decode. `0` after every clean shutdown and
    /// after every crash's cut — a crash leaves one only where the disk
    /// wrote an append's pages out of order, and a tail holding one is no
    /// crash's to this open: rot in the records of the journal's last
    /// committed transaction leaves one, and so does a rewrite of it, and the
    /// cut then may have taken a transaction this kernel acknowledged. So the
    /// open refuses such a tail ([`crate::DamagedTail`]) until it is told to
    /// cut it, and this is not `0` only after that accepted cut, whose bytes
    /// were kept beside the journal before one was cut
    /// ([`Recovery::tail_cut_kept`]). A tail refused for its length alone
    /// holds none, and cuts under the same word with this at `0`.
    pub tail_cut_intact: u64,
    /// Where the cut began: a file's name in the journal directory, and a byte.
    ///
    /// The file is the first a byte left, `seg-{n}.wal`, and the byte of it
    /// the cut began at — the cut segment at the last committed marker's frame
    /// end, or at its byte `0` where the scanned region holds no committed
    /// marker, or else the first wholly-later segment that held a byte, at
    /// byte `0`. `None` where [`Recovery::tail_cut`] is `0`. Where the bytes
    /// were kept, the first kept file holds them from its own byte `0` on.
    pub tail_cut_from: Option<(String, u64)>,
    /// The files the cut's bytes were kept in, by name, in journal order.
    ///
    /// Where the cut was an accepted cut of a damaged tail
    /// ([`Durability::Fsync`]'s `cut_damaged_tail`), every byte it took was
    /// first kept beside the journal, durably, before a byte was cut (§7's
    /// tail truncation): the cut segment's bytes from the cut on copied to
    /// `seg-{n}.wal.cut-{byte}`, and each wholly-later segment that held a
    /// byte moved whole to `seg-{n}.wal.cut-0`, a name already standing
    /// passed over for `….{k}` save a short copy of these very bytes, which
    /// the keep completes. No listing of the kernel's reads one, so a kept
    /// file is no segment and no base; no open writes over one, and an open
    /// removes one only where the keep that made or completed it fails. They
    /// are the operator's: the evidence of what the cut took and of what
    /// befell it, and the one copy of an acknowledged write it may have taken.
    /// None is to be moved back under its segment's name: the segment that
    /// name may since have been given is the next commits'. Empty for a
    /// crash's tail, which is cut and gone, and where nothing was cut.
    pub tail_cut_kept: Vec<String>,
    /// The position the cut tail claimed.
    ///
    /// It is the greatest `last_seq` an intact commit marker in the tail
    /// carried — a marker that committed nothing, which
    /// [`Recovery::tail_cut_intact`] counts. Rot in the journal's last
    /// committed transaction's records leaves that transaction's own marker
    /// intact, and this is then the position the transaction's
    /// acknowledgement named, its writer's and the change feed's alike: the
    /// one figure that names which acknowledged write the cut may have taken
    /// — and, where the cut could have held it, the position the order
    /// starts past ([`Kernel::order_floor`]), so no later write takes it.
    /// `None` where no intact marker stood in the cut — every crash's tail,
    /// and a tail whose intact frame does not decode, its fields unread.
    pub tail_cut_claimed: Option<Seq>,
    /// Whether no journal stood in the directory when the open listed it.
    ///
    /// No segment and no checkpoint stood, so the open began a journal at
    /// genesis rather than recovering one. Right on a fresh board's first
    /// open, and the one tell, on a board that had a journal, that the
    /// directory opened is not where the journal lives: a volume not mounted
    /// over its mount point, a mistyped path — where every later write lands
    /// on a new journal beside the real one, out of sight of it.
    pub began: bool,
    /// The corrupt runs below the start point that the open's scan passed over.
    ///
    /// The scan read them: runs in a segment straddling the start point, or in
    /// the active one, whose every position the start point embodies, so the
    /// open answered around them. Counted because a derivation from a base
    /// below a run meets it and refuses: a history read from an older base,
    /// and the open that falls back past this start point the day its
    /// checkpoint fails to load — damage this count names on every open
    /// before then. `0` on a journal with none.
    pub runs_passed_over: u64,
    /// The account of the first run [`Recovery::runs_passed_over`] counts.
    ///
    /// First in scan order: the files and the bytes its run spans, the
    /// position it holds none above, which bases meet it, and the act that
    /// clears it. `Some` exactly where the count is not `0`.
    pub first_run_passed_over: Option<String>,
}

/// One installed committed state (§Core data model).
///
/// The root's identity *is* the version coordinate. Reached only through
/// [`Snapshot`], and private to this module, where the three sites that mint
/// one each pair a coordinate with the world that embodies it — a world at a
/// coordinate it does not embody folds records it already holds, and since
/// [`WorldState::apply`] need not be idempotent, that is silent double
/// application answered `Ok`.
struct Committed<W> {
    seq: Seq,
    world: W,
    /// The commit chain's value at `seq`.
    ///
    /// It is what the transaction that installed this root carried in its
    /// marker, or what recovery derived for the committed head. Paired with
    /// the coordinate for the reason the world is — a checkpoint taken off
    /// this root writes it as the header's `chain_head`, and a chain read
    /// apart from the root it names would commit a later world under an
    /// earlier boundary. [`journal::CHAIN_GENESIS`] at `Seq(0)` and, under
    /// [`Durability::InMemory`], at every coordinate: there are no frames to
    /// hash, and the genesis value is what [`Kernel::chain_head`] and
    /// [`Snapshot::chain`] answer there.
    chain: [u8; 32],
}

/// A pinned, consistent view of one committed state.
///
/// It realizes MIC clauses 4 & 6 and A3/V0. A newtype over the loaded root
/// `Arc` — not a bare `Arc`, so it can carry the inherent [`seq`]/[`world`]
/// the orphan rule would forbid on a foreign `Arc` (§Public interface). Read
/// every constituent of a multi-read verdict off one `Snapshot` — that
/// discharges clause 6 / V2 by construction — and stamp the verdict with
/// this snapshot's [`seq`] (V1), never a later [`Kernel::current_seq`].
///
/// [`seq`]: Snapshot::seq
/// [`world`]: Snapshot::world
#[must_use = "a snapshot does nothing unless read; taking one and dropping it \
              leaves the kernel exactly as it was"]
pub struct Snapshot<W: WorldState>(Arc<Committed<W>>);

impl<W: WorldState> Snapshot<W> {
    /// Returns the committed index this view is *of* (V1 retrospective).
    ///
    /// By value (`Seq: Copy`).
    pub fn seq(&self) -> Seq {
        self.0.seq
    }

    /// Returns the committed world, for your store to read its slice off.
    ///
    /// Read it through your `HasX` accessor trait, per the composition
    /// contract — never concrete-field access.
    pub fn world(&self) -> &W {
        &self.0.world
    }

    /// Returns the commit chain's value at this view's coordinate.
    ///
    /// It is the third constituent the root carries, beside [`Snapshot::seq`]
    /// and [`Snapshot::world`]: the `chain` the marker closing that
    /// coordinate's transaction carries on disk, or what recovery derived for
    /// the committed head. The chain's genesis value (`journal::CHAIN_GENESIS`,
    /// thirty-two zero bytes) at `Seq(0)` and, under
    /// [`Durability::InMemory`], at every coordinate: there are no frames to
    /// hash. By value (`[u8; 32]: Copy`).
    ///
    /// Read it off the same snapshot as the [`Snapshot::seq`] it is paired
    /// with — the multi-read rule above — and `(seq(), chain())` names one
    /// committed state: the chain *of* that coordinate. [`Kernel::current_seq`]
    /// and [`Kernel::chain_head`] read the same two fields lock-free, but in
    /// two loads, between which a commit may land. `/health`'s pair is read
    /// here, through one root load.
    pub fn chain(&self) -> [u8; 32] {
        self.0.chain
    }
}

impl<W: WorldState> Clone for Snapshot<W> {
    /// Bumps the pinned root's refcount, never copying `W`.
    ///
    /// Clone freely to read one committed state from several places; that is
    /// what keeps a multi-read verdict on one snapshot (MIC clause 6 / V2)
    /// where taking a second [`Kernel::snapshot`] would silently read a later
    /// state.
    fn clone(&self) -> Self {
        Snapshot(Arc::clone(&self.0))
    }
}

impl<W: WorldState> fmt::Debug for Snapshot<W> {
    /// Writes the coordinate, not the world.
    ///
    /// `W` is the whole engine state and is not required to be `Debug`
    /// (§Public interface).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Snapshot")
            .field("seq", &self.0.seq)
            .finish_non_exhaustive()
    }
}

/// The in-flight state of one transaction's closure (§3).
///
/// `base` = Σ (the installed root at txn start), `working` = Σᵢ (base folded
/// with the records staged so far — ASN-0047's "observable intermediate
/// states", visible only to the executing closure, never to external
/// readers), `records` = the staged authoritative deltas.
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

    /// Returns Σ, the installed root at txn start.
    ///
    /// This `&W` carries no `seq()`; the base *index* is `transact`'s to
    /// report (§Public interface).
    pub fn base(&self) -> &W {
        &self.base.world
    }

    /// Returns Σᵢ, the base folded with the records pushed so far.
    ///
    /// Frontier/allocation math must read here (via the store's `HasX`
    /// accessor), so each atom of a multi-atom run mints at the frontier the
    /// prior atoms left — reading the unchanging `base()` would recompute one
    /// address m times and collide (§3/§4, W2).
    pub fn working(&self) -> &W {
        &self.working
    }

    /// Folds `record` into `working` and appends it to the txn's records.
    ///
    /// Stage your store's own record type lifted via `.into()` — never the
    /// central `Record` (composition contract).
    ///
    /// This is where [`WorldState::apply`] runs on the write path: once per
    /// staged record, inside the [`Kernel::transact`] closure and therefore
    /// on the applier lock's critical section — which is why a composite's
    /// record count is a cost that method's transaction budget accounts for.
    pub fn push(&mut self, record: W::Record) {
        self.working = self.working.apply(&record);
        self.records.push(record);
    }
}

impl<W: WorldState> fmt::Debug for Staging<W> {
    /// Writes the base coordinate and how many records are staged against it.
    ///
    /// They are the two facts that place a transaction in flight. Neither
    /// world is printed: `W` is the whole engine state and is not required to
    /// be `Debug`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Staging")
            .field("base_seq", &self.base.seq)
            .field("staged", &self.records.len())
            .finish_non_exhaustive()
    }
}

/// The §6 auto-checkpoint trigger: the cadence policy and its counters.
///
/// The policy is evaluated against the counters. The mechanism is fixed —
/// the trigger is tested on commit, there is no timer thread — and only the
/// policy is the open knob. Lives in the applier-locked state and is
/// advanced, tested and reset only from there, so a caller-invoked
/// `checkpoint()` cannot disturb the cadence it never asked for (§6). The
/// two parts of it a running kernel moves are the byte bound and the commit
/// count ([`Kernel::set_cadence_bytes`], [`Kernel::set_cadence_commits`]),
/// each replaced under the same lock.
struct Cadence {
    policy: CheckpointPolicy,
    commits_since_reset: u64,
    bytes_since_reset: u64,
    /// When the counters were last reset.
    ///
    /// The trigger crossing resets them, and the open starts the first
    /// window; that is what `Interval` measures from.
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

    /// Charges one commit of `bytes` journal bytes against the threshold.
    ///
    /// It answers whether the commit crossed the threshold. A crossing resets
    /// the counters, so the next window starts at this commit — every counter,
    /// whichever half of a composite crossed. A quiescent kernel — nothing new
    /// to charge — correctly never crosses, `Interval` included (§6).
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

    /// Tests `policy` for a crossing against the counters as they stand.
    ///
    /// A read of them, never an advance, so a composite tests both halves
    /// against the same figures and the order of the two tests cannot
    /// matter: `EitherOf` crosses when either does, and `Deferred` crosses
    /// exactly when its inner policy does (*where* the checkpoint then runs is
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

/// The `Seq` order's high-water and the two operations that move it (§2).
///
/// They are minting the contiguous `Seq` range a transaction commits at, and
/// rolling back a failed transaction's burned range. Lives in the
/// applier-locked state, so the order is drawn under the same lock that
/// installs — which is what makes it gap-free under
/// [`BurnedSeqPolicy::Rollback`] and a composite's records `Seq`-contiguous.
/// The burned-`Seq` policy is captured here at `open`, so the commit path
/// asks the configuration nothing.
///
/// [`BurnedSeqPolicy::Rollback`]: crate::BurnedSeqPolicy::Rollback
struct Sequencer {
    high_water: u64,
    /// The position the order never goes back below (§7).
    ///
    /// It is the committed head the open recovered, or — after an accepted
    /// cut of a damaged tail — the position an intact marker in the cut
    /// claimed, where the cut could have held it: a rollback under
    /// [`BurnedSeqPolicy::Rollback`] sets the high-water back to the base the
    /// failed transaction found, which before the first commit after such an
    /// open is the head below the claim, and this is what keeps the claimed
    /// positions a gap rather than the next transaction's.
    ///
    /// [`BurnedSeqPolicy::Rollback`]: crate::BurnedSeqPolicy::Rollback
    floor: u64,
    burned_seq: BurnedSeqPolicy,
}

impl Sequencer {
    /// Returns the order a recovery hands over.
    ///
    /// The single `Seq` high-water is the whole of the recovered sequencer
    /// state: `Txn` is a transaction's first `Seq`, so the next session's
    /// first `Txn` = W + 1 needs no second counter (§1/§7) — `W` being the
    /// committed head, or the position an accepted cut's tail claimed where
    /// that lies above it (`floor`; [`Kernel::order_floor`]).
    fn recovered(floor: u64, burned_seq: BurnedSeqPolicy) -> Sequencer {
        Sequencer {
            high_water: floor,
            floor,
            burned_seq,
        }
    }

    /// Draws the contiguous range `first..=last` this transaction commits at.
    ///
    /// It is the one site a `Seq` is minted (§2). `None` when the order has no
    /// room left for it: `last` would overflow, or would be the top coordinate
    /// itself, which leaves no coordinate for a successor — the invariant
    /// recovery checks of every committed head ([`Kernel::open`] refuses a
    /// head with no successor as [`OpenError::Corruption`]), established here,
    /// where every head is made, so a kernel never commits a journal it cannot
    /// reopen. Renumbering over a committed predecessor is not an option, so
    /// there is nothing this order can answer with, and what to do about that
    /// is the kernel's to decide.
    ///
    /// `n ≥ 1` is carried by the type, which is what makes `high_water + 1`
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

    /// Rolls back a failed transaction's burned range, if the policy says to.
    ///
    /// The roll-back is an absolute set back to `base_seq`, the head the
    /// transaction found, hence idempotent, iff [`BurnedSeqPolicy::Rollback`]
    /// is in force — never below the order's floor, which a base below the
    /// position an accepted cut's tail claimed is until the first commit
    /// after that open. Under [`BurnedSeqPolicy::TolerateGap`] this does
    /// nothing and the order relaxes to monotone-only, with recovery
    /// tolerating the gap (§1/§3).
    ///
    /// [`BurnedSeqPolicy::Rollback`]: crate::BurnedSeqPolicy::Rollback
    /// [`BurnedSeqPolicy::TolerateGap`]: crate::BurnedSeqPolicy::TolerateGap
    fn roll_back_to(&mut self, base_seq: Seq) {
        if self.burned_seq == BurnedSeqPolicy::Rollback {
            self.high_water = base_seq.0.max(self.floor);
        }
    }
}

/// State owned by the single applier lock (§3/§8).
///
/// The `Seq` order, the journal, and the §6 on-commit checkpoint trigger.
/// Reached only through [`ApplierLock::acquire`]: the lock's fields are
/// private to `applier`, so the door that refuses a nested acquisition is the
/// only way in.
struct ApplierState {
    sequencer: Sequencer,
    journal: Journal,
    cadence: Cadence,
}

/// What a journaled kernel has and an in-memory one does not.
///
/// Where its files live, how many checkpoint bases its `BadCheckpoint`
/// fallback chain keeps, the Σ₀ its derivations fold onto when no checkpoint
/// covers a boundary, and the `open()`-held exclusion lock it holds for its
/// lifetime (Lifecycle, §6).
///
/// One value rather than several optional fields, so "is there a journal?" is
/// one question with one answer: under [`Durability::InMemory`] there is no
/// directory, no fallback chain, nothing to derive and nothing to exclude, and
/// the caller's `genesis` is consumed into the root rather than kept.
struct Journaled<W> {
    /// The journal's directory as `journal_path` named it at the open.
    ///
    /// It was resolved there to an absolute path, so no later move of the
    /// process's working directory moves a file the kernel touches.
    dir: PathBuf,
    retain_checkpoints: usize,
    /// Σ₀, the genesis world this kernel was opened under.
    ///
    /// Kept because it is the base every history read falls back to when no
    /// checkpoint covers the boundary ([`Kernel::world_at`],
    /// [`Kernel::chain_at`], [`Kernel::attestation_at`]) or the position
    /// ([`Kernel::boundaries_above`]).
    genesis: W,
    /// What the open found and did ([`Kernel::recovery`]).
    ///
    /// The start point, the bases it passed over, the commits it replayed and
    /// the tail it cut.
    recovery: Recovery,
    /// The `checkpoint.tmp` the open removed, by its length in bytes.
    ///
    /// A checkpoint a crash or a failed write left half-written, which the
    /// kernel's own directory contract makes the kernel's to delete
    /// ([`Kernel::stray_checkpoint_removed`]); `None` where none stood.
    stray_checkpoint_removed: Option<u64>,
    /// The names the open passed over that may still stand on disk.
    ///
    /// The seqs of `recovery.skipped`, less any a later checkpoint wrote over
    /// — which retention passes over when it counts the bases to keep and
    /// removes as excess (`checkpoint::retain`); emptied once a landing has
    /// removed them. Taken inside [`Kernel::checkpoint`] alone, under its
    /// mutex, so the lock is a formality the type asks for.
    skipped_bases: Mutex<Vec<u64>>,
    /// The journal bytes the last landing reclaimed.
    ///
    /// It is [`Kernel::last_reclaimed_bytes`]'s figure: the lengths of the
    /// segments `reclaim_below` removed, each read before its removal, summed
    /// — or [`NO_LANDING`] before the first landing of this uptime. Stored by
    /// [`Kernel::checkpoint`] after its reclamation step, read lock-free.
    last_reclaimed: AtomicU64,
    /// The checkpoints the last landing's retention removed.
    ///
    /// They are [`Kernel::last_removed_checkpoints`]'s, each by its seq and
    /// its length, read before the removal — empty before the first landing of
    /// this uptime and after a landing that removed none. Stored beside
    /// `last_reclaimed`, at the end of a landed call, read lock-free.
    last_removed: ArcSwap<Vec<(Seq, u64)>>,
    /// The `open()`-held exclusive advisory lock, kept for its `Drop`.
    ///
    /// The flock releases when this file closes (Lifecycle).
    _lock: File,
}

/// [`Journaled::last_reclaimed`]'s value before any landing.
///
/// A figure no landing reclaims, since the segments one removes together fit
/// a volume. A landing that reclaimed nothing stores `0`, which is an answer.
const NO_LANDING: u64 = u64::MAX;

/// What a journaled recovery hands [`Kernel::open`].
///
/// The root it commits from, the live appender, the exclusion lock, the
/// account of the open, and the stray `checkpoint.tmp` it removed — five
/// values one call produces, named so the open reads each by what it is
/// rather than by its place in a tuple.
struct Recovered<W> {
    root: Committed<W>,
    journal: Journal,
    lock: File,
    recovery: Recovery,
    stray_checkpoint_removed: Option<u64>,
    /// The order's floor ([`Kernel::order_floor`]): the root's seq, or the
    /// position an accepted cut's tail claimed where that lies above it.
    order_floor: u64,
}

/// One checkpoint [`Kernel::transact`] ran inline on a committing thread (§6).
///
/// The inline arms' at every crossing, the backstop's under
/// [`CheckpointPolicy::Deferred`] — as [`Kernel::last_inline_checkpoint`]
/// answers the last of them: which commit carried it, how long it kept that
/// commit's caller waiting past the commit itself, and how it ended. The run
/// takes no applier lock, so the kernel's other writers proceed beside it;
/// a caller that serializes its own writes around `transact`, as a daemon
/// does, holds every one of them for `held`.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InlineCheckpoint {
    /// The position the committing transaction installed.
    ///
    /// It is the `last_seq` its own `transact` answered, whose crossing ran
    /// the checkpoint.
    pub after: Seq,
    /// The run's duration on the committing thread.
    ///
    /// From the call into [`Kernel::checkpoint`] after that commit installed
    /// to its return.
    pub held: Duration,
    /// How it ended: the position it landed at, or its failure as text.
    ///
    /// The position is [`Kernel::checkpoint`]'s `Ok`; the failure is rendered
    /// as text — never the error value, which does not clone.
    pub outcome: Result<Seq, String>,
}

/// The transactional kernel over an engine-supplied `W` (§Public interface).
///
/// v1 concurrency realization: the single applier (§8) — every write runs to
/// completion under one global lock, subsuming the `LockKey` seam; the
/// `transact`/`snapshot` signatures are invariant across realizations.
pub struct Kernel<W: WorldState> {
    root: ArcSwap<Committed<W>>,
    applier: ApplierLock,
    /// The lock that serializes `checkpoint()` against itself (§6).
    ///
    /// Caller calls and the on-commit auto-trigger alike; distinct from the
    /// applier lock so persisting and reclaiming never block writers.
    ///
    /// **Lock order.** This is taken while the applier lock is held (from
    /// inside a [`Kernel::transact`] closure, which that precondition permits)
    /// or with no lock held at all, and never the reverse:
    /// [`Kernel::checkpoint`] must acquire no applier lock, or a
    /// closure-invoked checkpoint deadlocks against a concurrent writer —
    /// silently, and indistinguishably from a slow fsync.
    checkpoint_mutex: Mutex<()>,
    poisoned: AtomicBool,
    /// Why the kernel halted, in words.
    ///
    /// Set once, by [`Kernel::poison`], the one site that raises `poisoned`
    /// from the commit path, before it raises it — so a reader that sees the
    /// flag reads the cause — and read lock-free by [`Kernel::poison_cause`].
    /// The first poisoning's cause stands: a halted kernel commits nothing
    /// more, so nothing later can be the reason it halted.
    poison_cause: OnceLock<String>,
    /// The due flag (§6, the deferred arm).
    ///
    /// Set by a crossing under [`CheckpointPolicy::Deferred`] in place of an
    /// inline checkpoint, read lock-free by [`Kernel::checkpoint_due`], and
    /// cleared first by every [`Kernel::checkpoint`]. Its one other reader is
    /// the crossing itself: a crossing that finds it already set runs the
    /// checkpoint inline, the backstop. The `poisoned` flag's shape, and like
    /// it never a gate — a flag read false may be set by the next commit.
    checkpoint_due: AtomicBool,
    /// The inline count (§6).
    ///
    /// How many checkpoints [`Kernel::transact`] has run on a committing
    /// thread this uptime — the inline arms' at every crossing, and the
    /// backstop's at a crossing that found the due flag set — read lock-free
    /// by [`Kernel::inline_checkpoints`]. Moved after each such run returns,
    /// landed or failed; a run that unwinds moves it not, the unwind being the
    /// caller's.
    inline_checkpoints: AtomicU64,
    /// The last inline run, as [`InlineCheckpoint`] records it.
    ///
    /// The commit whose crossing ran it, how long it held that commit's
    /// caller, and how it ended, a failure as text — never the error value,
    /// which does not clone — or `None` before the first. Stored before the
    /// count moves, so a reader that sees the count move reads a record at
    /// least as new as that run's ([`Kernel::last_inline_checkpoint`]).
    last_inline: ArcSwapOption<InlineCheckpoint>,
    cfg: KernelConfig,
    /// The order's floor, fixed at the open ([`Kernel::order_floor`]).
    order_floor: Seq,
    /// The write-fault seam this kernel's write paths hook before each step.
    ///
    /// The commit path and the checkpoint write, and the open's tail keep
    /// before them, hook it before [their steps](crate::Step): under
    /// `test-hooks` the state the `#[doc(hidden)]` doors arm, shared with the
    /// journal appender, which holds a second handle; without the feature a
    /// no-op. One per kernel, never the process's.
    seam: Seam,
    /// The journaled half, or `None` under [`Durability::InMemory`].
    ///
    /// Every path that touches files asks here, save the commit path, which
    /// asks its [`Journal`] — the same answer, both made at the open — so the
    /// mode question is one question with one answer. Last, so the exclusion
    /// lock it carries drops after the applier's appender — a kernel releases
    /// its journal only once it has stopped writing to it.
    journaled: Option<Journaled<W>>,
}

impl<W: WorldState> fmt::Debug for Kernel<W> {
    /// Writes the installed head, the poison and due flags, and the config.
    ///
    /// That is, whether the write paths are halted and whether a checkpoint
    /// is due, beside the head and the configuration — read lock-free, so this
    /// is safe to call from anywhere, including a `Drop` under the applier
    /// lock. The world itself is not printed: `W` is the whole engine state
    /// and is not required to be `Debug`.
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
    /// Recovers or initializes a kernel (Lifecycle, §7).
    ///
    /// Under [`Durability::Fsync`] it recovers the journal by the steps under
    /// `# Errors`, whose order is the order its refusals speak in.
    ///
    /// Under [`Durability::InMemory`]: no journal to name, no recovery, and
    /// the root is initialized directly from `genesis` (`S_load = 0`);
    /// [`WorldState::rebuild_derived`] is not run, so `genesis` is installed
    /// exactly as given — which is why that value must already carry its own
    /// derived hints ([`WorldState::rebuild_derived`]'s genesis obligation).
    ///
    /// **Caller contract.** `genesis` (= Σ₀) must be byte-identical on every
    /// `open()` of a given journal: recovery folds journaled deltas onto it
    /// wherever no checkpoint stands in, never onto a journaled root; a
    /// drifting `genesis` silently mis-recovers. M2 cannot check this
    /// (ASN-0047's fixed Σ₀ satisfies it by construction).
    ///
    /// **Damage model.** Three outcomes, pinned case by case by the chain's
    /// tamper matrix (`tests/it/chain.rs`) against a file-level writer of the
    /// journal directory who can rewrite any byte and re-fix any CRC. What
    /// recovery detects is frames that fail their CRC or do not decode — the
    /// corrupt-run verdict, which speaks first where there is one — and chain
    /// links that fail, the base mismatch and the intact transaction no intact
    /// marker closes among them.
    ///
    /// **Caught** — a chain break: [`OpenError::Corruption`] naming the
    /// `last_seq` of the first committed transaction above the base whose
    /// marker's chain is not the recomputation over its predecessor's value
    /// and its own bytes — record payloads, marker fields, salt and slot
    /// digest — the cause travelling and nothing cut. A record payload
    /// rewritten with every CRC re-fixed, at that transaction; a marker's chain
    /// field edited, at that transaction, the next never masking it; two
    /// transactions swapped, at the one now sitting first; a transaction
    /// deleted and the file closed up, a closed segment rolled back to an older
    /// copy of itself, a closed segment absent — each at the next transaction,
    /// the one chaining from a predecessor the scan never saw (§7 requires no
    /// `Seq` contiguity, so by coordinates alone each of these reads as a
    /// shorter world, answered `Ok` at the true head); two damages of one kind,
    /// at the first only — the halt names the first of each kind, and a chain
    /// link above a break is judged from the marker's own claim, so one edit is
    /// one verdict; of two kinds, at the one [`OpenError::Corruption`] lists
    /// first, whatever their coordinates — an edited transaction speaks
    /// before an earlier, independent chain break, as a corrupt run speaks
    /// before both.
    /// A checkpoint's `chain_head` edited, at the base's own coordinate where
    /// the marker closing it is scanned — at the head whenever the active
    /// segment holds the head's marker, which it does unless that segment is
    /// empty after a rotation whose transaction failed or never landed, when
    /// the head's marker ends the closed segment before it and is skipped
    /// (residue (ii)'s boundary coincidence below; the matrix's case 15) —
    /// and at the first transaction above it otherwise: nothing in the header
    /// covers that field, so the base loads and the journal contradicts it,
    /// at its own marker where that marker is read, else at the first chain
    /// link judged against it. A marker's `txn`, `records_checksum` or
    /// `last_seq` edited, at that transaction, as an intact transaction no
    /// intact marker closes — its own refusing it, or naming another
    /// transaction as its own — a shape no writer of this format leaves, so
    /// the marker was rewritten; on the last transaction too, where
    /// un-committing it would otherwise have been the torn tail recovery
    /// cuts; and at any height in a segment the scan reads, below a standing
    /// base as well, since that verdict compares a marker with its own
    /// records and needs no chain link from the base. The signature slot is a
    /// chain input by digest (the matrix's case 4): a slot filled, stripped or
    /// altered after its commit, its CRC re-fixed, is caught at that
    /// transaction. The salt is one too (`SKJ4`, the matrix's case 16): a
    /// marker's salt edited, its CRC re-fixed, is caught at that transaction —
    /// and being drawn at random per transaction under [`SaltSource::Os`] and
    /// served by no route, it is what keeps a served chain value from
    /// confirming a guess at a transaction's bytes, while against a party
    /// holding the journal, who holds the bytes, it protects nothing.
    ///
    /// **Refused** — the checkpoint's own door: a body rewritten with its CRC
    /// re-fixed fails `body_hash`, the fallback reaches an older base or
    /// genesis, and the journal above it re-verifies.
    ///
    /// **Not caught by design** — histories the chain alone accepts, which are
    /// the published head's to catch ([`Kernel::chain_head`] is its input; a
    /// peer holding an older head checks that the new history *extends* it —
    /// against this kernel's recomputation through [`Kernel::chain_at`], which
    /// the daemon serves as `GET /chain?at=N`). A clean tail cut — the last
    /// transactions removed at a boundary — opens at the shorter head. A
    /// consistent re-chain — a rewrite at any point with every later chain
    /// link recomputed, from genesis or mid-history, the retained checkpoints'
    /// heads rewritten with it — passes: the chain has no anchor but its
    /// genesis value and the base's header, and a base's body, which nothing
    /// compares to the journal below it, the forger re-mints with this
    /// kernel's own `checkpoint()` over the forged replay. A checkpoint body
    /// forged with its CRC and `body_hash` re-fixed loads as the base. The
    /// base-mismatch check has three residues: (i) the header and the marker
    /// closing its seq edited consistently, every chain link above re-chained
    /// from the edit — the open passes, and a history read below the base
    /// recomputes the chain link at the base's seq over its predecessor and
    /// fails it, unless the forger re-chained from below that too, which is
    /// the consistent re-chain; (ii) the base's marker segment reclaimed or
    /// skipped — a closed segment ending exactly at the base's seq, the
    /// boundary coincidence — where the check is vacuous: the first chain link
    /// above the base is judged against the header, and a header edited with
    /// nothing above it opens on the edit; (iii) two retained checkpoints
    /// edited consistently with the journal re-chained between them, the
    /// consistent re-chain again. And a rewrite below a standing base (the
    /// matrix's case 12): the chain is verified for transactions above the
    /// base a replay selects, so a consistent rewrite below a standing base —
    /// its CRCs and `records_checksum` re-fixed, so it commits — is unseen at
    /// `open` while that base stands, seen by any history read below the base
    /// — which verifies every chain link from the base it selects to the
    /// journal's end — and beyond any replay once reclamation drops the
    /// segment; an edited transaction there is caught, as above. The
    /// `journal_path` caller contract still keeps the files whole; what it
    /// does not have to keep is the silence.
    ///
    /// **Caught at the tail** (the matrix's case 17): a frame of the last
    /// transaction rewritten so it does not decode — a payload tag, a length
    /// prefix, the signature slot's one spelling of empty — its CRC re-fixed.
    /// Mid-history the corrupt run it opens halts at the next intact frame
    /// (case 4); in the last transaction the run lies above the committed
    /// head, where §7's tail rule asks whether the tail is a crash's, and a
    /// CRC-intact frame that does not decode says it is not: the open
    /// refuses it as a damaged tail ([`OpenError::Corruption`] carrying
    /// [`crate::DamagedTail`]), the journal as found, as it refuses an intact
    /// marker committing nothing and a frameless tail longer than one append
    /// — until the configuration accepts the cut by name
    /// ([`Durability::Fsync`]'s `cut_damaged_tail`), when the tail is kept
    /// beside the journal ([`Recovery::tail_cut_kept`]) and cut, and no
    /// position it claimed is handed out again ([`Kernel::order_floor`]).
    ///
    /// # Errors
    ///
    /// The configuration is validated first — a rule this kernel does not
    /// offer is refused with [`OpenError::InvalidConfig`] before the journal
    /// lock is taken and before any file is read.
    ///
    /// Under [`Durability::Fsync`]: take the exclusive advisory journal lock
    /// (a second `open()` of the same journal fails with [`OpenError::Io`]);
    /// load the latest valid retained checkpoint @`S_load` and seed it through
    /// [`WorldState::rebuild_derived`] — on a bad one, or one whose seed
    /// refuses ([`RebuildError`](crate::RebuildError): a base that is not a
    /// start point, AUTH-2.84/2.85), fall back to the next-older retained
    /// checkpoint, then to genesis while still reachable (earliest surviving
    /// segment's `firstSeq` still `Seq(1)`; chain exhausted ⟹
    /// [`OpenError::BadCheckpoint`]), and report the start point and every
    /// base passed over as [`Kernel::recovery`] — scan the journal (Pass 1:
    /// derive `W` = the last committed marker's `last_seq`, classify corrupt
    /// runs by inferred `Seq` max — in `(S_load, W]` ⟹
    /// [`OpenError::Corruption`], halt, never drop), replay exactly
    /// `S_load < Seq ≤ W` through [`WorldState::apply`] in `Seq` order (Pass 2
    /// — no contiguity required: `TolerateGap` burns fold harmlessly), judge
    /// the tail beyond `W` — a crash's, or damage, which is
    /// [`OpenError::Corruption`]'s ninth cause and halts unless the
    /// configuration accepts the cut — then durably truncate it before any
    /// write is served (skipped on every halt path; a truncation failure
    /// fails `open()` with `Io` — idempotent, retried next `open()`), an
    /// accepted cut of a damaged tail first keeping its every byte beside the
    /// journal ([`Recovery::tail_cut_kept`]; a keep that fails cuts nothing
    /// and fails `open()` with `Io` the same way). A committed-but-unacked
    /// tail marker is replayed — the lost-ack case is the client's (ASN-0134
    /// SAFE(b)(iii)), not a phantom.
    ///
    /// **Refusal precedence.** The steps above are the order in which refusals
    /// speak: [`OpenError::InvalidConfig`] precedes the lock, the lock
    /// precedes any read of the journal, [`OpenError::BadCheckpoint`] precedes
    /// the first-sync-word probe — the first scanned segment's opening is read
    /// once the base has said where the scan begins, and before a byte of the
    /// scan — which answers [`OpenError::ForeignFormat`] for a journal of
    /// another format and [`OpenError::Corruption`] for one damaged sync word;
    /// and every route to `Corruption` — [`OpenError::Corruption`] lists them
    /// in the order they speak, the damaged tail last, after the fold —
    /// precedes the tail truncation, which is why a halt never cuts anything.
    pub fn open(cfg: KernelConfig, genesis: W) -> Result<Self, OpenError> {
        cfg.validate().map_err(OpenError::InvalidConfig)?;
        // The seam is made here, before the appender it is handed to and
        // the kernel that holds it exist, so one state serves both.
        let seam = Seam::default();
        let (root, journal, journaled, order_floor) = match &cfg.durability {
            // "Directly from genesis" (Lifecycle): no journal, no recovery,
            // no rebuild_derived — the caller's live value becomes the root,
            // and nothing else here wants it, so it is moved rather than kept.
            Durability::InMemory => (
                Committed {
                    seq: Seq(0),
                    world: genesis,
                    chain: journal::CHAIN_GENESIS,
                },
                Journal::InMemory,
                None,
                0,
            ),
            Durability::Fsync {
                journal_path,
                retain_checkpoints,
                cut_damaged_tail,
                ..
            } => {
                // The directory as the path names it now: a relative path is
                // resolved against the working directory once, here, so every
                // file the kernel touches afterwards lies under the directory
                // it named at the open, wherever that working directory moves.
                let dir = std::path::absolute(journal_path)
                    .map_err(at_file(journal_path.display(), "resolve"))?;
                let recovered =
                    Self::recover(&dir, &genesis, cfg.salt, *cut_damaged_tail, seam.clone())?;
                // The names the open passed over, for retention to pass over
                // in turn, until the first landing has removed them.
                let skipped_bases = recovered.recovery.skipped.iter().map(|b| b.seq.0).collect();
                (
                    recovered.root,
                    recovered.journal,
                    Some(Journaled {
                        dir,
                        retain_checkpoints: *retain_checkpoints,
                        genesis,
                        recovery: recovered.recovery,
                        stray_checkpoint_removed: recovered.stray_checkpoint_removed,
                        skipped_bases: Mutex::new(skipped_bases),
                        last_reclaimed: AtomicU64::new(NO_LANDING),
                        last_removed: ArcSwap::from_pointee(Vec::new()),
                        _lock: recovered.lock,
                    }),
                    recovered.order_floor,
                )
            }
        };
        Ok(Self::assemble(cfg, root, journal, journaled, seam, order_floor))
    }

    /// Recovers the journal at `dir`, answering what the open commits from.
    ///
    /// It answers the root the open commits from, its live appender — handed
    /// `salt_source`, the configured [`SaltSource`] every transaction it
    /// commits draws from (`SKJ4`); recovery itself draws nothing, reading
    /// each salt off its marker — and `seam`, the kernel's write-fault seam,
    /// which the appender's append, barrier and repair hook before they run;
    /// the exclusion lock the kernel holds for its lifetime, the account of
    /// the base it stood on and the bases it passed over (§7), the stray
    /// `checkpoint.tmp` it removed, if one stood, and the order's floor
    /// ([`Recovered`]). `cut_damaged_tail` is the configuration's word on a
    /// damaged tail ([`Durability::Fsync`]): without it such a tail halts
    /// the open; with it the tail is kept and cut. Recovery's own writes —
    /// the stray's removal, the tail cut and its keep, the first segment's
    /// creation — run no step of the seam but the tail keep's fsync
    /// ([`crate::Step::TailKeep`]), hooked on `seam`, which nothing has
    /// armed: it was made for this open.
    ///
    /// # Errors
    ///
    /// Every refusal of [`Kernel::open`] past its configuration's and its
    /// path's resolution, in the order that method's doc states.
    fn recover(
        dir: &Path,
        genesis: &W,
        salt_source: SaltSource,
        cut_damaged_tail: bool,
        seam: Seam,
    ) -> Result<Recovered<W>, OpenError> {
        // The directory, owner-only: every component this creates is born
        // with the kernel's directory mode (`journal::dir_builder`), as every
        // file the kernel creates in it is born with its file mode; one that
        // already stands is left exactly as found.
        journal::dir_builder()
            .recursive(true)
            .create(dir)
            .map_err(at_file(dir.display(), "create"))?;
        let lock = journal::acquire_journal_lock(dir)?;
        // The stray temp file, removed under the flock before anything is
        // listed: a checkpoint a crash or a failed write left half-written
        // under the fixed temp name is no base (`checkpoint::list` would skip
        // it by name) and keeps its room on the volume — which, after a
        // write the volume's room failed, is the room the next checkpoint
        // needs. The name is one of those the kernel owns in this
        // directory, so the file is the kernel's to delete; the caller is
        // told it was, and how large it was, through
        // [`Kernel::stray_checkpoint_removed`].
        let stray_checkpoint_removed = checkpoint::remove_stray_tmp(dir)?;
        let segs = journal::list_segments(dir)?;
        let checkpoints = checkpoint::list(dir)?;
        // No journal stood here: what this open begins is a journal at
        // genesis, which the report says ([`Recovery::began`]) — right on a
        // fresh board, and the one tell of a directory that is not where the
        // board's journal lives.
        let began = segs.is_empty() && checkpoints.is_empty();

        // The base, with its whole fallback chain: newest retained checkpoint
        // that loads and seeds → next-older retained → genesis-while-reachable;
        // an exhausted chain is the operator-intervention condition (§6/§7).
        // What the chain passed over is reported, never a failure.
        let base = replay::select_base(&checkpoints, &segs, None, genesis).map_err(|fail| {
            OpenError::BadCheckpoint { cause: fail.cause }
        })?;
        // The report's first two members, read off the base before the fold
        // consumes it; the rest are the scan's counts and the cut's, known
        // once each has run, and whether a journal stood at all, known above.
        let start_point = Seq(base.s_load());
        let skipped = base.skipped().to_vec();

        // The first-sync-word probe, ahead of the scan (the encoding report's
        // §8). A segment written under another format holds no frame this
        // build's sync word anchors, so the scan would read the whole of it as
        // one corrupt run reaching end-of-file — the un-acked tail — and the
        // cut below would truncate it to nothing and serve an empty world over
        // a journal it had just erased. Refused by name instead, before a byte
        // is scanned and before any write to a segment or a checkpoint: those
        // stay as they were found, the open having only taken its lock and
        // removed a stray `checkpoint.tmp`. A single damaged sync word —
        // foreign-shaped, before a frame of this build's — is refused as
        // early, and as the damage it is: its remedy is to restore the
        // segment, where a format's discards the journal.
        match journal::first_sync_word(&segs, base.s_load())? {
            FirstSyncWord::Scan => {}
            FirstSyncWord::Foreign { found, segment } => {
                return Err(OpenError::ForeignFormat {
                    found,
                    expected: journal::MAGIC,
                    segment,
                });
            }
            // The probe reads a frame header and no `Seq`, so the coordinate
            // is the base's own: where the scan would have begun. The
            // account names the segment, the one file the remedy touches.
            FirstSyncWord::Damaged { found, segment } => {
                return Err(OpenError::Corruption {
                    at: Seq(base.s_load()),
                    cause: Some(journal::damaged_sync_word_cause(found, &segment)),
                });
            }
        }

        // Pass 1: derive W, classify the corrupt runs and verify the chain
        // (§7). A scan that could not take a segment in within its bounds —
        // enumerate its frame stream in bounded work, or read it in bounded
        // memory — produces no outcome at all and halts here, its account
        // naming the segment and the bound it broke. Of the runs it does
        // report, those beyond W and the EOF ones are the un-acked/torn tail,
        // physically discarded below, and those at or below S_load are
        // already embodied in the base.
        let scan = base.scan(&segs, None).map_err(|fail| match fail {
            ScanFail::Io(e) => OpenError::Io(e),
            ScanFail::Unscannable { at, cause } => OpenError::Corruption {
                at: Seq(at),
                cause: Some(cause),
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

        // The tail's class, the last refusal (§7): a crash's tail is cut
        // below as every open cuts it; damage — an intact frame no torn
        // write leaves, or more bytes than one append leaves — may hold a
        // write this kernel acknowledged, so it halts the open, the journal
        // as found, unless the configuration accepts the cut by name. Judged
        // after the fold, so a committed record that does not decode speaks
        // ahead of it, as the other at-rest verdicts do; the coordinate is
        // the position the tail claims, else the first above the head.
        if let Some(damaged) = scan.damaged_tail() {
            if !cut_damaged_tail {
                return Err(OpenError::Corruption {
                    at: damaged.claimed.unwrap_or(Seq(next_seq)),
                    cause: Some(Box::new(damaged)),
                });
            }
        }

        // Tail truncation: after every refusal, and before any write is
        // served (§7). The fold serves none, so the §7 obligation is kept
        // while an `open()` that refuses leaves the journal exactly as it
        // found it, save the lock file and a stray `checkpoint.tmp` it
        // removed — which is what an operator images after a halt. It is
        // also before the appender is opened over that segment, whose length
        // this cut settles and which the appender reads once. Where the tail
        // is damage the cut was accepted above, and the cut keeps its every
        // byte beside the journal before it cuts one. What it cut, in bytes
        // and from where, and the files it kept them in, is the open's to
        // report, as the commits the fold replayed are: the scan counted
        // those as it closed their markers, the intact frames of no writer's
        // in the tail as it met them, with the position their markers
        // claimed, and the corrupt runs below the start point it read and
        // passed over.
        let cut = journal::truncate_tail(dir, &scan, cut_damaged_tail, &seam)?;
        // The order's floor: the head, or the position an accepted cut's
        // tail claimed where the cut could have held it, so a client holding
        // that acknowledgement is never shown another write under it. The
        // appender continues past it; the root stays at the head, the
        // positions between a gap the next recovery folds across.
        let order_floor = scan.restored_high_water();
        let next_seq = order_floor.checked_add(1).ok_or(OpenError::Corruption {
            at: Seq(order_floor),
            cause: None,
        })?;
        let (runs_passed_over, first_run_passed_over) = scan.runs_passed_over();
        let recovery = Recovery {
            start_point,
            skipped,
            replayed: scan.commits_above_base,
            tail_cut: cut.bytes,
            tail_cut_intact: scan.tail_intact,
            tail_cut_from: cut.from,
            tail_cut_kept: cut.kept,
            tail_cut_claimed: scan.tail_claimed.map(Seq),
            began,
            runs_passed_over,
            first_run_passed_over,
        };

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
            order_floor,
        })
    }

    fn assemble(
        cfg: KernelConfig,
        root: Committed<W>,
        journal: Journal,
        journaled: Option<Journaled<W>>,
        seam: Seam,
        order_floor: u64,
    ) -> Self {
        let cadence = Cadence::new(cfg.checkpoint.clone());
        let sequencer = Sequencer::recovered(order_floor, cfg.durability.burned_seq_policy());
        Kernel {
            root: ArcSwap::from_pointee(root),
            applier: ApplierLock::new(ApplierState {
                sequencer,
                journal,
                cadence,
            }),
            checkpoint_mutex: Mutex::new(()),
            poisoned: AtomicBool::new(false),
            poison_cause: OnceLock::new(),
            checkpoint_due: AtomicBool::new(false),
            inline_checkpoints: AtomicU64::new(0),
            last_inline: ArcSwapOption::empty(),
            cfg,
            order_floor: Seq(order_floor),
            seam,
            journaled,
        }
    }

    /// Runs `f` on a consistent base and commits what it staged, atomically.
    ///
    /// It holds `keys` for the txn's duration, runs `f` against a consistent
    /// base state, and — iff `f` returns `Ok` with ≥1 staged record — commits
    /// them atomically — durably, under one commit marker, where journaled —
    /// installs the root, then returns (A7 commit-before-acknowledge;
    /// MIC clauses 1/2/3/5/7).
    /// Returns `(T, Seq)`: the closure's value and the committed `last_seq` —
    /// a write's exact V1 retrospective coordinate (for a multi-record
    /// composite the interior `Seq`s are M2-internal; the terminal `last_seq`
    /// is the one observable boundary — §2).
    ///
    /// `f` → `Ok` with zero records: zero-step op (A1: read-only / idem-hit /
    /// nullify-hit), no commit; the returned `Seq` is the base `Committed`'s
    /// seq — the committed index the op evaluated against (A2/V1; under
    /// per-commit `Fsync` that base is durable, so a zero-step op never waits
    /// on the durability barrier — but like every transaction it waits for the
    /// applier lock and then clones `W` to stage against, both of which a
    /// zero-step op pays in full, which is why [`Kernel::snapshot`] and not a
    /// zero-step `transact` is the read path, §5).
    ///
    /// `f` may take this kernel's reads ([`Kernel::snapshot`],
    /// [`Kernel::current_seq`], [`Kernel::world_at`]): they acquire no applier
    /// lock and observe Σ, the base, never the staged Σᵢ — which is what makes
    /// a composite's intermediates invisible to external readers (§3).
    /// [`Kernel::checkpoint`] likewise acquires no applier lock; one taken
    /// from inside `f` embodies Σ, not the transaction in flight. A composite
    /// composes neighbors' pure math inside one closure (§3; seam contract 3).
    ///
    /// **Transaction budget.** One transaction's encoded form is bounded by
    /// [`crate::MAX_TXN_BYTES`], and a transaction past it whose records all
    /// frame is refused with [`TxnError::OverBudget`], in both durability
    /// modes, before the journal is touched. The budget bounds four costs: the
    /// first, second and fourth transient, the third durable. Three scale with
    /// a transaction's bytes: the whole transaction is serialized under the
    /// applier lock, so every other writer in the process waits behind it; its
    /// serialized bytes live twice for the length of the commit region, once
    /// as records and once as the frames they become; and — because a
    /// transaction never spans a segment — the segment holding it is at least
    /// that large, and recovery reads a segment whole, so the budget is what
    /// keeps the memory floor of every later `open()` and every
    /// [`Kernel::world_at`] bounded, and identical on every replica. The fourth
    /// scales with the record count instead: [`Staging::push`] folds each
    /// staged record through [`WorldState::apply`], which builds a new world
    /// per record, and it runs inside `f` and therefore on that same critical
    /// section — so a composite of `m` records costs `m` folds of `W` there,
    /// over and above the one clone every transaction pays. The budget bounds
    /// `m` only at [`crate::MAX_TXN_BYTES`] over the 40 journal bytes a record
    /// occupies at minimum — over a million and a half — so a caller batching
    /// small records is choosing that figure rather than inheriting one from
    /// here. A composite too large for the budget is split by the caller;
    /// atomicity of the split is then the caller's, as it already is for every
    /// multi-`transact` batch (ASN-0134 A5).
    ///
    /// Under the v1 single applier the global lock subsumes `keys` (§4):
    /// callers still pass the keys they would need under the deferred per-key
    /// realization, so it slots in later without changing any call shape.
    /// `keys` is a set as far as this kernel is concerned — order and
    /// duplicates are the kernel's to normalize under any realization, never
    /// the caller's to arrange — so no store invents an ordering discipline
    /// the deferred per-key realization would then have to honour.
    ///
    /// A committing call may additionally take a checkpoint before it
    /// returns: the §6 on-commit trigger is evaluated under the applier lock
    /// and, when it crosses under an inline arm of the policy,
    /// [`Kernel::checkpoint`] runs to completion on this thread —
    /// serializing `W`, writing and fsyncing a file, applying retention,
    /// reclaiming segments — after the commit is durable and installed. Its
    /// failure is not the transaction's: the transaction is already
    /// acknowledged, so there is no sound path for that error through
    /// [`TxnError`], and the kernel has no logging seam — but every such run
    /// is counted and the last one recorded: the commit that ran it, how long
    /// it held this thread past that commit, and how it ended, a failure kept
    /// as text ([`Kernel::inline_checkpoints`],
    /// [`Kernel::last_inline_checkpoint`]), the facts a caller above reads and
    /// says. Under [`CheckpointPolicy::Deferred`] the crossing sets the due
    /// flag instead ([`Kernel::checkpoint_due`]) and this thread runs nothing
    /// — the caller's own thread runs [`Kernel::checkpoint`] and reads the
    /// result — unless the flag is already set, the last crossing unserviced,
    /// when the checkpoint runs inline here after all, the backstop that keeps
    /// the window bounded, counted and recorded as every inline run is. A
    /// caller who needs to know whether checkpointing is succeeding calls
    /// [`Kernel::checkpoint`] itself and reads the result, or reads the count
    /// and the record; a kernel that has stopped checkpointing inline goes on
    /// committing.
    ///
    /// # Errors
    ///
    /// `f` → `Err(e)`: clean typed rejection ([`TxnError::Rejected`]),
    /// nothing committed, no dangling state.
    ///
    /// Staged records that cannot be journaled — a serializer that refuses,
    /// or a record past the journal's frame cap — are
    /// [`TxnError::Unencodable`]: a no-op like [`TxnError::Durability`], and
    /// unlike it, one that re-invoking with the same records cannot fix. A
    /// transaction whose records all encode but whose whole encoded form —
    /// frames, marker and headers — exceeds the journal's per-transaction
    /// budget, [`crate::MAX_TXN_BYTES`], is [`TxnError::OverBudget`]: the
    /// same no-op with a different remedy — no record is at fault, the
    /// staging is, and the caller splits the transaction where fixing a value
    /// cannot help, save a single record no transaction can carry beside its
    /// marker, which must shrink. Both size limits are judged above the
    /// durability-mode branch, so an in-memory kernel refuses exactly what a
    /// journaled one refuses — a store that passes an in-memory test does not
    /// meet a size refusal only in production.
    ///
    /// On a poisoned kernel the refusal precedes `f`: the call returns
    /// [`TxnError::Poisoned`] without running the closure, so a closure with
    /// effects of its own does not run for a transaction that cannot commit.
    ///
    /// **Refusal precedence.** Several of these can hold at once, and this is
    /// the order in which they speak: the reentrancy panic first, being a
    /// caller's bug and answered before the applier lock is even taken; then
    /// [`TxnError::Poisoned`], before `f` runs; then `f`'s own
    /// [`TxnError::Rejected`]; then the zero-step `Ok`; then
    /// [`TxnError::Poisoned`] again where the `Seq` order has no room left for
    /// this transaction, which is judged before the journal is consulted and
    /// poisons on the way out; and inside the commit region
    /// [`TxnError::Unencodable`] before [`TxnError::OverBudget`] before
    /// [`TxnError::Durability`]: the encode and the size accounting precede
    /// the first file operation, a refusal that belongs to the records must
    /// not be reported on the channel a caller retries, and a record's own
    /// refusal precedes the transaction's, so a caller fixing a value is not
    /// first told to split. `Poisoned` displaces `Durability` where the tail
    /// truncation itself cannot complete durably, which
    /// [`TxnError::Durability`] states.
    ///
    /// # Panics
    ///
    /// Panics where `f` takes this kernel's applier lock again — the
    /// precondition: `f` must not call `transact` or
    /// [`Kernel::transact_attested`] on this kernel, nor a cadence setter
    /// ([`Kernel::set_cadence_bytes`], [`Kernel::set_cadence_commits`]); this
    /// call holds the applier lock for the whole of `f`, so a nested write can
    /// never proceed. The violation is a caller's bug and is answered as one —
    /// a panic naming the broken obligation — not as the deadlock it would
    /// otherwise be.
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
    /// A panic after the commit region — the on-commit checkpoint's own (`W`'s
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

    /// Runs [`Kernel::transact`] with the transaction's signature slot filled.
    ///
    /// It is `transact` with the signature slot of this transaction's commit
    /// marker filled (signed ops; the design record §2.4's inbound route):
    /// where `attestation` is `Some`, the marker `encode_txn` writes for this
    /// transaction carries its tag and blob in the slot X2 reserves, and
    /// nothing else about the commit moves but its chain — the records, their
    /// frames, the salt and the accounting the transaction budget names are as
    /// `transact` leaves them, the blob's bytes sitting outside that budget
    /// (the design record §4.4 (b)) and bounded instead by
    /// [`crate::MAX_SIG_BYTES`], which [`Attestation::new`] holds every value
    /// to — so the marker's own frame stays inside the frame cap at any width
    /// an attestation can have — while the link closes over the slot's digest,
    /// so an attested transaction's chain value is not its unattested twin's.
    /// `None` is `transact` exactly: the slot written empty, in its one
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
    ///
    /// # Errors
    ///
    /// [`Kernel::transact`]'s refusals, in its order: an attested commit
    /// meets no refusal its unattested twin would not.
    ///
    /// # Panics
    ///
    /// As [`Kernel::transact`] does: where `f` takes this kernel's applier
    /// lock again, and with the panics it propagates.
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
        // The staging holds the root for the whole of this call — the
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
            self.poison(format!(
                "no position is left above position {} for a transaction of {n} records: a \
                 journal whose head leaves no position above it is refused at the next open, so \
                 none was committed",
                state.sequencer.high_water
            ));
            return Err(TxnError::Poisoned);
        };

        // The commit region: one call into the journal, which serializes the
        // records, judges the size limits no mode may skip, and commits
        // (§1: append records → marker → one fsync → install). Run under
        // catch_unwind so the §3 guard can repair a mid-commit unwind — the
        // encode is where a record's own `Serialize` can panic, so it must
        // sit inside the guard; the guard fires only on unwind, and the error
        // returns below carry the journal's own verdict on what its failure
        // left behind.
        //
        // A transaction's serialized bytes live inside that call twice for
        // the length of the region — once as records, once as the frames they
        // become — and all of it under the applier lock, so it is also the
        // length of time every other writer waits. The staging is moved in, so
        // it is that pair and not a third copy: each record is released as the
        // journal encodes it. The journal is what bounds both, refusing above
        // its own mode branch: the frame cap per record and `MAX_TXN_BYTES` per
        // transaction, identically in both durability modes.
        let commit_out: std::thread::Result<Result<u64, CommitFail>> = {
            let state = &mut *state;
            let root = &self.root;
            catch_unwind(AssertUnwindSafe(move || {
                state.journal.commit_txn(first, records, attestation, move |chain| {
                    // Atomic install after durability (A0/A4; durable-before-
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
                    UnwindRepair::Unrepaired(repair) => self.poison(format!(
                        "a panic unwound out of the commit of {}{}, and the truncation that \
                         repairs it failed ({repair}): its frames may stand on disk, so the next \
                         open decides whether it stands",
                        positions(first, last),
                        panic_words(&*payload)
                    )),
                    UnwindRepair::AfterBarrier => self.poison(format!(
                        "a panic unwound out of the commit of {}{} after its barrier and before \
                         its install: it is durable, so the next open replays it",
                        positions(first, last),
                        panic_words(&*payload)
                    )),
                }
                drop(applier);
                resume_unwind(payload)
            }
            // §1/§3: the barrier never completed and the journal is durably
            // back where this txn found it — a true no-op the caller may
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
            // splitting it changes that, save a single record past the budget
            // beside its marker, which must shrink (§1/§3).
            Ok(Err(CommitFail::OverBudget { bytes })) => {
                state.sequencer.roll_back_to(base_seq);
                Err(TxnError::OverBudget { bytes })
            }
            // The truncation itself could not complete durably (§1).
            Ok(Err(CommitFail::Unrepaired { failed, repair })) => {
                self.poison(format!(
                    "the commit of {} failed ({failed}), and the truncation that repairs it \
                     failed too ({repair}): its frames may stand on disk, so the next open \
                     decides whether it stands",
                    positions(first, last)
                ));
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
                    // The deferred arm: the crossing sets the due flag for the
                    // caller's thread to service, and runs nothing here —
                    // unless the flag was already set, the last crossing not
                    // yet serviced, when the backstop runs the checkpoint
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
                        // the run is counted and recorded — the commit that
                        // ran it, how long it held this caller, how it ended
                        // — for the caller above to read and say; safe by
                        // §6's crash argument (at most a .tmp the write or
                        // the next open removes, an extra base, and an
                        // unreclaimed journal).
                        let began = Instant::now();
                        let outcome = self.checkpoint();
                        self.note_inline_run(Seq(last), began.elapsed(), outcome);
                    }
                }
                Ok((value, Seq(last))) // commit-before-acknowledge (A7, MIC-3)
            }
        }
    }

    /// Records one checkpoint [`Kernel::transact`] ran inline.
    ///
    /// It ran on a committing thread ([`InlineCheckpoint`]): the commit at
    /// `after` that ran it, the run's duration `held`, and how it ended — its
    /// failure as text — stored first, then the count moved, so a reader that
    /// sees the count move reads a record at least as new as that run's. The
    /// error value itself goes no further: it is not `Clone`, and the caller
    /// above wants the sentence.
    fn note_inline_run(&self, after: Seq, held: Duration, outcome: Result<Seq, CheckpointError>) {
        let outcome = outcome.map_err(|e| e.to_string());
        self.last_inline.store(Some(Arc::new(InlineCheckpoint { after, held, outcome })));
        self.inline_checkpoints.fetch_add(1, Ordering::AcqRel);
    }

    /// Halts the write paths (§1/§3), saying why.
    ///
    /// The cause is kept first, then the flag raised, so a reader of
    /// [`Kernel::poison_cause`] that saw [`Kernel::is_poisoned`] answer `true`
    /// reads the cause beside it. The one door to the commit path's halt, so
    /// no poisoning goes unsaid.
    fn poison(&self, cause: String) {
        let _ = self.poison_cause.set(cause);
        self.poisoned.store(true, Ordering::Release);
    }

    /// Returns one committed state, pinned (MIC clauses 4 & 6; A3/V0/V2).
    ///
    /// One lock-free `ArcSwap` load. Infallible, and continues to serve the
    /// last in-memory root even on a poisoned kernel: the poison paths
    /// (§1/§3) leave that root a consistent committed state, so reads stay
    /// sound; only write/checkpoint paths fail with `Poisoned`.
    pub fn snapshot(&self) -> Snapshot<W> {
        Snapshot(self.root.load_full())
    }

    /// Returns how many checkpoints [`Kernel::transact`] has run inline (§6).
    ///
    /// Run on a committing thread this uptime: under an inline arm of the
    /// policy, every crossing's; under [`CheckpointPolicy::Deferred`], the
    /// backstop's alone — a crossing that found the due flag still set, the
    /// last crossing unserviced, and ran the checkpoint on the writer's
    /// thread, its result reaching no caller but as the record
    /// ([`Kernel::last_inline_checkpoint`]). A caller's own
    /// [`Kernel::checkpoint`] moves it not, nor does a run that unwinds; a
    /// run counts whether it landed or failed, and under
    /// [`Durability::InMemory`], where the run is the no-op, it counts as
    /// landed. Lock-free, like [`Kernel::checkpoint_due`]: the caller above
    /// reads it once per commit beside that flag, and where it moved reads
    /// [`Kernel::last_inline_checkpoint`] and says so — the kernel still has
    /// no logging seam; it answers a fact. The count and the record are two
    /// loads, between which a run may land.
    pub fn inline_checkpoints(&self) -> u64 {
        self.inline_checkpoints.load(Ordering::Acquire)
    }

    /// Returns the last checkpoint [`Kernel::transact`] ran inline.
    ///
    /// It ran on a committing thread, as [`InlineCheckpoint`] records it —
    /// the commit whose crossing ran it, how long the run held that commit's
    /// caller, and whether it landed and where, or how it failed — or `None`
    /// where no run has happened this uptime. Written at each inline run, so
    /// the answer is the last run's and not the last failure's, which is what
    /// a line saying "the last landed" or "the last failed" needs. Read
    /// lock-free, with the count's caveat ([`Kernel::inline_checkpoints`]).
    pub fn last_inline_checkpoint(&self) -> Option<InlineCheckpoint> {
        self.last_inline.load_full().map(|run| InlineCheckpoint::clone(&run))
    }

    /// Returns how the last checkpoint [`Kernel::transact`] ran inline failed.
    ///
    /// As text — [`Kernel::last_inline_checkpoint`]'s outcome where it is a
    /// failure — or `None` where that run landed, or no run has happened.
    pub fn last_inline_checkpoint_failure(&self) -> Option<String> {
        self.last_inline.load_full().and_then(|run| run.outcome.as_ref().err().cloned())
    }

    /// Returns the checkpoints the last landing's retention removed.
    ///
    /// The landing is the last landed [`Kernel::checkpoint`]'s; oldest first,
    /// each by its seq and its file's length in bytes, read before the
    /// removal: the oldest bases past the `retain_checkpoints` kept, and every
    /// base the open passed over that still stood — whose removal is the end
    /// of the evidence [`Kernel::recovery`]'s `skipped` names. Empty where the
    /// landing removed none, before any landing of this uptime, and under
    /// [`Durability::InMemory`]; a failed call stores nothing, as
    /// [`Kernel::last_reclaimed_bytes`]'s figure is stored. Lock-free, read
    /// after `Ok`.
    pub fn last_removed_checkpoints(&self) -> Vec<(Seq, u64)> {
        self.journaled.as_ref().map_or_else(Vec::new, |journaled| {
            Vec::clone(&journaled.last_removed.load())
        })
    }

    /// Returns the journal bytes the last landing reclaimed.
    ///
    /// The landing is the last landed [`Kernel::checkpoint`]'s; the figure is
    /// the lengths of the closed segments its reclamation removed below the
    /// oldest kept base, each read before its removal and summed. `Some(0)`
    /// where the landing removed no segment — a landing that reclaims
    /// nothing says so — and `None` before any landing of this uptime, and
    /// under [`Durability::InMemory`], which has no journal to reclaim. A
    /// failed call stores nothing: the figure is a landing's, and a call
    /// that failed before or after its base landed is not one, whatever its
    /// reclamation removed before failing. Lock-free, in
    /// [`Kernel::stray_checkpoint_removed`]'s shape, read after `Ok`; the
    /// landing's `Ok` type carries the seq alone.
    pub fn last_reclaimed_bytes(&self) -> Option<u64> {
        let journaled = self.journaled.as_ref()?;
        match journaled.last_reclaimed.load(Ordering::Acquire) {
            NO_LANDING => None,
            bytes => Some(bytes),
        }
    }

    /// Returns what [`Kernel::open`] found in the journal directory and did.
    ///
    /// The start point it resolved from, the retained checkpoints it passed
    /// over, the commits it replayed and the tail it cut ([`Recovery`]; §7;
    /// AUTH-2.85) — or `None` under [`Durability::InMemory`], which loaded
    /// nothing. Fixed at `open`: a checkpoint taken since neither adds to it
    /// nor retires an entry, since the report is of the open and not of the
    /// directory as it now stands — retention removing a skipped base retires
    /// nothing here either. Lock-free, like every other read.
    pub fn recovery(&self) -> Option<&Recovery> {
        self.journaled.as_ref().map(|journaled| &journaled.recovery)
    }

    /// Returns the position the order started past at the open (§7).
    ///
    /// It is the committed head the open recovered — equal to
    /// [`Kernel::current_seq`] at the open — save after an accepted cut of a
    /// damaged tail ([`Durability::Fsync`]'s `cut_damaged_tail`), where an
    /// intact marker in the cut claimed a position above the head
    /// ([`Recovery`]'s `tail_cut_claimed`) and the cut could have held it:
    /// then it is that position, so the first transaction after the open
    /// takes the one after it and a client holding the acknowledgement that
    /// named it finds a missing write there, never another's. The positions
    /// between the head and it are a gap the next recovery folds across, and
    /// a rollback of a failed transaction never goes below it. A claim the
    /// cut could not have held — a `last_seq` forged past what its bytes
    /// could number, or at the order's ceiling — is not trusted, and the
    /// floor is the head. `Seq(0)` under [`Durability::InMemory`]. Fixed at
    /// `open`; lock-free.
    pub fn order_floor(&self) -> Seq {
        self.order_floor
    }

    /// Returns the currently installed root's seq.
    ///
    /// Equal at the instant of call to a `snapshot()` taken then, but not a
    /// substitute for it across calls, and not the stamp for a
    /// snapshot-computed verdict (a write may land between; stamp with the one
    /// `Snapshot`'s [`Snapshot::seq`] instead — V1, §5). Install is
    /// serialized, so this never regresses. Infallible, including when
    /// poisoned.
    pub fn current_seq(&self) -> Seq {
        self.root.load().seq
    }

    /// Returns the commit chain's value at the installed head.
    ///
    /// It is the `chain` the marker closing [`Kernel::current_seq`]'s
    /// transaction carries on disk, or what recovery derived for that head —
    /// the last committed marker's above the base, else the base's own (the
    /// `SKC4` header's `chain_head`, or the chain's genesis value at genesis).
    /// The genesis value at every coordinate under [`Durability::InMemory`],
    /// where there are no frames to hash. Read lock-free off the root, like
    /// [`Kernel::current_seq`] and with the same caveat: equal at the instant
    /// of call to the value for that coordinate, and no substitute for reading
    /// the two together — a commit may land between two calls.
    ///
    /// **The published head's input** (`/health`): what a periodically
    /// published head carries, and what a peer holding an older head checks
    /// the new history *extends* — the closer for the histories the chain
    /// alone accepts, which [`Kernel::open`]'s damage model names.
    pub fn chain_head(&self) -> [u8; 32] {
        self.root.load().chain
    }

    /// Returns whether this kernel's write paths are halted (§1/§3).
    ///
    /// An unrecoverable failure halts them — the state [`TxnError::Poisoned`]
    /// and [`CheckpointError::Poisoned`] report. Lock-free and infallible,
    /// like the other reads, so a supervisor can ask without taking the
    /// applier lock, cloning `W`, or writing a checkpoint file.
    ///
    /// Not a gate: a kernel healthy at this call may poison before the next
    /// write, so the authoritative answer is the refusal [`Kernel::transact`]
    /// returns. Poison is terminal in the other direction, so a `true` here is
    /// actionable without a race. Why it halted is [`Kernel::poison_cause`]'s.
    pub fn is_poisoned(&self) -> bool {
        self.poisoned.load(Ordering::Acquire)
    }

    /// Returns why the write paths halted, in words an operator acts on.
    ///
    /// `None` while this kernel has not halted them. The words say which of
    /// the three unrecoverable failures [`TxnError::Poisoned`] lists it was,
    /// the transaction by its positions — the operator stream's word for its
    /// coordinates — and the failures' own words — each naming its segment and
    /// its act, the truncation's beside the step's it failed to repair — and
    /// what the next open does with what stands. A panic's words ride it only
    /// where the panic's payload is a literal the code wrote, never a
    /// formatted one, whose text a record's values may have made. Kept as
    /// text, set once, before the halt is visible, by the commit path's one
    /// poisoning door. Lock-free, like [`Kernel::is_poisoned`], and for the
    /// operator's stream: it names files and failures, so it is not a member
    /// to serve to every reader.
    pub fn poison_cause(&self) -> Option<&str> {
        self.poison_cause.get().map(String::as_str)
    }

    /// Returns whether a checkpoint is due (§6, the deferred arm).
    ///
    /// It is due when a commit has crossed the cadence under
    /// [`CheckpointPolicy::Deferred`] since the last [`Kernel::checkpoint`]
    /// began, and the checkpoint it calls for has not been started. Lock-free
    /// and infallible, like [`Kernel::is_poisoned`]: the caller's checkpoint
    /// thread reads it to decide whether to run [`Kernel::checkpoint`], which
    /// clears it first and then runs — so a `true` read after that call
    /// returns is a crossing during the run, which the thread services by
    /// running once more. Never set under any other arm, whose crossings run
    /// inline; never a gate, since the next commit may set it; and never
    /// cleared by anything but a call to `checkpoint`, so a caller that reads
    /// it true and runs nothing leaves the next crossing to the backstop
    /// ([`Kernel::transact`]).
    pub fn checkpoint_due(&self) -> bool {
        self.checkpoint_due.load(Ordering::Acquire)
    }

    /// Moves the cadence's byte bound to `bytes`.
    ///
    /// The bound is every [`CheckpointPolicy::JournalBytes`] threshold the
    /// policy holds, wherever its arms nest one, and the answer is whether the
    /// policy held one to move. One of the two figures of the cadence a
    /// running kernel changes, [`Kernel::set_cadence_commits`] the other:
    /// every other value of the configuration is read once, at
    /// [`Kernel::open`] ([`KernelConfig`]). It serves a caller that sizes the
    /// bound by the newest checkpoint and re-reads it as each lands
    /// ([`Kernel::newest_checkpoint`] answers the size). Taken under the
    /// applier lock, where the cadence lives and is tested: the next commit
    /// tests the new bound against the counters as they stand — the window
    /// in progress is neither reset nor re-charged — and a crossing it makes
    /// resets them as any crossing does. `n ≥ 1` is the type's, so the rule
    /// [`Kernel::open`] validates holds after every call.
    ///
    /// # Panics
    ///
    /// Panics when called from inside a [`Kernel::transact`] or
    /// [`Kernel::transact_attested`] closure on this kernel, which holds the
    /// lock this takes.
    pub fn set_cadence_bytes(&self, bytes: NonZeroU64) -> bool {
        let mut applier = self.applier.acquire();
        applier.cadence.policy.set_bytes(bytes)
    }

    /// Moves the cadence's commit bound to `commits`.
    ///
    /// The bound is every [`CheckpointPolicy::EveryN`] count the policy
    /// holds, wherever its arms nest one, and the answer is whether the policy
    /// held one to move: [`Kernel::set_cadence_bytes`]'s twin, under the same
    /// lock and the same rules (the window in progress is neither reset nor
    /// re-charged). A caller that moves both bounds past any count it will
    /// commit holds off every crossing but an `Interval`'s for its life, which
    /// is what a suite measuring a board that must reclaim nothing does.
    ///
    /// # Panics
    ///
    /// Panics when called from inside a transact closure on this kernel, as
    /// [`Kernel::set_cadence_bytes`] does.
    pub fn set_cadence_commits(&self, commits: NonZeroU64) -> bool {
        let mut applier = self.applier.acquire();
        applier.cadence.policy.set_commits(commits)
    }

    /// Returns the size of the stray `checkpoint.tmp` the open removed.
    ///
    /// The file is a checkpoint a crash or a failed write left half-written
    /// under the fixed temp name, which is no base and keeps its room on the
    /// volume until something deletes it; the name is one of those the
    /// kernel owns in its directory ([`Durability::Fsync`]'s `journal_path`
    /// contract), so that something is [`Kernel::open`], under the flock.
    /// `None` where none stood, and under [`Durability::InMemory`], which
    /// opens no directory. Fixed at `open`, like [`Kernel::recovery`], and
    /// kept apart from it: the report is of the directory as found, not of
    /// the derivation, and the daemon above renders it as its own startup
    /// line. A `.tmp` a failed [`Kernel::checkpoint`] leaves is removed by
    /// that call itself, best-effort, and reaches here only where that removal
    /// failed.
    pub fn stray_checkpoint_removed(&self) -> Option<u64> {
        self.journaled.as_ref().and_then(|journaled| journaled.stray_checkpoint_removed)
    }

    /// Persists a checkpoint of the installed root, then retains and reclaims.
    ///
    /// It persists a checkpoint embodying all records with `Seq ≤ s`, keeps
    /// the journal's `retain_checkpoints` most recent the open did not pass
    /// over, and reclaims whole *closed* journal segments lying wholly below
    /// the oldest retained checkpoint (segment-granular space reclamation,
    /// never a correctness mechanism — recovery's `Seq > S_load` filter
    /// handles straddler leftovers; §6). Non-blocking to writers (grabs a
    /// lock-free `Snapshot`, never the applier lock — which is a rule, not an
    /// economy: a closure inside [`Kernel::transact`] may call this while
    /// holding that lock, so reaching for it here would deadlock against a
    /// concurrent writer) and serialized against itself by the dedicated
    /// checkpoint mutex, whose lock order states the same rule from the other
    /// side. Cadence counters live in `transact`'s applier-locked state — a
    /// caller-invoked `checkpoint()` does not reset them (§6). Returns the
    /// checkpointed seq. Under [`Durability::InMemory`] and unpoisoned it is a
    /// no-op returning [`current_seq`].
    ///
    /// **The due flag is cleared first**, before any of that — whichever
    /// caller this is, the deferred arm's thread, the backstop or a caller of
    /// its own ([`Kernel::checkpoint_due`]): a crossing during the run then
    /// sets it again and the thread runs once more after, where a flag
    /// cleared after the run would send every crossing during it to the
    /// backstop, an inline checkpoint queued behind this one's mutex. A
    /// failure clears it the same, so the next attempt is the next crossing's:
    /// a kernel that cannot checkpoint is not asked again until there is
    /// something new to persist.
    ///
    /// **Retention counts every base but those the open skipped**: the
    /// `retain_checkpoints` kept are counted among the checkpoints this
    /// kernel's open did not pass over — the names it passed over
    /// ([`Kernel::recovery`]'s `skipped`) are passed over by the count and
    /// removed as excess, whatever their age — so the first landing after an
    /// open that skipped a base keeps the base the open loaded from beside the
    /// new one, where `retain_checkpoints` is two or more, and removes the
    /// skipped one; the reclamation floor is the oldest base kept.
    /// A base this call writes over a skipped name is a base again and is
    /// counted. With nothing skipped, the newest `retain_checkpoints` stand.
    ///
    /// The journal bytes a landing reclaimed, and the checkpoints its
    /// retention removed, are read after `Ok` through
    /// [`Kernel::last_reclaimed_bytes`] and
    /// [`Kernel::last_removed_checkpoints`].
    ///
    /// # Errors
    ///
    /// [`CheckpointError::Poisoned`] — a prior failure halted the kernel —
    /// outranks every other answer, the in-memory no-op included, so a halted
    /// kernel takes no checkpoint in either mode.
    ///
    /// A failure after the base landed — the rename ran, then the directory's
    /// fsync, retention or the journal's reclamation failed — is
    /// [`CheckpointError::Landed`], naming the step ([`LandedStep`]) and
    /// carrying the cause; an I/O failure before it is
    /// [`CheckpointError::Io`] and leaves no base, as does `W`'s serializer
    /// refusing, [`CheckpointError::Serialize`].
    ///
    /// A failed write leaves no `checkpoint.tmp` save one whose removal
    /// failed: the file is removed before the error is answered, best-effort,
    /// the removal's own failure folded into the account
    /// ([`CheckpointError::Io`]).
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
        // The seq, the world and the chain head off one root: a checkpoint
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
        // the open did not pass over, which answers with the oldest survivor.
        // This kernel leaves one: `retain_checkpoints ≥ 1` is validated at
        // `open`, and this call has just added to the set the retention is
        // applied to. Another process can still take it between the rename and
        // the listing — the flock excludes other kernels and nothing else (the
        // `journal_path` contract) — and an auto-triggered call runs after its
        // commit is acknowledged, so that is answered as the I/O failure it is,
        // over a base that landed, never as a panic in place of the commit's
        // `Ok`.
        let landed = |step: LandedStep| move |cause| CheckpointError::Landed { step, cause };
        let retained = checkpoint::retain(&journaled.dir, journaled.retain_checkpoints, &skipped)
            .map_err(landed(LandedStep::Retention))?;
        let s_old = retained.floor.ok_or_else(|| {
            landed(LandedStep::Retention)(io::Error::new(
                io::ErrorKind::NotFound,
                "the checkpoint this call wrote was gone before retention listed it: something \
                 other than this kernel removed it from the journal directory",
            ))
        })?;
        // Every file retention passed over is gone, so nothing stands to
        // pass over at the next landing.
        journaled.skipped_bases.lock().clear();
        // Reclaim the journal below the oldest kept checkpoint — that floor,
        // not the newest, is what keeps the BadCheckpoint fallback real (§6)
        // — and keep what it reclaimed, and the bases retention removed, for
        // the landing's reader.
        let reclaimed = journal::reclaim_below(&journaled.dir, s_old)
            .map_err(landed(LandedStep::Reclamation))?;
        journaled.last_reclaimed.store(reclaimed.min(NO_LANDING - 1), Ordering::Release);
        let removed = retained.removed.into_iter().map(|(seq, len)| (Seq(seq), len)).collect();
        journaled.last_removed.store(Arc::new(removed));
        Ok(s)
    }

    /// Returns what the checkpoint at `seq` claims by its `SKC4` header.
    ///
    /// It is [`Kernel::newest_checkpoint`]'s read, for one base named by its
    /// coordinate rather than for the newest: the start point's, which loaded
    /// ([`Kernel::recovery`]'s `start_point`), is what a caller sizes a floor
    /// or a byte bound by after an open that skipped a newer base, since the
    /// newest file's header is then the skipped base's claim. The file is
    /// named directly from `seq` — one short read, no listing — and held to
    /// the checks a header passes without its body. Fail-quiet as the newest
    /// read is: `None` where no file of that name stands — a seq no checkpoint
    /// was taken at, or one retention has since removed — where its header
    /// refuses, and under [`Durability::InMemory`]. The body is not verified,
    /// so a base whose body is damaged still answers its header, as the newest
    /// read answers it; `Seq(0)` names a file only where a checkpoint was taken
    /// before the first commit, genesis itself being no checkpoint. Lock-free:
    /// it consults the directory.
    pub fn checkpoint_header(&self, seq: Seq) -> Option<CheckpointHeader> {
        let journaled = self.journaled.as_ref()?;
        checkpoint::header_at(&journaled.dir, seq.0)
    }

    /// Returns what the newest retained checkpoint's `SKC4` header claims.
    ///
    /// Its coordinate, the commit chain's value there, its body's hash and
    /// its file's length as the header claims it, as a [`CheckpointHeader`] —
    /// or `None` under [`Durability::InMemory`] and before the first
    /// checkpoint. It is what a published head record's `base` member names
    /// (PUB-6.65), so a peer that copies a checkpoint file has its coordinate
    /// confirmed, a full replica verifies the base's canonical body by
    /// `body_hash`, and the coordinate survives the retention
    /// (`retain_checkpoints`) that drops the file — the base is the one
    /// durable record of a reclaimed checkpoint's coordinate. The length is
    /// the figure a caller sizes by: the room the next checkpoint takes on the
    /// volume, and the byte bound a cadence relative to it holds the journal
    /// to ([`Kernel::set_cadence_bytes`]).
    ///
    /// Reads the newest file's header alone — its fixed 88 bytes, never the
    /// body, which is the whole serialized world — so it costs one directory
    /// list and one short read whatever the world's size. The header is read
    /// through the checkpoint module's one header parse and held to every
    /// check a header can pass without its body: this build's stamp, and a
    /// seq agreeing with the file's name. A header either check refuses names
    /// no base: `None`, as on any I/O error or a file shorter than its own
    /// header — fail-quiet, because the head writer that reads this must
    /// never fail a commit over it, and writes `base: null` instead. The body
    /// is not verified: its checksum and hash need the body, and `body_hash`
    /// is what a party holding the file verifies it by. Lock-free, like
    /// [`Kernel::chain_head`]: it consults the directory, not the applier, so
    /// a checkpoint racing this read is at worst not-yet-seen — or, removed by
    /// a racing retention between the listing and the read, `None` — and
    /// never a torn one (a checkpoint is renamed into place whole).
    pub fn newest_checkpoint(&self) -> Option<CheckpointHeader> {
        let journaled = self.journaled.as_ref()?;
        checkpoint::newest_header(&journaled.dir)
    }

    /// Runs the shutdown/checkpoint hook, which has nothing to flush.
    ///
    /// It is the slot-in point for the deferred group-commit (`FsyncBatch`)
    /// durability mode, where it would flush the pending batch and advance
    /// that mode's `Clean{through}` durability watermark (Open build
    /// decisions) — the API is invariant across durability modes.
    ///
    /// # Errors
    ///
    /// None. Under per-commit `Fsync` every commit already fsyncs its
    /// records+marker barrier, so there is nothing pending and this is a
    /// no-op returning `Ok(())`; under the in-memory mode it is likewise a
    /// no-op, and on a poisoned kernel it is a no-op returning `Ok`.
    pub fn flush(&self) -> io::Result<()> {
        Ok(())
    }
}

/// Returns a transaction as a poisoning's cause names it.
///
/// By its one position, or the first and last of a composite's.
fn positions(first: u64, last: u64) -> String {
    if first == last {
        format!("the transaction at position {first}")
    } else {
        format!("the transaction at positions {first}–{last}")
    }
}

/// Returns a panic's own words as a poisoning's cause carries them.
///
/// They are ` ({words})`, where its payload is a `&'static str`: a literal the
/// code wrote, which no request can have formatted. A `String` payload is a
/// formatted panic, an `expect`'s or an `assert_eq!`'s, whatever its site
/// formatted — inside the commit region that site is a record's own
/// `Serialize`, so the text may hold record values — and the cause carries
/// nothing of it, as the binary's panic hook keeps such a payload off the
/// operator's stream (`operations.md` §1, what a line never carries). The
/// same literal words ride the hook's own line for the same panic, which is
/// what joins the two lines.
fn panic_words(payload: &(dyn Any + Send)) -> String {
    payload
        .downcast_ref::<&'static str>()
        .map_or_else(String::new, |words| format!(" ({words})"))
}

/// The write-fault seam's doors, in `test-hooks` builds only.
///
/// `hooks.rs` is the seam. They are how a test makes the next step of this
/// kernel's write paths fail or unwind on cue — and reads the one count the
/// seam keeps, the bases this kernel's history reads loaded. Each door arms
/// or reads this kernel's seam alone.
#[cfg(feature = "test-hooks")]
impl<W: WorldState> Kernel<W> {
    /// TEST HOOK (`test-hooks`): arms the next `step` to fail, once.
    ///
    /// The step is the next this kernel's write paths reach; it fails with an
    /// `io::Error` of `kind`, in the step's place — a full volume is
    /// [`io::ErrorKind::StorageFull`] — once: the arm fires and disarms, and
    /// the next call of the same step runs the real step. One arm per step;
    /// arming a step again replaces its arm. What each failure leaves and how
    /// it is answered is the step's own card ([`Step`]): the journal's three
    /// reach the caller through [`TxnError::Durability`] —
    /// [`TxnError::Poisoned`] for the repair's — with the kind unchanged, the
    /// checkpoint's two before the rename through [`CheckpointError::Io`] and
    /// the directory's fsync after it through [`CheckpointError::Landed`]. On
    /// an in-memory kernel the arm stands unfired: that kernel appends nothing
    /// and its [`Kernel::checkpoint`] is the no-op, so it reaches no step. On
    /// any kernel an arm at the tail keep stands unfired: that step runs only
    /// inside the open, before a door can arm it.
    #[doc(hidden)]
    pub fn fail_the_next(&self, step: Step, kind: io::ErrorKind) {
        self.seam.fail_the_next(step, kind);
    }

    /// TEST HOOK (`test-hooks`): arms the next `step` to panic, once.
    ///
    /// The step is the next this kernel's write paths reach, and the panic
    /// takes its place — the checkpoint write's three steps, whose unwind an
    /// inline checkpoint, an inline arm's or the backstop's, carries out of
    /// [`Kernel::transact`] after the commit landed, and the journal's append,
    /// the unwind out of the commit region the §3 guard repairs. Replaces any
    /// arm at the step; an in-memory kernel reaches no step, as
    /// [`Kernel::fail_the_next`] says.
    ///
    /// # Panics
    ///
    /// The barrier, the repair and the tail keep take no panic arm
    /// (`hooks.rs` says why), and naming one here is a caller's bug answered
    /// as one.
    #[doc(hidden)]
    pub fn panic_at_the_next(&self, step: Step) {
        self.seam.panic_at_the_next(step);
    }

    /// TEST HOOK (`test-hooks`): returns the steps an arm still stands at.
    ///
    /// In arming order — empty once every arm has fired, which is how a test
    /// reads that a step was reached.
    #[doc(hidden)]
    pub fn armed_steps(&self) -> Vec<Step> {
        self.seam.armed_steps()
    }

    /// TEST HOOK (`test-hooks`): returns how many bases history reads loaded.
    ///
    /// The bases this kernel's history reads have loaded since the open — one
    /// per base a read's selection stood on, a retained checkpoint's whole
    /// body read, hashed, deserialized and seeded, or genesis cloned and
    /// seeded: "the base loaded" every history read's cost paragraph counts
    /// ([`Kernel::world_at`], [`Kernel::boundaries_above`]), counted at its
    /// one site, the reads' base selection — so a suite fences what a caller
    /// costs in bases, which no clock can on a loaded machine: a consumer
    /// asking once over a window and one asking once per boundary read the
    /// same slots and differ here alone (§3.3 step 2 of the operations
    /// design). Not counted: recovery's base at the open, which runs the
    /// selection directly; a candidate the fallback chain passed over; a
    /// selection that refused `Reclaimed`. Monotone over the kernel's life and
    /// read lock-free; a suite reads it twice and pins the difference.
    #[doc(hidden)]
    pub fn bases_loaded(&self) -> u64 {
        self.seam.bases_loaded()
    }
}

#[cfg(test)]
mod tests;
