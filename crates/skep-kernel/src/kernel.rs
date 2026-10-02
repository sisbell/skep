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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwap;
use parking_lot::Mutex;

use crate::checkpoint::{self, CheckpointHeader};
use crate::config::{BurnedSeqPolicy, CheckpointPolicy, Durability, KernelConfig, SaltSource};
use crate::error::{CheckpointError, OpenError, TxnError};
use crate::journal::{
    self, Attestation, CommitFail, FirstSyncWord, Journal, JournalWriter, ScanFail, UnwindRepair,
};
use crate::replay;
use crate::{LockKey, Seq, WorldState};
use applier::ApplierLock;

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
    /// [`Kernel::attestation_at`]).
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
    /// damages, at the first only — the chain cannot see past a break. A
    /// checkpoint's `chain_head` edited, at the base's own coordinate where
    /// the marker closing it is scanned — at the head whenever the active
    /// segment holds the head's marker, which it does unless that segment is
    /// EMPTY after a rotation whose transaction failed or never landed, when
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
    /// appender — handed `salt_source`, the configured [`SaltSource`] every
    /// transaction it commits draws from (`SKJ4`); recovery itself draws
    /// nothing, reading each salt off its marker — and the exclusion lock the
    /// kernel holds for its lifetime (§7).
    fn recover(
        dir: &Path,
        genesis: &W,
        salt_source: SaltSource,
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
        // this cut settles and which the appender reads once.
        journal::truncate_tail(dir, &scan)?;

        let writer = JournalWriter::open_active(dir, next_seq, chain_head, salt_source)?;
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
    /// A panic AFTER the commit region — the superseded root's destructor,
    /// run as this call returns and releases what may be the last reference
    /// to it ([`WorldState`]'s drop obligation) — propagates with the
    /// transaction committed and installed: the lost-ack case (§3), the
    /// kernel not poisoned and its order intact.
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
        // checkpoint set, which answers with the oldest survivor. This kernel
        // leaves one: `retain_checkpoints ≥ 1` is validated at `open`, and this
        // call has just added to the set the retention is applied to. Another
        // process can still take it between the rename and the listing — the
        // flock excludes other kernels and nothing else (the `journal_path`
        // contract) — and an auto-triggered call runs after its commit is
        // acknowledged, so that is answered as the I/O failure it is, which
        // `transact` discards, never as a panic in place of the commit's `Ok`.
        let s_old = checkpoint::retain(&journaled.dir, journaled.retain_checkpoints)?
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "the checkpoint this call wrote was gone before retention listed it: \
                     something other than this kernel removed it from the journal directory",
                )
            })?;
        // Reclaim the journal below the OLDEST retained checkpoint — that
        // floor, not the newest, is what keeps the BadCheckpoint fallback
        // real (§6).
        journal::reclaim_below(&journaled.dir, s_old)?;
        Ok(s)
    }

    /// What the NEWEST RETAINED checkpoint's `SKC4` header claims — its
    /// coordinate, the commit chain's value there and its body's hash, as a
    /// [`CheckpointHeader`] — or `None` under [`Durability::InMemory`] and
    /// before the first checkpoint. ADDITIVE
    /// (QUEUE item 10 piece 2, the PUBLISHED HEAD): what a head record's `base`
    /// member names (PUB-6.65), so a peer that copies a checkpoint file has its
    /// coordinate confirmed, a full replica verifies the base's canonical body
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
    pub fn newest_checkpoint(&self) -> Option<CheckpointHeader> {
        let journaled = self.journaled.as_ref()?;
        // `list` is ascending by seq (§6), so the last entry is the newest.
        checkpoint::list(&journaled.dir).ok()?.pop()?.header().ok()
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
mod tests;
