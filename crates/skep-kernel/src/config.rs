//! Kernel configuration — the knobs the design's Open-build-decisions section
//! selects, carried on [`KernelConfig`] (§Public interface).

use std::io;
use std::num::NonZeroU64;
use std::path::PathBuf;
use std::time::Duration;

use sha2::{Digest, Sha256};

/// Kernel configuration, passed to [`crate::Kernel::open`].
///
/// READ ONCE, at [`crate::Kernel::open`], and validated there first, before
/// the journal's lock is taken or a file read; persisted nowhere. The
/// journal records no retention count, no burned-`Seq` policy, no cadence
/// and no salt source — each salt is read back off its own marker, and
/// recovery tolerates burned gaps under either policy — so every field but
/// the journal's directory, which names the journal itself, may differ from
/// one open to the next, and a reopen is how any of them changes. Two
/// figures alone move while a kernel runs, both the cadence's: its commit
/// count and its byte bound ([`crate::Kernel::set_cadence_commits`],
/// [`crate::Kernel::set_cadence_bytes`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KernelConfig {
    /// Per-commit [`Durability::Fsync`] (the canonical durable-before-visible
    /// barrier, carrying the journal it writes to) or [`Durability::InMemory`]
    /// (no journal/barrier/recovery — MIC-faithful).
    pub durability: Durability,
    /// Auto-checkpoint trigger, evaluated by an ON-COMMIT check inside
    /// `transact` (§6). No background timer; `Manual` disables the
    /// auto-trigger, leaving cadence to the caller. Meaningful in both
    /// durability modes: under [`Durability::InMemory`] the trigger still
    /// evaluates and the `checkpoint()` it fires is a no-op.
    ///
    /// Under every arm but [`CheckpointPolicy::Deferred`], a checkpoint the
    /// trigger fires runs INLINE on the committing thread, after that commit
    /// is durable and installed; the run is COUNTED and RECORDED — the commit
    /// that ran it, how long it held that commit's caller, and how it ended,
    /// a failure KEPT as text ([`crate::Kernel::inline_checkpoints`],
    /// [`crate::Kernel::last_inline_checkpoint`]) — and that is the whole of
    /// where the failure goes: the transaction is already acknowledged, so
    /// the error has no path out of `transact` (§3/§6).
    /// Under the deferred arm the crossing SETS THE DUE FLAG
    /// ([`crate::Kernel::checkpoint_due`]) and runs nothing; the caller's own
    /// thread runs [`crate::Kernel::checkpoint`] and reads the result — and a
    /// second crossing that finds the flag still set runs the checkpoint
    /// inline as the backstop, so the window never grows unbounded. A caller
    /// who needs to know whether checkpointing is succeeding calls
    /// [`crate::Kernel::checkpoint`] itself and reads the result, under
    /// either arm.
    pub checkpoint: CheckpointPolicy,
    /// Where the commit chain's per-transaction SALT comes from (`SKJ4`):
    /// [`SaltSource::Os`] for every deployment, [`SaltSource::Seeded`] for
    /// fixtures and tests alone. Consulted once per journaled commit, by the
    /// appender, for the thirty-two bytes the commit marker stores and the
    /// chain hashes; never consulted on replay, where the salt is read off
    /// the marker, and never under [`Durability::InMemory`], which frames
    /// nothing.
    pub salt: SaltSource,
}

impl KernelConfig {
    /// The rules this configuration must satisfy, asked of each knob in field
    /// order — [`Durability::validate`], then [`CheckpointPolicy::validate`],
    /// then [`SaltSource::validate`]. Each rule lives with the knob it
    /// constrains; `Err` names the rule broken, which is the whole of what a
    /// caller can act on.
    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        self.durability.validate()?;
        self.checkpoint.validate()?;
        self.salt.validate()
    }
}

/// Where the commit chain's per-transaction SALT is drawn from (`SKJ4`; the
/// signed-ops re-base report's R1, the owner's ruling of 2026-09-23). Every
/// committed transaction's marker carries thirty-two salt bytes, and the
/// chain's preimage hashes them after the marker's other fields
/// (`crate::journal`'s `ChainLink`), so a reader holding two consecutive
/// chain values off the wire — `/chain?at=N` serves both `chain(N − 1)` and
/// `chain(N)` to everyone — cannot CONFIRM a guess at transaction `N`'s bytes
/// by hashing the guess: the preimage has thirty-two bytes the reader was
/// never served. Stored in the marker at commit and READ BACK on every
/// replay, never regenerated, so the source matters only on the write path
/// and a journal written under one source replays under any.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SaltSource {
    /// PRODUCTION: thirty-two bytes of OS entropy per transaction
    /// (`getrandom`), unpredictable to every party that does not hold the
    /// journal. The one source a daemon opens under — a daemon under any
    /// other source publishes chain values a reader can invert, which is the
    /// oracle the salt exists to close.
    Os,
    /// FIXTURES AND TESTS ONLY, never a daemon's: a deterministic stream, the
    /// salt of transaction `txn` being `SHA-256(seed LE64 ‖ txn LE64)` — a
    /// pure function of the seed and the transaction's identity, so a
    /// replayed op sequence under one seed writes ONE history byte for byte
    /// (the golden fixture, two processes writing one checkpoint, two
    /// daemons writing one head), and under two seeds two histories that
    /// differ at every transaction. Nothing about it is secret: the seed is in
    /// the test's source.
    Seeded(u64),
}

impl SaltSource {
    /// The rule this source must satisfy: none — both sources are modes this
    /// kernel offers, and which one a deployment may use is the caller's
    /// discipline (a daemon is `Os`), which a configuration cannot check.
    /// Spelled out variant by variant, for the reason
    /// [`Durability::validate`]'s is: a source added here has to say whether
    /// it carries a rule.
    pub(crate) fn validate(self) -> Result<(), &'static str> {
        match self {
            SaltSource::Os | SaltSource::Seeded(_) => Ok(()),
        }
    }

    /// Draw the salt for the transaction whose identity — its first `Seq` —
    /// is `txn`. The one site salt bytes are made: the appender calls it once
    /// per commit, before a frame is built, and stores the answer in the
    /// marker. `Err` is the OS refusing entropy, which nothing here can
    /// repair; the commit that asked is then a true no-op the caller may
    /// re-invoke, since no byte of it has been framed.
    pub(crate) fn draw(self, txn: u64) -> io::Result<[u8; 32]> {
        match self {
            SaltSource::Os => {
                let mut salt = [0u8; 32];
                getrandom::fill(&mut salt)
                    .map_err(|e| io::Error::other(format!("OS entropy unavailable: {e}")))?;
                Ok(salt)
            }
            SaltSource::Seeded(seed) => Ok(Sha256::new()
                .chain_update(seed.to_le_bytes())
                .chain_update(txn.to_le_bytes())
                .finalize()
                .into()),
        }
    }
}

/// Durability mode (§1, Conflicts #3). The journal's own knobs ride on the
/// variant that has a journal, so a configuration cannot name a directory or
/// a retention count for a kernel that writes nothing.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Durability {
    /// The ONE v1 ordering — durable-before-visible (§1): append records →
    /// append commit marker → barrier (one records+marker fsync) → atomic
    /// install. A committed marker *is* the commit ack (§1); `burned_seq`
    /// governs the durability-failure rollback.
    Fsync {
        /// The directory the journal's segments, checkpoints and lock live in.
        ///
        /// It holds the journal segments, the checkpoints and the
        /// `open()`-held exclusion lock file (Lifecycle). An empty path names
        /// no directory and is refused at `open()`
        /// ([`crate::OpenError::InvalidConfig`]); a relative one is resolved
        /// against the working directory once, at `open()`, so every file the
        /// kernel touches afterwards lies in the directory the path named
        /// then, wherever the process's working directory moves.
        ///
        /// **Precondition.** The kernel owns five names in this directory:
        /// `seg-<n>.wal`, `checkpoint.<n>`, `checkpoint.tmp`, `kernel.lock`
        /// and `seg-<n>.wal.cut-<b>` (`seg-<n>.wal.cut-<b>.<k>` where that
        /// one already stands). `open()` creates the directory if absent, and
        /// the kernel creates, reads and deletes files under the first four:
        /// checkpoint retention and journal reclamation are deletions, and a
        /// foreign file bearing one of those names is a base or a segment as
        /// far as recovery is concerned. The fifth is the tail cut's keep —
        /// the bytes an open cut from a tail holding an intact frame no torn
        /// write leaves ([`crate::Recovery`]'s `tail_cut_kept`) — which the
        /// kernel creates and never removes or writes over: a kept file is
        /// the operator's. Every other name it leaves alone, its listings
        /// taking only the spellings it writes, so an embedder may keep files
        /// of its own beside the journal — the daemon keeps its change feed
        /// and its blob store there. On unix the directory and every file the
        /// kernel creates in it are owner-only — the directory `0700` (every
        /// component `open()` makes), each file `0600` — the mode set at
        /// creation, the process umask irrelevant; a directory or file that
        /// already stands keeps the mode it has. The `open()`-held flock
        /// excludes a second kernel and nothing else. M2 cannot check this.
        journal_path: PathBuf,
        /// `N ≥ 1` most-recent checkpoints kept; the journal is reclaimed only
        /// BELOW the OLDEST retained one, so `BadCheckpoint` can fall back to
        /// an older retained base. `N = 1` ⇒ newest is the sole base, no
        /// fallback (§6/§7).
        retain_checkpoints: usize,
        /// Policy for the `Seq`s a failed (truncated) transaction burned.
        burned_seq: BurnedSeqPolicy,
    },
    /// Fully in-memory: no journal, no barrier, no recovery (MIC-faithful —
    /// ASN-0134 is silent on durability; atomicity/isolation intact).
    /// `checkpoint()` and `flush()` are then no-ops (§6/Lifecycle).
    ///
    /// Records are still SERIALIZED on every commit: the encode step precedes
    /// the journal and runs in both modes, and this mode drops the bytes it
    /// produces. So an in-memory kernel pays a full serialization per record,
    /// and refuses everything a journaled one refuses of the records
    /// themselves: [`crate::TxnError::Unencodable`] — a serializer's own
    /// refusal, or a record whose serialized form exceeds the journal's
    /// frame cap — and [`crate::TxnError::OverBudget`] — a transaction past
    /// the per-transaction byte budget. Both are judged above the mode
    /// branch, which is what lets an in-memory test catch every encoding and
    /// size refusal a journaled deployment would meet. What this mode has no
    /// path to at all is [`crate::TxnError::Durability`], which is a
    /// barrier's failure and there is no barrier.
    ///
    /// This mode does not LOAD, so [`crate::WorldState::rebuild_derived`] does
    /// not run: the caller's `genesis` value becomes the root exactly as given,
    /// where a journaled `open()` seeds whichever base it selects through that
    /// method. A world whose hints rely on the seeding is therefore right
    /// under [`Durability::Fsync`] and wrong here — which is what that method's
    /// genesis obligation asks the caller to rule out.
    InMemory,
}

impl Durability {
    /// The rules this mode must satisfy, asked in field order: a
    /// `journal_path` that names a directory — an empty one names none, and
    /// every name the kernel joined to it would land in whatever directory
    /// the process happens to run in — then the interface's `N ≥ 1`
    /// retention rule (§Public interface). A violation is surfaced rather
    /// than silently clamped — `N = 0` asks for a journal with no base to
    /// recover from, which is a caller's mistake and not a mode this kernel
    /// offers.
    ///
    /// Spelled out variant by variant, so a mode added here has to say
    /// whether it carries a rule: a wildcard would compile and silently admit
    /// the next journaled mode with no fallback base.
    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        match self {
            Durability::Fsync { journal_path, .. } if journal_path.as_os_str().is_empty() => {
                Err("journal_path must name a directory; an empty path names none")
            }
            Durability::Fsync {
                retain_checkpoints: 0,
                ..
            } => Err("retain_checkpoints must be >= 1"),
            Durability::Fsync { .. } | Durability::InMemory => Ok(()),
        }
    }

    /// What becomes of the `Seq`s a failed transaction burned: rolled back
    /// (keeping the order gap-free) or left advanced (relaxing it to
    /// monotone-only) — §1/§3. The in-memory mode has no burned-`Seq` policy
    /// of its own: its commit path has no barrier to fail, so the ways it
    /// burns coordinates are a size-refused transaction (unencodable or
    /// over-budget) and an unwind, and the default it answers with rolls
    /// them all back, keeping its order gap-free.
    pub(crate) fn burned_seq_policy(&self) -> BurnedSeqPolicy {
        match self {
            Durability::Fsync { burned_seq, .. } => *burned_seq,
            Durability::InMemory => BurnedSeqPolicy::default(),
        }
    }
}

/// What happens to the `Seq`s a durability-failed transaction had been
/// assigned (§1: barrier failure is a true no-op, tail truncated, Seqs
/// burned).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BurnedSeqPolicy {
    /// Roll the `Seq` high-water back to the last committed marker's
    /// `last_seq` (an absolute set — idempotent), keeping the order gap-free.
    /// The documented default.
    #[default]
    Rollback,
    /// Leave the high-water advanced: the order relaxes to monotone-only, and
    /// recovery tolerates the resulting gaps (§7 — no contiguity check; the
    /// corrupt-run classifier may then conservatively over-halt).
    TolerateGap,
}

/// Auto-checkpoint cadence policy — evaluated on-commit inside `transact`
/// (§6); there is no timer thread. The *mechanism* (on-commit trigger,
/// counters in the applier-locked state, reset by the triggering commit) is
/// fixed; the variant/threshold is the open knob, and — under
/// [`CheckpointPolicy::Deferred`] alone — WHERE the checkpoint a crossing
/// calls for runs. Two arms hold policies of their own, so the type is
/// `Clone` and not `Copy`: a configuration is built once and cloned where
/// the kernel keeps it.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckpointPolicy {
    /// Checkpoint after every `n` commits, `n ≥ 1`. [`Manual`] is how the
    /// auto-trigger is disabled; `0` is refused at [`crate::Kernel::open`].
    /// One of the two thresholds a running kernel can MOVE:
    /// [`crate::Kernel::set_cadence_commits`] replaces it in place, wherever
    /// this arm sits inside the policy.
    ///
    /// [`Manual`]: CheckpointPolicy::Manual
    EveryN(u64),
    /// Checkpoint when at least this much wall time has passed since the last
    /// auto-trigger reset, evaluated on-commit (a quiescent kernel — nothing
    /// new to persist — correctly never fires; §6). [`Duration::ZERO`] is an
    /// always-elapsed window: the first commit after each reset crosses.
    Interval(Duration),
    /// Checkpoint after this many journal bytes appended since the last
    /// auto-trigger reset, `n ≥ 1` (always zero under
    /// [`Durability::InMemory`], which journals nothing). [`Manual`] is how
    /// the auto-trigger is disabled; `0` is refused at
    /// [`crate::Kernel::open`]. One of the two thresholds a running kernel
    /// can MOVE, [`EveryN`]'s count the other:
    /// [`crate::Kernel::set_cadence_bytes`] replaces it in place, wherever
    /// this arm sits inside the policy, so a caller sizing the bound from the
    /// newest checkpoint re-reads it as each one lands.
    ///
    /// [`EveryN`]: CheckpointPolicy::EveryN
    /// [`Manual`]: CheckpointPolicy::Manual
    JournalBytes(u64),
    /// No auto-trigger — the caller drives `checkpoint()` from its own loop.
    Manual,
    /// Checkpoint when EITHER policy crosses, whichever first — a commit
    /// count beside a byte bound is the shape it exists for, `EveryN(n)` and
    /// `JournalBytes(b)`, so the journal between two checkpoints is bounded
    /// in commits AND in bytes. One crossing resets EVERY counter, for both
    /// halves: the next window starts at the commit that crossed. Each half
    /// is held to its own rule at [`crate::Kernel::open`], and neither half
    /// may be [`Deferred`], which is the outermost arm alone.
    ///
    /// [`Deferred`]: CheckpointPolicy::Deferred
    EitherOf(Box<CheckpointPolicy>, Box<CheckpointPolicy>),
    /// The inner policy's crossing DEFERRED to the caller's own thread. A
    /// commit that crosses resets the counters as every crossing does and
    /// SETS THE DUE FLAG ([`crate::Kernel::checkpoint_due`]) in place of
    /// running the checkpoint: nothing runs on the committing thread. The
    /// caller's thread reads the flag — lock-free — and runs
    /// [`crate::Kernel::checkpoint`], which CLEARS THE FLAG FIRST and then
    /// runs, so a crossing during the run sets it again and that thread runs
    /// once more after; the result, which under the inline arms never
    /// reaches `transact`'s caller and is kept only as the kernel's record
    /// of the run ([`crate::Kernel::last_inline_checkpoint`]), is that
    /// thread's to read and report.
    ///
    /// THE BACKSTOP, the kernel's own and thread-free: a crossing that finds
    /// the flag ALREADY SET — the last crossing not yet serviced — runs the
    /// checkpoint INLINE on the committing thread, as the inner policy alone
    /// would at every crossing. So a caller that never services the flag,
    /// and a board whose writes outrun its checkpointer, get a checkpoint at
    /// every second crossing and never an unbounded window: the journal
    /// between two checkpoints is bounded by TWO windows of the inner policy
    /// — one of grace — where the inner policy alone bounds it by one. The
    /// outermost arm alone: a `Deferred` inside another arm is refused at
    /// [`crate::Kernel::open`]. A [`Manual`] inside crosses never and defers
    /// nothing.
    ///
    /// [`Manual`]: CheckpointPolicy::Manual
    Deferred(Box<CheckpointPolicy>),
}

impl CheckpointPolicy {
    /// The rule this policy must satisfy: `n ≥ 1` on either threshold, in
    /// every arm a composite holds, and [`CheckpointPolicy::Deferred`] the
    /// outermost arm alone. A violation is surfaced rather than silently
    /// clamped — a threshold of `0` asks for a checkpoint after every zero
    /// commits, a caller's mistake and not a mode this kernel offers.
    /// Clamping would be the worse charity: `0` reads as "disabled" in most
    /// configurations, and the nearest meaning here is
    /// [`CheckpointPolicy::Manual`]'s opposite — a whole checkpoint on the
    /// committing thread at every commit, whose failure never reaches
    /// [`crate::Kernel::transact`]'s caller and is kept only as a record. A
    /// `Deferred` nested inside an arm would make one half of a composite
    /// deferred and the other inline, a shape with no reading, so it is
    /// refused as the mistake it is.
    ///
    /// [`CheckpointPolicy::Interval`] is deliberately NOT refused at
    /// [`Duration::ZERO`]: an always-elapsed window is a coherent reading of a
    /// zero interval, it is what that variant documents, and it is what the
    /// suite pins.
    ///
    /// Spelled out variant by variant, for the reason
    /// [`Durability::validate`]'s is.
    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        match self {
            CheckpointPolicy::EveryN(0) => {
                Err("CheckpointPolicy::EveryN requires n >= 1; Manual disables the auto-trigger")
            }
            CheckpointPolicy::JournalBytes(0) => Err(
                "CheckpointPolicy::JournalBytes requires n >= 1; Manual disables the auto-trigger",
            ),
            CheckpointPolicy::EveryN(_)
            | CheckpointPolicy::JournalBytes(_)
            | CheckpointPolicy::Interval(_)
            | CheckpointPolicy::Manual => Ok(()),
            CheckpointPolicy::EitherOf(a, b) => {
                a.validate_inner()?;
                b.validate_inner()
            }
            CheckpointPolicy::Deferred(inner) => inner.validate_inner(),
        }
    }

    /// [`CheckpointPolicy::validate`] for a policy held INSIDE another arm,
    /// where [`CheckpointPolicy::Deferred`] is refused: the outermost arm is
    /// the one place the deferral is read.
    fn validate_inner(&self) -> Result<(), &'static str> {
        match self {
            CheckpointPolicy::Deferred(_) => {
                Err("CheckpointPolicy::Deferred is the outermost arm alone; it wraps the others")
            }
            other => other.validate(),
        }
    }

    /// Whether a crossing of this policy is DEFERRED to the caller's thread
    /// — the outermost arm is [`CheckpointPolicy::Deferred`] — rather than
    /// run inline on the committing one. Read once per crossing, under the
    /// applier lock, beside the crossing test.
    pub(crate) fn deferred(&self) -> bool {
        matches!(self, CheckpointPolicy::Deferred(_))
    }

    /// Replace the commit bound — every [`CheckpointPolicy::EveryN`] count
    /// this policy holds, wherever an arm nests it — with `commits`,
    /// answering whether one was there to replace; `set_bytes`'s twin for
    /// the other arm ([`crate::Kernel::set_cadence_commits`]).
    pub(crate) fn set_commits(&mut self, commits: NonZeroU64) -> bool {
        match self {
            CheckpointPolicy::EveryN(every) => {
                *every = commits.get();
                true
            }
            CheckpointPolicy::EitherOf(a, b) => {
                let in_a = a.set_commits(commits);
                let in_b = b.set_commits(commits);
                in_a || in_b
            }
            CheckpointPolicy::Deferred(inner) => inner.set_commits(commits),
            CheckpointPolicy::JournalBytes(_)
            | CheckpointPolicy::Interval(_)
            | CheckpointPolicy::Manual => false,
        }
    }

    /// Replace the byte bound — every [`CheckpointPolicy::JournalBytes`]
    /// threshold this policy holds, wherever an arm nests it — with `bytes`,
    /// answering whether one was there to replace. One of the two thresholds
    /// a running kernel moves ([`crate::Kernel::set_cadence_bytes`],
    /// [`CheckpointPolicy::set_commits`] the other's); `n ≥ 1` is the type's,
    /// for both, so the rule [`CheckpointPolicy::validate`] holds at `open`
    /// holds after every replacement too.
    pub(crate) fn set_bytes(&mut self, bytes: NonZeroU64) -> bool {
        match self {
            CheckpointPolicy::JournalBytes(threshold) => {
                *threshold = bytes.get();
                true
            }
            CheckpointPolicy::EitherOf(a, b) => {
                let in_a = a.set_bytes(bytes);
                let in_b = b.set_bytes(bytes);
                in_a || in_b
            }
            CheckpointPolicy::Deferred(inner) => inner.set_bytes(bytes),
            CheckpointPolicy::EveryN(_)
            | CheckpointPolicy::Interval(_)
            | CheckpointPolicy::Manual => false,
        }
    }
}

#[cfg(test)]
mod tests;
