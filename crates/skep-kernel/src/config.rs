//! Kernel configuration — the knobs the design's Open-build-decisions section
//! selects, carried on [`KernelConfig`] (§Public interface).

use std::io;
use std::path::PathBuf;
use std::time::Duration;

use sha2::{Digest, Sha256};

/// Kernel configuration, passed to [`crate::Kernel::open`].
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
    /// A checkpoint the trigger fires runs on the committing thread, after
    /// that commit is durable and installed, and its failure is DISCARDED —
    /// the transaction is already acknowledged, so the error has no sound
    /// path out (§3/§6). A caller who needs to know whether checkpointing is
    /// succeeding calls [`crate::Kernel::checkpoint`] itself and reads the
    /// result.
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
/// ([`crate::journal`]'s `ChainLink`), so a reader holding two consecutive
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
    /// differ at every position. Nothing about it is secret: the seed is in
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
        /// Directory for journal segments + checkpoints + the `open()`-held
        /// exclusion lock file (Lifecycle).
        ///
        /// CALLER CONTRACT — this directory belongs to the kernel alone.
        /// `open()` creates it if absent, and the kernel creates, reads and
        /// DELETES the files in it named `seg-<n>.wal`, `checkpoint.<n>`,
        /// `checkpoint.tmp` and `kernel.lock`: checkpoint retention and
        /// journal reclamation are deletions, and a foreign file bearing one
        /// of those names is a base or a segment as far as recovery is
        /// concerned. The `open()`-held flock excludes a second kernel and
        /// nothing else. M2 cannot check this.
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
    /// The rule this mode must satisfy: the interface's `N ≥ 1` retention
    /// rule (§Public interface). A violation is surfaced rather than silently
    /// clamped — `N = 0` asks for a journal with no base to recover from,
    /// which is a caller's mistake and not a mode this kernel offers.
    ///
    /// Spelled out variant by variant, so a mode added here has to say
    /// whether it carries a rule: a wildcard would compile and silently admit
    /// the next journaled mode with no fallback base.
    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        match self {
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
/// fixed; only the variant/threshold is the open knob.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckpointPolicy {
    /// Checkpoint after every `n` commits, `n ≥ 1`. [`Manual`] is how the
    /// auto-trigger is disabled; `0` is refused at [`crate::Kernel::open`].
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
    /// [`crate::Kernel::open`].
    ///
    /// [`Manual`]: CheckpointPolicy::Manual
    JournalBytes(u64),
    /// No auto-trigger — the caller drives `checkpoint()` from its own loop.
    Manual,
}

impl CheckpointPolicy {
    /// The rule this policy must satisfy: `n ≥ 1` on either threshold. A
    /// violation is surfaced rather than silently clamped — a threshold of
    /// `0` asks for a checkpoint after every zero commits, a caller's mistake
    /// and not a mode this kernel offers. Clamping would be the worse charity:
    /// `0` reads as "disabled" in most configurations, and the nearest meaning
    /// here is [`CheckpointPolicy::Manual`]'s opposite — a whole checkpoint on
    /// the committing thread at every commit, whose failure
    /// [`crate::Kernel::transact`] discards.
    ///
    /// [`CheckpointPolicy::Interval`] is deliberately NOT refused at
    /// [`Duration::ZERO`]: an always-elapsed window is a coherent reading of a
    /// zero interval, it is what that variant documents, and it is what the
    /// suite pins.
    ///
    /// Spelled out variant by variant, for the reason
    /// [`Durability::validate`]'s is.
    pub(crate) fn validate(self) -> Result<(), &'static str> {
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
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fsync_mode(burned_seq: BurnedSeqPolicy) -> Durability {
        Durability::Fsync {
            journal_path: PathBuf::from("/tmp/skep-kernel-config-test"),
            retain_checkpoints: 1,
            burned_seq,
        }
    }

    #[test]
    fn the_burned_seq_policy_is_a_property_of_the_durability_mode() {
        assert_eq!(
            fsync_mode(BurnedSeqPolicy::Rollback).burned_seq_policy(),
            BurnedSeqPolicy::Rollback
        );
        assert_eq!(
            fsync_mode(BurnedSeqPolicy::TolerateGap).burned_seq_policy(),
            BurnedSeqPolicy::TolerateGap
        );
        // The in-memory mode carries no policy of its own and answers with
        // the default, which keeps its order gap-free.
        assert_eq!(
            Durability::InMemory.burned_seq_policy(),
            BurnedSeqPolicy::default()
        );
    }

    #[test]
    fn the_retention_rule_binds_the_journal_and_nothing_else() {
        // `N ≥ 1` is a rule about a journal's fallback chain, so it is
        // checked where a journal is configured and is vacuous where none is.
        let bad = KernelConfig {
            durability: Durability::Fsync {
                journal_path: PathBuf::from("/tmp/skep-kernel-config-test"),
                retain_checkpoints: 0,
                burned_seq: BurnedSeqPolicy::Rollback,
            },
            checkpoint: CheckpointPolicy::Manual,
            salt: SaltSource::Os,
        };
        assert_eq!(
            bad.validate().unwrap_err(),
            "retain_checkpoints must be >= 1"
        );
        let in_memory = KernelConfig {
            durability: Durability::InMemory,
            checkpoint: CheckpointPolicy::Manual,
            salt: SaltSource::Os,
        };
        assert!(in_memory.validate().is_ok());
    }

    #[test]
    fn both_salt_sources_are_modes_this_kernel_offers() {
        // The salt knob carries no rule: which source a deployment may use is
        // the caller's discipline (a daemon is `Os`), and a configuration
        // cannot check it. Both validate, in either durability mode.
        for salt in [SaltSource::Os, SaltSource::Seeded(0), SaltSource::Seeded(u64::MAX)] {
            for durability in [Durability::InMemory, fsync_mode(BurnedSeqPolicy::Rollback)] {
                let cfg = KernelConfig {
                    durability,
                    checkpoint: CheckpointPolicy::Manual,
                    salt,
                };
                assert!(cfg.validate().is_ok(), "{salt:?} is a mode this offers");
            }
        }
    }

    #[test]
    fn the_seeded_salt_is_a_pure_function_of_the_seed_and_the_transaction() {
        // The formula, spelled out by hand beside the source: SHA-256 over
        // the seed's eight little-endian bytes then the transaction's — so a
        // replayed op sequence under one seed writes one history, and the
        // golden fixture's markers carry exactly these bytes.
        let by_hand = |seed: u64, txn: u64| -> [u8; 32] {
            let mut preimage = Vec::with_capacity(16);
            preimage.extend_from_slice(&seed.to_le_bytes());
            preimage.extend_from_slice(&txn.to_le_bytes());
            Sha256::digest(&preimage).into()
        };
        for (seed, txn) in [(0, 1), (7, 1), (7, 2), (u64::MAX, u64::MAX)] {
            assert_eq!(SaltSource::Seeded(seed).draw(txn).unwrap(), by_hand(seed, txn));
        }
        // Deterministic across draws, distinct across transactions and across
        // seeds: two boards under two seeds salt every position differently.
        let seeded = SaltSource::Seeded(7);
        assert_eq!(seeded.draw(1).unwrap(), seeded.draw(1).unwrap());
        assert_ne!(seeded.draw(1).unwrap(), seeded.draw(2).unwrap());
        assert_ne!(seeded.draw(1).unwrap(), SaltSource::Seeded(8).draw(1).unwrap());
        assert_ne!(seeded.draw(1).unwrap(), [0u8; 32], "a salt is never the zero seed");
    }

    #[test]
    fn the_os_source_draws_fresh_entropy_on_every_call() {
        // Two draws for ONE transaction differ: the OS source is a function
        // of nothing the caller supplies, which is what makes a chain value
        // under it confirm no guess. (Equal draws would be a 2^-256 event.)
        let first = SaltSource::Os.draw(1).expect("OS entropy");
        let second = SaltSource::Os.draw(1).expect("OS entropy");
        assert_ne!(first, second, "the OS source repeated a salt");
        assert_ne!(first, [0u8; 32]);
        assert_ne!(first, SaltSource::Seeded(0).draw(1).unwrap(), "not the seeded stream");
    }

    #[test]
    fn a_zero_auto_trigger_threshold_is_refused_in_either_durability_mode() {
        // "Checkpoint after every 0 commits" has no meaning, and coercing it
        // would read as the most expensive mode this kernel has — a whole
        // checkpoint on the committing thread at every commit, whose failure
        // `transact` discards. `Manual` is what asks for no auto-trigger, so
        // the mistake has an answer and gets named rather than performed.
        let with = |checkpoint| KernelConfig {
            durability: Durability::InMemory,
            checkpoint,
            salt: SaltSource::Os,
        };
        assert_eq!(
            with(CheckpointPolicy::EveryN(0)).validate().unwrap_err(),
            "CheckpointPolicy::EveryN requires n >= 1; Manual disables the auto-trigger"
        );
        assert_eq!(
            with(CheckpointPolicy::JournalBytes(0))
                .validate()
                .unwrap_err(),
            "CheckpointPolicy::JournalBytes requires n >= 1; Manual disables the auto-trigger"
        );
        // The trigger has no journal to ride on, so the rule binds both modes
        // — and it is the trigger's rule that speaks, not the retention one.
        let journaled = KernelConfig {
            durability: fsync_mode(BurnedSeqPolicy::Rollback),
            checkpoint: CheckpointPolicy::EveryN(0),
            salt: SaltSource::Os,
        };
        assert_eq!(
            journaled.validate().unwrap_err(),
            "CheckpointPolicy::EveryN requires n >= 1; Manual disables the auto-trigger"
        );

        // Everything at or above the floor validates — including a zero
        // `Interval`, which is an always-elapsed window rather than a
        // thresholdless one, and is what `interval_is_evaluated_on_commit…`
        // pins.
        for policy in [
            CheckpointPolicy::EveryN(1),
            CheckpointPolicy::JournalBytes(1),
            CheckpointPolicy::Interval(Duration::ZERO),
            CheckpointPolicy::Manual,
        ] {
            assert!(
                with(policy).validate().is_ok(),
                "{policy:?} is a mode this offers"
            );
        }
    }
}
