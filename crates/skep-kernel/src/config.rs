//! Kernel configuration — the knobs the design's Open-build-decisions section
//! selects, carried on [`KernelCfg`] (§Public interface).

use std::path::PathBuf;
use std::time::Duration;

/// Kernel configuration, passed to [`crate::Kernel::open`].
#[derive(Clone, Debug)]
pub struct KernelCfg {
    /// Directory for journal segments + checkpoints + the `open()`-held
    /// exclusion lock file (Lifecycle). The in-memory mode ignores it.
    pub journal_path: PathBuf,
    /// Per-commit [`Durability::Fsync`] (the canonical durable-before-visible
    /// barrier, with its burned-Seq policy) or [`Durability::InMemory`]
    /// (no journal/barrier/recovery — MIC-faithful).
    pub durability: Durability,
    /// Auto-checkpoint trigger, evaluated by an ON-COMMIT check inside
    /// `transact` (§6). No background timer; `Manual` disables the
    /// auto-trigger, leaving cadence to the caller.
    pub checkpoint: CheckpointPolicy,
    /// `N ≥ 1` most-recent checkpoints kept; the journal is reclaimed only
    /// BELOW the OLDEST retained one, so `BadCheckpoint` can fall back to an
    /// older retained base. `N = 1` ⇒ newest is the sole base, no fallback
    /// (§6/§7).
    pub retain_checkpoints: usize,
}

/// Durability mode (§1, Conflicts #3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Durability {
    /// The ONE v1 ordering — durable-before-visible (§1): append records →
    /// append commit marker → barrier (one records+marker fsync) → atomic
    /// install. A committed marker *is* the commit ack (§1); `burned_seq`
    /// governs the durability-failure rollback.
    Fsync {
        /// Policy for the `Seq`s a failed (truncated) transaction burned.
        burned_seq: BurnedSeqPolicy,
    },
    /// Fully in-memory: no journal, no barrier, no recovery (MIC-faithful —
    /// ASN-0134 is silent on durability; atomicity/isolation intact).
    /// `checkpoint()` and `flush()` are then no-ops (§6/Lifecycle).
    InMemory,
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckpointPolicy {
    /// Checkpoint after every `n` commits.
    EveryN(u64),
    /// Checkpoint when at least this much wall time has passed since the last
    /// auto-trigger reset, evaluated on-commit (a quiescent kernel — nothing
    /// new to persist — correctly never fires; §6).
    Interval(Duration),
    /// Checkpoint after this many journal bytes appended since the last
    /// auto-trigger reset (always zero under [`Durability::InMemory`], which
    /// journals nothing).
    JournalBytes(u64),
    /// No auto-trigger — the caller drives `checkpoint()` from its own loop.
    Manual,
}
