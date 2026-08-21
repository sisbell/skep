//! Error types of the public surface (§Public interface).

use std::fmt;
use std::io;

use crate::Seq;

/// Failure of [`crate::Kernel::open`] (§6/§7).
#[derive(Debug)]
pub enum OpenError {
    /// The configuration is not one this kernel offers; the payload names the
    /// rule broken. Not an environmental failure: no retry and no operator
    /// action on the store changes it, only a corrected configuration does.
    InvalidConfig(&'static str),
    /// I/O failure during open/recovery — including a recovery tail-truncation
    /// that fails to complete durably (§7; `open()` then fails, the step is
    /// idempotent and the next `open()` retries it) and a failed acquisition
    /// of the journal-path exclusion lock (a second live kernel on this
    /// journal; Lifecycle).
    Io(io::Error),
    /// No retained checkpoint loads (each unreadable / failed its checksum)
    /// and genesis is unreachable (its covering journal reclaimed). Recovery
    /// internally falls back newest → next-older RETAINED checkpoint →
    /// genesis-while-reachable (§6/§7); this is returned only when that whole
    /// chain is exhausted. Operator-intervention condition — not auto-retried.
    BadCheckpoint,
    /// A corrupt run whose INFERRED `Seq` max (= next-intact coordinate − 1,
    /// the CLASSIFIER; a record landing contributes its `seq`, a marker
    /// landing `last_seq + 1` — §7) falls in the genuinely-replayed range
    /// `(S_load, W]` — durable committed data the recovered state needs is
    /// corrupt; halt, never drop. `at` is only the PAYLOAD: the next-intact
    /// coordinate the magic-resync lands on (the run's own seqs are
    /// unreadable; at a marker landing, `at = last_seq + 1`). An EOF-reaching
    /// run classes as the tail, so `Corruption` never carries an EOF payload
    /// (§7). Operator-intervention condition — not auto-retried.
    Corruption {
        /// The next intact frame's coordinate (see above).
        at: Seq,
    },
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OpenError::InvalidConfig(msg) => write!(f, "invalid kernel configuration: {msg}"),
            OpenError::Io(e) => write!(f, "journal open/recovery I/O failure: {e}"),
            OpenError::BadCheckpoint => {
                write!(f, "no retained checkpoint loads and genesis is unreachable")
            }
            OpenError::Corruption { at } => write!(
                f,
                "durable committed data corrupt in the replayed range; next intact frame at seq {at}"
            ),
        }
    }
}

impl std::error::Error for OpenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            OpenError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for OpenError {
    fn from(e: io::Error) -> Self {
        OpenError::Io(e)
    }
}

/// Failure of [`crate::Kernel::checkpoint`] (§6). A failed checkpoint never
/// poisons the kernel and never disturbs the write path; each variant states
/// what it left behind, since that is what decides the caller's next move.
#[derive(Debug)]
pub enum CheckpointError {
    /// I/O failure persisting the checkpoint, applying retention, or
    /// reclaiming journal segments. What survives is benign in each case: a
    /// checkpoint written but not yet retained-against is a valid base, an
    /// unapplied retention leaves extra bases, and an unreclaimed segment is
    /// space. So the call is safe to retry, and a retry re-does the whole
    /// sequence from a fresh root.
    Io(io::Error),
    /// The world failed to serialize. Carries the serializer's own account of
    /// which part of the world it could not encode — the only thing that
    /// identifies the failure, since M2 never inspects `W`. Nothing was
    /// written, not even a temp file: the encode precedes the first file
    /// operation. Retrying repeats the refusal until `W` itself encodes.
    Serialize(Box<dyn std::error::Error + Send + Sync + 'static>),
    /// A prior barrier/truncation/unwind failure has halted the kernel
    /// (§1/§3). No checkpoint was attempted, nothing was written, and none
    /// will be until the kernel is reopened.
    Poisoned,
}

impl fmt::Display for CheckpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CheckpointError::Io(e) => write!(f, "checkpoint I/O failure: {e}"),
            CheckpointError::Serialize(e) => {
                write!(f, "checkpoint world serialization failed: {e}")
            }
            CheckpointError::Poisoned => write!(f, "kernel is poisoned; no checkpoint taken"),
        }
    }
}

impl std::error::Error for CheckpointError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CheckpointError::Io(e) => Some(e),
            CheckpointError::Serialize(e) => Some(&**e),
            CheckpointError::Poisoned => None,
        }
    }
}

impl From<io::Error> for CheckpointError {
    fn from(e: io::Error) -> Self {
        CheckpointError::Io(e)
    }
}

/// Failure of [`crate::Kernel::world_at`] — the read-only bounded replay
/// (observation-surface API). None of these poisons the kernel or perturbs
/// the live write path; every variant is an honest "this boundary cannot be
/// answered" (or a genuine at-rest corruption find).
#[derive(Debug)]
pub enum HistoryError {
    /// `at` exceeds the committed head at the time of the call. `head` is
    /// that head — the greatest currently answerable boundary.
    BeyondHead {
        /// The committed head observed by this call.
        head: Seq,
    },
    /// `at` is not a committed transaction boundary: it names an interior
    /// `Seq` of a multi-record commit (never externally observable — §2/§3)
    /// or a burned `Seq` under `TolerateGap`. Boundaries are the `Seq` values
    /// `transact` returns; nothing else is one.
    NotABoundary {
        /// The greatest boundary at or below the requested value that THIS
        /// call can still answer — never below the base it selected, since a
        /// segment straddling that base contributes boundaries below it with
        /// no base left to fold from (0 = genesis). It is therefore the value
        /// a caller may safely re-ask with; a boundary lower still may be
        /// answerable in its own right, from the older base a lower `at`
        /// would select.
        nearest: Seq,
    },
    /// No base at or below `at` remains derivable: every retained checkpoint
    /// sits above it and the journal below the oldest retained checkpoint
    /// has been reclaimed (§6), so genesis is unreachable. `floor` names the
    /// oldest boundary a base could still be derived at, when a checkpoint
    /// exists to derive it from.
    Reclaimed {
        /// The oldest retained checkpoint's seq — the oldest boundary a base
        /// could still be derived at — or `None` when no checkpoint exists.
        /// That checkpoint is the oldest CANDIDATE, not a guarantee: one that
        /// fails its own header checksum refuses this way again.
        floor: Option<Seq>,
    },
    /// The kernel runs under [`crate::Durability::InMemory`]: there is no
    /// journal to derive history from.
    Unjournaled,
    /// I/O failure reading checkpoints or journal segments. May be transient
    /// (a concurrent checkpoint's segment reclamation can remove a file
    /// between listing and reading); a retry re-selects a base.
    Io(io::Error),
    /// Corrupt data at rest in the scanned region (a corrupt run not wholly
    /// embodied in the loaded base, or a committed record that fails to
    /// decode) — the same halt-never-drop verdict recovery gives (§7). `at`
    /// is the next-intact coordinate / the undecodable record's seq.
    Corruption {
        /// See above.
        at: Seq,
    },
}

impl fmt::Display for HistoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HistoryError::BeyondHead { head } => {
                write!(f, "boundary beyond the committed head {head}")
            }
            HistoryError::NotABoundary { nearest } => {
                write!(f, "not a committed boundary; nearest at or below is {nearest}")
            }
            HistoryError::Reclaimed { floor: Some(floor) } => write!(
                f,
                "history below the oldest retained checkpoint (seq {floor}) has been reclaimed"
            ),
            HistoryError::Reclaimed { floor: None } => {
                write!(f, "no checkpoint and no genesis-reaching journal; history unavailable")
            }
            HistoryError::Unjournaled => {
                write!(f, "in-memory kernel: no journal to derive history from")
            }
            HistoryError::Io(e) => write!(f, "history read I/O failure: {e}"),
            HistoryError::Corruption { at } => write!(
                f,
                "journal corrupt at rest in the scanned region; next intact frame at seq {at}"
            ),
        }
    }
}

impl std::error::Error for HistoryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            HistoryError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for HistoryError {
    fn from(e: io::Error) -> Self {
        HistoryError::Io(e)
    }
}

/// Failure of [`crate::Kernel::transact`] (§1/§3).
#[derive(Debug)]
pub enum TxnError<E> {
    /// `f`'s typed precondition failure — surfaced verbatim to M10 (never a
    /// silent skip). Nothing committed, no dangling state; the rejected call
    /// is an A1 zero-step case evaluated against the base committed index.
    Rejected(E),
    /// The per-commit barrier (the single records+marker fsync) failed BEFORE
    /// install — or a non-unwind `io::Error` from the append path preceded it
    /// (e.g. ENOSPC; §3) — AND the txn's un-acked record+marker tail was
    /// durably truncated (Seqs burned per [`crate::BurnedSeqPolicy`]), so
    /// nothing was installed and no durable marker survives → a TRUE no-op;
    /// the caller may safely re-invoke. If the truncation ITSELF fails to
    /// complete durably the kernel POISONS and the call returns [`Poisoned`]
    /// instead (§1: a surviving un-acked marker would let a successor collide
    /// on recovery).
    ///
    /// [`Poisoned`]: TxnError::Poisoned
    Durability(io::Error),
    /// The staged records could not be turned into journal frames at all — a
    /// record whose serializer refuses, or one whose serialized form exceeds
    /// the journal's frame size. Nothing was appended and nothing installed,
    /// so this is a true no-op like [`Durability`] — but the refusal is a
    /// property of the RECORDS, so re-invoking with the same records fails
    /// the same way, however healthy the disk. The serializer's own account
    /// travels, since M2 never inspects `W::Record`.
    ///
    /// [`Durability`]: TxnError::Durability
    Unencodable(io::Error),
    /// The kernel was halted by an UNRECOVERABLE failure (§1/§3): a
    /// durability-failure or panic-guard truncation that itself failed to
    /// complete durably, an unwind after a successful barrier but before
    /// install, or a `Seq` order with no room left for another transaction
    /// (§2 — the coordinates are exhausted, and renumbering over a committed
    /// predecessor is not an option). Returned by the poisoning call ITSELF
    /// (in place of `Durability`; a panic-path poisoning propagates the panic
    /// instead) and by every later `transact`; reads
    /// (`snapshot`/`current_seq`) keep serving the last consistent root. Do
    /// not re-invoke.
    Poisoned,
}

impl<E: fmt::Display> fmt::Display for TxnError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TxnError::Rejected(e) => write!(f, "transaction rejected: {e}"),
            TxnError::Durability(e) => {
                write!(f, "durability barrier failed before install (true no-op): {e}")
            }
            TxnError::Unencodable(e) => {
                write!(f, "records cannot be journaled (true no-op, not retryable): {e}")
            }
            TxnError::Poisoned => write!(f, "kernel is poisoned; write paths are halted"),
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for TxnError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TxnError::Durability(e) | TxnError::Unencodable(e) => Some(e),
            _ => None,
        }
    }
}
