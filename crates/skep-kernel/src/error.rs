//! Error types of the public surface (§Public interface).

use std::fmt;
use std::io;

use crate::Seq;

/// Failure of [`crate::Kernel::open`] (§6/§7).
#[derive(Debug)]
pub enum OpenError {
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
            OpenError::Io(e) => write!(f, "journal open/recovery I/O failure: {e}"),
            OpenError::BadCheckpoint => {
                write!(f, "no retained checkpoint loads and genesis is unreachable")
            }
            OpenError::Corruption { at } => write!(
                f,
                "durable committed data corrupt in the replayed range; next intact frame at seq {}",
                at.0
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

/// Failure of [`crate::Kernel::checkpoint`] (§6).
#[derive(Debug)]
pub enum CheckpointError {
    /// I/O failure persisting the checkpoint, pruning retention, or reclaiming
    /// journal segments.
    Io(io::Error),
    /// The world failed to serialize.
    Serialize,
    /// A prior barrier/truncation/unwind failure has halted the kernel
    /// (§1/§3); no further checkpoint is taken.
    Poisoned,
}

impl fmt::Display for CheckpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CheckpointError::Io(e) => write!(f, "checkpoint I/O failure: {e}"),
            CheckpointError::Serialize => write!(f, "checkpoint world serialization failed"),
            CheckpointError::Poisoned => write!(f, "kernel is poisoned; no checkpoint taken"),
        }
    }
}

impl std::error::Error for CheckpointError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CheckpointError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for CheckpointError {
    fn from(e: io::Error) -> Self {
        CheckpointError::Io(e)
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
    /// The kernel was halted by a prior UNRECOVERABLE failure (§1/§3): a
    /// durability-failure or panic-guard truncation that itself failed to
    /// complete durably, or an unwind after a successful barrier but before
    /// install. Returned by the poisoning call ITSELF (in place of
    /// `Durability`; a panic-path poisoning propagates the panic instead) and
    /// by every later `transact`; reads (`snapshot`/`current_seq`) keep
    /// serving the last consistent root. Do not re-invoke.
    Poisoned,
}

impl<E: fmt::Display> fmt::Display for TxnError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TxnError::Rejected(e) => write!(f, "transaction rejected: {e}"),
            TxnError::Durability(e) => {
                write!(f, "durability barrier failed before install (true no-op): {e}")
            }
            TxnError::Poisoned => write!(f, "kernel is poisoned; write paths are halted"),
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for TxnError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TxnError::Durability(e) => Some(e),
            _ => None,
        }
    }
}
