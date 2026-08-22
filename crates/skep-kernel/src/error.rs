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
    /// Durable committed data the recovered state needs cannot be read. Four
    /// conditions reach here: a corrupt run inside the genuinely-replayed
    /// range `(S_load, W]` (a run reaching EOF is the un-acked / torn tail,
    /// not this); a segment whose frame stream could not be enumerated in
    /// bounded work, so nothing derived from it is more than a prefix; a
    /// committed record that does not decode as `W::Record`, or one the
    /// committed set presents twice; and a committed head that leaves no
    /// coordinate for a successor, which no sequencer here could have
    /// written. Halt, never drop — nothing is folded, nothing is installed,
    /// and nothing is truncated. Operator-intervention condition — not
    /// auto-retried (§7).
    Corruption {
        /// The coordinate naming the damage, which differs by condition: for
        /// a corrupt run, the next INTACT frame's coordinate — the run's own
        /// seqs are unreadable, so this bounds the damage rather than
        /// locating it; for an unbounded resynchronization, the base's own
        /// coordinate, since the damage lies somewhere above it and the scan
        /// could not reach past it to say where; for an undecodable or
        /// repeated record, that record's own `Seq`; for an exhausted order,
        /// the committed head itself.
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

/// Failure of [`crate::Kernel::world_at`] — the read-only bounded replay.
/// None of these poisons the kernel or perturbs the live write path; every
/// variant is an honest "this boundary cannot be answered" (or a genuine
/// at-rest corruption find).
#[derive(Debug)]
pub enum HistoryError {
    /// `at` is above the INSTALLED head at the time of the call — the
    /// installed root's seq ([`crate::Kernel::current_seq`]), which is the
    /// greatest boundary this kernel answers. Not §7's committed head: a
    /// kernel poisoned after a barrier but before its install holds a durable
    /// committed boundary above this one, and refuses it.
    BeyondHead {
        /// The installed head observed by this call.
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
    /// Corrupt data at rest in the scanned region — the same conditions, and
    /// the same coordinate, that [`OpenError::Corruption`] carries, with the
    /// same halt-never-drop verdict (§7). The exhausted `Seq` order is the one
    /// route not available here: only a mint site reaches it, and this call
    /// mints nothing.
    Corruption {
        /// See [`OpenError::Corruption`].
        at: Seq,
    },
}

impl fmt::Display for HistoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HistoryError::BeyondHead { head } => {
                write!(f, "boundary beyond the installed head {head}")
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
    /// the journal's frame cap. Nothing was appended and nothing installed,
    /// so this is a true no-op like [`Durability`] — but the refusal is a
    /// property of the RECORDS, so the remedy is to fix the record, where
    /// re-invoking unchanged fails the same way however healthy the disk.
    /// The serializer's own account travels, since M2 never inspects
    /// `W::Record`.
    ///
    /// Both halves arise in BOTH durability modes: the encode runs before
    /// the journal is consulted, and the frame-cap half is judged there too
    /// — against the frames the journaled mode would build — so an in-memory
    /// kernel refuses exactly what a journaled one refuses.
    ///
    /// [`Durability`]: TxnError::Durability
    Unencodable(io::Error),
    /// The staged records all encode, and their whole encoded form — record
    /// frames, commit marker and headers — exceeds the journal's
    /// per-transaction budget, [`crate::MAX_TXN_BYTES`]. Refused in BOTH
    /// durability modes, above the journal's mode branch, before anything is
    /// appended or installed: a true no-op like [`Durability`]. Unlike
    /// [`Unencodable`] the refusal is a property of the STAGING, not of any
    /// one record — the serializer refused nothing — so the remedy is to
    /// SPLIT the transaction, where fixing a value cannot help and
    /// re-invoking unsplit fails the same way forever.
    ///
    /// The budget is what keeps recovery's memory floor replica-independent:
    /// a transaction never spans a journal segment and recovery reads a
    /// segment whole, so an unbounded transaction would permanently raise the
    /// cost of every later `open()` of the store it committed to.
    ///
    /// [`Durability`]: TxnError::Durability
    /// [`Unencodable`]: TxnError::Unencodable
    OverBudget {
        /// The transaction's accounted encoded size — what the journal would
        /// have had to hold, and what the caller's split must get under
        /// [`crate::MAX_TXN_BYTES`].
        bytes: u64,
    },
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
            TxnError::OverBudget { bytes } => write!(
                f,
                "transaction encodes to {bytes} bytes, over the journal's per-transaction \
                 budget (true no-op; split the transaction)"
            ),
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
