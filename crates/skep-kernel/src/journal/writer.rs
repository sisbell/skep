//! The writer, which is the journal's append side: the appender over the
//! active segment — the barrier, the install hand-off, the repair after a
//! failed or unwound commit — and the [`Journal`] a kernel commits through,
//! which judges the records above its durability-mode branch.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::Serialize;

use super::{
    encode_record, encode_txn, fsync_dir, list_segments, record_frame_len, record_payload_len,
    segment_path, Attestation, CHAIN_GENESIS, MARKER_FRAME_LEN, MAX_FRAME_LEN, MAX_TXN_BYTES,
    SEGMENT_ROTATE_BYTES,
};
use crate::config::SaltSource;
use crate::error::Cause;
use crate::{Seam, Step};

/// How a commit failed (§1). Three of these leave the journal where the
/// transaction found it, so what separates them is the caller's REMEDY: a
/// cleanly-failed transaction may be re-invoked, an unencodable one needs the
/// record fixed, an over-budget one needs the transaction split. The fourth
/// may have left a durable un-acked marker that a successor would collide
/// with on recovery, and has no remedy but to halt.
#[derive(Debug)]
pub(crate) enum CommitFail {
    /// The active segment is durably back where this transaction found it: no
    /// frame of it survives — a CLEAN failure, a TRUE no-op (§1). Carries what
    /// failed, which the caller may surface; the remedy is to re-invoke, which
    /// is safe precisely because no frame survives.
    Clean(io::Error),
    /// The transaction's records could not be turned into frames at all — a
    /// record that refuses to serialize, or a payload past
    /// [`MAX_FRAME_LEN`]. Nothing reached the file, so this is a no-op like
    /// [`CommitFail::Clean`]; what differs is the remedy: the refusal is a
    /// property of the records, so the record must be fixed — the same
    /// records fail the same way forever. Both halves are judged before the
    /// first file operation, so the cause travels as the error it is rather
    /// than as an `io::Error` a caller would read a disk into.
    Unencodable(Cause),
    /// The transaction's whole encoded form — record frames, marker and
    /// headers, [`txn_encoded_len`](super::txn_encoded_len)'s accounting — exceeds [`MAX_TXN_BYTES`].
    /// Nothing reached the file, so this is a no-op like
    /// [`CommitFail::Clean`]; what differs is the remedy: no record refused
    /// ([`CommitFail::Unencodable`] is that), the caller staged too much at
    /// once, and the same staging refuses the same way forever — split the
    /// transaction. Carries the accounted size, which the caller may surface.
    OverBudget { bytes: u64 },
    /// The truncation could not itself complete durably; frames of this
    /// transaction, possibly including its marker, may survive (§1/§3). The
    /// only sound response is to halt, so no error travels with it — nothing
    /// about which write failed changes what the caller must do.
    Unrepaired,
}

/// What an unwind out of the commit region left in the journal (§3).
#[derive(Debug)]
pub(crate) enum UnwindRepair {
    /// Nothing of the transaction survives — either it never reached the
    /// file, or the repair durably removed what it had appended.
    Clean,
    /// The repair could not complete durably: an un-acked marker may survive.
    Unrepaired,
    /// The unwind came after the barrier: the transaction is durably
    /// committed, and whether its effect was ever installed cannot be
    /// accounted for from here.
    AfterBarrier,
}

/// What an in-flight transaction has reached in the active segment — the
/// writer's own answer to "if something unwinds now, what is on disk?" (§3).
enum InFlight {
    /// Nothing in flight: the segment holds only completed transactions.
    Idle,
    /// Frames may be appended past `mark` and none of them are durable yet.
    Appending { mark: u64 },
    /// The barrier passed: durably committed, install in progress.
    Barriered,
}

/// The live appender over the active (last) segment. All calls happen under
/// the applier lock (§3/§8); appends are in `Seq` order, so file order ==
/// `Seq` order (§2).
pub(crate) struct JournalWriter {
    dir: PathBuf,
    file: File,
    len: u64,
    /// The commit chain's running value: the chain of the last COMMITTED
    /// transaction in this journal, which the next one links from
    /// ([`ChainLink`](super::chain::ChainLink)). Seeded at [`JournalWriter::open_active`] with what
    /// recovery derived — the last committed marker's value, or the base's —
    /// advanced only once a transaction's barrier has passed (a transaction
    /// truncated back leaves it where it was), and carried across a segment
    /// rotation: the chain is over the journal, not the segment.
    chain: [u8; 32],
    /// The kernel's configured [`SaltSource`] (`SKJ4`), which each
    /// transaction's salt is drawn from — handed in at
    /// [`JournalWriter::open_active`] and carried across a rotation like the
    /// chain. Consulted once per commit, before a frame is built; the reader
    /// never consults it, since the salt it needs is in the marker.
    salt_source: SaltSource,
    /// What the transaction in progress has reached. On entry to
    /// [`JournalWriter::commit_txn`] this is always [`InFlight::Idle`]: every
    /// path that returns to a caller who may commit again leaves it so, and
    /// the two that do not — a truncation that could not itself complete
    /// durably, and an unwind through the install — halt the kernel, so no
    /// transaction follows them. That is what lets the commit path start
    /// against this field rather than resetting it defensively first (§3).
    in_flight: InFlight,
    /// The write-fault seam ([`Step`]) the three file operations below hook
    /// before — the append, the barrier and the repair's truncation. The
    /// kernel's, handed after the open ([`JournalWriter::with_seam`]) and
    /// carried across a rotation like the chain; an appender nobody hands
    /// one holds a fresh one nothing has armed. A no-op without
    /// `test-hooks`.
    seam: Seam,
}

impl JournalWriter {
    /// Reopen the last existing segment for append, or create `seg-<next_seq>`
    /// (first init / fully-reclaimed-to-checkpoint journal).
    ///
    /// CALLER OBLIGATION — this reads the active segment's length ONCE, and
    /// every pre-transaction mark, rotation test and repair truncation
    /// afterwards is relative to that figure. So any truncation of that
    /// segment must already be durable when this is called: recovery's tail
    /// cut runs first (§7), and an appender opened before it holds a length
    /// above the real data, so the next failed barrier truncates back to a
    /// mark above it and cuts committed frames. Appends still land at the end
    /// of file, which is what makes the mistake silent.
    ///
    /// `chain` is the commit chain's value at the committed head this
    /// appender continues from — what the recovery scan derived
    /// ([`ScanOutcome::chain_head`](super::ScanOutcome::chain_head)), or [`CHAIN_GENESIS`] for a journal with
    /// nothing committed — and is the second thing this reads once.
    /// `salt_source` is the kernel's configured source for every transaction
    /// this appender will commit; a journal written under one source reopens
    /// under any, since the salts already written are read off their markers.
    pub(crate) fn open_active(
        dir: &Path,
        next_seq: u64,
        chain: [u8; 32],
        salt_source: SaltSource,
    ) -> io::Result<Self> {
        let segs = list_segments(dir)?;
        match segs.last() {
            Some(seg) => {
                let file = OpenOptions::new().append(true).open(&seg.path)?;
                let len = file.metadata()?.len();
                Ok(JournalWriter {
                    dir: dir.to_path_buf(),
                    file,
                    len,
                    chain,
                    salt_source,
                    in_flight: InFlight::Idle,
                    seam: Seam::default(),
                })
            }
            None => Self::create_segment(dir, next_seq, chain, salt_source, Seam::default()),
        }
    }

    /// This appender holding the kernel's write-fault seam in place of the
    /// fresh one [`JournalWriter::open_active`] gave it — so what the
    /// kernel's doors arm, the append, the barrier and the repair here fire.
    /// Handed after the open rather than at it because the appender is
    /// opened by recovery, which has no kernel yet, and by fixtures that
    /// have none at all.
    pub(crate) fn with_seam(mut self, seam: Seam) -> Self {
        self.seam = seam;
        self
    }

    fn create_segment(
        dir: &Path,
        first_seq: u64,
        chain: [u8; 32],
        salt_source: SaltSource,
        seam: Seam,
    ) -> io::Result<Self> {
        let path = segment_path(dir, first_seq);
        // Born `0600` on unix: the segment is the board's history whole, and
        // the mode is set at creation so the process umask cannot loosen it.
        let mut opts = OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts.open(&path)?;
        // The new entry must be durable before any commit acked out of this
        // segment can rely on recovery finding the file (§1: fsync-of-dir on
        // rotate / first init).
        fsync_dir(dir)?;
        let len = file.metadata()?.len();
        Ok(JournalWriter {
            dir: dir.to_path_buf(),
            file,
            len,
            chain,
            salt_source,
            in_flight: InFlight::Idle,
            seam,
        })
    }

    /// Commit one whole transaction and install its effect (§1: append
    /// records → append marker → ONE records+marker fsync → `install`),
    /// rotating first at this txn boundary if the active segment is over the
    /// threshold, and answering the byte count appended.
    ///
    /// The segment is this writer's to repair: a failure anywhere past the
    /// pre-transaction mark durably truncates back to it before returning, so
    /// [`CommitFail::Clean`] states that nothing of the transaction survives.
    /// Only a truncation that cannot itself complete durably answers
    /// [`CommitFail::Unrepaired`]. A transaction that never became frames at
    /// all answers [`CommitFail::Unencodable`], before the segment is touched.
    ///
    /// `install` makes the committed effect visible, and runs HERE — after
    /// the barrier, before this returns — because the window between a
    /// durable commit and its install is the one failure this writer cannot
    /// repair (§3). Bounding it inside the call is what keeps a caller from
    /// leaving the writer believing a committed transaction is still in
    /// flight. It is handed the transaction's chain value — the marker's,
    /// now durable — so the root it installs carries the chain at its own
    /// coordinate, which is what a checkpoint taken off that root writes as
    /// its `chain_head`.
    pub(crate) fn commit_txn(
        &mut self,
        first_seq: u64,
        record_bytes: Vec<Vec<u8>>,
        attestation: Option<&Attestation>,
        install: impl FnOnce([u8; 32]),
    ) -> Result<u64, CommitFail> {
        // THE SALT IS DRAWN HERE (`SKJ4`), once per transaction, from the
        // kernel's source, before a frame exists: `encode_txn` stores it in
        // the marker and closes the link with it. An OS that refuses entropy
        // refuses the commit as a clean failure — nothing was framed, nothing
        // appended, the segment is where the transaction found it, and
        // re-invoking is safe — rather than as a property of the records.
        let salt = self.salt_source.draw(first_seq).map_err(CommitFail::Clean)?;
        let (buf, chain) = encode_txn(first_seq, record_bytes, &self.chain, salt, attestation)
            .map_err(|e| CommitFail::Unencodable(Box::new(e)))?;
        self.maybe_rotate(first_seq).map_err(CommitFail::Clean)?;
        let mark = self.len;
        self.in_flight = InFlight::Appending { mark };
        match self.append(&buf).and_then(|()| self.barrier()) {
            Ok(()) => {
                // Durable, so the chain has advanced whatever happens to the
                // install: a poisoned kernel's next recovery derives this
                // same value from the marker on disk.
                self.chain = chain;
                self.in_flight = InFlight::Barriered;
                install(chain);
                self.in_flight = InFlight::Idle;
                Ok(buf.len() as u64)
            }
            Err(e) => Err(match self.truncate_to(mark) {
                Ok(()) => CommitFail::Clean(e),
                Err(_) => CommitFail::Unrepaired,
            }),
        }
    }

    /// Repair the active segment after an unwind out of the commit region and
    /// answer what the unwind left behind (§3): an append still short of its
    /// barrier is durably truncated back to the pre-transaction mark, and a
    /// transaction that passed its barrier is durably committed and beyond
    /// repair — its record+marker tail must stay, since removing an acked
    /// commit is the one thing recovery may never do.
    ///
    /// This CONSUMES the in-flight state, so it answers once per unwind. Both
    /// non-[`UnwindRepair::Clean`] answers halt the kernel, and this writer is
    /// not used again.
    pub(crate) fn repair_after_unwind(&mut self) -> UnwindRepair {
        match std::mem::replace(&mut self.in_flight, InFlight::Idle) {
            InFlight::Idle => UnwindRepair::Clean,
            InFlight::Appending { mark } => match self.truncate_to(mark) {
                Ok(()) => UnwindRepair::Clean,
                Err(_) => UnwindRepair::Unrepaired,
            },
            InFlight::Barriered => UnwindRepair::AfterBarrier,
        }
    }

    /// Durably truncate back to `mark` — the §1 barrier-failure / §3
    /// unwind-guard tail truncation, idempotent and retried harmlessly. `Err`
    /// is a truncation that could not itself complete durably, leaving the
    /// segment where it was; nothing about WHICH write failed changes what
    /// either caller must do, so both drop it. The seam's
    /// [`Step::JournalRepair`] is hooked before the truncation, so an armed
    /// failure is exactly that `Err`.
    fn truncate_to(&mut self, mark: u64) -> io::Result<()> {
        self.seam.before(Step::JournalRepair)?;
        self.file.set_len(mark)?;
        self.file.sync_data()?;
        self.len = mark;
        self.in_flight = InFlight::Idle;
        Ok(())
    }

    /// Rotate at a txn boundary if the active segment is over the threshold.
    /// `first_seq` is the incoming txn's first `Seq` — the new segment's name
    /// — so segment names stay lower bounds of their content and successor
    /// names stay sound `lastSeq` inferences for predecessors (§1). Called
    /// BEFORE any of the txn's frames are appended; on failure nothing of the
    /// txn is on disk (the §3 pre-append discipline applies) and the next
    /// attempt re-enters rotation.
    fn maybe_rotate(&mut self, first_seq: u64) -> io::Result<()> {
        // The first disjunct is redundant while the threshold is a positive
        // constant, and it states the rule the rotation rests on: an EMPTY
        // segment never rotates. Without it a zero threshold would answer
        // every transaction with a fresh empty file and accumulate them
        // forever, so the guard is what keeps the threshold a tuning knob
        // rather than a correctness one.
        if self.len == 0 || self.len < SEGMENT_ROTATE_BYTES {
            return Ok(());
        }
        // Under per-commit Fsync the old segment is already durable (the
        // previous txn's barrier fsynced it) — the §1 rotation discipline.
        // The chain rides across: it is over the journal, not the segment;
        // the salt source and the seam with it.
        *self = Self::create_segment(
            &self.dir,
            first_seq,
            self.chain,
            self.salt_source,
            self.seam.clone(),
        )?;
        Ok(())
    }

    /// Append the transaction's frames, the seam's [`Step::JournalAppend`]
    /// hooked before the write: an armed failure there is a transaction no
    /// byte of which reached the file.
    fn append(&mut self, buf: &[u8]) -> io::Result<()> {
        self.seam.before(Step::JournalAppend)?;
        self.file.write_all(buf)?;
        self.len += buf.len() as u64;
        Ok(())
    }

    /// The durability barrier: ONE fsync of records+marker (§1), the seam's
    /// [`Step::JournalBarrier`] hooked before it: an armed failure there is
    /// the frames appended and none of them durable.
    fn barrier(&mut self) -> io::Result<()> {
        self.seam.before(Step::JournalBarrier)?;
        self.file.sync_data()
    }
}

/// The journal a kernel commits through: segments on disk, or their absence
/// under [`crate::Durability::InMemory`], which journals nothing while its
/// commit path still runs the `Seq` allocation and the atomic install (§1).
/// Both answers live here, so no caller re-discovers the absence.
pub(crate) enum Journal {
    InMemory,
    Segments(JournalWriter),
}

impl Journal {
    /// Commit one whole transaction: serialize its records, judging each
    /// against the two size limits no durability mode may skip, then commit
    /// through whichever journal this is.
    ///
    /// The encode and the size judgment happen HERE, above this enum's own
    /// mode branch, which is what makes them mode-independent by construction
    /// rather than by a caller's discipline: an in-memory kernel serializes
    /// every record a journaled one serializes and refuses exactly what a
    /// journaled one refuses of the records themselves, so a store that
    /// passes an in-memory test does not meet a size refusal only in
    /// production. The two arms below therefore differ only in what only a
    /// file can refuse — [`JournalWriter::commit_txn`] for the durable one,
    /// and for the in-memory one no bytes appended, no failure available, and
    /// an install where the durable journal installs, after a barrier it has
    /// no need of. The slot rides past this judgment and is no exception to
    /// it: every [`Attestation`] is at most [`super::MAX_SIG_BYTES`] wide,
    /// which the frame cap admits beside the marker's own fields (asserted
    /// where `MARKER_FRAME_LEN` is defined), so the durable arm frames every
    /// slot the in-memory arm drops. The in-memory arm hands `install`
    /// [`CHAIN_GENESIS`]: the chain is over journal frames, of which that arm
    /// builds none, so an in-memory kernel's chain reads as the genesis value
    /// at every coordinate, as [`crate::Kernel::chain_head`] states, and no
    /// checkpoint persists it.
    ///
    /// The two limits are judged AS THE LOOP GOES, and a record past the
    /// budget is dropped rather than kept, which is what makes enforcing
    /// [`MAX_TXN_BYTES`] cost [`MAX_TXN_BYTES`]: a caller who stages a hundred
    /// records each just under the frame cap would otherwise have every one of
    /// them materialized — under the applier lock, so with every other writer
    /// in the process waiting — before the sum that refuses them was taken.
    /// Held bytes are therefore bounded by the budget and the transient peak
    /// by one further frame. The records are CONSUMED into their bytes, one
    /// per iteration, so that pair is the whole of what a commit holds and
    /// not a pair beside the unserialized staging: each record is released as
    /// this loop encodes it.
    ///
    /// Two refusals, and their order is the caller's remedy in each case: a
    /// record whose frame payload would exceed [`MAX_FRAME_LEN`] — the refusal
    /// [`push_frame`](super::push_frame) would give it, [`CommitFail::Unencodable`], a property of
    /// that record — precedes a whole encoded form past [`MAX_TXN_BYTES`] —
    /// [`CommitFail::OverBudget`], a property of the staging, where every
    /// record is fine and the caller staged too much at once. So a caller
    /// fixing a value is not first told to split. [`push_frame`](super::push_frame)'s own
    /// frame-cap refusal deliberately stays: writer and reader sit on opposite
    /// sides of a trust boundary, and the writer's guard is what entitles
    /// recovery to treat a larger claimed `len` as corrupt.
    ///
    /// PRECONDITION — `records` is non-empty. A zero-step op never reaches the
    /// journal: [`crate::Kernel::transact`] returns at the zero-step before a
    /// coordinate is minted, and `NonZeroU64` carries the rest. The assertion
    /// below is a second check of that one rule at a second boundary, owed for
    /// the reason [`push_frame`](super::push_frame)'s frame-cap guard is owed beside this method's
    /// own size limit: what this method promises is that its two arms answer
    /// alike, and without it a violation panics through [`encode_txn`] on the
    /// durable arm and INSTALLS a transaction with no records on the in-memory
    /// one — a disagreement in the one element whose purpose is that the arms
    /// cannot disagree.
    pub(crate) fn commit_txn<R: Serialize>(
        &mut self,
        first_seq: u64,
        records: Vec<R>,
        attestation: Option<&Attestation>,
        install: impl FnOnce([u8; 32]),
    ) -> Result<u64, CommitFail> {
        assert!(
            !records.is_empty(),
            "zero-step ops never reach the journal: `transact` returns before \
             minting a coordinate"
        );
        let mut record_bytes: Vec<Vec<u8>> = Vec::new();
        // The EMPTY marker's figure, whatever the slot will hold: the
        // attestation's blob sits OUTSIDE this budget ([`MARKER_FRAME_LEN`]'s
        // card says why), so an attested transaction and its unattested twin
        // are judged alike here.
        let mut accounted = MARKER_FRAME_LEN;
        let mut over_budget = false;
        for record in records {
            // The closure is the unsizing coercion site: the bare constructor
            // as a function value does not coerce `bincode`'s boxed error.
            let bytes = encode_record(&record).map_err(|e| CommitFail::Unencodable(e))?;
            if record_payload_len(bytes.len()) > MAX_FRAME_LEN as u64 {
                return Err(CommitFail::Unencodable(
                    "record's serialized form exceeds the journal's frame cap".into(),
                ));
            }
            accounted = accounted.saturating_add(record_frame_len(bytes.len()));
            // Past the budget this transaction cannot commit, so only its SIZE
            // is still wanted: the loop runs on to finish the accounting the
            // refusal reports and to keep judging each record's own frame cap
            // first, and the bytes are dropped rather than held.
            over_budget |= accounted > MAX_TXN_BYTES;
            if !over_budget {
                record_bytes.push(bytes);
            }
        }
        if over_budget {
            return Err(CommitFail::OverBudget { bytes: accounted });
        }
        match self {
            // No marker exists here, so no slot: the attestation is dropped
            // with the frames it would have ridden. A fixture that wants to
            // pin a filled slot is journaled, as the golden is.
            Journal::InMemory => {
                install(CHAIN_GENESIS);
                Ok(0)
            }
            Journal::Segments(writer) => {
                writer.commit_txn(first_seq, record_bytes, attestation, install)
            }
        }
    }

    /// [`JournalWriter::repair_after_unwind`]. The in-memory arm answers
    /// [`UnwindRepair::Clean`] for every unwind, because every unwind out of
    /// it precedes the install: past the size refusals it only calls
    /// `install`, and `install` drops no world — [`crate::Kernel::transact`]
    /// holds the superseded root until it returns, so the store releases
    /// only a reference ([`crate::WorldState`]'s drop obligation) — so
    /// nothing it runs can unwind. The durable arm tracks
    /// [`InFlight::Barriered`] because it has a barrier to be after, and this
    /// arm has none.
    pub(crate) fn repair_after_unwind(&mut self) -> UnwindRepair {
        match self {
            Journal::InMemory => UnwindRepair::Clean,
            Journal::Segments(writer) => writer.repair_after_unwind(),
        }
    }
}

#[cfg(test)]
mod tests;
