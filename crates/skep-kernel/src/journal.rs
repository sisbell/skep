//! The journal — the ONLY durable, authoritative state M2 owns (§Core data
//! model; Lampson: the log is the truth, in-memory structures are hints).
//!
//! Frames: `[u32 magic][u32 len][u32 crc][payload]`, where the fixed `magic`
//! sync word anchors recovery resynchronization (§7) and `crc` covers BOTH the
//! `len` field and the payload, so a corrupt length is *detected* rather than
//! silently mis-delimiting the following frame (§1). Payload is one of
//! [`LogRecord`] or [`Marker`], every frame `txn`-tagged so recovery groups a
//! transaction's records to validate its marker's `records_checksum` even
//! after a magic-resync skipped a corrupt frame (§1/§7).
//!
//! Segments: append-only files named by their `firstSeq` (`seg-<n>.wal` — the
//! open build decision's name-by-firstSeq representation), so a *closed*
//! segment's `lastSeq` is inferred from its successor's name. The final
//! (active) segment has no trusted `lastSeq`: always scanned by recovery,
//! never range-reclaimed (§1/§6/§7).

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// Per-frame sync word anchoring recovery resynchronization (§1/§7).
const MAGIC: [u8; 4] = *b"SKJ1";
/// Frame header: magic (4) + len (4) + crc (4).
pub(crate) const FRAME_HEADER_LEN: usize = 12;
/// Sanity bound on a single frame (open build decision: max frame size). The
/// writer enforces it, so recovery may treat a larger claimed `len` as corrupt.
const MAX_FRAME_LEN: u32 = 64 * 1024 * 1024;
/// Rotation threshold (open build decision), tested BEFORE a transaction is
/// appended and only at a txn boundary — so a closed segment holds this many
/// bytes plus one whole transaction, and a caller bounding memory or file size
/// reckons with that transaction rather than with this figure. Rotating at txn
/// boundaries only is what keeps a txn's frames from spanning a segment; under
/// per-commit Fsync the old segment is already durable at rotation (its last
/// txn's barrier fsynced it), preserving marker-as-ack across the boundary
/// (§1).
const SEGMENT_ROTATE_BYTES: u64 = 1024 * 1024;

/// A transaction's identity: its FIRST `Seq` (§1) — a distinguished `Seq`,
/// never a separate counter, which is why it is unique within any scanned
/// journal region and recovered for free with the single `Seq` high-water
/// (§1/§7). Seqs travel this layer as raw `u64`; typing the identity is what
/// keeps a frame's `seq` and its `txn` from being interchanged.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(crate) struct Txn(pub u64);

/// One journaled authoritative delta (§1). `bytes` is the serialized
/// `W::Record`; the struct is named `LogRecord` so it does not collide with
/// the trait's `W::Record`. Every frame is [`Txn`]-tagged, so recovery groups
/// a transaction's records by identity rather than by file position (§1/§7).
#[derive(Serialize, Deserialize)]
pub(crate) struct LogRecord {
    pub seq: u64,
    pub txn: Txn,
    pub bytes: Vec<u8>,
}

/// Per-txn commit marker — the terminal frame of a transaction. In v1 a
/// committed marker (intact, durable, `records_checksum`-valid) *is* the
/// commit ack (§1). `records_checksum` is CRC32C over the concatenated payload
/// bytes of the txn's record frames, in `Seq` order — which is the order they
/// are framed in, so recovery reproduces it by streaming the frames as it
/// reads them. Distinct from the marker's own per-frame `crc`, and
/// byte-reproducible at recovery (§1/§7).
#[derive(Serialize, Deserialize)]
pub(crate) struct Marker {
    pub txn: Txn,
    pub last_seq: u64,
    pub records_checksum: u32,
}

/// The serde-tagged frame payload (§1).
#[derive(Serialize, Deserialize)]
pub(crate) enum FramePayload {
    Record(LogRecord),
    Marker(Marker),
}

fn invalid_data(e: bincode::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

/// One `W::Record`'s wire form — the `bytes` a [`LogRecord`] frame carries.
///
/// Stated as a pair with [`decode_record`], here, because the encode and the
/// decode are one agreement: a change to either that the other does not match
/// turns every healthy journal into one that cannot be replayed. M2 never
/// inspects a record, so the serializer's own account is the whole of what
/// identifies a refusal, and it travels.
pub(crate) fn encode_record<R: Serialize>(record: &R) -> io::Result<Vec<u8>> {
    bincode::serialize(record).map_err(invalid_data)
}

/// Read back what [`encode_record`] wrote. `Err` is a committed, CRC-intact
/// record that does not decode as this `W::Record` — corrupt committed data,
/// or a writer/reader skew, either way something the fold cannot supply and
/// must not skip (§7).
pub(crate) fn decode_record<R: DeserializeOwned>(bytes: &[u8]) -> io::Result<R> {
    bincode::deserialize(bytes).map_err(invalid_data)
}

/// Append one framed payload to `buf`: `[magic][len][crc(len+payload)][payload]`.
fn push_frame(buf: &mut Vec<u8>, payload: &[u8]) -> io::Result<()> {
    if payload.len() as u64 > MAX_FRAME_LEN as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame payload exceeds MAX_FRAME_LEN",
        ));
    }
    let len = payload.len() as u32;
    let len_le = len.to_le_bytes();
    let crc = crc32c::crc32c_append(crc32c::crc32c(&len_le), payload);
    buf.extend_from_slice(&MAGIC);
    buf.extend_from_slice(&len_le);
    buf.extend_from_slice(&crc.to_le_bytes());
    buf.extend_from_slice(payload);
    Ok(())
}

/// Encode one whole transaction: its record frames (seqs `first_seq..`) then
/// its terminal commit marker, ready for a single `write_all` + one barrier
/// fsync (§1/§3). `records` are the already-serialized `W::Record` bytes, and
/// they are consumed into their frames: the caller has no use for them past
/// this call, and a commit is no place to copy every record a second time.
///
/// The `Seq` arithmetic here stays in range because the coordinates were
/// already minted: [`crate::Kernel::transact`] draws the whole run
/// `first_seq..=first_seq + (n - 1)` from the kernel's sequencer — the one
/// mint site — through a checked add before any of it reaches this function
/// (§2). The parenthesisation is load-bearing at the ceiling:
/// `first_seq + (n - 1)` computes no intermediate above the last coordinate
/// the run legitimately holds.
fn encode_txn(first_seq: u64, records: Vec<Vec<u8>>) -> io::Result<Vec<u8>> {
    let n = records.len() as u64;
    assert!(n > 0, "zero-step ops never reach the journal");
    let txn = Txn(first_seq);
    let mut buf = Vec::new();
    let mut checksum = 0u32;
    for (i, bytes) in records.into_iter().enumerate() {
        let payload = bincode::serialize(&FramePayload::Record(LogRecord {
            seq: first_seq + i as u64,
            txn,
            bytes,
        }))
        .map_err(invalid_data)?;
        checksum = crc32c::crc32c_append(checksum, &payload);
        push_frame(&mut buf, &payload)?;
    }
    let last_seq = first_seq + (n - 1);
    let payload = bincode::serialize(&FramePayload::Marker(Marker {
        txn,
        last_seq,
        records_checksum: checksum,
    }))
    .map_err(invalid_data)?;
    push_frame(&mut buf, &payload)?;
    Ok(buf)
}

enum Parsed {
    /// The frame at `pos` is intact: its own `crc` validates over `len`+payload.
    Intact { payload: Range<usize>, end: usize },
    /// Not a trustworthy frame start (bad magic, oversize/overrunning `len`,
    /// or CRC mismatch) — resynchronize via the magic word (§1/§7).
    Bad,
}

fn parse_frame(buf: &[u8], pos: usize) -> Parsed {
    if pos + FRAME_HEADER_LEN > buf.len() || buf[pos..pos + 4] != MAGIC {
        return Parsed::Bad;
    }
    let len = u32::from_le_bytes(buf[pos + 4..pos + 8].try_into().unwrap());
    let crc = u32::from_le_bytes(buf[pos + 8..pos + 12].try_into().unwrap());
    if len > MAX_FRAME_LEN {
        return Parsed::Bad;
    }
    let end = pos + FRAME_HEADER_LEN + len as usize;
    if end > buf.len() {
        return Parsed::Bad;
    }
    let computed = crc32c::crc32c_append(
        crc32c::crc32c(&buf[pos + 4..pos + 8]),
        &buf[pos + FRAME_HEADER_LEN..end],
    );
    if computed != crc {
        return Parsed::Bad;
    }
    Parsed::Intact {
        payload: pos + FRAME_HEADER_LEN..end,
        end,
    }
}

fn find_magic(buf: &[u8], from: usize) -> Option<usize> {
    if from >= buf.len() {
        return None;
    }
    buf[from..]
        .windows(MAGIC.len())
        .position(|w| w == MAGIC)
        .map(|p| from + p)
}

/// A journal segment file, named by its `firstSeq` (§1).
pub(crate) struct SegmentMeta {
    pub first_seq: u64,
    pub path: PathBuf,
}

pub(crate) fn segment_path(dir: &Path, first_seq: u64) -> PathBuf {
    dir.join(format!("seg-{first_seq}.wal"))
}

/// All segments in `dir`, ascending by `firstSeq`. Non-segment files
/// (checkpoints, the lock file) are skipped by the name filter.
pub(crate) fn list_segments(dir: &Path) -> io::Result<Vec<SegmentMeta>> {
    let mut v = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(stem) = name.strip_prefix("seg-").and_then(|r| r.strip_suffix(".wal")) else {
            continue;
        };
        let Ok(first_seq) = stem.parse::<u64>() else { continue };
        v.push(SegmentMeta {
            first_seq,
            path: entry.path(),
        });
    }
    v.sort_by_key(|s| s.first_seq);
    Ok(v)
}

/// The `lastSeq` segment `i` covers, inferred from its successor's name
/// (`firstSeq` − 1). An upper bound — under `TolerateGap` burns the successor
/// starts above its predecessor's true last `Seq` — so every use of it is
/// conservative. `None` for the final (active) segment, which has no
/// successor and therefore no trusted `lastSeq`: it is always scanned, never
/// range-reclaimed (§1/§6/§7).
pub(crate) fn inferred_last_seq(segs: &[SegmentMeta], i: usize) -> Option<u64> {
    segs.get(i + 1).map(|next| next.first_seq.saturating_sub(1))
}

/// Whether the surviving segments still cover `Seq(1)` — whether a fold from
/// genesis can still reach the present. True for an empty journal (nothing
/// has been reclaimed yet); false once reclamation has dropped the segment
/// that began the log, which is what makes genesis unusable as a fallback
/// base (§6/§7).
pub(crate) fn reaches_genesis(segs: &[SegmentMeta]) -> bool {
    segs.first().is_none_or(|s| s.first_seq == 1)
}

/// Reclaim whole *closed* segments covering nothing above `floor`: the
/// qualifying segments form a prefix, so the walk stops at the first that
/// does not qualify, and the active segment never does (§6). Space
/// reclamation only — never a correctness mechanism; recovery's
/// `Seq > S_load` filter handles a straddler's leftovers. On return the
/// directory durably reflects whatever this call removed, with no case split
/// on whether that was anything.
pub(crate) fn reclaim_below(dir: &Path, floor: u64) -> io::Result<()> {
    let segs = list_segments(dir)?;
    for (i, seg) in segs.iter().enumerate() {
        match inferred_last_seq(&segs, i) {
            Some(last) if last <= floor => fs::remove_file(&seg.path)?,
            _ => break,
        }
    }
    fsync_dir(dir)
}

/// Fsync a directory so entry creations/deletions/renames are durable. On
/// non-unix targets this is a no-op (v1 targets unix; the design's dir-fsync
/// obligations are discharged there).
pub(crate) fn fsync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(dir)?.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
    Ok(())
}

/// Take the `open()`-held exclusive advisory lock on the journal directory
/// (Lifecycle): at most one live kernel — appender *or* recoverer — per
/// journal. flock semantics, so the lock dies with the process; a second
/// `open()` fails with the acquisition error (surfaced as `OpenError::Io`).
pub(crate) fn acquire_journal_lock(dir: &Path) -> io::Result<File> {
    let f = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(dir.join("kernel.lock"))?;
    fs2::FileExt::try_lock_exclusive(&f)?;
    Ok(f)
}

/// How a commit failed (§1). The distinction IS the caller's decision: a
/// cleanly-failed transaction left nothing behind and may be re-invoked, an
/// unencodable one left nothing behind and re-invoking cannot change that,
/// and an unrepaired one may have left a durable un-acked marker that a
/// successor would collide with on recovery.
pub(crate) enum CommitFail {
    /// The active segment is durably back where this transaction found it: no
    /// frame of it survives — a CLEAN failure, a TRUE no-op (§1). Carries what
    /// failed, which the caller may surface: the transaction is safe to
    /// re-invoke.
    Clean(io::Error),
    /// The transaction's records could not be turned into frames at all — a
    /// record that refuses to serialize, or a payload past
    /// [`MAX_FRAME_LEN`]. Nothing reached the file, so this is a no-op like
    /// [`CommitFail::Clean`]; what differs is the answer to "retry?", since
    /// the refusal is a property of the records and the same records fail the
    /// same way forever.
    Unencodable(io::Error),
    /// The truncation could not itself complete durably; frames of this
    /// transaction, possibly including its marker, may survive (§1/§3). The
    /// only sound response is to halt, so no error travels with it — nothing
    /// about which write failed changes what the caller must do.
    Unrepaired,
}

/// What an unwind out of the commit region left in the journal (§3).
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
    /// What the transaction in progress has reached. Every path out of this
    /// writer leaves it [`InFlight::Idle`] except the two that halt the
    /// kernel — a truncation that could not itself complete durably, and an
    /// unwind through the install — so a transaction never starts against a
    /// predecessor's leavings (§3).
    in_flight: InFlight,
}

impl JournalWriter {
    /// Reopen the last existing segment for append, or create `seg-<next_seq>`
    /// (first init / fully-reclaimed-to-checkpoint journal).
    pub(crate) fn open_active(dir: &Path, next_seq: u64) -> io::Result<Self> {
        let segs = list_segments(dir)?;
        match segs.last() {
            Some(seg) => {
                let file = OpenOptions::new().append(true).open(&seg.path)?;
                let len = file.metadata()?.len();
                Ok(JournalWriter {
                    dir: dir.to_path_buf(),
                    file,
                    len,
                    in_flight: InFlight::Idle,
                })
            }
            None => Self::create_segment(dir, next_seq),
        }
    }

    fn create_segment(dir: &Path, first_seq: u64) -> io::Result<Self> {
        let path = segment_path(dir, first_seq);
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        // The new entry must be durable before any commit acked out of this
        // segment can rely on recovery finding the file (§1: fsync-of-dir on
        // rotate / first init).
        fsync_dir(dir)?;
        let len = file.metadata()?.len();
        Ok(JournalWriter {
            dir: dir.to_path_buf(),
            file,
            len,
            in_flight: InFlight::Idle,
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
    /// flight.
    pub(crate) fn commit_txn(
        &mut self,
        first_seq: u64,
        records: Vec<Vec<u8>>,
        install: impl FnOnce(),
    ) -> Result<u64, CommitFail> {
        let buf = encode_txn(first_seq, records).map_err(CommitFail::Unencodable)?;
        self.maybe_rotate(first_seq).map_err(CommitFail::Clean)?;
        let mark = self.len;
        self.in_flight = InFlight::Appending { mark };
        match self.append(&buf).and_then(|()| self.barrier()) {
            Ok(()) => {
                self.in_flight = InFlight::Barriered;
                install();
                self.in_flight = InFlight::Idle;
                Ok(buf.len() as u64)
            }
            Err(e) => Err(if self.truncate_to(mark) {
                CommitFail::Clean(e)
            } else {
                CommitFail::Unrepaired
            }),
        }
    }

    /// Repair the active segment after an unwind out of the commit region and
    /// answer what the unwind left behind (§3): an append still short of its
    /// barrier is durably truncated back to the pre-transaction mark, and a
    /// transaction that passed its barrier is durably committed and beyond
    /// repair — its record+marker tail must stay, since removing an acked
    /// commit is the one thing recovery may never do.
    pub(crate) fn repair_after_unwind(&mut self) -> UnwindRepair {
        match std::mem::replace(&mut self.in_flight, InFlight::Idle) {
            InFlight::Idle => UnwindRepair::Clean,
            InFlight::Appending { mark } => {
                if self.truncate_to(mark) {
                    UnwindRepair::Clean
                } else {
                    UnwindRepair::Unrepaired
                }
            }
            InFlight::Barriered => UnwindRepair::AfterBarrier,
        }
    }

    /// Durably truncate back to `mark`, answering whether the segment is now
    /// there. Idempotent — the §1 barrier-failure / §3 unwind-guard tail
    /// truncation, retried harmlessly.
    fn truncate_to(&mut self, mark: u64) -> bool {
        let truncate = self.file.set_len(mark).and_then(|()| self.file.sync_data());
        let repaired = truncate.is_ok();
        if repaired {
            self.len = mark;
            self.in_flight = InFlight::Idle;
        }
        repaired
    }

    /// Rotate at a txn boundary if the active segment is over the threshold.
    /// `first_seq` is the incoming txn's first `Seq` — the new segment's name
    /// — so segment names stay lower bounds of their content and successor
    /// names stay sound `lastSeq` inferences for predecessors (§1). Called
    /// BEFORE any of the txn's frames are appended; on failure nothing of the
    /// txn is on disk (the §3 pre-append discipline applies) and the next
    /// attempt re-enters rotation.
    fn maybe_rotate(&mut self, first_seq: u64) -> io::Result<()> {
        if self.len == 0 || self.len < SEGMENT_ROTATE_BYTES {
            return Ok(());
        }
        // Under per-commit Fsync the old segment is already durable (the
        // previous txn's barrier fsynced it) — the §1 rotation discipline.
        *self = Self::create_segment(&self.dir, first_seq)?;
        Ok(())
    }

    fn append(&mut self, buf: &[u8]) -> io::Result<()> {
        self.file.write_all(buf)?;
        self.len += buf.len() as u64;
        Ok(())
    }

    /// The durability barrier: ONE fsync of records+marker (§1).
    fn barrier(&mut self) -> io::Result<()> {
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
    /// [`JournalWriter::commit_txn`]; the in-memory journal appends no bytes
    /// and cannot fail, and installs where the durable one installs — after
    /// a barrier it has no need of.
    pub(crate) fn commit_txn(
        &mut self,
        first_seq: u64,
        records: Vec<Vec<u8>>,
        install: impl FnOnce(),
    ) -> Result<u64, CommitFail> {
        match self {
            Journal::InMemory => {
                install();
                Ok(0)
            }
            Journal::Segments(writer) => writer.commit_txn(first_seq, records, install),
        }
    }

    /// [`JournalWriter::repair_after_unwind`]. The in-memory journal holds
    /// nothing durable, so every unwind through it is a pre-install unwind
    /// with nothing to repair.
    pub(crate) fn repair_after_unwind(&mut self) -> UnwindRepair {
        match self {
            Journal::InMemory => UnwindRepair::Clean,
            Journal::Segments(writer) => writer.repair_after_unwind(),
        }
    }
}

/// How a corrupt run (a span the scan skipped via magic-resync) ended (§7).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RunEnd {
    /// The resync landed on an intact frame. `at` = that next-intact
    /// coordinate — a record landing contributes its `seq`, a marker landing
    /// `last_seq + 1`, since markers carry no `Seq` of their own.
    /// `inferred_max` = the greatest `Seq` the run itself can hold, one below
    /// the coordinate it landed on. The run's own seqs are unreadable, so
    /// these two are all that is known of it (§7).
    Landed { inferred_max: u64, at: u64 },
    /// The run reached end-of-journal with no next intact frame: classes as
    /// the un-acked / torn tail (`> W`), sound because the last committed
    /// marker is itself intact and so precedes any EOF-reaching run (§7).
    Eof,
}

/// Where the un-acked / torn tail begins: the segment file to cut, the offset
/// to cut it at, and the wholly-later segment files to remove (§7). Resolved
/// to paths by the scan itself, while the segment list is in hand, so a
/// truncation cannot be aimed at a list other than the one that was scanned.
pub(crate) struct TailCut {
    segment: PathBuf,
    offset: u64,
    discard: Vec<PathBuf>,
}

/// Pass-1 result (§7): the committed head (§7's `W`), the committed records,
/// the corrupt runs, and where the tail to truncate begins.
pub(crate) struct ScanOutcome {
    /// The base this scan ran against — §7's `S_load`. Every judgment it
    /// answers is relative to that base, so it is carried here rather than
    /// re-supplied per question, where a caller could hand back a different
    /// one than the scan was run with.
    s_load: u64,
    /// The last COMMITTED marker's `last_seq`, floored at `S_load` — §7's `W`
    /// (if no committed marker sits above the loaded checkpoint it is
    /// `S_load` itself and Pass 2 folds nothing).
    pub committed_head: u64,
    /// `(seq, serialized W::Record bytes)` of every record belonging to a
    /// committed transaction, unordered (the caller sorts by `Seq` and filters
    /// to `(S_load, W]`).
    pub committed_records: Vec<(u64, Vec<u8>)>,
    /// Every committed marker's `last_seq`, in scan order — the transaction
    /// boundaries of the scanned region, which [`ScanOutcome::require_boundary`]
    /// answers from.
    committed_boundaries: Vec<u64>,
    /// Corrupt runs in scan order — what [`ScanOutcome::fatal_run_to_head`]
    /// and [`ScanOutcome::fatal_run_anywhere`] answer from. The verdict on a
    /// run belongs to those, not to a caller re-deriving the classifier.
    runs: Vec<RunEnd>,
    /// The tail-truncation cut, `None` when nothing was scanned.
    pub tail: Option<TailCut>,
}

impl ScanOutcome {
    /// The corrupt run a RECOVERY fold cannot answer around, classified within
    /// the committed region this scan derived: a run above the committed head
    /// is the un-acked / torn tail, which recovery is about to discard (§7).
    pub(crate) fn fatal_run_to_head(&self) -> Option<u64> {
        self.fatal_run(Some(self.committed_head))
    }

    /// The corrupt run a BOUNDED READ cannot answer around, at any height. A
    /// read truncates nothing, so a run above the committed head is at-rest
    /// damage rather than a tail — and since a run's own seqs are unreadable,
    /// its reach below `inferred_max` is unknowable, so answering around it
    /// could answer from a hole (§7).
    pub(crate) fn fatal_run_anywhere(&self) -> Option<u64> {
        self.fatal_run(None)
    }

    /// The corrupt run a fold over `(s_load, upto]` cannot answer around: the
    /// `at` payload of the first run whose inferred `Seq` max lands in that
    /// range — durable committed data the folded state needs, and unreadable.
    /// Halt, never drop (§7). `upto = None` is an open ceiling: every run
    /// above the base is fatal, however far above it lands.
    ///
    /// The run is classified by its `inferred_max` and REPORTED by its `at`,
    /// and keeping the two apart is what the boundary case turns on: a run
    /// wholly embodied in the base can still land on the very next coordinate
    /// (`at = s_load + 1`), which is harmless — its content is already in the
    /// base — where classifying by `at` would spuriously halt. An
    /// [`RunEnd::Eof`] run is never fatal: it is the un-acked / torn tail,
    /// which the last committed marker precedes.
    fn fatal_run(&self, upto: Option<u64>) -> Option<u64> {
        self.runs.iter().find_map(|run| match *run {
            RunEnd::Landed { inferred_max, at }
                if inferred_max > self.s_load && upto.is_none_or(|c| inferred_max <= c) =>
            {
                Some(at)
            }
            _ => None,
        })
    }

    /// Whether `at` is one of the committed transaction boundaries this scan
    /// saw — the values [`crate::Kernel::transact`] returns, and the only ones
    /// a bounded fold may answer at. `Err` carries the greatest boundary at or
    /// below `at`, never below the base: the base's own seq is itself a
    /// boundary, and a segment straddling it contributes boundaries below it
    /// that no longer have a base to fold from.
    pub(crate) fn require_boundary(&self, at: u64) -> Result<(), u64> {
        if self.committed_boundaries.contains(&at) {
            return Ok(());
        }
        Err(self
            .committed_boundaries
            .iter()
            .copied()
            .filter(|&b| b < at)
            .max()
            .map_or(self.s_load, |m| m.max(self.s_load)))
    }
}

/// The record frames of the ONE transaction a scan currently has open,
/// accumulated as they arrive (§1/§7).
///
/// A scan holds one of these at a time. That is the writer's own shape:
/// [`encode_txn`] emits a transaction's records contiguously and closes them
/// with its marker, so a group left open by an intervening transaction's
/// record can never be closed by a later marker — and holding one group is
/// what bounds a scan's own memory to a transaction rather than to the whole
/// scanned region.
struct PendingTxn {
    txn: Txn,
    /// CRC32C over the record-frame payloads in ARRIVAL order — which is `Seq`
    /// order for anything this writer produced. Streaming it is what lets the
    /// group carry one copy of each record instead of a second copy kept only
    /// to checksum later.
    checksum: u32,
    last_seq: Option<u64>,
    /// Cleared by a record that does not exceed its predecessor. That is a
    /// transaction this writer cannot emit, and it is the shape that would
    /// have a non-idempotent [`crate::WorldState::apply`] fold one coordinate
    /// twice, so such a transaction never commits however its checksum lands.
    ordered: bool,
    /// `(seq, serialized W::Record bytes)`, in arrival order.
    records: Vec<(u64, Vec<u8>)>,
}

impl PendingTxn {
    fn open(txn: Txn) -> PendingTxn {
        PendingTxn {
            txn,
            checksum: 0,
            last_seq: None,
            ordered: true,
            records: Vec::new(),
        }
    }

    /// Take one record frame of this transaction: `payload` is the frame
    /// payload exactly as framed, which is what `records_checksum` covers.
    fn push(&mut self, record: LogRecord, payload: &[u8]) {
        if self.last_seq.is_some_and(|prev| record.seq <= prev) {
            self.ordered = false;
        }
        self.last_seq = Some(record.seq);
        self.checksum = crc32c::crc32c_append(self.checksum, payload);
        self.records.push((record.seq, record.bytes));
    }

    /// Whether `marker` commits this group: intact + durable (it is on the
    /// disk we read) + `records_checksum`-valid over a `Seq`-ascending run
    /// (§1).
    fn commits(&self, marker: &Marker) -> bool {
        self.ordered && self.checksum == marker.records_checksum
    }
}

/// Pass 1 (§7): scan in file order (== `Seq` order — in-order append plus the
/// prior recovery's tail truncation), resynchronizing past bad frames via the
/// magic word (accepting only intact frames — a coincidental magic inside a
/// payload fails the CRC check and the scan continues), grouping record
/// frames by `txn` — NOT file position — to validate each marker's
/// `records_checksum`, and deriving `W`.
///
/// A transaction commits only if its records arrive `Seq`-ascending as well
/// as checksum-valid ([`PendingTxn`]), so no journal can present one
/// coordinate twice inside a transaction and have it folded twice.
///
/// Closed segments whose inferred `lastSeq` (successor's `firstSeq` − 1, a
/// conservative upper bound under TolerateGap burns) is `≤ s_load` are
/// skipped without opening them; the active (final) segment is always scanned
/// (§1/§7). A corrupt run persists across a segment boundary: the journal is
/// one logical `Seq`-ordered stream.
///
/// Memory: one segment's bytes, one transaction's records, and the committed
/// records of the whole scanned region — the last of which is the term that
/// grows with the journal, and is what a caller bounds by checkpointing.
pub(crate) fn scan(segs: &[SegmentMeta], s_load: u64) -> io::Result<ScanOutcome> {
    let mut out = ScanOutcome {
        s_load,
        committed_head: s_load,
        committed_records: Vec::new(),
        committed_boundaries: Vec::new(),
        runs: Vec::new(),
        tail: None,
    };
    let mut cut: Option<(usize, u64)> = None;
    let mut first_scanned: Option<usize> = None;
    let mut pending: Option<PendingTxn> = None;
    let mut run_open = false;
    for (i, seg) in segs.iter().enumerate() {
        if inferred_last_seq(segs, i).is_some_and(|last| last <= s_load) {
            continue;
        }
        if first_scanned.is_none() {
            first_scanned = Some(i);
        }
        let buf = fs::read(&seg.path)?;
        let mut pos = 0usize;
        while pos < buf.len() {
            match parse_frame(&buf, pos) {
                Parsed::Intact { payload, end } => {
                    match bincode::deserialize::<FramePayload>(&buf[payload.clone()]) {
                        Ok(FramePayload::Record(r)) => {
                            if run_open {
                                out.runs.push(RunEnd::Landed {
                                    inferred_max: r.seq.saturating_sub(1),
                                    at: r.seq,
                                });
                                run_open = false;
                            }
                            let mut group = pending
                                .take()
                                .filter(|g| g.txn == r.txn)
                                .unwrap_or_else(|| PendingTxn::open(r.txn));
                            group.push(r, &buf[payload]);
                            pending = Some(group);
                            pos = end;
                        }
                        Ok(FramePayload::Marker(m)) => {
                            if run_open {
                                out.runs.push(RunEnd::Landed {
                                    inferred_max: m.last_seq,
                                    // A marker carries no `Seq` of its own, so
                                    // the coordinate it contributes is one past
                                    // its own. At the ceiling there is no such
                                    // coordinate, and the run is reported at the
                                    // ceiling itself.
                                    at: m.last_seq.saturating_add(1),
                                });
                                run_open = false;
                            }
                            if let Some(group) = pending.take_if(|g| g.txn == m.txn) {
                                if group.commits(&m) {
                                    out.committed_head = out.committed_head.max(m.last_seq);
                                    cut = Some((i, end as u64));
                                    out.committed_boundaries.push(m.last_seq);
                                    out.committed_records.extend(group.records);
                                }
                                // else: torn txn — not committed; its frames are
                                // either beyond W (tail, truncated) or explained
                                // by a corrupt run the caller classifies (§7).
                            }
                            pos = end;
                        }
                        // Intact by CRC but undecodable: writer/reader skew.
                        // Treat as a corrupt frame — it participates in run
                        // classification rather than being silently dropped.
                        Err(_) => {
                            run_open = true;
                            pos = end;
                        }
                    }
                }
                Parsed::Bad => {
                    run_open = true;
                    pos = match find_magic(&buf, pos + 1) {
                        Some(p) => p,
                        None => buf.len(),
                    };
                }
            }
        }
    }
    if run_open {
        out.runs.push(RunEnd::Eof);
    }
    // Everything past the last committed marker is tail. When the scanned
    // region holds no committed marker at all, everything scanned is tail:
    // the first scanned segment is cut at offset 0. Harmless corrupt runs
    // (inferred max ≤ `s_load`) sit below the cut and are not touched.
    out.tail = cut
        .or_else(|| first_scanned.map(|first| (first, 0)))
        .map(|(i, offset)| TailCut {
            segment: segs[i].path.clone(),
            offset,
            discard: segs[i + 1..].iter().map(|s| s.path.clone()).collect(),
        });
    Ok(out)
}

/// The tail-truncation step (§7), run between Pass 1 and Pass 2 — only on a
/// clean classification (never on the Corruption/BadCheckpoint halt paths):
/// durably remove everything after the last committed marker — cut its
/// segment at the marker's frame end, delete every wholly-later segment,
/// fsync file and directory — BEFORE any write is served. This is what makes
/// cross-session `Txn` uniqueness and file-order == `Seq`-order true at the
/// next recovery (§1/§7). Idempotent; a failure fails `open()` with `Io`.
///
/// The files are the scan's own [`TailCut`], so this cuts exactly what was
/// scanned and nothing else.
pub(crate) fn truncate_tail(dir: &Path, scan: &ScanOutcome) -> io::Result<()> {
    let Some(tail) = &scan.tail else {
        return Ok(());
    };
    let f = OpenOptions::new().write(true).open(&tail.segment)?;
    f.set_len(tail.offset)?;
    f.sync_data()?;
    for path in &tail.discard {
        fs::remove_file(path)?;
    }
    fsync_dir(dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// A record's bytes as the commit path produces them, so a fixture cannot
    /// drift from the wire form the real writer uses.
    fn rec(x: u64) -> Vec<u8> {
        encode_record(&x).unwrap()
    }

    /// A fixture commit. These journals stand alone — there is no root to
    /// install into — so the install step is empty.
    fn write_txn(writer: &mut JournalWriter, first: u64, records: Vec<Vec<u8>>) {
        assert!(writer.commit_txn(first, records, || {}).is_ok(), "fixture commit");
    }

    /// Frame spans of a CLEAN journal file, via the real parser.
    fn frame_spans(path: &Path) -> Vec<(usize, usize)> {
        let buf = fs::read(path).unwrap();
        let mut v = Vec::new();
        let mut pos = 0;
        while pos < buf.len() {
            match parse_frame(&buf, pos) {
                Parsed::Intact { end, .. } => {
                    v.push((pos, end - pos));
                    pos = end;
                }
                Parsed::Bad => panic!("clean journal expected"),
            }
        }
        v
    }

    fn flip_byte(path: &Path, off: usize) {
        let mut data = fs::read(path).unwrap();
        data[off] ^= 0xFF;
        fs::write(path, data).unwrap();
    }

    fn committed_seqs(out: &ScanOutcome) -> Vec<u64> {
        let mut s: Vec<u64> = out.committed_records.iter().map(|r| r.0).collect();
        s.sort_unstable();
        s
    }

    /// The scan aims truncation at `segment` @ `offset`, with nothing later to
    /// discard (these fixtures hold one segment).
    fn assert_tail(out: &ScanOutcome, segment: &Path, offset: u64) {
        let tail = out.tail.as_ref().expect("a scanned region has a cut");
        assert_eq!(tail.segment, segment);
        assert_eq!(tail.offset, offset);
        assert!(tail.discard.is_empty());
    }

    #[test]
    fn frame_roundtrip_and_crc_covers_len() {
        let payload = b"hello frame".to_vec();
        let mut buf = Vec::new();
        push_frame(&mut buf, &payload).unwrap();
        match parse_frame(&buf, 0) {
            Parsed::Intact { payload: p, end } => {
                assert_eq!(&buf[p], payload.as_slice());
                assert_eq!(end, buf.len());
            }
            Parsed::Bad => panic!("intact frame expected"),
        }
        // A flipped payload byte fails the frame crc.
        let mut bad = buf.clone();
        bad[FRAME_HEADER_LEN + 2] ^= 0xFF;
        assert!(matches!(parse_frame(&bad, 0), Parsed::Bad));
        // A corrupt len is DETECTED (crc covers len), not silently
        // mis-delimiting the following frame (§1).
        let mut badlen = buf;
        badlen[5] ^= 0xFF;
        assert!(matches!(parse_frame(&badlen, 0), Parsed::Bad));
    }

    #[test]
    fn push_frame_refuses_a_payload_past_the_frame_cap() {
        // The writer's half of the cap the reader relies on: a claimed `len`
        // above MAX_FRAME_LEN is corrupt precisely because nothing here can
        // write one (§1).
        let mut buf = Vec::new();
        let over = vec![0u8; MAX_FRAME_LEN as usize + 1];
        let e = push_frame(&mut buf, &over).expect_err("an oversize payload is refused");
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        assert!(buf.is_empty(), "a refused frame appends nothing");
        // And the cap itself is writable, so the refusal is the boundary and
        // not a fence one short of it.
        push_frame(&mut buf, &over[..MAX_FRAME_LEN as usize]).unwrap();
        assert!(matches!(parse_frame(&buf, 0), Parsed::Intact { .. }));
    }

    #[test]
    fn a_txn_repeating_a_seq_never_commits() {
        // Two record frames at ONE `Seq`, under a marker whose checksum covers
        // both: a transaction this writer cannot emit, and the shape that
        // would have a non-idempotent fold apply one coordinate twice. The
        // scan refuses it outright, so nothing downstream has to notice.
        let mut buf = Vec::new();
        let mut checksum = 0u32;
        for bytes in [vec![1u8], vec![2u8]] {
            let payload = bincode::serialize(&FramePayload::Record(LogRecord {
                seq: 2,
                txn: Txn(2),
                bytes,
            }))
            .unwrap();
            checksum = crc32c::crc32c_append(checksum, &payload);
            push_frame(&mut buf, &payload).unwrap();
        }
        let payload = bincode::serialize(&FramePayload::Marker(Marker {
            txn: Txn(2),
            last_seq: 2,
            records_checksum: checksum,
        }))
        .unwrap();
        push_frame(&mut buf, &payload).unwrap();

        let dir = tempdir().unwrap();
        fs::write(segment_path(dir.path(), 2), &buf).unwrap();
        let segs = list_segments(dir.path()).unwrap();
        let out = scan(&segs, 1).unwrap();
        assert_eq!(out.committed_head, 1, "the repeat must not commit");
        assert!(out.committed_records.is_empty());
        assert!(out.committed_boundaries.is_empty());
    }

    #[test]
    fn a_marker_at_the_seq_ceiling_classifies_without_wrapping() {
        // A marker contributes the coordinate one past its own `last_seq`. At
        // the ceiling there is no such coordinate, and the run is reported at
        // the ceiling — never wrapped to 0, which would report a run above the
        // base as one below it (§7).
        let mut buf = vec![0xABu8; 8]; // no magic: a corrupt run opens here
        let payload = bincode::serialize(&FramePayload::Marker(Marker {
            txn: Txn(u64::MAX),
            last_seq: u64::MAX,
            records_checksum: 0,
        }))
        .unwrap();
        push_frame(&mut buf, &payload).unwrap();

        let dir = tempdir().unwrap();
        fs::write(segment_path(dir.path(), 1), &buf).unwrap();
        let segs = list_segments(dir.path()).unwrap();
        let out = scan(&segs, 0).unwrap();
        assert_eq!(
            out.runs,
            vec![RunEnd::Landed {
                inferred_max: u64::MAX,
                at: u64::MAX
            }]
        );
    }

    #[test]
    fn frame_payload_layout_spends_a_bare_u64_on_the_txn() {
        // The on-disk payload layout (§1), spelled out: bincode fixint LE —
        // the variant index as a `u32`, then the fields in declaration order,
        // with a [`Txn`] occupying exactly the `u64` it wraps. A journal
        // written by one build is read by the next, so the layout is pinned
        // here rather than left to whatever the derives happen to produce.
        let buf = encode_txn(2, vec![vec![9u8, 8, 7]]).unwrap();

        let mut expect_record = Vec::new();
        expect_record.extend_from_slice(&0u32.to_le_bytes()); // FramePayload::Record
        expect_record.extend_from_slice(&2u64.to_le_bytes()); // seq
        expect_record.extend_from_slice(&2u64.to_le_bytes()); // txn == the first seq
        expect_record.extend_from_slice(&3u64.to_le_bytes()); // bytes.len()
        expect_record.extend_from_slice(&[9, 8, 7]);
        let Parsed::Intact { payload, end } = parse_frame(&buf, 0) else {
            panic!("intact record frame expected")
        };
        assert_eq!(&buf[payload], expect_record.as_slice());

        let mut expect_marker = Vec::new();
        expect_marker.extend_from_slice(&1u32.to_le_bytes()); // FramePayload::Marker
        expect_marker.extend_from_slice(&2u64.to_le_bytes()); // txn
        expect_marker.extend_from_slice(&2u64.to_le_bytes()); // last_seq
        // records_checksum: over the record frames' payloads, in Seq order.
        expect_marker
            .extend_from_slice(&crc32c::crc32c_append(0, &expect_record).to_le_bytes());
        let Parsed::Intact { payload, .. } = parse_frame(&buf, end) else {
            panic!("intact marker frame expected")
        };
        assert_eq!(&buf[payload], expect_marker.as_slice());
    }

    #[test]
    fn an_installed_commit_leaves_nothing_in_flight() {
        // The install happens inside the commit, so an installed transaction
        // is behind the writer by the time it returns: a later unwind finds
        // nothing of it to repair, and the next transaction starts clean (§3).
        let dir = tempdir().unwrap();
        let mut writer = JournalWriter::open_active(dir.path(), 1).unwrap();
        let mut installed = false;
        assert!(writer.commit_txn(1, vec![rec(10)], || installed = true).is_ok());
        assert!(installed, "the commit installs before it returns");
        assert!(matches!(writer.repair_after_unwind(), UnwindRepair::Clean));
    }

    #[test]
    fn an_unwind_through_the_install_is_beyond_repair() {
        // The one window the writer cannot repair: durably committed, with
        // the install unaccounted for. Its record+marker tail stays —
        // removing an acked commit is what recovery may never do (§3).
        let dir = tempdir().unwrap();
        let mut writer = JournalWriter::open_active(dir.path(), 1).unwrap();
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = writer.commit_txn(1, vec![rec(10)], || panic!("install unwinds"));
        }));
        assert!(unwound.is_err(), "the panic reaches the caller");
        assert!(matches!(writer.repair_after_unwind(), UnwindRepair::AfterBarrier));
        let segs = list_segments(dir.path()).unwrap();
        assert_eq!(scan(&segs, 0).unwrap().committed_head, 1);
    }

    #[test]
    fn scan_groups_by_txn_and_derives_the_committed_head() {
        let dir = tempdir().unwrap();
        let mut writer = JournalWriter::open_active(dir.path(), 1).unwrap();
        write_txn(&mut writer, 1, vec![rec(10)]);
        write_txn(&mut writer, 2, vec![rec(20), rec(21)]); // seqs 2, 3
        let segs = list_segments(dir.path()).unwrap();
        let out = scan(&segs, 0).unwrap();
        assert_eq!(out.committed_head, 3);
        assert!(out.runs.is_empty());
        assert_eq!(committed_seqs(&out), vec![1, 2, 3]);
        // Naming seg-1 as the cut file is also what proves it was scanned
        // rather than skipped.
        let file_len = fs::metadata(&segs[0].path).unwrap().len();
        assert_tail(&out, &segs[0].path, file_len);
    }

    #[test]
    fn scan_tolerates_burned_seq_gaps() {
        // §7: the replayed range needs NO Seq-contiguity — a TolerateGap burn
        // folds harmlessly; a missing Seq is never corruption.
        let dir = tempdir().unwrap();
        let mut writer = JournalWriter::open_active(dir.path(), 1).unwrap();
        write_txn(&mut writer, 1, vec![rec(10)]);
        write_txn(&mut writer, 5, vec![rec(50), rec(60)]); // burned 2..=4
        let segs = list_segments(dir.path()).unwrap();
        let out = scan(&segs, 0).unwrap();
        assert_eq!(out.committed_head, 6);
        assert!(out.runs.is_empty());
        assert_eq!(committed_seqs(&out), vec![1, 5, 6]);
    }

    #[test]
    fn corrupt_record_classifies_by_marker_landing() {
        // T1 = seq 1, T2 = seq 2, T3 = seq 3; corrupt T2's record frame. The
        // resync lands on T2's marker — a marker landing: at = last_seq + 1,
        // inferred max = last_seq (markers carry no Seq of their own; §7).
        let dir = tempdir().unwrap();
        let mut writer = JournalWriter::open_active(dir.path(), 1).unwrap();
        write_txn(&mut writer, 1, vec![rec(10)]);
        write_txn(&mut writer, 2, vec![rec(20)]);
        write_txn(&mut writer, 3, vec![rec(30)]);
        let segs = list_segments(dir.path()).unwrap();
        let spans = frame_spans(&segs[0].path);
        // Frames: 0=T1 rec, 1=T1 marker, 2=T2 rec, 3=T2 marker, 4=T3 rec, 5=T3 marker.
        flip_byte(&segs[0].path, spans[2].0 + FRAME_HEADER_LEN + 1);
        let out = scan(&segs, 0).unwrap();
        assert_eq!(
            out.runs,
            vec![RunEnd::Landed {
                inferred_max: 2,
                at: 3
            }]
        );
        // T2's marker no longer validates its records_checksum → uncommitted;
        // W is still bounded by the last committed marker (T3's).
        assert_eq!(out.committed_head, 3);
        assert_eq!(committed_seqs(&out), vec![1, 3]);
    }

    #[test]
    fn corrupt_marker_lands_on_next_record() {
        // T2 = seqs 2..=3; corrupt T2's MARKER. The resync lands on T3's first
        // record (seq 4) — a record landing: at = seq, inferred max = seq − 1.
        let dir = tempdir().unwrap();
        let mut writer = JournalWriter::open_active(dir.path(), 1).unwrap();
        write_txn(&mut writer, 1, vec![rec(10)]);
        write_txn(&mut writer, 2, vec![rec(20), rec(21)]);
        write_txn(&mut writer, 4, vec![rec(40)]);
        let segs = list_segments(dir.path()).unwrap();
        let spans = frame_spans(&segs[0].path);
        // Frames: 0=T1 rec, 1=T1 marker, 2..=3=T2 recs, 4=T2 marker, 5=T3 rec, 6=T3 marker.
        flip_byte(&segs[0].path, spans[4].0 + FRAME_HEADER_LEN + 1);
        let out = scan(&segs, 0).unwrap();
        assert_eq!(
            out.runs,
            vec![RunEnd::Landed {
                inferred_max: 3,
                at: 4
            }]
        );
        assert_eq!(out.committed_head, 4);
        assert_eq!(committed_seqs(&out), vec![1, 4]);
    }

    #[test]
    fn resync_rejects_coincidental_magic_inside_payload() {
        // A record whose bytes contain the magic word; corrupt its frame. The
        // resync must reject the embedded magic (its crc check fails) and land
        // on the real next frame — T1's marker (§1/§7).
        let dir = tempdir().unwrap();
        let mut writer = JournalWriter::open_active(dir.path(), 1).unwrap();
        let mut evil = Vec::new();
        evil.extend_from_slice(b"xx");
        evil.extend_from_slice(&MAGIC);
        evil.extend_from_slice(b"yyyyyyyy");
        write_txn(&mut writer, 1, vec![evil]);
        write_txn(&mut writer, 2, vec![rec(20)]);
        let segs = list_segments(dir.path()).unwrap();
        let spans = frame_spans(&segs[0].path);
        flip_byte(&segs[0].path, spans[0].0 + FRAME_HEADER_LEN + 1);
        let out = scan(&segs, 0).unwrap();
        assert_eq!(
            out.runs,
            vec![RunEnd::Landed {
                inferred_max: 1,
                at: 2
            }]
        );
        assert_eq!(out.committed_head, 2);
        assert_eq!(committed_seqs(&out), vec![2]);
    }

    #[test]
    fn torn_tail_reaches_eof() {
        let dir = tempdir().unwrap();
        let mut writer = JournalWriter::open_active(dir.path(), 1).unwrap();
        write_txn(&mut writer, 1, vec![rec(10)]);
        write_txn(&mut writer, 2, vec![rec(20)]);
        // Crash mid-append: a partial header at the tail.
        writer.append(&[0xAB, 0xCD, 0xEF]).unwrap();
        let segs = list_segments(dir.path()).unwrap();
        let out = scan(&segs, 0).unwrap();
        assert_eq!(out.runs, vec![RunEnd::Eof]);
        assert_eq!(out.committed_head, 2);
        assert_eq!(committed_seqs(&out), vec![1, 2]);
        // The cut sits at the last committed marker's frame end.
        let prefix_end = intact_prefix_end(&segs[0].path);
        assert_tail(&out, &segs[0].path, prefix_end);
    }

    #[test]
    fn the_cut_names_the_segment_holding_the_last_committed_marker() {
        // A rotation, then a crash leaving the NEW segment's transaction
        // torn: the cut aims at the older segment's marker end, and the whole
        // younger segment is tail to discard (§7).
        let dir = tempdir().unwrap();
        let mut writer = JournalWriter::open_active(dir.path(), 1).unwrap();
        write_txn(&mut writer, 1, vec![vec![7u8; SEGMENT_ROTATE_BYTES as usize]]); // fills seg-1
        write_txn(&mut writer, 2, vec![rec(20)]); // rotates into seg-2
        let segs = list_segments(dir.path()).unwrap();
        assert_eq!(segs.len(), 2, "the fixture rotates");
        // Tear seg-2's marker: its txn is no longer committed.
        let spans = frame_spans(&segs[1].path);
        flip_byte(&segs[1].path, spans[1].0 + FRAME_HEADER_LEN + 1);
        let out = scan(&segs, 0).unwrap();
        assert_eq!(out.committed_head, 1);
        let tail = out.tail.as_ref().expect("a scanned region has a cut");
        assert_eq!(tail.segment, segs[0].path);
        assert_eq!(tail.offset, fs::metadata(&segs[0].path).unwrap().len());
        assert_eq!(tail.discard, vec![segs[1].path.clone()]);
    }

    #[test]
    fn require_boundary_answers_from_the_committed_markers() {
        let dir = tempdir().unwrap();
        let mut writer = JournalWriter::open_active(dir.path(), 1).unwrap();
        write_txn(&mut writer, 1, vec![rec(10)]);
        write_txn(&mut writer, 2, vec![rec(20), rec(21)]); // a composite: boundary 3
        write_txn(&mut writer, 4, vec![rec(40)]);
        let segs = list_segments(dir.path()).unwrap();

        let out = scan(&segs, 0).unwrap();
        assert_eq!(out.require_boundary(3), Ok(()));
        // A composite's interior Seq was never a boundary (§3).
        assert_eq!(out.require_boundary(2), Err(1));

        // The active segment is always scanned, so it reports boundaries
        // below a base too — but those have no base left to fold from, and
        // the nearest ANSWERABLE boundary is the base's own seq.
        let out = scan(&segs, 3).unwrap();
        assert_eq!(out.require_boundary(4), Ok(()));
        assert_eq!(out.require_boundary(2), Err(3));
    }

    /// Byte offset just past the last INTACT frame (walks until a bad frame).
    fn intact_prefix_end(path: &Path) -> u64 {
        let buf = fs::read(path).unwrap();
        let mut pos = 0;
        loop {
            match parse_frame(&buf, pos) {
                Parsed::Intact { end, .. } => pos = end,
                Parsed::Bad => return pos as u64,
            }
        }
    }
}
