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
/// Sanity bound on a single frame — the journal's FRAME CAP (open build
/// decision: max frame size), which is what every mention of the frame cap
/// here names. The writer enforces it, so recovery may treat a larger claimed
/// `len` as corrupt.
pub(crate) const MAX_FRAME_LEN: u32 = 64 * 1024 * 1024;
/// The most bytes one TRANSACTION may occupy in the journal — its record
/// frames, commit marker and headers together. A transaction past it is
/// REFUSED with [`crate::TxnError::OverBudget`], in both durability modes,
/// before anything is appended or installed, so this is the figure a caller
/// splitting an over-budget transaction must get under.
///
/// Equal to the journal's FRAME CAP as a RELATIONSHIP, not a free
/// knob: a transaction is at most one frame's worth, so a segment — which
/// rotates only at a transaction boundary — is at most one rotation
/// threshold plus one frame, and recovery, which reads a segment WHOLE, has
/// a memory floor that is bounded and IDENTICAL ON EVERY REPLICA. Untie the
/// two and the second clause fails where it hurts: a transaction never spans
/// a segment, so one oversized transaction permanently raises the floor of
/// every later [`crate::Kernel::open`] and every [`crate::Kernel::world_at`]
/// above that base — a store that opens on the machine that wrote it and not
/// on the replica.
pub const MAX_TXN_BYTES: u64 = MAX_FRAME_LEN as u64;
/// Rotation threshold (open build decision), tested BEFORE a transaction is
/// appended and only at a txn boundary — so a closed segment holds this many
/// bytes plus one whole transaction, and a caller bounding memory or file size
/// reckons with that transaction rather than with this figure. Rotating at txn
/// boundaries only is what keeps a txn's frames from spanning a segment; under
/// per-commit Fsync the old segment is already durable at rotation (its last
/// txn's barrier fsynced it), preserving marker-as-ack across the boundary
/// (§1).
const SEGMENT_ROTATE_BYTES: u64 = 1024 * 1024;
/// Resynchronization budget, as a multiple of a segment's own size: how many
/// bytes of CRC a scan will spend on rejected frame candidates before it gives
/// up on enumerating that segment's frame stream (§7). A WORK allowance on
/// the read path — the one budget here that is not the write path's
/// [`MAX_TXN_BYTES`], which is why the frame cap is named in full wherever it
/// appears below.
///
/// The sequential walk needs no budget — an intact frame's CRC covers exactly
/// the bytes it advances over, so the walk sums to one pass — and this bounds
/// the other work. A candidate the resync lands on charges the payload length
/// it CLAIMS, which its advance does not bound: the resync moves four bytes
/// and the claim may reach [`MAX_FRAME_LEN`], so without a budget a record
/// whose own bytes plant frame headers makes the scan quadratic in a size that
/// record's author chose.
///
/// The figure: a whole scan then costs at most this many passes over a
/// segment, plus one candidate in flight, so the worst crafted 64 MiB segment
/// spends 512 MiB of CRC — a twentieth of a second at hardware rates. Honest
/// journals spend almost none of it, because a candidate must clear the magic
/// word AND a length inside the frame cap before its CRC is computed at all:
/// the sync word occurs by chance about once per 2^32 bytes, and a randomly
/// damaged length field lands inside the frame cap about once in 64, so
/// tripping eight segment-sized candidates by accident is a ~10^-15 event.
/// Crafted content trips it after a few dozen.
const RESYNC_BUDGET_PASSES: u64 = 8;

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

/// A decode refusal as the `io::Error` it is: bytes read off a disk that do
/// not hold what their format says, which is exactly what
/// [`io::ErrorKind::InvalidData`] names. Only the read side wraps — an encode
/// touches no file, so its refusal travels as the serializer's own error.
fn invalid_data(e: bincode::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

/// One `W::Record`'s wire form — the `bytes` a [`LogRecord`] frame carries.
///
/// Stated as a pair with [`decode_record`], here, because the encode and the
/// decode are one agreement: a change to either that the other does not match
/// turns every healthy journal into one that cannot be replayed. M2 never
/// inspects a record, so the serializer's own account is the whole of what
/// identifies a refusal, and it travels unwrapped: the encode precedes every
/// file operation, so nothing it can answer with is a disk's failure.
pub(crate) fn encode_record<R: Serialize>(record: &R) -> Result<Vec<u8>, bincode::Error> {
    bincode::serialize(record)
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
/// fsync (§1/§3). The bytes are consumed into their frames: the caller has no
/// use for them past this call, and a commit is no place to copy every record
/// a second time.
///
/// The `Seq` arithmetic here stays in range because the coordinates were
/// already minted: [`crate::Kernel::transact`] draws the whole range
/// `first_seq..=first_seq + (n - 1)` from the kernel's sequencer — the one
/// mint site — through a checked add before any of it reaches this function
/// (§2). The parenthesisation is load-bearing at the ceiling:
/// `first_seq + (n - 1)` computes no intermediate above the last coordinate
/// the range legitimately holds.
fn encode_txn(first_seq: u64, record_bytes: Vec<Vec<u8>>) -> io::Result<Vec<u8>> {
    let n = record_bytes.len() as u64;
    assert!(n > 0, "zero-step ops never reach the journal");
    let txn = Txn(first_seq);
    // The exact figure, not a guess: [`txn_encoded_len`] is what this function
    // emits, pinned to it by the accounting test. Reserving it is what holds
    // the commit region to the two copies of a transaction's bytes its own
    // contract budgets for — a doubling `Vec` transiently holds a third.
    let mut buf = Vec::with_capacity(txn_encoded_len(&record_bytes) as usize);
    let mut checksum = 0u32;
    for (i, bytes) in record_bytes.into_iter().enumerate() {
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

/// What [`encode_txn`] wraps around one record's own bytes inside its frame
/// payload: the [`FramePayload`] variant tag (4), `seq` (8), `txn` (8) and
/// the byte-vector's length prefix (8) — bincode's fixed-width encoding,
/// value-independent. A constant so [`Journal::commit_txn`] can charge a
/// record without building its frame; the accounting test pins it to the
/// encoder's own output, so a codec change breaks the gate rather than
/// silently loosening either limit it feeds.
pub(crate) const RECORD_PAYLOAD_OVERHEAD: u64 = 28;
/// The marker frame's whole encoded size: header (12) plus the tagged
/// [`Marker`] payload — tag (4), `txn` (8), `last_seq` (8),
/// `records_checksum` (4). Pinned alongside [`RECORD_PAYLOAD_OVERHEAD`].
const MARKER_FRAME_LEN: u64 = FRAME_HEADER_LEN as u64 + 24;

/// What one already-encoded record occupies in the journal: its frame header
/// plus the payload [`encode_txn`] wraps around it. The ONE spelling of a
/// record's cost on the WRITE side, so the running charge in
/// [`Journal::commit_txn`] and the reservation [`encode_txn`] takes from
/// [`txn_encoded_len`] cannot disagree about what is being built.
///
/// A reader has the framed payload rather than the record's own bytes, so
/// [`PendingTxn`] reaches the same figure by the other route — header plus
/// framed payload — and the accounting test pins the two equal.
const fn record_frame_len(payload_bytes: usize) -> u64 {
    (FRAME_HEADER_LEN as u64 + RECORD_PAYLOAD_OVERHEAD).saturating_add(payload_bytes as u64)
}

/// The exact byte length [`encode_txn`] emits for these already-encoded
/// records: each record frame ([`record_frame_len`]) plus the terminal marker
/// frame. Saturating, so a sum no allocator could hold refuses as over-budget
/// rather than wrapping back under the budget.
pub(crate) fn txn_encoded_len(record_bytes: &[Vec<u8>]) -> u64 {
    record_bytes.iter().fold(MARKER_FRAME_LEN, |total, bytes| {
        total.saturating_add(record_frame_len(bytes.len()))
    })
}

#[derive(Debug)]
enum Parsed {
    /// The frame at `pos` is intact: its own `crc` validates over `len`+payload.
    /// The frame ends where its payload does, at `payload.end` — one fact, so
    /// the two cannot disagree and mis-delimit the frame that follows.
    Intact { payload: Range<usize> },
    /// Not a trustworthy frame start (bad magic, oversize/overrunning `len`,
    /// or CRC mismatch) — resynchronize via the magic word (§1/§7).
    ///
    /// `crc_bytes` is what rejecting this candidate cost: the payload length
    /// it claimed, when the CRC was computed and mismatched, and `0` for the
    /// rejections that precede the CRC. The scan charges it against
    /// [`RESYNC_BUDGET_PASSES`], which is why the accounting lives on the one
    /// function that knows the cost rather than on a second header parse.
    Bad { crc_bytes: u64 },
}

fn parse_frame(buf: &[u8], pos: usize) -> Parsed {
    // The rejections above the CRC cost nothing to reach, so they charge
    // nothing: a candidate is free until its claimed payload is read.
    if pos + FRAME_HEADER_LEN > buf.len() || buf[pos..pos + 4] != MAGIC {
        return Parsed::Bad { crc_bytes: 0 };
    }
    let len = u32::from_le_bytes(buf[pos + 4..pos + 8].try_into().unwrap());
    let crc = u32::from_le_bytes(buf[pos + 8..pos + 12].try_into().unwrap());
    if len > MAX_FRAME_LEN {
        return Parsed::Bad { crc_bytes: 0 };
    }
    let end = pos + FRAME_HEADER_LEN + len as usize;
    if end > buf.len() {
        return Parsed::Bad { crc_bytes: 0 };
    }
    let computed = crc32c::crc32c_append(
        crc32c::crc32c(&buf[pos + 4..pos + 8]),
        &buf[pos + FRAME_HEADER_LEN..end],
    );
    if computed != crc {
        return Parsed::Bad {
            crc_bytes: len as u64,
        };
    }
    Parsed::Intact {
        payload: pos + FRAME_HEADER_LEN..end,
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

/// A journal segment file, named by its `firstSeq` (§1). Every operation over
/// a slice of these reads a neighbour's name as this segment's bound, so the
/// slice must be ascending by `first_seq` as [`list_segments`] produces it.
///
/// Both fields are read only by the operations here that own segment names —
/// [`inferred_last_seq`], [`reaches_genesis`], [`reclaim_below`] and
/// [`scan`] — because a `firstSeq` read outside them is a coverage inference
/// made away from the naming rule it rests on, and [`reclaim_below`] deletes
/// files on that inference. A slice of these travels; the names inside do not.
pub(crate) struct SegmentMeta {
    first_seq: u64,
    path: PathBuf,
}

/// The one file name a segment beginning at `first_seq` has:
/// `seg-<firstSeq>.wal` (§1).
///
/// Stated as a pair with [`parse_segment_name`], which reads it back by
/// re-emitting it, because the format and the parse are one agreement: a
/// change to either that the other does not match makes every segment on disk
/// invisible to recovery, which reads as an empty store rather than as a
/// failure.
fn segment_name(first_seq: u64) -> String {
    format!("seg-{first_seq}.wal")
}

/// Where a segment beginning at `first_seq` lives (§1).
pub(crate) fn segment_path(dir: &Path, first_seq: u64) -> PathBuf {
    dir.join(segment_name(first_seq))
}

/// Read back the `firstSeq` [`segment_name`] wrote — and ONLY the spelling it
/// writes. `u64::from_str` accepts a leading `+` and any number of leading
/// zeros, so the round trip is what keeps `seg-01.wal` from claiming a live
/// segment's `firstSeq`: two entries at one coordinate make
/// [`inferred_last_seq`] answer `0` for the first of them, and
/// [`reclaim_below`] deletes on that inference. `None` for any other name — a
/// checkpoint, the lock file, or something foreign.
fn parse_segment_name(name: &str) -> Option<u64> {
    let first_seq: u64 = name.strip_prefix("seg-")?.strip_suffix(".wal")?.parse().ok()?;
    (name == segment_name(first_seq)).then_some(first_seq)
}

/// All segments in `dir`, ascending by `firstSeq`. Non-segment files
/// (checkpoints, the lock file) fail the name parse and are skipped.
pub(crate) fn list_segments(dir: &Path) -> io::Result<Vec<SegmentMeta>> {
    let mut segs = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(first_seq) = name.to_str().and_then(parse_segment_name) else {
            continue;
        };
        segs.push(SegmentMeta {
            first_seq,
            path: entry.path(),
        });
    }
    segs.sort_by_key(|seg| seg.first_seq);
    Ok(segs)
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
    segs.first().is_none_or(|seg| seg.first_seq == 1)
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
    Unencodable(Box<dyn std::error::Error + Send + Sync + 'static>),
    /// The transaction's whole encoded form — record frames, marker and
    /// headers, [`txn_encoded_len`]'s accounting — exceeds [`MAX_TXN_BYTES`].
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
    /// What the transaction in progress has reached. On entry to
    /// [`JournalWriter::commit_txn`] this is always [`InFlight::Idle`]: every
    /// path that returns to a caller who may commit again leaves it so, and
    /// the two that do not — a truncation that could not itself complete
    /// durably, and an unwind through the install — halt the kernel, so no
    /// transaction follows them. That is what lets the commit path start
    /// against this field rather than resetting it defensively first (§3).
    in_flight: InFlight,
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
        record_bytes: Vec<Vec<u8>>,
        install: impl FnOnce(),
    ) -> Result<u64, CommitFail> {
        let buf = encode_txn(first_seq, record_bytes)
            .map_err(|e| CommitFail::Unencodable(Box::new(e)))?;
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
    /// either caller must do, so both drop it.
    fn truncate_to(&mut self, mark: u64) -> io::Result<()> {
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
    /// Commit one whole transaction: serialize its records, charging each
    /// against the two size refusals no durability mode may skip, then commit
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
    /// no need of.
    ///
    /// The two refusals are charged AS THE LOOP GOES, and a record past the
    /// budget is dropped rather than kept, which is what makes enforcing
    /// [`MAX_TXN_BYTES`] cost [`MAX_TXN_BYTES`]: a caller who stages a hundred
    /// records each just under the frame cap would otherwise have every one of
    /// them materialized — under the applier lock, so with every other writer
    /// in the process waiting — before the sum that refuses them was taken.
    /// Held bytes are therefore bounded by the budget and the transient peak
    /// by one further frame.
    ///
    /// Two refusals, and their order is the caller's remedy in each case: a
    /// record whose frame payload would exceed [`MAX_FRAME_LEN`] — the refusal
    /// [`push_frame`] would give it, [`CommitFail::Unencodable`], a property of
    /// that record — precedes a whole encoded form past [`MAX_TXN_BYTES`] —
    /// [`CommitFail::OverBudget`], a property of the staging, where every
    /// record is fine and the caller staged too much at once. So a caller
    /// fixing a value is not first told to split. [`push_frame`]'s own
    /// frame-cap refusal deliberately stays: writer and reader sit on opposite
    /// sides of a trust boundary, and the writer's guard is what entitles
    /// recovery to treat a larger claimed `len` as corrupt.
    pub(crate) fn commit_txn<R: Serialize>(
        &mut self,
        first_seq: u64,
        records: &[R],
        install: impl FnOnce(),
    ) -> Result<u64, CommitFail> {
        let mut record_bytes: Vec<Vec<u8>> = Vec::new();
        let mut accounted = MARKER_FRAME_LEN;
        let mut over_budget = false;
        for record in records {
            // The closure is the unsizing coercion site: the bare constructor
            // as a function value does not coerce `bincode`'s boxed error.
            let bytes = encode_record(record).map_err(|e| CommitFail::Unencodable(e))?;
            if bytes.len() as u64 + RECORD_PAYLOAD_OVERHEAD > MAX_FRAME_LEN as u64 {
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
            Journal::InMemory => {
                install();
                Ok(0)
            }
            Journal::Segments(writer) => writer.commit_txn(first_seq, record_bytes, install),
        }
    }

    /// [`JournalWriter::repair_after_unwind`]. The in-memory arm answers
    /// [`UnwindRepair::Clean`] for every unwind, because the only thing it
    /// does past the size refusals is call `install`, and a world's destructor
    /// does not unwind ([`crate::WorldState`]'s drop obligation) — the durable
    /// arm tracks [`InFlight::Barriered`] because it has a barrier to be
    /// after, and this arm has none.
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

/// Why a scan could not produce an outcome (§7). Both answers are the
/// caller's to phrase in its own error vocabulary; neither leaves a partial
/// [`ScanOutcome`] for anyone to draw a verdict from.
#[derive(Debug)]
pub(crate) enum ScanFail {
    /// A segment could not be read.
    Io(io::Error),
    /// Resynchronization exceeded [`RESYNC_BUDGET_PASSES`]: the frame stream
    /// could not be enumerated in bounded work, so nothing derived from it
    /// would be more than a PREFIX of what the segment holds — a committed
    /// head that may be short, records that may be missing, a boundary set
    /// that may not be the journal's. Fatal at any height, which is why the
    /// scan refuses rather than answering with a qualification.
    Unbounded {
        /// The base's own coordinate: the damage lies somewhere above it, and
        /// the scan could not reach past it to say where.
        at: u64,
    },
}

impl From<io::Error> for ScanFail {
    fn from(e: io::Error) -> Self {
        ScanFail::Io(e)
    }
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
/// the corrupt runs, and where the tail to truncate begins. A scan that could
/// not enumerate the frame stream produces none of this — it answers
/// [`ScanFail`] — so every field here describes the whole scanned region and
/// carries no qualification.
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
    /// The tail-truncation cut, `None` when nothing was scanned — what
    /// [`truncate_tail`] cuts. Resolved here and read there, so no caller can
    /// aim a truncation at a region other than the one this scan judged.
    tail: Option<TailCut>,
}

impl ScanOutcome {
    /// The corrupt run a RECOVERY cannot answer around, classified within
    /// the committed region this scan derived: a run above the committed head
    /// is the un-acked / torn tail, which recovery is about to discard (§7).
    pub(crate) fn fatal_run_to_head(&self) -> Option<u64> {
        self.fatal_run(Some(self.committed_head))
    }

    /// The corrupt run a BOUNDED REPLAY cannot answer around, at any height. A
    /// bounded replay truncates nothing, so a run above the committed head is
    /// at-rest damage rather than a tail — and since a run's own seqs are
    /// unreadable, its reach below `inferred_max` is unknowable, so answering
    /// around it could answer from a hole (§7).
    pub(crate) fn fatal_run_anywhere(&self) -> Option<u64> {
        self.fatal_run(None)
    }

    /// The corrupt run a fold over `(s_load, bound]` cannot answer around: the
    /// `at` payload of the first run whose inferred `Seq` max lands in that
    /// range — durable committed data the folded state needs, and unreadable.
    /// Halt, never drop (§7). `bound = None` is unbounded above: every run
    /// above the base is fatal, however far above it lands.
    ///
    /// The run is classified by its `inferred_max` and REPORTED by its `at`,
    /// and keeping the two apart is what the boundary case turns on: a run
    /// wholly embodied in the base can still land on the very next coordinate
    /// (`at = s_load + 1`), which is harmless — its content is already in the
    /// base — where classifying by `at` would spuriously halt. An
    /// [`RunEnd::Eof`] run is never fatal: it is the un-acked / torn tail,
    /// which the last committed marker precedes.
    fn fatal_run(&self, bound: Option<u64>) -> Option<u64> {
        self.runs.iter().find_map(|run| match *run {
            RunEnd::Landed { inferred_max, at }
                if inferred_max > self.s_load && bound.is_none_or(|b| inferred_max <= b) =>
            {
                Some(at)
            }
            _ => None,
        })
    }

    /// Whether `at` is one of the committed transaction boundaries this scan
    /// saw — the values [`crate::Kernel::transact`] returns, and the only ones
    /// a bounded replay may answer at. `Err` carries the greatest boundary at or
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
            .fold(self.s_load, u64::max))
    }
}

/// The record frames of the ONE transaction a scan currently has open,
/// accumulated as they arrive (§1/§7).
///
/// A scan holds one of these at a time. That is the writer's own shape:
/// [`encode_txn`] emits a transaction's records contiguously and closes them
/// with its marker, so a group left open by an intervening transaction's
/// record can never be closed by a later marker.
///
/// One group at a time is not by itself a memory bound, because a journal is
/// not obliged to have been written by this writer: frames spread over every
/// segment of a store, all carrying one `txn`, are one group. So the size of
/// the group is bounded HERE, by the same [`MAX_TXN_BYTES`] the write path
/// refuses at ([`Self::oversize`]) — one segment's bytes plus one
/// transaction's worth, which is the memory floor
/// [`crate::Kernel::open`] promises on every replica.
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
    /// What this group's frames would occupy in the journal, accounted to the
    /// same figure [`txn_encoded_len`] gives the write side: seeded with the
    /// marker frame that will close the group, then charged one frame header
    /// plus one framed payload per record — which is [`record_frame_len`]
    /// reached from the bytes a reader actually holds.
    accounted: u64,
    /// Set once [`Self::accounted`] passes [`MAX_TXN_BYTES`]. A group past the
    /// budget is one no writer here can emit — [`Journal::commit_txn`] refuses
    /// it before a byte is appended — so the READER enforces the same bound
    /// rather than trusting it, which is what holds a scan's group memory to
    /// one transaction's worth against a journal this writer did not write.
    oversize: bool,
    /// `(seq, serialized W::Record bytes)`, in arrival order. Released the
    /// moment the group is known dead, since nothing downstream can want it.
    records: Vec<(u64, Vec<u8>)>,
}

impl PendingTxn {
    fn open(txn: Txn) -> PendingTxn {
        PendingTxn {
            txn,
            checksum: 0,
            last_seq: None,
            ordered: true,
            // The write side's own seed, so an honest transaction AT the
            // budget accounts to exactly the budget and is admitted.
            accounted: MARKER_FRAME_LEN,
            oversize: false,
            records: Vec::new(),
        }
    }

    /// Take one record frame of this transaction: `payload` is the frame
    /// payload exactly as framed, which is what `records_checksum` covers —
    /// and what [`record_frame_len`] charges, since a framed payload is the
    /// record's own bytes plus [`RECORD_PAYLOAD_OVERHEAD`].
    fn push(&mut self, record: LogRecord, payload: &[u8]) {
        if self.last_seq.is_some_and(|prev| record.seq <= prev) {
            self.ordered = false;
        }
        self.last_seq = Some(record.seq);
        self.checksum = crc32c::crc32c_append(self.checksum, payload);
        self.accounted = self
            .accounted
            .saturating_add(FRAME_HEADER_LEN as u64 + payload.len() as u64);
        self.oversize |= self.accounted > MAX_TXN_BYTES;
        if self.ordered && !self.oversize {
            self.records.push((record.seq, record.bytes));
        } else {
            // Dead: this group can never commit, so its records are released
            // as soon as that is known. The checksum and `last_seq` keep
            // advancing, so the refusal stays the one `commits` states.
            self.records = Vec::new();
        }
    }

    /// Whether `marker` commits this group: intact + durable (it is on the
    /// disk we read) + `records_checksum`-valid over a `Seq`-ascending group
    /// that the marker's own `last_seq` closes and that fits the journal's
    /// per-transaction budget (§1).
    ///
    /// The `last_seq` conjunct is the one the checksum cannot supply: the
    /// checksum ties the RECORDS to the marker, while `last_seq` is a separate
    /// field under no protection but the frame CRC. [`encode_txn`] sets it to
    /// the last record's own `Seq`, so a marker claiming less is one this
    /// writer cannot emit — and it is the shape that has the fold drop
    /// committed records above the claim while the sequencer restarts over
    /// their coordinates, which the next recovery then meets as one `Seq`
    /// presented twice.
    ///
    /// The budget conjunct is the reader's half of a bound the write path
    /// already keeps: accepting a group past [`MAX_TXN_BYTES`] would fold a
    /// transaction this kernel could not have committed, and would let a
    /// journal spread one `txn` over a whole store's segments while the scan
    /// held every record of it.
    fn commits(&self, marker: &Marker) -> bool {
        self.ordered
            && !self.oversize
            && self.last_seq == Some(marker.last_seq)
            && self.checksum == marker.records_checksum
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
///
/// Work: the sequential walk is one pass per scanned segment, and
/// resynchronization is bounded at [`RESYNC_BUDGET_PASSES`] more. A segment
/// that exhausts that budget refuses the scan outright
/// ([`ScanFail::Unbounded`]) rather than answering with a prefix, so a payload
/// that plants frame headers costs a bounded scan and a halt rather than an
/// unbounded one.
///
/// `segs` must be ASCENDING by `firstSeq`, as [`list_segments`] produces it.
/// The skip test, the tail resolution and [`inferred_last_seq`] all read a
/// neighbour's name as this segment's bound, so an out-of-order slice makes
/// those inferences meaningless — and [`reclaim_below`], which reads the same
/// order, deletes on one of them.
///
/// Reached through [`crate::replay::Base::scan`], which supplies `s_load` from
/// the base it selected. A scan and the fold that consumes it must agree on
/// their base, and that is the one route where they cannot disagree.
pub(crate) fn scan(segs: &[SegmentMeta], s_load: u64) -> Result<ScanOutcome, ScanFail> {
    let mut outcome = ScanOutcome {
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
    for (seg_index, seg) in segs.iter().enumerate() {
        if inferred_last_seq(segs, seg_index).is_some_and(|last| last <= s_load) {
            continue;
        }
        if first_scanned.is_none() {
            first_scanned = Some(seg_index);
        }
        let buf = fs::read(&seg.path)?;
        // This segment's resynchronization budget. EVERY rejected candidate
        // charges, not only the ones a resync landed on: a payload can plant
        // a valid frame between two expensive rejections, which clears the
        // resync and would leave the alternation uncharged.
        let budget = (buf.len() as u64).saturating_mul(RESYNC_BUDGET_PASSES);
        let mut spent = 0u64;
        let mut pos = 0usize;
        while pos < buf.len() {
            match parse_frame(&buf, pos) {
                Parsed::Intact { payload } => {
                    // The frame ends where its payload does, so the advance is
                    // one fact taken once — before the payload is consumed by
                    // the indexing below, and stated once for all three arms.
                    let end = payload.end;
                    let frame = &buf[payload];
                    match bincode::deserialize::<FramePayload>(frame) {
                        Ok(FramePayload::Record(record)) => {
                            if run_open {
                                outcome.runs.push(RunEnd::Landed {
                                    inferred_max: record.seq.saturating_sub(1),
                                    at: record.seq,
                                });
                                run_open = false;
                            }
                            let mut group = pending
                                .take()
                                .filter(|group| group.txn == record.txn)
                                .unwrap_or_else(|| PendingTxn::open(record.txn));
                            group.push(record, frame);
                            pending = Some(group);
                        }
                        Ok(FramePayload::Marker(marker)) => {
                            if run_open {
                                outcome.runs.push(RunEnd::Landed {
                                    inferred_max: marker.last_seq,
                                    // A marker carries no `Seq` of its own, so
                                    // the coordinate it contributes is one past
                                    // its own. At the ceiling there is no such
                                    // coordinate, and the run is reported at the
                                    // ceiling itself.
                                    at: marker.last_seq.saturating_add(1),
                                });
                                run_open = false;
                            }
                            if let Some(group) = pending.take_if(|group| group.txn == marker.txn) {
                                if group.commits(&marker) {
                                    outcome.committed_head = outcome.committed_head.max(marker.last_seq);
                                    cut = Some((seg_index, end as u64));
                                    outcome.committed_boundaries.push(marker.last_seq);
                                    outcome.committed_records.extend(group.records);
                                }
                                // else: torn txn — not committed; its frames are
                                // either beyond W (tail, truncated) or explained
                                // by a corrupt run the caller classifies (§7).
                            }
                        }
                        // Intact by CRC but undecodable: writer/reader skew.
                        // Treat as a corrupt frame — it participates in run
                        // classification rather than being silently dropped.
                        Err(_) => run_open = true,
                    }
                    pos = end;
                }
                Parsed::Bad { crc_bytes } => {
                    spent += crc_bytes;
                    if spent > budget {
                        // Everything derived so far is a prefix, so none of it
                        // travels: no verdict can be drawn from it and no
                        // truncation aimed with it.
                        return Err(ScanFail::Unbounded { at: s_load });
                    }
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
        outcome.runs.push(RunEnd::Eof);
    }
    // Everything past the last committed marker is tail. When the scanned
    // region holds no committed marker at all, everything scanned is tail:
    // the first scanned segment is cut at offset 0. Harmless corrupt runs
    // (inferred max ≤ `s_load`) sit below the cut and are not touched.
    outcome.tail = cut
        .or_else(|| first_scanned.map(|first| (first, 0)))
        .map(|(seg_index, offset)| TailCut {
            segment: segs[seg_index].path.clone(),
            offset,
            discard: segs[seg_index + 1..]
                .iter()
                .map(|seg| seg.path.clone())
                .collect(),
        });
    Ok(outcome)
}

/// The tail-truncation step (§7), run AFTER every refusal and BEFORE any
/// write is served: durably remove everything after the last committed marker
/// — cut its segment at the marker's frame end, delete every wholly-later
/// segment, fsync file and directory. Every halt precedes it — the corrupt-run
/// classification, an unenumerable frame stream, an exhausted `Seq` order, the
/// fold's own verdict on an undecodable or repeated record, and an exhausted
/// checkpoint chain — which is what leaves the store an operator images after
/// a halt exactly as it was found (§7). This is what makes cross-session `Txn`
/// uniqueness and file-order == `Seq`-order true at the next recovery (§1/§7).
/// Idempotent; a failure fails `open()` with `Io`.
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
    fn write_txn(writer: &mut JournalWriter, first: u64, record_bytes: Vec<Vec<u8>>) {
        writer
            .commit_txn(first, record_bytes, || {})
            .expect("fixture commit");
    }

    /// Frame spans of a CLEAN journal file, via the real parser.
    fn frame_spans(path: &Path) -> Vec<(usize, usize)> {
        let buf = fs::read(path).unwrap();
        let mut v = Vec::new();
        let mut pos = 0;
        while pos < buf.len() {
            match parse_frame(&buf, pos) {
                Parsed::Intact { payload } => {
                    v.push((pos, payload.end - pos));
                    pos = payload.end;
                }
                Parsed::Bad { .. } => panic!("clean journal expected"),
            }
        }
        v
    }

    fn flip_byte(path: &Path, offset: usize) {
        let mut data = fs::read(path).unwrap();
        data[offset] ^= 0xFF;
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
    fn frame_roundtrip_and_a_corrupt_length_is_detected() {
        let payload = b"hello frame".to_vec();
        let mut buf = Vec::new();
        push_frame(&mut buf, &payload).unwrap();
        match parse_frame(&buf, 0) {
            Parsed::Intact { payload: p } => {
                // The frame's end IS its payload's end, and the whole frame is
                // the header plus that payload.
                assert_eq!(p.end, buf.len());
                assert_eq!(&buf[p], payload.as_slice());
            }
            Parsed::Bad { .. } => panic!("intact frame expected"),
        }
        // A flipped payload byte fails the frame crc.
        let mut bad = buf.clone();
        bad[FRAME_HEADER_LEN + 2] ^= 0xFF;
        assert!(matches!(parse_frame(&bad, 0), Parsed::Bad { .. }));
        // A corrupt len is DETECTED, not silently mis-delimiting the frame
        // that follows (§1) — the length that OVERRUNS the buffer, which the
        // bounds check refuses before any crc is computed…
        let mut bad_len = buf.clone();
        bad_len[5] ^= 0xFF;
        assert!(matches!(parse_frame(&bad_len, 0), Parsed::Bad { crc_bytes: 0 }));
        // …and the one that FITS, where nothing but the crc can reject it: a
        // reader trusting this length would take a 5-byte payload and resume
        // mid-frame. `crc_bytes` names which door refused it.
        let mut short_len = buf;
        short_len[4..8].copy_from_slice(&5u32.to_le_bytes());
        assert!(matches!(parse_frame(&short_len, 0), Parsed::Bad { crc_bytes: 5 }));
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
        // And the frame cap itself is writable: the refusal begins one past
        // it, not at it.
        push_frame(&mut buf, &over[..MAX_FRAME_LEN as usize]).unwrap();
        assert!(matches!(parse_frame(&buf, 0), Parsed::Intact { .. }));
    }

    #[test]
    fn txn_size_accounting_matches_the_encoder_to_the_byte() {
        // The accounting stands in for building the frames, so it must match
        // the encoder exactly — pinned at extreme field values, so a codec
        // change toward value-dependent widths breaks here, not the two
        // limits this accounting feeds.
        for records in [
            vec![vec![5u8; 3]],
            vec![rec(u64::MAX), vec![7u8; 300], Vec::new()],
        ] {
            let expected = txn_encoded_len(&records);
            let buf = encode_txn(u64::MAX - 3, records).unwrap();
            assert_eq!(buf.len() as u64, expected);
        }
        // The per-record half: what push_frame judges is the wrapped payload,
        // the record's own bytes plus RECORD_PAYLOAD_OVERHEAD exactly.
        let payload = bincode::serialize(&FramePayload::Record(LogRecord {
            seq: u64::MAX,
            txn: Txn(u64::MAX),
            bytes: vec![1, 2, 3],
        }))
        .unwrap();
        assert_eq!(payload.len() as u64, 3 + RECORD_PAYLOAD_OVERHEAD);

        // …and the READER charges a framed payload to the same figure, which
        // is what lets it enforce the write path's budget without a second
        // accounting: a transaction the writer emits AT the budget accounts to
        // the budget on the way back in, so recovery cannot refuse a
        // transaction this kernel acked.
        let mut group = PendingTxn::open(Txn(u64::MAX));
        group.push(
            LogRecord {
                seq: u64::MAX,
                txn: Txn(u64::MAX),
                bytes: vec![1, 2, 3],
            },
            &payload,
        );
        assert_eq!(group.accounted, txn_encoded_len(&[vec![1, 2, 3]]));
    }

    #[test]
    fn commit_txn_refuses_what_no_mode_may_accept() {
        // The two size refusals, charged as the commit encodes each record.
        // `Vec<u8>` encodes as an 8-byte length prefix plus its bytes, so a
        // body of `n` occupies `n + prefix` of a frame payload.
        let prefix = encode_record(&Vec::<u8>::new()).unwrap().len();
        let mut journal = Journal::InMemory;
        let mut installs = 0u32;

        // A record one past the frame cap's payload edge is the RECORD's own
        // fault — Unencodable, not OverBudget, though the sum is over too: a
        // caller fixing a value is not first told to split.
        let cap_bytes = (MAX_FRAME_LEN as u64 - RECORD_PAYLOAD_OVERHEAD) as usize;
        let over_frame = vec![vec![0u8; cap_bytes + 1 - prefix]];
        let out = journal.commit_txn(1, &over_frame, || installs += 1);
        assert!(matches!(out, Err(CommitFail::Unencodable(_))), "got {out:?}");
        drop(over_frame);

        // At the budget exactly: commits — the refusal begins one past the
        // budget, not at it.
        let body = (MAX_TXN_BYTES - txn_encoded_len(&[Vec::new()])) as usize - prefix;
        let at_budget = vec![vec![0u8; body]];
        assert_eq!(
            txn_encoded_len(&[encode_record(&at_budget[0]).unwrap()]),
            MAX_TXN_BYTES
        );
        assert!(journal.commit_txn(1, &at_budget, || installs += 1).is_ok());
        drop(at_budget);

        // One byte past: OverBudget, carrying the size.
        let past_budget = vec![vec![0u8; body + 1]];
        match journal.commit_txn(1, &past_budget, || installs += 1) {
            Err(CommitFail::OverBudget { bytes }) => assert_eq!(bytes, MAX_TXN_BYTES + 1),
            other => panic!("expected OverBudget, got {other:?}"),
        }
        drop(past_budget);

        // …and a staging FAR past the budget still reports the whole accounted
        // size. The charge runs on past the crossing precisely so the figure a
        // caller's split must get under is the one they staged, where a charge
        // that stopped where it refused would name a number they already met.
        let half = (MAX_TXN_BYTES / 2) as usize;
        let far_over = vec![vec![0u8; half], vec![0u8; half], vec![0u8; 8]];
        let expected = {
            let encoded: Vec<Vec<u8>> =
                far_over.iter().map(|r| encode_record(r).unwrap()).collect();
            txn_encoded_len(&encoded)
        };
        assert!(expected > MAX_TXN_BYTES + record_frame_len(8 + prefix));
        match journal.commit_txn(1, &far_over, || installs += 1) {
            Err(CommitFail::OverBudget { bytes }) => assert_eq!(bytes, expected),
            other => panic!("expected the whole staging accounted, got {other:?}"),
        }

        assert_eq!(installs, 1, "only the at-budget transaction installs");
    }

    /// A record whose serializer refuses — the cheapest way to reach the
    /// encode step, which no size of value can exercise.
    struct RefusesSerialization;

    impl Serialize for RefusesSerialization {
        fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
            Err(serde::ser::Error::custom("record refused to serialize"))
        }
    }

    #[test]
    fn the_in_memory_journal_refuses_what_the_durable_one_refuses() {
        // The encode and the two size refusals belong to `Journal::commit_txn`
        // and run above its own mode branch, so the mode that journals nothing
        // still serializes every record and still refuses what only the frames
        // could reject. The frame cap once lived in the frame builder alone —
        // which this arm never reaches — and a store whose values could exceed
        // it passed every in-memory test and met the refusal in production;
        // owning the check above the branch is what keeps that closed by
        // construction rather than by whatever the caller remembers to do
        // first.
        let mut installed = false;
        let mut memory = Journal::InMemory;

        // The encode: a record the serializer refuses, in the mode that would
        // otherwise never encode anything.
        let out = memory.commit_txn(1, &[RefusesSerialization], || installed = true);
        assert!(matches!(out, Err(CommitFail::Unencodable(_))), "got {out:?}");

        // The frame cap, which is a property of frames this arm never builds.
        let prefix = encode_record(&Vec::<u8>::new()).unwrap().len();
        let cap_bytes = (MAX_FRAME_LEN as u64 - RECORD_PAYLOAD_OVERHEAD) as usize;
        let over_frame = vec![vec![0u8; cap_bytes + 1 - prefix]];
        let out = memory.commit_txn(1, &over_frame, || installed = true);
        assert!(matches!(out, Err(CommitFail::Unencodable(_))), "got {out:?}");
        drop(over_frame);

        // The transaction budget, likewise.
        let half = (MAX_TXN_BYTES / 2) as usize;
        let over_budget = vec![vec![0u8; half], vec![0u8; half]];
        let out = memory.commit_txn(1, &over_budget, || installed = true);
        assert!(matches!(out, Err(CommitFail::OverBudget { .. })), "got {out:?}");
        drop(over_budget);

        assert!(!installed, "a refused transaction installs nothing");

        // …and the durable arm answers the same, which is the parity these
        // three refusals exist to hold: one judgment, one place, both modes.
        let dir = tempdir().unwrap();
        let mut segments = Journal::Segments(JournalWriter::open_active(dir.path(), 1).unwrap());
        let out = segments.commit_txn(1, &[RefusesSerialization], || installed = true);
        assert!(matches!(out, Err(CommitFail::Unencodable(_))), "got {out:?}");
        assert!(!installed, "a refused transaction installs nothing");
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
    fn a_marker_that_disagrees_with_its_records_never_commits() {
        // A marker whose `last_seq` sits BELOW the group it closes. Its
        // checksum validates — that field ties the records to the marker and
        // says nothing about `last_seq` — so without the third conjunct the
        // txn commits at 5, the fold silently drops the committed records at
        // 6 and 7 as out of range, and the sequencer restarts over
        // coordinates that are still on disk. A transaction this writer
        // cannot emit, refused outright.
        let mut buf = Vec::new();
        let mut checksum = 0u32;
        for seq in 5..=7u64 {
            let payload = bincode::serialize(&FramePayload::Record(LogRecord {
                seq,
                txn: Txn(5),
                bytes: rec(seq * 10),
            }))
            .unwrap();
            checksum = crc32c::crc32c_append(checksum, &payload);
            push_frame(&mut buf, &payload).unwrap();
        }
        let payload = bincode::serialize(&FramePayload::Marker(Marker {
            txn: Txn(5),
            last_seq: 5, // the group reaches 7
            records_checksum: checksum,
        }))
        .unwrap();
        push_frame(&mut buf, &payload).unwrap();

        let dir = tempdir().unwrap();
        fs::write(segment_path(dir.path(), 5), &buf).unwrap();
        let segs = list_segments(dir.path()).unwrap();
        let out = scan(&segs, 4).unwrap();
        assert_eq!(out.committed_head, 4, "a short marker must not commit");
        assert!(out.committed_records.is_empty());
        assert!(out.committed_boundaries.is_empty());
    }

    #[test]
    fn a_group_past_the_transaction_budget_never_commits() {
        // The reader's half of the write path's own bound: `commit_txn`
        // refuses a staging past MAX_TXN_BYTES before a byte is appended, so a
        // group past it is one no writer here emits — and accepting it would
        // let a journal spread one `txn` over a whole store while the scan
        // held every record of it.
        //
        // The charge must reproduce the write side's term for term, which is
        // what the two cases below check from either side of the edge: four
        // record frames plus the marker frame land EXACTLY on the budget.
        const N: u64 = 4;
        let payload_len =
            ((MAX_TXN_BYTES - MARKER_FRAME_LEN) / N - FRAME_HEADER_LEN as u64) as usize;
        let buf = vec![7u8; payload_len + 1];
        let group_of = |last: &[u8]| {
            let mut group = PendingTxn::open(Txn(1));
            for seq in 1..=N {
                let payload = if seq == N { last } else { &buf[..payload_len] };
                let record = LogRecord {
                    seq,
                    txn: Txn(1),
                    bytes: Vec::new(),
                };
                group.push(record, payload);
            }
            group
        };
        let closed_by = |group: &PendingTxn| Marker {
            txn: Txn(1),
            last_seq: N,
            records_checksum: group.checksum,
        };

        // At the budget: a transaction this writer can emit, so it commits —
        // the refusal begins one byte past the budget, not at it.
        let at_budget = group_of(&buf[..payload_len]);
        assert_eq!(at_budget.accounted, MAX_TXN_BYTES);
        assert!(at_budget.commits(&closed_by(&at_budget)));
        assert_eq!(at_budget.records.len() as u64, N);

        // One byte past: refused, however its checksum lands — and the records
        // are released where the group is known dead, which is the memory this
        // bound exists for.
        let over = group_of(&buf);
        assert_eq!(over.accounted, MAX_TXN_BYTES + 1);
        assert!(!over.commits(&closed_by(&over)));
        assert!(over.records.is_empty(), "a dead group holds no records");
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
        let Parsed::Intact { payload } = parse_frame(&buf, 0) else {
            panic!("intact record frame expected")
        };
        let end = payload.end; // where the marker frame begins
        assert_eq!(&buf[payload], expect_record.as_slice());

        let mut expect_marker = Vec::new();
        expect_marker.extend_from_slice(&1u32.to_le_bytes()); // FramePayload::Marker
        expect_marker.extend_from_slice(&2u64.to_le_bytes()); // txn
        expect_marker.extend_from_slice(&2u64.to_le_bytes()); // last_seq
        // records_checksum: over the record frames' payloads, in Seq order.
        expect_marker
            .extend_from_slice(&crc32c::crc32c_append(0, &expect_record).to_le_bytes());
        let Parsed::Intact { payload } = parse_frame(&buf, end) else {
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
        writer
            .commit_txn(1, vec![rec(10)], || installed = true)
            .expect("fixture commit");
        assert!(installed, "the commit installs before it returns");
        let repair = writer.repair_after_unwind();
        assert!(matches!(repair, UnwindRepair::Clean), "got {repair:?}");
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
        let repair = writer.repair_after_unwind();
        assert!(matches!(repair, UnwindRepair::AfterBarrier), "got {repair:?}");
        let segs = list_segments(dir.path()).unwrap();
        assert_eq!(scan(&segs, 0).unwrap().committed_head, 1);
    }

    #[test]
    fn only_the_name_the_writer_emits_is_a_segment() {
        // `seg-01.wal` and `seg-+7.wal` parse as 1 and 7 under a bare
        // `u64::from_str`, so without the round trip they alias live segments'
        // `firstSeq`s. Two entries at one coordinate sort adjacent, which
        // makes the first one's inferred `lastSeq` 0 — and `reclaim_below`
        // deletes every segment whose inference is at or below the floor.
        let dir = tempdir().unwrap();
        fs::write(segment_path(dir.path(), 1), b"").unwrap();
        fs::write(dir.path().join("seg-01.wal"), b"").unwrap();
        fs::write(dir.path().join("seg-+7.wal"), b"").unwrap();
        fs::write(dir.path().join("seg-0007.wal"), b"").unwrap();
        let segs = list_segments(dir.path()).unwrap();
        assert_eq!(segs.len(), 1, "only one spelling names a segment");
        assert_eq!(segs[0].first_seq, 1);
        assert_eq!(segs[0].path, segment_path(dir.path(), 1));
        // The active segment is never range-reclaimed, and it is the only one
        // here — so nothing is deleted, where an aliased name would have made
        // the real `seg-1.wal` a closed segment covering nothing.
        reclaim_below(dir.path(), 100).unwrap();
        assert!(segment_path(dir.path(), 1).exists(), "a live segment was reclaimed");
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
        let mut embedded_magic = Vec::new();
        embedded_magic.extend_from_slice(b"xx");
        embedded_magic.extend_from_slice(&MAGIC);
        embedded_magic.extend_from_slice(b"yyyyyyyy");
        write_txn(&mut writer, 1, vec![embedded_magic]);
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
    fn resynchronization_over_planted_frame_headers_is_bounded() {
        // A committed record whose own bytes plant a frame header every 16
        // bytes, each claiming a payload that fits the file. Corrupt the frame
        // carrying them and every planted header becomes a resync candidate
        // whose CRC must be computed: without a budget the scan does
        // (payload / 16) × (claimed len) bytes of work — quadratic in a record
        // whose size the caller chooses, and an `open()` that never returns.
        let dir = tempdir().unwrap();
        let mut writer = JournalWriter::open_active(dir.path(), 1).unwrap();
        let mut evil = Vec::new();
        while evil.len() < 256 * 1024 {
            evil.extend_from_slice(&MAGIC);
            evil.extend_from_slice(&(64 * 1024u32).to_le_bytes()); // a len that fits
            evil.extend_from_slice(&0u32.to_le_bytes()); // a crc that will not
            evil.extend_from_slice(&[0u8; 4]);
        }
        write_txn(&mut writer, 1, vec![evil]);
        write_txn(&mut writer, 2, vec![rec(20)]);
        let segs = list_segments(dir.path()).unwrap();
        let spans = frame_spans(&segs[0].path);
        flip_byte(&segs[0].path, spans[0].0 + FRAME_HEADER_LEN + 1);

        // The scan refuses, at the base's own coordinate. That refusal is the
        // whole of what there is to check here: what such a scan derived is a
        // prefix, so it produces no outcome at all — there is no committed
        // head to read short, and no cut for a truncation to be aimed with.
        let fail = scan(&segs, 0).err();
        assert!(
            matches!(fail, Some(ScanFail::Unbounded { at: 0 })),
            "got {fail:?}"
        );
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
                Parsed::Intact { payload } => pos = payload.end,
                Parsed::Bad { .. } => return pos as u64,
            }
        }
    }
}
