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

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Per-frame sync word anchoring recovery resynchronization (§1/§7).
const MAGIC: [u8; 4] = *b"SKJ1";
/// Frame header: magic (4) + len (4) + crc (4).
pub(crate) const FRAME_HEADER: usize = 12;
/// Sanity bound on a single frame (open build decision: max frame size). The
/// writer enforces it, so recovery may treat a larger claimed `len` as corrupt.
const MAX_FRAME_LEN: u32 = 64 * 1024 * 1024;
/// Rotation threshold (open build decision). Rotation happens at txn
/// boundaries only, so a txn's frames never span a segment; under per-commit
/// Fsync the old segment is already durable at rotation (its last txn's
/// barrier fsynced it), preserving marker-as-ack across the boundary (§1).
const SEGMENT_MAX_BYTES: u64 = 1024 * 1024;

/// One journaled authoritative delta (§1). `bytes` is the serialized
/// `W::Record`; the struct is named `LogRecord` so it does not collide with
/// the trait's `W::Record`. `txn` is the transaction's FIRST `Seq` — not a
/// separate counter — so it is unique within any scanned journal region and
/// recovered for free with the single `Seq` high-water (§1/§7).
#[derive(Serialize, Deserialize)]
pub(crate) struct LogRecord {
    pub seq: u64,
    pub txn: u64,
    pub bytes: Vec<u8>,
}

/// Per-txn commit marker — the terminal frame of a transaction. In v1 a
/// committed marker (intact, durable, `records_checksum`-valid) *is* the
/// commit ack (§1). `records_checksum` is CRC32C over the concatenated payload
/// bytes of the txn's record frames, in `Seq` order — distinct from the
/// marker's own per-frame `crc`, and byte-reproducible at recovery (§1/§7).
#[derive(Serialize, Deserialize)]
pub(crate) struct Marker {
    pub txn: u64,
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
/// fsync (§1/§3). `records` are the already-serialized `W::Record` bytes.
pub(crate) fn encode_txn(first_seq: u64, records: &[Vec<u8>]) -> io::Result<Vec<u8>> {
    assert!(!records.is_empty(), "zero-step ops never reach the journal");
    let txn = first_seq;
    let mut buf = Vec::new();
    let mut checksum = 0u32;
    for (i, bytes) in records.iter().enumerate() {
        let payload = bincode::serialize(&FramePayload::Record(LogRecord {
            seq: first_seq + i as u64,
            txn,
            bytes: bytes.clone(),
        }))
        .map_err(invalid_data)?;
        checksum = crc32c::crc32c_append(checksum, &payload);
        push_frame(&mut buf, &payload)?;
    }
    let last_seq = first_seq + records.len() as u64 - 1;
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
    if pos + FRAME_HEADER > buf.len() || buf[pos..pos + 4] != MAGIC {
        return Parsed::Bad;
    }
    let len = u32::from_le_bytes(buf[pos + 4..pos + 8].try_into().unwrap());
    let crc = u32::from_le_bytes(buf[pos + 8..pos + 12].try_into().unwrap());
    if len > MAX_FRAME_LEN {
        return Parsed::Bad;
    }
    let end = pos + FRAME_HEADER + len as usize;
    if end > buf.len() {
        return Parsed::Bad;
    }
    let computed = crc32c::crc32c_append(
        crc32c::crc32c(&buf[pos + 4..pos + 8]),
        &buf[pos + FRAME_HEADER..end],
    );
    if computed != crc {
        return Parsed::Bad;
    }
    Parsed::Intact {
        payload: pos + FRAME_HEADER..end,
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
pub(crate) fn acquire_dir_lock(dir: &Path) -> io::Result<File> {
    let f = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(dir.join("kernel.lock"))?;
    fs2::FileExt::try_lock_exclusive(&f)?;
    Ok(f)
}

/// The live appender over the active (last) segment. All calls happen under
/// the applier lock (§3/§8); appends are in `Seq` order, so file order ==
/// `Seq` order (§2).
pub(crate) struct JournalWriter {
    dir: PathBuf,
    file: File,
    len: u64,
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
        })
    }

    pub(crate) fn len(&self) -> u64 {
        self.len
    }

    /// Rotate at a txn boundary if the active segment is over the threshold.
    /// `first_seq` is the incoming txn's first `Seq` — the new segment's name
    /// — so segment names stay lower bounds of their content and successor
    /// names stay sound `lastSeq` inferences for predecessors (§1). Called
    /// BEFORE any of the txn's frames are appended; on failure nothing of the
    /// txn is on disk (the §3 pre-append discipline applies) and the next
    /// attempt re-enters rotation.
    pub(crate) fn maybe_rotate(&mut self, first_seq: u64) -> io::Result<()> {
        if self.len == 0 || self.len < SEGMENT_MAX_BYTES {
            return Ok(());
        }
        // Under per-commit Fsync the old segment is already durable (the
        // previous txn's barrier fsynced it) — the §1 rotation discipline.
        *self = Self::create_segment(&self.dir, first_seq)?;
        Ok(())
    }

    pub(crate) fn append(&mut self, buf: &[u8]) -> io::Result<()> {
        self.file.write_all(buf)?;
        self.len += buf.len() as u64;
        Ok(())
    }

    /// The durability barrier: ONE fsync of records+marker (§1).
    pub(crate) fn barrier(&mut self) -> io::Result<()> {
        self.file.sync_data()
    }

    /// Durably truncate the active segment back to `len` — the §1
    /// barrier-failure / §3 unwind-guard tail truncation. Idempotent.
    pub(crate) fn truncate_to(&mut self, len: u64) -> io::Result<()> {
        self.file.set_len(len)?;
        self.file.sync_data()?;
        self.len = len;
        Ok(())
    }
}

/// How a corrupt run (a span the scan skipped via magic-resync) ended (§7).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RunEnd {
    /// The resync landed on an intact frame. `inferred_max` = next-intact
    /// coordinate − 1 (the CLASSIFIER: a record landing contributes its `seq`,
    /// a marker landing `last_seq + 1` — markers carry no `Seq` of their own);
    /// `at` = the next-intact coordinate itself (the error PAYLOAD). Keeping
    /// the two apart is what keeps the boundary frame at `at = S_load + 1`
    /// harmless rather than spuriously fatal (§7).
    Landed { inferred_max: u64, at: u64 },
    /// The run reached end-of-journal with no next intact frame: classes as
    /// the un-acked / torn tail (`> W`), sound because the last committed
    /// marker is itself intact and so precedes any EOF-reaching run (§7).
    Eof,
}

/// Pass-1 result (§7): the trustworthy boundary `W`, the committed records,
/// the corrupt runs (for the caller to classify against `S_load`/`W`), and the
/// physical cut point for tail truncation.
pub(crate) struct ScanOutcome {
    /// The last COMMITTED marker's `last_seq`, floored at `S_load` (if no
    /// committed marker sits above the loaded checkpoint, `W = S_load` and
    /// Pass 2 folds nothing).
    pub w: u64,
    /// `(seq, serialized W::Record bytes)` of every record belonging to a
    /// committed transaction, unordered (the caller sorts by `Seq` and filters
    /// to `(S_load, W]`).
    pub committed_records: Vec<(u64, Vec<u8>)>,
    /// Corrupt runs in scan order.
    pub runs: Vec<RunEnd>,
    /// `(segment index, byte offset of the last committed marker's frame
    /// end)` — the tail-truncation cut (§7). `None` when no committed marker
    /// was seen in the scanned region.
    pub cut: Option<(usize, u64)>,
    /// Index of the first scanned segment, `None` iff there are no segments.
    pub first_scanned: Option<usize>,
}

struct PendingRec {
    seq: u64,
    /// The frame payload exactly as framed — what `records_checksum` covers.
    payload: Vec<u8>,
    /// The serialized `W::Record` carried inside.
    bytes: Vec<u8>,
}

/// Pass 1 (§7): scan in file order (== `Seq` order — in-order append plus the
/// prior recovery's tail truncation), resynchronizing past bad frames via the
/// magic word (accepting only intact frames — a coincidental magic inside a
/// payload fails the CRC check and the scan continues), grouping record
/// frames by `txn` — NOT file position — to validate each marker's
/// `records_checksum`, and deriving `W`.
///
/// Closed segments whose inferred `lastSeq` (successor's `firstSeq` − 1, a
/// conservative upper bound under TolerateGap burns) is `≤ s_load` are
/// skipped without opening them; the active (final) segment is always scanned
/// (§1/§7). A corrupt run persists across a segment boundary: the journal is
/// one logical `Seq`-ordered stream.
pub(crate) fn scan(segs: &[SegmentMeta], s_load: u64) -> io::Result<ScanOutcome> {
    let mut out = ScanOutcome {
        w: s_load,
        committed_records: Vec::new(),
        runs: Vec::new(),
        cut: None,
        first_scanned: None,
    };
    let mut pending: HashMap<u64, Vec<PendingRec>> = HashMap::new();
    let mut run_open = false;
    for (i, seg) in segs.iter().enumerate() {
        let is_last = i + 1 == segs.len();
        if !is_last && segs[i + 1].first_seq.saturating_sub(1) <= s_load {
            continue;
        }
        if out.first_scanned.is_none() {
            out.first_scanned = Some(i);
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
                            pending.entry(r.txn).or_default().push(PendingRec {
                                seq: r.seq,
                                payload: buf[payload].to_vec(),
                                bytes: r.bytes,
                            });
                            pos = end;
                        }
                        Ok(FramePayload::Marker(m)) => {
                            if run_open {
                                out.runs.push(RunEnd::Landed {
                                    inferred_max: m.last_seq,
                                    at: m.last_seq + 1,
                                });
                                run_open = false;
                            }
                            if let Some(mut group) = pending.remove(&m.txn) {
                                group.sort_by_key(|p| p.seq);
                                let mut checksum = 0u32;
                                for p in &group {
                                    checksum = crc32c::crc32c_append(checksum, &p.payload);
                                }
                                if checksum == m.records_checksum {
                                    // Committed: intact + durable (it is on the
                                    // disk we read) + records_checksum-valid (§1).
                                    out.w = out.w.max(m.last_seq);
                                    out.cut = Some((i, end as u64));
                                    out.committed_records
                                        .extend(group.into_iter().map(|p| (p.seq, p.bytes)));
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
/// When the scanned region holds no committed marker, everything scanned is
/// tail: the first scanned segment is cut at offset 0. Harmless corrupt runs
/// (inferred max ≤ `S_load`) sit below the cut and are not touched.
pub(crate) fn truncate_tail(dir: &Path, segs: &[SegmentMeta], scan: &ScanOutcome) -> io::Result<()> {
    let cut = match (scan.cut, scan.first_scanned) {
        (Some(c), _) => Some(c),
        (None, Some(first)) => Some((first, 0)),
        (None, None) => None,
    };
    let Some((idx, off)) = cut else {
        return Ok(());
    };
    let f = OpenOptions::new().write(true).open(&segs[idx].path)?;
    f.set_len(off)?;
    f.sync_data()?;
    for seg in &segs[idx + 1..] {
        fs::remove_file(&seg.path)?;
    }
    fsync_dir(dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn rec(x: u64) -> Vec<u8> {
        bincode::serialize(&x).unwrap()
    }

    fn write_txn(w: &mut JournalWriter, first: u64, records: &[Vec<u8>]) {
        let buf = encode_txn(first, records).unwrap();
        w.append(&buf).unwrap();
        w.barrier().unwrap();
    }

    /// Frame spans of a CLEAN journal file, via the real parser.
    fn spans_of(path: &Path) -> Vec<(usize, usize)> {
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

    fn flip(path: &Path, off: usize) {
        let mut data = fs::read(path).unwrap();
        data[off] ^= 0xFF;
        fs::write(path, data).unwrap();
    }

    fn committed_seqs(out: &ScanOutcome) -> Vec<u64> {
        let mut s: Vec<u64> = out.committed_records.iter().map(|r| r.0).collect();
        s.sort_unstable();
        s
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
        bad[FRAME_HEADER + 2] ^= 0xFF;
        assert!(matches!(parse_frame(&bad, 0), Parsed::Bad));
        // A corrupt len is DETECTED (crc covers len), not silently
        // mis-delimiting the following frame (§1).
        let mut badlen = buf;
        badlen[5] ^= 0xFF;
        assert!(matches!(parse_frame(&badlen, 0), Parsed::Bad));
    }

    #[test]
    fn scan_groups_by_txn_and_derives_w() {
        let dir = tempdir().unwrap();
        let mut w = JournalWriter::open_active(dir.path(), 1).unwrap();
        write_txn(&mut w, 1, &[rec(10)]);
        write_txn(&mut w, 2, &[rec(20), rec(21)]); // seqs 2, 3
        let segs = list_segments(dir.path()).unwrap();
        let out = scan(&segs, 0).unwrap();
        assert_eq!(out.w, 3);
        assert!(out.runs.is_empty());
        assert_eq!(committed_seqs(&out), vec![1, 2, 3]);
        assert_eq!(out.first_scanned, Some(0));
        let file_len = fs::metadata(&segs[0].path).unwrap().len();
        assert_eq!(out.cut, Some((0, file_len)));
    }

    #[test]
    fn scan_tolerates_burned_seq_gaps() {
        // §7: the replayed range needs NO Seq-contiguity — a TolerateGap burn
        // folds harmlessly; a missing Seq is never corruption.
        let dir = tempdir().unwrap();
        let mut w = JournalWriter::open_active(dir.path(), 1).unwrap();
        write_txn(&mut w, 1, &[rec(10)]);
        write_txn(&mut w, 5, &[rec(50), rec(60)]); // burned 2..=4
        let segs = list_segments(dir.path()).unwrap();
        let out = scan(&segs, 0).unwrap();
        assert_eq!(out.w, 6);
        assert!(out.runs.is_empty());
        assert_eq!(committed_seqs(&out), vec![1, 5, 6]);
    }

    #[test]
    fn corrupt_record_classifies_by_marker_landing() {
        // T1 = seq 1, T2 = seq 2, T3 = seq 3; corrupt T2's record frame. The
        // resync lands on T2's marker — a marker landing: at = last_seq + 1,
        // inferred max = last_seq (markers carry no Seq of their own; §7).
        let dir = tempdir().unwrap();
        let mut w = JournalWriter::open_active(dir.path(), 1).unwrap();
        write_txn(&mut w, 1, &[rec(10)]);
        write_txn(&mut w, 2, &[rec(20)]);
        write_txn(&mut w, 3, &[rec(30)]);
        let segs = list_segments(dir.path()).unwrap();
        let spans = spans_of(&segs[0].path);
        // Frames: 0=T1 rec, 1=T1 marker, 2=T2 rec, 3=T2 marker, 4=T3 rec, 5=T3 marker.
        flip(&segs[0].path, spans[2].0 + FRAME_HEADER + 1);
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
        assert_eq!(out.w, 3);
        assert_eq!(committed_seqs(&out), vec![1, 3]);
    }

    #[test]
    fn corrupt_marker_lands_on_next_record() {
        // T2 = seqs 2..=3; corrupt T2's MARKER. The resync lands on T3's first
        // record (seq 4) — a record landing: at = seq, inferred max = seq − 1.
        let dir = tempdir().unwrap();
        let mut w = JournalWriter::open_active(dir.path(), 1).unwrap();
        write_txn(&mut w, 1, &[rec(10)]);
        write_txn(&mut w, 2, &[rec(20), rec(21)]);
        write_txn(&mut w, 4, &[rec(40)]);
        let segs = list_segments(dir.path()).unwrap();
        let spans = spans_of(&segs[0].path);
        // Frames: 0=T1 rec, 1=T1 marker, 2..=3=T2 recs, 4=T2 marker, 5=T3 rec, 6=T3 marker.
        flip(&segs[0].path, spans[4].0 + FRAME_HEADER + 1);
        let out = scan(&segs, 0).unwrap();
        assert_eq!(
            out.runs,
            vec![RunEnd::Landed {
                inferred_max: 3,
                at: 4
            }]
        );
        assert_eq!(out.w, 4);
        assert_eq!(committed_seqs(&out), vec![1, 4]);
    }

    #[test]
    fn resync_rejects_coincidental_magic_inside_payload() {
        // A record whose bytes contain the magic word; corrupt its frame. The
        // resync must reject the embedded magic (its crc check fails) and land
        // on the real next frame — T1's marker (§1/§7).
        let dir = tempdir().unwrap();
        let mut w = JournalWriter::open_active(dir.path(), 1).unwrap();
        let mut evil = Vec::new();
        evil.extend_from_slice(b"xx");
        evil.extend_from_slice(&MAGIC);
        evil.extend_from_slice(b"yyyyyyyy");
        write_txn(&mut w, 1, &[evil]);
        write_txn(&mut w, 2, &[rec(20)]);
        let segs = list_segments(dir.path()).unwrap();
        let spans = spans_of(&segs[0].path);
        flip(&segs[0].path, spans[0].0 + FRAME_HEADER + 1);
        let out = scan(&segs, 0).unwrap();
        assert_eq!(
            out.runs,
            vec![RunEnd::Landed {
                inferred_max: 1,
                at: 2
            }]
        );
        assert_eq!(out.w, 2);
        assert_eq!(committed_seqs(&out), vec![2]);
    }

    #[test]
    fn torn_tail_reaches_eof() {
        let dir = tempdir().unwrap();
        let mut w = JournalWriter::open_active(dir.path(), 1).unwrap();
        write_txn(&mut w, 1, &[rec(10)]);
        write_txn(&mut w, 2, &[rec(20)]);
        // Crash mid-append: a partial header at the tail.
        w.append(&[0xAB, 0xCD, 0xEF]).unwrap();
        let segs = list_segments(dir.path()).unwrap();
        let out = scan(&segs, 0).unwrap();
        assert_eq!(out.runs, vec![RunEnd::Eof]);
        assert_eq!(out.w, 2);
        assert_eq!(committed_seqs(&out), vec![1, 2]);
        // The cut sits at the last committed marker's frame end.
        let prefix_end = intact_prefix_end(&segs[0].path);
        assert_eq!(out.cut, Some((0, prefix_end)));
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
