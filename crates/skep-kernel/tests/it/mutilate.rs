//! Naming and damaging the files a kernel keeps — the operations both suites
//! perform on a CLOSED journal: name a segment or a checkpoint, copy a
//! fixture, flip a byte, cut a file short, append past the end.
//!
//! These know no format. What each suite restates for itself is the *layout*
//! it judges — the frame header, the checkpoint header, the frame walk —
//! because reading the on-disk shape from outside the crate is the point of
//! testing it at this tier. Reading a path and writing it back is not, so it
//! is stated once.
//!
//! Failures here are the harness's own, never a finding: a panic names which
//! step of the mutilation could not be performed.
//!
//! The FRAME-AWARE helpers at the end are the one exception to "these know
//! no format": a CRC-CONSISTENT rewrite — the commit chain's whole subject,
//! what a file-level writer does and what no CRC can see — cannot be made
//! without the frame layout, so that layout is restated once, there, for
//! the chain's tamper matrix (`chain`).

use std::fs::{self, OpenOptions};
use std::ops::Range;
use std::path::{Path, PathBuf};

/// The journal segment beginning at `first_seq` (§1's name-by-firstSeq).
pub fn seg_file(dir: &Path, first_seq: u64) -> PathBuf {
    dir.join(format!("seg-{first_seq}.wal"))
}

/// The checkpoint embodying `Seq ≤ seq` (§6).
pub fn ckpt_file(dir: &Path, seq: u64) -> PathBuf {
    dir.join(format!("checkpoint.{seq}"))
}

/// Copy every regular file of `src` into a fresh `dst`, so one built fixture
/// can be damaged several ways without rebuilding it.
pub fn copy_dir(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).expect("case dir");
    for entry in fs::read_dir(src).expect("fixture dir lists") {
        let entry = entry.expect("dir entry");
        if entry.file_type().expect("file type").is_file() {
            fs::copy(entry.path(), dst.join(entry.file_name())).expect("copy fixture file");
        }
    }
}

/// Invert every bit of the byte at `offset`, so a single-bit-rot fixture
/// damages exactly the field it names and nothing beside it.
pub fn flip_byte(path: &Path, offset: u64) {
    let mut data = fs::read(path).expect("read for flip");
    data[offset as usize] ^= 0xFF;
    fs::write(path, data).expect("write flipped");
}

/// Cut `path` to `len` bytes — a crash that lost everything after it.
pub fn truncate_file(path: &Path, len: u64) {
    let f = OpenOptions::new()
        .write(true)
        .open(path)
        .expect("open for truncate");
    f.set_len(len).expect("truncate");
}

/// Append `bytes` past the end — a partial write that landed, or junk.
pub fn append_bytes(path: &Path, bytes: &[u8]) {
    use std::io::Write as _;
    let mut f = OpenOptions::new()
        .append(true)
        .open(path)
        .expect("open for append");
    f.write_all(bytes).expect("append");
}

// ── the frame-aware helpers: the chain's tamper matrix ───────────────────
//
// The `SKJ4` layout these judge, restated. A frame is
// `[magic 4][len u32 LE][crc32c u32 LE][payload]`, its CRC over the `len`
// bytes and the payload. A payload opens with a `u32` tag: `0` a RECORD —
// `seq` u64, `txn` u64, then the record's own bytes behind a `u64` length —
// and `1` a MARKER — `txn` u64, `last_seq` u64, `records_checksum` u32
// (CRC32C streamed over the transaction's record payloads in file order),
// `salt` [u8; 32] (the per-transaction salt, the last bytes the chain
// hashes), `chain` [u8; 32], `sig_alg` u8, `sig` behind a `u64` length:
// ninety-seven bytes with the slot empty. A transaction is a run of record
// frames closed by the marker after them. Every helper below walks a CLEAN
// segment by its length fields and re-seals exactly the CRCs the edit it
// makes would break, so every frame stays intact to the parser and the chain
// alone is left to judge what changed.

/// The frame header: magic + len + crc.
pub const FRAME_HEADER_LEN: usize = 12;
/// The sync word every frame of this build opens with.
const FRAME_MAGIC: &[u8; 4] = b"SKJ4";
/// The payload tags.
pub const RECORD_TAG: u32 = 0;
pub const MARKER_TAG: u32 = 1;
/// A record payload's fields, by offset.
pub const RECORD_SEQ_AT: usize = 4;
pub const RECORD_BYTES_AT: usize = 28;
/// A marker payload's fields, by offset.
pub const MARKER_TXN_AT: usize = 4;
pub const MARKER_LAST_SEQ_AT: usize = 12;
pub const MARKER_CHECKSUM_AT: usize = 20;
pub const MARKER_SALT_AT: usize = 24;
pub const MARKER_CHAIN_AT: usize = 56;
pub const MARKER_SIG_ALG_AT: usize = 88;
pub const MARKER_SIG_LEN_AT: usize = 89;
/// A marker payload's length with the signature slot EMPTY.
pub const MARKER_EMPTY_LEN: usize = 97;

/// One frame of a clean segment: where its header begins, where its payload
/// lies. The frame ends where the payload does.
#[derive(Clone, Debug)]
pub struct Frame {
    pub start: usize,
    pub payload: Range<usize>,
}

impl Frame {
    pub fn end(&self) -> usize {
        self.payload.end
    }
}

/// One committed transaction of a clean segment, as its frames lay it down.
#[derive(Clone, Debug)]
pub struct Txn {
    /// The whole byte extent: the first record frame's header to the
    /// marker's end — what a swap moves and a delete closes up over.
    pub bytes: Range<usize>,
    /// The record frames, in file order.
    pub records: Vec<Frame>,
    /// The marker frame that closes them.
    pub marker: Frame,
    pub txn: u64,
    pub first_seq: u64,
    pub last_seq: u64,
    pub records_checksum: u32,
    /// The marker's salt field, as found — the per-transaction salt the
    /// chain hashes last (`SKJ4`).
    pub salt: [u8; 32],
    /// The marker's chain field, as found.
    pub chain: [u8; 32],
}

/// The frame at `start` of a clean segment, from its header alone.
fn frame_at(data: &[u8], start: usize) -> Frame {
    assert!(start + FRAME_HEADER_LEN <= data.len(), "a frame header at {start}");
    assert_eq!(&data[start..start + 4], FRAME_MAGIC, "a clean frame at {start}");
    let len = u32::from_le_bytes(data[start + 4..start + 8].try_into().unwrap()) as usize;
    let payload = start + FRAME_HEADER_LEN..start + FRAME_HEADER_LEN + len;
    assert!(payload.end <= data.len(), "the frame at {start} fits its segment");
    Frame { start, payload }
}

/// Every frame of a CLEAN segment, walked by the length fields. A torn or
/// damaged file is a harness failure here, never a finding.
pub fn frames(data: &[u8]) -> Vec<Frame> {
    let mut frames = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        let frame = frame_at(data, pos);
        pos = frame.end();
        frames.push(frame);
    }
    frames
}

fn tag_of(data: &[u8], frame: &Frame) -> u32 {
    u32::from_le_bytes(data[frame.payload.start..frame.payload.start + 4].try_into().unwrap())
}

/// Every transaction of a clean segment, in file order — one per marker.
pub fn transactions(data: &[u8]) -> Vec<Txn> {
    let mut txns = Vec::new();
    let mut records: Vec<Frame> = Vec::new();
    for frame in frames(data) {
        match tag_of(data, &frame) {
            RECORD_TAG => records.push(frame),
            MARKER_TAG => {
                let p = &data[frame.payload.clone()];
                let first = records.first().expect("a marker closes at least one record");
                let first_start = first.start;
                let first_seq = u64::from_le_bytes(
                    data[first.payload.start + RECORD_SEQ_AT..first.payload.start + RECORD_SEQ_AT + 8]
                        .try_into()
                        .unwrap(),
                );
                txns.push(Txn {
                    bytes: first_start..frame.end(),
                    records: std::mem::take(&mut records),
                    txn: u64::from_le_bytes(p[MARKER_TXN_AT..MARKER_LAST_SEQ_AT].try_into().unwrap()),
                    first_seq,
                    last_seq: u64::from_le_bytes(
                        p[MARKER_LAST_SEQ_AT..MARKER_CHECKSUM_AT].try_into().unwrap(),
                    ),
                    records_checksum: u32::from_le_bytes(
                        p[MARKER_CHECKSUM_AT..MARKER_SALT_AT].try_into().unwrap(),
                    ),
                    salt: p[MARKER_SALT_AT..MARKER_CHAIN_AT].try_into().unwrap(),
                    chain: p[MARKER_CHAIN_AT..MARKER_SIG_ALG_AT].try_into().unwrap(),
                    marker: frame,
                });
            }
            tag => panic!("a frame payload tag this layout does not name: {tag}"),
        }
    }
    assert!(records.is_empty(), "a clean segment ends on a marker");
    txns
}

/// The CRC a frame's header must carry: CRC32C over its `len` bytes, then
/// its payload.
pub fn frame_crc(data: &[u8], frame: &Frame) -> u32 {
    crc32c::crc32c_append(
        crc32c::crc32c(&data[frame.start + 4..frame.start + 8]),
        &data[frame.payload.clone()],
    )
}

/// Re-seal a frame's CRC after its payload was edited in place.
pub fn reseal_frame(data: &mut [u8], frame: &Frame) {
    let crc = frame_crc(data, frame);
    data[frame.start + 8..frame.start + 12].copy_from_slice(&crc.to_le_bytes());
}

/// The `records_checksum` a transaction's marker must carry: CRC32C streamed
/// over its record payloads, in file order.
pub fn records_checksum(data: &[u8], txn: &Txn) -> u32 {
    txn.records
        .iter()
        .fold(0u32, |crc, frame| crc32c::crc32c_append(crc, &data[frame.payload.clone()]))
}

/// Re-seal everything a CRC covers in `txn`: each record frame, the
/// marker's `records_checksum`, then the marker frame. The chain field is
/// left as found.
pub fn reseal_txn(data: &mut [u8], txn: &Txn) {
    for record in &txn.records {
        reseal_frame(data, record);
    }
    let checksum = records_checksum(data, txn);
    let at = txn.marker.payload.start + MARKER_CHECKSUM_AT;
    data[at..at + 4].copy_from_slice(&checksum.to_le_bytes());
    reseal_frame(data, &txn.marker);
}

/// THE FRAME-AWARE REWRITE: edit the payload of the frame at `start` in
/// place — its length unchanged — and re-seal that frame's CRC, so the frame
/// is intact to the parser. Nothing else is re-fixed: a record edited this
/// way leaves its marker's `records_checksum` stale, and a marker edited this
/// way carries whatever the edit put there. What the marker's own validation
/// and the chain make of it is the case's to judge.
pub fn rewrite_frame(path: &Path, start: usize, edit: impl FnOnce(&mut [u8])) {
    let mut data = fs::read(path).expect("read for rewrite");
    let frame = frame_at(&data, start);
    edit(&mut data[frame.payload.clone()]);
    reseal_frame(&mut data, &frame);
    fs::write(path, data).expect("write rewritten");
}

/// Replace the payload of the frame at `start` wholesale — its LENGTH may
/// change — re-sealing the frame's `len` and CRC; every later frame shifts
/// by the difference. How a marker's signature slot is filled.
pub fn replace_frame_payload(path: &Path, start: usize, payload: &[u8]) {
    let data = fs::read(path).expect("read for replace");
    let frame = frame_at(&data, start);
    let len_le = (payload.len() as u32).to_le_bytes();
    let mut out = Vec::with_capacity(data.len() + payload.len());
    out.extend_from_slice(&data[..frame.start]);
    out.extend_from_slice(FRAME_MAGIC);
    out.extend_from_slice(&len_le);
    out.extend_from_slice(&crc32c::crc32c_append(crc32c::crc32c(&len_le), payload).to_le_bytes());
    out.extend_from_slice(payload);
    out.extend_from_slice(&data[frame.end()..]);
    fs::write(path, out).expect("write replaced");
}

/// THE CONSISTENT TRANSACTION REWRITE — what a file-level writer who can
/// re-fix any CRC does: edit anywhere inside transaction `index` (the
/// closure sees the whole segment and the transaction's spans), then re-seal
/// every record frame, recompute `records_checksum` into the marker and
/// re-seal the marker. Every CRC passes and the marker still CLOSES its
/// group, so the transaction COMMITS as rewritten, and the chain is the one
/// thing left that can see it.
pub fn rewrite_txn(path: &Path, index: usize, edit: impl FnOnce(&mut [u8], &Txn)) {
    let mut data = fs::read(path).expect("read for rewrite");
    let txn = transactions(&data)
        .get(index)
        .cloned()
        .unwrap_or_else(|| panic!("no transaction {index}"));
    edit(&mut data, &txn);
    reseal_txn(&mut data, &txn);
    fs::write(path, data).expect("write rewritten");
}

/// Swap two whole transactions' byte extents; every frame stays intact.
pub fn swap_txns(path: &Path, i: usize, j: usize) {
    let data = fs::read(path).expect("read for swap");
    let txns = transactions(&data);
    let (lo, hi) = (i.min(j), i.max(j));
    assert!(lo < hi && hi < txns.len(), "two distinct transactions to swap");
    let (a, b) = (txns[lo].bytes.clone(), txns[hi].bytes.clone());
    let mut out = Vec::with_capacity(data.len());
    out.extend_from_slice(&data[..a.start]);
    out.extend_from_slice(&data[b.clone()]);
    out.extend_from_slice(&data[a.end..b.start]);
    out.extend_from_slice(&data[a]);
    out.extend_from_slice(&data[b.end..]);
    fs::write(path, out).expect("write swapped");
}

/// Delete one whole transaction and close the file up over it.
pub fn delete_txn(path: &Path, index: usize) {
    let mut data = fs::read(path).expect("read for delete");
    let bytes = transactions(&data)
        .get(index)
        .map(|txn| txn.bytes.clone())
        .unwrap_or_else(|| panic!("no transaction {index}"));
    data.drain(bytes);
    fs::write(path, data).expect("write closed up");
}

/// Replace a segment with an OLDER copy of itself — a rollback of that one
/// file while every later segment stands.
pub fn rollback_segment(path: &Path, older: &[u8]) {
    fs::write(path, older).expect("write the older copy back");
}
