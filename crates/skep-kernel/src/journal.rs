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
//!
//! This file is the format both sides read: the frame, the record and marker
//! types, the codec every byte of the crate goes through, and the size
//! accounting. Its children are the operations over it — `writer` appends
//! (the barrier, the install hand-off, the repair after a failed commit),
//! `scan` reads (recovery's Pass 1, its verdicts, the tail cut, the format
//! probe), `segment` names, lists and reclaims the files, `chain` spells the
//! commit chain's one link, and `attest` is the signature slot's public type.
//! The children see this file's private items; the rest of the crate sees
//! what is marked `pub(crate)` here and the re-export block below.

mod attest;
mod chain;
mod scan;
mod segment;
mod writer;

pub use attest::Attestation;
pub use attest::AttestationError;
pub(crate) use chain::CHAIN_GENESIS;
pub(crate) use scan::damaged_sync_word_cause;
pub(crate) use scan::first_sync_word;
pub(crate) use scan::scan;
pub(crate) use scan::truncate_tail;
pub(crate) use scan::ClosingMarker;
pub(crate) use scan::FirstSyncWord;
pub(crate) use scan::ScanFail;
pub(crate) use scan::ScanOutcome;
pub(crate) use segment::acquire_journal_lock;
pub(crate) use segment::fsync_dir;
pub(crate) use segment::list_segments;
pub(crate) use segment::reaches_genesis;
pub(crate) use segment::reclaim_below;
pub(crate) use segment::segment_path;
pub(crate) use segment::SegmentMeta;
pub(crate) use writer::{CommitFail, Journal, JournalWriter, UnwindRepair};

use std::io;
use std::ops::Range;

use bincode::Options;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use attest::SIG_ALG_UNSIGNED;
use chain::ChainLink;

/// Per-frame sync word anchoring recovery resynchronization (§1/§7) — and
/// the journal's FORMAT stamp: the trailing numeral names the format that
/// wrote the frame. Bumped 1 → 2 at the 2026-08-26 genesis re-baseline
/// (ghost-tumbler reserved types; `GenesisConfig` retired), so a journal
/// written under the 9-space regime does not reopen as this format's. Bumped
/// 2 → 3 on 2026-09-23 (QUEUE item 10, the hash chain's first lane): the
/// commit marker gained its chain field and signature slot, the codec was
/// pinned behind [`codec`], and the checkpoint went canonical beside it
/// (`SKC3`). Bumped 3 → 4 on 2026-09-24 (the chain's SALT; the signed-ops
/// re-base report's R1): the commit marker gained a per-transaction random
/// salt that the chain's preimage hashes, so every chain value moved — the
/// marker doc's own definition of a format event — and the checkpoint stamp
/// moved with it (`SKC4`), its `chain_head` being a value under the salted
/// rule. A segment opening with another format's sync word is refused BY
/// NAME at `open` ([`first_sync_word`]) rather than read as this one's.
pub(crate) const MAGIC: [u8; 4] = *b"SKJ4";
/// The stamp's fixed prefix: what makes four bytes a well-formed journal sync
/// word of SOME format. [`first_sync_word`] tells such a word (`SKJ` + a
/// numeral this build does not write) from damage that is not one (anything
/// else) by it — and, since every one-bit flip of this build's numeral keeps
/// the prefix, tells a format from ONE damaged word by the frame after it.
const STAMP_PREFIX: &[u8; 3] = b"SKJ";
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
/// above that base — a journal that opens on the machine that wrote it and not
/// on the replica. The reader holds the floor as well as the writer: a segment
/// longer than twice this figure is refused before a byte of it is read.
///
/// Being EQUAL rather than nested, the two limits do not stack: a transaction
/// carries its records' frames and a commit marker, so the largest record this
/// budget admits is smaller than the largest the frame cap admits, and the top
/// of the frame cap is unreachable in practice. A record in that band frames
/// and cannot commit, which is the one case where
/// [`crate::TxnError::OverBudget`]'s remedy is to shrink the record rather
/// than to split the transaction — as that variant states.
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
/// The longest segment this module READS: twice the transaction budget. The
/// writer appends only to a segment under [`SEGMENT_ROTATE_BYTES`], and a
/// transaction is at most [`MAX_TXN_BYTES`], so no segment this journal's
/// writer produces reaches it; a file past it is damage, or not this writer's,
/// and reading it whole would size an allocation by the file's own claim. It
/// is what makes the memory floor [`MAX_TXN_BYTES`] promises a fact about the
/// reader as well as the writer. Twice the budget rather than the writer's
/// exact maximum, so a later build that lowers the rotation threshold never
/// refuses a segment an earlier one wrote: this moves only with the format.
const MAX_SEGMENT_LEN: u64 = 2 * MAX_TXN_BYTES;
// …which holds only while the threshold is at or below the budget: a threshold
// moved above it would let an honest segment pass the ceiling, so it moves the
// ceiling with it.
const _: () = assert!(SEGMENT_ROTATE_BYTES <= MAX_TXN_BYTES);
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
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
struct Txn(pub u64);

/// One journaled authoritative delta (§1). `bytes` is the serialized
/// `W::Record`; the struct is named `LogRecord` so it does not collide with
/// the trait's `W::Record`. Every frame is [`Txn`]-tagged, so recovery groups
/// a transaction's records by identity rather than by file position (§1/§7).
#[derive(Serialize, Deserialize)]
struct LogRecord {
    pub seq: u64,
    pub txn: Txn,
    pub bytes: Vec<u8>,
}

/// One committed record as the fold consumes it: the coordinate it was
/// committed at, and the serialized `W::Record` bytes there — a [`LogRecord`]
/// minus its `txn`, which the group that closed it has already established.
/// Named for the only state in which one is ever read: a dead group releases
/// its records unread, so every one that reaches
/// [`ScanOutcome::committed_records`] came through `PendingTxn::commits`.
pub(crate) struct CommittedRecord {
    pub(crate) seq: u64,
    pub(crate) bytes: Vec<u8>,
}

/// Per-txn commit marker — the terminal frame of a transaction. In v1 a
/// committed marker (intact, durable, `records_checksum`-valid) *is* the
/// commit ack (§1). `records_checksum` is CRC32C over the concatenated payload
/// bytes of the txn's record frames, in `Seq` order — which is the order they
/// are framed in, so recovery reproduces it by streaming the frames as it
/// reads them. Distinct from the marker's own per-frame `crc`, and
/// byte-reproducible at recovery (§1/§7).
///
/// LAYOUT (`SKJ4`; bincode fixint LE, the fields positionally, no names): the
/// [`FramePayload`] tag (4), `txn` (8), `last_seq` (8), `records_checksum`
/// (4), `salt` (32 — a serde array is a tuple, no length prefix), `chain`
/// (32), `sig_alg` (1), `sig` (8 + n). NINETY-SEVEN bytes with the slot
/// empty, which [`MARKER_FRAME_LEN`] carries and the accounting test and the
/// golden fixture pin. The three fields appended since `SKJ2` sit AFTER
/// `records_checksum` — the salt (`SKJ4`) first, then the chain, the slot
/// LAST: `records_checksum` covers record frame payloads only, the marker's
/// own frame CRC covers whatever the marker holds, and resynchronization
/// reads the sync word and the header — so `PendingTxn::commits` and the
/// resync are untouched by any of the three, and a FILLED slot appends bytes
/// after `sig_alg` and moves no other marker byte (its frame's `len` and
/// `crc` differ, as any payload's must). The salt's place, before the chain,
/// is the preimage's own order: the chain is computed OVER the salt, so the
/// bytes it is computed over precede it, as `records_checksum` does.
///
/// Decoded through [`MarkerShadow`], the one door that holds the slot's
/// one-spelling-of-empty rule; the bytes are the struct's own.
#[derive(Serialize, Deserialize)]
#[serde(try_from = "MarkerShadow")]
struct Marker {
    pub txn: Txn,
    pub last_seq: u64,
    pub records_checksum: u32,
    /// THE SALT (`SKJ4`; the signed-ops re-base report's R1): thirty-two
    /// bytes DRAWN per transaction from the kernel's [`crate::SaltSource`] — OS
    /// entropy in production, a seeded stream in fixtures — stored here at
    /// commit and READ BACK from here by every replay, never regenerated,
    /// and hashed into `chain` after the marker's other pre-chain fields
    /// ([`ChainLink::close`]). Served by no route: `/chain?at=N` and
    /// `/health` serve the chain value alone, the feed carries no marker
    /// byte. That is what it is for — a reader holding `chain(N − 1)` and
    /// `chain(N)` off the wire cannot confirm a guess at transaction `N`'s
    /// bytes, since the preimage has thirty-two bytes that reader was never
    /// served. A chain input, so a marker whose salt is edited is a chain
    /// break at that transaction (the tamper matrix's case 16).
    pub salt: [u8; 32],
    /// THE CHAIN (QUEUE item 10, X1): this transaction's link of the commit
    /// chain — SHA-256 over its predecessor's value and this transaction's
    /// own bytes exactly as [`ChainLink`] states them, the salt among them.
    /// Bound to the stamp rather than tagged: a hash, unlike a signature, is
    /// recomputable from the bytes it covers, so a change of hash would be a
    /// re-chaining of every board — a format event by nature, and a tag
    /// would buy nothing. COMPUTED by the writer and RECOMPUTED by every
    /// replay; never zero-filled, so the bytes this field holds under
    /// `SKJ4` are the bytes it holds forever.
    pub chain: [u8; 32],
    /// The signature slot's tag (X2): which hybrid pair `sig` was made under.
    /// [`SIG_ALG_UNSIGNED`] (`0`) is the one value this build writes; the
    /// kernel reads the tag only to hold the one-spelling-of-empty rule at
    /// [`MarkerShadow`]'s door and never interprets the blob — a signed
    /// marker's verification is the verifier's, beside the table, fold-inert.
    pub sig_alg: u8,
    /// The signature under the pair `sig_alg` names — EMPTY under tag `0`,
    /// which costs eight bytes (the length prefix) per commit.
    pub sig: Vec<u8>,
}

/// The at-rest shadow of [`Marker`] — same fields, same order, so the frame
/// bytes are the struct's own — and the ONE door a marker re-enters memory
/// through. It holds the slot's rule: EMPTY has one spelling, tag `0` with no
/// bytes. Tag `0` with bytes (a signature under no pair) and a non-zero tag
/// with none (a pair that signed nothing) are refused at decode, so a marker
/// that spells them is an undecodable frame to the scan — treated as corrupt,
/// classified by run — rather than a second empty a later reader could
/// disagree about.
#[derive(Deserialize)]
struct MarkerShadow {
    txn: Txn,
    last_seq: u64,
    records_checksum: u32,
    salt: [u8; 32],
    chain: [u8; 32],
    sig_alg: u8,
    sig: Vec<u8>,
}

impl TryFrom<MarkerShadow> for Marker {
    type Error = &'static str;
    fn try_from(shadow: MarkerShadow) -> Result<Marker, &'static str> {
        if (shadow.sig_alg == SIG_ALG_UNSIGNED) != shadow.sig.is_empty() {
            return Err(
                "a commit marker's signature slot has one spelling of empty: tag 0 with no bytes",
            );
        }
        Ok(Marker {
            txn: shadow.txn,
            last_seq: shadow.last_seq,
            records_checksum: shadow.records_checksum,
            salt: shadow.salt,
            chain: shadow.chain,
            sig_alg: shadow.sig_alg,
            sig: shadow.sig,
        })
    }
}

/// The serde-tagged frame payload (§1).
#[derive(Serialize, Deserialize)]
enum FramePayload {
    Record(LogRecord),
    Marker(Marker),
}

/// THE CODEC — the one configuration of bincode 1 every byte this crate
/// writes or reads goes through: the frame payloads, the `W::Record` bytes
/// inside them, and the checkpoint body (the seven production sites and every
/// test fixture that pins bytes). Its settings, each load-bearing:
///
/// * FIXED-WIDTH integers — a `u64` is eight bytes whatever its value, a
///   length prefix is a `u64`, an enum tag a `u32`, a `bool` or `u8` one
///   byte, an `Option` one tag byte then its payload, a struct or tuple its
///   fields in declaration order with no names and no count, a newtype its
///   inner value with nothing added, an array a tuple with no prefix;
/// * LITTLE-ENDIAN;
/// * NO byte limit (the frame cap and the transaction budget bound the bytes
///   before the codec sees them);
/// * TRAILING BYTES REJECTED on decode — the decoder accepts exactly the
///   encoder's output, so a frame payload, record or checkpoint body carrying
///   bytes past its value is a decode refusal (`Corruption` at replay, a
///   skipped base at load) rather than a silent pass. This is the read-side
///   half of "one byte-form per value".
///
/// The first three are the configuration bincode's free functions used under
/// `SKJ2`, so no byte moved for the codec's sake at the `SKJ3` bump — the
/// format moved for the marker's; the fourth is new and changes no written
/// byte. A function rather than a `const` because bincode 1's options are a
/// type-state builder with no `const fn`; the value is `Copy`, so a call site
/// takes a fresh one: `codec().serialize(&v)`, `codec().deserialize(bytes)`.
/// The workspace pins `bincode = "=1.3.3"`, and the golden fixtures under
/// `tests/golden/` pin this configuration's output byte for byte: a release
/// of bincode or serde that moved a width, a tag or a shadow fails there by
/// name.
pub(crate) fn codec() -> impl Options + Copy {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_little_endian()
        .with_no_limit()
        .reject_trailing_bytes()
}

/// A decode refusal as the `io::Error` it is: bytes read off a disk that do
/// not hold what their format says, which is exactly what
/// [`io::ErrorKind::InvalidData`] names. Only the read side wraps — an encode
/// touches no file, so its refusal travels as the serializer's own error.
fn invalid_data(e: bincode::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

/// One `W::Record`'s wire form — the `bytes` a [`LogRecord`] frame carries,
/// under [`codec`].
///
/// Stated as a pair with [`decode_record`], here, because the encode and the
/// decode are one agreement: a change to either that the other does not match
/// turns every healthy journal into one that cannot be replayed. M2 never
/// inspects a record, so the serializer's own account is the whole of what
/// identifies a refusal, and it travels unwrapped: the encode precedes every
/// file operation, so nothing it can answer with is a disk's failure.
pub(crate) fn encode_record<R: Serialize>(record: &R) -> Result<Vec<u8>, bincode::Error> {
    codec().serialize(record)
}

/// Read back what [`encode_record`] wrote. `Err` is a committed, CRC-intact
/// record that does not decode as this `W::Record` — corrupt committed data,
/// or a writer/reader skew, either way something the fold cannot supply and
/// must not skip (§7). Trailing bytes are a refusal here too ([`codec`]).
pub(crate) fn decode_record<R: DeserializeOwned>(bytes: &[u8]) -> io::Result<R> {
    codec().deserialize(bytes).map_err(invalid_data)
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
/// fsync (§1/§3), and answer the chain value the marker carries — this
/// transaction's link, computed from `prev_chain`, the frames as they are
/// built and `salt` ([`ChainLink`]), which the writer adopts once the barrier
/// passes. `salt` is the transaction's own, drawn by
/// [`JournalWriter::commit_txn`] from the kernel's [`crate::SaltSource`] before
/// this is called, and it goes two places from here: into the marker, where
/// every replay reads it back, and into the link, closed with it after the
/// marker's other pre-chain fields. The bytes are consumed into their frames:
/// the caller has no use for them past this call, and a commit is no place
/// to copy every record a second time.
///
/// The `Seq` arithmetic here stays in range because the coordinates were
/// already minted: [`crate::Kernel::transact`] draws the whole range
/// `first_seq..=first_seq + (n - 1)` from the kernel's sequencer — the one
/// mint site — through a checked add before any of it reaches this function
/// (§2). The parenthesisation is load-bearing at the ceiling:
/// `first_seq + (n - 1)` computes no intermediate above the last coordinate
/// the range legitimately holds.
///
/// The assertion below guards the FRAME BUILDER's own boundary, which
/// [`JournalWriter::commit_txn`] reaches and the test tier calls directly.
/// [`Journal::commit_txn`] asserts the same rule at its own entry, for a
/// reason of its own: there it is what makes the two durability arms answer a
/// violation alike.
fn encode_txn(
    first_seq: u64,
    record_bytes: Vec<Vec<u8>>,
    prev_chain: &[u8; 32],
    salt: [u8; 32],
    attest: Option<&Attestation>,
) -> io::Result<(Vec<u8>, [u8; 32])> {
    let n = record_bytes.len() as u64;
    assert!(n > 0, "zero-step ops never reach the journal");
    let txn = Txn(first_seq);
    // The exact figure, not a guess: [`txn_encoded_len`] is what this function
    // emits, pinned to it by the accounting test. Reserving it is what holds
    // the commit region to the two copies of a transaction's bytes its own
    // contract budgets for — a doubling `Vec` transiently holds a third.
    let mut buf = Vec::with_capacity(txn_encoded_len(&record_bytes, attest) as usize);
    let mut checksum = 0u32;
    let mut link = ChainLink::open(prev_chain);
    for (i, bytes) in record_bytes.into_iter().enumerate() {
        let payload = codec()
            .serialize(&FramePayload::Record(LogRecord {
                seq: first_seq + i as u64,
                txn,
                bytes,
            }))
            .map_err(invalid_data)?;
        checksum = crc32c::crc32c_append(checksum, &payload);
        link.add_payload(&payload);
        push_frame(&mut buf, &payload)?;
    }
    let last_seq = first_seq + (n - 1);
    let chain = link.close(txn, last_seq, checksum, &salt);
    // THE SLOT (signed ops): the attestation's pair, where the transaction
    // carries one, else the one spelling of empty. Written AFTER the chain is
    // closed, so the slot is no chain input by construction — a signature
    // over the entry's content must sit outside the chain that covers it.
    let (sig_alg, sig) = match attest {
        Some(a) => (a.sig_alg(), a.sig().to_vec()),
        None => (SIG_ALG_UNSIGNED, Vec::new()),
    };
    let payload = codec()
        .serialize(&FramePayload::Marker(Marker {
            txn,
            last_seq,
            records_checksum: checksum,
            salt,
            chain,
            sig_alg,
            sig,
        }))
        .map_err(invalid_data)?;
    push_frame(&mut buf, &payload)?;
    Ok((buf, chain))
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
/// [`Marker`] payload with its slot EMPTY — tag (4), `txn` (8), `last_seq`
/// (8), `records_checksum` (4), `salt` (32), `chain` (32), `sig_alg` (1),
/// `sig`'s length prefix (8): 97, so 109 in all. Pinned alongside
/// [`RECORD_PAYLOAD_OVERHEAD`]. The EMPTY slot's pin, and it stays one: a
/// FILLED slot appends the blob's own bytes after this figure, which the two
/// sites this seeds treat differently, by design (signed ops, the design
/// record §4.4 (b)) — [`txn_encoded_len`] counts them, because it is what
/// [`encode_txn`] EMITS and reserves; [`Journal::commit_txn`]'s budget does
/// NOT, because the slot sits OUTSIDE [`MAX_TXN_BYTES`]'s accounting: the
/// budget bounds the RECORDS a staging holds, and an attested transaction
/// answers no refusal an unattested one would not, a `publish` shot being
/// unsplittable. What a filled slot moves is the marker frame's own size
/// (its `len` and CRC), far under [`MAX_FRAME_LEN`] at any tag's width, and
/// the memory floor M2 promises a replica by the blob's width — the price
/// the design record states and takes.
const MARKER_FRAME_LEN: u64 = frame_len(97);

/// What one framed payload occupies in a segment: the header [`push_frame`]
/// writes, plus the payload it wraps. The outer of the two levels every
/// figure here is built from.
const fn frame_len(payload_len: u64) -> u64 {
    (FRAME_HEADER_LEN as u64).saturating_add(payload_len)
}

/// The frame PAYLOAD one already-encoded record occupies: its own bytes plus
/// what [`encode_txn`] wraps around them ([`RECORD_PAYLOAD_OVERHEAD`]). The
/// inner level — and the figure [`push_frame`] judges against
/// [`MAX_FRAME_LEN`], so [`Journal::commit_txn`]'s size gate and that guard
/// compare one named quantity rather than two spellings of it.
const fn record_payload_len(record_len: usize) -> u64 {
    RECORD_PAYLOAD_OVERHEAD.saturating_add(record_len as u64)
}

/// What one already-encoded record occupies in the journal: both levels
/// together. The ONE spelling of a record's cost on the WRITE side, so the
/// running charge in [`Journal::commit_txn`] and the reservation
/// [`encode_txn`] takes from [`txn_encoded_len`] cannot disagree about what
/// is being built.
///
/// A reader has the framed payload rather than the record's own bytes, so
/// `PendingTxn` reaches the same figure by the other route —
/// [`frame_len`] over what it holds — and the accounting test pins the two
/// equal.
const fn record_frame_len(record_len: usize) -> u64 {
    frame_len(record_payload_len(record_len))
}

/// The exact byte length [`encode_txn`] emits for these already-encoded
/// records: each record frame ([`record_frame_len`]) plus the terminal marker
/// frame — the EMPTY marker's pin plus the slot's blob where the transaction
/// carries an [`Attestation`] (the blob rides inside the marker's `sig` field,
/// whose length prefix the pin already counts). Saturating, so a sum no
/// allocator could hold refuses as over-budget rather than wrapping back
/// under the budget.
pub(crate) fn txn_encoded_len(record_bytes: &[Vec<u8>], attest: Option<&Attestation>) -> u64 {
    let marker = MARKER_FRAME_LEN.saturating_add(attest.map_or(0, |a| a.sig().len() as u64));
    record_bytes.iter().fold(marker, |total, bytes| {
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

/// Read back the frame [`push_frame`] wrote, at `pos`.
///
/// Stated as a pair with [`push_frame`], because the layout and the parse are
/// one agreement: a change to either that the other does not match makes
/// every frame of every healthy journal unreadable, which recovery meets as
/// corruption rather than as the writer/reader skew it is.
///
/// Nothing is believed before it is checked, and the ORDER is what makes the
/// checks mean anything: the header must be present, then carry the sync
/// word, then claim a `len` inside [`MAX_FRAME_LEN`] that does not overrun
/// the buffer — and only then is the CRC computed, over the `len` field AND
/// the payload, so a corrupt length is detected here rather than silently
/// mis-delimiting the frame that follows (§1). [`Parsed::Intact`] is
/// therefore what every later stage may trust without re-checking, and
/// [`Parsed::Bad`]'s `crc_bytes` says which of those doors refused.
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

#[cfg(test)]
mod tests;
