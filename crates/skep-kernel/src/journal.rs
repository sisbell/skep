//! The journal, the only durable, authoritative state M2 owns.
//!
//! The log is the truth, and in-memory structures are hints (§Core data
//! model; Lampson).
//!
//! Frames: `[u32 magic][u32 len][u32 crc][payload]`, where the fixed `magic`
//! sync word anchors recovery resynchronization (§7) and `crc` covers both the
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
//! types, the codec every value the crate serializes goes through, and the
//! size accounting. Its children are the operations over it — `writer` appends
//! (the barrier, the install hand-off, the repair after a failed commit),
//! `scan` reads (recovery's Pass 1, its verdicts, the tail cut, the format
//! probe, and the same pass collecting the committed boundaries with their
//! slots), `segment` names, lists and reclaims the files, `chain` spells the
//! commit chain's one link, and `attest` is the signature slot's public type.
//! The children see this file's private items; the rest of the crate sees
//! what is marked `pub` or `pub(crate)` here and the re-export block below.

mod attest;
mod chain;
mod scan;
mod segment;
mod writer;

pub use attest::Attestation;
pub use attest::AttestationError;
pub use attest::MAX_SIG_BYTES;
pub(crate) use chain::CHAIN_GENESIS;
pub(crate) use scan::damaged_sync_word_cause;
pub(crate) use scan::first_sync_word;
pub(crate) use scan::scan;
pub(crate) use scan::scan_boundaries;
pub(crate) use scan::truncate_tail;
pub(crate) use scan::ClosingMarker;
pub(crate) use scan::FirstSyncWord;
pub(crate) use scan::ScanFail;
pub(crate) use scan::ScanOutcome;
pub(crate) use segment::acquire_journal_lock;
pub(crate) use segment::dir_builder;
pub(crate) use segment::file_options;
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
use chain::{slot_digest, ChainLink};

/// The per-frame sync word anchoring recovery resynchronization (§1/§7).
///
/// It is also the journal's format stamp: the trailing numeral names the
/// format that wrote the frame. Under `SKJ4` the genesis the records fold
/// onto carries the ghost-tumbler reserved types and no `GenesisConfig`, so a
/// journal written under the 9-space regime does not reopen as this format's;
/// the commit marker carries its chain field and signature slot, the codec is
/// pinned behind [`codec`], and the checkpoint beside it is canonical; and the
/// commit marker carries a per-transaction random salt that the chain's
/// preimage hashes (the signed-ops re-base report's R1), so no chain value is
/// an unsalted one's — the marker doc's own definition of a format event —
/// and the checkpoint's stamp is `SKC4` beside it, its `chain_head` being a
/// value under the salted rule. The first segment a scan reads, opening with
/// another format's sync word, is refused by name at `open`
/// ([`first_sync_word`]) rather than read as this one's; a segment the base
/// embodies is not read, and so not probed.
pub(crate) const MAGIC: [u8; 4] = *b"SKJ4";
/// The journal's format stamp, as a caller above the kernel names it.
///
/// The callers are the daemon's version line, which says at every open which
/// formats the build reads, and the published head record's `format` member:
/// `MAGIC`'s four bytes, `SKJ4`, read as ASCII the way the kernel's own
/// refusal spells a stamp. One value with the sync word, defined from it;
/// re-exported at the crate root beside [`MAX_SEGMENT_LEN`].
pub const JOURNAL_FORMAT: [u8; 4] = MAGIC;
/// The stamp's fixed prefix: what makes four bytes a well-formed sync word.
///
/// A journal sync word of *some* format: [`first_sync_word`] tells such a
/// word (`SKJ` + a fourth byte that is not this build's numeral) from damage
/// that is not one (anything else) by it — and, since every one-bit flip of
/// this build's numeral keeps the prefix, tells a format from *one* damaged
/// word by the frame after it.
const STAMP_PREFIX: &[u8; 3] = b"SKJ";
/// The frame header's length: magic (4) + len (4) + crc (4).
pub(crate) const FRAME_HEADER_LEN: usize = 12;
/// The sanity bound on a single frame's payload: the journal's frame cap.
///
/// It is the open build decision's max frame size, and what every mention of
/// the frame cap here names. The writer enforces it, so recovery may treat a
/// larger claimed `len` as corrupt.
///
/// A format constant for that reason, never a pin the design moves alone:
/// recovery holds every journal to it, so a build that lowered it under an
/// unchanged [`MAGIC`] would read an older build's honest frame as a corrupt
/// run — a halt mid-history, an acknowledged transaction cut as the tail at
/// the end — and a build that raised it would write frames an older one reads
/// so. It moves only with the stamp, so a journal written under the old
/// figure is refused by name before a byte of it is scanned, with PUB-1.2's
/// remedy; `src/journal/tests.rs` pins it beside the stamps.
pub(crate) const MAX_FRAME_LEN: u32 = 64 * 1024 * 1024;
/// The most bytes one transaction may occupy in the journal.
///
/// It counts the record frames, commit marker and headers together, the
/// signature slot's blob excepted: that is the marker's own, at most
/// [`MAX_SIG_BYTES`] more. A transaction past it whose records all frame is
/// refused with [`crate::TxnError::OverBudget`], in both durability modes,
/// before anything is appended or installed, so this is the figure a caller
/// splitting an over-budget transaction must get under.
///
/// Equal to the journal's frame cap as a relationship, not a free knob: a
/// transaction is at most one frame's worth and a slot's, so a segment —
/// which rotates only at a transaction boundary — is at most one rotation
/// threshold plus one frame and one slot, and recovery, which reads a segment
/// whole, has a memory floor that is bounded and identical on every replica.
/// Untie the two and the second clause fails where it hurts: a transaction
/// never spans a segment, so one oversized transaction permanently raises the
/// floor of every later [`crate::Kernel::open`] and every
/// [`crate::Kernel::world_at`] above that base — a journal that opens on the
/// machine that wrote it and not on the replica. The reader holds the floor
/// as well as the writer: a segment longer than twice this figure is refused
/// on its length alone, before the scan reads a byte of it.
///
/// Being equal rather than nested, the two limits do not stack: a transaction
/// carries its records' frames and a commit marker, so the largest record this
/// budget admits is smaller than the largest the frame cap admits, and the top
/// of the frame cap is unreachable in practice. A record in that band frames
/// and cannot commit, which is the one case where
/// [`crate::TxnError::OverBudget`]'s remedy is to shrink the record rather
/// than to split the transaction — as that variant states.
///
/// A format constant, as the frame cap it equals is: the reader holds every
/// journal to it — a group past it never commits, and the marker after it
/// reads as rewritten — and [`MAX_SEGMENT_LEN`] is twice it. So a build that
/// moved it under an unchanged stamp would read another build's honest
/// journal as damage, with no golden byte moving to say so. It moves only
/// with [`JOURNAL_FORMAT`].
pub const MAX_TXN_BYTES: u64 = MAX_FRAME_LEN as u64;
/// The rotation threshold (open build decision).
///
/// It is tested before a transaction is appended and only at a txn boundary
/// — so a closed segment holds at most this many bytes plus one whole
/// transaction, and a caller bounding memory or file size reckons with that
/// transaction rather than with this figure. Rotating at txn boundaries only
/// is what keeps a txn's frames from spanning a segment; under per-commit
/// Fsync the old segment is already durable at rotation (its last txn's
/// barrier fsynced it), preserving marker-as-ack across the boundary (§1).
///
/// A pin, not a format constant: no reader holds a journal to it — a closed
/// segment's reach is read off its successor's name, never off this figure —
/// so the design may move it under one stamp, within the assertion below.
const SEGMENT_ROTATE_BYTES: u64 = 1024 * 1024;
/// The longest segment this module reads: twice the transaction budget.
///
/// The writer appends only to a segment under `SEGMENT_ROTATE_BYTES`, and a
/// transaction is at most [`MAX_TXN_BYTES`] plus its slot's blob, at most
/// [`MAX_SIG_BYTES`], so no segment this journal's writer produces reaches it
/// (asserted below); a file past it is damage, or not this writer's, and
/// reading it whole would size an allocation by the file's own claim. It is
/// what makes the memory floor [`MAX_TXN_BYTES`] promises a fact about the
/// reader as well as the writer. Twice the budget rather than the writer's
/// exact maximum, so a later build that lowers the rotation threshold never
/// refuses a segment an earlier one wrote: this moves only with the format,
/// as the budget it doubles does.
///
/// Public as the one figure for "one maximal segment": a caller holding a
/// volume's free space above a floor reserves this much for the segment in
/// flight beside the next checkpoint, and reads it from here rather than
/// transcribing it.
pub const MAX_SEGMENT_LEN: u64 = 2 * MAX_TXN_BYTES;
// …which holds only while a segment under the threshold, plus one whole
// transaction at the budget, plus its slot at the cap, fits under it: the
// writer appends to a segment under `SEGMENT_ROTATE_BYTES`, and the slot sits
// outside the budget. A threshold or a cap moved past this lets an honest
// segment pass the ceiling — a commit acknowledged that the next open refuses.
const _: () =
    assert!(SEGMENT_ROTATE_BYTES - 1 + MAX_TXN_BYTES + MAX_SIG_BYTES as u64 <= MAX_SEGMENT_LEN);
/// The resynchronization budget, as a multiple of a segment's own size.
///
/// It is how many bytes of CRC a scan will spend on rejected frame candidates
/// before it gives up on enumerating that segment's frame stream (§7). A work
/// allowance on the read path — the one budget here that is not the write
/// path's [`MAX_TXN_BYTES`], which is why the frame cap is named in full
/// wherever it appears below.
///
/// The sequential walk needs no budget — an intact frame's CRC covers exactly
/// the bytes it advances over, so the walk sums to one pass — and this bounds
/// the other work. A candidate the resync lands on charges the payload length
/// it *claims*, which its advance does not bound: the resync moves four bytes
/// and the claim may reach [`MAX_FRAME_LEN`], so without a budget a record
/// whose own bytes plant frame headers makes the scan quadratic in a size that
/// record's author chose.
///
/// The figure: a whole scan then costs at most this many passes over a
/// segment, plus one candidate in flight, so the worst crafted 64 MiB segment
/// spends 512 MiB of CRC — a twentieth of a second at hardware rates. Honest
/// journals spend almost none of it, because a candidate must clear the magic
/// word and a length inside the frame cap before its CRC is computed at all:
/// the sync word occurs by chance about once per 2^32 bytes, and a randomly
/// damaged length field lands inside the frame cap about once in 64, so
/// tripping eight segment-sized candidates by accident is a ~10^-15 event.
/// Crafted content trips it after a few dozen.
///
/// A pin, as the rotation threshold is: it bounds only the work a scan
/// spends reading through damage, so moving it changes how much damage a scan
/// reads before it refuses, never whether an honest journal opens — and the
/// design may move it under one stamp.
const RESYNC_BUDGET_PASSES: u64 = 8;

/// A transaction's identity: its first `Seq` (§1).
///
/// A distinguished `Seq`, never a separate counter, which is why it is
/// unique within any scanned journal region and recovered for free with the
/// single `Seq` high-water (§1/§7). Seqs travel this layer as raw `u64`;
/// typing the identity is what keeps a frame's `seq` and its `txn` from being
/// interchanged.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
struct Txn(pub u64);

/// One journaled authoritative delta (§1).
///
/// `bytes` is the serialized `W::Record`; the struct is named `LogRecord` so
/// it does not collide with the trait's `W::Record`. Every frame is
/// [`Txn`]-tagged, so recovery groups a transaction's records by identity
/// rather than by file position (§1/§7).
#[derive(Serialize, Deserialize)]
struct LogRecord {
    pub seq: u64,
    pub txn: Txn,
    pub bytes: Vec<u8>,
}

/// One committed record as the fold consumes it.
///
/// The coordinate it was committed at, and the serialized `W::Record` bytes
/// there — a [`LogRecord`] minus its `txn`, which the group that closed it has
/// already established. Named for the only state in which one is ever read: a
/// dead group releases its records unread, so every one that reaches
/// [`ScanOutcome::committed_records`] came through `PendingTxn::commits`.
pub(crate) struct CommittedRecord {
    pub(crate) seq: u64,
    pub(crate) bytes: Vec<u8>,
}

/// Per-txn commit marker: the terminal frame of a transaction.
///
/// In v1 a committed marker — intact, durable, and `records_checksum`-valid
/// over a `Seq`-ascending group that its own `last_seq` closes and that fits
/// the per-transaction budget — *is* the commit ack (§1). `records_checksum`
/// is CRC32C over the concatenated payload bytes of the txn's record frames,
/// in `Seq` order — which is the order they are framed in, so recovery
/// reproduces it by streaming the frames as it reads them. Distinct from the
/// marker's own per-frame `crc`, and byte-reproducible at recovery (§1/§7).
///
/// **Layout** (`SKJ4`; bincode fixint LE, the fields positionally, no
/// names): the [`FramePayload`] tag (4), `txn` (8), `last_seq` (8),
/// `records_checksum` (4), `salt` (32 — a serde array is a tuple, no length
/// prefix), `chain` (32), `sig_alg` (1), `sig` (8 + n). Ninety-seven bytes
/// with the slot empty, which [`MARKER_FRAME_LEN`] carries and the accounting
/// test and the golden fixture pin. The three fields an `SKJ2` marker lacks
/// sit after `records_checksum` — the salt (`SKJ4`) first, then the chain,
/// the slot last: `records_checksum` covers record frame payloads only, the
/// marker's own frame CRC covers whatever the marker holds, and
/// resynchronization reads the sync word and the header — so
/// `PendingTxn::commits` and the resync are untouched by any of the three,
/// and a filled slot appends bytes after `sig_alg` and moves no other marker
/// byte (its frame's `len` and `crc` differ, as any payload's must). The
/// salt's place, before the chain, is the preimage's own order: the chain is
/// computed over the salt, so the bytes it is computed over precede it, as
/// `records_checksum` does. The slot is the one input stored *after* the
/// field it feeds — its digest closes the link after the salt ([`ChainLink`])
/// — and it stays last for the layout's own reason: a filled slot moves no
/// other marker byte.
///
/// Decoded through [`MarkerShadow`], the one door a marker re-enters memory
/// through, which asks the slot rule ([`attest::slot`]); the bytes are the
/// struct's own.
#[derive(Serialize, Deserialize)]
#[serde(try_from = "MarkerShadow")]
struct Marker {
    pub txn: Txn,
    pub last_seq: u64,
    pub records_checksum: u32,
    /// The salt (`SKJ4`; the signed-ops re-base report's R1).
    ///
    /// Thirty-two bytes drawn per transaction from the kernel's
    /// [`crate::SaltSource`] — OS entropy in production, a seeded stream in
    /// fixtures — stored here at commit and read back from here by every
    /// replay, never regenerated, and hashed into `chain` after the marker's
    /// other pre-chain fields ([`ChainLink::close`]). Served by no route:
    /// `/chain?at=N` and `/health` serve the chain value alone, and the feed
    /// carries no marker byte but the signature slot's (`GET /changes`'s
    /// `attest` member). That is what it is for — a reader holding
    /// `chain(N − 1)` and `chain(N)` off the wire cannot confirm a guess at
    /// transaction `N`'s bytes, since the preimage has thirty-two bytes that
    /// reader was never served. A chain input, so a marker whose salt is
    /// edited is a chain break at that transaction (the tamper matrix's case
    /// 16).
    pub salt: [u8; 32],
    /// The chain (X1): this transaction's link of the commit chain.
    ///
    /// SHA-256 over its predecessor's value and this transaction's own bytes
    /// exactly as [`ChainLink`] states them, the salt among them. Bound to the
    /// stamp rather than tagged: a hash, unlike a signature, is recomputable
    /// from the bytes it covers, so a change of hash would be a re-chaining of
    /// every journal — a format event by nature, and a tag would buy nothing.
    /// Computed by the writer and recomputed by every replay from a base
    /// below it; never zero-filled, so the bytes this field holds under `SKJ4`
    /// are the bytes it holds forever.
    pub chain: [u8; 32],
    /// The signature slot's tag (X2): which hybrid pair `sig` was made under.
    ///
    /// [`SIG_ALG_UNSIGNED`] (`0`) is what every unattested transaction writes;
    /// the kernel reads the tag to hold the one-spelling-of-empty rule at
    /// [`MarkerShadow`]'s door and to hash the slot's bytes into `chain`
    /// ([`chain::slot_digest`]), and never interprets the blob — an attested
    /// marker's verification is the verifier's, beside the table, fold-inert.
    pub sig_alg: u8,
    /// The signature under the pair `sig_alg` names, empty under tag `0`.
    ///
    /// The empty slot costs nine bytes per commit: the tag and this field's
    /// length prefix. With the tag, a chain input by digest: a slot stripped
    /// or altered in a committed marker is a chain break at that transaction
    /// (the tamper matrix's case 4).
    pub sig: Vec<u8>,
}

/// The at-rest shadow of [`Marker`]: same fields, same order.
///
/// So the frame bytes are the struct's own — and it is the one door a marker
/// re-enters memory through. It asks the slot rule ([`attest::slot`]), the
/// very rule [`Attestation::new`] asks: empty has one spelling, tag `0` with
/// no bytes, and tag `0` with bytes (a signature under no pair), a non-zero
/// tag with none (a pair that signed nothing) and a blob wider than
/// [`MAX_SIG_BYTES`] are refused at decode, so a marker that spells them is an
/// undecodable frame to the scan — treated as corrupt, classified by run —
/// rather than a second empty a later reader could disagree about, or a slot
/// no [`Attestation`] could hold.
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
        let (sig_alg, sig) = match attest::slot(shadow.sig_alg, shadow.sig) {
            Ok(None) => (SIG_ALG_UNSIGNED, Vec::new()),
            Ok(Some(attestation)) => attestation.into_parts(),
            // One arm per refusal, no wildcard: a rule the slot gains must
            // name its account here before this compiles.
            Err(AttestationError::UnsignedTag | AttestationError::EmptyBlob) => {
                return Err(
                    "a commit marker's signature slot has one spelling of empty: tag 0 with no \
                     bytes",
                )
            }
            Err(AttestationError::TooWide { .. }) => {
                return Err(
                    "a commit marker's signature slot is wider than any attestation this kernel \
                     commits",
                )
            }
        };
        Ok(Marker {
            txn: shadow.txn,
            last_seq: shadow.last_seq,
            records_checksum: shadow.records_checksum,
            salt: shadow.salt,
            chain: shadow.chain,
            sig_alg,
            sig,
        })
    }
}

/// The serde-tagged frame payload (§1).
#[derive(Serialize, Deserialize)]
enum FramePayload {
    Record(LogRecord),
    Marker(Marker),
}

/// Returns the codec, the one configuration of bincode 1 the crate uses.
///
/// Every value this crate serializes or deserializes goes through it: the
/// frame payloads, the `W::Record` bytes inside them, and the checkpoint body
/// (the seven production sites and every test fixture that pins bytes). Its
/// settings, each load-bearing:
///
/// * fixed-width integers — a `u64` is eight bytes whatever its value, a
///   length prefix is a `u64`, an enum tag a `u32`, a `bool` or `u8` one
///   byte, an `Option` one tag byte then its payload, a struct or tuple its
///   fields in declaration order with no names and no count, a newtype its
///   inner value with nothing added, an array a tuple with no prefix;
/// * little-endian;
/// * no byte limit (the frame cap and the transaction budget bound a frame's
///   bytes before the codec sees them) — and the checkpoint body streams in
///   one pass because of it: bincode 1's `serialize_into` walks a value a
///   first time, to size it, only where a limit is set, so a limit added here
///   would make that size pass over the whole world at every checkpoint
///   (`checkpoint::write`), which is why there is none;
/// * trailing bytes rejected on decode — the decoder accepts exactly the
///   encoder's output, so a frame payload, record or checkpoint body carrying
///   bytes past its value is a decode refusal (`Corruption` at replay — save
///   a frame payload of the journal's last transaction, which the open's tail
///   cut takes — and a skipped base at load) rather than a silent pass. This
///   is the read-side half of "one byte-form per value" — the codec's half;
///   the order a value's own `Serialize` visits a map or a set is
///   [`crate::WorldState`]'s canonical-encoding obligation, which no codec
///   setting can fix.
///
/// The first three are the configuration of bincode's free functions, which
/// `SKJ2`'s frames share, so between `SKJ2` and this format no byte moves
/// for the codec's sake — the format moves for the marker's; the fourth
/// changes no written byte. A function rather than a `const` because
/// bincode 1's options are a type-state builder with no `const fn`; the
/// value is `Copy`, so a call site takes a fresh one: `codec().serialize(&v)`,
/// `codec().deserialize(bytes)`. The workspace pins `bincode = "=1.3.3"`, and
/// the golden fixtures under `tests/golden/` pin this configuration's output
/// byte for byte: a release of bincode or serde that moved a width, a tag or
/// a shadow fails there by name.
pub(crate) fn codec() -> impl Options + Copy {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_little_endian()
        .with_no_limit()
        .reject_trailing_bytes()
}

/// Returns a frame payload's serialize refusal as an `io::Error`.
///
/// It is the error [`encode_txn`] answers with, beside [`push_frame`]'s own
/// refusal of that kind: [`io::ErrorKind::InvalidData`] names a payload that
/// cannot be framed. Unreachable in practice — a payload is fixed-width
/// fields and byte vectors, which the codec always encodes — and a record's
/// own refusals are judged before any payload is built
/// ([`Journal::commit_txn`]), where they travel as the serializer's own error
/// or the frame cap's.
fn invalid_data(e: bincode::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

/// Returns one `W::Record`'s wire form, the `bytes` a [`LogRecord`] carries.
///
/// It is encoded under [`codec`]. Stated as a pair with [`decode_record`],
/// here, because the encode and the decode are one agreement: a change to
/// either that the other does not match turns every healthy journal into one
/// that cannot be replayed.
///
/// # Errors
///
/// The serializer's refusal. M2 never inspects a record, so the serializer's
/// own account is the whole of what identifies a refusal, and it travels
/// unwrapped: the encode precedes every file operation, so nothing it can
/// answer with is a disk's failure.
pub(crate) fn encode_record<R: Serialize>(record: &R) -> Result<Vec<u8>, bincode::Error> {
    codec().serialize(record)
}

/// Reads back what [`encode_record`] wrote.
///
/// # Errors
///
/// `Err` is a committed, CRC-intact record that does not decode as this
/// `W::Record` — corrupt committed data, or a writer/reader skew, either way
/// something the fold cannot supply and must not skip (§7) — and it travels
/// as the serializer's own refusal, unwrapped, as [`encode_record`]'s does:
/// that account is the whole of what tells the two apart. Trailing bytes are
/// a refusal here too ([`codec`]).
pub(crate) fn decode_record<R: DeserializeOwned>(bytes: &[u8]) -> Result<R, bincode::Error> {
    codec().deserialize(bytes)
}

/// Appends one framed payload to `buf`.
///
/// The frame is `[magic][len][crc(len+payload)][payload]`.
///
/// # Errors
///
/// A payload past [`MAX_FRAME_LEN`] is refused as
/// [`io::ErrorKind::InvalidData`], before a byte is appended.
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

/// Encodes one whole transaction: its record frames, then its commit marker.
///
/// The record frames carry seqs `first_seq..` and the terminal marker closes
/// them, ready for a single `write_all` + one barrier fsync (§1/§3). It
/// answers the chain value the marker carries — this transaction's link,
/// computed from `prev_chain`, the record payloads as they are framed, the
/// marker's pre-chain fields, `salt` and the digest of the slot `attestation`
/// fills ([`ChainLink`]), which the writer adopts once the barrier passes.
/// `salt` is the transaction's own, drawn by [`JournalWriter::commit_txn`]
/// from the kernel's [`crate::SaltSource`] before this is called, and it goes
/// two places from here: into the marker, where every replay reads it back,
/// and into the link, closed with it after the marker's other pre-chain
/// fields. The slot goes the same two places — spelled into the marker's last
/// two fields, and hashed into the link after the salt — so it is an input to
/// this function's link and nothing is ordered around it. The bytes are
/// consumed into their frames: the caller has no use for them past this call,
/// and a commit is no place to copy every record a second time.
///
/// The `Seq` arithmetic here stays in range because the coordinates were
/// already minted: [`crate::Kernel::transact`] draws the whole range
/// `first_seq..=first_seq + (n - 1)` from the kernel's sequencer — the one
/// mint site — through a checked add before any of it reaches this function
/// (§2). The parenthesisation is load-bearing at the ceiling:
/// `first_seq + (n - 1)` computes no intermediate above the last coordinate
/// the range legitimately holds.
///
/// # Errors
///
/// [`io::ErrorKind::InvalidData`] where a frame payload does not serialize
/// ([`invalid_data`]) or exceeds the frame cap ([`push_frame`]).
///
/// # Panics
///
/// Panics where `record_bytes` is empty. The assertion guards the frame
/// builder's own boundary, which [`JournalWriter::commit_txn`] reaches and
/// the test tier calls directly. [`Journal::commit_txn`] asserts the same
/// rule at its own entry, for a reason of its own: there it is what makes the
/// two durability arms answer a violation alike.
fn encode_txn(
    first_seq: u64,
    record_bytes: Vec<Vec<u8>>,
    prev_chain: &[u8; 32],
    salt: [u8; 32],
    attestation: Option<&Attestation>,
) -> io::Result<(Vec<u8>, [u8; 32])> {
    let n = record_bytes.len() as u64;
    assert!(n > 0, "zero-step ops never reach the journal");
    let txn = Txn(first_seq);
    // The exact figure, not a guess: [`txn_encoded_len`] is what this function
    // emits, pinned to it by the accounting test. Reserving it is what holds
    // the commit region to the two copies of a transaction's bytes its own
    // contract budgets for — a doubling `Vec` transiently holds a third.
    let mut buf = Vec::with_capacity(txn_encoded_len(&record_bytes, attestation) as usize);
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
    // The slot (signed ops): the attestation's pair, where the transaction
    // carries one, else the one spelling of empty — and a chain input: its
    // digest closes the link after the salt, at every transaction, so a slot
    // stripped or altered after this commit is a chain break at it. A
    // signature over the entry's content, made before the commit, sits
    // outside the chain that covers it all the same: the chain covers the
    // signature, not the other way round.
    let (sig_alg, sig) = match attestation {
        Some(a) => (a.sig_alg(), a.sig().to_vec()),
        None => (SIG_ALG_UNSIGNED, Vec::new()),
    };
    let chain = link.close(txn, last_seq, checksum, &salt, &slot_digest(sig_alg, &sig));
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

/// What [`encode_txn`] wraps around one record's bytes in its frame payload.
///
/// The [`FramePayload`] variant tag (4), `seq` (8), `txn` (8) and the
/// byte-vector's length prefix (8) — bincode's fixed-width encoding,
/// value-independent. A constant so [`Journal::commit_txn`] can charge a
/// record without building its frame; the accounting test pins it to the
/// encoder's own output, so a codec change breaks the gate rather than
/// silently loosening either limit it feeds.
pub(crate) const RECORD_PAYLOAD_OVERHEAD: u64 = 28;
/// The marker frame's whole encoded size, with its slot empty.
///
/// Header (12) plus the tagged [`Marker`] payload — tag (4), `txn` (8),
/// `last_seq` (8), `records_checksum` (4), `salt` (32), `chain` (32),
/// `sig_alg` (1), `sig`'s length prefix (8): 97, so 109 in all. Pinned
/// alongside [`RECORD_PAYLOAD_OVERHEAD`]. The empty slot's pin, and it stays
/// one: a filled slot appends the blob's own bytes after this figure, which
/// the sites this seeds treat differently, by design (signed ops, the design
/// record §4.4 (b)) — [`txn_encoded_len`] counts them, because it is what
/// [`encode_txn`] emits and reserves; [`Journal::commit_txn`]'s budget does
/// not, nor does the scan's, which holds a group to the same budget, because
/// the slot sits outside [`MAX_TXN_BYTES`]'s accounting: the budget bounds
/// the records a staging holds, and an attested transaction answers no
/// refusal an unattested one would not, a `publish` shot being unsplittable.
/// What a filled slot moves is the marker frame's own size (its `len` and
/// CRC), at most [`MAX_SIG_BYTES`] past this figure and so inside
/// [`MAX_FRAME_LEN`] at any width an [`Attestation`] holds (asserted below),
/// and the memory floor M2 promises a replica by the blob's width,
/// [`MAX_SIG_BYTES`] at most — the price the design record states and takes.
const MARKER_FRAME_LEN: u64 = frame_len(97);
// …and the widest slot frames: the marker's payload with a blob at the cap is
// inside the frame cap, so `encode_txn` frames every marker an `Attestation`
// fills, and the durable journal refuses no slot the in-memory one drops.
const _: () = assert!(
    MARKER_FRAME_LEN - FRAME_HEADER_LEN as u64 + MAX_SIG_BYTES as u64 <= MAX_FRAME_LEN as u64
);

/// Returns what one framed payload occupies in a segment.
///
/// The header [`push_frame`] writes, plus the payload it wraps: the outer of
/// the two levels every figure here is built from.
const fn frame_len(payload_len: u64) -> u64 {
    (FRAME_HEADER_LEN as u64).saturating_add(payload_len)
}

/// Returns the frame payload one already-encoded record occupies.
///
/// Its own bytes plus what [`encode_txn`] wraps around them
/// ([`RECORD_PAYLOAD_OVERHEAD`]). The inner level — and the figure
/// [`push_frame`] judges against [`MAX_FRAME_LEN`], so
/// [`Journal::commit_txn`]'s size gate and that guard compare one named
/// quantity rather than two spellings of it.
const fn record_payload_len(record_len: usize) -> u64 {
    RECORD_PAYLOAD_OVERHEAD.saturating_add(record_len as u64)
}

/// Returns what one already-encoded record occupies in the journal.
///
/// Both levels together: the one spelling of a record's cost on the write
/// side, so the running charge in [`Journal::commit_txn`] and the reservation
/// [`encode_txn`] takes from [`txn_encoded_len`] cannot disagree about what is
/// being built.
///
/// A reader has the framed payload rather than the record's own bytes, so
/// `PendingTxn` reaches the same figure by the other route —
/// [`frame_len`] over what it holds — and the accounting test pins the two
/// equal.
const fn record_frame_len(record_len: usize) -> u64 {
    frame_len(record_payload_len(record_len))
}

/// Returns the exact byte length [`encode_txn`] emits for these records.
///
/// The records are already encoded, and the length is each record frame
/// ([`record_frame_len`]) plus the terminal marker frame — the empty marker's
/// pin plus the slot's blob where the transaction carries an [`Attestation`]
/// (the blob rides inside the marker's `sig` field, whose length prefix the
/// pin already counts). Saturating, as the budget's running charge in
/// [`Journal::commit_txn`] is, which is what refuses a sum no allocator could
/// hold as over-budget rather than wrapping it back under the budget.
pub(crate) fn txn_encoded_len(record_bytes: &[Vec<u8>], attestation: Option<&Attestation>) -> u64 {
    let marker_len =
        MARKER_FRAME_LEN.saturating_add(attestation.map_or(0, |a| a.sig().len() as u64));
    record_bytes.iter().fold(marker_len, |total, bytes| {
        total.saturating_add(record_frame_len(bytes.len()))
    })
}

#[derive(Debug)]
enum Parsed {
    /// The frame at `pos` is intact.
    ///
    /// Its own `crc` validates over `len`+payload. The frame ends where its
    /// payload does, at `payload.end` — one fact, so the two cannot disagree
    /// and mis-delimit the frame that follows.
    Intact { payload: Range<usize> },
    /// Not a trustworthy frame start: resynchronize via the magic word (§1/§7).
    ///
    /// A header past the buffer's end, bad magic, an oversize or overrunning
    /// `len`, or a CRC mismatch.
    ///
    /// `crc_bytes` is what rejecting this candidate cost: the payload length
    /// it claimed, when the CRC was computed and mismatched, and `0` for the
    /// rejections that precede the CRC. The scan charges it against
    /// [`RESYNC_BUDGET_PASSES`], which is why the accounting lives on the one
    /// function that knows the cost rather than on a second header parse.
    Bad { crc_bytes: u64 },
}

/// Reads back the frame [`push_frame`] wrote, at `pos`.
///
/// Stated as a pair with [`push_frame`], because the layout and the parse are
/// one agreement: a change to either that the other does not match makes
/// every frame of every healthy journal unreadable, which recovery meets as
/// corruption rather than as the writer/reader skew it is.
///
/// Nothing is believed before it is checked, and the order is what makes the
/// checks mean anything: the header must be present, then carry the sync
/// word, then claim a `len` inside [`MAX_FRAME_LEN`] that does not overrun
/// the buffer — and only then is the CRC computed, over the `len` field and
/// the payload, so a corrupt length is detected here rather than silently
/// mis-delimiting the frame that follows (§1). [`Parsed::Intact`] is
/// therefore what every later stage may trust without re-checking, and
/// [`Parsed::Bad`]'s `crc_bytes` says what the door that refused cost: `0`
/// before the CRC, the claimed length at it.
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
