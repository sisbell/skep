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
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};

use bincode::Options;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::SaltSource;
use crate::error::stamp_text;

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

/// One committed record as the fold consumes it: the coordinate it was
/// committed at, and the serialized `W::Record` bytes there — a [`LogRecord`]
/// minus its `txn`, which the group that closed it has already established.
/// Named for the only state in which one is ever read: a dead group releases
/// its records unread, so every one that reaches
/// [`ScanOutcome::committed_records`] came through [`PendingTxn::commits`].
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
/// reads the sync word and the header — so [`PendingTxn::commits`] and the
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
pub(crate) struct Marker {
    pub txn: Txn,
    pub last_seq: u64,
    pub records_checksum: u32,
    /// THE SALT (`SKJ4`; the signed-ops re-base report's R1): thirty-two
    /// bytes DRAWN per transaction from the kernel's [`SaltSource`] — OS
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

/// The signature slot's EMPTY tag: unsigned, the one value this build writes.
/// The pairs the design names — `1` = ML-DSA-65 + Ed25519 (the ruled
/// default), `2` reserved for FN-DSA-512 + Ed25519 — are the signed-ops
/// lane's to write and a verifier's to read; a change of pair is a verifier
/// update, never a stamp bump.
pub(crate) const SIG_ALG_UNSIGNED: u8 = 0;

/// THE CHAIN'S GENESIS — chain₀, the value the first transaction of a journal
/// chains from: thirty-two zero bytes. Named here, read by the writer of a
/// fresh journal and by every replay from genesis, and pinned by the golden
/// fixture, whose first marker's chain is SHA-256 over this seed and that
/// transaction's bytes. When a checkpoint is the base the value read is the
/// `SKC4` header's `chain_head` instead — the chain at that checkpoint's
/// coordinate, which the marker that held it may no longer exist to say.
pub(crate) const CHAIN_GENESIS: [u8; 32] = [0u8; 32];

/// One link of the commit chain under construction — the ONE spelling of
/// what the chain hashes, used by the writer ([`encode_txn`]) and the reader
/// ([`PendingTxn`]) alike, so the two cannot disagree about a single byte:
///
/// ```text
/// chain(T) = SHA-256(
///     chain(T − 1)                      32 bytes: the previous COMMITTED transaction's value in journal
///                                       order; CHAIN_GENESIS for a journal's first, the SKC4 header's
///                                       chain_head for the first above a checkpoint base
///   ‖ payload_1 ‖ … ‖ payload_k         each RECORD frame's payload exactly as framed — the
///                                       FramePayload tag, seq, txn, the length prefix and the record's
///                                       own bytes — in the order framed: the bytes records_checksum
///                                       streams, which the frame CRC has verified before they are read
///   ‖ txn LE64 ‖ last_seq LE64 ‖ records_checksum LE32
///                                       the marker's own PRE-CHAIN fields, as the marker frame carries them
///   ‖ salt (32)                         the marker's per-transaction SALT, exactly as the marker carries
///                                       it (SKJ4): drawn by the writer from the kernel's SaltSource, read
///                                       by the reader off the marker — the last bytes before finalize
/// )
/// ```
///
/// NOT hashed: the frame headers (sync word, `len`, `crc` — derivable from
/// the payload and the stamp), the `chain` field itself, and the signature
/// slot (a signature over the chain must sit outside it). A writer hashes
/// what it framed and a reader hashes what the CRC just verified, from the
/// same byte strings, so the chain needs no canonical re-serialization on
/// either side; that the records themselves have one byte-form per value on
/// every machine is the codec's promise ([`codec`]), which is what makes two
/// replicas of one history agree on every link.
///
/// WHAT THE SALT PROTECTS, and what it does not (the signed-ops re-base
/// report's R1, the `/chain?at=N` confirmation oracle). Every other input
/// above is either served or enumerable: the previous value and this one are
/// what `/chain?at=N` answers to every reader, and a transaction whose bytes
/// a reader can ENUMERATE — the draft home of a straddle nullify, a
/// delegate's minted prefix, a one-value insert into a masked draft — is a
/// transaction whose preimage that reader can build and hash, CONFIRMING the
/// guess against the served value. The salt is thirty-two bytes of that
/// preimage that no route serves and no reader can enumerate, so a served
/// chain value confirms nothing about the transaction's bytes. It protects
/// nothing from a party HOLDING THE JOURNAL — the salt sits in the marker
/// beside the bytes it salts, and such a party has the bytes anyway — and it
/// is no anchor: a forger who rewrites the journal chooses its own salts and
/// re-chains consistently, exactly as before (the tamper matrix's case 11).
struct ChainLink(Sha256);

impl ChainLink {
    /// Open the link that follows `prev`.
    fn open(prev: &[u8; 32]) -> ChainLink {
        ChainLink(Sha256::new().chain_update(prev))
    }

    /// Stream one record frame's payload, exactly as framed.
    fn add_payload(&mut self, payload: &[u8]) {
        self.0.update(payload);
    }

    /// Close the link with the marker's own pre-chain fields, then its salt —
    /// the ONE spelling, which the writer closes with the salt it drew and
    /// the reader with the salt the marker carries.
    fn close(self, txn: Txn, last_seq: u64, records_checksum: u32, salt: &[u8; 32]) -> [u8; 32] {
        self.0
            .chain_update(txn.0.to_le_bytes())
            .chain_update(last_seq.to_le_bytes())
            .chain_update(records_checksum.to_le_bytes())
            .chain_update(salt)
            .finalize()
            .into()
    }
}

/// The serde-tagged frame payload (§1).
#[derive(Serialize, Deserialize)]
pub(crate) enum FramePayload {
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
/// [`JournalWriter::commit_txn`] from the kernel's [`SaltSource`] before
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
) -> io::Result<(Vec<u8>, [u8; 32])> {
    let n = record_bytes.len() as u64;
    assert!(n > 0, "zero-step ops never reach the journal");
    let txn = Txn(first_seq);
    // The exact figure, not a guess: [`txn_encoded_len`] is what this function
    // emits, pinned to it by the accounting test. Reserving it is what holds
    // the commit region to the two copies of a transaction's bytes its own
    // contract budgets for — a doubling `Vec` transiently holds a third.
    let mut buf = Vec::with_capacity(txn_encoded_len(&record_bytes) as usize);
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
    let payload = codec()
        .serialize(&FramePayload::Marker(Marker {
            txn,
            last_seq,
            records_checksum: checksum,
            salt,
            chain,
            sig_alg: SIG_ALG_UNSIGNED,
            sig: Vec::new(),
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
/// [`RECORD_PAYLOAD_OVERHEAD`]. A constant only while the empty slot has a
/// value-independent size, which it does; a FILLED slot changes the
/// accounting at the two sites this seeds, which is the signed-ops lane's to
/// add.
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
/// [`PendingTxn`] reaches the same figure by the other route —
/// [`frame_len`] over what it holds — and the accounting test pins the two
/// equal.
const fn record_frame_len(record_len: usize) -> u64 {
    frame_len(record_payload_len(record_len))
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

/// A journal segment file, named by its `firstSeq` (§1). Every operation over
/// a slice of these reads a neighbour's name as this segment's bound, so the
/// slice must be ascending by `first_seq` as [`list_segments`] produces it.
///
/// Both fields are read only by the operations here that own segment names —
/// [`inferred_last_seq`], [`reaches_genesis`], [`reclaim_below`] and
/// [`scan`] — because a `firstSeq` read outside them is a coverage inference
/// made away from the naming rule it rests on, and [`reclaim_below`] deletes
/// files on that inference. A slice of these travels; the names inside do not,
/// and neither does the inference drawn from them — the one fact about segment
/// coverage that leaves this module is [`reaches_genesis`]'s answer.
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
/// invisible to recovery, which reads as an empty journal rather than as a
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
///
/// Private for the reason [`SegmentMeta`]'s fields are: a coverage inference
/// drawn outside this module is drawn away from the naming rule it rests on,
/// and [`reclaim_below`] deletes files on it.
fn inferred_last_seq(segs: &[SegmentMeta], i: usize) -> Option<u64> {
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
    /// The commit chain's running value: the chain of the last COMMITTED
    /// transaction in this journal, which the next one links from
    /// ([`ChainLink`]). Seeded at [`JournalWriter::open_active`] with what
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
    /// ([`ScanOutcome::chain_head`]), or [`CHAIN_GENESIS`] for a journal with
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
                })
            }
            None => Self::create_segment(dir, next_seq, chain, salt_source),
        }
    }

    fn create_segment(
        dir: &Path,
        first_seq: u64,
        chain: [u8; 32],
        salt_source: SaltSource,
    ) -> io::Result<Self> {
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
            chain,
            salt_source,
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
    /// flight. It is handed the transaction's chain value — the marker's,
    /// now durable — so the root it installs carries the chain at its own
    /// coordinate, which is what a checkpoint taken off that root writes as
    /// its `chain_head`.
    pub(crate) fn commit_txn(
        &mut self,
        first_seq: u64,
        record_bytes: Vec<Vec<u8>>,
        install: impl FnOnce([u8; 32]),
    ) -> Result<u64, CommitFail> {
        // THE SALT IS DRAWN HERE (`SKJ4`), once per transaction, from the
        // kernel's source, before a frame exists: `encode_txn` stores it in
        // the marker and closes the link with it. An OS that refuses entropy
        // refuses the commit as a clean failure — nothing was framed, nothing
        // appended, the segment is where the transaction found it, and
        // re-invoking is safe — rather than as a property of the records.
        let salt = self.salt_source.draw(first_seq).map_err(CommitFail::Clean)?;
        let (buf, chain) = encode_txn(first_seq, record_bytes, &self.chain, salt)
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
        // The chain rides across: it is over the journal, not the segment;
        // the salt source with it.
        *self = Self::create_segment(&self.dir, first_seq, self.chain, self.salt_source)?;
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
    /// no need of. The in-memory arm hands `install` [`CHAIN_GENESIS`]: the
    /// chain is over journal frames, of which that arm builds none, and
    /// nothing reads a chain off an in-memory kernel — it writes no
    /// checkpoint.
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
    /// [`push_frame`] would give it, [`CommitFail::Unencodable`], a property of
    /// that record — precedes a whole encoded form past [`MAX_TXN_BYTES`] —
    /// [`CommitFail::OverBudget`], a property of the staging, where every
    /// record is fine and the caller staged too much at once. So a caller
    /// fixing a value is not first told to split. [`push_frame`]'s own
    /// frame-cap refusal deliberately stays: writer and reader sit on opposite
    /// sides of a trust boundary, and the writer's guard is what entitles
    /// recovery to treat a larger claimed `len` as corrupt.
    ///
    /// PRECONDITION — `records` is non-empty. A zero-step op never reaches the
    /// journal: [`crate::Kernel::transact`] returns at the zero-step before a
    /// coordinate is minted, and `NonZeroU64` carries the rest. The assertion
    /// below is a second check of that one rule at a second boundary, owed for
    /// the reason [`push_frame`]'s frame-cap guard is owed beside this method's
    /// own size limit: what this method promises is that its two arms answer
    /// alike, and without it a violation panics through [`encode_txn`] on the
    /// durable arm and INSTALLS a transaction with no records on the in-memory
    /// one — a disagreement in the one element whose purpose is that the arms
    /// cannot disagree.
    pub(crate) fn commit_txn<R: Serialize>(
        &mut self,
        first_seq: u64,
        records: Vec<R>,
        install: impl FnOnce([u8; 32]),
    ) -> Result<u64, CommitFail> {
        assert!(
            !records.is_empty(),
            "zero-step ops never reach the journal: `transact` returns before \
             minting a coordinate"
        );
        let mut record_bytes: Vec<Vec<u8>> = Vec::new();
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
            Journal::InMemory => {
                install(CHAIN_GENESIS);
                Ok(0)
            }
            Journal::Segments(writer) => writer.commit_txn(first_seq, record_bytes, install),
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

/// How a corrupt run (a span the scan skipped via magic-resync) ended (§7).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RunEnd {
    /// The resync landed on an intact frame. `at` = that next-intact
    /// coordinate; `inferred_max` = the greatest `Seq` the run itself can
    /// hold. The run's own seqs are unreadable, so these two are all that is
    /// known of it (§7). What each landing contributes is
    /// [`RunEnd::landed_on_record`] and [`RunEnd::landed_on_marker`], which
    /// are the only way one of these is built.
    Landed { inferred_max: u64, at: u64 },
    /// The run reached end-of-journal with no next intact frame: classes as
    /// the un-acked / torn tail (`> W`), sound because the last committed
    /// marker is itself intact and so precedes any EOF-reaching run (§7) —
    /// sound against torn writes and CRC-failing damage under §1's storage
    /// assumptions, save §7's documented post-commit-rot exception; NOT
    /// against a rewrite that leaves one of the last transaction's frames
    /// intact and undecodable, which reads as a run reaching here and is cut
    /// (the open item in [`crate::Kernel::open`]'s damage model).
    Eof,
}

impl RunEnd {
    /// The resync landed on an intact RECORD: the run ends one below that
    /// record's own coordinate, and is reported at it (§7).
    fn landed_on_record(seq: u64) -> RunEnd {
        RunEnd::Landed {
            inferred_max: seq.saturating_sub(1),
            at: seq,
        }
    }

    /// …on an intact MARKER, which carries no `Seq` of its own, so the
    /// coordinate it contributes is one past its `last_seq`. At the ceiling
    /// there is no such coordinate and the run is reported at the ceiling
    /// itself — never wrapped to `0`, which would report a run above the base
    /// as one below it (§7).
    fn landed_on_marker(last_seq: u64) -> RunEnd {
        RunEnd::Landed {
            inferred_max: last_seq,
            at: last_seq.saturating_add(1),
        }
    }
}

/// Why a scan could not produce an outcome (§7). Both answers are the
/// caller's to phrase in its own error vocabulary; neither leaves a partial
/// [`ScanOutcome`] for anyone to draw a verdict from.
#[derive(Debug)]
pub(crate) enum ScanFail {
    /// A segment could not be read.
    Io(io::Error),
    /// A segment could not be taken in within the scan's bounds: its
    /// resynchronization exceeded [`RESYNC_BUDGET_PASSES`], so its frame
    /// stream could not be enumerated in bounded work, or the file is longer
    /// than [`MAX_SEGMENT_LEN`], so it could not be read in bounded memory.
    /// Either way nothing derived from it would be more than a PREFIX of what
    /// the segment holds — a committed head that may be short, records that
    /// may be missing, a boundary set that may not be the journal's. Fatal at
    /// any height, which is why the scan refuses rather than answering with a
    /// qualification.
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

/// Pass-1 result (§7): the committed head (§7's `W`), the committed records a
/// fold may read, the corrupt runs, and where the tail to truncate begins. A
/// scan that could not enumerate the frame stream produces none of this — it
/// answers [`ScanFail`] — so nothing here is a PREFIX of what the region
/// holds. What it COLLECTED is bounded by the caller's own fold bound, which
/// is why the records are reached through [`ScanOutcome::records_to`] rather
/// than read as a set.
pub(crate) struct ScanOutcome {
    /// The base this scan ran against — §7's `S_load`. Every judgment it
    /// answers is relative to that base, so it is carried here rather than
    /// re-supplied per question, where a caller could hand back a different
    /// one than the scan was run with.
    s_load: u64,
    /// The boundary this scan COLLECTED to, as [`scan`] was called with it —
    /// `None` for the whole scanned region. Applied by
    /// [`ScanOutcome::collect_commit`], the only writer of the two collections
    /// below, and read back by [`ScanOutcome::covers`] to hold a fold to it:
    /// records above it were read and dropped, so a fold past it is one this
    /// outcome cannot answer. Bounding the collection is what keeps a bounded
    /// replay of one transaction from materializing the whole retained window.
    bound: Option<u64>,
    /// The last COMMITTED marker's `last_seq`, floored at `S_load` — §7's `W`
    /// (if no committed marker sits above the loaded checkpoint it is
    /// `S_load` itself and Pass 2 folds nothing). Never bounded: it is
    /// recovery's own fold bound, so it names the last committed marker of the
    /// whole scanned region.
    pub committed_head: u64,
    /// The records a fold may apply, unordered and unfiltered as collected.
    /// Written only by [`ScanOutcome::collect_commit`], which is where the
    /// collection bound is applied; read through [`ScanOutcome::records_to`],
    /// which is where the order, the range and the one-coordinate-once rule
    /// are settled.
    committed_records: Vec<CommittedRecord>,
    /// The transaction boundaries a bounded replay may be asked about, in scan
    /// order — the `Seq` values [`crate::Kernel::transact`] returned. Written
    /// only by [`ScanOutcome::collect_commit`]; read by
    /// [`ScanOutcome::require_boundary`], which reads the requested value, and
    /// by [`ScanOutcome::nearest_boundary_below`], which reads the boundaries
    /// below it — so a boundary the collection bound excluded is one nothing
    /// can ask for.
    committed_boundaries: Vec<u64>,
    /// Corrupt runs in scan order — what [`ScanOutcome::fatal_run_to_head`]
    /// and [`ScanOutcome::fatal_run_anywhere`] answer from. The verdict on a
    /// run belongs to those, not to a caller re-deriving the classifier.
    runs: Vec<RunEnd>,
    /// The tail-truncation cut, `None` when nothing was scanned — what
    /// [`truncate_tail`] cuts. Resolved here and read there, so no caller can
    /// aim a truncation at a region other than the one this scan judged.
    tail: Option<TailCut>,
    /// The commit chain's value at the committed head: the last committed
    /// marker's `chain` in journal order above the base, or the base's own
    /// value when nothing above it committed. What the appender continues
    /// from and the recovered root carries. Never bounded, for the reason
    /// the head is not.
    pub chain_head: [u8; 32],
    /// The first CHAIN BREAK above the base, as the `last_seq` of the
    /// committed transaction whose marker's `chain` was not the recomputation
    /// ([`ChainLink`]) over the previous committed transaction's value and
    /// its own records — `None` when every link above the base verified.
    /// Recorded rather than refused on the spot, so the corrupt-run
    /// classification, which names the root cause when a run swallowed the
    /// predecessor, speaks first; read through [`ScanOutcome::chain_break`].
    chain_break: Option<u64>,
    /// THE BASE'S OWN LINK (QUEUE item 10's case 9, the at-head fork): the
    /// base's seq when the committed marker closing `s_load` itself was
    /// scanned and its `chain` is not `chain_at_base` — the `SKC4` header's
    /// `chain_head`, which nothing in the header covers. Two STORED values
    /// disagreeing, nothing recomputed: the header was rewritten, or the
    /// marker was. `None` when they agree, and `None` — vacuously — when
    /// that marker was not scanned: a closed segment ending exactly at
    /// `s_load` is skipped, and one below the reclaim floor is gone. At the
    /// HEAD the marker is scanned whenever the active segment holds it — not
    /// while that segment is EMPTY after a rotation whose transaction failed
    /// or never landed, when the head's marker ends the closed segment before
    /// it and is skipped as the rest are. Recorded, not refused, for the
    /// reason `chain_break` is; read through [`ScanOutcome::base_mismatch`].
    base_mismatch: Option<u64>,
    /// THE EDITED TRANSACTION (case 2's coordinate): the last seq of the
    /// first transaction whose frames were ALL intact and which an intact
    /// marker failed to close — its own marker refusing it
    /// ([`PendingTxn::commits`]), or its next intact frame being ANOTHER
    /// transaction's marker, the marker's `txn` rewritten — the GROUP's own
    /// last seq, since in the `last_seq`-edited shape the marker's is the
    /// forged field. NO WRITER OF THIS JOURNAL PRODUCES THAT SHAPE:
    /// [`encode_txn`] streams `records_checksum` over the frames it writes
    /// and sets `last_seq` to the last record's, emits one transaction's
    /// frames contiguously and `Seq`-ascending — so a clean group's next
    /// intact frame is its own marker — and refuses a group past the budget
    /// before a byte lands; a crash truncates (a frame fails its CRC) or
    /// loses frames (they are absent), and never leaves a complete marker
    /// disagreeing with complete records. So the marker was rewritten — and
    /// the transaction it should have closed is un-committed, which on the
    /// LAST transaction is the tail cut in disguise this names before
    /// recovery cuts it. Recorded at any height, below the base as well: the
    /// verdict compares a marker with its own records and needs no link from
    /// the base. A group that met a corrupt or undecodable frame while open,
    /// or whose first record closed a corrupt run (the run may have eaten its
    /// own earlier frames), is not clean and never records here: that is the
    /// corrupt-run verdict's — which mid-history halts, and in the last
    /// transaction does not (the open item in [`crate::Kernel::open`]'s
    /// damage model). Recorded, not refused; read through
    /// [`ScanOutcome::uncommitted_intact`].
    uncommitted_intact: Option<u64>,
    /// The running chain AT `bound`: the `chain` of the committed marker
    /// whose `last_seq` is `bound`, above the base — `None` when `bound` is
    /// `None`, is not a committed boundary above the base, or is the base's
    /// own seq (the base answers that itself). What
    /// [`crate::Kernel::chain_at`] answers, captured in the pass that
    /// verifies every link to the journal's end; read through
    /// [`ScanOutcome::chain_at_boundary`], which reads its presence as the
    /// membership test and holds its caller to the bound it is keyed on.
    chain_at_bound: Option<[u8; 32]>,
}

impl ScanOutcome {
    /// The first chain break above the base ([`ScanOutcome::chain_break`]'s
    /// field), for the two callers to halt on in their own vocabulary —
    /// after the corrupt-run verdict, which names the root cause where a run
    /// lost the predecessor a break follows from.
    pub(crate) fn chain_break(&self) -> Option<u64> {
        self.chain_break
    }

    /// The base's own link failed ([`ScanOutcome::base_mismatch`]'s field):
    /// `Some(s_load)` when the scanned marker closing the base's seq does
    /// not carry the header's `chain_head`.
    pub(crate) fn base_mismatch(&self) -> Option<u64> {
        self.base_mismatch
    }

    /// The first intact transaction which an intact marker failed to close
    /// ([`ScanOutcome::uncommitted_intact`]'s field), by its own last seq.
    pub(crate) fn uncommitted_intact(&self) -> Option<u64> {
        self.uncommitted_intact
    }

    /// THE CHAIN'S VERDICTS, in the order they speak — the coordinate and
    /// the account each caller wraps as its own `Corruption`: the base's own
    /// link ([`ScanOutcome::base_mismatch`]), then the intact transaction no
    /// intact marker closes ([`ScanOutcome::uncommitted_intact`]), then the
    /// chain break ([`ScanOutcome::chain_break`]). One site for the order, so
    /// the open and the two bounded reads cannot drift on it. A verdict of
    /// an earlier kind speaks first whatever its coordinate, as the
    /// corrupt-run verdict — which every caller asks for BEFORE this, in its
    /// own classification — does: the base's link is the lowest coordinate
    /// scanned, and the un-committed transaction is the ROOT of the break
    /// the next committed one shows. `None` when every link verified.
    pub(crate) fn chain_verdict(
        &self,
    ) -> Option<(u64, Box<dyn std::error::Error + Send + Sync + 'static>)> {
        if let Some(at) = self.base_mismatch() {
            return Some((at, base_mismatch_cause(at)));
        }
        if let Some(at) = self.uncommitted_intact() {
            return Some((at, uncommitted_intact_cause(at)));
        }
        self.chain_break().map(|at| (at, chain_break_cause(at)))
    }
    /// Collect everything a COMMITTED transaction contributes: its marker's
    /// `last_seq` raises the committed head and — when this scan's collection
    /// bound admits it — joins the boundary set, and its records join the
    /// committed set, filtered the same way.
    ///
    /// The head is deliberately UNBOUNDED: it is recovery's own fold bound, so
    /// it must name the last committed marker wherever it sits. The two
    /// COLLECTIONS obey `bound`, and per RECORD rather than per group, so a
    /// transaction straddling the bound keeps the half below it. That
    /// asymmetry is the whole of what `bound` means, and stating it here is
    /// what keeps it off the walk — this is the only writer of either
    /// collection, so the rule has one site.
    fn collect_commit(&mut self, marker: &Marker, records: Vec<CommittedRecord>) {
        self.committed_head = self.committed_head.max(marker.last_seq);
        let bound = self.bound;
        let collected = |seq: u64| bound.is_none_or(|b| seq <= b);
        if collected(marker.last_seq) {
            self.committed_boundaries.push(marker.last_seq);
        }
        self.committed_records
            .extend(records.into_iter().filter(|entry| collected(entry.seq)));
    }

    /// The corrupt run a RECOVERY cannot answer around, classified within
    /// the committed region this scan derived: a run above the committed head
    /// is the un-acked / torn tail, which recovery is about to discard (§7) —
    /// the tail against torn writes and CRC-failing damage; NOT against a
    /// rewrite that leaves one of the last transaction's frames intact and
    /// undecodable, whose run lands here above the head, or reaches
    /// end-of-journal, and is cut with the transaction (the open item in
    /// [`crate::Kernel::open`]'s damage model).
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

    /// Whether a fold over `(s_load, bound]` can be answered from this scan:
    /// whether `bound` is at or below the boundary this scan COLLECTED to.
    /// Records above that boundary were read and dropped, so a fold past it
    /// cannot restore them and would answer `Ok` with a world missing exactly
    /// the range between (§7).
    fn covers(&self, bound: u64) -> bool {
        self.bound.is_none_or(|collected| bound <= collected)
    }

    /// Whether `at` is one of the committed transaction boundaries this scan
    /// saw — the values [`crate::Kernel::transact`] returns, and the only ones
    /// a bounded replay may answer at. `Err` carries
    /// [`ScanOutcome::nearest_boundary_below`] `at`.
    pub(crate) fn require_boundary(&self, at: u64) -> Result<(), u64> {
        if self.committed_boundaries.contains(&at) {
            return Ok(());
        }
        Err(self.nearest_boundary_below(at))
    }

    /// The greatest committed boundary below `at`, never below the base: the
    /// base's own seq is itself a boundary, and a segment straddling it
    /// contributes boundaries below it that no longer have a base to fold
    /// from. What a refusal of a non-boundary names as the value a caller may
    /// safely re-ask with.
    fn nearest_boundary_below(&self, at: u64) -> u64 {
        self.committed_boundaries
            .iter()
            .copied()
            .filter(|&b| b < at)
            .fold(self.s_load, u64::max)
    }

    /// The commit chain at boundary `at` — the one question
    /// [`crate::Kernel::chain_at`] asks of a scan above its base: the `chain`
    /// of the committed marker closing `at`, which this scan captured as it
    /// verified it. The capture is keyed on the collection bound, so it is
    /// also the membership test: a committed marker closed at `at` exactly
    /// when one was captured, and one answer serves both questions. `Err` is
    /// [`ScanOutcome::require_boundary`]'s: the nearest boundary below.
    ///
    /// PRECONDITION — this scan COLLECTED to exactly `at`, above its base
    /// ([`scan`]'s `bound` was `Some(at)`, and `at > s_load`). The capture is
    /// keyed on that bound and on nothing else, so a scan collected to any
    /// other would answer every boundary as absent: a caller's bug, answered
    /// as one, as [`ScanOutcome::records_to`] answers a fold past its
    /// collection.
    pub(crate) fn chain_at_boundary(&self, at: u64) -> Result<[u8; 32], u64> {
        assert!(
            self.bound == Some(at) && at > self.s_load,
            "chain at {at} asked of a scan collected to {:?} above {}: the capture is keyed \
             on the collection bound (Base::scan)",
            self.bound,
            self.s_load
        );
        self.chain_at_bound.ok_or_else(|| self.nearest_boundary_below(at))
    }

    /// The committed records a fold over `(s_load, bound]` must apply, in
    /// `Seq` order and each coordinate once. Order, range and uniqueness are
    /// all facts about the set THIS scan derived, so they are settled here
    /// rather than by whoever folds: [`crate::WorldState::apply`] is not
    /// required to be idempotent, so a coordinate applied twice is silent
    /// double application answered `Ok` — while a `Seq` merely MISSING is not
    /// corruption at all, since a burned-`Seq` gap folds harmlessly (§6/§7).
    ///
    /// `Err` is a `Seq` this scan saw twice in that range — a journal no
    /// sequencer here wrote, since each coordinate is minted once. This is the
    /// ACROSS-transactions half of "no coordinate twice"; [`PendingTxn`]'s
    /// `ordered` is the within-transaction half, and both sit with the journal
    /// they are properties of.
    ///
    /// PRECONDITION — `bound` must be at or below the boundary this scan
    /// COLLECTED to ([`ScanOutcome::covers`]). Records above it were read and
    /// dropped, so a fold past it reads records that were never collected,
    /// which no filter can restore: a caller's bug, answered as one rather
    /// than with a world short by exactly that range.
    pub(crate) fn records_to(&self, bound: u64) -> Result<Vec<&CommittedRecord>, u64> {
        assert!(
            self.covers(bound),
            "fold to {bound} against a scan that did not collect that far: the \
             records between them were never collected (Base::scan)"
        );
        let mut records: Vec<&CommittedRecord> = self
            .committed_records
            .iter()
            .filter(|entry| entry.seq > self.s_load && entry.seq <= bound)
            .collect();
        records.sort_by_key(|entry| entry.seq);
        match records.windows(2).find(|pair| pair[0].seq == pair[1].seq) {
            Some(pair) => Err(pair[0].seq),
            None => Ok(records),
        }
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
/// not obliged to have been written by this writer: frames spread across all
/// its segments, all carrying one `txn`, are one group. So the size of the
/// group is bounded HERE, by the same [`MAX_TXN_BYTES`] the write path refuses
/// at ([`Self::oversize`]) — one segment's bytes plus one transaction's worth,
/// which is the memory floor [`crate::Kernel::open`] promises on every replica.
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
    /// marker frame that will close the group, then charged [`frame_len`] per
    /// record — which is [`record_frame_len`] reached from the framed payload
    /// a reader actually holds rather than from the record's own bytes.
    accounted: u64,
    /// Set once [`Self::accounted`] passes [`MAX_TXN_BYTES`]. A group past the
    /// budget is one no writer here can emit — [`Journal::commit_txn`] refuses
    /// it before a byte is appended — so the READER enforces the same bound
    /// rather than trusting it, which is what holds a scan's group memory to
    /// one transaction's worth against a journal this writer did not write.
    oversize: bool,
    /// The group's records, in arrival order. Released the moment the group is
    /// known dead, since nothing downstream can want it.
    records: Vec<CommittedRecord>,
    /// The chain link this group would close, streamed beside the checksum
    /// from the same payloads: opened on the running chain value — which
    /// cannot move while a group is open, since only a committed marker
    /// moves it and a committed marker closes the group — and closed with
    /// the marker's fields by [`PendingTxn::recomputed_chain`].
    link: ChainLink,
    /// Whether every frame this group could have had was seen intact: opened
    /// `false` when the group's first record closed a corrupt run — the run
    /// may have eaten this transaction's own earlier frames — and cleared
    /// when a corrupt or undecodable frame is met while the group is open.
    /// A clean group no intact marker closes — its own refusing it, or
    /// another transaction's following it — is the shape no writer produces
    /// ([`ScanOutcome::uncommitted_intact`]); an unclean one is the
    /// corrupt-run verdict's, whatever its marker says.
    clean: bool,
}

impl PendingTxn {
    fn open(txn: Txn, prev_chain: &[u8; 32], clean: bool) -> PendingTxn {
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
            link: ChainLink::open(prev_chain),
            clean,
        }
    }

    /// The chain value `marker` MUST carry to be this group's honest close:
    /// the link opened on the running value, streamed with this group's
    /// payloads, closed with the marker's own pre-chain fields and the SALT
    /// the marker carries — the writer's computation ([`encode_txn`]) re-run
    /// from the bytes the CRC verified. The salt is READ here, never drawn:
    /// a replay under any [`SaltSource`] recomputes the link the writer
    /// closed, and an edited salt is a link that fails.
    fn recomputed_chain(&self, marker: &Marker) -> [u8; 32] {
        ChainLink(self.link.0.clone()).close(
            marker.txn,
            marker.last_seq,
            marker.records_checksum,
            &marker.salt,
        )
    }

    /// Take one record frame of this transaction: `payload` is the frame
    /// payload exactly as framed, which is what `records_checksum` covers —
    /// and the chain, and what [`frame_len`] charges, a framed payload being
    /// the inner level [`record_payload_len`] gives the write side.
    fn push(&mut self, record: LogRecord, payload: &[u8]) {
        if self.last_seq.is_some_and(|prev| record.seq <= prev) {
            self.ordered = false;
        }
        self.last_seq = Some(record.seq);
        self.checksum = crc32c::crc32c_append(self.checksum, payload);
        self.link.add_payload(payload);
        self.accounted = self.accounted.saturating_add(frame_len(payload.len() as u64));
        self.oversize |= self.accounted > MAX_TXN_BYTES;
        if self.ordered && !self.oversize {
            self.records.push(CommittedRecord {
                seq: record.seq,
                bytes: record.bytes,
            });
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
    /// journal spread one `txn` over all its segments while the scan held
    /// every record of it.
    fn commits(&self, marker: &Marker) -> bool {
        self.ordered
            && !self.oversize
            && self.last_seq == Some(marker.last_seq)
            && self.checksum == marker.records_checksum
    }
}

/// Read one segment whole for [`scan`], refusing a file longer than
/// [`MAX_SEGMENT_LEN`] on its length alone, before a byte of it is read: that
/// length is the file's own claim, and an allocation sized by it is what the
/// ceiling exists to refuse. `take` bounds the read even when the file grows
/// after its length is read — a live appender beneath
/// [`crate::Kernel::world_at`] — and a read that reaches past the ceiling
/// refuses as well, since what it holds is then a prefix of the file.
fn read_segment(path: &Path, s_load: u64) -> Result<Vec<u8>, ScanFail> {
    let file = File::open(path)?;
    let claimed = file.metadata()?.len();
    if claimed > MAX_SEGMENT_LEN {
        return Err(ScanFail::Unbounded { at: s_load });
    }
    // `claimed` is at most the ceiling, 2^27, so the cast is exact on any 32-
    // or 64-bit target and the reservation is the file's own size, as
    // `fs::read` would make it.
    let mut buf = Vec::with_capacity(claimed as usize);
    file.take(MAX_SEGMENT_LEN + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > MAX_SEGMENT_LEN {
        return Err(ScanFail::Unbounded { at: s_load });
    }
    Ok(buf)
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
/// `bound` is the boundary the caller will fold to, when it has one: committed
/// records and boundaries above it are not COLLECTED, since no caller reads
/// them, so a bounded replay of one transaction above a checkpoint no longer
/// materializes every committed record in the retained window. `None` collects
/// the whole scanned region, which recovery needs — its own bound is
/// [`ScanOutcome::committed_head`], and that is not known until this returns.
/// Every segment above the base is still READ either way: the corrupt-run
/// classification is at any height, and [`ScanOutcome::committed_head`] and the
/// tail cut must name the last committed marker wherever it sits.
///
/// Memory: one segment's bytes — at most [`MAX_SEGMENT_LEN`], a longer file
/// being refused ([`ScanFail::Unbounded`]) before a byte of it is read, since
/// its length is its own claim — one transaction's records, and the committed
/// records of the scanned region at or below `bound` — the last of which is
/// the term that grows with the journal, and is what a caller bounds by
/// checkpointing, or by asking for a lower boundary.
///
/// Work: the sequential walk is one pass per scanned segment, and
/// resynchronization is bounded at [`RESYNC_BUDGET_PASSES`] more. A segment
/// that exhausts that budget refuses the scan outright
/// ([`ScanFail::Unbounded`]) rather than answering with a prefix, so a payload
/// that plants frame headers costs a bounded scan and a halt rather than an
/// unbounded one.
///
/// THE CHAIN IS VERIFIED HERE, in the same pass (QUEUE item 10): every
/// committed transaction above `s_load` must carry, in its marker, the
/// recomputation of [`ChainLink`] over the previous committed transaction's
/// value — `chain_at_base` for the first, which is [`CHAIN_GENESIS`] from
/// genesis and the `SKC4` header's `chain_head` off a checkpoint — its own
/// record payloads as the CRC verified them, and the salt the marker itself
/// carries (`SKJ4`; read, never drawn). A mismatch is recorded as
/// the first CHAIN BREAK ([`ScanOutcome::chain_break`]) and the running value
/// continues from the marker's own claim; transactions at or below the base
/// are not verified, being embodied in it, exactly as a corrupt run there is
/// harmless. The link is verified in JOURNAL order, which is the order the
/// writer chained in, and it is verified without re-serializing anything:
/// the bytes hashed are the framed payloads in the buffer.
///
/// TWO MORE VERDICTS ARE RECORDED in the same pass, refused by the callers
/// as the break is (the chain's open items, 2026-09-23). THE BASE'S OWN
/// LINK: when the committed marker closing `s_load` itself is scanned — at
/// the head whenever the active segment holds it, which it does unless that
/// segment is EMPTY after a rotation whose transaction failed or never
/// landed; mid-history whenever the base's segment is — its `chain` must
/// equal `chain_at_base`, the header's `chain_head`, else
/// [`ScanOutcome::base_mismatch`] names the base: two stored values
/// disagree, and a header edited at the head, which no link above it would
/// ever judge, is seen here rather than forked from. THE EDITED
/// TRANSACTION: a group whose every frame was intact and which an intact
/// marker fails to close — refusing it, or naming another transaction as its
/// own — a shape no writer of this format produces, is recorded as
/// [`ScanOutcome::uncommitted_intact`] at the group's own last seq, naming
/// the transaction that was edited rather than the next one, whose link then
/// also fails. Neither moves `committed_head`, the collections or the tail
/// cut: the scan records, the callers halt. And ONE VALUE IS CAPTURED: the
/// running chain at `bound`, which [`ScanOutcome::chain_at_boundary`]
/// answers [`crate::Kernel::chain_at`] with.
///
/// `segs` must be ASCENDING by `firstSeq`, as [`list_segments`] produces it.
/// The skip test, the tail resolution and [`inferred_last_seq`] all read a
/// neighbour's name as this segment's bound, so an out-of-order slice makes
/// those inferences meaningless — and [`reclaim_below`], which reads the same
/// order, deletes on one of them.
///
/// Reached through [`crate::replay::Base::scan`], which supplies `s_load` and
/// `chain_at_base` from the base it selected. A scan and the fold that
/// consumes it must agree on their base, and that is the one route where they
/// cannot disagree.
pub(crate) fn scan(
    segs: &[SegmentMeta],
    s_load: u64,
    bound: Option<u64>,
    chain_at_base: [u8; 32],
) -> Result<ScanOutcome, ScanFail> {
    let mut outcome = ScanOutcome {
        s_load,
        bound,
        committed_head: s_load,
        committed_records: Vec::new(),
        committed_boundaries: Vec::new(),
        runs: Vec::new(),
        tail: None,
        chain_head: chain_at_base,
        chain_break: None,
        base_mismatch: None,
        uncommitted_intact: None,
        chain_at_bound: None,
    };
    // The commit chain's running value: the last committed marker's above
    // the base, in journal order, else the base's.
    let mut chain = chain_at_base;
    // The scanned-segment index and the BYTE offset just past the last
    // committed marker's frame — where the tail begins. Resolved to a
    // `TailCut` once at the end rather than at each committed marker, which
    // would clone the discard list per commit.
    let mut cut: Option<(usize, u64)> = None;
    // The first segment this scan did not skip: what the tail resolution
    // below falls to when no committed marker is found anywhere.
    let mut first_scanned: Option<usize> = None;
    let mut pending: Option<PendingTxn> = None;
    // A corrupt run has begun and its end is not yet known. The next intact
    // frame closes it — `RunEnd::landed_on_record` or `landed_on_marker` —
    // and end-of-journal closes it as `RunEnd::Eof`.
    let mut run_open = false;
    for (seg_index, seg) in segs.iter().enumerate() {
        if inferred_last_seq(segs, seg_index).is_some_and(|last| last <= s_load) {
            continue;
        }
        if first_scanned.is_none() {
            first_scanned = Some(seg_index);
        }
        let buf = read_segment(&seg.path, s_load)?;
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
                    let payload = &buf[payload];
                    match codec().deserialize::<FramePayload>(payload) {
                        Ok(FramePayload::Record(record)) => {
                            // A group opened by the record a run landed on
                            // is not clean: the run may have been its own
                            // earlier frames. A group already open met the
                            // run while open, and was marked below.
                            let landed = run_open;
                            if run_open {
                                outcome.runs.push(RunEnd::landed_on_record(record.seq));
                                run_open = false;
                            }
                            let mut group = pending
                                .take()
                                .filter(|group| group.txn == record.txn)
                                .unwrap_or_else(|| PendingTxn::open(record.txn, &chain, !landed));
                            group.push(record, payload);
                            pending = Some(group);
                        }
                        Ok(FramePayload::Marker(marker)) => {
                            if run_open {
                                outcome.runs.push(RunEnd::landed_on_marker(marker.last_seq));
                                run_open = false;
                            }
                            if let Some(group) = pending.take_if(|group| group.txn == marker.txn) {
                                if group.commits(&marker) {
                                    // The chain: verified above the base only
                                    // — the base embodies what sits at or
                                    // below it — and recorded, not refused,
                                    // so the run classification speaks first.
                                    if marker.last_seq > s_load {
                                        if group.recomputed_chain(&marker) != marker.chain
                                            && outcome.chain_break.is_none()
                                        {
                                            outcome.chain_break = Some(marker.last_seq);
                                        }
                                        chain = marker.chain;
                                        // The value at the bound, once the
                                        // running chain IS this marker's.
                                        if bound == Some(marker.last_seq) {
                                            outcome.chain_at_bound = Some(chain);
                                        }
                                    } else if marker.last_seq == s_load
                                        && marker.chain != chain_at_base
                                        && outcome.base_mismatch.is_none()
                                    {
                                        // The base's own link: the marker
                                        // closing the base's seq carries the
                                        // chain the header must — stored
                                        // against stored, nothing recomputed.
                                        outcome.base_mismatch = Some(s_load);
                                    }
                                    outcome.collect_commit(&marker, group.records);
                                    // The cut is unbounded for the reason the
                                    // head is: it must name the last committed
                                    // marker wherever it sits.
                                    cut = Some((seg_index, end as u64));
                                } else if group.clean && outcome.uncommitted_intact.is_none() {
                                    // Every frame intact, the marker intact,
                                    // and it does not close them: no writer
                                    // produces this — the marker was edited.
                                    // Named at the GROUP's last seq, the
                                    // marker's being the forged field in one
                                    // of the two shapes. Not committed all
                                    // the same: the scan records, the
                                    // callers halt.
                                    outcome.uncommitted_intact =
                                        Some(group.last_seq.unwrap_or(marker.last_seq));
                                }
                                // else: torn txn — not committed; its frames are
                                // either beyond W (tail, truncated) or explained
                                // by a corrupt run the caller classifies (§7).
                            } else if let Some(group) =
                                pending.as_ref().filter(|group| group.clean)
                            {
                                // A clean group whose next intact frame is
                                // ANOTHER transaction's marker: the writer
                                // emits a transaction's marker immediately
                                // after its own records, so no writer leaves
                                // this — the marker's `txn` was rewritten, and
                                // the group it should have closed can never
                                // commit. Named at the group's own last seq,
                                // as a refused close is; the group stays open
                                // and inert, as a non-matching marker leaves it.
                                if outcome.uncommitted_intact.is_none() {
                                    outcome.uncommitted_intact = group.last_seq;
                                }
                            }
                        }
                        // Intact by CRC but undecodable: under one stamp no
                        // writer of this format writes it and no torn write
                        // leaves it, so it is a rewrite. It joins run
                        // classification, and an open group is no longer
                        // clean: mid-history the run lands on the next intact
                        // frame and halts the caller; in the LAST transaction
                        // the run lies above the committed head, where §7
                        // calls it the torn tail, and the transaction is cut
                        // though its CRC proves these are the bytes that were
                        // written — the open item in `Kernel::open`'s damage
                        // model.
                        Err(_) => {
                            run_open = true;
                            if let Some(group) = pending.as_mut() {
                                group.clean = false;
                            }
                        }
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
                    // A group open across a corrupt frame may have lost one
                    // of its own: whatever its marker says of it is the
                    // run's to explain, never the edited-transaction verdict.
                    if let Some(group) = pending.as_mut() {
                        group.clean = false;
                    }
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
    outcome.chain_head = chain;
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

/// The account a chain break travels with, in the two callers' `cause`
/// slot: what the marker at `at` should have carried and did not.
pub(crate) fn chain_break_cause(at: u64) -> Box<dyn std::error::Error + Send + Sync + 'static> {
    format!(
        "chain break: the commit marker closing the transaction at {at} does not carry SHA-256 \
         over the previous committed transaction's chain value and this transaction's own record \
         frames — the transaction was rewritten consistently with its frame CRCs, or the one it \
         follows is not the one before it"
    )
    .into()
}

/// The account the base's own link travels with
/// ([`ScanOutcome::base_mismatch`]): two stored values at one coordinate
/// disagree, and which party lies is not said — so the remedy is the
/// operator's, named here, rather than a silent fallback to an older base
/// that would leave the edited header on disk for the next head to publish.
pub(crate) fn base_mismatch_cause(at: u64) -> Box<dyn std::error::Error + Send + Sync + 'static> {
    format!(
        "chain break at the base: the checkpoint at {at} carries a chain_head that is not the \
         chain the journal's own commit marker closing {at} carries — the checkpoint header was \
         rewritten, or the marker was; nothing was recomputed, two stored values disagree. Remove \
         or restore the checkpoint and the open re-verifies from the base below it"
    )
    .into()
}

/// The account the edited transaction travels with
/// ([`ScanOutcome::uncommitted_intact`]): the shape, the five ways an intact
/// marker fails to close an intact group, and why no writer leaves it.
pub(crate) fn uncommitted_intact_cause(
    at: u64,
) -> Box<dyn std::error::Error + Send + Sync + 'static> {
    format!(
        "chain break at an edited transaction: the transaction ending at {at} is intact frame by \
         frame but no commit marker closes it — the marker after its records disagrees with them \
         in records_checksum or last_seq, or they are not Seq-ascending, or they exceed the \
         transaction budget, or that marker names another transaction as its own; no writer of \
         this journal produces that shape, so the marker was rewritten, and the transaction it \
         should have closed is un-committed"
    )
    .into()
}

/// The account a damaged sync word travels with ([`FirstSyncWord::Damaged`]):
/// the word found, why it is damage and not a format, and the remedy — which
/// is NOT [`crate::OpenError::ForeignFormat`]'s, the board being this build's.
pub(crate) fn damaged_sync_word_cause(
    found: [u8; 4],
) -> Box<dyn std::error::Error + Send + Sync + 'static> {
    format!(
        "damaged sync word: the first frame the scan would read opens with `{found}`, where the \
         frame after it opens with this build's `{ours}` — another format's journal carries its \
         stamp in every frame, so this is one damaged word in a journal this build wrote, and the \
         frame's CRC does not cover it. Restore the segment from a copy, or rewrite those four \
         bytes to `{ours}` and reopen, when the scan judges the frame by its CRC; this board needs \
         no migration",
        found = stamp_text(&found),
        ours = stamp_text(&MAGIC),
    )
    .into()
}

/// What the first segment [`scan`] would read opens with — the answer of
/// [`first_sync_word`], which [`crate::Kernel::open`] asks BEFORE the scan.
/// A format shows in EVERY frame's sync word, and damage in ONE: the two are
/// told apart by the frame after the first.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum FirstSyncWord {
    /// This build's stamp, an empty or absent segment, or no well-formed sync
    /// word at all — zeros, a torn header, junk: the scan's to classify, as a
    /// corrupt run or the un-acked tail (the dirty-crash suite's honest
    /// outcomes), never a format event.
    Scan,
    /// A well-formed sync word of ANOTHER format — [`STAMP_PREFIX`] and a
    /// numeral this build does not write — on a frame whose successor does
    /// not open with this build's stamp, or cannot be read: another format's
    /// journal.
    Foreign([u8; 4]),
    /// A well-formed sync word that is not this build's, on a frame whose
    /// successor opens with this build's: ONE damaged word in a journal this
    /// build wrote. The frame CRC covers the length and the payload and not
    /// the sync word, so nothing else about the frame says so.
    Damaged([u8; 4]),
}

/// THE FIRST-SYNC-WORD PROBE (§8 of the encoding report): what the first
/// segment [`scan`] would read above `s_load` opens with — the same skip rule,
/// so this looks where the scan will look.
///
/// Read BEFORE the scan by [`crate::Kernel::open`], because the scan cannot
/// tell a format from damage: an old-format segment contains no frame the new
/// sync word anchors, so its resynchronization runs to end-of-file, classifies
/// the whole segment as the un-acked tail, and the tail cut then TRUNCATES it
/// to nothing and serves an empty board — an old-stamp board wiped rather than
/// refused. Refusing on this probe, ahead of the scan and the cut, is what
/// leaves the files untouched.
///
/// And a foreign-shaped word alone does not name a format: every one-bit flip
/// of this build's numeral keeps the [`STAMP_PREFIX`], and the frame CRC does
/// not cover the sync word, so one flipped bit would read as a board of
/// another format — whose ruled remedy discards the board. So such a word is
/// judged by its frame's SUCCESSOR, at the offset the first frame's own `len`
/// names: this build's stamp there is [`FirstSyncWord::Damaged`], anything
/// else [`FirstSyncWord::Foreign`]. A successor that cannot be read — a
/// header too short to name its offset, a segment ending first — stays
/// foreign: a format whose frame header is not this one's puts its successor
/// wherever it likes, and scanning such a journal would wipe it.
///
/// Reads the first frame's header and four bytes at its successor, whatever
/// the segment's size.
pub(crate) fn first_sync_word(segs: &[SegmentMeta], s_load: u64) -> io::Result<FirstSyncWord> {
    let Some(first) = segs
        .iter()
        .enumerate()
        .find(|(i, _)| inferred_last_seq(segs, *i).is_none_or(|last| last > s_load))
        .map(|(_, seg)| seg)
    else {
        return Ok(FirstSyncWord::Scan);
    };
    let mut file = File::open(&first.path)?;
    let mut header = Vec::with_capacity(FRAME_HEADER_LEN);
    (&mut file)
        .take(FRAME_HEADER_LEN as u64)
        .read_to_end(&mut header)?;
    let Some(&word) = header.first_chunk::<4>() else {
        return Ok(FirstSyncWord::Scan); // shorter than a sync word: damage or empty
    };
    if word == MAGIC || !word.starts_with(STAMP_PREFIX) {
        return Ok(FirstSyncWord::Scan);
    }
    let Some(len) = header
        .get(4..8)
        .and_then(|len| <[u8; 4]>::try_from(len).ok())
        .map(u32::from_le_bytes)
    else {
        return Ok(FirstSyncWord::Foreign(word));
    };
    file.seek(SeekFrom::Start(FRAME_HEADER_LEN as u64 + u64::from(len)))?;
    let mut successor = Vec::with_capacity(MAGIC.len());
    file.take(MAGIC.len() as u64).read_to_end(&mut successor)?;
    Ok(if successor == MAGIC {
        FirstSyncWord::Damaged(word)
    } else {
        FirstSyncWord::Foreign(word)
    })
}

/// The tail-truncation step (§7), run AFTER every refusal and BEFORE any
/// write is served: durably remove everything after the last committed marker
/// — cut its segment at the marker's frame end, delete every wholly-later
/// segment, fsync file and directory. Every halt precedes it — every route to
/// [`crate::OpenError::Corruption`], which enumerates them, and the exhausted
/// checkpoint chain of [`crate::OpenError::BadCheckpoint`] — which is what
/// leaves the journal directory an operator images after a halt exactly as it
/// was found (§7); [`crate::Kernel::open`] is where that order is kept and
/// stated. This is what makes cross-session `Txn` uniqueness and
/// file-order == `Seq`-order true at the next recovery (§1/§7). Idempotent; a
/// failure fails `open()` with `Io`.
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
            .commit_txn(first, record_bytes, |_| {})
            .expect("fixture commit");
    }

    /// The seeded salt source these fixtures write under: deterministic, so
    /// a fixture's bytes are the same on every run, and named once.
    const TEST_SEED: u64 = 0x5A17;

    /// A fixed salt for the frame builder's direct callers, where the source
    /// is not under test and a value with a shape beats zeros.
    const FIXED_SALT: [u8; 32] = [0xA5; 32];

    /// A fresh appender at genesis: the chain seeded where a new journal's is,
    /// the salts from the seeded stream.
    fn fresh_writer(dir: &Path) -> JournalWriter {
        JournalWriter::open_active(dir, 1, CHAIN_GENESIS, SaltSource::Seeded(TEST_SEED)).unwrap()
    }

    /// An unsigned marker whose chain is NOT under test — the fixtures that
    /// hand-build a marker build one that never commits, or one with no
    /// group, so the chain it carries is never read — and whose salt is
    /// likewise never hashed against anything.
    fn marker(txn: Txn, last_seq: u64, records_checksum: u32) -> Marker {
        Marker {
            txn,
            last_seq,
            records_checksum,
            salt: [0u8; 32],
            chain: [0u8; 32],
            sig_alg: SIG_ALG_UNSIGNED,
            sig: Vec::new(),
        }
    }

    /// The committed marker closing the frame at `pos`, decoded whole.
    fn marker_at(path: &Path, pos: usize) -> Marker {
        let buf = fs::read(path).unwrap();
        let Parsed::Intact { payload } = parse_frame(&buf, pos) else {
            panic!("intact marker frame expected at {pos}")
        };
        match codec().deserialize::<FramePayload>(&buf[payload]).unwrap() {
            FramePayload::Marker(m) => m,
            FramePayload::Record(_) => panic!("a marker frame expected at {pos}"),
        }
    }

    /// Every marker of a CLEAN journal file, in file order.
    fn markers_in(path: &Path) -> Vec<Marker> {
        let buf = fs::read(path).unwrap();
        frame_starts(path)
            .into_iter()
            .filter_map(|pos| {
                let Parsed::Intact { payload } = parse_frame(&buf, pos) else {
                    panic!("clean journal expected")
                };
                match codec().deserialize::<FramePayload>(&buf[payload]).unwrap() {
                    FramePayload::Marker(m) => Some(m),
                    FramePayload::Record(_) => None,
                }
            })
            .collect()
    }

    /// The `chain` field of the committed marker closing the frame at `pos`.
    fn chain_of_marker_at(path: &Path, pos: usize) -> [u8; 32] {
        marker_at(path, pos).chain
    }

    /// Rewrite the payload of the intact frame at `pos` through `edit` and
    /// RE-SEAL its CRC, so the frame stays intact: what a consistent rewrite
    /// looks like — the thing the chain exists to catch and the CRC cannot.
    fn rewrite_payload(path: &Path, pos: usize, edit: impl FnOnce(&mut [u8])) {
        let mut data = fs::read(path).unwrap();
        let Parsed::Intact { payload } = parse_frame(&data, pos) else {
            panic!("intact frame expected at {pos}")
        };
        edit(&mut data[payload.clone()]);
        let crc = crc32c::crc32c_append(crc32c::crc32c(&data[pos + 4..pos + 8]), &data[payload]);
        data[pos + 8..pos + 12].copy_from_slice(&crc.to_le_bytes());
        fs::write(path, data).unwrap();
    }

    /// Byte offset of each frame in a CLEAN journal file, via the real parser
    /// — which is what a fixture aims damage with.
    fn frame_starts(path: &Path) -> Vec<usize> {
        let buf = fs::read(path).unwrap();
        let mut starts = Vec::new();
        let mut pos = 0;
        while pos < buf.len() {
            match parse_frame(&buf, pos) {
                Parsed::Intact { payload } => {
                    starts.push(pos);
                    pos = payload.end;
                }
                Parsed::Bad { .. } => panic!("clean journal expected"),
            }
        }
        starts
    }

    fn flip_byte(path: &Path, offset: usize) {
        let mut data = fs::read(path).unwrap();
        data[offset] ^= 0xFF;
        fs::write(path, data).unwrap();
    }

    fn committed_seqs(out: &ScanOutcome) -> Vec<u64> {
        let mut s: Vec<u64> = out.committed_records.iter().map(|r| r.seq).collect();
        s.sort_unstable();
        s
    }

    /// The coordinates `records_to` hands a fold, in the order it hands them —
    /// so an assertion reads as the sequence of applications it stands for.
    fn folded_seqs(out: &ScanOutcome, bound: u64) -> Result<Vec<u64>, u64> {
        out.records_to(bound)
            .map(|records| records.iter().map(|entry| entry.seq).collect())
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
        for record_bytes in [
            vec![vec![5u8; 3]],
            vec![rec(u64::MAX), vec![7u8; 300], Vec::new()],
        ] {
            let expected = txn_encoded_len(&record_bytes);
            let (buf, _) =
                encode_txn(u64::MAX - 3, record_bytes, &CHAIN_GENESIS, FIXED_SALT).unwrap();
            assert_eq!(buf.len() as u64, expected);
        }
        // The marker half, stated as the figures the layout doc promises: a
        // 97-byte payload with the slot empty (`SKJ4`: the salt's thirty-two
        // after `SKJ3`'s sixty-five), a 109-byte frame.
        let empty_marker = codec()
            .serialize(&FramePayload::Marker(marker(Txn(u64::MAX), u64::MAX, u32::MAX)))
            .unwrap();
        assert_eq!(empty_marker.len(), 97);
        assert_eq!(MARKER_FRAME_LEN, 109);
        assert_eq!(MARKER_FRAME_LEN, frame_len(empty_marker.len() as u64));
        // The per-record half: what push_frame judges is the wrapped payload,
        // the record's own bytes plus RECORD_PAYLOAD_OVERHEAD exactly.
        let payload = codec()
            .serialize(&FramePayload::Record(LogRecord {
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
        let mut group = PendingTxn::open(Txn(u64::MAX), &CHAIN_GENESIS, true);
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
        // Each record is charged against the two size limits as the commit
        // encodes it.
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
        let out = journal.commit_txn(1, over_frame, |_| installs += 1);
        assert!(matches!(out, Err(CommitFail::Unencodable(_))), "got {out:?}");

        // At the budget exactly: commits — the refusal begins one past the
        // budget, not at it.
        let body = (MAX_TXN_BYTES - txn_encoded_len(&[Vec::new()])) as usize - prefix;
        let at_budget = vec![vec![0u8; body]];
        assert_eq!(
            txn_encoded_len(&[encode_record(&at_budget[0]).unwrap()]),
            MAX_TXN_BYTES
        );
        assert!(journal.commit_txn(1, at_budget, |_| installs += 1).is_ok());

        // One byte past: OverBudget, carrying the size.
        let past_budget = vec![vec![0u8; body + 1]];
        match journal.commit_txn(1, past_budget, |_| installs += 1) {
            Err(CommitFail::OverBudget { bytes }) => assert_eq!(bytes, MAX_TXN_BYTES + 1),
            other => panic!("expected OverBudget, got {other:?}"),
        }

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
        match journal.commit_txn(1, far_over, |_| installs += 1) {
            Err(CommitFail::OverBudget { bytes }) => assert_eq!(bytes, expected),
            other => panic!("expected the whole staging accounted, got {other:?}"),
        }

        assert_eq!(installs, 1, "only the at-budget transaction installs");
    }

    #[test]
    fn a_record_past_the_frame_cap_is_unencodable_after_the_budget_is_crossed() {
        // The record's own refusal precedes the staging's AT EVERY POSITION,
        // not only at the first: the loop keeps judging each record's frame
        // cap past the crossing, so a caller fixing a value is never first
        // told to split — and then handed the same refusal on the split half.
        let prefix = encode_record(&Vec::<u8>::new()).unwrap().len();
        let cap_bytes = (MAX_FRAME_LEN as u64 - RECORD_PAYLOAD_OVERHEAD) as usize;
        // The largest record the frame cap admits already puts the transaction
        // over the budget on its own — so the crossing happens at record one…
        let at_cap = vec![0u8; cap_bytes - prefix];
        // …and record two, one byte larger, still cannot be framed.
        let past_cap = vec![0u8; cap_bytes + 1 - prefix];
        let mut journal = Journal::InMemory;
        let mut installed = false;
        let out = journal.commit_txn(1, vec![at_cap, past_cap], |_| installed = true);
        assert!(matches!(out, Err(CommitFail::Unencodable(_))), "got {out:?}");
        assert!(!installed, "a refused transaction installs nothing");
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
        // The encode and the two size judgments belong to `Journal::commit_txn`
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
        let out = memory.commit_txn(1, vec![RefusesSerialization], |_| installed = true);
        assert!(matches!(out, Err(CommitFail::Unencodable(_))), "got {out:?}");

        // The frame cap, which is a property of frames this arm never builds.
        let prefix = encode_record(&Vec::<u8>::new()).unwrap().len();
        let cap_bytes = (MAX_FRAME_LEN as u64 - RECORD_PAYLOAD_OVERHEAD) as usize;
        let over_frame = vec![vec![0u8; cap_bytes + 1 - prefix]];
        let out = memory.commit_txn(1, over_frame, |_| installed = true);
        assert!(matches!(out, Err(CommitFail::Unencodable(_))), "got {out:?}");

        // The transaction budget, likewise.
        let half = (MAX_TXN_BYTES / 2) as usize;
        let over_budget = vec![vec![0u8; half], vec![0u8; half]];
        let out = memory.commit_txn(1, over_budget, |_| installed = true);
        assert!(matches!(out, Err(CommitFail::OverBudget { .. })), "got {out:?}");

        assert!(!installed, "a refused transaction installs nothing");

        // …and the durable arm answers the same, which is the parity these
        // three refusals exist to hold: one judgment, one place, both modes.
        let dir = tempdir().unwrap();
        let mut segments = Journal::Segments(fresh_writer(dir.path()));
        let out = segments.commit_txn(1, vec![RefusesSerialization], |_| installed = true);
        assert!(matches!(out, Err(CommitFail::Unencodable(_))), "got {out:?}");
        assert!(!installed, "a refused transaction installs nothing");
    }

    #[test]
    fn records_to_orders_the_fold_ranges_it_and_refuses_a_repeated_seq() {
        // The three facts about the derived set, settled where the set is:
        // `apply` need not be idempotent, so a coordinate applied twice is
        // silent double application answered `Ok`, and a coordinate applied
        // out of order is a fold over a state that never existed.
        let dir = tempdir().unwrap();
        let mut writer = fresh_writer(dir.path());
        // File order is NOT `Seq` order here. In-order append plus the prior
        // recovery's tail truncation normally makes the two agree, and the
        // ordering is what holds a fold together where they do not.
        write_txn(&mut writer, 5, vec![rec(50)]);
        write_txn(&mut writer, 1, vec![rec(10), rec(20)]); // seqs 1, 2
        let segs = list_segments(dir.path()).unwrap();

        let outcome = scan(&segs, 0, None, CHAIN_GENESIS).unwrap();
        assert_eq!(folded_seqs(&outcome, 5), Ok(vec![1, 2, 5]));
        // The range is INCLUSIVE at the bound — a fold to 2 applies 2.
        assert_eq!(folded_seqs(&outcome, 2), Ok(vec![1, 2]));
        // …and EXCLUSIVE at the base, whose records the base already embodies.
        assert_eq!(folded_seqs(&scan(&segs, 1, None, CHAIN_GENESIS).unwrap(), 5), Ok(vec![2, 5]));
    }

    #[test]
    fn a_seq_the_committed_set_presents_twice_is_refused_in_range_and_ignored_below_it() {
        // Two committed transactions at ONE coordinate: a journal no sequencer
        // here wrote, since each `Seq` is minted once. Refused rather than
        // folded twice (§7) — and the range is applied FIRST, so a repeat the
        // base already embodies is harmless rather than a halt.
        let dir = tempdir().unwrap();
        let mut writer = fresh_writer(dir.path());
        write_txn(&mut writer, 1, vec![rec(10)]);
        write_txn(&mut writer, 1, vec![rec(20)]);
        let segs = list_segments(dir.path()).unwrap();

        assert_eq!(folded_seqs(&scan(&segs, 0, None, CHAIN_GENESIS).unwrap(), 1), Err(1));
        assert_eq!(folded_seqs(&scan(&segs, 1, None, CHAIN_GENESIS).unwrap(), 1), Ok(vec![]));
    }

    #[test]
    #[should_panic(expected = "did not collect that far")]
    fn a_fold_past_what_the_scan_collected_is_refused_as_the_callers_bug() {
        // Records above the collection bound were read and dropped, so a fold
        // past it reads a set that is missing exactly the range between —
        // which no filter here can restore, and which would otherwise be
        // answered `Ok` with a short world.
        let dir = tempdir().unwrap();
        let mut writer = fresh_writer(dir.path());
        write_txn(&mut writer, 1, vec![rec(10)]);
        write_txn(&mut writer, 2, vec![rec(20)]);
        let segs = list_segments(dir.path()).unwrap();
        let _ = scan(&segs, 0, Some(1), CHAIN_GENESIS).unwrap().records_to(2);
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
            let payload = codec()
                .serialize(&FramePayload::Record(LogRecord {
                    seq: 2,
                    txn: Txn(2),
                    bytes,
                }))
                .unwrap();
            checksum = crc32c::crc32c_append(checksum, &payload);
            push_frame(&mut buf, &payload).unwrap();
        }
        let payload = codec()
            .serialize(&FramePayload::Marker(marker(Txn(2), 2, checksum)))
            .unwrap();
        push_frame(&mut buf, &payload).unwrap();

        let dir = tempdir().unwrap();
        fs::write(segment_path(dir.path(), 2), &buf).unwrap();
        let segs = list_segments(dir.path()).unwrap();
        let out = scan(&segs, 1, None, CHAIN_GENESIS).unwrap();
        assert_eq!(out.committed_head, 1, "the repeat must not commit");
        assert!(out.committed_records.is_empty());
        assert!(out.committed_boundaries.is_empty());
        // Every frame intact and the marker not closing them: the
        // edited-transaction verdict is RECORDED at the group's last seq —
        // the scan refuses nothing itself; the callers halt on it.
        assert_eq!(out.uncommitted_intact(), Some(2));
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
            let payload = codec()
                .serialize(&FramePayload::Record(LogRecord {
                    seq,
                    txn: Txn(5),
                    bytes: rec(seq * 10),
                }))
                .unwrap();
            checksum = crc32c::crc32c_append(checksum, &payload);
            push_frame(&mut buf, &payload).unwrap();
        }
        // `last_seq` 5: the group reaches 7.
        let payload = codec()
            .serialize(&FramePayload::Marker(marker(Txn(5), 5, checksum)))
            .unwrap();
        push_frame(&mut buf, &payload).unwrap();

        let dir = tempdir().unwrap();
        fs::write(segment_path(dir.path(), 5), &buf).unwrap();
        let segs = list_segments(dir.path()).unwrap();
        let out = scan(&segs, 4, None, CHAIN_GENESIS).unwrap();
        assert_eq!(out.committed_head, 4, "a short marker must not commit");
        assert!(out.committed_records.is_empty());
        assert!(out.committed_boundaries.is_empty());
        // Recorded at the GROUP's last seq (7), not the marker's forged 5.
        assert_eq!(out.uncommitted_intact(), Some(7));
    }

    #[test]
    fn a_marker_naming_another_transaction_is_the_edited_one() {
        // The marker's third pre-chain field. A marker whose `txn` names
        // another transaction closes nothing, and a clean group's next intact
        // frame is its own marker in anything a writer here emits — so the
        // group is the edited transaction, named where its marker should have
        // closed it. Left open instead, it is dropped at the scan's end, and
        // on the last transaction cut as the torn tail: an acknowledged commit
        // removed on a one-field rewrite.
        let dir = tempdir().unwrap();
        let mut writer = fresh_writer(dir.path());
        write_txn(&mut writer, 1, vec![rec(10)]);
        write_txn(&mut writer, 2, vec![rec(20), rec(21)]); // seqs 2, 3: the last transaction
        drop(writer);
        let segs = list_segments(dir.path()).unwrap();
        let starts = frame_starts(&segs[0].path);
        // Frames: 0=T1 rec, 1=T1 marker, 2..=3=T2 recs, 4=T2 marker; the
        // marker's `txn` is payload bytes 4..12, after the FramePayload tag.
        rewrite_payload(&segs[0].path, starts[4], |payload| payload[4] ^= 0xFF);
        let out = scan(&segs, 0, None, CHAIN_GENESIS).unwrap();
        assert!(out.runs.is_empty(), "no frame was damaged");
        assert_eq!(out.committed_head, 1, "the rewritten marker commits nothing");
        assert_eq!(out.uncommitted_intact(), Some(3), "named at the group's own last seq");
        // …and still named off a base at 3, which claims to embody it: the
        // verdict compares a marker with its own records and needs no link
        // from the base.
        assert_eq!(scan(&segs, 3, None, CHAIN_GENESIS).unwrap().uncommitted_intact(), Some(3));
    }

    #[test]
    fn a_group_past_the_transaction_budget_never_commits() {
        // The reader's half of the write path's own bound: `commit_txn`
        // refuses a staging past MAX_TXN_BYTES before a byte is appended, so a
        // group past it is one no writer here emits — and accepting it would
        // let a journal spread one `txn` over all its segments while the scan
        // held every record of it.
        //
        // The charge must reproduce the write side's term for term, which is
        // what the two cases below check from either side of the edge: four
        // record frames plus the marker frame land EXACTLY on the budget.
        const N: u64 = 4;
        // Four frames share the budget less the marker; the LAST absorbs the
        // division's remainder, so the sum lands on the budget exactly
        // whatever the marker's size leaves over.
        let for_records = MAX_TXN_BYTES - MARKER_FRAME_LEN;
        let payload_len = (for_records / N - FRAME_HEADER_LEN as u64) as usize;
        let last_len = payload_len + (for_records % N) as usize;
        let buf = vec![7u8; last_len + 1];
        let group_of = |last: &[u8]| {
            let mut group = PendingTxn::open(Txn(1), &CHAIN_GENESIS, true);
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
        let closed_by = |group: &PendingTxn| marker(Txn(1), N, group.checksum);

        // At the budget: a transaction this writer can emit, so it commits —
        // the refusal begins one byte past the budget, not at it.
        let at_budget = group_of(&buf[..last_len]);
        assert_eq!(at_budget.accounted, MAX_TXN_BYTES);
        assert!(at_budget.commits(&closed_by(&at_budget)));
        assert_eq!(at_budget.records.len() as u64, N);

        // One byte past: refused, however its checksum lands — and the records
        // are released where the group is known dead, which is the memory this
        // bound exists for.
        let over_budget = group_of(&buf);
        assert_eq!(over_budget.accounted, MAX_TXN_BYTES + 1);
        assert!(!over_budget.commits(&closed_by(&over_budget)));
        assert!(
            over_budget.records.is_empty(),
            "a dead group holds no records"
        );
    }

    #[test]
    fn a_marker_at_the_seq_ceiling_classifies_without_wrapping() {
        // A marker contributes the coordinate one past its own `last_seq`. At
        // the ceiling there is no such coordinate, and the run is reported at
        // the ceiling — never wrapped to 0, which would report a run above the
        // base as one below it (§7).
        let mut buf = vec![0xABu8; 8]; // no magic: a corrupt run opens here
        let payload = codec()
            .serialize(&FramePayload::Marker(marker(Txn(u64::MAX), u64::MAX, 0)))
            .unwrap();
        push_frame(&mut buf, &payload).unwrap();

        let dir = tempdir().unwrap();
        fs::write(segment_path(dir.path(), 1), &buf).unwrap();
        let segs = list_segments(dir.path()).unwrap();
        let out = scan(&segs, 0, None, CHAIN_GENESIS).unwrap();
        assert_eq!(
            out.runs,
            vec![RunEnd::Landed {
                inferred_max: u64::MAX,
                at: u64::MAX
            }]
        );
    }

    #[test]
    fn frame_payloads_spend_a_bare_u64_on_the_txn_and_carry_the_documented_chain() {
        // The on-disk payload layout (§1), spelled out: bincode fixint LE —
        // the variant index as a `u32`, then the fields in declaration order,
        // with a [`Txn`] occupying exactly the `u64` it wraps. A journal
        // written by one build is read by the next, so the layout is pinned
        // here rather than left to whatever the derives happen to produce —
        // the marker's chain included, computed here by hand from the bytes
        // `ChainLink` says it covers — the salt last — so the formula is
        // pinned beside the layout and not only by the golden fixture.
        let (buf, chain) = encode_txn(2, vec![vec![9u8, 8, 7]], &CHAIN_GENESIS, FIXED_SALT).unwrap();

        let mut expected_record = Vec::new();
        expected_record.extend_from_slice(&0u32.to_le_bytes()); // FramePayload::Record
        expected_record.extend_from_slice(&2u64.to_le_bytes()); // seq
        expected_record.extend_from_slice(&2u64.to_le_bytes()); // txn == the first seq
        expected_record.extend_from_slice(&3u64.to_le_bytes()); // bytes.len()
        expected_record.extend_from_slice(&[9, 8, 7]);
        let Parsed::Intact { payload } = parse_frame(&buf, 0) else {
            panic!("intact record frame expected")
        };
        let end = payload.end; // where the marker frame begins
        assert_eq!(&buf[payload], expected_record.as_slice());

        // records_checksum: over the record frames' payloads, in Seq order.
        let records_checksum = crc32c::crc32c_append(0, &expected_record);
        // The chain: SHA-256 over the genesis seed, the record payload as
        // framed, the marker's own pre-chain fields in their wire form, then
        // the salt — the last bytes before finalize.
        let expected_chain: [u8; 32] = Sha256::new()
            .chain_update(CHAIN_GENESIS)
            .chain_update(&expected_record)
            .chain_update(2u64.to_le_bytes()) // txn
            .chain_update(2u64.to_le_bytes()) // last_seq
            .chain_update(records_checksum.to_le_bytes())
            .chain_update(FIXED_SALT) // salt
            .finalize()
            .into();
        assert_eq!(chain, expected_chain, "the writer answers the chain it framed");
        // …and a link closed WITHOUT the salt is not this chain: the salt is
        // hashed, not merely stored.
        let unsalted: [u8; 32] = Sha256::new()
            .chain_update(CHAIN_GENESIS)
            .chain_update(&expected_record)
            .chain_update(2u64.to_le_bytes())
            .chain_update(2u64.to_le_bytes())
            .chain_update(records_checksum.to_le_bytes())
            .finalize()
            .into();
        assert_ne!(chain, unsalted, "the salt is a chain input");

        let mut expected_marker = Vec::new();
        expected_marker.extend_from_slice(&1u32.to_le_bytes()); // FramePayload::Marker
        expected_marker.extend_from_slice(&2u64.to_le_bytes()); // txn
        expected_marker.extend_from_slice(&2u64.to_le_bytes()); // last_seq
        expected_marker.extend_from_slice(&records_checksum.to_le_bytes());
        expected_marker.extend_from_slice(&FIXED_SALT); // salt: a 32-tuple, no prefix
        expected_marker.extend_from_slice(&expected_chain); // chain: likewise
        expected_marker.push(SIG_ALG_UNSIGNED); // sig_alg
        expected_marker.extend_from_slice(&0u64.to_le_bytes()); // sig: empty, its length alone
        assert_eq!(expected_marker.len(), 97, "the empty marker payload");
        let Parsed::Intact { payload } = parse_frame(&buf, end) else {
            panic!("intact marker frame expected")
        };
        assert_eq!(&buf[payload], expected_marker.as_slice());
    }

    #[test]
    fn the_marker_decoder_admits_one_spelling_of_empty() {
        // The slot's rule, held at the decode door: tag 0 with no bytes is
        // EMPTY, the one spelling; tag 0 with bytes (a signature under no
        // pair) and a non-zero tag with none (a pair that signed nothing) are
        // refused, so no two readers can disagree about whether a marker is
        // signed. A filled slot under a non-zero tag DECODES — the kernel
        // never interprets the blob — and rejecting trailing bytes is what
        // keeps the length prefix the whole of the slot's extent.
        let honest = codec()
            .serialize(&FramePayload::Marker(marker(Txn(3), 3, 0)))
            .unwrap();
        assert!(codec().deserialize::<FramePayload>(&honest).is_ok());
        // Layout: tag 4 | txn 8 | last_seq 8 | checksum 4 | salt 32 | chain 32 | sig_alg @88 | len @89..97.
        let with = |sig_alg: u8, sig: &[u8]| {
            let mut bytes = honest[..88].to_vec();
            bytes.push(sig_alg);
            bytes.extend_from_slice(&(sig.len() as u64).to_le_bytes());
            bytes.extend_from_slice(sig);
            bytes
        };
        let refused = |bytes: &[u8]| {
            codec()
                .deserialize::<FramePayload>(bytes)
                .err()
                .map(|e| e.to_string())
                .expect("refused")
        };
        assert!(refused(&with(0, &[0xAA])).contains("one spelling of empty"));
        assert!(refused(&with(1, &[])).contains("one spelling of empty"));
        assert!(codec().deserialize::<FramePayload>(&with(1, &[0xAA, 0xBB])).is_ok());
        // Trailing bytes past the slot are not a longer slot: refused.
        let mut trailing = with(0, &[]);
        trailing.push(0);
        assert!(codec().deserialize::<FramePayload>(&trailing).is_err());
    }

    #[test]
    fn each_commit_chains_from_its_predecessor_and_a_consistent_rewrite_breaks_the_chain() {
        // The chain links every committed transaction to the one before it,
        // from the genesis seed; the scan recomputes each link from the
        // bytes the CRC verified and answers the head's value. A rewrite that
        // keeps every frame CRC consistent — which is what a file-level
        // writer does, and what neither the CRC nor `records_checksum` can
        // see — is caught as a CHAIN BREAK at the first transaction whose
        // marker no longer follows from its predecessor.
        let dir = tempdir().unwrap();
        let mut writer = fresh_writer(dir.path());
        write_txn(&mut writer, 1, vec![rec(10)]);
        write_txn(&mut writer, 2, vec![rec(20), rec(21)]);
        write_txn(&mut writer, 4, vec![rec(40)]);
        let segs = list_segments(dir.path()).unwrap();
        let starts = frame_starts(&segs[0].path);
        // Frames: 0=T1 rec, 1=T1 marker, 2..=3=T2 recs, 4=T2 marker, 5=T3 rec, 6=T3 marker.
        let out = scan(&segs, 0, None, CHAIN_GENESIS).unwrap();
        assert_eq!(out.chain_break(), None);
        assert_eq!(out.chain_head, chain_of_marker_at(&segs[0].path, starts[6]));
        assert_ne!(out.chain_head, CHAIN_GENESIS);
        // …and the appender continues from it: a scan from a base ABOVE T1
        // seeded with T1's own value verifies T2 and T3 against it.
        let t1 = chain_of_marker_at(&segs[0].path, starts[1]);
        let above = scan(&segs, 1, None, t1).unwrap();
        assert_eq!(above.chain_break(), None);
        assert_eq!(above.chain_head, out.chain_head);
        // …while a wrong base value is a break at the first transaction
        // above the base, and nowhere below it.
        let wrong = scan(&segs, 1, None, CHAIN_GENESIS).unwrap();
        assert_eq!(wrong.chain_break(), Some(3));

        // Rewrite T2's marker's chain — payload offset 56 under `SKJ4`, the
        // salt's thirty-two bytes sitting between the checksum and it —
        // re-sealing its frame CRC: every frame stays intact, every group
        // still commits, and the break lands on T2.
        let t2 = chain_of_marker_at(&segs[0].path, starts[4]);
        rewrite_payload(&segs[0].path, starts[4], |payload| payload[56] ^= 0xFF);
        assert_ne!(chain_of_marker_at(&segs[0].path, starts[4]), t2, "the rewrite took");
        let out = scan(&segs, 0, None, CHAIN_GENESIS).unwrap();
        assert!(out.runs.is_empty(), "no frame was damaged");
        assert_eq!(out.committed_head, 4, "the groups still commit — the halt is the caller's");
        assert_eq!(out.chain_break(), Some(3), "T2 closes at 3");
        // A rewritten marker AT the base is not this scan's to judge: the base
        // embodies it, and T3 verifies against the value the base vouches for
        // — what T2 carried when that base was taken…
        assert_eq!(scan(&segs, 3, None, t2).unwrap().chain_break(), None);
        // …while against a base that vouches for something else, T3 is the
        // first break, and T2 below it is never named.
        assert_eq!(scan(&segs, 3, None, [0x77; 32]).unwrap().chain_break(), Some(4));
    }

    /// Every frame of the CLEAN segment at `path` restamped with `stamp` —
    /// what a journal written under another format looks like to this parser,
    /// the frame CRC not covering the sync word.
    fn restamp_every_frame(path: &Path, stamp: &[u8; 4]) {
        let starts = frame_starts(path);
        let mut data = fs::read(path).unwrap();
        for pos in starts {
            data[pos..pos + 4].copy_from_slice(stamp);
        }
        fs::write(path, data).unwrap();
    }

    #[test]
    fn a_foreign_stamp_is_told_from_damage() {
        // The probe names a FORMAT only where the first frame's well-formed
        // sync word is not this build's AND the frame after it is not this
        // build's either: a format stamps every frame, damage changes one
        // word. This build's own stamp, an empty segment, a segment shorter
        // than a sync word, and junk at offset 0 are the scan's (an empty
        // journal, the un-acked tail, a corrupt run), never a format event —
        // and ONE foreign-shaped word before a frame of this build's is
        // damage, which every one-bit flip of the numeral is.
        let dir = tempdir().unwrap();
        let mut writer = fresh_writer(dir.path());
        write_txn(&mut writer, 1, vec![rec(10)]);
        drop(writer);
        let segs = list_segments(dir.path()).unwrap();
        let seg = segs[0].path.clone();
        let clean = fs::read(&seg).unwrap();
        // Frames: 0 = the record, 1 = its marker.
        let clean_starts = frame_starts(&seg);
        let probe = |segs: &[SegmentMeta], s_load: u64| first_sync_word(segs, s_load).unwrap();
        // The clean segment with its first bytes replaced — damage confined to
        // the opening, every later frame this build's.
        let opened_with = |word: &[u8]| {
            let mut data = clean.clone();
            data[..word.len()].copy_from_slice(word);
            fs::write(&seg, data).unwrap();
        };

        assert_eq!(probe(&segs, 0), FirstSyncWord::Scan, "this build's own stamp");
        for stamp in [b"SKJ3", b"SKJ2", b"SKJ1", b"SKJ9"] {
            fs::write(&seg, &clean).unwrap();
            restamp_every_frame(&seg, stamp);
            assert_eq!(probe(&segs, 0), FirstSyncWord::Foreign(*stamp), "every frame restamped");
        }
        // Every one-bit flip of this build's numeral keeps the `SKJ` prefix,
        // so by its word alone each reads as another format's stamp; the
        // frame after it opens with this build's, which no other format's
        // journal does.
        for bit in 0..8 {
            let word = [b'S', b'K', b'J', MAGIC[3] ^ (1 << bit)];
            opened_with(&word);
            assert_eq!(probe(&segs, 0), FirstSyncWord::Damaged(word), "bit {bit} of the numeral");
        }
        opened_with(&[0xAB, 0xCD, 0xEF, 0x01]);
        assert_eq!(probe(&segs, 0), FirstSyncWord::Scan, "junk is damage, not a format");
        opened_with(&[0, 0, 0, 0]);
        assert_eq!(probe(&segs, 0), FirstSyncWord::Scan, "zeros are damage, not a format");
        fs::write(&seg, b"SKJ").unwrap();
        assert_eq!(probe(&segs, 0), FirstSyncWord::Scan, "shorter than a sync word");
        fs::write(&seg, b"").unwrap();
        assert_eq!(probe(&segs, 0), FirstSyncWord::Scan, "an empty segment");
        assert_eq!(probe(&[], 0), FirstSyncWord::Scan, "no segment at all");
        // A foreign-shaped word whose successor cannot be read stays foreign:
        // a header too short to say where the successor begins, and a first
        // frame with nothing after it. Scanning either would wipe it.
        fs::write(&seg, b"SKJ3\x05\x00").unwrap();
        assert_eq!(probe(&segs, 0), FirstSyncWord::Foreign(*b"SKJ3"), "a header cut short");
        opened_with(b"SKJ3");
        let lone = fs::read(&seg).unwrap()[..clean_starts[1]].to_vec();
        fs::write(&seg, lone).unwrap();
        assert_eq!(probe(&segs, 0), FirstSyncWord::Foreign(*b"SKJ3"), "no successor to read");

        // The probe looks where the scan looks: a closed segment the base
        // embodies is skipped, so a foreign stamp there is not read — and
        // the first segment the scan WOULD read is.
        let dir = tempdir().unwrap();
        let mut writer = fresh_writer(dir.path());
        write_txn(&mut writer, 1, vec![vec![7u8; SEGMENT_ROTATE_BYTES as usize]]); // fills seg-1
        write_txn(&mut writer, 2, vec![rec(20)]); // rotates into seg-2
        drop(writer);
        let segs = list_segments(dir.path()).unwrap();
        assert_eq!(segs.len(), 2, "the fixture rotates");
        restamp_every_frame(&segs[0].path, b"SKJ2");
        assert_eq!(probe(&segs, 0), FirstSyncWord::Foreign(*b"SKJ2"), "seg-1 is read from genesis");
        assert_eq!(probe(&segs, 1), FirstSyncWord::Scan, "seg-1 is skipped above a base at 1");
        restamp_every_frame(&segs[1].path, b"SKJ2");
        assert_eq!(probe(&segs, 1), FirstSyncWord::Foreign(*b"SKJ2"), "seg-2 is read");
    }

    #[test]
    fn the_chain_rides_across_a_segment_rotation() {
        // The chain is over the journal, not the segment: the first
        // transaction of a new segment links from the last of the old one,
        // and a scan across the boundary verifies every link.
        let dir = tempdir().unwrap();
        let mut writer = fresh_writer(dir.path());
        write_txn(&mut writer, 1, vec![vec![7u8; SEGMENT_ROTATE_BYTES as usize]]); // fills seg-1
        write_txn(&mut writer, 2, vec![rec(20)]); // rotates into seg-2
        write_txn(&mut writer, 3, vec![rec(30)]);
        drop(writer);
        let segs = list_segments(dir.path()).unwrap();
        assert_eq!(segs.len(), 2, "the fixture rotates");
        let out = scan(&segs, 0, None, CHAIN_GENESIS).unwrap();
        assert_eq!(out.chain_break(), None);
        assert_eq!(out.committed_head, 3);
        let seg2_starts = frame_starts(&segs[1].path);
        assert_eq!(out.chain_head, chain_of_marker_at(&segs[1].path, seg2_starts[3]));
        // Reopened over the rotated journal, the appender continues the same
        // chain: the next commit verifies against what the scan derived.
        let mut writer =
            JournalWriter::open_active(dir.path(), 4, out.chain_head, SaltSource::Seeded(TEST_SEED))
                .unwrap();
        write_txn(&mut writer, 4, vec![rec(40)]);
        drop(writer);
        let segs = list_segments(dir.path()).unwrap();
        let out = scan(&segs, 0, None, CHAIN_GENESIS).unwrap();
        assert_eq!((out.chain_break(), out.committed_head), (None, 4));
    }

    #[test]
    fn the_marker_carries_the_sources_salt_and_an_edited_salt_breaks_the_chain() {
        // The writer draws each transaction's salt from its source and stores
        // it in the marker — under the seeded source, the stream's value for
        // that transaction, byte for byte — and the scan closes each link with
        // the salt it READS there. So a salt edited in place, its frame CRC
        // re-sealed, is a link that no longer verifies: a CHAIN BREAK at that
        // transaction, whatever the records say. The salt is hashed, not
        // merely stored.
        let dir = tempdir().unwrap();
        let mut writer = fresh_writer(dir.path());
        write_txn(&mut writer, 1, vec![rec(10)]);
        write_txn(&mut writer, 2, vec![rec(20), rec(21)]);
        write_txn(&mut writer, 4, vec![rec(40)]);
        drop(writer);
        let segs = list_segments(dir.path()).unwrap();
        let starts = frame_starts(&segs[0].path);
        // Frames: 0=T1 rec, 1=T1 marker, 2..=3=T2 recs, 4=T2 marker, 5=T3 rec, 6=T3 marker.
        for (marker_frame, txn) in [(1, 1u64), (4, 2), (6, 4)] {
            let m = marker_at(&segs[0].path, starts[marker_frame]);
            assert_eq!(m.txn, Txn(txn));
            assert_eq!(
                m.salt,
                SaltSource::Seeded(TEST_SEED).draw(txn).unwrap(),
                "the marker closing transaction {txn} carries the seeded stream's salt"
            );
            assert_ne!(m.salt, [0u8; 32]);
        }
        let salts: Vec<[u8; 32]> =
            [1, 4, 6].iter().map(|&f| marker_at(&segs[0].path, starts[f]).salt).collect();
        assert!(salts[0] != salts[1] && salts[1] != salts[2], "one salt per transaction");
        assert_eq!(scan(&segs, 0, None, CHAIN_GENESIS).unwrap().chain_break(), None);

        // Edit one byte of T2's salt — payload offset 24 + 5, inside the
        // salt's thirty-two — and re-seal the frame: intact, still committed,
        // and the link fails at T2 (last seq 3); T3 is chained from T2's
        // stored value and does not mask it.
        rewrite_payload(&segs[0].path, starts[4], |payload| payload[24 + 5] ^= 0xFF);
        let out = scan(&segs, 0, None, CHAIN_GENESIS).unwrap();
        assert!(out.runs.is_empty(), "no frame was damaged");
        assert_eq!(out.committed_head, 4, "the groups still commit — the halt is the caller's");
        assert_eq!(out.chain_break(), Some(3), "the salt is a chain input: T2 closes at 3");
    }

    #[test]
    fn a_journal_written_under_one_salt_source_replays_under_any() {
        // The salt is READ off the marker on replay, never regenerated, so a
        // reopen under a different source — or the same seed, or the OS —
        // verifies every link written before it, and the commits it adds
        // chain from the recovered head under its own source.
        let dir = tempdir().unwrap();
        let mut writer = fresh_writer(dir.path());
        write_txn(&mut writer, 1, vec![rec(10)]);
        write_txn(&mut writer, 2, vec![rec(20)]);
        drop(writer);
        for source in [SaltSource::Os, SaltSource::Seeded(TEST_SEED + 1), SaltSource::Seeded(TEST_SEED)] {
            let segs = list_segments(dir.path()).unwrap();
            let out = scan(&segs, 0, None, CHAIN_GENESIS).unwrap();
            assert_eq!(out.chain_break(), None, "reopened under {source:?}");
            let next = out.committed_head + 1;
            let mut writer = JournalWriter::open_active(dir.path(), next, out.chain_head, source).unwrap();
            write_txn(&mut writer, next, vec![rec(next * 10)]);
            drop(writer);
        }
        let segs = list_segments(dir.path()).unwrap();
        let out = scan(&segs, 0, None, CHAIN_GENESIS).unwrap();
        assert_eq!((out.chain_break(), out.committed_head), (None, 5));
        // The OS-drawn salt at 3 is neither seeded stream's value; the seeded
        // ones at 4 and 5 are exactly their streams'.
        let markers = markers_in(&segs[0].path);
        let salt_of = |txn: u64| {
            markers
                .iter()
                .find(|m| m.txn == Txn(txn))
                .map(|m| m.salt)
                .expect("a marker per transaction")
        };
        assert_ne!(salt_of(3), SaltSource::Seeded(TEST_SEED).draw(3).unwrap());
        assert_ne!(salt_of(3), SaltSource::Seeded(TEST_SEED + 1).draw(3).unwrap());
        assert_eq!(salt_of(4), SaltSource::Seeded(TEST_SEED + 1).draw(4).unwrap());
        assert_eq!(salt_of(5), SaltSource::Seeded(TEST_SEED).draw(5).unwrap());
    }

    #[test]
    fn an_installed_commit_leaves_nothing_in_flight() {
        // The install happens inside the commit, so an installed transaction
        // is behind the writer by the time it returns: a later unwind finds
        // nothing of it to repair, and the next transaction starts clean (§3).
        let dir = tempdir().unwrap();
        let mut writer = fresh_writer(dir.path());
        let mut installed = None;
        writer
            .commit_txn(1, vec![rec(10)], |chain| installed = Some(chain))
            .expect("fixture commit");
        let installed = installed.expect("the commit installs before it returns");
        // …and hands the install the chain the marker on disk carries.
        let segs = list_segments(dir.path()).unwrap();
        let starts = frame_starts(&segs[0].path);
        assert_eq!(installed, chain_of_marker_at(&segs[0].path, starts[1]));
        let repair = writer.repair_after_unwind();
        assert!(matches!(repair, UnwindRepair::Clean), "got {repair:?}");
    }

    #[test]
    fn an_unwind_through_the_install_is_beyond_repair() {
        // The one window the writer cannot repair: durably committed, with
        // the install unaccounted for. Its record+marker tail stays —
        // removing an acked commit is what recovery may never do (§3).
        let dir = tempdir().unwrap();
        let mut writer = fresh_writer(dir.path());
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = writer.commit_txn(1, vec![rec(10)], |_| panic!("install unwinds"));
        }));
        assert!(unwound.is_err(), "the panic reaches the caller");
        let repair = writer.repair_after_unwind();
        assert!(matches!(repair, UnwindRepair::AfterBarrier), "got {repair:?}");
        let segs = list_segments(dir.path()).unwrap();
        assert_eq!(scan(&segs, 0, None, CHAIN_GENESIS).unwrap().committed_head, 1);
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
    fn segments_list_in_first_seq_order_across_a_digit_boundary() {
        // A closed segment's reach is read off its SUCCESSOR's name; the scan
        // skips on that inference and `reclaim_below` deletes on it. Name
        // order and `firstSeq` order agree while names have one digit — and
        // `seg-10.wal` sorts BEFORE `seg-9.wal` by name.
        let dir = tempdir().unwrap();
        for first_seq in [10, 1, 100, 9] {
            fs::write(segment_path(dir.path(), first_seq), b"").unwrap();
        }
        let segs = list_segments(dir.path()).unwrap();
        let firsts: Vec<u64> = segs.iter().map(|seg| seg.first_seq).collect();
        assert_eq!(firsts, vec![1, 9, 10, 100]);
        assert_eq!(
            inferred_last_seq(&segs, 1),
            Some(9),
            "seg-9 ends where seg-10 begins"
        );
        // …and reclamation takes exactly the closed prefix that inference
        // admits.
        reclaim_below(dir.path(), 9).unwrap();
        let left: Vec<u64> = list_segments(dir.path())
            .unwrap()
            .iter()
            .map(|seg| seg.first_seq)
            .collect();
        assert_eq!(left, vec![10, 100]);
    }

    #[test]
    fn scan_groups_by_txn_and_derives_the_committed_head() {
        let dir = tempdir().unwrap();
        let mut writer = fresh_writer(dir.path());
        write_txn(&mut writer, 1, vec![rec(10)]);
        write_txn(&mut writer, 2, vec![rec(20), rec(21)]); // seqs 2, 3
        let segs = list_segments(dir.path()).unwrap();
        let out = scan(&segs, 0, None, CHAIN_GENESIS).unwrap();
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
        let mut writer = fresh_writer(dir.path());
        write_txn(&mut writer, 1, vec![rec(10)]);
        write_txn(&mut writer, 5, vec![rec(50), rec(60)]); // burned 2..=4
        let segs = list_segments(dir.path()).unwrap();
        let out = scan(&segs, 0, None, CHAIN_GENESIS).unwrap();
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
        let mut writer = fresh_writer(dir.path());
        write_txn(&mut writer, 1, vec![rec(10)]);
        write_txn(&mut writer, 2, vec![rec(20)]);
        write_txn(&mut writer, 3, vec![rec(30)]);
        let segs = list_segments(dir.path()).unwrap();
        let starts = frame_starts(&segs[0].path);
        // Frames: 0=T1 rec, 1=T1 marker, 2=T2 rec, 3=T2 marker, 4=T3 rec, 5=T3 marker.
        flip_byte(&segs[0].path, starts[2] + FRAME_HEADER_LEN + 1);
        let out = scan(&segs, 0, None, CHAIN_GENESIS).unwrap();
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
        // T3 was chained from T2, which this scan never committed: a chain
        // break at 3 — recorded, so the run above names the root cause first.
        assert_eq!(out.chain_break(), Some(3));
    }

    #[test]
    fn corrupt_marker_lands_on_next_record() {
        // T2 = seqs 2..=3; corrupt T2's MARKER. The resync lands on T3's first
        // record (seq 4) — a record landing: at = seq, inferred max = seq − 1.
        let dir = tempdir().unwrap();
        let mut writer = fresh_writer(dir.path());
        write_txn(&mut writer, 1, vec![rec(10)]);
        write_txn(&mut writer, 2, vec![rec(20), rec(21)]);
        write_txn(&mut writer, 4, vec![rec(40)]);
        let segs = list_segments(dir.path()).unwrap();
        let starts = frame_starts(&segs[0].path);
        // Frames: 0=T1 rec, 1=T1 marker, 2..=3=T2 recs, 4=T2 marker, 5=T3 rec, 6=T3 marker.
        flip_byte(&segs[0].path, starts[4] + FRAME_HEADER_LEN + 1);
        let out = scan(&segs, 0, None, CHAIN_GENESIS).unwrap();
        assert_eq!(
            out.runs,
            vec![RunEnd::Landed {
                inferred_max: 3,
                at: 4
            }]
        );
        assert_eq!(out.committed_head, 4);
        assert_eq!(committed_seqs(&out), vec![1, 4]);
        assert_eq!(out.chain_break(), Some(4), "T3 followed the T2 this scan lost");
    }

    #[test]
    fn resync_rejects_coincidental_magic_inside_payload() {
        // A record whose bytes contain the magic word; corrupt its frame. The
        // resync must reject the embedded magic (its crc check fails) and land
        // on the real next frame — T1's marker (§1/§7).
        let dir = tempdir().unwrap();
        let mut writer = fresh_writer(dir.path());
        let mut embedded_magic = Vec::new();
        embedded_magic.extend_from_slice(b"xx");
        embedded_magic.extend_from_slice(&MAGIC);
        embedded_magic.extend_from_slice(b"yyyyyyyy");
        write_txn(&mut writer, 1, vec![embedded_magic]);
        write_txn(&mut writer, 2, vec![rec(20)]);
        let segs = list_segments(dir.path()).unwrap();
        let starts = frame_starts(&segs[0].path);
        flip_byte(&segs[0].path, starts[0] + FRAME_HEADER_LEN + 1);
        let out = scan(&segs, 0, None, CHAIN_GENESIS).unwrap();
        assert_eq!(
            out.runs,
            vec![RunEnd::Landed {
                inferred_max: 1,
                at: 2
            }]
        );
        assert_eq!(out.committed_head, 2);
        assert_eq!(committed_seqs(&out), vec![2]);
        assert_eq!(out.chain_break(), Some(2), "T2 followed the T1 this scan lost");
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
        let mut writer = fresh_writer(dir.path());
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
        let starts = frame_starts(&segs[0].path);
        flip_byte(&segs[0].path, starts[0] + FRAME_HEADER_LEN + 1);

        // The scan refuses, at the base's own coordinate. That refusal is the
        // whole of what there is to check here: what such a scan derived is a
        // prefix, so it produces no outcome at all — there is no committed
        // head to read short, and no cut for a truncation to be aimed with.
        let fail = scan(&segs, 0, None, CHAIN_GENESIS).err();
        assert!(
            matches!(fail, Some(ScanFail::Unbounded { at: 0 })),
            "got {fail:?}"
        );
    }

    #[test]
    fn resynchronization_charges_every_rejection_even_between_intact_frames() {
        // The alternation the budget's own comment names: each expensive
        // rejection is followed by an INTACT frame that closes the run it
        // opened. A budget charged only while a run is open, or kept per run,
        // sees one rejection at a time and never refuses — while the scan
        // spends (rejections) × (claimed length) bytes of CRC on content its
        // author chose. `resynchronization_over_planted_frame_headers_is_bounded`
        // plants its headers back to back, so nothing closes a run there, and
        // it cannot tell those budgets from this one.
        let marker_payload = codec()
            .serialize(&FramePayload::Marker(marker(Txn(u64::MAX), 0, 0)))
            .unwrap();
        let mut unit = Vec::new();
        unit.extend_from_slice(&MAGIC);
        unit.extend_from_slice(&(128 * 1024u32).to_le_bytes()); // a len that fits
        unit.extend_from_slice(&0u32.to_le_bytes()); // a crc that will not
        push_frame(&mut unit, &marker_payload).unwrap(); // …then a frame that closes the run
        let mut evil = Vec::new();
        while evil.len() < 256 * 1024 {
            evil.extend_from_slice(&unit);
        }
        let dir = tempdir().unwrap();
        let mut writer = fresh_writer(dir.path());
        write_txn(&mut writer, 1, vec![evil]);
        write_txn(&mut writer, 2, vec![rec(20)]);
        let segs = list_segments(dir.path()).unwrap();
        let starts = frame_starts(&segs[0].path);
        flip_byte(&segs[0].path, starts[0] + FRAME_HEADER_LEN + 1);

        let fail = scan(&segs, 0, None, CHAIN_GENESIS).err();
        assert!(
            matches!(fail, Some(ScanFail::Unbounded { at: 0 })),
            "got {fail:?}"
        );
    }

    #[test]
    fn a_segment_longer_than_any_writer_produces_is_refused_before_it_is_read() {
        // A segment is read WHOLE, so its length sizes an allocation, and a
        // file's length is its own claim: damage, or a stray or concatenated
        // file bearing a segment's name, would size one as it pleased. No
        // writer here produces a segment past `MAX_SEGMENT_LEN`, so one past it
        // is refused on its length alone — the scan's refusal, fatal at any
        // height, with nothing derived from a prefix.
        let dir = tempdir().unwrap();
        let mut writer = fresh_writer(dir.path());
        write_txn(&mut writer, 1, vec![rec(10)]);
        drop(writer);
        let segs = list_segments(dir.path()).unwrap();
        // Sparse: the length costs no disk.
        OpenOptions::new()
            .write(true)
            .open(&segs[0].path)
            .unwrap()
            .set_len(MAX_SEGMENT_LEN + 1)
            .unwrap();
        let fail = scan(&segs, 0, None, CHAIN_GENESIS).err();
        assert!(
            matches!(fail, Some(ScanFail::Unbounded { at: 0 })),
            "got {fail:?}"
        );
    }

    #[test]
    fn torn_tail_reaches_eof() {
        let dir = tempdir().unwrap();
        let mut writer = fresh_writer(dir.path());
        write_txn(&mut writer, 1, vec![rec(10)]);
        write_txn(&mut writer, 2, vec![rec(20)]);
        // Crash mid-append: a partial header at the tail.
        writer.append(&[0xAB, 0xCD, 0xEF]).unwrap();
        let segs = list_segments(dir.path()).unwrap();
        let out = scan(&segs, 0, None, CHAIN_GENESIS).unwrap();
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
        let mut writer = fresh_writer(dir.path());
        write_txn(&mut writer, 1, vec![vec![7u8; SEGMENT_ROTATE_BYTES as usize]]); // fills seg-1
        write_txn(&mut writer, 2, vec![rec(20)]); // rotates into seg-2
        let segs = list_segments(dir.path()).unwrap();
        assert_eq!(segs.len(), 2, "the fixture rotates");
        // Tear seg-2's marker: its txn is no longer committed.
        let starts = frame_starts(&segs[1].path);
        flip_byte(&segs[1].path, starts[1] + FRAME_HEADER_LEN + 1);
        let out = scan(&segs, 0, None, CHAIN_GENESIS).unwrap();
        assert_eq!(out.committed_head, 1);
        let tail = out.tail.as_ref().expect("a scanned region has a cut");
        assert_eq!(tail.segment, segs[0].path);
        assert_eq!(tail.offset, fs::metadata(&segs[0].path).unwrap().len());
        assert_eq!(tail.discard, vec![segs[1].path.clone()]);
    }

    #[test]
    fn require_boundary_answers_from_the_committed_markers() {
        let dir = tempdir().unwrap();
        let mut writer = fresh_writer(dir.path());
        write_txn(&mut writer, 1, vec![rec(10)]);
        write_txn(&mut writer, 2, vec![rec(20), rec(21)]); // a composite: boundary 3
        write_txn(&mut writer, 4, vec![rec(40)]);
        let segs = list_segments(dir.path()).unwrap();

        let out = scan(&segs, 0, None, CHAIN_GENESIS).unwrap();
        assert_eq!(out.require_boundary(3), Ok(()));
        // A composite's interior Seq was never a boundary (§3).
        assert_eq!(out.require_boundary(2), Err(1));

        // The active segment is always scanned, so it reports boundaries
        // below a base too — but those have no base left to fold from, and
        // the nearest ANSWERABLE boundary is the base's own seq.
        let out = scan(&segs, 3, None, CHAIN_GENESIS).unwrap();
        assert_eq!(out.require_boundary(4), Ok(()));
        assert_eq!(out.require_boundary(2), Err(3));
    }

    #[test]
    fn a_bound_keeps_what_a_fold_to_it_reads_and_drops_the_rest() {
        // A bounded scan collects for a fold to `bound` and nothing else, so a
        // bounded replay of one transaction above a base does not materialize
        // the whole retained window. What a fold to `bound` reads is exactly
        // `bound` itself, the boundaries below it, and the records at or below
        // it — so the edge is inclusive at all three, and a bound that dropped
        // its own coordinate would answer a short world.
        let dir = tempdir().unwrap();
        let mut writer = fresh_writer(dir.path());
        write_txn(&mut writer, 1, vec![rec(10)]);
        write_txn(&mut writer, 2, vec![rec(20), rec(21)]); // a composite: boundary 3
        write_txn(&mut writer, 4, vec![rec(40)]);
        let segs = list_segments(dir.path()).unwrap();

        let out = scan(&segs, 0, Some(3), CHAIN_GENESIS).unwrap();
        assert_eq!(committed_seqs(&out), vec![1, 2, 3], "the bound is inclusive");
        assert_eq!(out.require_boundary(3), Ok(()), "…of its own boundary too");
        assert_eq!(out.require_boundary(1), Ok(()));
        // The head and the cut are NOT bounded: recovery folds to the first and
        // truncates at the second, and both must name the whole scanned region.
        assert_eq!(out.committed_head, 4);
        assert_tail(&out, &segs[0].path, fs::metadata(&segs[0].path).unwrap().len());

        // A composite STRADDLING the bound keeps the half below it: its group
        // is filtered per record, not discarded whole.
        let out = scan(&segs, 0, Some(2), CHAIN_GENESIS).unwrap();
        assert_eq!(committed_seqs(&out), vec![1, 2]);
        // …and 3 is then a boundary nothing can ask about, so the nearest
        // answerable one is 1 — never the interior coordinate 2.
        assert_eq!(out.require_boundary(3), Err(1));
    }

    #[test]
    fn the_chain_at_a_boundary_is_its_capture_and_its_absence_the_nearest_below() {
        // One capture answers both of `chain_at`'s questions: a scan collected
        // to a boundary holds the chain the marker closing it carries, and a
        // scan collected to an interior coordinate holds none — answered, as
        // `require_boundary` answers it, with the nearest boundary below.
        let dir = tempdir().unwrap();
        let mut writer = fresh_writer(dir.path());
        write_txn(&mut writer, 1, vec![rec(10)]);
        write_txn(&mut writer, 2, vec![rec(20), rec(21)]); // a composite: boundary 3
        write_txn(&mut writer, 4, vec![rec(40)]);
        let segs = list_segments(dir.path()).unwrap();
        let starts = frame_starts(&segs[0].path);
        // Frames: 0=T1 rec, 1=T1 marker, 2..=3=T2 recs, 4=T2 marker, 5=T3 rec, 6=T3 marker.
        let at_3 = scan(&segs, 0, Some(3), CHAIN_GENESIS).unwrap();
        assert_eq!(at_3.chain_at_boundary(3), Ok(chain_of_marker_at(&segs[0].path, starts[4])));
        let at_4 = scan(&segs, 0, Some(4), CHAIN_GENESIS).unwrap();
        assert_eq!(at_4.chain_at_boundary(4), Ok(chain_of_marker_at(&segs[0].path, starts[6])));
        // A composite's interior coordinate closes no marker.
        let at_2 = scan(&segs, 0, Some(2), CHAIN_GENESIS).unwrap();
        assert_eq!(at_2.chain_at_boundary(2), Err(1));
    }

    #[test]
    #[should_panic(expected = "keyed on the collection bound")]
    fn a_chain_asked_of_a_scan_not_collected_to_it_is_refused_as_the_callers_bug() {
        // The capture is keyed on the collection bound and on nothing else, so
        // a scan collected to anything but the boundary asked would answer a
        // boundary `transact` returned as no boundary at all.
        let dir = tempdir().unwrap();
        let mut writer = fresh_writer(dir.path());
        write_txn(&mut writer, 1, vec![rec(10)]);
        let segs = list_segments(dir.path()).unwrap();
        let _ = scan(&segs, 0, None, CHAIN_GENESIS).unwrap().chain_at_boundary(1);
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
