//! The chain link (`CHAIN_GENESIS`, `ChainLink`).

use sha2::{Digest, Sha256};

use super::Txn;

/// THE CHAIN'S GENESIS — chain₀, the value the first transaction of a journal
/// chains from: thirty-two zero bytes. Named here, read by the writer of a
/// fresh journal and by every replay from genesis, and pinned by the golden
/// fixture, whose first marker's chain is SHA-256 over this value and that
/// transaction's bytes. When a checkpoint is the base the value read is the
/// `SKC4` header's `chain_head` instead — the chain at that checkpoint's
/// coordinate, which the marker that held it may no longer exist to say.
pub(crate) const CHAIN_GENESIS: [u8; 32] = [0u8; 32];

/// One link of the commit chain under construction — the ONE spelling of
/// what the chain hashes, used by the writer ([`super::encode_txn`]) and the reader
/// (`PendingTxn`) alike, so the two cannot disagree about a single byte:
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
/// every machine is the codec's promise ([`super::codec`]), which is what makes two
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
///
/// The hasher inside is this type's alone: every byte the chain covers enters
/// through [`ChainLink::open`], [`ChainLink::add_payload`] or
/// [`ChainLink::close`], and a reader that must close a link it still holds
/// clones the link.
#[derive(Clone)]
pub(super) struct ChainLink(Sha256);

impl ChainLink {
    /// Open the link that follows `prev`.
    pub(super) fn open(prev: &[u8; 32]) -> ChainLink {
        ChainLink(Sha256::new().chain_update(prev))
    }

    /// Stream one record frame's payload, exactly as framed.
    pub(super) fn add_payload(&mut self, payload: &[u8]) {
        self.0.update(payload);
    }

    /// Close the link with the marker's own pre-chain fields, then its salt —
    /// the ONE spelling, which the writer closes with the salt it drew and
    /// the reader with the salt the marker carries.
    pub(super) fn close(self, txn: Txn, last_seq: u64, records_checksum: u32, salt: &[u8; 32]) -> [u8; 32] {
        self.0
            .chain_update(txn.0.to_le_bytes())
            .chain_update(last_seq.to_le_bytes())
            .chain_update(records_checksum.to_le_bytes())
            .chain_update(salt)
            .finalize()
            .into()
    }
}
