//! `Attestation`, `AttestationError` (public types).

use std::fmt;

/// The signature slot's EMPTY tag: unsigned, what every transaction that
/// carries no [`Attestation`] writes, and the one tag no signature is made
/// under. Every other tag is the verifier's to assign — which pair it names,
/// and a blob's layout under it, are the verifier's table and not this
/// kernel's ([`Attestation`]) — so a change of pair is a verifier update,
/// never a stamp bump.
pub(super) const SIG_ALG_UNSIGNED: u8 = 0;

/// THE ATTESTATION a transaction's commit marker carries (signed ops; the
/// slot X2 reserved, at its designed use): the TAG of the hybrid pair and
/// the signature BLOB made under it — the marker's `sig_alg` and `sig`
/// fields exactly, written where `Some` by [`crate::Kernel::transact_attested`]
/// for THAT transaction alone and read back by
/// [`crate::Kernel::attestation_at`]. OPAQUE to this kernel: no byte of the
/// blob is interpreted here (an attested marker's verification is the
/// verifier's, beside the table, fold-inert — the fold reads no signature),
/// the slot is no chain input (the tamper matrix's case 4), and its bytes sit
/// OUTSIDE [`super::MAX_TXN_BYTES`]'s accounting (the design record §4.4 (b): the
/// budget bounds the RECORDS a staging holds; the slot is the marker's own).
///
/// The one-spelling-of-empty rule is held at CONSTRUCTION: a value of this
/// type always names a non-zero tag with a non-empty blob, so no transaction
/// can write the marker [`super::MarkerShadow`]'s door refuses — tag `0` with bytes,
/// or a tag with none — and "unattested" has exactly one spelling, the absent
/// value. Which tags exist and what a blob's layout is under each are the
/// verifier's table, not this kernel's: any non-zero tag and any non-empty
/// blob are admitted here, as the decoder admits them.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Attestation {
    sig_alg: u8,
    sig: Vec<u8>,
}

impl Attestation {
    /// An attestation under `sig_alg` with the blob `sig`, refusing the two
    /// spellings the marker decoder refuses: tag `0` (the empty slot's tag,
    /// which no signature is made under) and an empty blob.
    pub fn new(sig_alg: u8, sig: Vec<u8>) -> Result<Attestation, AttestationError> {
        if sig_alg == SIG_ALG_UNSIGNED {
            return Err(AttestationError::UnsignedTag);
        }
        if sig.is_empty() {
            return Err(AttestationError::EmptyBlob);
        }
        Ok(Attestation { sig_alg, sig })
    }

    /// The tag of the hybrid pair the blob was made under — the marker's
    /// `sig_alg` byte.
    pub fn sig_alg(&self) -> u8 {
        self.sig_alg
    }

    /// The signature blob — the marker's `sig` bytes, whole and uninterpreted.
    pub fn sig(&self) -> &[u8] {
        &self.sig
    }
}

/// The tag and the blob's LENGTH, never its bytes: a signature is not a
/// thing to print into a diagnostic, and its width beside its tag is what a
/// reader of one wants to see.
impl fmt::Debug for Attestation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Attestation")
            .field("sig_alg", &self.sig_alg)
            .field("sig_len", &self.sig.len())
            .finish()
    }
}

/// [`Attestation::new`]'s refusal — the two spellings of "no signature" a
/// caller may not smuggle under a tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttestationError {
    /// Tag `0` is the EMPTY slot's tag; a signature is made under no such
    /// pair. An unattested transaction carries no `Attestation` at all.
    UnsignedTag,
    /// A tag with no bytes is the undecodable marker the door refuses.
    EmptyBlob,
}

impl fmt::Display for AttestationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            AttestationError::UnsignedTag => {
                "an attestation names a non-zero tag: tag 0 is the empty slot's own"
            }
            AttestationError::EmptyBlob => "an attestation carries a non-empty signature blob",
        })
    }
}

impl std::error::Error for AttestationError {}
