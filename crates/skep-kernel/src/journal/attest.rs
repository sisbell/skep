//! `Attestation`, `AttestationError`, `MAX_SIG_BYTES` (public), and the slot
//! rule both of the slot's doors ask.

use std::fmt;

/// The signature slot's EMPTY tag: unsigned, what every transaction that
/// carries no [`Attestation`] writes, and the one tag no signature is made
/// under. Every other tag is the verifier's to assign — which pair it names,
/// and a blob's layout under it, are the verifier's table and not this
/// kernel's ([`Attestation`]) — so a change of pair is a verifier update,
/// never a stamp bump.
pub(super) const SIG_ALG_UNSIGNED: u8 = 0;

/// The widest blob a signature slot holds: refused past at both of the
/// slot's doors, the constructor of [`Attestation`] and the commit-marker
/// decoder, which ask one rule. The budget: the widest signature of the
/// stateless post-quantum standards — SLH-DSA-256f's 49,856 bytes (FIPS 205;
/// ML-DSA under FIPS 204 and FN-DSA under FIPS 206 are at least an order of
/// magnitude narrower) — beside an Ed25519 half fits with 15 KiB to spare, so
/// no hybrid pair a verifier's table can name is refused; and a slot this wide
/// moves a replica's memory floor, and an attested commit's hashing under the
/// applier lock, by 64 KiB at most. The slot sits OUTSIDE
/// [`super::MAX_TXN_BYTES`], so this is the bound that holds an attested
/// transaction's bytes — the journal's segment ceiling and its frame cap are
/// both asserted against it where they are defined. A format constant: it
/// moves only with the stamp.
pub const MAX_SIG_BYTES: usize = 64 * 1024;

/// THE SLOT RULE, spelled once: what a commit marker's signature slot may
/// hold. `Ok(None)` is the one spelling of empty — tag `0` with no bytes;
/// `Ok(Some(_))` a non-zero tag with a non-empty blob of at most
/// [`MAX_SIG_BYTES`] bytes; everything else is refused. Both of the slot's
/// doors ask THIS — [`Attestation::new`], and the marker decoder
/// (`MarkerShadow`'s conversion) — so a slot the decoder admitted is one this
/// admits again, unchanged, which is what the scan's conversion of a decoded
/// slot back into an [`Attestation`] rests on. A rule the slot gains is added
/// here, where both doors meet it.
pub(super) fn slot(sig_alg: u8, sig: Vec<u8>) -> Result<Option<Attestation>, AttestationError> {
    if sig_alg == SIG_ALG_UNSIGNED {
        return if sig.is_empty() {
            Ok(None)
        } else {
            Err(AttestationError::UnsignedTag)
        };
    }
    if sig.is_empty() {
        return Err(AttestationError::EmptyBlob);
    }
    if sig.len() > MAX_SIG_BYTES {
        return Err(AttestationError::TooWide { len: sig.len() });
    }
    Ok(Some(Attestation { sig_alg, sig }))
}

/// THE ATTESTATION a transaction's commit marker carries (signed ops; the
/// slot X2 reserved, at its designed use): the TAG of the hybrid pair and
/// the signature BLOB made under it — the marker's `sig_alg` and `sig`
/// fields exactly, written where `Some` by [`crate::Kernel::transact_attested`]
/// for THAT transaction alone and read back by
/// [`crate::Kernel::attestation_at`]. OPAQUE to this kernel: no byte of the
/// blob is interpreted here (an attested marker's verification is the
/// verifier's, beside the table, fold-inert — the fold reads no signature),
/// though the slot's bytes are HASHED into the commit chain by digest (the
/// board's r6-2c; the tamper matrix's case 4: a slot stripped or altered
/// after its commit is a chain break at that transaction), and they sit
/// OUTSIDE [`super::MAX_TXN_BYTES`]'s accounting (the design record §4.4 (b): the
/// budget bounds the RECORDS a staging holds; the slot is the marker's own),
/// bounded instead by [`MAX_SIG_BYTES`].
///
/// The slot rule is held at CONSTRUCTION and at the decode door alike, both
/// asking the one rule (`attest::slot`): a value of this type always names a
/// non-zero tag with a non-empty blob no wider than [`MAX_SIG_BYTES`], so no
/// transaction can write a marker the decoder refuses — tag `0` with bytes, a
/// tag with none, a blob past the cap — and "unattested" has exactly one
/// spelling, the absent value. Which tags exist and what a blob's layout is
/// under each are the verifier's table, not this kernel's: any non-zero tag
/// and any non-empty blob within the cap are admitted here, as the decoder
/// admits them.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Attestation {
    sig_alg: u8,
    sig: Vec<u8>,
}

impl Attestation {
    /// An attestation under `sig_alg` with the blob `sig`, refusing what the
    /// marker decoder refuses — tag `0` (the empty slot's tag, which no
    /// signature is made under), an empty blob, and a blob wider than
    /// [`MAX_SIG_BYTES`] — since both ask the one slot rule. The empty slot
    /// itself is no `Attestation`: it is spelled by the absent value.
    pub fn new(sig_alg: u8, sig: Vec<u8>) -> Result<Attestation, AttestationError> {
        slot(sig_alg, sig)?.ok_or(AttestationError::UnsignedTag)
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

    /// The tag and the blob, taken apart for the marker's two slot fields —
    /// the decoder's way back from the slot rule's answer to the bytes it
    /// stores.
    pub(super) fn into_parts(self) -> (u8, Vec<u8>) {
        (self.sig_alg, self.sig)
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
/// caller may not smuggle under a tag, and a blob past the slot's width.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttestationError {
    /// Tag `0` is the EMPTY slot's tag; a signature is made under no such
    /// pair. An unattested transaction carries no `Attestation` at all.
    UnsignedTag,
    /// A tag with no bytes is the undecodable marker the door refuses.
    EmptyBlob,
    /// A blob wider than [`MAX_SIG_BYTES`], which no slot holds: the decoder
    /// refuses the marker that spells one, so no transaction may write it.
    TooWide {
        /// The width of the blob refused, in bytes.
        len: usize,
    },
}

impl fmt::Display for AttestationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AttestationError::UnsignedTag => f.write_str(
                "an attestation must name a non-zero tag: tag 0 is the empty slot's own",
            ),
            AttestationError::EmptyBlob => {
                f.write_str("an attestation must carry a non-empty signature blob")
            }
            AttestationError::TooWide { len } => write!(
                f,
                "an attestation's signature blob must be at most {MAX_SIG_BYTES} bytes; this one \
                 is {len}"
            ),
        }
    }
}

impl std::error::Error for AttestationError {}
