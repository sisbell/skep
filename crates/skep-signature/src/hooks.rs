//! THE FIXTURES' HOOKS (the `fuzz_support` standing: `#[doc(hidden)]`, not a
//! stable API) — the seeded stream a tag-3 golden signs over
//! ([`SeededRng06`]), the widths the sizes pin reads ([`pq_widths`]), and the
//! suites' classical pair ([`Ed25519SigningKey`], [`Ed25519VerifyingKey`]),
//! the one door a suite has to `ed25519-dalek`'s key types — compiled under
//! `test-hooks` alone, which no shipped signer enables. The two hooks on
//! `HybridSigner` itself sit in the signer's file, beside the private fields
//! they read.

use std::fmt;

use ed25519_dalek::{Signer as _, SigningKey as EdSigningKey, VerifyingKey as EdVerifyingKey};
use fn_dsa::{signature_size, sign_key_size, vrfy_key_size, FN_DSA_LOGN_512};
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, ExpandedSigningKeyBytes, MlDsa65};
use sha2::Sha256;

use crate::Rule;

/// TEST HOOK (the `fuzz_support` standing: `#[doc(hidden)]`, not a stable
/// API) — a DETERMINISTIC `rand_core` 0.6 stream for FIXTURES, SHA-256 in
/// counter mode over a seed, so a tag-3 signature (randomized by the draft's
/// own rule) is byte-stable in a golden. No part of any tag's rule: a tag-3
/// signature verifies under the tag's rule whatever RNG made it. Never for
/// production use — the stream is a function of its seed.
#[doc(hidden)]
pub struct SeededRng06 {
    seed: [u8; 32],
    counter: u64,
    /// The current SHA-256 block, handed out front to back; `drawn ==
    /// block.len()` when the next byte needs a fresh one.
    block: [u8; 32],
    drawn: usize,
}

impl SeededRng06 {
    pub fn new(seed: [u8; 32]) -> SeededRng06 {
        let block = [0; 32];
        SeededRng06 { seed, counter: 0, drawn: block.len(), block }
    }
}

/// The stream's position, never its seed: this crate prints no seed.
impl fmt::Debug for SeededRng06 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SeededRng06").field("counter", &self.counter).finish_non_exhaustive()
    }
}

impl rand_core_06::RngCore for SeededRng06 {
    fn next_u32(&mut self) -> u32 {
        rand_core_06::impls::next_u32_via_fill(self)
    }
    fn next_u64(&mut self) -> u64 {
        rand_core_06::impls::next_u64_via_fill(self)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        use sha2::Digest;
        for out in dest {
            if self.drawn == self.block.len() {
                self.block = Sha256::new()
                    .chain_update(self.seed)
                    .chain_update(self.counter.to_be_bytes())
                    .finalize()
                    .into();
                self.counter += 1;
                self.drawn = 0;
            }
            *out = self.block[self.drawn];
            self.drawn += 1;
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core_06::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core_06::CryptoRng for SeededRng06 {}

/// The widths one tag's rule fixes — [`pq_widths`]' answer. Named, not a
/// triple: three `usize`s meaning three things, printed into a report that
/// is transcribed.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PqWidths {
    /// The PQ half's verifying key.
    pub key: usize,
    /// The PQ half's signature.
    pub sig: usize,
    /// The PQ signing key in its crate's encoding — the expanded key's for
    /// ML-DSA-65, which the signer holds decoded, and the bytes the signer
    /// stores for the FN-DSA-512 preview.
    pub signing_key: usize,
}

/// TEST HOOK (the `fuzz_support` standing: `#[doc(hidden)]`, not a stable
/// API) — the widths a tag's rule fixes, READ OFF each pinned crate's own
/// sizes — `ml-dsa`'s encoded-array types for tag 1, `fn-dsa`'s size
/// functions for tag 3 — so a bump of either crate that moved one fails
/// `sizes_and_timings_per_tag`'s literal pin by name. `None` for a tag this
/// build holds no rule for.
#[doc(hidden)]
pub fn pq_widths(tag: u8) -> Option<PqWidths> {
    Some(match Rule::of(tag)? {
        Rule::MlDsa65Ed25519 => PqWidths {
            key: EncodedVerifyingKey::<MlDsa65>::default().len(),
            sig: EncodedSignature::<MlDsa65>::default().len(),
            signing_key: ExpandedSigningKeyBytes::<MlDsa65>::default().len(),
        },
        Rule::FnDsa512PreviewEd25519 => PqWidths {
            key: vrfy_key_size(FN_DSA_LOGN_512),
            sig: signature_size(FN_DSA_LOGN_512),
            signing_key: sign_key_size(FN_DSA_LOGN_512),
        },
    })
}

/// TEST HOOK (the `fuzz_support` standing: `#[doc(hidden)]`, not a stable
/// API) — THE SUITES' SEED CARRIER: an Ed25519 signing key from 32 bytes.
/// The fixtures hold one per principal and read its bytes back as the seed
/// of that principal's hybrid key
/// ([`HybridSigner::from_seed`](crate::HybridSigner::from_seed) over
/// [`Ed25519SigningKey::to_bytes`]);
/// [`HybridSigner::ed25519_signing_key`](crate::HybridSigner::ed25519_signing_key)
/// hands the hybrid's derived Ed25519 half out as one too. It signs the
/// 64-byte classical blob — the suites' one negative vector, the
/// Ed25519-only layout no served board admits — and names its verifying
/// key, so a suite names this crate and never `ed25519-dalek`, which this
/// crate alone links. Private-key material: prints none of itself, wiped on
/// drop (`ed25519-dalek`'s own). Its field is the crate's, so
/// `HybridSigner::ed25519_signing_key` wraps a clone of the signer's own
/// half.
#[doc(hidden)]
#[derive(Clone)]
pub struct Ed25519SigningKey(pub(crate) EdSigningKey);

impl Ed25519SigningKey {
    /// The key `bytes` seed (`ed25519-dalek`'s `SigningKey::from_bytes`).
    pub fn from_bytes(bytes: &[u8; 32]) -> Ed25519SigningKey {
        Ed25519SigningKey(EdSigningKey::from_bytes(bytes))
    }

    /// The seed back — the 32 bytes the key was made from.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// The classical Ed25519 signature over `msg`: 64 bytes, this half
    /// alone — never a hybrid blob, which
    /// [`HybridSigner::sign`](crate::HybridSigner::sign) makes.
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.0.sign(msg).to_bytes()
    }

    /// This key's verifying key.
    pub fn verifying_key(&self) -> Ed25519VerifyingKey {
        Ed25519VerifyingKey(self.0.verifying_key())
    }
}

impl fmt::Debug for Ed25519SigningKey {
    /// A signing key is private-key material: never printed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Ed25519SigningKey(..)")
    }
}

/// TEST HOOK (the same standing) — an Ed25519 verifying key: the 32 bytes
/// of a key's public half, or the point decode's refusal of 32 bytes that
/// are no point — how a suite finds the undecodable key it enrolls to draw
/// the daemon's own refusal, from the verifier's answer rather than a
/// hard-coded string.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ed25519VerifyingKey(EdVerifyingKey);

impl Ed25519VerifyingKey {
    /// The key `bytes` encode, or
    /// [`HybridFault::Signature`](crate::HybridFault::Signature) where they
    /// decode to no point — the decode [`verify`](crate::verify) runs on an
    /// Ed25519 half, and the fault it answers under a half that does not
    /// decode ([`key_decodes`](crate::key_decodes) answers `false` there).
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Ed25519VerifyingKey, crate::HybridFault> {
        EdVerifyingKey::from_bytes(bytes)
            .map(Ed25519VerifyingKey)
            .map_err(|_| crate::HybridFault::Signature)
    }

    /// The key's 32 bytes, borrowed.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// The key's 32 bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}
