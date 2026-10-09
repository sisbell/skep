//! THE FIXTURES' HOOKS (the `fuzz_support` standing: `#[doc(hidden)]`, not a
//! stable API), compiled under `test-hooks` alone, which no shipped signer
//! enables — and the crate's ONE LIST of its hooks, every item whose doc opens
//! `TEST HOOK`: `tests/it/tidy.rs` holds this list to those markers both ways,
//! so a hook added or dropped is named here and nowhere else in prose. In this
//! file: the seeded stream a tag-3 golden signs over ([`SeededRng06`]), the
//! widths the sizes pin reads ([`pq_widths`], answering [`PqWidths`]), the
//! suites' seed ([`Seed`]), which is no key, and the hybrid's Ed25519 half
//! as a suite holds it ([`Ed25519SigningKey`]), the one door a suite has to
//! `ed25519-dalek`'s key type. Beside the private fields they read, in the
//! signer's file:
//! [`HybridSigner::ed25519_signing_key`](crate::HybridSigner::ed25519_signing_key)
//! and [`HybridSigner::sign_with_rng`](crate::HybridSigner::sign_with_rng).
//! And the KDF's own answer, re-exported at the crate root:
//! [`derive_half_seeds`](crate::derive_half_seeds), answering
//! [`HalfSeeds`](crate::HalfSeeds).

use std::fmt;

use ed25519_dalek::{Signer as _, SigningKey as EdSigningKey};
use fn_dsa::{signature_size, sign_key_size, vrfy_key_size, FN_DSA_LOGN_512};
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, ExpandedSigningKeyBytes, MlDsa65};
use sha2::Sha256;
use zeroize::Zeroizing;

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

/// TEST HOOK (the same standing) — the widths one tag's rule fixes,
/// [`pq_widths`]' answer. Named, not a triple: three `usize`s meaning three
/// things, printed into a report that is transcribed.
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
/// API) — THE SUITES' SEED: one hybrid key's 32-byte seed — wire.md's seed,
/// the paper backup's 64 hex — held for a fixture, one per principal, and
/// lent by [`Seed::as_bytes`] to
/// [`HybridSigner::from_seed`](crate::HybridSigner::from_seed), which derives
/// the key it seeds. It is NO KEY: it signs nothing and names no public key,
/// so no fixture signs or enrols under the raw seed (the KDF PIN: never the
/// raw seed to either half). Private-key material: prints none of itself,
/// wiped on drop (`Zeroizing`).
///
/// The twin signs with the Ed25519 half the seed derives; the refusal below
/// it signs with the seed itself, its one difference (the `E0599` code is
/// checked on nightly only, so the twin rather than the annotation carries
/// the weight):
///
/// ```
/// use skep_signature::{HybridSigner, Seed, TAG_MLDSA65_ED25519};
/// let seed = Seed::from_bytes(&[7; 32]);
/// let signer = HybridSigner::from_seed(TAG_MLDSA65_ED25519, seed.as_bytes()).unwrap();
/// let half = signer.ed25519_signing_key();
/// let _ = half.sign(b"the entry frame");
/// ```
/// ```compile_fail,E0599
/// use skep_signature::{HybridSigner, Seed, TAG_MLDSA65_ED25519};
/// let seed = Seed::from_bytes(&[7; 32]);
/// let signer = HybridSigner::from_seed(TAG_MLDSA65_ED25519, seed.as_bytes()).unwrap();
/// let half = seed;
/// let _ = half.sign(b"the entry frame");
/// ```
#[doc(hidden)]
#[derive(Clone)]
pub struct Seed(Zeroizing<[u8; 32]>);

impl Seed {
    /// The seed `bytes`.
    pub fn from_bytes(bytes: &[u8; 32]) -> Seed {
        Seed(Zeroizing::new(*bytes))
    }

    /// The seed's 32 bytes, lent as `HybridSigner::from_seed` takes them: a
    /// borrow of the wiped buffer, never a copy of it.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for Seed {
    /// A seed is private-key material: never printed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Seed(..)")
    }
}

/// TEST HOOK (the same standing) — THE HYBRID'S DERIVED ED25519 HALF, as a
/// suite holds it: what
/// [`HybridSigner::ed25519_signing_key`](crate::HybridSigner::ed25519_signing_key)
/// hands out, and the only way to get one — the type has no public
/// constructor, so every Ed25519 key a suite holds is a hybrid's half and
/// never a raw seed's (a seed is a [`Seed`], which is no key). It makes a
/// bare Ed25519 signature, 64 bytes (wire.md §Sessions) — the suites' one
/// negative vector, the classical layout no served board admits — and names
/// its verifying key's 32 bytes, so a suite names this crate and never
/// `ed25519-dalek`, which this crate alone links. Private-key material:
/// prints none of itself, wiped on drop (`ed25519-dalek`'s own). Its field
/// is the crate's, so `HybridSigner::ed25519_signing_key` wraps a clone of
/// the signer's own half.
///
/// The twin takes the half from a signer; the refusal below it makes one
/// from 32 bytes, its one difference:
///
/// ```
/// use skep_signature::{Ed25519SigningKey, HybridSigner, TAG_MLDSA65_ED25519};
/// let signer = HybridSigner::from_seed(TAG_MLDSA65_ED25519, &[7; 32]).unwrap();
/// let half: Ed25519SigningKey = signer.ed25519_signing_key();
/// let _ = half.sign(b"the entry frame");
/// ```
/// ```compile_fail,E0599
/// use skep_signature::{Ed25519SigningKey, HybridSigner, TAG_MLDSA65_ED25519};
/// let signer = HybridSigner::from_seed(TAG_MLDSA65_ED25519, &[7; 32]).unwrap();
/// let half: Ed25519SigningKey = Ed25519SigningKey::from_bytes(&[7; 32]);
/// let _ = half.sign(b"the entry frame");
/// ```
#[doc(hidden)]
#[derive(Clone)]
pub struct Ed25519SigningKey(pub(crate) EdSigningKey);

impl Ed25519SigningKey {
    /// The half's 32 bytes — the KDF's Ed25519 half seed it was made from
    /// (`ed25519-dalek`'s `SigningKey::to_bytes`).
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// A bare Ed25519 signature over `msg`, 64 bytes: this half alone —
    /// never a blob, which [`HybridSigner::sign`](crate::HybridSigner::sign)
    /// makes.
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.0.sign(msg).to_bytes()
    }

    /// This half's verifying key, as its 32 bytes — the Ed25519 half a hybrid
    /// public key carries
    /// ([`PublicKey::ed25519_half`](skep_identity::PublicKey::ed25519_half)).
    pub fn verifying_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
}

impl fmt::Debug for Ed25519SigningKey {
    /// A signing key is private-key material: never printed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Ed25519SigningKey(..)")
    }
}
