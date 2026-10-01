//! THE FIXTURES' HOOKS (the `fuzz_support` standing: `#[doc(hidden)]`, not a
//! stable API) — the seeded stream a tag-3 golden signs over
//! ([`SeededRng06`]) and the widths the sizes pin reads ([`pq_widths`]),
//! compiled under `test-hooks` alone, which no shipped signer enables. The
//! two hooks on `HybridSigner` itself sit in the signer's file, beside the
//! private fields they read.

use std::fmt;

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
