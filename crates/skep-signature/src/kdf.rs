//! THE KDF as code (the crate doc states the KDF PIN whole): one 32-byte
//! seed to both half seeds under a tag's token by HKDF-SHA-256, never the raw
//! seed to either — the signer's side, compiled under `sign`. The signer
//! derives through [`derive_half_seeds`] inside `HybridSigner::from_seed`;
//! the crate's surface carries it, and the [`HalfSeeds`] it answers, only as
//! a test hook, for the integration suites that hold a half seed to a second
//! implementation: the tag-1 differential, and the KDF recomputed from
//! RFC 5869.

use std::fmt;

use hkdf::Hkdf;
use sha2::Sha256;
use skep_identity::SigAlgRow;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::Rule;

/// The KDF's salt — the derivation's own name, so the same seed under
/// another KDF version derives other keys.
const KDF_SALT: &[u8] = b"skep-kdf-v1";
/// The half labels.
const HALF_LABEL_ED25519: &[u8] = b"ed25519";
const HALF_LABEL_MLDSA65: &[u8] = b"ml-dsa-65";
const HALF_LABEL_FNDSA512: &[u8] = b"fn-dsa-512";

/// The two half seeds one 32-byte seed derives under one tag —
/// private-key material: WIPED ON DROP, both halves overwritten as the
/// value goes out of scope (`Zeroize`, `ZeroizeOnDrop`), which inside
/// `HybridSigner::from_seed` is once each half has been handed to its
/// keygen. So `Clone` and nothing more: not `Copy`, which a `Drop` impl
/// rules out and could never be taken back; and no derived `PartialEq`,
/// whose comparison stops at the first differing byte. A constant-time
/// equality could be added later without breaking a caller; nothing here
/// could be removed.
#[derive(Clone)]
pub struct HalfSeeds {
    /// The Ed25519 half's seed (`ed25519-dalek`'s `SigningKey::from_bytes`).
    pub ed25519: [u8; 32],
    /// The post-quantum half's seed: ξ for ML-DSA-65; the keygen draw for
    /// the FN-DSA-512 preview.
    pub pq: [u8; 32],
}

impl fmt::Debug for HalfSeeds {
    /// A seed is private-key material: never printed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HalfSeeds(..)")
    }
}

impl Zeroize for HalfSeeds {
    fn zeroize(&mut self) {
        self.ed25519.zeroize();
        self.pq.zeroize();
    }
}

/// The wipe on drop the type's doc states; `ZeroizeOnDrop` below is the
/// marker the signer's wiping test reads it off.
impl Drop for HalfSeeds {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for HalfSeeds {}

/// HKDF-SHA-256 as the KDF PIN states it: `salt = KDF_SALT`, `IKM = seed`,
/// `info = token ‖ 0x00 ‖ half_label`, 32 bytes out.
///
/// THE ONE UNWIPED RESIDUE of a signer's keygen, by name: the `Hkdf` state —
/// `hmac` 0.12's HMAC core, keyed by the PRK every half seed of a tag
/// derives from, so as good as the seed itself — lives for this one call
/// and is released before the half seed is handed back, but released as it
/// is: neither `hkdf` 0.12 nor `hmac` 0.12 offers a wipe, and its fields
/// are theirs to reach, not this crate's. The signer's wiping test pins
/// exactly this.
fn derive_half_seed(seed: &[u8; 32], token: &str, half_label: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(KDF_SALT), seed);
    let mut out = [0u8; 32];
    // `info = token ‖ 0x00 ‖ half_label`, handed over as its three
    // components: `hkdf`'s own `expand` is `expand_multi_info` over one
    // component, so the concatenation is the crate's to make and no buffer is
    // built here.
    hk.expand_multi_info(&[token.as_bytes(), &[0u8], half_label], &mut out)
        .expect("32 bytes is within HKDF-SHA-256's output bound");
    out
}

/// THE KDF: one seed to both half seeds under `tag`'s token; `None` for a
/// tag no row names or this build holds no rule for.
pub fn derive_half_seeds(tag: u8, seed: &[u8; 32]) -> Option<HalfSeeds> {
    let row = SigAlgRow::of_tag(tag)?;
    let pq_label = match Rule::of(tag)? {
        Rule::MlDsa65Ed25519 => HALF_LABEL_MLDSA65,
        Rule::FnDsa512PreviewEd25519 => HALF_LABEL_FNDSA512,
    };
    Some(HalfSeeds {
        ed25519: derive_half_seed(seed, row.token, HALF_LABEL_ED25519),
        pq: derive_half_seed(seed, row.token, pq_label),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TAG_FNDSA512_PREVIEW_ED25519, TAG_MLDSA65_ED25519};

    /// The KDF never hands either half the raw seed, and the two halves of
    /// one tag differ.
    #[test]
    fn the_kdf_derives_both_halves_and_neither_is_the_seed() {
        let seed = [0x01u8; 32];
        let h1 = derive_half_seeds(TAG_MLDSA65_ED25519, &seed).unwrap();
        assert_ne!(h1.ed25519, seed);
        assert_ne!(h1.pq, seed);
        assert_ne!(h1.ed25519, h1.pq);
        let h3 = derive_half_seeds(TAG_FNDSA512_PREVIEW_ED25519, &seed).unwrap();
        assert_ne!(h3.pq, h1.pq);
        assert_ne!(h3.ed25519, h1.ed25519);
    }
}
