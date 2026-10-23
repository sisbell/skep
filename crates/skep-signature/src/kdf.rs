//! The KDF as code: one 32-byte seed to both half seeds, by HKDF-SHA-256.
//!
//! The crate doc states the KDF pin whole: the seed derives both half seeds
//! under a tag's token, never the raw seed to either. This is the signer's
//! side, compiled under `sign`. The signer derives through
//! [`derive_half_seeds`] inside `HybridSigner::from_seed`; the crate's
//! surface carries it, and the [`HalfSeeds`] it answers, only as a test
//! hook, for the integration suites that hold a half seed to a second
//! implementation: the tag-1 differential, and the KDF recomputed from
//! RFC 5869.

use std::fmt;

use hkdf::Hkdf;
use sha2::Sha256;
use skep_identity::SigAlgRow;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::Rule;

/// The KDF's salt: the derivation's own name.
///
/// The same seed under another KDF version derives other keys.
const KDF_SALT: &[u8] = b"skep-kdf-v1";
/// The half labels, the Ed25519 half's first.
const HALF_LABEL_ED25519: &[u8] = b"ed25519";
const HALF_LABEL_MLDSA65: &[u8] = b"ml-dsa-65";
const HALF_LABEL_FNDSA512: &[u8] = b"fn-dsa-512";

/// The two half seeds one 32-byte seed derives under one tag.
///
/// They are private-key material, wiped on drop: both halves are overwritten
/// as the value goes out of scope, which inside `HybridSigner::from_seed` is
/// once each half has been handed to its keygen. So `Clone` and nothing
/// more: not `Copy`, which a `Drop` impl rules out and could never be taken
/// back; and no derived `PartialEq`, whose comparison stops at the first
/// differing byte. A constant-time equality could be added later without
/// breaking a caller; nothing here could be removed.
///
/// The wipe is derived, `Zeroize` and `ZeroizeOnDrop` together: the one
/// `ZeroizeOnDrop` derive writes both the `Drop` that overwrites the halves
/// and the `ZeroizeOnDrop` marker the signer's wiping test reads, so the
/// marker cannot stand without the wipe it promises.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HalfSeeds {
    /// The Ed25519 half seed: the half's private key.
    ///
    /// It is `ed25519-dalek`'s `SecretKey` (`SigningKey::from_bytes`).
    pub ed25519: [u8; 32],
    /// The post-quantum half seed.
    ///
    /// It is ξ for ML-DSA-65, and the one keygen draw for the FN-DSA-512
    /// preview.
    pub pq: [u8; 32],
}

impl fmt::Debug for HalfSeeds {
    /// Writes `HalfSeeds(..)` and nothing of either half.
    ///
    /// A seed is private-key material: never printed.
    ///
    /// # Errors
    ///
    /// The formatter's error, where the sink it writes to refuses the bytes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HalfSeeds(..)")
    }
}

/// Derives both half seeds from `seed` under `tag`'s token: the KDF.
///
/// It is the KDF as the KDF pin states it (the crate doc), by HKDF-SHA-256 —
/// one Extract, `PRK = HMAC(KDF_SALT, seed)`, then one Expand per half,
/// `info = token ‖ 0x00 ‖ half_label`, 32 bytes out, written straight into
/// the [`HalfSeeds`] that wipes it. `None` for a tag no row names or this
/// build holds no rule for.
///
/// **What it leaves unwiped.** It leaves the working state of `hkdf` 0.12
/// and of the `hmac` 0.12 and `digest` 0.10 it runs on, which wipe nothing
/// they drop. By name, the parts that matter: a copy of the seed itself,
/// which Extract's HMAC buffers and leaves in place when it pads the block;
/// the PRK, which `Hkdf::new` computes and drops, and the HMAC state keyed by
/// it, which the `Hkdf` keeps and each Expand copies; and each Expand's
/// output block, which at 32 bytes is that half seed. Every other
/// intermediate derives from these. None of it is this crate's to reach; all
/// of it is released before this returns; and holding a copy of the seed, it
/// can tell no more than the seed does. The signer's wiping test pins the
/// types.
pub fn derive_half_seeds(tag: u8, seed: &[u8; 32]) -> Option<HalfSeeds> {
    let row = SigAlgRow::of_tag(tag)?;
    let pq_label = match Rule::of(tag)? {
        Rule::MlDsa65Ed25519 => HALF_LABEL_MLDSA65,
        Rule::FnDsa512PreviewEd25519 => HALF_LABEL_FNDSA512,
    };
    let hk = Hkdf::<Sha256>::new(Some(KDF_SALT), seed);
    // `info = token ‖ 0x00 ‖ half_label`, handed over as its three
    // components, so no buffer is built here.
    let expand = |half_label: &[u8], out: &mut [u8; 32]| {
        hk.expand_multi_info(&[row.token.as_bytes(), &[0u8], half_label], out)
            .expect("32 bytes is within HKDF-SHA-256's output bound");
    };
    let mut halves = HalfSeeds { ed25519: [0; 32], pq: [0; 32] };
    expand(HALF_LABEL_ED25519, &mut halves.ed25519);
    expand(pq_label, &mut halves.pq);
    Some(halves)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TAG_FNDSA512_PREVIEW_ED25519, TAG_MLDSA65_ED25519};

    /// Checks that neither of tag 1's half seeds is the raw seed.
    ///
    /// Tag 1's two halves differ, too, and each of tag 3's halves differs
    /// from tag 1's.
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
