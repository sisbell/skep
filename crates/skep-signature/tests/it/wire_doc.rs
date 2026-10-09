//! `docs/wire.md`'s keygen-from-seed rule (§The claim ceremony and
//! credentials) held to the code: its formula, recomputed from RFC 5869 by
//! an oracle that shares no code with the `hkdf` crate the KDF calls,
//! against the KDF; and its two vectors against the keys the KDF and keygen
//! derive. wire.md is read as prose, so a rewrap moves nothing.

use sha2::{Digest, Sha256};
use skep_identity::{Fingerprint, SigAlgRow};
use skep_signature::{derive_half_seeds, HybridSigner};

use crate::golden::{hex, GOLDEN_SEED};

/// `docs/wire.md` as prose, rewrapped at will: every run of whitespace reads
/// as one space.
fn wire_md_prose() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/wire.md");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// THE PUBLISHED VECTORS: `docs/wire.md`'s keygen-from-seed rule (§The
/// claim ceremony and credentials) hands a client author `GOLDEN_SEED` and
/// each tag's fingerprint as that rule's vectors — the keys the two goldens
/// in `golden.rs` derive. Checked against the KDF and keygen themselves, so a
/// vector that drifts in the prose fails as a drifted key does.
#[test]
fn wire_md_publishes_the_keygen_from_seed_vectors() {
    let prose = wire_md_prose();
    let seed = format!("the seed `{}` derives", hex(&GOLDEN_SEED));
    assert!(prose.contains(&seed), "wire.md's vectors do not say: {seed}");
    for tag in [1u8, 3] {
        let token = SigAlgRow::of_tag(tag).unwrap().token;
        let signer = HybridSigner::from_seed(tag, &GOLDEN_SEED).unwrap();
        let vector = format!(
            "under tag `{tag}` (`{token}`), the key whose fingerprint is `{}`",
            Fingerprint::of(signer.public_key()).to_hex()
        );
        assert!(prose.contains(&vector), "wire.md's vectors do not say: {vector}");
    }
}

/// HMAC-SHA-256 (RFC 2104) from `sha2` alone, so the oracle below shares no
/// code with the `hkdf` crate the KDF calls. Every key here is at most one
/// SHA-256 output, inside the 64-byte block.
fn hmac_sha256(key: &[u8], message: &[&[u8]]) -> [u8; 32] {
    let mut block = [0u8; 64];
    block[..key.len()].copy_from_slice(key);
    let mut inner = Sha256::new().chain_update(block.map(|b| b ^ 0x36));
    for part in message {
        inner.update(part);
    }
    Sha256::new()
        .chain_update(block.map(|b| b ^ 0x5c))
        .chain_update(inner.finalize())
        .finalize()
        .into()
}

/// HKDF-SHA-256 (RFC 5869) at `L = 32`: `PRK = HMAC(salt, IKM)`, then the one
/// Expand block `T(1) = HMAC(PRK, info ‖ 0x01)`, `info` given as its parts.
fn hkdf_sha256_32(salt: &[u8], ikm: &[u8], info: &[&[u8]]) -> [u8; 32] {
    let prk = hmac_sha256(salt, &[ikm]);
    let mut expand = info.to_vec();
    expand.push(&[1u8]);
    hmac_sha256(&prk, &expand)
}

/// THE KDF IS THE FORMULA `docs/wire.md` PUBLISHES: the formula and its half
/// labels as wire.md states them, recomputed by RFC 5869 from `sha2` alone —
/// the oracle first held to RFC 5869's own Test Case 1 — for both tags, both
/// halves and three seeds; and the signer's Ed25519 key IS its half seed, the
/// key's Ed25519 half that key's public half. The published vectors are the
/// code's own output; this holds the code to the formula a client implements.
#[test]
fn the_kdf_is_the_hkdf_formula_wire_md_publishes() {
    let rfc_salt: Vec<u8> = (0x00..=0x0c).collect();
    let rfc_info: Vec<u8> = (0xf0..=0xf9).collect();
    assert_eq!(
        hex(&hkdf_sha256_32(&rfc_salt, &[0x0b; 22], &[&rfc_info[..]])),
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf",
        "the oracle is not RFC 5869's HKDF-SHA-256 (Appendix A.1, the OKM's first 32 bytes)"
    );
    let prose = wire_md_prose();
    for stated in [
        "half_seed = HKDF-SHA-256(salt = \"skep-kdf-v1\", IKM = seed, \
         info = <alg token> ‖ 0x00 ‖ <half label>, L = 32)",
        "with the half labels `ed25519` for the Ed25519 half and, for the post-quantum half, \
         `ml-dsa-65` under tag `1` and `fn-dsa-512` under tag `3`",
    ] {
        assert!(prose.contains(stated), "wire.md's keygen-from-seed rule does not say: {stated}");
    }
    for (tag, token, pq_label) in
        [(1u8, "mldsa65-ed25519", "ml-dsa-65"), (3, "fndsa512-preview-ed25519", "fn-dsa-512")]
    {
        let formula = |seed: &[u8; 32], label: &str| {
            hkdf_sha256_32(b"skep-kdf-v1", seed, &[token.as_bytes(), &[0u8], label.as_bytes()])
        };
        for seed in [GOLDEN_SEED, [0x00; 32], [0xff; 32]] {
            let halves = derive_half_seeds(tag, &seed).unwrap();
            assert!(
                halves.ed25519 == formula(&seed, "ed25519"),
                "tag {tag}: the Ed25519 half seed"
            );
            assert!(halves.pq == formula(&seed, pq_label), "tag {tag}: the post-quantum half seed");
        }
        let signer = HybridSigner::from_seed(tag, &GOLDEN_SEED).unwrap();
        let ed = signer.ed25519_signing_key();
        assert!(ed.to_bytes() == formula(&GOLDEN_SEED, "ed25519"), "tag {tag}: the Ed25519 key");
        assert_eq!(
            signer.public_key().ed25519_half(),
            ed.verifying_key().as_bytes(),
            "tag {tag}: the key's Ed25519 half is that key's public half"
        );
    }
}
