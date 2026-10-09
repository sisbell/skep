//! `docs/wire.md`'s keygen-from-seed rule (§The claim ceremony and
//! credentials) held to the code: its formula, recomputed from RFC 5869 by
//! an oracle that shares no code with the `hkdf` crate the KDF calls,
//! against the KDF; its key and blob layout, built from that oracle's half
//! seeds by each half's own library, against the signer and the verify; and
//! its two vectors against the keys the KDF and keygen derive. wire.md is
//! read as prose, so a rewrap moves nothing.

use sha2::{Digest, Sha256};
use skep_identity::{Fingerprint, PublicKey, SigAlgRow};
use skep_signature::{derive_half_seeds, verify, HybridSigner, SeededRng06};

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
    let seed_clause = format!("the seed `{}` derives", hex(&GOLDEN_SEED));
    assert!(prose.contains(&seed_clause), "wire.md's vectors do not say: {seed_clause}");
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
            &ed.verifying_key(),
            "tag {tag}: the key's Ed25519 half is that key's public half"
        );
    }
}

/// One 32-byte draw and nothing more: the FN-DSA-512 preview's keygen input
/// as wire.md's rule states it — "the one 32-byte draw `fn-dsa` 0.4.0's
/// keygen makes, and nothing else" — written here, not borrowed from the
/// signer's `ExactBytes`.
struct OneDraw(Option<[u8; 32]>);

impl fn_dsa::RngCore for OneDraw {
    fn next_u32(&mut self) -> u32 {
        unreachable!("fn-dsa 0.4.0's keygen draws bytes, never a word")
    }
    fn next_u64(&mut self) -> u64 {
        unreachable!("fn-dsa 0.4.0's keygen draws bytes, never a word")
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let draw = self.0.take().expect("fn-dsa 0.4.0's keygen draws once");
        assert_eq!(dest.len(), draw.len(), "fn-dsa 0.4.0's keygen draws 32 bytes");
        dest.copy_from_slice(&draw);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), fn_dsa::RngError> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl fn_dsa::CryptoRng for OneDraw {}

/// THE KEY AND THE BLOB AS wire.md'S LAYOUT SENTENCE STATES THEM, BUILT
/// WITHOUT THE SIGNER: per tag, the half seeds by the formula (the oracle
/// above); the post-quantum half by its own library — tag 1's by `fips204`,
/// a second FIPS 204 (`KeyGen_internal(ξ)`, then the deterministic signature
/// under the empty context), tag 3's by `fn-dsa` 0.4.0 (its keygen fed the
/// half seed as its one draw, then a signature under `DOMAIN_NONE` and
/// `HASH_ID_RAW` drawn from the fixtures' stream), the crate doc's CTX PIN at
/// both; the Ed25519 half as RFC 8032's signature with its half seed the
/// private key; the two composed as wire.md lays them out. Over an empty
/// message and a short one, `HybridSigner` derives that key and makes that
/// blob byte for byte — tag 3 over the same stream — and `verify` passes it.
/// It signs no fixed frame and both sides draw one stream, so neither a frame
/// change nor a change to `SeededRng06` moves it, and it holds no pin to
/// re-pin: a change to which bytes a half signs, under which context or in
/// which order — made to the signer and the verifier alike, which every round
/// trip passes — fails here whatever the signature goldens are re-pinned
/// beside.
#[test]
fn the_key_and_the_blob_are_wire_mds_layout_built_without_the_signer() {
    use ed25519_dalek::Signer as _;
    use fips204::traits::{KeyGen, SerDes, Signer as _};
    use fn_dsa::{KeyPairGenerator as _, SigningKey as _};
    let layout = "The raw public key is the post-quantum key THEN the Ed25519 key's 32 bytes; a \
                  signature blob is the post-quantum signature THEN the Ed25519 signature's 64 \
                  bytes, both over the same bytes, two fixed-width fields with no length prefix.";
    assert!(wire_md_prose().contains(layout), "wire.md's layout does not say: {layout}");
    let stream_seed = [7u8; 32];
    for (tag, token, pq_label) in
        [(1u8, "mldsa65-ed25519", "ml-dsa-65"), (3, "fndsa512-preview-ed25519", "fn-dsa-512")]
    {
        let half_seed = |label: &str| {
            let info: [&[u8]; 3] = [token.as_bytes(), &[0u8], label.as_bytes()];
            hkdf_sha256_32(b"skep-kdf-v1", &GOLDEN_SEED, &info)
        };
        let ed = ed25519_dalek::SigningKey::from_bytes(&half_seed("ed25519"));
        let signer = HybridSigner::from_seed(tag, &GOLDEN_SEED).unwrap();
        for msg in [&b""[..], &b"no fixed frame"[..]] {
            let (pq_key, pq_sig) = if tag == 1 {
                let (pk, sk) = fips204::ml_dsa_65::KG::keygen_from_seed(&half_seed(pq_label));
                let sig = sk.try_sign_with_seed(&[0u8; 32], msg, &[]).expect("fips204 signs");
                (pk.into_bytes().to_vec(), sig.to_vec())
            } else {
                let logn = fn_dsa::FN_DSA_LOGN_512;
                let mut sk = vec![0u8; fn_dsa::sign_key_size(logn)];
                let mut pk = vec![0u8; fn_dsa::vrfy_key_size(logn)];
                let mut draw = OneDraw(Some(half_seed(pq_label)));
                fn_dsa::KeyPairGeneratorStandard::default()
                    .keygen(logn, &mut draw, &mut sk, &mut pk);
                let mut sig = vec![0u8; fn_dsa::signature_size(logn)];
                fn_dsa::SigningKeyStandard::decode(&sk)
                    .expect("its own key decodes")
                    .sign(
                        &mut SeededRng06::new(stream_seed),
                        &fn_dsa::DOMAIN_NONE,
                        &fn_dsa::HASH_ID_RAW,
                        msg,
                        &mut sig,
                    )
                    .expect("a valid signing key signs");
                (pk, sig)
            };
            let key = PublicKey::from_halves(token, &pq_key, &ed.verifying_key().to_bytes())
                .expect("the row's widths");
            assert_eq!(signer.public_key(), &key, "tag {tag}: the key wire.md lays out");
            let blob = [&pq_sig[..], &ed.sign(msg).to_bytes()[..]].concat();
            let ours = signer.sign_with_rng(&mut SeededRng06::new(stream_seed), msg);
            let parts_at = ours.iter().zip(&blob).position(|(a, b)| a != b);
            assert!(
                ours.len() == blob.len() && parts_at.is_none(),
                "tag {tag}, a {}-byte message: our blob ({} bytes) parts from the one wire.md lays \
                 out ({} bytes, its post-quantum field the first {}) at byte {parts_at:?}",
                msg.len(),
                ours.len(),
                blob.len(),
                pq_sig.len()
            );
            assert_eq!(
                verify(tag, &key, msg, &blob),
                Ok(()),
                "tag {tag}, a {}-byte message: the blob wire.md lays out verifies",
                msg.len()
            );
        }
    }
}
