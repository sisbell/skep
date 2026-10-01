//! THE GOLDENS (the frozen-tag rule's pin), beside the one implementation
//! they pin: per tag, one seed through the KDF to both public keys and the
//! fingerprint; the four grammars' signatures over fixed entry frames (the
//! `record` grammar at three kinds); tag 1's signatures byte-stable (FIPS
//! 204's deterministic variant), tag 3's under the fixtures' seeded RNG; the
//! hybrid cross-check; tag 1 DIFFERENTIAL against a second pure-Rust FIPS 204
//! crate — keys-from-seed and signatures byte-equal; the widths each pinned
//! crate fixes, pinned by hand beside the sizes and timings the report takes
//! back; which FN-DSA backend signed them on this target; and the
//! keygen-from-seed rule as `docs/wire.md` publishes it: its formula,
//! recomputed from RFC 5869 against the KDF, and its two vectors, checked
//! against the keys themselves.

use sha2::{Digest, Sha256};
use skep_identity::{
    entry_body_insert, entry_body_make_link, entry_body_publish, entry_body_record, entry_frame,
    BoardTerm, EntrySlot, Fingerprint, LinkSlots, RecordRows, ShotSegmentPiece, SigAlgRow,
    ALG_MLDSA65_ED25519,
};
use skep_signature::{
    derive_half_seeds, pq_widths, verify, HybridFault, HybridSigner, PqWidths, SeededRng06,
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// `docs/wire.md` as prose, rewrapped at will: every run of whitespace reads
/// as one space.
fn wire_md_prose() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/wire.md");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

// ── the frames ──────────────────────────────────────────────────────────────
//
// TWINS: `addr` and `fixed_frames` are copies of the two in skepd's
// `tests/it/signed_ops.rs`, whose `the_entry_frames_bytes_per_op_are_pinned`
// pins the frames' bytes; the goldens below pin their signatures, so a copy
// that drifts from its twin fails a golden here.

fn addr(s: &str) -> skep_address::Address {
    let comps: Vec<skep_address::Nat> =
        s.split('.').map(|c| skep_address::Nat::from(c.parse::<u64>().unwrap())).collect();
    skep_address::validate(skep_address::Tumbler::new(comps).unwrap()).unwrap()
}

/// The six fixed instances every golden signs: the frames of an `insert`
/// (undeclared, two values), a `make_link` (three address-form slots), a
/// `publish` (three values copied in, one window of two positions onto
/// another document, the base taken at three — the address form, l6-A4)
/// and three `record`s (the frame merge, fm-I; the record grade, 2a): an
/// enrol's kind — its type slot, one subject, neither optional row named, a
/// short canonical body — a retire's kind beside it over the same subject,
/// and the claim's — its type slot, the EMPTY target slot, no record at all
/// (a claim carries none, AUTH-2.48), the body-bytes row empty — on a board
/// whose `H.1` pair is `(12, 0xAB…)`, by account `1.0.1`.
fn fixed_frames(alg: &str) -> [(&'static str, Vec<u8>); 6] {
    let (account, doc) = (addr("1.0.1"), addr("1.0.1.0.1"));
    let insert = entry_body_insert(None, [&b"a"[..], &b"b"[..]]);
    let ty = [addr("1.1.0.1.0.1.0.3.90")];
    let from = [addr("1.0.1")];
    let to: [skep_address::Address; 0] = [];
    let link = entry_body_make_link(LinkSlots {
        from: EntrySlot::Addrs(&from),
        to: EntrySlot::Addrs(&to),
        ty: EntrySlot::Addrs(&ty),
    });
    let window = addr("1.0.1.0.2.0.1.1");
    let publish = entry_body_publish(
        [
            ShotSegmentPiece::Value(b"x"),
            ShotSegmentPiece::Value(b"y"),
            ShotSegmentPiece::Value(b"z"),
            ShotSegmentPiece::Window {
                start: &window,
                width: std::num::NonZeroU64::new(2).expect("2 is not zero"),
            },
        ],
        Some(3),
    );
    let subject = [addr("1.0.2")];
    let enrol = entry_body_record(RecordRows {
        ty: &addr("1.1.0.1.0.1.0.3.1"),
        to: &subject,
        replaces: None,
        lineage_fork_point: None,
        sigless_canonical_record: br#"{"type":"skep-enroll"}"#,
    });
    let retire = entry_body_record(RecordRows {
        ty: &addr("1.1.0.1.0.1.0.3.2"),
        to: &subject,
        replaces: None,
        lineage_fork_point: None,
        sigless_canonical_record: br#"{"type":"skep-retire"}"#,
    });
    let claim = entry_body_record(RecordRows {
        ty: &addr("1.1.0.1.0.1.0.3.3"),
        to: &[],
        replaces: None,
        lineage_fork_point: None,
        sigless_canonical_record: b"",
    });
    let board = BoardTerm { log_position: 12, chain: [0xAB; 32] };
    [insert, link, publish, enrol, retire, claim]
        .map(|body| (body.op(), entry_frame(alg, board, &account, &doc, &body)))
}

// ── the goldens ─────────────────────────────────────────────────────────────

/// The golden's seed: one 32-byte seed, the paper backup's one 64-hex line —
/// and the seed of the keygen-from-seed rule's vectors `docs/wire.md`
/// publishes, so the fingerprints below are the ones a client author checks
/// against.
const GOLDEN_SEED: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

/// The seed of the fixtures' stream the tag-3 golden signatures draw their
/// per-signature seeds from — `GOLDEN_SEED`'s bytes reused, so those six
/// pins depend on the key seed twice: through the key and through the stream.
const GOLDEN_STREAM_SEED: [u8; 32] = GOLDEN_SEED;

/// One tag's golden, in the documented form: the SHA-256 of the PQ public
/// half, of the Ed25519 public half, of the whole raw key; the fingerprint;
/// and per grammar the SHA-256 of the signature blob — the frames themselves
/// pinned byte for byte by skepd's `the_entry_frames_bytes_per_op_are_pinned`.
/// The `make_link` signatures moved with the replay fix (PUB-5.15): the body
/// gained its `replaces` row, an EMPTY group in this member-less frame, in
/// place under `skep-entry-v1` (l6-A3). The `publish` signatures moved with
/// the publish re-pin of 2026-09-29 (V, l6-A4, D25's (c′)): the body became
/// the count, the runs in the address form and the base-extent group, in
/// place under the same tag, and the fixed instance gained a window and a
/// base; and the `record` signatures were minted then, the frame merge's
/// fourth grammar (fm-I) — the enrol's, which the record grade's build (2a)
/// left unmoved, pinning the retire's and the claim's beside it. The keys,
/// the fingerprints and the `insert` signatures have not moved since the tag
/// was pinned.
struct TagGolden {
    tag: u8,
    pq_pk: &'static str,
    ed_pk: &'static str,
    raw_key: &'static str,
    fingerprint: &'static str,
    sigs: [&'static str; 6],
}

/// One fixed frame, signed: its op's name, the frame's bytes and the
/// signature blob over them — named, not a triple, as `PqWidths` is: the
/// frame and the blob are both `Vec<u8>`, and a position would let them
/// trade places.
struct SignedFrame {
    op: &'static str,
    frame: Vec<u8>,
    sig: Vec<u8>,
}

fn sign_fixed_frames(tag: u8) -> (HybridSigner, Vec<SignedFrame>) {
    let signer = HybridSigner::from_seed(tag, &GOLDEN_SEED).unwrap();
    let alg = SigAlgRow::of_tag(tag).unwrap().token;
    let mut out = Vec::new();
    for (op, frame) in fixed_frames(alg) {
        // Tag 3's signature draws its per-signature seed from the fixtures'
        // stream, reseeded per op from `GOLDEN_STREAM_SEED` so each signature
        // is a function of its frame alone.
        let mut rng = SeededRng06::new(GOLDEN_STREAM_SEED);
        let sig = signer.sign_with_rng(&mut rng, &frame);
        assert_eq!(
            verify(tag, signer.public_key(), &frame, &sig),
            Ok(()),
            "tag {tag}: the {op} frame's blob verifies"
        );
        out.push(SignedFrame { op, frame, sig });
    }
    (signer, out)
}

fn check_golden(g: &TagGolden) {
    let (signer, signed) = sign_fixed_frames(g.tag);
    let key = signer.public_key();
    let pq = sha_hex(key.pq_half());
    let ed = sha_hex(key.ed25519_half());
    let raw = sha_hex(key.raw());
    let fp = Fingerprint::of(key).to_hex();
    let sigs: Vec<String> = signed.iter().map(|s| sha_hex(&s.sig)).collect();
    let report = format!(
        "tag {}: pq_pk {pq}\n ed_pk {ed}\n raw_key {raw}\n fingerprint {fp}\n sigs {}",
        g.tag,
        sigs.join(" ")
    );
    assert_eq!(pq, g.pq_pk, "the PQ public half moved — a keygen change is a NEW tag\n{report}");
    assert_eq!(ed, g.ed_pk, "the Ed25519 half moved — the KDF is a frozen pin\n{report}");
    assert_eq!(raw, g.raw_key, "{report}");
    assert_eq!(fp, g.fingerprint, "{report}");
    for (i, SignedFrame { op, .. }) in signed.iter().enumerate() {
        assert_eq!(sigs[i], g.sigs[i], "the {op} signature moved under tag {}\n{report}", g.tag);
    }
}

/// TAG 1's GOLDEN: the KEY-DERIVATION golden (seed → KDF → both public
/// keys → fingerprint) and the six fixed frames' signatures, byte-stable under
/// FIPS 204's deterministic variant and Ed25519's own determinism.
#[test]
fn golden_tag_1_mldsa65_ed25519() {
    check_golden(&TagGolden {
        tag: 1,
        pq_pk: "41b2f17766cec1a3ccc6b4c8a661e07c5ebc1d1503ec4c95f4a283aa750d5a4e",
        ed_pk: "427a61d4297fffd61db5ada0dc592fa22858b6b8dbb19219b2f55437e2b671d2",
        raw_key: "21ee44a4d3a59b86fafc6ef131e2bfb63688023f6101f392a34c17a41fefe27b",
        fingerprint: "8c7d0b0e21969ffa5039ccebce2c857614740c3be9498ab8c697bc9320c30623",
        sigs: [
            "2892943416a13f80eeb95f4c8bd55f115d7248324c433bffbeaf7f0501828148",
            "9d47fea8f8cc6077222b89060ebcc69b93d7d9b228c1a9196f324ee3a80119d0",
            "e36e6e421c3a4ed0826144f6cb2d578cc18eb72e7d84fbc483fd5ac000d7cf16",
            "28c70f669d44919062bf99a79cec75a973c7f6acaf315991a53daea054b7f508",
            "abb554df48572fb1fbfa72445b1ef8024dd6fd2c8889ed33cc1a756d5a9a07c3",
            "4c367931a56e731f01c0f5dc19d4d79d7be5b459c3cc113cbf946fe54cf90472",
        ],
    });
}

/// TAG 3's GOLDEN (the PREVIEW): the KEY-DERIVATION golden — `fn-dsa`
/// 0.4.0's keygen from the KDF's seed IS the tag's frozen keygen rule — and
/// the six signatures under the fixtures' seeded RNG (FN-DSA signing is
/// randomized by the draft's own rule; what the tag freezes is the key, the
/// frame and the verify, and the fixture's RNG makes the bytes reproducible
/// here).
#[test]
fn golden_tag_3_fndsa512_preview_ed25519() {
    check_golden(&TagGolden {
        tag: 3,
        pq_pk: "0e70d565dce4eaf0da8790ca44478f85587b3e77322359ac65fc7ab3f6848571",
        ed_pk: "43ac1d6774e9a307df9ca5d82c010bb99c3c4ef42439e78fc09b133f401bbf10",
        raw_key: "c259e2fd41a3534528a7edf6550befa1fa134a3371aca0cccfe5caf28c90c886",
        fingerprint: "d38e5be29f0c62fe1a51cb09d00250ea18bfd2ba799536c0596077d1d1d65fca",
        sigs: [
            "da92e3fc0247d5f39ed149f574a6c18cc1bf959a4f167ba33d381a955ed95779",
            "a7bc27e514b92dd4bc23f1c69ec46ad010cca17a22eada4f944e0f31edfd7d75",
            "0af99ce8edd4c6f9230fe381a22b2dfb3eb59febf497d5bb9a76a0e6ca105434",
            "38b456b9f4413a0f6164aad2e0cc3e9e8b35b8534c915f465992391cf71b03ad",
            "7399b23baaae2e1a1bdc85eb74bfc6b88f76029bf3e17857635c86b9e106eab1",
            "7807cbba98e2e04fa7647c50baeacdaefb44fbf477fd9ee3f71095f47d1fe37d",
        ],
    });
}

/// THE PUBLISHED VECTORS: `docs/wire.md`'s keygen-from-seed rule (§The
/// claim ceremony and credentials) hands a client author `GOLDEN_SEED` and
/// each tag's fingerprint as that rule's vectors — the keys the two goldens
/// above derive. Checked against the KDF and keygen themselves, so a vector
/// that drifts in the prose fails as a drifted key does.
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

// ── the KDF, recomputed ─────────────────────────────────────────────────────

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

/// THE HYBRID CROSS-CHECK at the frame: each half alone fails — a valid PQ
/// half with a foreign Ed25519 half, and the reverse — answering `Signature`
/// under both tags: the spliced blob is the row's width under the row's own
/// tag, so the signature is all that can be at fault.
#[test]
fn each_half_alone_fails_under_both_tags() {
    for tag in [1u8, 3] {
        let (signer, signed) = sign_fixed_frames(tag);
        let row = SigAlgRow::of_tag(tag).unwrap();
        let other = HybridSigner::from_seed(tag, &[0x99; 32]).unwrap();
        let SignedFrame { frame, sig, .. } = &signed[0];
        let mut rng = SeededRng06::new([1; 32]);
        let foreign = other.sign_with_rng(&mut rng, frame);
        // The PQ half ours, the Ed25519 half theirs.
        let mut mixed = sig[..row.pq_sig_len].to_vec();
        mixed.extend_from_slice(&foreign[row.pq_sig_len..]);
        assert_eq!(
            verify(tag, signer.public_key(), frame, &mixed),
            Err(HybridFault::Signature),
            "tag {tag}: our post-quantum half beside a foreign Ed25519 half"
        );
        // The Ed25519 half ours, the PQ half theirs.
        let mut mixed = foreign[..row.pq_sig_len].to_vec();
        mixed.extend_from_slice(&sig[row.pq_sig_len..]);
        assert_eq!(
            verify(tag, signer.public_key(), frame, &mixed),
            Err(HybridFault::Signature),
            "tag {tag}: a foreign post-quantum half beside our Ed25519 half"
        );
        assert_eq!(
            verify(tag, signer.public_key(), frame, sig),
            Ok(()),
            "tag {tag}: our blob, unmixed"
        );
    }
}

/// THE DIFFERENTIAL TEST for tag 1 (the PQ investigation §8.4 (4), §8.5
/// (ii)): `ml-dsa` 0.1.1's keys from ξ and its deterministic signatures are
/// byte-equal to `fips204` 0.4.6's, a second pure-Rust FIPS 204, over
/// sixteen seeds and the six fixed frames — the gate every future bump of
/// the pinned crate must pass, since FIPS 204 fixes `KeyGen_internal(ξ)`
/// and the deterministic variant.
#[test]
fn tag_1_is_byte_equal_to_a_second_fips_204_implementation() {
    use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
    for i in 0..16u8 {
        let seed = [i; 32];
        let halves = derive_half_seeds(1, &seed).unwrap();
        // `ml-dsa`'s side: the PQ half of the hybrid key and its signature.
        let ours = HybridSigner::from_seed(1, &seed).unwrap();
        let our_pk = ours.public_key().pq_half().to_vec();
        // `fips204`'s side, from the same ξ.
        let (their_pk, their_sk) = fips204::ml_dsa_65::KG::keygen_from_seed(&halves.pq);
        assert_eq!(our_pk, their_pk.clone().into_bytes().to_vec(), "seed {i}: the public key");
        for (op, frame) in fixed_frames(ALG_MLDSA65_ED25519) {
            let our_sig = ours.sign(&frame);
            let our_pq = &our_sig[..ours.public_key().sig_alg_row().pq_sig_len];
            let their_sig = their_sk.try_sign_with_seed(&[0u8; 32], &frame, &[]).unwrap();
            assert_eq!(our_pq, &their_sig[..], "seed {i}, {op}: the deterministic signature");
            assert!(their_pk.verify(&frame, &their_sig, &[]), "their verify of their own");
            let as_theirs: [u8; fips204::ml_dsa_65::SIG_LEN] = our_pq.try_into().unwrap();
            assert!(their_pk.verify(&frame, &as_theirs, &[]), "their verify of ours");
        }
    }
}

/// THE SIZES AND TIMINGS the report takes back: per tag the public key, the
/// signature blob and the FILLED marker payload (97 + the blob), and the
/// median sign and verify on this machine — printed, and the sizes pinned.
#[test]
fn sizes_and_timings_per_tag() {
    use std::time::Instant;
    for tag in [1u8, 3] {
        let row = SigAlgRow::of_tag(tag).unwrap();
        let (signer, signed) = sign_fixed_frames(tag);
        let key_len = signer.public_key().raw().len();
        let sig_len = signed[0].sig.len();
        assert_eq!(key_len, row.key_len(), "tag {tag}: the key is the row's width");
        assert_eq!(sig_len, row.sig_len(), "tag {tag}: the blob is the row's width");
        let PqWidths { key: pq_key_len, sig: pq_sig_len, signing_key: pq_signing_key_len } =
            pq_widths(tag).unwrap();
        let frame = &signed[0].frame;
        let n = 40;
        let mut sign_us = Vec::new();
        let mut verify_us = Vec::new();
        let mut keygen_us = Vec::new();
        for k in 0..n {
            let t = Instant::now();
            let s = HybridSigner::from_seed(tag, &[k as u8; 32]).unwrap();
            keygen_us.push(t.elapsed().as_micros());
            let t = Instant::now();
            let sig = s.sign(frame);
            sign_us.push(t.elapsed().as_micros());
            let t = Instant::now();
            assert_eq!(
                verify(tag, s.public_key(), frame, &sig),
                Ok(()),
                "tag {tag}, seed {k}: a blob `sign` made verifies"
            );
            verify_us.push(t.elapsed().as_micros());
        }
        let median = |v: &mut Vec<u128>| {
            v.sort();
            v[v.len() / 2]
        };
        eprintln!(
            "SIGNED-OPS SIZES tag {tag} ({}): public key {key_len} B (pq {pq_key_len} + ed 32), \
             signature {sig_len} B (pq {pq_sig_len} + ed 64), filled marker payload {} B \
             (97 + {sig_len}), pq signing key {pq_signing_key_len} B; medians over {n}: \
             keygen {} µs, sign {} µs, verify {} µs",
            row.token,
            97 + sig_len,
            median(&mut keygen_us),
            median(&mut sign_us),
            median(&mut verify_us)
        );
    }
    // `ml-dsa` 0.1.1's ML-DSA-65 — FIPS 204's verifying key, signature and
    // expanded signing key — read off the crate by `pq_widths` and pinned here
    // by hand.
    assert_eq!(
        pq_widths(1),
        Some(PqWidths { key: 1952, sig: 3309, signing_key: 4032 })
    );
    // `fn-dsa` 0.4.0's signing key at degree 9: 65 + (6 << 7) + 512 = 1,345
    // (its `f, g, F` and the hashed verifying key), the PQ investigation's
    // measured figure.
    assert_eq!(
        pq_widths(3),
        Some(PqWidths { key: 897, sig: 666, signing_key: 1345 })
    );
}

/// THE FN-DSA PREVIEW's signer backend on this machine (the owner's added
/// question): `fn-dsa` 0.4.0 selects its floating-point backend by
/// `target_arch` alone — the native `f64` on `x86_64`, `aarch64`, `arm64ec`
/// and `riscv64`, the INTEGER-EMULATED IEEE-754 backend everywhere else —
/// with no feature to force the emulation, so on this `aarch64` machine the
/// native backend signs; the emulated signer is compiled for no installed
/// target here and could not be run. This test records which backend signed
/// the goldens, and that it signs and verifies.
#[test]
fn the_fn_dsa_preview_signs_and_verifies_on_this_target() {
    let native = cfg!(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "arm64ec",
        target_arch = "riscv64"
    ));
    eprintln!(
        "SIGNED-OPS FN-DSA backend on {}: {}",
        std::env::consts::ARCH,
        if native { "native f64 (fn-dsa 0.4.0 flr_native)" } else { "integer-emulated IEEE-754 (flr_emu)" }
    );
    let (signer, signed) = sign_fixed_frames(3);
    for SignedFrame { op, frame, sig } in &signed {
        assert_eq!(verify(3, signer.public_key(), frame, sig), Ok(()), "{op}");
        assert_eq!(sig.len(), 730, "{op}");
    }
}
