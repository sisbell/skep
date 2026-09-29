//! THE GOLDENS (the frozen-tag rule's pin), beside the one implementation
//! they pin: per tag, one seed through the KDF to both public keys and the
//! fingerprint; the three ops' signatures over fixed entry frames; tag 1's
//! signatures byte-stable (FIPS 204's deterministic variant), tag 3's under
//! the fixtures' seeded RNG; the hybrid cross-check; and tag 1 DIFFERENTIAL
//! against a second pure-Rust FIPS 204 crate — keys-from-seed and signatures
//! byte-equal.

use sha2::{Digest, Sha256};
use skep_identity::{
    entry_body_insert, entry_body_make_link, entry_body_publish, entry_frame, BoardTerm, EntrySlot,
    Fingerprint, LinkSlots, SigAlgRow, ALG_MLDSA65_ED25519,
};
use skep_signature::{derive_seeds, pq_widths, verify, HybridSigner, PqWidths, SeededRng06};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
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

/// The three fixed instances every golden signs: the frames of an
/// `insert` (undeclared, two values), a `make_link` (three address-form
/// slots) and a `publish` (three values) on a board whose `H.1` pair is
/// `(12, 0xAB…)`, by account `1.0.1`.
fn fixed_frames(alg: &str) -> [(&'static str, Vec<u8>); 3] {
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
    let publish = entry_body_publish([&b"x"[..], &b"y"[..], &b"z"[..]]);
    let board = BoardTerm { log_position: 12, chain: [0xAB; 32] };
    [insert, link, publish].map(|body| (body.op(), entry_frame(alg, board, &account, &doc, &body)))
}

// ── the goldens ─────────────────────────────────────────────────────────────

/// The golden's seed: one 32-byte seed, the paper backup's one 64-hex line.
const GOLDEN_SEED: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

/// One tag's golden, in the documented form: the SHA-256 of the PQ public
/// half, of the Ed25519 public half, of the whole raw key; the fingerprint;
/// and per op the SHA-256 of the signature blob — the frames themselves
/// pinned byte for byte by skepd's `the_entry_frames_bytes_per_op_are_pinned`.
struct TagGolden {
    tag: u8,
    pq_pk: &'static str,
    ed_pk: &'static str,
    raw_key: &'static str,
    fingerprint: &'static str,
    sigs: [&'static str; 3],
}

/// Per op: its name, its frame's bytes, its signature blob.
type SignedFrames = Vec<(String, Vec<u8>, Vec<u8>)>;

fn golden_of(tag: u8) -> (HybridSigner, SignedFrames) {
    let signer = HybridSigner::from_seed(tag, &GOLDEN_SEED).unwrap();
    let alg = SigAlgRow::of_tag(tag).unwrap().token;
    let mut out = Vec::new();
    for (op, frame) in fixed_frames(alg) {
        // Tag 3's signature draws its seed from the fixtures' seeded RNG,
        // reseeded per op so each signature is a function of its frame alone.
        let mut rng = SeededRng06::new(GOLDEN_SEED);
        let sig = signer.sign_with_rng(&frame, &mut rng);
        assert_eq!(verify(tag, signer.public_key(), &frame, &sig), Ok(()));
        out.push((op.to_string(), frame, sig));
    }
    (signer, out)
}

fn check_golden(g: &TagGolden) {
    let (signer, signed) = golden_of(g.tag);
    let key = signer.public_key();
    let pq = sha_hex(key.pq_half());
    let ed = sha_hex(key.ed25519_half());
    let raw = sha_hex(key.raw());
    let fp = Fingerprint::of(key).to_hex();
    let sigs: Vec<String> = signed.iter().map(|(_, _, sig)| sha_hex(sig)).collect();
    let report = format!(
        "tag {}: pq_pk {pq}\n ed_pk {ed}\n raw_key {raw}\n fingerprint {fp}\n sigs {} {} {}",
        g.tag, sigs[0], sigs[1], sigs[2]
    );
    assert_eq!(pq, g.pq_pk, "the PQ public half moved — a keygen change is a NEW tag\n{report}");
    assert_eq!(ed, g.ed_pk, "the Ed25519 half moved — the KDF is a frozen pin\n{report}");
    assert_eq!(raw, g.raw_key, "{report}");
    assert_eq!(fp, g.fingerprint, "{report}");
    for (i, (op, _, _)) in signed.iter().enumerate() {
        assert_eq!(sigs[i], g.sigs[i], "the {op} signature moved under tag {}\n{report}", g.tag);
    }
}

/// TAG 1's GOLDEN: the KEY-DERIVATION golden (seed → KDF → both public
/// keys → fingerprint) and the three ops' signatures, byte-stable under
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
            "7fd029f5cad3498cd5321332c6d0dba23e326d5603781ee19ec00f2c70d3f940",
            "50d83bfcc18792e51073852113df636c4d6f3aa86391f7fd970b5738b5737879",
        ],
    });
}

/// TAG 3's GOLDEN (the PREVIEW): the KEY-DERIVATION golden — `fn-dsa`
/// 0.4.0's keygen from the KDF's seed IS the tag's frozen keygen rule — and
/// the three signatures under the fixtures' seeded RNG (FN-DSA signing is
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
            "20c93bb2e587c2139fd47bfe48fb4738e9f761862d66908c4e26d2f237d292e7",
            "4a5bc2ebd6345adf18bbe073e21f5d02815d4ca5625d1ba2751461e6a1fe9c64",
        ],
    });
}

/// THE HYBRID CROSS-CHECK at the frame: each half alone fails — a valid PQ
/// half with a foreign Ed25519 half, and the reverse — under both tags.
#[test]
fn each_half_alone_fails_under_both_tags() {
    for tag in [1u8, 3] {
        let (signer, signed) = golden_of(tag);
        let row = SigAlgRow::of_tag(tag).unwrap();
        let other = HybridSigner::from_seed(tag, &[0x99; 32]).unwrap();
        let (_, frame, sig) = &signed[0];
        let mut rng = SeededRng06::new([1; 32]);
        let foreign = other.sign_with_rng(frame, &mut rng);
        // The PQ half ours, the Ed25519 half theirs.
        let mut mixed = sig[..row.pq_sig_len].to_vec();
        mixed.extend_from_slice(&foreign[row.pq_sig_len..]);
        assert!(verify(tag, signer.public_key(), frame, &mixed).is_err(), "tag {tag}: ed half");
        // The Ed25519 half ours, the PQ half theirs.
        let mut mixed = foreign[..row.pq_sig_len].to_vec();
        mixed.extend_from_slice(&sig[row.pq_sig_len..]);
        assert!(verify(tag, signer.public_key(), frame, &mixed).is_err(), "tag {tag}: pq half");
        assert_eq!(verify(tag, signer.public_key(), frame, sig), Ok(()));
    }
}

/// THE DIFFERENTIAL TEST for tag 1 (the PQ investigation §8.4 (4), §8.5
/// (ii)): `ml-dsa` 0.1.1's keys from ξ and its deterministic signatures are
/// byte-equal to `fips204` 0.4.6's, a second pure-Rust FIPS 204, over
/// sixteen seeds and the three fixed frames — the gate every future bump of
/// the pinned crate must pass, since FIPS 204 fixes `KeyGen_internal(ξ)`
/// and the deterministic variant.
#[test]
fn tag_1_is_byte_equal_to_a_second_fips_204_implementation() {
    use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
    for i in 0..16u8 {
        let seed = [i; 32];
        let halves = derive_seeds(1, &seed).unwrap();
        // `ml-dsa`'s side: the PQ half of the hybrid key and its signature.
        let ours = HybridSigner::from_seed(1, &seed).unwrap();
        let our_pk = ours.public_key().pq_half().to_vec();
        // `fips204`'s side, from the same ξ.
        let (their_pk, their_sk) = fips204::ml_dsa_65::KG::keygen_from_seed(&halves.pq);
        assert_eq!(our_pk, their_pk.clone().into_bytes().to_vec(), "seed {i}: the public key");
        for (op, frame) in fixed_frames(ALG_MLDSA65_ED25519) {
            let our_sig = ours.sign(&frame);
            let our_pq = &our_sig[..3309];
            let their_sig = their_sk.try_sign_with_seed(&[0u8; 32], &frame, &[]).unwrap();
            assert_eq!(our_pq, &their_sig[..], "seed {i}, {op}: the deterministic signature");
            assert!(their_pk.verify(&frame, &their_sig, &[]), "their verify of their own");
            let as_theirs: [u8; 3309] = our_pq.try_into().unwrap();
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
        let (signer, signed) = golden_of(tag);
        let key_len = signer.public_key().raw().len();
        let sig_len = signed[0].2.len();
        assert_eq!(key_len, row.key_len());
        assert_eq!(sig_len, row.sig_len());
        let PqWidths { key: pq_key, sig: pq_sig, signing_key: pq_sk } =
            pq_widths(tag).unwrap();
        let frame = &signed[0].1;
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
            assert_eq!(verify(tag, s.public_key(), frame, &sig), Ok(()));
            verify_us.push(t.elapsed().as_micros());
        }
        let median = |v: &mut Vec<u128>| {
            v.sort();
            v[v.len() / 2]
        };
        eprintln!(
            "SIGNED-OPS SIZES tag {tag} ({}): public key {key_len} B (pq {pq_key} + ed 32), \
             signature {sig_len} B (pq {pq_sig} + ed 64), filled marker payload {} B \
             (97 + {sig_len}), pq signing key {pq_sk} B; medians over {n}: keygen {} µs, \
             sign {} µs, verify {} µs",
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
    let (signer, signed) = golden_of(3);
    for (op, frame, sig) in &signed {
        assert_eq!(verify(3, signer.public_key(), frame, sig), Ok(()), "{op}");
        assert_eq!(sig.len(), 730);
    }
}
