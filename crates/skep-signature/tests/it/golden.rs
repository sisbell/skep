//! THE GOLDENS (the frozen-tag rule's pin), beside the one implementation
//! they pin: per tag, one seed through the KDF to both public keys and the
//! fingerprint; a signature over each fixed entry frame (`frames.rs`), under
//! its name — the ten publish-class kinds and the `record` grammar at three
//! kinds; tag 1's signatures byte-stable (FIPS 204's deterministic variant),
//! tag 3's under the fixtures' seeded stream; the preimage of every fixed
//! frame and of the shapes of a cell they leave out; the hybrid cross-check;
//! the widths each pinned crate fixes, pinned by hand beside the sizes and
//! timings the report takes back; and which FN-DSA backend signed them on
//! this target.

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};
use skep_identity::{
    entry_body_insert, entry_body_make_link, entry_body_make_link_replacing, entry_body_publish,
    entry_frame, unit_span, BoardTerm, DocTerm, EntrySlot, Fingerprint, LinkSlots,
    ShotSegmentPiece, SigAlgRow, ALG_MLDSA65_ED25519,
};
use skep_signature::{pq_widths, verify, HybridFault, HybridSigner, PqWidths, SeededRng06};

use crate::frames::{addr, extent, fixed_frames};

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// The golden's seed: one 32-byte seed, the paper backup's one 64-hex line —
/// and the seed of the keygen-from-seed rule's vectors `docs/wire.md`
/// publishes, so the fingerprints below are the ones a client author checks
/// against.
pub const GOLDEN_SEED: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

/// The seed of the fixtures' stream the tag-3 golden signatures draw their
/// per-signature seeds from — `GOLDEN_SEED`'s bytes reused, so those
/// thirteen pins depend on the key seed twice: through the key and through
/// the stream.
const GOLDEN_STREAM_SEED: [u8; 32] = GOLDEN_SEED;

/// One tag's golden, in the documented form: the SHA-256 of the PQ public
/// half, of the Ed25519 public half, of the whole raw key; the fingerprint;
/// and per fixed frame (`frames.rs`), in `fixed_frames`' order, the SHA-256
/// of the signature blob over it.
///
/// WHAT MAY MOVE A PIN — the frozen-tag rule, as a failing golden reads it.
/// The pins on the key are what the seed derives under the tag — through the
/// KDF, the keygen and THE KEY PIN's half order — and the fingerprint of
/// that key `docs/wire.md` publishes (`wire_doc.rs`). None is ever
/// re-pinned: a moved key is a changed rule, which ships as a NEW tag, and a
/// moved fingerprint renames every key a board has enrolled. A SIGNATURE pin
/// is a function of the key, its fixed frame and, under tag 3, the fixtures'
/// stream (`GOLDEN_STREAM_SEED`), and is re-pinned only in the change that
/// moves one of those: a frame that changes — skep-identity's entry frame,
/// changed in place under `skep-entry-v1` (l6-A3), or a fixed instance in
/// `frames.rs` — moves that frame's own preimage pin, the row under the same
/// name in `the_frame_preimage_per_op_cell_is_pinned`, in the same change,
/// and a change to `SeededRng06` moves every tag-3 signature at once. A
/// signature that moves while its frame's preimage pin and, under tag 3, the
/// stream stand is a change to what the tag signs or verifies: a NEW tag,
/// never a re-pin. Made to the signer and the verifier alike, such a change
/// passes every round trip in this crate, and for tag 3's post-quantum half
/// and both tags' Ed25519 half these pins alone see it. Which pins have
/// moved, and under which ruling, is this file's history.
struct TagGolden {
    tag: u8,
    pq_pk: &'static str,
    ed_pk: &'static str,
    raw_key: &'static str,
    fingerprint: &'static str,
    sigs: [&'static str; 13],
}

/// One fixed frame, signed: the name `fixed_frames` gives it, the frame's
/// bytes and the signature blob over them — named, not a triple, as
/// `PqWidths` is: the frame and the blob are both `Vec<u8>`, and a position
/// would let them trade places.
struct SignedFrame {
    name: &'static str,
    frame: Vec<u8>,
    sig: Vec<u8>,
}

fn sign_fixed_frames(tag: u8) -> (HybridSigner, Vec<SignedFrame>) {
    let signer = HybridSigner::from_seed(tag, &GOLDEN_SEED).unwrap();
    let alg = SigAlgRow::of_tag(tag).unwrap().token;
    let mut out = Vec::new();
    for (name, frame) in fixed_frames(alg) {
        // Tag 3's signature draws its per-signature seed from the fixtures'
        // stream, reseeded per frame from `GOLDEN_STREAM_SEED` so each
        // signature is a function of its frame alone.
        let mut rng = SeededRng06::new(GOLDEN_STREAM_SEED);
        let sig = signer.sign_with_rng(&mut rng, &frame);
        assert_eq!(
            verify(tag, signer.public_key(), &frame, &sig),
            Ok(()),
            "tag {tag}: the blob over `{name}` verifies"
        );
        out.push(SignedFrame { name, frame, sig });
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
    assert_eq!(
        raw, g.raw_key,
        "the raw key moved with both halves standing — the KEY PIN's order is frozen: a NEW \
         tag\n{report}"
    );
    assert_eq!(
        fp, g.fingerprint,
        "the fingerprint moved with the key standing — that renames every enrolled key and moves \
         wire.md's published vectors: never a re-pin here\n{report}"
    );
    for (i, SignedFrame { name, .. }) in signed.iter().enumerate() {
        assert_eq!(
            sigs[i], g.sigs[i],
            "the signature over `{name}` moved under tag {} — re-pinned only beside a moved \
             preimage pin under the same name in `the_frame_preimage_per_op_cell_is_pinned` (or, \
             under tag 3, a changed fixture stream); otherwise the rule moved: a NEW tag \
             (`TagGolden`)\n{report}",
            g.tag
        );
    }
}

/// TAG 1's GOLDEN: the KEY-DERIVATION golden (seed → KDF → both public
/// keys → fingerprint) and the thirteen fixed frames' signatures,
/// byte-stable under FIPS 204's deterministic variant and Ed25519's own
/// determinism.
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
            "66f4f573eaf53426b5a3d4d360a06d98df61ca6d0578fa5fe5aadc92c9c32bb0",
            "b433f7cd372e1bd8073f1b3222eba5b06976ee47734b66e761a3493d2c0deac0",
            "28c70f669d44919062bf99a79cec75a973c7f6acaf315991a53daea054b7f508",
            "abb554df48572fb1fbfa72445b1ef8024dd6fd2c8889ed33cc1a756d5a9a07c3",
            "4c367931a56e731f01c0f5dc19d4d79d7be5b459c3cc113cbf946fe54cf90472",
            "cf8c0a4ffd3e6a77b7eda2443c2cad4ccf998f255c119d6eb507d20d68073c60",
            "002fbd1c5cd08cd8726f163db8810e647246b4ab04ea2236fe773c89f3f90024",
            "69438cf67ea4ae427185e7b6cdf153935df95c277ff075441716aa145cd40836",
            "87993cf5652f6cb0c71de67152615f67b66300534b7d0f8282bf119c48959c02",
            "4979c2918ea65effe9786f37f0c17507542552fa3f77905d872bd3b0c11ddeb4",
            "bb1e5dd0f0d3eb078fefc15c45742dadf0799e7fe299db0d2ceac3ea8059d972",
            "d2257f46aa5bc456f5012509ad36a5a8fe59c6fdac7cd6f8b1649653c2b95c13",
        ],
    });
}

/// TAG 3's GOLDEN (the PREVIEW): the KEY-DERIVATION golden — `fn-dsa`
/// 0.4.0's keygen from the KDF's PQ half seed IS the tag's frozen keygen
/// rule — and the thirteen signatures under the fixtures' seeded stream
/// (FN-DSA signing is randomized by the draft's own rule; what the tag
/// freezes is the key, the frame and the verify, and that stream makes the
/// bytes reproducible here).
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
            "be84ffa9151b386e184f89530add29898fb70808537dc8b2bd044c290a1173cb",
            "5df7ecb18a4809f0f6dad4a3db1cecfe946724d66024e66ff78d4fb92c5046a6",
            "38b456b9f4413a0f6164aad2e0cc3e9e8b35b8534c915f465992391cf71b03ad",
            "7399b23baaae2e1a1bdc85eb74bfc6b88f76029bf3e17857635c86b9e106eab1",
            "7807cbba98e2e04fa7647c50baeacdaefb44fbf477fd9ee3f71095f47d1fe37d",
            "8aa28f13cdcf1d3d7eae7333123a111cd099a56752edad5ce1e90a0d82cd581d",
            "8cc3a677839554c92ef680e8e890f4005b86e9bb02db6693a6566da55d376f85",
            "e8b3180c3e5e756e8c92b43c8f26a079f9c2427d207d03cbe3c6d2311deea456",
            "c20031b32997b4a332d318caebd02844e31f9c2779d1e5bc091bbf31f6cbd711",
            "8dbf24acd9767066804d04d1bc1c4d7b5e7e5cbce18bb36ce3d44b4c4ee5af01",
            "cff4019b429c51d254eebfb0e416a275c53ac839789585d2409014fcdc025b28",
            "68bd991afd3b4f9283f12027cf51f914f437f3952aba3afbdd7be974b07c5cc0",
        ],
    });
}

/// THE PREIMAGE GOLDEN (SO-I1, SO-I6): the PREIMAGE of every FIXED frame, and
/// of each shape of an op cell of the entry frame those frames leave out,
/// pinned as its bytes' SHA-256 hex under tag 1's `alg` token (preimages and
/// not signatures, since tag 3's signing is randomized), byte-asserted, so a
/// member silently absent from a body — the base member of a `publish`, for
/// one — fails the build here, whatever the signatures over it do. The
/// thirteen fixed frames (`frames.rs`) cover `insert` (undeclared),
/// `make_link` WITHOUT its `replaces` row over unit spans and the EMPTY `to`,
/// `publish` with a value stretch, a window and the base group FILLED, the
/// three `record`s (rows 3 and 4 EMPTY), the three EMPTY bodies over the
/// parent account, the three other link writes over the stored link and the
/// `edit_link` with its pair's row and resolved extents; this table adds the
/// shapes they leave out — an `insert` DECLARED under a type, a `make_link`
/// WITH its `replaces` row, a `make_link` whose `to` is a RESOLVED content
/// extent (the slot a V-spec stores as, §7.6's vector (vii)), the `publish`
/// BIRTH SHAPE with the EMPTY group — and pins the thirteen beside them under
/// their own names, so one table names every cell, at each shape it is pinned
/// at, with its preimage's length, and no two shapes share a name: a name
/// picks out one row. The frames are the twins skepd pins byte for byte
/// (`the_entry_frames_bytes_per_op_are_pinned`); the pin here is the hash a
/// second implementation checks against. It moves only with the frame —
/// skep-identity's entry frame, changed in place under `skep-entry-v1`
/// (l6-A3), or a fixed instance in `frames.rs` — re-pinned here beside
/// skepd's byte pin, and each fixed frame's row is the witness the signature
/// goldens' re-pin rule reads for the signature under the same name
/// (`TagGolden`).
#[test]
fn the_frame_preimage_per_op_cell_is_pinned() {
    let alg = ALG_MLDSA65_ED25519;
    let (account, doc) = (addr("1.0.1"), addr("1.0.1.0.1"));
    let board = BoardTerm { log_position: 12, chain: [0xAB; 32] };
    let frame = |body: &skep_identity::EntryBody| entry_frame(alg, board, &account, DocTerm::One(&doc), body);
    let declared = entry_body_insert(Some(&addr("1.1.0.1.0.1.0.3.1")), [&b"r"[..]]);
    let (ty, from) = ([unit_span(&addr("1.1.0.1.0.1.0.3.90"))], [unit_span(&addr("1.0.1"))]);
    let replacing = entry_body_make_link_replacing(
        LinkSlots { from: EntrySlot(&from), to: EntrySlot(&[]), ty: EntrySlot(&ty) },
        &addr("1.0.1.0.1.0.2.9"),
    );
    let resolved_to = [extent("1.0.1.0.2.0.1.1", 5)];
    let resolved = entry_body_make_link(LinkSlots {
        from: EntrySlot(&from),
        to: EntrySlot(&resolved_to),
        ty: EntrySlot(&ty),
    });
    let window = addr("1.0.1.0.2.0.1.1");
    let birth = entry_body_publish(
        [
            ShotSegmentPiece::Value(b"x"),
            ShotSegmentPiece::Window {
                start: &window,
                width: std::num::NonZeroU64::new(2).expect("2 is not zero"),
            },
        ],
        None,
    );
    let [insert, link, publish, enrol, retire, claim, create, fork, version, nullify, assert_sup, emit, edit] =
        fixed_frames(alg);
    // The thirteen come under `fixed_frames`' own names, the names the
    // signature goldens report them by; the shapes they leave out are named
    // here.
    let named = |(name, bytes): (&'static str, Vec<u8>), len: usize, hash: &'static str| {
        (name, bytes, len, hash)
    };
    let shapes: [(&str, Vec<u8>, usize, &str); 17] = [
        named(insert, 134, "d84853b3c36c8bf452ec57e662c57911eae550193a6c9cf6e8c468ecf118efe2"),
        ("insert, declared", frame(&declared), 146, "199775c4e92c52b6b49b7fb702de449690f2b6be837b5f72d07cb640176aed26"),
        named(link, 207, "c31ac3319996a82e6900d2571724d5b8ae69616fd2c3f785535bb09f63e880f5"),
        ("make_link, replacing", frame(&replacing), 235, "c18ce6f345cde5d15dcd2883d6be46b693fdaf87e0059dab6bdd1ecd1c093da3"),
        ("make_link, a resolved to", frame(&resolved), 245, "daea951d32f82858d99ea5e0500feceec7ae5d926d2ee5375f7392b48a95cd7b"),
        named(publish, 209, "774ae1d5bd454d7eb59ae7f3f3027a2f7cbc927c855036a9cbdda2b0664a6945"),
        ("publish, the birth shape", frame(&birth), 167, "34e6abd5f4dc9dac148a29b6dcddf040918730e45bd510d91cff262308e88e6f"),
        named(enrol, 194, "e15f5fce4fd268e3064237c413eb6d7fb25f67269c6d7f0b046b26c72a9dfc60"),
        named(retire, 194, "e60761e01fbd6785680b07833fd9618de55150aacefaee1d3e1ebf75ae42918a"),
        named(claim, 163, "e5f5b1a5b96c2f7ce52cf32c8ef6f59a8ea56e882f7e5181456feb511b74b15f"),
        named(create, 121, "a7c1b8b81d99252b51dcd44f342ab306f5db48a0226f43d41b5352b136c15fd5"),
        named(fork, 106, "a1225f6e56bf757f138ebb8471b417dbce494effff30f959840b99bfcf77eed2"),
        named(version, 109, "6f593040109dc5cf8932bb1c7d690fb053339fdba2ac196aee60ae74e833f1f6"),
        named(nullify, 250, "662660f94fedf12edec1f1a6aac041f953344dc3c4214b3021c3cee880662d1b"),
        named(assert_sup, 265, "9fd23e8ac0bb18347353b830fbc5bbbd0f68a268bd45451651c18d854aff54cc"),
        named(emit, 209, "e7b6e747a67f7d0f3545ae31f096c82df586c07e51c9d3537482bd8e22288d10"),
        named(edit, 333, "86c04744e99ffe3317c82e6283afa645e4601e177474fbf5f2eb61c80a39e09c"),
    ];
    let names: BTreeSet<&str> = shapes.iter().map(|(shape, ..)| *shape).collect();
    assert_eq!(
        names.len(),
        shapes.len(),
        "each shape under a name of its own, the name `TagGolden`'s re-pin rule reads: {names:?}"
    );
    let got: Vec<(&str, usize, String)> =
        shapes.iter().map(|(shape, bytes, ..)| (*shape, bytes.len(), sha_hex(bytes))).collect();
    let want: Vec<(&str, usize, String)> =
        shapes.iter().map(|(shape, _, len, want)| (*shape, *len, want.to_string())).collect();
    let report = got
        .iter()
        .map(|(shape, len, hash)| format!("  {shape}: {len} bytes, sha256 {hash}"))
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(got, want, "a preimage moved — the shapes as composed:\n{report}");
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
/// with no feature to force the emulation. The tag-3 signature pins are the
/// native backend's output; that the emulated one reproduces them — as
/// `fn-dsa` means it to, bit for bit — is checked only where this suite runs
/// on a target outside the four. This test prints which backend signs here,
/// and checks that it signs and verifies.
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
    for SignedFrame { name, frame, sig } in &signed {
        assert_eq!(verify(3, signer.public_key(), frame, sig), Ok(()), "{name}");
        assert_eq!(sig.len(), 730, "{name}");
    }
}
