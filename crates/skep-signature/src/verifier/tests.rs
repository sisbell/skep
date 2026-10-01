use super::*;
use crate::hooks::SeededRng06;
use crate::signer::HybridSigner;
use crate::{TAG_FNDSA512_PREVIEW_ED25519, TAG_MLDSA65_ED25519};

/// The first encoding `[y, 0, …, 0]` that decompresses to no point: an
/// Ed25519 half whose key [`key_decodes`] refuses, under either row.
fn no_point() -> [u8; 32] {
    (0..=u8::MAX)
        .map(|y| {
            let mut half = [0u8; 32];
            half[0] = y;
            half
        })
        .find(|half| EdVerifyingKey::from_bytes(half).is_err())
        .expect("about half of all encodings name no point")
}

/// The eight low-order points of edwards25519, each by its one canonical
/// encoding: the identity, the point of order 2, the two of order 4, the
/// four of order 8 (libsodium's small-order blocklist).
const LOW_ORDER: [&str; 8] = [
    "0100000000000000000000000000000000000000000000000000000000000000",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000080",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
];

/// 32 bytes from 64 hex digits.
fn bytes32(hex: &str) -> [u8; 32] {
    assert_eq!(hex.len(), 64, "64 hex digits: {hex}");
    std::array::from_fn(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("hex digits"))
}

/// The post-quantum half's decode, alone: a derived key of either tag
/// decodes; a tag-3 key whose FN-DSA header byte is any of the 255 but
/// `0x09` does not (the fault the precheck's `undecodable_key` names on that
/// half); a tag-1 key of the right length always does (ML-DSA's encoding
/// admits every byte string of its length), which is why the Ed25519 half is
/// what carries that row's decode fault. And the courtesy, [`key_decodes`],
/// answers exactly as the two decodes [`verify`] runs.
#[test]
fn the_pq_half_decode_refuses_every_fn_dsa_header_byte_but_0x09() {
    let seed = [0x42u8; 32];
    for tag in [TAG_MLDSA65_ED25519, TAG_FNDSA512_PREVIEW_ED25519] {
        let s = HybridSigner::from_seed(tag, &seed).unwrap();
        assert!(
            PqVerifier::decode(s.public_key()).is_some(),
            "tag {tag}: a derived key decodes"
        );
    }
    let s3 = HybridSigner::from_seed(TAG_FNDSA512_PREVIEW_ED25519, &seed).unwrap();
    let mut pq = s3.public_key().pq_half().to_vec();
    assert_eq!(pq[0], 0x09, "fn-dsa 0.4.0's degree-512 header byte");
    pq[0] = 0x0a;
    let bad = PublicKey::from_halves(s3.public_key().alg(), &pq, s3.public_key().ed25519_half())
        .expect("the row's widths");
    assert!(PqVerifier::decode(&bad).is_none(), "a bad header byte does not decode");
    // Every header byte: `0x09` alone decodes, and the courtesy agrees.
    for header in 0..=u8::MAX {
        let mut with = s3.public_key().pq_half().to_vec();
        with[0] = header;
        let key =
            PublicKey::from_halves(s3.public_key().alg(), &with, s3.public_key().ed25519_half())
                .expect("the row's widths");
        assert_eq!(PqVerifier::decode(&key).is_some(), header == 0x09, "header {header:#04x}");
        assert_eq!(key_decodes(&key), header == 0x09, "the courtesy, header {header:#04x}");
    }
    let s1 = HybridSigner::from_seed(TAG_MLDSA65_ED25519, &seed).unwrap();
    let mut pq = s1.public_key().pq_half().to_vec();
    pq[0] ^= 0xff;
    let still = PublicKey::from_halves(s1.public_key().alg(), &pq, s1.public_key().ed25519_half())
        .expect("the row's widths");
    assert!(PqVerifier::decode(&still).is_some(), "ML-DSA-65's encoding decodes at its length");
    assert!(!key_decodes(&bad) && key_decodes(&still), "the courtesy reads the same two decodes");
}

/// THE FN-DSA HALF'S COEFFICIENTS, AT q: `fn-dsa` 0.4.0 packs the key's 512
/// coefficients 14 bits each, four to every seven bytes after the header
/// byte, little-endian, and decodes one only below q = 12,289. A derived key
/// with its first or last coefficient set to 12,288 still decodes; set to
/// 12,289 it does not, and the courtesy refuses it with the decode.
#[test]
fn the_pq_half_decode_refuses_an_fn_dsa_coefficient_of_q() {
    fn with_coefficient(pq: &[u8], i: usize, value: u16) -> Vec<u8> {
        let mut pq = pq.to_vec();
        let at = 1 + 7 * (i / 4);
        let shift = 14 * (i % 4);
        let mut word = [0u8; 8];
        word[..7].copy_from_slice(&pq[at..at + 7]);
        let x = (u64::from_le_bytes(word) & !(0x3fff_u64 << shift)) | (u64::from(value) << shift);
        pq[at..at + 7].copy_from_slice(&x.to_le_bytes()[..7]);
        pq
    }
    let s3 = HybridSigner::from_seed(TAG_FNDSA512_PREVIEW_ED25519, &[0x42; 32]).unwrap();
    let key = s3.public_key();
    for i in [0, 511] {
        for (value, decodes) in [(12_288, true), (12_289, false)] {
            let pq = with_coefficient(key.pq_half(), i, value);
            let k = PublicKey::from_halves(key.alg(), &pq, key.ed25519_half())
                .expect("the row's widths");
            assert_eq!(PqVerifier::decode(&k).is_some(), decodes, "coefficient {i} at {value}");
            assert_eq!(key_decodes(&k), decodes, "the courtesy, coefficient {i} at {value}");
        }
    }
}

/// A KEY THAT DOES NOT DECODE ANSWERS `Signature`, whichever half fails
/// first: a tag-3 key whose FN-DSA header byte is not `0x09`, handed a
/// blob its own signer made over `msg`, answers `Signature` over `msg` —
/// its Ed25519 half passes, then its post-quantum half does not decode —
/// and over another message, where the Ed25519 half fails first. The
/// order `verify` checks the halves in moves no verdict, the variant
/// included; `WrongRow` is the row's answer alone. That such a half is
/// the KEY's fault and never its row's is the crate's tag sweep's to
/// show: every `SIG_ALGS` row has a rule here.
#[test]
fn a_key_that_does_not_decode_answers_signature_whichever_half_fails_first() {
    let seed = [0x42u8; 32];
    let s3 = HybridSigner::from_seed(TAG_FNDSA512_PREVIEW_ED25519, &seed).unwrap();
    let msg = b"the entry frame";
    let sig = s3.sign_with_rng(&mut SeededRng06::new([7; 32]), msg);
    let mut pq = s3.public_key().pq_half().to_vec();
    pq[0] = 0x0a;
    let bad = PublicKey::from_halves(s3.public_key().alg(), &pq, s3.public_key().ed25519_half())
        .expect("the row's widths");
    assert!(
        decode_ed25519_half(&bad).is_some() && PqVerifier::decode(&bad).is_none(),
        "the premise: its Ed25519 half decodes and its post-quantum half does not"
    );
    for signed in [&msg[..], &b"other"[..]] {
        assert_eq!(
            verify(TAG_FNDSA512_PREVIEW_ED25519, &bad, signed, &sig),
            Err(HybridFault::Signature),
            "over {:?}",
            String::from_utf8_lossy(signed)
        );
    }
}

/// THE COURTESY'S PROMISE ON THE OTHER HALF: a key of either tag whose
/// Ed25519 half is no curve point — the one decode fault a tag-1 key can
/// carry — answers `false` from [`key_decodes`], and [`verify`] answers
/// `Signature` past the row and the width, over a blob its own signer
/// made.
#[test]
fn a_key_whose_ed25519_half_is_no_point_decodes_and_verifies_nothing() {
    let seed = [0x42u8; 32];
    let msg = b"the entry frame";
    let no_point = no_point();
    for tag in [TAG_MLDSA65_ED25519, TAG_FNDSA512_PREVIEW_ED25519] {
        let s = HybridSigner::from_seed(tag, &seed).unwrap();
        let sig = s.sign_with_rng(&mut SeededRng06::new([7; 32]), msg);
        let key = s.public_key();
        let bad =
            PublicKey::from_halves(key.alg(), key.pq_half(), &no_point).expect("the row's widths");
        assert!(PqVerifier::decode(&bad).is_some(), "tag {tag}: the premise, its PQ half decodes");
        assert!(!key_decodes(&bad), "tag {tag}: the courtesy refuses it");
        assert_eq!(verify(tag, &bad, msg, &sig), Err(HybridFault::Signature), "tag {tag}");
    }
}

/// THE COURTESY'S `false`, BEHIND THE ROW AND THE WIDTH: against a key
/// [`key_decodes`] refuses — either tag's with its Ed25519 half no point, and
/// a tag-3 key with its FN-DSA header byte broken — [`verify`] answers, under
/// every tag and over each blob of a family (the source signer's own, the
/// other row's, one byte short, one byte long, the Ed25519 field alone, one
/// byte shorter than that, empty), what it answers against the key it was
/// broken from, save that a pass becomes `Signature`: the row, then the
/// width, are judged before either half is decoded.
#[test]
fn an_undecodable_key_answers_as_its_source_key_save_that_nothing_passes() {
    let msg = b"the entry frame";
    let signers: Vec<HybridSigner> = [TAG_MLDSA65_ED25519, TAG_FNDSA512_PREVIEW_ED25519]
        .into_iter()
        .map(|tag| HybridSigner::from_seed(tag, &[0x42; 32]).unwrap())
        .collect();
    let blobs: Vec<Vec<u8>> =
        signers.iter().map(|s| s.sign_with_rng(&mut SeededRng06::new([7; 32]), msg)).collect();
    for (i, s) in signers.iter().enumerate() {
        let key = s.public_key();
        let own = &blobs[i];
        let mut broken = vec![PublicKey::from_halves(key.alg(), key.pq_half(), &no_point())
            .expect("the row's widths")];
        if s.tag() == TAG_FNDSA512_PREVIEW_ED25519 {
            let mut pq = key.pq_half().to_vec();
            pq[0] = 0x0a;
            broken.push(
                PublicKey::from_halves(key.alg(), &pq, key.ed25519_half())
                    .expect("the row's widths"),
            );
        }
        let long = [&own[..], &[0u8]].concat();
        let family: [&[u8]; 7] = [
            &own[..],
            &blobs[1 - i][..],
            &own[1..],
            &long[..],
            &own[own.len() - 64..],
            &own[..63],
            &[],
        ];
        for bad in &broken {
            assert!(!key_decodes(bad), "the premise: the courtesy refuses it");
            for tag in 0..=u8::MAX {
                for blob in family {
                    let expected = match verify(tag, key, msg, blob) {
                        Ok(()) => Err(HybridFault::Signature),
                        refused => refused,
                    };
                    assert_eq!(
                        verify(tag, bad, msg, blob),
                        expected,
                        "tag {tag} against a broken tag-{} key, a {}-byte blob",
                        s.tag(),
                        blob.len()
                    );
                }
            }
        }
    }
}

/// EACH HALF ANSWERS ON ITS OWN CARD: `PqVerifier::verify` judges the
/// blob's post-quantum field alone — it passes that field over the signed
/// message, with the Ed25519 field broken beside it, and refuses it over
/// another — while [`verify`] refuses the same blob, so "both halves
/// verify" is the hybrid's conjunction and no half vouches for the other.
#[test]
fn the_pq_half_verifies_its_own_field_and_the_hybrid_needs_both() {
    let seed = [0x42u8; 32];
    let msg = b"the entry frame";
    for tag in [TAG_MLDSA65_ED25519, TAG_FNDSA512_PREVIEW_ED25519] {
        let s = HybridSigner::from_seed(tag, &seed).unwrap();
        let half = PqVerifier::decode(s.public_key()).expect("a derived key decodes");
        let mut sig = s.sign_with_rng(&mut SeededRng06::new([7; 32]), msg);
        let pq_len = s.public_key().sig_alg_row().pq_sig_len;
        sig[pq_len] ^= 1;
        let (pq_sig, _) = sig.split_at(pq_len);
        assert!(half.verify(msg, pq_sig), "tag {tag}: its own field");
        assert!(!half.verify(b"other", pq_sig), "tag {tag}: another message");
        assert_eq!(
            verify(tag, s.public_key(), msg, &sig),
            Err(HybridFault::Signature),
            "tag {tag}: the hybrid refuses a broken Ed25519 field"
        );
    }
}

/// THE FROZEN RULE'S REFUSING EDGE, WHERE A DECODER DECIDES: one genuine
/// post-quantum field per tag, the low bit of one byte flipped at a time —
/// each byte of ML-DSA-65's hint (its last ω + k = 55 + 6 bytes, which FIPS
/// 204's HintBitUnpack admits in one encoding only) and of the FN-DSA-512
/// preview's header and compressed `s2` with its zero padding (byte 0, and
/// every byte past the 40-byte nonce) — and `PqVerifier::verify` refuses each
/// one. Each field carries bytes its decoder must read as zero — the hint's
/// unused index slots, the padding after `s2` — so a bump of a pinned crate
/// that stopped checking them fails here rather than widening a frozen tag.
#[test]
fn the_pq_half_refuses_every_one_bit_near_miss_where_a_decoder_decides() {
    let msg = b"the entry frame";
    for tag in [TAG_MLDSA65_ED25519, TAG_FNDSA512_PREVIEW_ED25519] {
        let s = HybridSigner::from_seed(tag, &[0x42; 32]).unwrap();
        let half = PqVerifier::decode(s.public_key()).expect("a derived key decodes");
        let pq_len = s.public_key().sig_alg_row().pq_sig_len;
        let blob = s.sign_with_rng(&mut SeededRng06::new([7; 32]), msg);
        let field = &blob[..pq_len];
        assert!(half.verify(msg, field), "tag {tag}: the premise, the field verifies");
        let decided: Vec<usize> = if tag == TAG_MLDSA65_ED25519 {
            // The hint's last byte counts its ones; fewer than ω leaves slots.
            assert!(field[pq_len - 1] < 55, "the premise: the hint leaves index slots unused");
            (pq_len - (55 + 6)..pq_len).collect()
        } else {
            assert_eq!(field[pq_len - 1], 0, "the premise: `s2` leaves zero padding");
            std::iter::once(0).chain(1 + 40..pq_len).collect()
        };
        for at in decided {
            let mut near = field.to_vec();
            near[at] ^= 1;
            assert!(!half.verify(msg, &near), "tag {tag}: byte {at} flipped still verifies");
        }
    }
}

/// An FN-DSA-512 `s2` field of `len` bytes laid out as `fn-dsa` 0.4.0's
/// `comp_encode` lays it, low bit first: per magnitude (a multiple of 128,
/// sign 0) eight zero bits, `m / 128` zeros and a stop bit; zero bits after
/// the last.
fn s2_of(magnitudes: &[usize], len: usize) -> Vec<u8> {
    let mut field = vec![0u8; len];
    let mut at = 0;
    for m in magnitudes {
        at += 8 + m / 128;
        field[at / 8] |= 1 << (at % 8);
        at += 1;
    }
    field
}

/// THE DECODERS' PANIC GUARDS, AT THE INPUTS THAT WOULD TRIP THEM: behind a
/// genuine Ed25519 half — which any account holder makes with their own
/// enrolled key, so the post-quantum field beside it is theirs to choose —
/// [`verify`] hands a post-quantum decoder a field that stands on one guard
/// alone: ML-DSA-65's genuine `c̃` and `z` with a hint whose cuts decrease
/// (`HintBitUnpack` would slice `indices[2..1]`) or whose last cut is one
/// past ω (it would slice `indices[56..]`); the FN-DSA-512 preview's `s2`
/// running out of bytes at a coefficient's first byte or inside its run of
/// zeros (`comp_decode` would read `d[625]`). Each answers `Signature`. A
/// bump of either pinned crate that indexed before it checked panics here
/// rather than in a hostile session request.
#[test]
fn a_hostile_post_quantum_field_behind_a_genuine_ed25519_half_answers_signature() {
    let msg = b"the entry frame";
    for tag in [TAG_MLDSA65_ED25519, TAG_FNDSA512_PREVIEW_ED25519] {
        let s = HybridSigner::from_seed(tag, &[0x42; 32]).unwrap();
        let key = s.public_key();
        let pq_len = key.sig_alg_row().pq_sig_len;
        let genuine = s.sign_with_rng(&mut SeededRng06::new([7; 32]), msg);
        assert_eq!(verify(tag, key, msg, &genuine), Ok(()), "tag {tag}: the premise");
        let fields: Vec<(&str, Vec<u8>)> = if tag == TAG_MLDSA65_ED25519 {
            // The genuine `c̃` and `z`; the hint — the last ω + k = 55 + 6
            // bytes, its cuts the last 6 — replaced whole.
            let with_hint = |indices: &[u8], cuts: [u8; 6]| {
                let mut field = genuine[..pq_len].to_vec();
                field[pq_len - 61..].fill(0);
                field[pq_len - 61..][..indices.len()].copy_from_slice(indices);
                field[pq_len - 6..].copy_from_slice(&cuts);
                field
            };
            vec![
                ("cuts decreasing", with_hint(&[0, 1], [2, 1, 1, 1, 1, 1])),
                ("a cut one past ω", with_hint(&[], [0, 0, 0, 0, 0, 56])),
            ]
        } else {
            // The degree-512 header byte, a zero nonce, then `s2`. 333
            // coefficients of 15 bits fill it to bit 4,995, three bits into
            // its last byte, so the 334th coefficient's first byte lies past
            // its 625; 8 of 15 bits and 348 of 14 fill it to bit 4,992, so
            // the 357th coefficient's first byte is that last byte, zero, and
            // its run of zeros runs past it.
            let with_s2 = |magnitudes: &[usize]| {
                let mut field = vec![0x39_u8];
                field.extend([0u8; 40]);
                field.extend(s2_of(magnitudes, pq_len - 41));
                field
            };
            vec![
                ("s2 runs out at a coefficient's first byte", with_s2(&[768_usize; 333])),
                (
                    "s2 runs out inside a run of zeros",
                    with_s2(&[vec![768_usize; 8], vec![640_usize; 348]].concat()),
                ),
            ]
        };
        for (what, field) in fields {
            let blob = [&field[..], &genuine[pq_len..]].concat();
            assert_eq!(
                verify(tag, key, msg, &blob),
                Err(HybridFault::Signature),
                "tag {tag}: {what}"
            );
        }
    }
}

/// `comp_decode`'s walk of an FN-DSA-512 `s2` field, by position (`fn-dsa`
/// 0.4.0, low bit first): each of the 512 coefficients' start — its sign
/// bit — with its magnitude (seven low bits, then 128 per zero before the
/// stop bit), and the bit just past the last; `None` where the field runs
/// out first.
fn s2_walk(s2: &[u8]) -> Option<(Vec<(usize, usize)>, usize)> {
    let bit = |at: usize| s2.get(at / 8).map(|&byte| usize::from((byte >> (at % 8)) & 1));
    let mut coefficients = Vec::with_capacity(512);
    let mut at = 0;
    for _ in 0..512 {
        let start = at;
        let mut magnitude =
            (1..8).map(|b| Some(bit(start + b)? << (b - 1))).sum::<Option<usize>>()?;
        at += 8;
        while bit(at)? == 0 {
            magnitude += 128;
            at += 1;
        }
        coefficients.push((start, magnitude));
        at += 1;
    }
    Some((coefficients, at))
}

/// THE ONE-ENCODING DOORS THE BIT-0 SWEEP CANNOT REACH: four second
/// encodings of a genuine post-quantum field, each of which a decoder lax in
/// exactly one check would read as the very values the genuine field holds —
/// so that tag would verify two blobs for one signature with every golden
/// green: ML-DSA-65's hint with two of one polynomial's indices swapped and
/// with its first index repeated (FIPS 204's HintBitUnpack: strictly
/// increasing); the FN-DSA-512 preview's `s2` with a zero coefficient's sign
/// bit set (`comp_decode`'s "-0") and with the first bit past its last
/// coefficient set (its unused bits). `PqVerifier::verify` refuses each.
/// `the_pq_half_refuses_every_one_bit_near_miss_where_a_decoder_decides`
/// flips bit 0 alone, which reaches none of the four: a flipped hint index
/// moves the hint, which the arithmetic refuses under any decoder, and
/// `comp_decode` reads low bit first, so the unused bits are the last data
/// byte's HIGH bits and a sign bit sits at bit 0 only where a coefficient
/// starts on a byte.
#[test]
fn the_pq_half_refuses_a_second_encoding_of_a_genuine_field() {
    let msg = b"the entry frame";

    // Tag 1: the hint is the field's last ω + k = 55 + 6 bytes, its cuts the
    // last 6.
    let s1 = HybridSigner::from_seed(TAG_MLDSA65_ED25519, &[0x42; 32]).unwrap();
    let half = PqVerifier::decode(s1.public_key()).expect("a derived key decodes");
    let pq_len = s1.public_key().sig_alg_row().pq_sig_len;
    let field = s1.sign_with_rng(&mut SeededRng06::new([7; 32]), msg)[..pq_len].to_vec();
    assert!(half.verify(msg, &field), "the premise: tag 1's field verifies");
    let (indices, cuts) = (pq_len - 61, pq_len - 6);
    let used = usize::from(field[pq_len - 1]);
    assert!(used < 55, "the premise: the hint leaves an index slot unused");
    let (poly, first) = (0..6)
        .map(|i| (i, if i == 0 { 0 } else { usize::from(field[cuts + i - 1]) }))
        .find(|&(i, first)| usize::from(field[cuts + i]) >= first + 2)
        .expect("the premise: some polynomial's hint holds two indices");
    let mut swapped = field.clone();
    swapped.swap(indices + first, indices + first + 1);
    let mut repeated = field.clone();
    repeated.copy_within(indices + first + 1..indices + used, indices + first + 2);
    repeated[indices + first + 1] = repeated[indices + first];
    for cut in &mut repeated[cuts + poly..] {
        *cut += 1;
    }
    assert!(!half.verify(msg, &swapped), "tag 1: two of a polynomial's hint indices swapped");
    assert!(!half.verify(msg, &repeated), "tag 1: a polynomial's first hint index repeated");

    // Tag 3: the first stream that signs with a zero coefficient and ends
    // mid-byte.
    let s3 = HybridSigner::from_seed(TAG_FNDSA512_PREVIEW_ED25519, &[0x42; 32]).unwrap();
    let half = PqVerifier::decode(s3.public_key()).expect("a derived key decodes");
    let pq_len = s3.public_key().sig_alg_row().pq_sig_len;
    let (field, zero, end) = (0..=u8::MAX)
        .find_map(|n| {
            let field = s3.sign_with_rng(&mut SeededRng06::new([n; 32]), msg)[..pq_len].to_vec();
            let (coefficients, end) = s2_walk(&field[41..])?;
            let &(zero, _) = coefficients.iter().find(|&&(_, magnitude)| magnitude == 0)?;
            (end % 8 != 0).then_some((field, zero, end))
        })
        .expect("the premise: a stream signs with a zero coefficient, ending mid-byte");
    assert!(half.verify(msg, &field), "the premise: tag 3's field verifies");
    for (at, what) in [
        (zero, "a zero coefficient's sign bit set"),
        (end, "the first unused bit set"),
    ] {
        let mut near = field.clone();
        near[41 + at / 8] |= 1 << (at % 8);
        assert!(!half.verify(msg, &near), "tag 3: {what}");
    }
}

/// THE ED25519 HALF IS `verify_strict`'s (AUTH-4.32), AGAINST A LOW-ORDER
/// KEY: under each of the eight low-order Ed25519 halves, beside either tag's
/// genuine post-quantum half, a blob whose post-quantum field the signer made
/// over a message and whose Ed25519 field is a forgery the cofactorless check
/// passes over that message — `S` = 0 and an `R` of low order, found by that
/// very check — answers `Signature`. A non-strict Ed25519 verify passes every
/// one, and the hybrid would stand on its post-quantum half alone.
#[test]
fn a_low_order_ed25519_half_verifies_no_forgery() {
    use ed25519_dalek::Verifier as _;
    let low_order = LOW_ORDER.map(bytes32);
    let points: Vec<EdVerifyingKey> = low_order
        .iter()
        .map(|a| EdVerifyingKey::from_bytes(a).expect("the premise: each encodes a point"))
        .collect();
    for (i, point) in points.iter().enumerate() {
        assert!(point.is_weak(), "the premise: encoding {i} is of low order");
        assert!(
            points[..i].iter().all(|other| other.to_edwards() != point.to_edwards()),
            "the premise: encoding {i} is a point the ones before it are not"
        );
    }
    for tag in [TAG_MLDSA65_ED25519, TAG_FNDSA512_PREVIEW_ED25519] {
        let s = HybridSigner::from_seed(tag, &[0x42; 32]).unwrap();
        let key = s.public_key();
        let pq_len = key.sig_alg_row().pq_sig_len;
        for (a, point) in low_order.iter().zip(&points) {
            let weak =
                PublicKey::from_halves(key.alg(), key.pq_half(), a).expect("the row's widths");
            let (msg, forged) = (0..64)
                .map(|n| format!("the entry frame {n}").into_bytes())
                .find_map(|msg| {
                    let forged = low_order
                        .iter()
                        .map(|r| {
                            let mut sig = [0u8; 64];
                            sig[..32].copy_from_slice(r);
                            sig
                        })
                        .find(|sig| {
                            point.verify(&msg, &ed25519_dalek::Signature::from_bytes(sig)).is_ok()
                        })?;
                    Some((msg, forged))
                })
                .expect("the premise: the cofactorless check passes a forgery");
            let mut blob = s.sign_with_rng(&mut SeededRng06::new([7; 32]), &msg);
            blob[pq_len..].copy_from_slice(&forged);
            assert_eq!(
                verify(tag, &weak, &msg, &blob),
                Err(HybridFault::Signature),
                "tag {tag}, the Ed25519 half {a:02x?}"
            );
        }
    }
}

/// THE ED25519 HALF IS `verify_strict`'s, AGAINST AN UNREDUCED SCALAR: a
/// genuine blob whose Ed25519 `S` is raised by the group order ℓ — the same
/// scalar mod ℓ, so a second encoding of one signature — answers `Signature`
/// under both tags. A verify that admitted unreduced scalars
/// (`ed25519-dalek`'s `legacy_compatibility`, which a feature anywhere in a
/// build unifies in) passes it, and one signed frame would carry two blobs.
#[test]
fn an_ed25519_s_raised_by_the_group_order_is_refused() {
    // ℓ = 2^252 + 27742317777372353535851937790883648493, little-endian.
    const ELL: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];
    let msg = b"the entry frame";
    for tag in [TAG_MLDSA65_ED25519, TAG_FNDSA512_PREVIEW_ED25519] {
        let s = HybridSigner::from_seed(tag, &[0x42; 32]).unwrap();
        let mut blob = s.sign_with_rng(&mut SeededRng06::new([7; 32]), msg);
        let s_at = blob.len() - 32;
        let mut carry = 0u16;
        for (byte, ell) in blob[s_at..].iter_mut().zip(ELL) {
            let sum = u16::from(*byte) + u16::from(ell) + carry;
            *byte = sum as u8;
            carry = sum >> 8;
        }
        assert!(
            carry == 0 && blob[blob.len() - 1] & 0xe0 == 0,
            "tag {tag}: the premise, S + ℓ is below 2^253 — a scalar whose top three bits are \
             clear, which the legacy check admits"
        );
        assert_eq!(
            verify(tag, s.public_key(), msg, &blob),
            Err(HybridFault::Signature),
            "tag {tag}"
        );
    }
}

/// THE ROW CHECK, over every value a marker tag can take: a blob its own
/// signer made verifies under the key's own row's tag alone, and every
/// other tag — another row's, or one no row names — answers `WrongRow`,
/// ahead of any judgement of the blob's width: so does every blob of a wrong
/// width (one byte short, one byte long, the Ed25519 field alone, one byte
/// shorter than that, empty), each of which, under the key's own tag,
/// answers `Malformed`.
#[test]
fn every_tag_but_the_keys_own_answers_wrong_row() {
    let seed = [0x42u8; 32];
    let msg = b"the entry frame";
    for own in [TAG_MLDSA65_ED25519, TAG_FNDSA512_PREVIEW_ED25519] {
        let s = HybridSigner::from_seed(own, &seed).unwrap();
        let sig = s.sign_with_rng(&mut SeededRng06::new([7; 32]), msg);
        let long = [&sig[..], &[0u8]].concat();
        let blobs: [(&[u8], Result<(), HybridFault>); 6] = [
            (&sig[..], Ok(())),
            (&sig[1..], Err(HybridFault::Malformed)),
            (&long[..], Err(HybridFault::Malformed)),
            (&sig[sig.len() - 64..], Err(HybridFault::Malformed)),
            (&sig[..63], Err(HybridFault::Malformed)),
            (&[], Err(HybridFault::Malformed)),
        ];
        for tag in 0..=u8::MAX {
            for (blob, under_own) in blobs {
                let expected = if tag == own { under_own } else { Err(HybridFault::WrongRow) };
                assert_eq!(
                    verify(tag, s.public_key(), msg, blob),
                    expected,
                    "tag {tag} against a tag-{own} key, a {}-byte blob",
                    blob.len()
                );
            }
        }
    }
}

/// The verify's refusal is an ERROR a caller propagates with `?` into
/// its own error type, and its text does not guess which half failed.
#[test]
fn a_verify_refusal_propagates_as_an_error() {
    fn propagate(
        r: Result<(), HybridFault>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        r?;
        Ok(())
    }
    for fault in [HybridFault::WrongRow, HybridFault::Malformed, HybridFault::Signature] {
        let e = propagate(Err(fault)).expect_err("a refusal propagates");
        assert_eq!(e.to_string(), fault.to_string());
    }
    let signature = HybridFault::Signature.to_string();
    assert!(!signature.contains("Ed25519") && !signature.contains("post-quantum"), "{signature}");
}
