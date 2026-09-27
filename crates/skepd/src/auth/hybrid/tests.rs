use super::*;
use crate::codec::hex_string;

/// Both tags: keygen from one seed is deterministic, the halves differ
/// per tag (the token is in the KDF's `info`), the widths are the ruled
/// ones, a signature verifies, either half alone fails, another message
/// fails, and the other tag's key refuses the row.
#[test]
fn both_tags_sign_verify_and_refuse_a_broken_half() {
    let seed = [0x42u8; 32];
    for tag in [TAG_MLDSA65_ED25519, TAG_FNDSA512_PREVIEW_ED25519] {
        let signer = HybridSigner::from_seed(tag, &seed).unwrap();
        let twin = HybridSigner::from_seed(tag, &seed).unwrap();
        assert_eq!(signer.public_key(), twin.public_key(), "keygen from seed is deterministic");
        let row = SigAlgRow::of_tag(tag).unwrap();
        assert_eq!(signer.public_key().raw().len(), row.key_len());
        let msg = b"the entry frame";
        let mut rng = SeededRng06::new([7; 32]);
        let sig = signer.sign_with_rng(msg, &mut rng);
        assert_eq!(sig.len(), row.sig_len());
        assert_eq!(verify(tag, signer.public_key(), msg, &sig), Ok(()));
        assert_eq!(
            verify(tag, signer.public_key(), b"other", &sig),
            Err(HybridFault::Rejected)
        );
        // The Ed25519 half broken.
        let mut broken = sig.clone();
        broken[row.pq_sig_len] ^= 1;
        assert_eq!(verify(tag, signer.public_key(), msg, &broken), Err(HybridFault::Rejected));
        // The PQ half broken.
        let mut broken = sig.clone();
        broken[3] ^= 1;
        assert_eq!(verify(tag, signer.public_key(), msg, &broken), Err(HybridFault::Rejected));
        // The wrong width.
        assert_eq!(
            verify(tag, signer.public_key(), msg, &sig[1..]),
            Err(HybridFault::Malformed)
        );
        // The other tag's key.
        let other_tag = if tag == TAG_MLDSA65_ED25519 {
            TAG_FNDSA512_PREVIEW_ED25519
        } else {
            TAG_MLDSA65_ED25519
        };
        let other_signer = HybridSigner::from_seed(other_tag, &seed).unwrap();
        assert_eq!(
            verify(tag, other_signer.public_key(), msg, &sig),
            Err(HybridFault::WrongRow)
        );
        assert_ne!(
            signer.ed25519_signing_key().to_bytes(),
            other_signer.ed25519_signing_key().to_bytes(),
            "the Ed25519 half differs per tag: the token is in the KDF's info"
        );
    }
    assert!(HybridSigner::from_seed(0, &seed).is_none());
    assert!(HybridSigner::from_seed(2, &seed).is_none());
    assert!(derive_seeds(2, &seed).is_none());
}

/// The post-quantum half's decode, alone: a derived key of either tag
/// decodes; a tag-3 key whose FN-DSA header byte is not `0x09` does not
/// (the fault the precheck's `undecodable_key` names on that half); a
/// tag-1 key of the right length always does (ML-DSA's encoding admits
/// every byte string of its length), which is why the Ed25519 half is
/// what carries that row's decode fault. And the courtesy,
/// [`key_decodes`], answers exactly as the two decodes [`verify`] runs.
#[test]
fn the_pq_half_decode_refuses_a_bad_fn_dsa_header_byte() {
    let seed = [0x42u8; 32];
    for tag in [TAG_MLDSA65_ED25519, TAG_FNDSA512_PREVIEW_ED25519] {
        let s = HybridSigner::from_seed(tag, &seed).unwrap();
        assert!(
            decode_pq_half(tag, s.public_key()).is_some(),
            "tag {tag}: a derived key decodes"
        );
    }
    let s3 = HybridSigner::from_seed(TAG_FNDSA512_PREVIEW_ED25519, &seed).unwrap();
    let mut pq = s3.public_key().pq_half().to_vec();
    assert_eq!(pq[0], 0x09, "fn-dsa 0.4.0's degree-512 header byte");
    pq[0] = 0x0a;
    let bad = PublicKey::from_halves(s3.public_key().alg(), &pq, s3.public_key().ed25519_half())
        .expect("the row's widths");
    assert!(
        decode_pq_half(TAG_FNDSA512_PREVIEW_ED25519, &bad).is_none(),
        "a bad header byte does not decode"
    );
    let s1 = HybridSigner::from_seed(TAG_MLDSA65_ED25519, &seed).unwrap();
    let mut pq = s1.public_key().pq_half().to_vec();
    pq[0] ^= 0xff;
    let still = PublicKey::from_halves(s1.public_key().alg(), &pq, s1.public_key().ed25519_half())
        .expect("the row's widths");
    assert!(
        decode_pq_half(TAG_MLDSA65_ED25519, &still).is_some(),
        "ML-DSA-65's encoding decodes at its length"
    );
    assert!(!key_decodes(&bad) && key_decodes(&still), "the courtesy reads the same two decodes");
}

/// A KEY THAT DOES NOT DECODE ANSWERS `Rejected`, whichever half fails
/// first: a tag-3 key whose FN-DSA header byte is not `0x09`, handed a
/// blob its own signer made over `msg`, answers `Rejected` over `msg` —
/// its Ed25519 half passes, then its post-quantum half does not decode —
/// and over another message, where the Ed25519 half fails first. The
/// order `verify` checks the halves in moves no verdict, the variant
/// included; `WrongRow` is the row's answer alone. And every `SIG_ALGS`
/// row has a rule here, so a post-quantum half this module cannot decode
/// is the KEY's fault and never the tag's.
#[test]
fn a_key_that_does_not_decode_answers_rejected_whichever_half_fails_first() {
    let seed = [0x42u8; 32];
    let s3 = HybridSigner::from_seed(TAG_FNDSA512_PREVIEW_ED25519, &seed).unwrap();
    let msg = b"the entry frame";
    let sig = s3.sign_with_rng(msg, &mut SeededRng06::new([7; 32]));
    let mut pq = s3.public_key().pq_half().to_vec();
    pq[0] = 0x0a;
    let bad = PublicKey::from_halves(s3.public_key().alg(), &pq, s3.public_key().ed25519_half())
        .expect("the row's widths");
    assert!(
        decode_ed25519_half(&bad).is_some()
            && decode_pq_half(TAG_FNDSA512_PREVIEW_ED25519, &bad).is_none(),
        "the premise: its Ed25519 half decodes and its post-quantum half does not"
    );
    for signed in [&msg[..], &b"other"[..]] {
        assert_eq!(
            verify(TAG_FNDSA512_PREVIEW_ED25519, &bad, signed, &sig),
            Err(HybridFault::Rejected),
            "over {:?}",
            String::from_utf8_lossy(signed)
        );
    }
    for row in skep_identity::SIG_ALGS {
        assert!(Rule::of(row.tag).is_some(), "tag {} is a row with no rule here", row.tag);
    }
}

/// THE TAG SET is stated once ([`Rule::of`]): the KDF, keygen and the
/// widths answer for exactly the tags it names, over every value a marker
/// tag can take, so no step serves a tag another refuses — and the set is
/// the two rules the module card names.
#[test]
fn every_per_tag_step_answers_for_exactly_the_tags_rule_names() {
    let seed = [0x42u8; 32];
    for tag in 0..=u8::MAX {
        let ruled = Rule::of(tag).is_some();
        assert_eq!(derive_seeds(tag, &seed).is_some(), ruled, "the KDF, tag {tag}");
        assert_eq!(HybridSigner::from_seed(tag, &seed).is_some(), ruled, "keygen, tag {tag}");
        assert_eq!(pq_widths(tag).is_some(), ruled, "the widths, tag {tag}");
    }
    assert_eq!(
        (0..=u8::MAX).filter(|&t| Rule::of(t).is_some()).collect::<Vec<_>>(),
        [TAG_MLDSA65_ED25519, TAG_FNDSA512_PREVIEW_ED25519],
        "this build holds exactly the two rules the module card names"
    );
}

/// The verify's refusal is an ERROR a caller propagates with `?` into
/// its own error type — the door the crate's other public errors keep —
/// and its text does not guess which half failed.
#[test]
fn a_verify_refusal_propagates_as_an_error() {
    fn propagate(
        r: Result<(), HybridFault>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        r?;
        Ok(())
    }
    for fault in [HybridFault::WrongRow, HybridFault::Malformed, HybridFault::Rejected] {
        let e = propagate(Err(fault)).expect_err("a refusal propagates");
        assert_eq!(e.to_string(), fault.to_string());
    }
    let rejected = HybridFault::Rejected.to_string();
    assert!(!rejected.contains("Ed25519") && !rejected.contains("post-quantum"), "{rejected}");
}

/// The KDF never hands either half the raw seed, and the two halves of
/// one tag differ.
#[test]
fn the_kdf_derives_both_halves_and_neither_is_the_seed() {
    let seed = [0x01u8; 32];
    let h1 = derive_seeds(TAG_MLDSA65_ED25519, &seed).unwrap();
    assert_ne!(h1.ed25519, seed);
    assert_ne!(h1.pq, seed);
    assert_ne!(h1.ed25519, h1.pq);
    let h3 = derive_seeds(TAG_FNDSA512_PREVIEW_ED25519, &seed).unwrap();
    assert_ne!(h3.pq, h1.pq);
    assert_ne!(h3.ed25519, h1.ed25519);
}

/// PRIVATE-KEY MATERIAL PRINTS NONE OF ITSELF: `{:?}` of `HalfSeeds`, a
/// `HybridSigner` of either tag and `SeededRng06` — what a log line, an
/// assertion's message or a panic carries — holds neither the seed, nor a
/// half seed, nor the Ed25519 signing key, nor the FN-DSA signing key the
/// tag-3 signer stores as bytes, in the decimal list a derived `Debug`
/// prints or in hex. The hand-written impls are all that stands between a
/// `#[derive(Debug)]` and a production key's ξ in a log.
#[test]
fn private_key_material_prints_none_of_itself() {
    let seed = [0x42u8; 32];
    let leaks = |printed: &str, secret: &[u8]| {
        printed.contains(&format!("{secret:?}")) || printed.contains(&hex_string(secret))
    };
    for tag in [TAG_MLDSA65_ED25519, TAG_FNDSA512_PREVIEW_ED25519] {
        let halves = derive_seeds(tag, &seed).unwrap();
        let signer = HybridSigner::from_seed(tag, &seed).unwrap();
        let mut secrets = vec![
            seed.to_vec(),
            halves.ed25519.to_vec(),
            halves.pq.to_vec(),
            signer.ed.to_bytes().to_vec(),
        ];
        if let PqSigner::FnDsa512Preview(sk) = &signer.pq {
            secrets.push(sk.clone());
        }
        for printed in [format!("{halves:?}"), format!("{signer:?}")] {
            for secret in &secrets {
                assert!(
                    !leaks(&printed, &secret[..]),
                    "tag {tag} prints private-key material: {printed}"
                );
            }
        }
    }
    let printed = format!("{:?}", SeededRng06::new(seed));
    assert!(!leaks(&printed, &seed[..]), "the fixture stream prints its seed: {printed}");
}
