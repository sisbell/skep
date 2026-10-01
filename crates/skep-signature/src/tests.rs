use super::*;
use skep_identity::{SigAlgRow, SIG_ALGS};

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
        // Shorter than the Ed25519 field alone.
        assert_eq!(
            verify(tag, signer.public_key(), msg, &sig[..63]),
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

/// THE TAG SET is stated once ([`Rule::of`]): the KDF, keygen and the
/// widths answer for exactly the tags it names, over every value a marker
/// tag can take, so no step serves a tag another refuses — and the set is
/// the two rules the module card names, and exactly the tags skep-identity's
/// `SIG_ALGS` names: every key's row has a rule here, so a post-quantum half
/// that does not decode is its key's fault, never its row's.
#[test]
fn every_per_tag_step_answers_for_exactly_the_tags_rule_names() {
    let seed = [0x42u8; 32];
    for tag in 0..=u8::MAX {
        let ruled = Rule::of(tag).is_some();
        assert_eq!(derive_seeds(tag, &seed).is_some(), ruled, "the KDF, tag {tag}");
        assert_eq!(HybridSigner::from_seed(tag, &seed).is_some(), ruled, "keygen, tag {tag}");
        assert_eq!(pq_widths(tag).is_some(), ruled, "the widths, tag {tag}");
    }
    let rule_tags: Vec<u8> = (0..=u8::MAX).filter(|&t| Rule::of(t).is_some()).collect();
    assert_eq!(
        rule_tags,
        [TAG_MLDSA65_ED25519, TAG_FNDSA512_PREVIEW_ED25519],
        "this build holds exactly the two rules the module card names"
    );
    let mut rows: Vec<u8> = SIG_ALGS.iter().map(|row| row.tag).collect();
    rows.sort_unstable();
    assert_eq!(rule_tags, rows, "a rule here for exactly the tags SIG_ALGS names");
}
