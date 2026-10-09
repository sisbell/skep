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
        assert_eq!(
            signer.public_key(),
            twin.public_key(),
            "tag {tag}: keygen from seed is deterministic"
        );
        let row = SigAlgRow::of_tag(tag).unwrap();
        assert_eq!(
            signer.public_key().raw().len(),
            row.key_len(),
            "tag {tag}: the key is the row's width"
        );
        let msg = b"the entry frame";
        let mut rng = SeededRng06::new([7; 32]);
        let sig = signer.sign_with_rng(&mut rng, msg);
        assert_eq!(sig.len(), row.sig_len(), "tag {tag}: the blob is the row's width");
        assert_eq!(
            verify(tag, signer.public_key(), msg, &sig),
            Ok(()),
            "tag {tag}: its own blob verifies"
        );
        assert_eq!(
            verify(tag, signer.public_key(), b"other", &sig),
            Err(HybridFault::Signature),
            "tag {tag}: another message"
        );
        // The Ed25519 half broken.
        let mut broken = sig.clone();
        broken[row.pq_sig_len] ^= 1;
        assert_eq!(
            verify(tag, signer.public_key(), msg, &broken),
            Err(HybridFault::Signature),
            "tag {tag}: the Ed25519 half broken"
        );
        // The PQ half broken.
        let mut broken = sig.clone();
        broken[3] ^= 1;
        assert_eq!(
            verify(tag, signer.public_key(), msg, &broken),
            Err(HybridFault::Signature),
            "tag {tag}: the post-quantum half broken"
        );
        // The wrong width.
        assert_eq!(
            verify(tag, signer.public_key(), msg, &sig[1..]),
            Err(HybridFault::Malformed),
            "tag {tag}: one byte short"
        );
        // Shorter than the Ed25519 field alone.
        assert_eq!(
            verify(tag, signer.public_key(), msg, &sig[..63]),
            Err(HybridFault::Malformed),
            "tag {tag}: shorter than the Ed25519 field"
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
            Err(HybridFault::WrongRow),
            "tag {tag}: the other tag's key"
        );
        assert_ne!(
            signer.ed25519_signing_key().to_bytes(),
            other_signer.ed25519_signing_key().to_bytes(),
            "the Ed25519 half differs per tag: the token is in the KDF's info"
        );
    }
    assert!(HybridSigner::from_seed(0, &seed).is_none());
    assert!(HybridSigner::from_seed(2, &seed).is_none());
    assert!(derive_half_seeds(2, &seed).is_none());
}

/// THE TAG SET is stated once ([`Rule::of`]): the KDF, keygen and the
/// widths answer for exactly the tags it names, over every value a marker
/// tag can take, so no step serves a tag another refuses and each signer
/// signs under the tag it was made under — and the set is the two rules the
/// crate doc names under THE TAGS, and exactly the tags skep-identity's
/// `SIG_ALGS` names: every key's row has a rule here, so a post-quantum half
/// that does not decode is its key's fault, never its row's.
#[test]
fn every_per_tag_step_answers_for_exactly_the_tags_rule_names() {
    let seed = [0x42u8; 32];
    for tag in 0..=u8::MAX {
        let ruled = Rule::of(tag).is_some();
        assert_eq!(derive_half_seeds(tag, &seed).is_some(), ruled, "the KDF, tag {tag}");
        assert_eq!(
            HybridSigner::from_seed(tag, &seed).map(|signer| signer.tag()),
            ruled.then_some(tag),
            "keygen, and the tag the signer signs under, tag {tag}"
        );
        assert_eq!(pq_widths(tag).is_some(), ruled, "the widths, tag {tag}");
    }
    let rule_tags: Vec<u8> = (0..=u8::MAX).filter(|&t| Rule::of(t).is_some()).collect();
    assert_eq!(
        rule_tags,
        [TAG_MLDSA65_ED25519, TAG_FNDSA512_PREVIEW_ED25519],
        "this build holds exactly the two rules the crate doc names under THE TAGS"
    );
    let mut row_tags: Vec<u8> = SIG_ALGS.iter().map(|row| row.tag).collect();
    row_tags.sort_unstable();
    assert_eq!(rule_tags, row_tags, "a rule here for exactly the tags SIG_ALGS names");
}

/// THE ED25519 HALF A SIGNER HANDS OUT IS THE ONE ITS BLOBS CARRY: under
/// either tag, the hook's bare Ed25519 signature over a message is the
/// Ed25519 field of the blob `sign` makes over it, and passes RFC 8032's
/// strict verify under the hook's verifying key — the Ed25519 half of the
/// signer's own key. The suites' negative vector is this hook's, and skepd
/// reads its refusal as the width's "and not a wrong key's"
/// (`sign_session_ed25519_half_alone`): a hook that signed under another
/// key, or signed nothing, would leave every cell that sends it green.
#[test]
fn the_ed25519_half_a_signer_hands_out_makes_its_blobs_ed25519_field() {
    let msg = b"the entry frame";
    for tag in [TAG_MLDSA65_ED25519, TAG_FNDSA512_PREVIEW_ED25519] {
        let signer = HybridSigner::from_seed(tag, &[0x42; 32]).unwrap();
        let half = signer.ed25519_signing_key();
        let bare = half.sign(msg);
        let pq_sig_len = signer.public_key().sig_alg_row().pq_sig_len;
        assert_eq!(
            bare[..],
            signer.sign(msg)[pq_sig_len..],
            "tag {tag}: the hook's bare signature is the blob's Ed25519 field"
        );
        assert_eq!(
            &half.verifying_key(),
            signer.public_key().ed25519_half(),
            "tag {tag}: the hook's verifying key is the key's Ed25519 half"
        );
        let point = ed25519_dalek::VerifyingKey::from_bytes(&half.verifying_key())
            .expect("a derived half is a point");
        assert!(
            point.verify_strict(msg, &ed25519_dalek::Signature::from_bytes(&bare)).is_ok(),
            "tag {tag}: the hook's bare signature is RFC 8032's over the message"
        );
    }
}
