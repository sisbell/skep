//! THE VERIFY and THE ALL-HALVES DECODE — what skepd links, in every build:
//! [`verify`], both halves of a hybrid signature over the same bytes, and
//! [`key_decodes`], the enrollment courtesy, which reads the very two half
//! decodes the verify runs before its arithmetic. The verify-only build a
//! daemon links is this file and the crate root, and nothing in either
//! signs; this file's tests sign their fixtures through the signer.

use std::fmt;

use ed25519_dalek::VerifyingKey as EdVerifyingKey;
use fn_dsa::{VerifyingKey as _, VerifyingKeyStandard, DOMAIN_NONE, HASH_ID_RAW};
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa65};
use skep_identity::{PublicKey, SigAlgRow};

use crate::Rule;

/// Why [`verify`] refused a hybrid signature, by where the fault lies — the
/// row the tag names, the blob's width, or the signature itself: the cause a
/// verifier can tell from the bytes in hand and nothing else. The three are
/// everything those bytes can tell apart, so the set is closed by design and
/// not `#[non_exhaustive]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HybridFault {
    /// The tag names no row, or the key is not that row's.
    WrongRow,
    /// The blob is not the tag's fixed width.
    Malformed,
    /// The signature itself: a half did not verify, or did not decode — no
    /// signature passes a half that is no key — and which one is
    /// deliberately not said: under "both halves verify" a partial pass is
    /// no pass. The wire names this cause `signature`
    /// (`attestation_invalid:signature`, where no candidate key's verify
    /// passes), as it names `Malformed`'s `malformed`.
    Signature,
}

/// The cause in words a log line can carry — for [`HybridFault::Signature`]
/// still not which half, which the variant does not know.
impl fmt::Display for HybridFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            HybridFault::WrongRow => {
                "the key is not of the row the marker tag names, or the tag names no row"
            }
            HybridFault::Malformed => "the signature blob is not its row's fixed width",
            HybridFault::Signature => {
                "the signature does not verify under the key: both halves must, and a partial \
                 pass is no pass"
            }
        })
    }
}

/// The ecosystem door: only a type carrying `Display` and `std::error::Error`
/// composes with `?` into a caller's own error type, and a caller cannot add
/// either impl.
impl std::error::Error for HybridFault {}

/// A hybrid key's Ed25519 half as a verifier — `ed25519-dalek`'s
/// `VerifyingKey::from_bytes`, the canonical point decode (the crate pick is
/// argued in `Cargo.toml`), over the KEY PIN's LAST 32 raw bytes — or `None`
/// where the half is no point. One of the two decodes [`verify`] runs before
/// its arithmetic and [`key_decodes`] runs alone.
fn decode_ed25519_half(key: &PublicKey) -> Option<EdVerifyingKey> {
    EdVerifyingKey::from_bytes(key.ed25519_half()).ok()
}

/// A hybrid key's post-quantum half AS A VERIFIER under its own row's rule —
/// the counterpart of the `EdVerifyingKey` [`decode_ed25519_half`] answers,
/// and of the signer's `PqSigner` — one arm per tag this crate holds a rule
/// for, and on this one card both things the rule asks of it: the decode
/// that can REFUSE the half (`PqVerifier::decode`), which [`key_decodes`]
/// runs alone, and the arithmetic [`verify`] runs after it
/// (`PqVerifier::verify`).
enum PqVerifier {
    /// Tag 1: ML-DSA-65's encoded verifying key.
    MlDsa65(EncodedVerifyingKey<MlDsa65>),
    /// Tag 3: the FN-DSA-512 PREVIEW verifying key, decoded by `fn-dsa`
    /// 0.4.0.
    FnDsa512Preview(VerifyingKeyStandard),
}

impl PqVerifier {
    /// `key`'s post-quantum half under its own row's rule
    /// (`PublicKey::sig_alg_row`), decoded as far as that rule can REFUSE it
    /// — the fallible stage alone: ML-DSA-65's encoded verifying key for tag
    /// 1 (its length, the one check that encoding makes — every byte string
    /// of the row's length decodes) and `fn-dsa` 0.4.0's
    /// `VerifyingKeyStandard::decode` for tag 3's preview (the header byte
    /// `0x09` for degree 512, the length, every coefficient in range). `None`
    /// where the half does not decode — or where the key's row has no rule
    /// here, which the crate's tests rule out for every `SIG_ALGS` row. The
    /// other of the two decodes [`verify`] and [`key_decodes`] share; it
    /// reads the rule off the key, so no caller can hand it another.
    fn decode(key: &PublicKey) -> Option<PqVerifier> {
        let pq = key.pq_half();
        match Rule::of(key.sig_alg_row().tag)? {
            Rule::MlDsa65Ed25519 => {
                EncodedVerifyingKey::<MlDsa65>::try_from(pq).ok().map(PqVerifier::MlDsa65)
            }
            Rule::FnDsa512PreviewEd25519 => {
                VerifyingKeyStandard::decode(pq).map(PqVerifier::FnDsa512Preview)
            }
        }
    }

    /// Whether `pq_sig` is this half's signature over `msg` under its rule —
    /// ML-DSA-65's `verify_with_context` with the empty context string, the
    /// FN-DSA-512 preview's `verify` with `DOMAIN_NONE` and `HASH_ID_RAW`
    /// (the CTX PIN at both). A signature that does not decode verifies
    /// nothing. A yes or a no: [`verify`] has already parted the blob at the
    /// row's widths, and naming a fault is the hybrid's business, not a half's.
    fn verify(&self, msg: &[u8], pq_sig: &[u8]) -> bool {
        match self {
            PqVerifier::MlDsa65(enc) => {
                let vk = ml_dsa::VerifyingKey::<MlDsa65>::decode(enc);
                let Some(sigma) = EncodedSignature::<MlDsa65>::try_from(pq_sig)
                    .ok()
                    .and_then(|enc_sig| ml_dsa::Signature::<MlDsa65>::decode(&enc_sig))
                else {
                    return false;
                };
                // The CTX PIN: the empty context string.
                vk.verify_with_context(msg, &[], &sigma)
            }
            PqVerifier::FnDsa512Preview(vk) => vk.verify(pq_sig, &DOMAIN_NONE, &HASH_ID_RAW, msg),
        }
    }
}

/// THE ALL-HALVES DECODE — the precheck's `undecodable_key` courtesy
/// (AUTH-3.56 as RES-206 landed it; the hybrid-only launch's Q9, owner
/// 2026-09-26): `true` iff EVERY half the key's row names decodes, by the
/// very two decodes [`verify`] runs before its arithmetic, so the two cannot
/// disagree and a new tag's decode is one arm both read. On a key this
/// answers `false` for, every [`verify`] that gets past the row and the
/// width answers [`HybridFault::Signature`]; on a key it answers `true` for,
/// the signature alone decides. A courtesy stricter than the verify would
/// refuse a key that can sign; a laxer one would admit a key that never can.
pub fn key_decodes(key: &PublicKey) -> bool {
    decode_ed25519_half(key).is_some() && PqVerifier::decode(key).is_some()
}

/// VERIFY `sig` over `msg` under `tag`'s frozen rule against the hybrid
/// `key`: the key's row must be the tag's, the blob the tag's width, and
/// BOTH halves — the PQ signature under the PQ half, the Ed25519 signature
/// under the Ed25519 half (`verify_strict`) — must verify over the SAME
/// `msg`. Either failing fails. Each half is decoded exactly as
/// [`key_decodes`] decodes it, and a half that does not DECODE answers
/// [`HybridFault::Signature`], as a half that does not verify does,
/// whichever half it is; [`HybridFault::WrongRow`] is the row's answer
/// alone — a tag no row names, or a key of another row.
///
/// `tag` is the marker tag the blob is presented under, and nothing more —
/// an entry's marker names one; a session's or a credential record's `sig`
/// names none, and each candidate key is tried under its own. The row it
/// names must be the key's, and gives the blob's width and where its halves
/// part; both decodes and all the arithmetic read the key.
///
/// `msg` comes before `sig`, the order RustCrypto's
/// `signature::Verifier::verify` and `ed25519-dalek`'s `verify_strict` take
/// them: the two are `&[u8]` the compiler cannot tell apart, so the order a
/// Rust caller already knows is the one that holds.
pub fn verify(tag: u8, key: &PublicKey, msg: &[u8], sig: &[u8]) -> Result<(), HybridFault> {
    let row = SigAlgRow::of_tag(tag).ok_or(HybridFault::WrongRow)?;
    if key.alg() != row.token {
        return Err(HybridFault::WrongRow);
    }
    // THE BLOB, parted where the row parts it: the PQ signature, then the
    // Ed25519 signature's 64 bytes, typed as such. A blob of any length but
    // the row's (`SigAlgRow::sig_len`, `pq_sig_len` + 64) is `Malformed`
    // here — the one place a width is judged — so neither field below can
    // be the wrong width.
    let Some((pq_sig, ed_sig)) = sig
        .split_last_chunk::<{ ed25519_dalek::SIGNATURE_LENGTH }>()
        .filter(|(pq, _)| pq.len() == row.pq_sig_len)
    else {
        return Err(HybridFault::Malformed);
    };
    // The Ed25519 half FIRST: cheap, and a failure here refuses before the
    // lattice arithmetic runs. Both are required, and a half that does not
    // DECODE answers as a half that does not verify — `Signature`, the
    // Ed25519 point and the post-quantum key alike — so the order moves no
    // verdict, the fault's variant included.
    let ed_key = decode_ed25519_half(key).ok_or(HybridFault::Signature)?;
    ed_key
        .verify_strict(msg, &ed25519_dalek::Signature::from_bytes(ed_sig))
        .map_err(|_| HybridFault::Signature)?;
    match PqVerifier::decode(key) {
        Some(half) if half.verify(msg, pq_sig) => Ok(()),
        _ => Err(HybridFault::Signature),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hooks::SeededRng06;
    use crate::signer::HybridSigner;
    use crate::{TAG_FNDSA512_PREVIEW_ED25519, TAG_MLDSA65_ED25519};

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
        let s1 = HybridSigner::from_seed(TAG_MLDSA65_ED25519, &seed).unwrap();
        let mut pq = s1.public_key().pq_half().to_vec();
        pq[0] ^= 0xff;
        let still =
            PublicKey::from_halves(s1.public_key().alg(), &pq, s1.public_key().ed25519_half())
                .expect("the row's widths");
        assert!(
            PqVerifier::decode(&still).is_some(),
            "ML-DSA-65's encoding decodes at its length"
        );
        assert!(
            !key_decodes(&bad) && key_decodes(&still),
            "the courtesy reads the same two decodes"
        );
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
        let sig = s3.sign_with_rng(msg, &mut SeededRng06::new([7; 32]));
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
        // The first encoding `[y, 0, …, 0]` that decompresses to no point.
        let no_point = (0..=u8::MAX)
            .map(|y| {
                let mut half = [0u8; 32];
                half[0] = y;
                half
            })
            .find(|half| EdVerifyingKey::from_bytes(half).is_err())
            .expect("about half of all encodings name no point");
        for tag in [TAG_MLDSA65_ED25519, TAG_FNDSA512_PREVIEW_ED25519] {
            let s = HybridSigner::from_seed(tag, &seed).unwrap();
            let sig = s.sign_with_rng(msg, &mut SeededRng06::new([7; 32]));
            let key = s.public_key();
            let bad = PublicKey::from_halves(key.alg(), key.pq_half(), &no_point)
                .expect("the row's widths");
            assert!(
                PqVerifier::decode(&bad).is_some(),
                "tag {tag}: the premise, its PQ half decodes"
            );
            assert!(!key_decodes(&bad), "tag {tag}: the courtesy refuses it");
            assert_eq!(verify(tag, &bad, msg, &sig), Err(HybridFault::Signature), "tag {tag}");
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
            let mut sig = s.sign_with_rng(msg, &mut SeededRng06::new([7; 32]));
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
        assert!(
            !signature.contains("Ed25519") && !signature.contains("post-quantum"),
            "{signature}"
        );
    }
}
