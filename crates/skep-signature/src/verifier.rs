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

/// Why a hybrid signature did not verify — the cause a verifier can tell
/// from the bytes in hand and nothing else. The three are everything those
/// bytes can tell apart, so the set is closed by design and not
/// `#[non_exhaustive]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HybridFault {
    /// The tag names no row, or the key is not that row's.
    WrongRow,
    /// The blob is not the tag's fixed width.
    Malformed,
    /// A half did not verify, or did not decode — no signature passes a half
    /// that is no key — and which one is deliberately not said: under "both
    /// halves verify" a partial pass is no pass.
    Rejected,
}

/// The cause in words a log line can carry — for [`HybridFault::Rejected`]
/// still not which half, which the variant does not know.
impl fmt::Display for HybridFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            HybridFault::WrongRow => {
                "the key is not of the row the marker tag names, or the tag names no row"
            }
            HybridFault::Malformed => "the signature blob is not its row's fixed width",
            HybridFault::Rejected => {
                "the hybrid signature did not verify: both halves must, and a partial pass is no \
                 pass"
            }
        })
    }
}

/// The ecosystem door, as `skepd::NotCanonical` and
/// `skepd::PortAlreadyBound` keep it: only a type carrying `Display` and
/// `std::error::Error` composes with `?` into a caller's own error type, and
/// a caller cannot add either impl.
impl std::error::Error for HybridFault {}

/// A hybrid key's Ed25519 half as a verifier — `ed25519-dalek`'s
/// `VerifyingKey::from_bytes`, the canonical point decode (the crate pick is
/// argued in `Cargo.toml`), over the KEY PIN's LAST 32 raw bytes — or `None`
/// where the half is no point. One of the two decodes [`verify`] runs before
/// its arithmetic and [`key_decodes`] runs alone.
fn decode_ed25519_half(key: &PublicKey) -> Option<EdVerifyingKey> {
    EdVerifyingKey::from_bytes(key.ed25519_half()).ok()
}

/// A hybrid key's post-quantum half, decoded as far as its tag's rule can
/// refuse it — one arm per tag this crate holds a rule for, and what
/// [`verify`] carries on into its arithmetic.
enum PqHalf {
    /// Tag 1: ML-DSA-65's encoded verifying key.
    MlDsa65(EncodedVerifyingKey<MlDsa65>),
    /// Tag 3: the FN-DSA-512 PREVIEW verifying key, decoded by `fn-dsa`
    /// 0.4.0.
    FnDsa512Preview(VerifyingKeyStandard),
}

/// `key`'s post-quantum half under `tag`'s rule, decoded as far as that rule
/// can REFUSE it — the fallible stage alone: ML-DSA-65's encoded verifying
/// key for tag 1 (its length, the one check that encoding makes — every byte
/// string of the row's length decodes) and `fn-dsa` 0.4.0's
/// `VerifyingKeyStandard::decode` for tag 3's preview (the header byte `0x09`
/// for degree 512, the length, every coefficient in range). `None` where the
/// half does not decode or `tag` names no rule of this crate's. The other
/// of the two decodes [`verify`] and [`key_decodes`] share.
fn decode_pq_half(tag: u8, key: &PublicKey) -> Option<PqHalf> {
    let pq = key.pq_half();
    match Rule::of(tag)? {
        Rule::MlDsa65Ed25519 => {
            EncodedVerifyingKey::<MlDsa65>::try_from(pq).ok().map(PqHalf::MlDsa65)
        }
        Rule::FnDsa512PreviewEd25519 => {
            VerifyingKeyStandard::decode(pq).map(PqHalf::FnDsa512Preview)
        }
    }
}

/// THE ALL-HALVES DECODE — the precheck's `undecodable_key` courtesy
/// (AUTH-3.56 as RES-206 landed it; the hybrid-only launch's Q9, owner
/// 2026-09-26): `true` iff EVERY half the key's row names decodes, by the
/// very two decodes [`verify`] runs before its arithmetic
/// (`decode_ed25519_half`, `decode_pq_half`) — so the courtesy and the verify
/// cannot disagree about what decodes, and a new tag's decode is one arm both
/// read. Both directions of a disagreement cost: a stricter courtesy refuses
/// an enrollment whose key decodes for every verify; a laxer one seats a key
/// that occupies a slot against the precheck's `MAX_ENROLLED_KEYS` and is
/// walked by the handshake's `find_signer` on every attempt, permanently,
/// since retiring it needs an anchor session of that account.
pub fn key_decodes(key: &PublicKey) -> bool {
    decode_ed25519_half(key).is_some() && decode_pq_half(key.sig_alg_row().tag, key).is_some()
}

/// VERIFY `sig` over `msg` under `tag`'s frozen rule against the hybrid
/// `key`: the key's row must be the tag's, the blob the tag's width, and
/// BOTH halves — the PQ signature under the PQ half, the Ed25519 signature
/// under the Ed25519 half (`verify_strict`) — must verify over the SAME
/// `msg`. Either failing fails. Each half is decoded by
/// `decode_ed25519_half` and `decode_pq_half`, the decodes [`key_decodes`]
/// runs alone, and a half that does not DECODE answers `Rejected`, as a half
/// that does not verify does, whichever half it is; [`HybridFault::WrongRow`]
/// is the row's answer alone — a tag no row names, or a key of another row.
///
/// `msg` comes before `sig`, the order RustCrypto's
/// `signature::Verifier::verify`, `ed25519-dalek`'s `verify_strict` and
/// skepd's own `session::verify` take them: the two are `&[u8]` the compiler
/// cannot tell apart, so the order a Rust caller already knows is the one
/// that holds.
pub fn verify(tag: u8, key: &PublicKey, msg: &[u8], sig: &[u8]) -> Result<(), HybridFault> {
    let row = SigAlgRow::of_tag(tag).ok_or(HybridFault::WrongRow)?;
    if key.alg() != row.token {
        return Err(HybridFault::WrongRow);
    }
    if sig.len() != row.sig_len() {
        return Err(HybridFault::Malformed);
    }
    let (pq_sig, ed_sig) = sig.split_at(row.pq_sig_len);
    // The Ed25519 half FIRST: cheap, and a failure here refuses before the
    // lattice arithmetic runs. Both are required, and a half that does not
    // DECODE answers as a half that does not verify — `Rejected`, the
    // Ed25519 point and the post-quantum key alike — so the order moves no
    // verdict, the fault's variant included.
    let ed_key = decode_ed25519_half(key).ok_or(HybridFault::Rejected)?;
    let ed_sig = ed25519_dalek::Signature::from_slice(ed_sig).map_err(|_| HybridFault::Malformed)?;
    ed_key.verify_strict(msg, &ed_sig).map_err(|_| HybridFault::Rejected)?;
    let pq_ok = match decode_pq_half(tag, key).ok_or(HybridFault::Rejected)? {
        PqHalf::MlDsa65(enc) => {
            let vk = ml_dsa::VerifyingKey::<MlDsa65>::decode(&enc);
            let enc_sig =
                EncodedSignature::<MlDsa65>::try_from(pq_sig).map_err(|_| HybridFault::Malformed)?;
            let Some(sigma) = ml_dsa::Signature::<MlDsa65>::decode(&enc_sig) else {
                return Err(HybridFault::Rejected);
            };
            // The CTX PIN: the empty context string.
            vk.verify_with_context(msg, &[], &sigma)
        }
        PqHalf::FnDsa512Preview(vk) => vk.verify(pq_sig, &DOMAIN_NONE, &HASH_ID_RAW, msg),
    };
    if pq_ok {
        Ok(())
    } else {
        Err(HybridFault::Rejected)
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
        let still =
            PublicKey::from_halves(s1.public_key().alg(), &pq, s1.public_key().ed25519_half())
                .expect("the row's widths");
        assert!(
            decode_pq_half(TAG_MLDSA65_ED25519, &still).is_some(),
            "ML-DSA-65's encoding decodes at its length"
        );
        assert!(
            !key_decodes(&bad) && key_decodes(&still),
            "the courtesy reads the same two decodes"
        );
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
}
