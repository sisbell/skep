//! THE VERIFY and THE ALL-HALVES DECODE — what skepd links, in every build:
//! [`verify`], both halves of a hybrid signature over the same bytes, and
//! [`key_decodes`], the enrollment courtesy, which reads the very two half
//! decodes the verify runs before its arithmetic. The verify-only build a
//! daemon links is this file and the crate root, and nothing in either
//! signs; its tests, in `verifier/tests.rs`, sign their fixtures through the
//! signer.

use std::fmt;

use ed25519_dalek::VerifyingKey as EdVerifyingKey;
use fn_dsa::{VerifyingKey as _, VerifyingKeyStandard, DOMAIN_NONE, HASH_ID_RAW};
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa65};
use skep_identity::PublicKey;

use crate::Rule;

/// Why [`verify`] refused a hybrid signature, by where the fault lies — the
/// row the tag names, the blob's width, or the signature itself — judged in
/// that order, the first that holds being the answer: `Malformed` says the
/// row is the tag's, and `Signature` that the width is too. Each is a cause a
/// verifier can tell from the bytes in hand and nothing else; the three are
/// everything those bytes can tell apart, so the set is closed by design and
/// not `#[non_exhaustive]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HybridFault {
    /// The tag names no row, or the key is not that row's.
    WrongRow,
    /// The tag names the key's row, and the blob is not that row's fixed
    /// width.
    Malformed,
    /// The row and the width are the tag's, and the signature itself fails:
    /// a half did not verify, or did not decode — no signature passes a half
    /// that is no key — and which one is deliberately not said: under "both
    /// halves verify" a partial pass is no pass. The wire names this cause
    /// `signature` (`attestation_invalid:signature`, where no candidate key's
    /// verify passes), as it names `Malformed`'s `malformed`.
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
/// `VerifyingKey::from_bytes` over the KEY PIN's LAST 32 raw bytes (the
/// crate pick is argued in `Cargo.toml`), which decodes under ZIP-215: a
/// point of any order, under its canonical encoding or not — or `None`
/// where the half is no point. One of the two decodes [`verify`] runs before
/// its arithmetic and [`key_decodes`] runs alone; a half of small order,
/// which it admits, is `verify_strict`'s to refuse, signature by signature.
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
                let Some(sigma) = <&EncodedSignature<MlDsa65>>::try_from(pq_sig)
                    .ok()
                    .and_then(ml_dsa::Signature::<MlDsa65>::decode)
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
/// disagree about what decodes and a new tag's decode is one arm both read.
/// On a key this answers `false` for, every [`verify`] that gets past the
/// row and the width answers [`HybridFault::Signature`]. Its `true` is a
/// decode's, not a promise that the key can sign: wire.md's
/// `undecodable_key` is a half "to no point" or "to no key", and this
/// answers exactly that test — so an Ed25519 half that is one of the curve's
/// eight points of small order decodes, and `verify_strict` refuses every
/// signature under it. It never panics, on any key.
#[must_use = "key_decodes answers whether every half decodes; it refuses no key itself"]
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
/// alone — a tag no row names, or a key of another row. The three faults
/// are judged in that order — `WrongRow`, `Malformed`, `Signature` — and
/// the first that holds is the answer: a blob of the wrong width under a tag
/// not the key's answers `WrongRow`, and no half is decoded until the row
/// and the width have passed (`every_tag_but_the_keys_own_answers_wrong_row`,
/// `an_undecodable_key_answers_as_its_source_key_save_that_nothing_passes`).
///
/// `tag` is the marker tag the blob is presented under, and nothing more —
/// an entry's marker names one; a session's or a credential record's `sig`
/// names none, and each candidate key is tried under its own. A tag that
/// does not name the key's own row is refused, by a check `verify` owns: it
/// reads the row off the key — a tag is never looked up in the table — and
/// that row gives the blob's width and where its halves part; both decodes
/// and all the arithmetic read the key.
///
/// It has NO PRECONDITION and NEVER PANICS, whatever `tag`, `key`, `msg` and
/// `sig` hold: every condition above is a check `verify` makes and answers,
/// so a caller establishes nothing first, and every fault a stranger's bytes
/// can carry is a [`HybridFault`]. A key holder chooses the post-quantum
/// field behind their own passing Ed25519 half, so this is a promise about
/// the two pinned decoders as much as about this function; the suite hands
/// each decoder, behind a genuine Ed25519 half, the fields that would trip
/// its bounds checks
/// (`a_hostile_post_quantum_field_behind_a_genuine_ed25519_half_answers_signature`).
///
/// `msg` comes before `sig`, the order RustCrypto's
/// `signature::Verifier::verify` and `ed25519-dalek`'s `verify_strict` take
/// them: the two are `&[u8]` the compiler cannot tell apart, so the order a
/// Rust caller already knows is the one that holds.
pub fn verify(tag: u8, key: &PublicKey, msg: &[u8], sig: &[u8]) -> Result<(), HybridFault> {
    // The key's own row, which `tag` must name. One comparison answers both
    // of `WrongRow`'s cases, since a tag that names no row is no key's row's
    // tag either.
    let row = key.sig_alg_row();
    if row.tag != tag {
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
mod tests;
