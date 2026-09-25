//! THE HYBRID ENTRY SIGNATURE (signed ops, the seam build 2026-09-25): the
//! two marker tags' FROZEN RULES — keygen from one seed, signing, verifying —
//! in the one crate that may link a signature library (AUTH-2.2; the PQ
//! crate investigation §8.4 (5)). skep-identity holds the SYNTAX (the `ALGS`
//! rows, the `SIG_ALGS` table, the entry frame); this module holds the
//! ARITHMETIC, dispatching on the tag to THAT tag's rule and to no other.
//!
//! THE TAGS, each one exact rule held whole (the design record §1's
//! algorithm row, the frozen-tag rule; the owner 2026-09-25: it extends to
//! keygen):
//!
//! * TAG 1 — ML-DSA-65 + Ed25519, PRODUCTION: RustCrypto `ml-dsa` `=0.1.1`
//!   (final FIPS 204; `SigningKey::from_seed` is `ML-DSA.KeyGen_internal(ξ)`,
//!   Algorithm 6) and `ed25519-dalek` 2 (`verify_strict`). The signature is
//!   FIPS 204's DETERMINISTIC variant (`rnd` = 0) with an EMPTY context
//!   string — the CTX PIN: the entry frame's own tag is the domain
//!   separation, and `ml-dsa`'s `Signer` supports only the empty `ctx`.
//! * TAG 3 — FN-DSA-512 + Ed25519, PREVIEW: Thomas Pornin's `fn-dsa`
//!   `=0.4.0` — its 2026-07-22 "best guess" at the FN-DSA draft, which the
//!   crate itself says will change before 1.0 — so the exact version IS the
//!   rule: its keygen from a 32-byte seed (the RNG draw `keygen_inner`
//!   makes, and nothing else), its key and signature encodings, its `verify`
//!   with `DOMAIN_NONE` and `HASH_ID_RAW` (the CTX PIN again). FN-DSA signing
//!   is RANDOMIZED (the draft "only allows randomized signing"), so a tag-3
//!   signature's bytes depend on the signer's RNG and only the KEY and the
//!   VERIFY are byte-stable; a seeded RNG makes a fixture reproducible.
//!
//! THE KDF PIN (the design record §5.2 (ii)'s three inputs: the KDF, the
//! domain-separation bytes, the keygen entry point) — ONE 32-byte seed to
//! BOTH halves, never the raw seed to either:
//!
//! ```text
//! half_seed = HKDF-SHA-256(salt = "skep-kdf-v1", IKM = seed,
//!                          info = <alg token> ‖ 0x00 ‖ <half label>, L = 32)
//! ```
//!
//! with the half labels `"ed25519"`, `"ml-dsa-65"` and `"fn-dsa-512"` — so a
//! seed derives DIFFERENT Ed25519 halves under tag 1 and tag 3 (the token is
//! in the label), one derived half's leak reveals neither the seed nor the
//! other half (HKDF is one-way), and the paper backup stays one 64-hex
//! seed. The Ed25519 half's 32 bytes are `ed25519-dalek`'s seed
//! (`SigningKey::from_bytes`); the ML-DSA half's are FIPS 204's ξ; the
//! FN-DSA half's are the bytes `fn-dsa` 0.4.0's keygen draws.
//!
//! THE KEY PIN: a hybrid's raw public key is the PQ half's encoding THEN the
//! Ed25519 half's 32 bytes ([`skep_identity::PublicKey`]'s arms). THE BLOB:
//! the PQ signature THEN the Ed25519 signature's 64 bytes, two fixed-width
//! fields, no length prefix (the record §2.4). VERIFY is BOTH halves over
//! the SAME bytes — either failing fails (the ruled "hybrid, both halves
//! verify").
//!
//! What lives here beside the daemon's verify — keygen and signing — is the
//! signer's side, used by the suites' test signer and by the goldens that
//! pin each tag's rule; the daemon itself holds no key and never signs.

use ed25519_dalek::{Signer as _, SigningKey as EdSigningKey, VerifyingKey as EdVerifyingKey};
use fn_dsa::{
    signature_size, sign_key_size, vrfy_key_size, KeyPairGenerator, KeyPairGeneratorStandard,
    SigningKey as _, SigningKeyStandard, VerifyingKey as _, VerifyingKeyStandard,
    DOMAIN_NONE, FN_DSA_LOGN_512, HASH_ID_RAW,
};
use hkdf::Hkdf;
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, Keypair as _, MlDsa65, Signer as _};
use sha2::Sha256;
use skep_identity::{sig_alg_of, token_of_sig_alg, PublicKey, SigAlgRow, MLDSA65_KEY_LEN};

/// Tag 1's marker byte.
pub const TAG_MLDSA65_ED25519: u8 = 1;
/// Tag 3's marker byte.
pub const TAG_FNDSA512_PREVIEW_ED25519: u8 = 3;

/// The KDF's salt — the derivation's own name, so the same seed under
/// another KDF version derives other keys.
const KDF_SALT: &[u8] = b"skep-kdf-v1";
/// The half labels.
const HALF_ED25519: &[u8] = b"ed25519";
const HALF_MLDSA65: &[u8] = b"ml-dsa-65";
const HALF_FNDSA512: &[u8] = b"fn-dsa-512";

/// The two half seeds one 32-byte seed derives under one tag.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct HalfSeeds {
    /// The Ed25519 half's seed (`ed25519-dalek`'s `SigningKey::from_bytes`).
    pub ed25519: [u8; 32],
    /// The post-quantum half's seed: ξ for ML-DSA-65; the keygen draw for
    /// FN-DSA-512.
    pub pq: [u8; 32],
}

impl core::fmt::Debug for HalfSeeds {
    /// A seed is private-key material: never printed.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("HalfSeeds(..)")
    }
}

/// HKDF-SHA-256 as the KDF PIN states it: `salt = KDF_SALT`, `IKM = seed`,
/// `info = token ‖ 0x00 ‖ half`, 32 bytes out.
fn derive_half(seed: &[u8; 32], token: &str, half: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(KDF_SALT), seed);
    let mut info = Vec::with_capacity(token.len() + 1 + half.len());
    info.extend_from_slice(token.as_bytes());
    info.push(0);
    info.extend_from_slice(half);
    let mut out = [0u8; 32];
    hk.expand(&info, &mut out).expect("32 bytes is within HKDF-SHA-256's output bound");
    out
}

/// THE KDF: one seed to both half seeds under `tag`'s token; `None` for a
/// tag no row names.
pub fn derive_seeds(tag: u8, seed: &[u8; 32]) -> Option<HalfSeeds> {
    let row = token_of_sig_alg(tag)?;
    let pq_label = match tag {
        TAG_MLDSA65_ED25519 => HALF_MLDSA65,
        TAG_FNDSA512_PREVIEW_ED25519 => HALF_FNDSA512,
        _ => return None,
    };
    Some(HalfSeeds {
        ed25519: derive_half(seed, row.token, HALF_ED25519),
        pq: derive_half(seed, row.token, pq_label),
    })
}

/// An RNG that yields EXACTLY the bytes it was given and then refuses — what
/// `fn-dsa` 0.4.0's keygen is fed so that its one 32-byte draw IS the KDF's
/// FN-DSA seed. A longer draw would be a keygen this build did not pin, and
/// under the frozen-tag rule a NEW tag; refusing it makes the rule loud.
struct ExactBytes {
    bytes: Vec<u8>,
    taken: usize,
}

impl rand_core_06::RngCore for ExactBytes {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let end = self.taken + dest.len();
        assert!(
            end <= self.bytes.len(),
            "fn-dsa 0.4.0's keygen draws exactly {} bytes; a longer draw ({} so far) is a keygen \
             this build did not pin — a NEW tag under the frozen-tag rule",
            self.bytes.len(),
            end
        );
        dest.copy_from_slice(&self.bytes[self.taken..end]);
        self.taken = end;
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core_06::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core_06::CryptoRng for ExactBytes {}

/// A `rand_core` 0.6 view of the OS entropy `getrandom` supplies — what a
/// tag-3 signature draws its 40-byte seed from outside a seeded fixture.
pub struct OsRng06;

impl rand_core_06::RngCore for OsRng06 {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom::fill(dest).expect("OS entropy unavailable");
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core_06::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core_06::CryptoRng for OsRng06 {}

/// A DETERMINISTIC `rand_core` 0.6 stream for FIXTURES — SHA-256 in counter
/// mode over a seed — so a tag-3 signature (randomized by the draft's own
/// rule) is byte-stable in a golden. A test seam and no part of any tag's
/// rule: a tag-3 signature verifies under the tag's rule whatever RNG made
/// it. Not for production use.
pub struct SeededRng06 {
    seed: [u8; 32],
    counter: u64,
    buf: Vec<u8>,
}

impl SeededRng06 {
    pub fn new(seed: [u8; 32]) -> SeededRng06 {
        SeededRng06 { seed, counter: 0, buf: Vec::new() }
    }
}

impl rand_core_06::RngCore for SeededRng06 {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        use sha2::Digest;
        for out in dest.iter_mut() {
            if self.buf.is_empty() {
                let block: [u8; 32] = Sha256::new()
                    .chain_update(self.seed)
                    .chain_update(self.counter.to_be_bytes())
                    .finalize()
                    .into();
                self.counter += 1;
                self.buf = block.to_vec();
                self.buf.reverse();
            }
            *out = self.buf.pop().expect("refilled above");
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core_06::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core_06::CryptoRng for SeededRng06 {}

/// The post-quantum half of a signer, per tag.
enum PqSigner {
    /// Tag 1: the expanded ML-DSA-65 signing key, from ξ.
    MlDsa65(ml_dsa::SigningKey<MlDsa65>),
    /// Tag 3: the FN-DSA-512 signing key in `fn-dsa`'s encoding (1,281
    /// bytes at degree 9), decoded per signature — the crate's `sign` takes
    /// `&mut self` and its key type zeroizes on drop.
    FnDsa512(Vec<u8>),
}

/// ONE HYBRID SIGNER: both halves derived from one seed under one tag, its
/// public key the one `ALGS` entry the two halves make. Holds private-key
/// material and prints none of it.
pub struct HybridSigner {
    row: &'static SigAlgRow,
    ed: EdSigningKey,
    pq: PqSigner,
    public: PublicKey,
}

impl core::fmt::Debug for HybridSigner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "HybridSigner(tag {}, {:?})", self.row.tag, self.public)
    }
}

impl HybridSigner {
    /// KEYGEN FROM SEED under `tag`'s frozen rule: the KDF's two half seeds,
    /// the Ed25519 key from its half, the PQ key from its half by the pinned
    /// crate's own keygen. `None` for a tag no row names.
    pub fn from_seed(tag: u8, seed: &[u8; 32]) -> Option<HybridSigner> {
        let row = token_of_sig_alg(tag)?;
        let halves = derive_seeds(tag, seed)?;
        let ed = EdSigningKey::from_bytes(&halves.ed25519);
        let ed_pk = ed.verifying_key().to_bytes();
        let (pq, pq_pk): (PqSigner, Vec<u8>) = match tag {
            TAG_MLDSA65_ED25519 => {
                let sk = ml_dsa::SigningKey::<MlDsa65>::from_seed(&halves.pq.into());
                let pk = sk.verifying_key().encode();
                (PqSigner::MlDsa65(sk), pk.as_slice().to_vec())
            }
            TAG_FNDSA512_PREVIEW_ED25519 => {
                let mut rng = ExactBytes { bytes: halves.pq.to_vec(), taken: 0 };
                let mut sk = vec![0u8; sign_key_size(FN_DSA_LOGN_512)];
                let mut vk = vec![0u8; vrfy_key_size(FN_DSA_LOGN_512)];
                KeyPairGeneratorStandard::default().keygen(
                    FN_DSA_LOGN_512,
                    &mut rng,
                    &mut sk,
                    &mut vk,
                );
                assert_eq!(rng.taken, 32, "fn-dsa 0.4.0's keygen draws its one 32-byte seed");
                (PqSigner::FnDsa512(sk), vk)
            }
            _ => return None,
        };
        let mut raw = pq_pk;
        raw.extend_from_slice(&ed_pk);
        let public = PublicKey::parse(row.token, &hex(&raw))
            .expect("the two halves concatenate to the row's raw length");
        Some(HybridSigner { row, ed, pq, public })
    }

    /// The one `ALGS` entry this signer's halves make.
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// The marker tag this signer signs under.
    pub fn tag(&self) -> u8 {
        self.row.tag
    }

    /// The Ed25519 half's signing key — what opens a SESSION under this
    /// entry (the ruled key model: the Ed25519 half is for sessions).
    pub fn ed25519_signing_key(&self) -> &EdSigningKey {
        &self.ed
    }

    /// SIGN `msg` (the entry frame's bytes) under the tag's rule: the PQ
    /// signature THEN the Ed25519 signature, the blob a marker slot carries.
    /// Tag 1 is deterministic (FIPS 204's deterministic variant, empty
    /// `ctx`); tag 3 draws its per-signature seed from `rng`.
    pub fn sign_with_rng<R: rand_core_06::CryptoRng + rand_core_06::RngCore>(
        &self,
        msg: &[u8],
        rng: &mut R,
    ) -> Vec<u8> {
        let mut blob = match &self.pq {
            PqSigner::MlDsa65(sk) => sk.sign(msg).encode().as_slice().to_vec(),
            PqSigner::FnDsa512(sk_bytes) => {
                let mut sk = SigningKeyStandard::decode(sk_bytes)
                    .expect("this signer's own encoded key decodes");
                let mut sig = vec![0u8; signature_size(FN_DSA_LOGN_512)];
                sk.sign(rng, &DOMAIN_NONE, &HASH_ID_RAW, msg, &mut sig)
                    .expect("a valid signing key signs");
                sig
            }
        };
        blob.extend_from_slice(&self.ed.sign(msg).to_bytes());
        debug_assert_eq!(blob.len(), self.row.sig_len());
        blob
    }

    /// [`HybridSigner::sign_with_rng`] under OS entropy for the tag-3 draw
    /// (tag 1 draws nothing).
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.sign_with_rng(msg, &mut OsRng06)
    }
}

/// Why a hybrid signature did not verify — the cause a verifier can tell
/// from the bytes in hand and nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HybridFault {
    /// The tag names no row, or the key is not that row's.
    WrongRow,
    /// The blob is not the tag's fixed width.
    Malformed,
    /// A half did not verify — which one is deliberately not said: under
    /// "both halves verify" a partial pass is no pass.
    Rejected,
}

/// VERIFY `sig` over `msg` under `tag`'s frozen rule against the hybrid
/// `key`: the key's row must be the tag's, the blob the tag's width, and
/// BOTH halves — the PQ signature under the PQ half, the Ed25519 signature
/// under the Ed25519 half (`verify_strict`) — must verify over the SAME
/// `msg`. Either failing fails.
pub fn verify(tag: u8, key: &PublicKey, sig: &[u8], msg: &[u8]) -> Result<(), HybridFault> {
    let row = token_of_sig_alg(tag).ok_or(HybridFault::WrongRow)?;
    if key.alg() != row.token {
        return Err(HybridFault::WrongRow);
    }
    if sig.len() != row.sig_len() {
        return Err(HybridFault::Malformed);
    }
    let (pq_sig, ed_sig) = sig.split_at(row.pq_sig_len);
    let pq_key = key.pq_half().ok_or(HybridFault::WrongRow)?;
    // The Ed25519 half FIRST: cheap, and a failure here refuses before the
    // lattice arithmetic runs. Both are required, so the order moves no
    // verdict.
    let ed_key = EdVerifyingKey::from_bytes(key.ed25519_half()).map_err(|_| HybridFault::Rejected)?;
    let ed_sig = ed25519_dalek::Signature::from_slice(ed_sig).map_err(|_| HybridFault::Malformed)?;
    ed_key.verify_strict(msg, &ed_sig).map_err(|_| HybridFault::Rejected)?;
    let pq_ok = match tag {
        TAG_MLDSA65_ED25519 => {
            let enc = EncodedVerifyingKey::<MlDsa65>::try_from(pq_key)
                .map_err(|_| HybridFault::WrongRow)?;
            let vk = ml_dsa::VerifyingKey::<MlDsa65>::decode(&enc);
            let enc_sig =
                EncodedSignature::<MlDsa65>::try_from(pq_sig).map_err(|_| HybridFault::Malformed)?;
            let Some(sigma) = ml_dsa::Signature::<MlDsa65>::decode(&enc_sig) else {
                return Err(HybridFault::Rejected);
            };
            // The CTX PIN: the empty context string.
            vk.verify_with_context(msg, &[], &sigma)
        }
        TAG_FNDSA512_PREVIEW_ED25519 => {
            let vk = VerifyingKeyStandard::decode(pq_key).ok_or(HybridFault::WrongRow)?;
            vk.verify(pq_sig, &DOMAIN_NONE, &HASH_ID_RAW, msg)
        }
        _ => return Err(HybridFault::WrongRow),
    };
    if pq_ok {
        Ok(())
    } else {
        Err(HybridFault::Rejected)
    }
}

/// The widths a tag's rule fixes, restated from the crates' own constants so
/// a crate bump that moved one fails a test by name: (PQ key, PQ signature,
/// PQ signing key as stored).
pub fn pq_widths(tag: u8) -> Option<(usize, usize, usize)> {
    match tag {
        TAG_MLDSA65_ED25519 => Some((MLDSA65_KEY_LEN, 3309, 4032)),
        TAG_FNDSA512_PREVIEW_ED25519 => Some((
            vrfy_key_size(FN_DSA_LOGN_512),
            signature_size(FN_DSA_LOGN_512),
            sign_key_size(FN_DSA_LOGN_512),
        )),
        _ => None,
    }
}

/// Lowercase hex — the spelling `PublicKey::parse` reads.
pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// The token of the row a tag names — a convenience for callers holding the
/// marker byte.
pub fn token_of(tag: u8) -> Option<&'static str> {
    token_of_sig_alg(tag).map(|r| r.token)
}

/// The tag of the row a token names.
pub fn tag_of(token: &str) -> Option<u8> {
    sig_alg_of(token).map(|r| r.tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both tags: keygen from one seed is deterministic, the halves differ
    /// per tag (the token is in the KDF label), the widths are the ruled
    /// ones, a signature verifies, either half alone fails, another message
    /// fails, and the other tag's key refuses the row.
    #[test]
    fn both_tags_sign_verify_and_refuse_a_broken_half() {
        let seed = [0x42u8; 32];
        for tag in [TAG_MLDSA65_ED25519, TAG_FNDSA512_PREVIEW_ED25519] {
            let s1 = HybridSigner::from_seed(tag, &seed).unwrap();
            let s2 = HybridSigner::from_seed(tag, &seed).unwrap();
            assert_eq!(s1.public_key(), s2.public_key(), "keygen from seed is deterministic");
            let row = token_of_sig_alg(tag).unwrap();
            assert_eq!(s1.public_key().raw().len(), row.key_len());
            let msg = b"the entry frame";
            let mut rng = SeededRng06::new([7; 32]);
            let sig = s1.sign_with_rng(msg, &mut rng);
            assert_eq!(sig.len(), row.sig_len());
            assert_eq!(verify(tag, s1.public_key(), &sig, msg), Ok(()));
            assert_eq!(verify(tag, s1.public_key(), &sig, b"other"), Err(HybridFault::Rejected));
            // The Ed25519 half broken.
            let mut broken = sig.clone();
            broken[row.pq_sig_len] ^= 1;
            assert_eq!(verify(tag, s1.public_key(), &broken, msg), Err(HybridFault::Rejected));
            // The PQ half broken.
            let mut broken = sig.clone();
            broken[3] ^= 1;
            assert_eq!(verify(tag, s1.public_key(), &broken, msg), Err(HybridFault::Rejected));
            // The wrong width.
            assert_eq!(verify(tag, s1.public_key(), &sig[1..], msg), Err(HybridFault::Malformed));
            // The other tag's key.
            let other = if tag == 1 { 3 } else { 1 };
            let o = HybridSigner::from_seed(other, &seed).unwrap();
            assert_eq!(verify(tag, o.public_key(), &sig, msg), Err(HybridFault::WrongRow));
            assert_ne!(
                s1.ed25519_signing_key().to_bytes(),
                o.ed25519_signing_key().to_bytes(),
                "the Ed25519 half differs per tag: the token is in the KDF label"
            );
        }
        assert!(HybridSigner::from_seed(0, &seed).is_none());
        assert!(HybridSigner::from_seed(2, &seed).is_none());
        assert!(derive_seeds(2, &seed).is_none());
    }

    /// The KDF never hands either half the raw seed, and the two halves of
    /// one tag differ.
    #[test]
    fn the_kdf_derives_both_halves_and_neither_is_the_seed() {
        let seed = [0x01u8; 32];
        let h = derive_seeds(TAG_MLDSA65_ED25519, &seed).unwrap();
        assert_ne!(h.ed25519, seed);
        assert_ne!(h.pq, seed);
        assert_ne!(h.ed25519, h.pq);
        let h3 = derive_seeds(TAG_FNDSA512_PREVIEW_ED25519, &seed).unwrap();
        assert_ne!(h3.pq, h.pq);
        assert_ne!(h3.ed25519, h.ed25519);
    }
}
