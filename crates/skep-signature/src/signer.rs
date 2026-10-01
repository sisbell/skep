//! KEYGEN FROM A SEED AND SIGNING, per tag — [`HybridSigner`], which composes
//! both halves into one key and one blob, and `PqSigner`, which holds each
//! tag's post-quantum keygen and signature; and the two RNGs the FN-DSA
//! preview draws through: the exact bytes its keygen is fed (the KDF's half
//! seed) and the OS draw a signature's seed comes from. Compiled under
//! `sign`, which skepd leaves off, so the daemon's build holds none of it.
//! The signer's own two test hooks sit here, beside the private fields they
//! read, each gated on `test-hooks`.

use std::fmt;

use ed25519_dalek::{Signer as _, SigningKey as EdSigningKey};
use fn_dsa::{
    signature_size, sign_key_size, vrfy_key_size, KeyPairGenerator, KeyPairGeneratorStandard,
    SigningKey as _, SigningKeyStandard, DOMAIN_NONE, FN_DSA_LOGN_512, HASH_ID_RAW,
};
use ml_dsa::{Keypair as _, MlDsa65, Signer as _};
use skep_identity::{PublicKey, SigAlgRow};

use crate::kdf::derive_seeds;
use crate::Rule;

/// An RNG that yields EXACTLY the bytes it was given and then refuses — what
/// `fn-dsa` 0.4.0's keygen is fed so that its one 32-byte draw IS the KDF's
/// FN-DSA seed. A longer draw would be a keygen this build did not pin, and
/// under the frozen-tag rule a NEW tag; refusing it makes the rule loud. It
/// BORROWS the bytes: the KDF's half seed is lent to the keygen and never
/// copied onto the heap.
struct ExactBytes<'a> {
    bytes: &'a [u8],
    taken: usize,
}

impl rand_core_06::RngCore for ExactBytes<'_> {
    fn next_u32(&mut self) -> u32 {
        rand_core_06::impls::next_u32_via_fill(self)
    }
    fn next_u64(&mut self) -> u64 {
        rand_core_06::impls::next_u64_via_fill(self)
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

impl rand_core_06::CryptoRng for ExactBytes<'_> {}

/// The crate's one OS RNG, fail-stop: what a tag-3 signature draws its
/// 40-byte seed from outside a seeded fixture. Every draw comes from the OS
/// (`getrandom`), so a signature's seed is never a function of process state;
/// `rand_core` 0.6's traits, which `fn-dsa` 0.4.0 draws through.
struct OsEntropy;

impl rand_core_06::RngCore for OsEntropy {
    fn next_u32(&mut self) -> u32 {
        rand_core_06::impls::next_u32_via_fill(self)
    }
    fn next_u64(&mut self) -> u64 {
        rand_core_06::impls::next_u64_via_fill(self)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // Fail-stop: a signer that cannot draw OS entropy must not sign over
        // a seed from anything weaker.
        getrandom::fill(dest).expect("OS entropy unavailable");
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core_06::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core_06::CryptoRng for OsEntropy {}

/// The post-quantum half of a signer, per tag — and on this one card both
/// things its rule asks of it: keygen from the KDF's PQ half seed
/// (`PqSigner::keygen`) and the PQ signature (`PqSigner::sign`).
enum PqSigner {
    /// Tag 1: the expanded ML-DSA-65 signing key, from ξ.
    MlDsa65(ml_dsa::SigningKey<MlDsa65>),
    /// Tag 3: the FN-DSA-512 PREVIEW signing key in `fn-dsa` 0.4.0's
    /// encoding (`sign_key_size(FN_DSA_LOGN_512)` bytes — 1,345 at degree 9,
    /// its `f`, `g`, `F` and the hashed verifying key, which
    /// `sizes_and_timings_per_tag` pins), decoded per signature — the crate's
    /// `sign` takes `&mut self` and its key type zeroizes on drop.
    FnDsa512Preview(Vec<u8>),
}

impl PqSigner {
    /// KEYGEN of the post-quantum half under `rule`, from the KDF's PQ half
    /// seed by the pinned crate's own keygen: the signing half, and its
    /// verifying key's encoding — the half the KEY PIN puts first.
    /// ML-DSA-65's is `SigningKey::from_seed(ξ)`; the FN-DSA-512 preview's is
    /// `fn-dsa` 0.4.0's keygen fed `seed` through `ExactBytes`, and checked to
    /// have drawn all 32 bytes.
    fn keygen(rule: Rule, seed: &[u8; 32]) -> (PqSigner, Vec<u8>) {
        match rule {
            Rule::MlDsa65Ed25519 => {
                let sk = ml_dsa::SigningKey::<MlDsa65>::from_seed(&(*seed).into());
                let pk = sk.verifying_key().encode();
                (PqSigner::MlDsa65(sk), pk.as_slice().to_vec())
            }
            Rule::FnDsa512PreviewEd25519 => {
                let mut rng = ExactBytes { bytes: seed, taken: 0 };
                let mut sk = vec![0u8; sign_key_size(FN_DSA_LOGN_512)];
                let mut pk = vec![0u8; vrfy_key_size(FN_DSA_LOGN_512)];
                KeyPairGeneratorStandard::default().keygen(
                    FN_DSA_LOGN_512,
                    &mut rng,
                    &mut sk,
                    &mut pk,
                );
                assert_eq!(rng.taken, 32, "fn-dsa 0.4.0's keygen draws its one 32-byte seed");
                (PqSigner::FnDsa512Preview(sk), pk)
            }
        }
    }

    /// THE POST-QUANTUM SIGNATURE over `msg` under this half's rule:
    /// ML-DSA-65's deterministic variant with the empty `ctx`, drawing
    /// nothing; the FN-DSA-512 preview's randomized signing with
    /// `DOMAIN_NONE` and `HASH_ID_RAW`, its per-signature seed drawn from
    /// `rng` and its key decoded from the stored bytes for this one signature
    /// (`fn-dsa`'s `sign` takes `&mut self`).
    fn sign<R: rand_core_06::CryptoRng + rand_core_06::RngCore>(
        &self,
        msg: &[u8],
        rng: &mut R,
    ) -> Vec<u8> {
        match self {
            PqSigner::MlDsa65(sk) => sk.sign(msg).encode().as_slice().to_vec(),
            PqSigner::FnDsa512Preview(sk_bytes) => {
                let mut sk = SigningKeyStandard::decode(sk_bytes)
                    .expect("this signer's own encoded key decodes");
                let mut sig = vec![0u8; signature_size(FN_DSA_LOGN_512)];
                sk.sign(rng, &DOMAIN_NONE, &HASH_ID_RAW, msg, &mut sig)
                    .expect("a valid signing key signs");
                sig
            }
        }
    }
}

/// ONE HYBRID SIGNER: both halves derived from one seed under one tag, its
/// public key the `alg` and `key` of ONE key entry — one `ALGS` token over
/// one concatenated raw value (wire.md). Holds private-key material and
/// prints none of it.
pub struct HybridSigner {
    row: &'static SigAlgRow,
    ed: EdSigningKey,
    pq: PqSigner,
    public: PublicKey,
}

impl fmt::Debug for HybridSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HybridSigner(tag {}, {:?})", self.row.tag, self.public)
    }
}

impl HybridSigner {
    /// KEYGEN FROM SEED under `tag`'s frozen rule: the KDF's two half seeds,
    /// the Ed25519 key from its half, the PQ key from its half by the pinned
    /// crate's own keygen (`PqSigner::keygen`), and the two public halves
    /// composed into one key by the KEY PIN. `None` for a tag no row names or
    /// this build holds no rule for.
    pub fn from_seed(tag: u8, seed: &[u8; 32]) -> Option<HybridSigner> {
        let row = SigAlgRow::of_tag(tag)?;
        let halves = derive_seeds(tag, seed)?;
        let ed = EdSigningKey::from_bytes(&halves.ed25519);
        let ed_pk = ed.verifying_key().to_bytes();
        let (pq, pq_pk) = PqSigner::keygen(Rule::of(tag)?, &halves.pq);
        let public = PublicKey::from_halves(row.token, &pq_pk, &ed_pk)
            .expect("the pinned crate's post-quantum key is the row's width");
        Some(HybridSigner { row, ed, pq, public })
    }

    /// This signer's public key — the `alg` and `key` of ONE key entry, one
    /// `ALGS` token over the two halves' concatenated raw value (wire.md).
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// The marker tag this signer signs under.
    pub fn tag(&self) -> u8 {
        self.row.tag
    }

    /// TEST HOOK (the `fuzz_support` standing: `#[doc(hidden)]`, not a stable
    /// API) — the Ed25519 half's signing key, ONE of the two halves every blob
    /// this signer makes carries, a session's and an entry's alike; alone it
    /// opens nothing (no half opens a session alone). This crate's own tests
    /// read it (the Ed25519 half differs per tag), skepd's fixtures check
    /// that it differs from the raw seed and matches the enrolled key's
    /// Ed25519 half, and the suites' negative vector — a 64-byte Ed25519-only
    /// `sig`, the classical layout no served board admits — is made with it.
    /// Hidden because its type is `ed25519-dalek`'s: a caller holding one
    /// names that crate at this crate's version.
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    pub fn ed25519_signing_key(&self) -> &EdSigningKey {
        &self.ed
    }

    /// TEST HOOK (the same standing) — [`HybridSigner::sign`] with tag 3's
    /// per-signature seed drawn from `rng`: the fixtures' door, handed a
    /// `SeededRng06` so a tag-3 golden is byte-stable (tag 1 draws nothing).
    /// Hidden because its bound is `rand_core` 0.6's — the version `fn-dsa`
    /// 0.4.0 draws through, which a caller's own RNG would have to match —
    /// and compiled only under `test-hooks`, as every fixture hook here is:
    /// a shipped build signs through [`HybridSigner::sign`] alone, over the
    /// OS's draw.
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    pub fn sign_with_rng<R: rand_core_06::CryptoRng + rand_core_06::RngCore>(
        &self,
        msg: &[u8],
        rng: &mut R,
    ) -> Vec<u8> {
        self.sign_drawing(msg, rng)
    }

    /// SIGN `msg` under the tag's rule: the PQ signature THEN the Ed25519
    /// signature over the same bytes — the blob a marker slot carries, and a
    /// session's `sig`. Tag 1 is deterministic (FIPS 204's deterministic
    /// variant, empty `ctx`); tag 3 draws its per-signature seed from OS
    /// entropy, and PANICS where the OS refuses it: the draw is the crate's
    /// fail-stop OS source (`OsEntropy`), so a tag-3 signature is never made
    /// over a seed from anything weaker. Tag 1 draws nothing, so this panic
    /// is tag 3's alone.
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.sign_drawing(msg, &mut OsEntropy)
    }

    /// The one signing body, over the RNG tag 3's per-signature seed is drawn
    /// from — the OS's for [`HybridSigner::sign`], a fixture's stream for the
    /// test hook `sign_with_rng` — private, so no shipped caller picks the
    /// draw. It composes THE BLOB: the PQ half's signature
    /// (`PqSigner::sign`) THEN the Ed25519 signature, over the same `msg`.
    fn sign_drawing<R: rand_core_06::CryptoRng + rand_core_06::RngCore>(
        &self,
        msg: &[u8],
        rng: &mut R,
    ) -> Vec<u8> {
        let mut blob = self.pq.sign(msg, rng);
        blob.extend_from_slice(&self.ed.sign(msg).to_bytes());
        debug_assert_eq!(blob.len(), self.row.sig_len());
        blob
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hooks::SeededRng06;
    use crate::{TAG_FNDSA512_PREVIEW_ED25519, TAG_MLDSA65_ED25519};

    /// Lowercase hex, two digits a byte — skepd's `codec::hex_string`'s output,
    /// the spelling [`private_key_material_prints_none_of_itself`] looks for.
    fn hex_string(b: &[u8]) -> String {
        b.iter().map(|byte| format!("{byte:02x}")).collect()
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

    /// THE PQ HALF ON ITS OWN CARD: `PqSigner::keygen` makes the public key's
    /// first half and `PqSigner::sign` the blob's first field — the KEY PIN
    /// and THE BLOB, the PQ half THEN the Ed25519 one — so `HybridSigner`
    /// composes the two halves and holds no tag's arithmetic itself.
    #[test]
    fn the_pq_half_makes_the_keys_first_half_and_the_blobs_first_field() {
        let seed = [0x42u8; 32];
        let msg = b"the entry frame";
        for tag in [TAG_MLDSA65_ED25519, TAG_FNDSA512_PREVIEW_ED25519] {
            let signer = HybridSigner::from_seed(tag, &seed).unwrap();
            let halves = derive_seeds(tag, &seed).unwrap();
            let (pq, pq_pk) = PqSigner::keygen(Rule::of(tag).unwrap(), &halves.pq);
            assert_eq!(
                &pq_pk[..],
                signer.public_key().pq_half(),
                "tag {tag}: the key's first half"
            );
            let blob = signer.sign_with_rng(msg, &mut SeededRng06::new([7; 32]));
            let pq_sig = pq.sign(msg, &mut SeededRng06::new([7; 32]));
            assert_eq!(&blob[..pq_sig.len()], &pq_sig[..], "tag {tag}: the blob's first field");
        }
    }
}
