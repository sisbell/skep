//! KEYGEN FROM A SEED AND SIGNING, per tag — [`HybridSigner`], which composes
//! both halves into one key and one blob, and `PqSigner`, which holds each
//! tag's post-quantum keygen and signature; and the two RNGs the FN-DSA
//! preview draws through: the exact bytes its keygen is fed (the KDF's half
//! seed) and the OS draw a signature's seed comes from. Compiled under
//! `sign`, which skepd leaves off, so the daemon's build holds none of it.
//! Its own test hooks sit here, beside the private fields they read, each
//! gated on `test-hooks`.

use std::fmt;

use ed25519_dalek::{Signer as _, SigningKey as EdSigningKey};
use fn_dsa::{
    sign_key_size, vrfy_key_size, KeyPairGenerator, KeyPairGeneratorStandard, SigningKey as _,
    SigningKeyStandard, DOMAIN_NONE, FN_DSA_LOGN_512, HASH_ID_RAW,
};
use ml_dsa::{Keypair as _, MlDsa65, Signer as _};
use skep_identity::{PublicKey, SigAlgRow};
use zeroize::Zeroizing;

use crate::kdf::derive_half_seeds;
use crate::Rule;

/// An RNG that yields EXACTLY the bytes it was given and then refuses — what
/// `fn-dsa` 0.4.0's keygen is fed so that its one 32-byte draw IS the KDF's
/// PQ half seed. A longer draw would be a keygen this build did not pin, and
/// under the frozen-tag rule a NEW tag; refusing it makes the rule loud. It
/// BORROWS the bytes: the KDF's half seed is lent to the keygen and never
/// copied onto the heap.
struct ExactBytes<'a> {
    bytes: &'a [u8],
    drawn: usize,
}

impl rand_core_06::RngCore for ExactBytes<'_> {
    fn next_u32(&mut self) -> u32 {
        rand_core_06::impls::next_u32_via_fill(self)
    }
    fn next_u64(&mut self) -> u64 {
        rand_core_06::impls::next_u64_via_fill(self)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let end = self.drawn + dest.len();
        assert!(
            end <= self.bytes.len(),
            "fn-dsa 0.4.0's keygen draws exactly {} bytes; a longer draw ({} so far) is a keygen \
             this build did not pin — a NEW tag under the frozen-tag rule",
            self.bytes.len(),
            end
        );
        dest.copy_from_slice(&self.bytes[self.drawn..end]);
        self.drawn = end;
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
/// (`PqSigner::keygen`) and the PQ signature (`PqSigner::sign_into`).
enum PqSigner {
    /// Tag 1: `ml-dsa`'s ML-DSA-65 signing key from ξ — the expanded key that
    /// signs, beside the verifying key and ξ itself, which `ml-dsa` keeps in
    /// it.
    MlDsa65(ml_dsa::SigningKey<MlDsa65>),
    /// Tag 3: the FN-DSA-512 PREVIEW signing key in `fn-dsa` 0.4.0's
    /// encoding (`sign_key_size(FN_DSA_LOGN_512)` bytes — 1,345 at degree 9,
    /// its `f`, `g`, `F` and the hashed verifying key, which
    /// `sizes_and_timings_per_tag` pins), decoded afresh for each signature
    /// because the crate's `sign` takes `&mut self`. The decoded key wipes
    /// itself on drop (`fn-dsa`'s own), and so do these stored bytes
    /// (`Zeroizing`; see [`HybridSigner`]).
    FnDsa512Preview(Zeroizing<Vec<u8>>),
}

impl PqSigner {
    /// KEYGEN of the post-quantum half under `rule`, from `half_seed`, the
    /// KDF's PQ half seed, by the pinned crate's own keygen: the signing half,
    /// and its verifying key's encoding — the half the KEY PIN puts first.
    /// ML-DSA-65's is `SigningKey::from_seed(ξ)`; the FN-DSA-512 preview's is
    /// `fn-dsa` 0.4.0's keygen fed `half_seed` through `ExactBytes`, and
    /// checked to have drawn all 32 bytes.
    fn keygen(rule: Rule, half_seed: &[u8; 32]) -> (PqSigner, Vec<u8>) {
        match rule {
            Rule::MlDsa65Ed25519 => {
                // ξ lent as `ml-dsa`'s `&Seed` (`hybrid-array` borrows a
                // `&[u8; 32]` as a `&Array<u8, U32>`), so no second copy of it
                // is made here; `ml-dsa` keeps its own inside the key.
                let sk = ml_dsa::SigningKey::<MlDsa65>::from_seed(half_seed.into());
                let pk = sk.verifying_key().encode();
                (PqSigner::MlDsa65(sk), pk.as_slice().to_vec())
            }
            Rule::FnDsa512PreviewEd25519 => {
                let mut rng = ExactBytes { bytes: half_seed, drawn: 0 };
                let mut sk = Zeroizing::new(vec![0u8; sign_key_size(FN_DSA_LOGN_512)]);
                let mut pk = vec![0u8; vrfy_key_size(FN_DSA_LOGN_512)];
                KeyPairGeneratorStandard::default().keygen(
                    FN_DSA_LOGN_512,
                    &mut rng,
                    &mut sk,
                    &mut pk,
                );
                assert_eq!(
                    rng.drawn, 32,
                    "fn-dsa 0.4.0's keygen draws the whole 32-byte half seed"
                );
                (PqSigner::FnDsa512Preview(sk), pk)
            }
        }
    }

    /// THE POST-QUANTUM SIGNATURE over `msg` under this half's rule, written
    /// into `field` — the blob's first field, exactly this rule's width
    /// (`SigAlgRow::pq_sig_len`), the out-slice `fn-dsa`'s own `sign` takes:
    /// ML-DSA-65's deterministic variant with the empty `ctx`, drawing
    /// nothing; the FN-DSA-512 preview's randomized signing with
    /// `DOMAIN_NONE` and `HASH_ID_RAW`, its per-signature seed drawn from
    /// `rng` and its key decoded from the stored bytes for this one signature
    /// (`fn-dsa`'s `sign` takes `&mut self`). A `field` of any other width
    /// would mean the row and the pinned crate disagree, which
    /// `sizes_and_timings_per_tag` rules out; that disagreement panics where
    /// the field is written — at the ML-DSA-65 copy, at `fn-dsa`'s own width
    /// assertion — so no blob is ever handed out at a width its crate did not
    /// sign.
    fn sign_into(&self, rng: &mut impl rand_core_06::CryptoRngCore, msg: &[u8], field: &mut [u8]) {
        match self {
            PqSigner::MlDsa65(sk) => field.copy_from_slice(sk.sign(msg).encode().as_slice()),
            PqSigner::FnDsa512Preview(sk_bytes) => {
                let mut sk = SigningKeyStandard::decode(sk_bytes)
                    .expect("this signer's own encoded key decodes");
                sk.sign(rng, &DOMAIN_NONE, &HASH_ID_RAW, msg, field)
                    .expect("a valid signing key signs");
            }
        }
    }
}

/// ONE HYBRID SIGNER: both halves derived from one seed under one tag, its
/// public key the `alg` and `key` of ONE key entry — one `ALGS` token over
/// one concatenated raw value (wire.md). Holds private-key material and
/// prints none of it.
///
/// DROPPING IT WIPES EVERY KEY IT HOLDS: the Ed25519 key (`ed25519-dalek`'s
/// default `zeroize` feature); the ML-DSA-65 key — ξ and the expanded key
/// beside it (`ml-dsa`'s `zeroize` feature); and the stored FN-DSA-512
/// encoding (a `Zeroizing` vector — the key each tag-3 signature decodes
/// from it wipes itself, `fn-dsa`'s own). The half seeds
/// [`HybridSigner::from_seed`] derives are wiped as they go out of scope
/// inside it, once each half has been handed to its keygen (`HalfSeeds`).
/// WHAT IS NOT WIPED, by name: the KDF's working state — `hkdf` 0.12's, and
/// that of the `hmac` 0.12 and `digest` 0.10 it runs on, which wipe nothing
/// they drop and which this crate cannot reach: a copy of the seed itself,
/// as Extract's HMAC buffers it, and what derives from it on the way to the
/// half seeds — the PRK, the HMAC state keyed by it, and each Expand's
/// output block, a copy of that half seed. All of it is released before
/// `from_seed` keygens either half, and holding a copy of the seed, it tells
/// no more than the seed does. And the caveat every wipe carries: a copy the
/// compiler makes when a value is moved is beyond any crate's reach. The
/// signer's wiping test holds this paragraph to the build, type by type.
pub struct HybridSigner {
    ed: EdSigningKey,
    pq: PqSigner,
    public: PublicKey,
}

impl fmt::Debug for HybridSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HybridSigner(tag {}, {:?})", self.tag(), self.public)
    }
}

impl HybridSigner {
    /// KEYGEN FROM SEED under `tag`'s frozen rule: the KDF's two half seeds,
    /// the Ed25519 key from its half, the PQ key from its half by the pinned
    /// crate's own keygen (`PqSigner::keygen`), and the two public halves
    /// composed into one key by the KEY PIN. `None` for a tag no row names or
    /// this build holds no rule for; on `Some`, the signer's
    /// [`tag`](HybridSigner::tag) is `tag`, and its key is a function of `tag`
    /// and `seed` alone — the same seed derives the same key every time,
    /// which is what lets one 64-hex seed back a key up.
    pub fn from_seed(tag: u8, seed: &[u8; 32]) -> Option<HybridSigner> {
        let row = SigAlgRow::of_tag(tag)?;
        let halves = derive_half_seeds(tag, seed)?;
        let ed = EdSigningKey::from_bytes(&halves.ed25519);
        let ed_pk = ed.verifying_key().to_bytes();
        let (pq, pq_pk) = PqSigner::keygen(Rule::of(tag)?, &halves.pq);
        let public = PublicKey::from_halves(row.token, &pq_pk, &ed_pk)
            .expect("the pinned crate's post-quantum key is the row's width");
        Some(HybridSigner { ed, pq, public })
    }

    /// This signer's public key — the `alg` and `key` of ONE key entry, one
    /// `ALGS` token over the two halves' concatenated raw value (wire.md).
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// The marker tag this signer signs under — its public key's row's, so
    /// the tag and the key never disagree.
    pub fn tag(&self) -> u8 {
        self.public.sig_alg_row().tag
    }

    /// TEST HOOK (the `fuzz_support` standing: `#[doc(hidden)]`, not a stable
    /// API) — the Ed25519 half's signing key, which makes the Ed25519 half of
    /// every blob this signer makes, a session's, an entry's and a record's
    /// alike; alone it opens nothing (no half opens a session alone). This
    /// crate's own tests read it (the Ed25519 half differs per tag), skepd's
    /// fixtures check that it differs from the raw seed and matches the
    /// enrolled key's Ed25519 half, and the suites' negative vector — a bare
    /// Ed25519 signature as the `sig`, the classical layout no served board
    /// admits — is made with it. Handed out as the suites' own
    /// [`Ed25519SigningKey`](crate::hooks::Ed25519SigningKey) — a copy of the
    /// half, wiped on drop as the original is — so no caller names
    /// `ed25519-dalek`'s type; and it is the one way a suite gets one, so
    /// every Ed25519 key a suite signs with is a hybrid's derived half and
    /// never a raw seed's.
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    pub fn ed25519_signing_key(&self) -> crate::hooks::Ed25519SigningKey {
        crate::hooks::Ed25519SigningKey(self.ed.clone())
    }

    /// TEST HOOK (the same standing) — [`HybridSigner::sign`] with tag 3's
    /// per-signature seed drawn from `rng`, the fixtures' seeded stream, so a
    /// tag-3 golden is byte-stable (tag 1 draws nothing). The RNG comes first,
    /// as in every `sign_with_rng` a Rust caller already knows (`signature`'s
    /// `RandomizedSigner`, `fips204`'s `try_sign_with_rng`), and it is the
    /// fixtures' own stream rather than any `rand_core` 0.6 RNG, so the hook
    /// names no `rand_core` version. Compiled only under `test-hooks`, as
    /// every fixture hook here is: a shipped build signs through
    /// [`HybridSigner::sign`] alone, over the OS's draw.
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    pub fn sign_with_rng(&self, rng: &mut crate::hooks::SeededRng06, msg: &[u8]) -> Vec<u8> {
        self.sign_drawing(rng, msg)
    }

    /// SIGN `msg` under the tag's rule: the PQ signature THEN the Ed25519
    /// signature over the same bytes — THE BLOB, whichever carrier takes it:
    /// an entry's `attest`, a credential record's `sig`, a session's `sig`.
    /// Tag 1 is deterministic (FIPS 204's deterministic variant, empty
    /// `ctx`); tag 3 draws its per-signature seed from OS entropy, and PANICS
    /// where the OS refuses it: the draw is the crate's fail-stop OS source
    /// (`OsEntropy`), so a tag-3 signature is never made over a seed from
    /// anything weaker. Tag 1 draws nothing, so this panic is tag 3's alone.
    /// Whatever it draws, the blob is its row's `sig_len()` bytes and
    /// [`verify`](crate::verify) passes it under this signer's
    /// [`tag`](HybridSigner::tag) and [`public_key`](HybridSigner::public_key)
    /// over `msg` — the round trip every carrier rests on.
    #[must_use = "sign returns the blob; the signer keeps no copy of it"]
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.sign_drawing(&mut OsEntropy, msg)
    }

    /// The one signing body, over the RNG tag 3's per-signature seed is drawn
    /// from — the OS's for [`HybridSigner::sign`], a fixture's stream for the
    /// test hook `sign_with_rng` — private, so no shipped caller picks the
    /// draw. It writes THE BLOB at its row's width, parted where
    /// [`verify`](crate::verify) parts it: the PQ half's signature into the
    /// first field (`PqSigner::sign_into`), the Ed25519 signature into the
    /// last 64 bytes, over the same `msg`.
    fn sign_drawing(&self, rng: &mut impl rand_core_06::CryptoRngCore, msg: &[u8]) -> Vec<u8> {
        let mut blob = vec![0u8; self.public.sig_alg_row().sig_len()];
        let (pq_field, ed_field) = blob
            .split_last_chunk_mut::<{ ed25519_dalek::SIGNATURE_LENGTH }>()
            .expect("a row's blob is its post-quantum field and the Ed25519 signature's 64 bytes");
        self.pq.sign_into(rng, msg, pq_field);
        *ed_field = self.ed.sign(msg).to_bytes();
        blob
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hooks::{Seed, SeededRng06};
    use crate::{TAG_FNDSA512_PREVIEW_ED25519, TAG_MLDSA65_ED25519};

    /// Lowercase hex, two digits a byte — skepd's `codec::hex_string`'s output,
    /// the spelling [`private_key_material_prints_none_of_itself`] looks for.
    fn hex_string(b: &[u8]) -> String {
        b.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// PRIVATE-KEY MATERIAL PRINTS NONE OF ITSELF: `{:?}` of `HalfSeeds`, a
    /// `HybridSigner` of either tag and the Ed25519 half it hands out, and the
    /// fixtures' `SeededRng06` and `Seed` — what a log line, an assertion's
    /// message or a panic carries — holds neither the seed, nor a half seed,
    /// nor the Ed25519 signing key, nor the FN-DSA signing key the tag-3
    /// signer stores as bytes, in the decimal list a derived `Debug` prints or
    /// in hex. The hand-written impls are all that stands between a
    /// `#[derive(Debug)]` and a production key's ξ in a log.
    #[test]
    fn private_key_material_prints_none_of_itself() {
        let seed = [0x42u8; 32];
        let leaks = |printed: &str, secret: &[u8]| {
            printed.contains(&format!("{secret:?}")) || printed.contains(&hex_string(secret))
        };
        for tag in [TAG_MLDSA65_ED25519, TAG_FNDSA512_PREVIEW_ED25519] {
            let halves = derive_half_seeds(tag, &seed).unwrap();
            let signer = HybridSigner::from_seed(tag, &seed).unwrap();
            let mut secrets = vec![
                seed.to_vec(),
                halves.ed25519.to_vec(),
                halves.pq.to_vec(),
                signer.ed.to_bytes().to_vec(),
            ];
            if let PqSigner::FnDsa512Preview(sk) = &signer.pq {
                secrets.push(sk.to_vec());
            }
            let half = signer.ed25519_signing_key();
            for printed in [format!("{halves:?}"), format!("{signer:?}"), format!("{half:?}")] {
                for secret in &secrets {
                    assert!(
                        !leaks(&printed, &secret[..]),
                        "tag {tag} prints private-key material: {printed}"
                    );
                }
            }
        }
        for printed in
            [format!("{:?}", SeededRng06::new(seed)), format!("{:?}", Seed::from_bytes(&seed))]
        {
            assert!(!leaks(&printed, &seed[..]), "a fixture hook prints its seed: {printed}");
        }
    }

    /// THE PQ HALF ON ITS OWN CARD: `PqSigner::keygen` makes the public key's
    /// first half and `PqSigner::sign_into` writes the blob's first field —
    /// the KEY PIN and THE BLOB, the PQ half THEN the Ed25519 one — so
    /// `HybridSigner` composes the two halves and holds no tag's arithmetic
    /// itself.
    #[test]
    fn the_pq_half_makes_the_keys_first_half_and_the_blobs_first_field() {
        let seed = [0x42u8; 32];
        let msg = b"the entry frame";
        for tag in [TAG_MLDSA65_ED25519, TAG_FNDSA512_PREVIEW_ED25519] {
            let signer = HybridSigner::from_seed(tag, &seed).unwrap();
            let halves = derive_half_seeds(tag, &seed).unwrap();
            let (pq, pq_pk) = PqSigner::keygen(Rule::of(tag).unwrap(), &halves.pq);
            assert_eq!(
                &pq_pk[..],
                signer.public_key().pq_half(),
                "tag {tag}: the key's first half"
            );
            let blob = signer.sign_with_rng(&mut SeededRng06::new([7; 32]), msg);
            let pq_sig_len = signer.public_key().sig_alg_row().pq_sig_len;
            let mut pq_sig = vec![0u8; pq_sig_len];
            pq.sign_into(&mut SeededRng06::new([7; 32]), msg, &mut pq_sig);
            assert_eq!(&blob[..pq_sig_len], &pq_sig[..], "tag {tag}: the blob's first field");
        }
    }

    /// `PqSigner::sign_into` WRITES ITS RULE'S WIDTH OR NOTHING: handed a
    /// field one byte short or one byte long of the row's post-quantum width,
    /// either tag's half panics where it writes — the ML-DSA-65 copy,
    /// `fn-dsa`'s own width assertion — rather than fill part of it: a row its
    /// pinned crate disagreed with makes `sign` panic, never a blob.
    #[test]
    fn the_pq_half_refuses_a_field_of_any_width_but_its_rules() {
        let msg = b"the entry frame";
        for tag in [TAG_MLDSA65_ED25519, TAG_FNDSA512_PREVIEW_ED25519] {
            let halves = derive_half_seeds(tag, &[0x42; 32]).unwrap();
            let (pq, _) = PqSigner::keygen(Rule::of(tag).unwrap(), &halves.pq);
            let pq_sig_len = SigAlgRow::of_tag(tag).unwrap().pq_sig_len;
            for len in [pq_sig_len - 1, pq_sig_len + 1] {
                let written = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    pq.sign_into(&mut SeededRng06::new([7; 32]), msg, &mut vec![0u8; len]);
                }));
                assert!(written.is_err(), "tag {tag}: a {len}-byte field was signed into");
            }
        }
    }

    /// `sign`'S DRAWS, AS ITS DOC STATES THEM: tag 1 draws nothing — a stream
    /// handed to it is where it began, and two `sign`s over one message are
    /// byte-equal — while tag 3 draws a fresh per-signature seed from the OS at
    /// every `sign`: two blobs' post-quantum fields differ (two 40-byte OS draws
    /// agree once in 2^320), their Ed25519 fields agree (Ed25519 signs
    /// deterministically), and both verify. A signer that drew tag 3's seed from
    /// anything fixed would make the two equal.
    #[test]
    fn sign_draws_nothing_under_tag_1_and_a_fresh_os_seed_under_tag_3() {
        let msg = b"the entry frame";
        for tag in [TAG_MLDSA65_ED25519, TAG_FNDSA512_PREVIEW_ED25519] {
            let signer = HybridSigner::from_seed(tag, &[0x42; 32]).unwrap();
            let mut stream = SeededRng06::new([7; 32]);
            let _ = signer.sign_with_rng(&mut stream, msg);
            let untouched = rand_core_06::RngCore::next_u64(&mut stream)
                == rand_core_06::RngCore::next_u64(&mut SeededRng06::new([7; 32]));
            assert_eq!(untouched, tag == TAG_MLDSA65_ED25519, "tag {tag}: what its signing drew");
            let (first, second) = (signer.sign(msg), signer.sign(msg));
            for blob in [&first, &second] {
                assert_eq!(crate::verify(tag, signer.public_key(), msg, blob), Ok(()), "tag {tag}");
            }
            let pq_sig_len = signer.public_key().sig_alg_row().pq_sig_len;
            assert_eq!(
                first[pq_sig_len..],
                second[pq_sig_len..],
                "tag {tag}: Ed25519 signs deterministically"
            );
            assert_eq!(
                first[..pq_sig_len] == second[..pq_sig_len],
                tag == TAG_MLDSA65_ED25519,
                "tag {tag}: the post-quantum field repeats under tag 1 alone"
            );
        }
    }

    /// WHAT A DROPPED SIGNER WIPES, as [`HybridSigner`]'s doc states it, read
    /// off each type's `ZeroizeOnDrop` in this very build: the Ed25519 signing
    /// key, the FN-DSA key each tag-3 signature decodes, the stored FN-DSA
    /// encoding it decodes from, the ML-DSA-65 key and the KDF's half seeds
    /// wipe themselves; the KDF's working state does not — Extract's HMAC,
    /// which buffers a copy of the seed, the `Output` the PRK and each
    /// Expand's block are held in, and the `Hkdf` keyed by the PRK — the
    /// residue the doc names. A feature line, a derive or a field type that
    /// moves any of the eight fails here, so the doc moves with it.
    #[test]
    fn a_dropped_signer_wipes_both_keys_and_the_half_seeds_but_not_the_kdf_state() {
        use std::marker::PhantomData;
        use zeroize::ZeroizeOnDrop;
        /// `Probe::<T>::WIPES` is `true` exactly where `T: ZeroizeOnDrop`: the
        /// inherent const, which path resolution prefers, exists only then,
        /// and the trait's `false` answers everywhere else.
        struct Probe<T>(PhantomData<T>);
        trait Unwiped {
            const WIPES: bool = false;
        }
        impl<T> Unwiped for Probe<T> {}
        impl<T: ZeroizeOnDrop> Probe<T> {
            const WIPES: bool = true;
        }
        // The stored encoding's type, read off a tag-3 signer's own field:
        // a field typed otherwise fails to compile here, so the probe below
        // asks about the type the signer holds.
        let tag3 = HybridSigner::from_seed(TAG_FNDSA512_PREVIEW_ED25519, &[0x42; 32]).unwrap();
        let _: &Zeroizing<Vec<u8>> = match &tag3.pq {
            PqSigner::FnDsa512Preview(stored) => stored,
            PqSigner::MlDsa65(_) => panic!("tag 3 stores its FN-DSA key as bytes"),
        };
        assert_eq!(
            [
                Probe::<EdSigningKey>::WIPES,
                Probe::<SigningKeyStandard>::WIPES,
                Probe::<Zeroizing<Vec<u8>>>::WIPES,
                Probe::<ml_dsa::SigningKey<MlDsa65>>::WIPES,
                Probe::<crate::kdf::HalfSeeds>::WIPES,
                Probe::<hkdf::HkdfExtract<sha2::Sha256>>::WIPES,
                Probe::<sha2::digest::Output<sha2::Sha256>>::WIPES,
                Probe::<hkdf::Hkdf<sha2::Sha256>>::WIPES,
            ],
            [true, true, true, true, true, false, false, false],
            "wiped on drop: the Ed25519 key, the decoded FN-DSA key and its stored encoding, the \
             ML-DSA-65 key and the half seeds; not the KDF's working state — Extract's HMAC with \
             its copy of the seed, the `Output` the PRK and each Expand's block are held in, the \
             `Hkdf` keyed by the PRK — which no crate in this build overwrites: `HybridSigner`'s \
             doc"
        );
    }
}
