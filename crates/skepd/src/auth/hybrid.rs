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
//!   string — the CTX PIN: the entry frame's framing tag, `ENTRY_TAG`
//!   (AUTH-1.11), is the domain separation, and `ml-dsa`'s `Signer` supports
//!   only the empty `ctx`.
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
//! in the `info`), one derived half's leak reveals neither the seed nor the
//! other half (HKDF is one-way), and the paper backup stays one 64-hex
//! seed. The Ed25519 half's 32 bytes are `ed25519-dalek`'s seed
//! (`SigningKey::from_bytes`); the ML-DSA half's are FIPS 204's ξ; the
//! FN-DSA half's are the bytes `fn-dsa` 0.4.0's keygen draws.
//!
//! THE KEY PIN: a hybrid's raw public key is the PQ half's encoding THEN the
//! Ed25519 half's 32 bytes ([`skep_identity::PublicKey`]'s arms). THE BLOB:
//! the PQ signature THEN the Ed25519 signature's 64 bytes, two fixed-width
//! fields, no length prefix (the record §2.4) — the marker slot's blob and,
//! since the hybrid handshake (the hybrid-only launch, owner 2026-09-26), a
//! session's `sig` over the session bytes too (AUTH-4.32, AUTH-6.3). VERIFY
//! is BOTH halves over the SAME bytes — either failing fails (the ruled
//! "hybrid, both halves verify"); no half opens a session alone.
//!
//! What lives here beside the daemon's verify and all-halves decode —
//! keygen and signing — is the signer's side, used by the suites' test
//! signer and by the goldens that pin each tag's rule; the daemon itself
//! holds no key and never signs.

use std::fmt;

use ed25519_dalek::{Signer as _, SigningKey as EdSigningKey, VerifyingKey as EdVerifyingKey};
use fn_dsa::{
    signature_size, sign_key_size, vrfy_key_size, KeyPairGenerator, KeyPairGeneratorStandard,
    SigningKey as _, SigningKeyStandard, VerifyingKey as _, VerifyingKeyStandard,
    DOMAIN_NONE, FN_DSA_LOGN_512, HASH_ID_RAW,
};
use hkdf::Hkdf;
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, ExpandedSigningKeyBytes, Keypair as _, MlDsa65,
    Signer as _,
};
use sha2::Sha256;
use skep_identity::{token_of_sig_alg, PublicKey, SigAlgRow};

use super::OsEntropy;
use crate::codec::hex_string;

/// The marker tag of the PRODUCTION row, `mldsa65-ed25519` (ML-DSA-65 +
/// Ed25519).
pub const TAG_MLDSA65_ED25519: u8 = 1;
/// The marker tag of the PREVIEW row, `fndsa512-preview-ed25519` (the
/// FN-DSA-512 preview + Ed25519).
pub const TAG_FNDSA512_PREVIEW_ED25519: u8 = 3;

/// The rules this module holds, one per marker tag — the ONE statement of
/// which tags this build can derive, keygen, decode and verify under.
/// Every per-tag step below matches on it exhaustively — the PQ half's KDF
/// label, its keygen, its decode, its widths — beside the signer and
/// verifier enums that already carry one variant per rule ([`PqSigner`],
/// [`PqHalf`]), so a new tag (tag 2 is free for the final FIPS 206 — whose
/// variant takes the unqualified token name, `FnDsa512Ed25519`; the preview
/// carries `Preview` in every name, as its token does, so the final
/// standard's arms never share a name with it) is one variant here and one
/// arm in [`Rule::of`], and the compiler names every step that must learn
/// it. Each variant is its row's token in CamelCase, as
/// [`super::session::SessionSig`]'s are.
#[derive(Clone, Copy)]
enum Rule {
    /// Tag 1: ML-DSA-65 + Ed25519 (`mldsa65-ed25519`).
    MlDsa65Ed25519,
    /// Tag 3: the FN-DSA-512 PREVIEW + Ed25519 (`fndsa512-preview-ed25519`).
    FnDsa512PreviewEd25519,
}

impl Rule {
    /// The rule `tag` names, or `None` for a tag this build holds no rule
    /// for — the one place a marker tag is read as a rule.
    fn of(tag: u8) -> Option<Rule> {
        match tag {
            TAG_MLDSA65_ED25519 => Some(Rule::MlDsa65Ed25519),
            TAG_FNDSA512_PREVIEW_ED25519 => Some(Rule::FnDsa512PreviewEd25519),
            _ => None,
        }
    }
}

/// The KDF's salt — the derivation's own name, so the same seed under
/// another KDF version derives other keys.
const KDF_SALT: &[u8] = b"skep-kdf-v1";
/// The half labels.
const HALF_ED25519: &[u8] = b"ed25519";
const HALF_MLDSA65: &[u8] = b"ml-dsa-65";
const HALF_FNDSA512: &[u8] = b"fn-dsa-512";

/// The two half seeds one 32-byte seed derives under one tag —
/// private-key material, so `Clone` and nothing more: not `Copy`, which
/// could never be taken back and would bar a `Drop` that zeroizes; and no
/// derived `PartialEq`, whose comparison stops at the first differing byte.
/// Either can be added later without breaking a caller; neither could be
/// removed.
#[derive(Clone)]
pub struct HalfSeeds {
    /// The Ed25519 half's seed (`ed25519-dalek`'s `SigningKey::from_bytes`).
    pub ed25519: [u8; 32],
    /// The post-quantum half's seed: ξ for ML-DSA-65; the keygen draw for
    /// the FN-DSA-512 preview.
    pub pq: [u8; 32],
}

impl fmt::Debug for HalfSeeds {
    /// A seed is private-key material: never printed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HalfSeeds(..)")
    }
}

/// HKDF-SHA-256 as the KDF PIN states it: `salt = KDF_SALT`, `IKM = seed`,
/// `info = token ‖ 0x00 ‖ half_label`, 32 bytes out.
fn derive_half_seed(seed: &[u8; 32], token: &str, half_label: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(KDF_SALT), seed);
    let mut out = [0u8; 32];
    // `info = token ‖ 0x00 ‖ half_label`, handed over as its three
    // components: `hkdf`'s own `expand` is `expand_multi_info` over one
    // component, so the concatenation is the crate's to make and no buffer is
    // built here.
    hk.expand_multi_info(&[token.as_bytes(), &[0u8], half_label], &mut out)
        .expect("32 bytes is within HKDF-SHA-256's output bound");
    out
}

/// THE KDF: one seed to both half seeds under `tag`'s token; `None` for a
/// tag no row names or this build holds no rule for.
pub fn derive_seeds(tag: u8, seed: &[u8; 32]) -> Option<HalfSeeds> {
    let row = token_of_sig_alg(tag)?;
    let pq_label = match Rule::of(tag)? {
        Rule::MlDsa65Ed25519 => HALF_MLDSA65,
        Rule::FnDsa512PreviewEd25519 => HALF_FNDSA512,
    };
    Some(HalfSeeds {
        ed25519: derive_half_seed(seed, row.token, HALF_ED25519),
        pq: derive_half_seed(seed, row.token, pq_label),
    })
}

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

/// `rand_core` 0.6's view of the crate's one OS RNG ([`OsEntropy`]): what a
/// tag-3 signature draws its 40-byte seed from outside a seeded fixture,
/// delegating to the 0.9 impl's `fill_bytes` so the OS draw and its
/// fail-stop are stated once.
impl rand_core_06::RngCore for OsEntropy {
    fn next_u32(&mut self) -> u32 {
        rand_core_06::impls::next_u32_via_fill(self)
    }
    fn next_u64(&mut self) -> u64 {
        rand_core_06::impls::next_u64_via_fill(self)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        rand_core::RngCore::fill_bytes(self, dest)
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core_06::Error> {
        rand_core::RngCore::fill_bytes(self, dest);
        Ok(())
    }
}

impl rand_core_06::CryptoRng for OsEntropy {}

/// TEST HOOK (the `fuzz_support` standing: `#[doc(hidden)]`, not a stable
/// API) — a DETERMINISTIC `rand_core` 0.6 stream for FIXTURES, SHA-256 in
/// counter mode over a seed, so a tag-3 signature (randomized by the draft's
/// own rule) is byte-stable in a golden. No part of any tag's rule: a tag-3
/// signature verifies under the tag's rule whatever RNG made it. Never for
/// production use — the stream is a function of its seed.
#[doc(hidden)]
pub struct SeededRng06 {
    seed: [u8; 32],
    counter: u64,
    /// The current SHA-256 block, handed out front to back; `used ==
    /// block.len()` when the next byte needs a fresh one.
    block: [u8; 32],
    used: usize,
}

impl SeededRng06 {
    pub fn new(seed: [u8; 32]) -> SeededRng06 {
        let block = [0; 32];
        SeededRng06 { seed, counter: 0, used: block.len(), block }
    }
}

/// The stream's position, never its seed: this module prints no seed.
impl fmt::Debug for SeededRng06 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SeededRng06").field("counter", &self.counter).finish_non_exhaustive()
    }
}

impl rand_core_06::RngCore for SeededRng06 {
    fn next_u32(&mut self) -> u32 {
        rand_core_06::impls::next_u32_via_fill(self)
    }
    fn next_u64(&mut self) -> u64 {
        rand_core_06::impls::next_u64_via_fill(self)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        use sha2::Digest;
        for out in dest {
            if self.used == self.block.len() {
                self.block = Sha256::new()
                    .chain_update(self.seed)
                    .chain_update(self.counter.to_be_bytes())
                    .finalize()
                    .into();
                self.counter += 1;
                self.used = 0;
            }
            *out = self.block[self.used];
            self.used += 1;
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
    /// Tag 3: the FN-DSA-512 PREVIEW signing key in `fn-dsa` 0.4.0's
    /// encoding (`sign_key_size(FN_DSA_LOGN_512)` bytes — 1,345 at degree 9,
    /// its `f`, `g`, `F` and the hashed verifying key, which
    /// `sizes_and_timings_per_tag` pins), decoded per signature — the crate's
    /// `sign` takes `&mut self` and its key type zeroizes on drop.
    FnDsa512Preview(Vec<u8>),
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
    /// crate's own keygen. `None` for a tag no row names or this build holds
    /// no rule for.
    pub fn from_seed(tag: u8, seed: &[u8; 32]) -> Option<HybridSigner> {
        let row = token_of_sig_alg(tag)?;
        let halves = derive_seeds(tag, seed)?;
        let ed = EdSigningKey::from_bytes(&halves.ed25519);
        let ed_pk = ed.verifying_key().to_bytes();
        let (pq, pq_pk): (PqSigner, Vec<u8>) = match Rule::of(tag)? {
            Rule::MlDsa65Ed25519 => {
                let sk = ml_dsa::SigningKey::<MlDsa65>::from_seed(&halves.pq.into());
                let pk = sk.verifying_key().encode();
                (PqSigner::MlDsa65(sk), pk.as_slice().to_vec())
            }
            Rule::FnDsa512PreviewEd25519 => {
                let mut rng = ExactBytes { bytes: &halves.pq, taken: 0 };
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
        };
        let mut raw = pq_pk;
        raw.extend_from_slice(&ed_pk);
        let public = PublicKey::parse(row.token, &hex_string(&raw))
            .expect("the two halves concatenate to the row's raw length");
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
    /// opens nothing (no half opens a session alone). The goldens read it, and
    /// the suites' negative vector — a 64-byte Ed25519-only `sig`, the
    /// classical layout no served board admits — is made with it. Hidden
    /// because its type is `ed25519-dalek`'s: a caller holding one names that
    /// crate at this crate's version.
    #[doc(hidden)]
    pub fn ed25519_signing_key(&self) -> &EdSigningKey {
        &self.ed
    }

    /// TEST HOOK (the same standing) — [`HybridSigner::sign`] with tag 3's
    /// per-signature seed drawn from `rng`: the fixtures' door, handed a
    /// [`SeededRng06`] so a tag-3 golden is byte-stable (tag 1 draws nothing).
    /// Hidden because its bound is `rand_core` 0.6's — the version `fn-dsa`
    /// 0.4.0 draws through, which a caller's own RNG would have to match.
    #[doc(hidden)]
    pub fn sign_with_rng<R: rand_core_06::CryptoRng + rand_core_06::RngCore>(
        &self,
        msg: &[u8],
        rng: &mut R,
    ) -> Vec<u8> {
        let mut blob = match &self.pq {
            PqSigner::MlDsa65(sk) => sk.sign(msg).encode().as_slice().to_vec(),
            PqSigner::FnDsa512Preview(sk_bytes) => {
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

    /// SIGN `msg` under the tag's rule: the PQ signature THEN the Ed25519
    /// signature over the same bytes — the blob a marker slot carries, and a
    /// session's `sig`. Tag 1 is deterministic (FIPS 204's deterministic
    /// variant, empty `ctx`); tag 3 draws its per-signature seed from OS
    /// entropy, and PANICS where the OS refuses it: the draw is the crate's
    /// fail-stop OS source (`OsEntropy`), so a tag-3 signature is never made
    /// over a seed from anything weaker. Tag 1 draws nothing, so this panic
    /// is tag 3's alone.
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.sign_with_rng(msg, &mut OsEntropy)
    }
}

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

/// The ecosystem door, as [`crate::NotCanonical`] and
/// [`crate::PortAlreadyBound`] keep it: only a type carrying `Display` and
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
/// refuse it — one arm per tag this module holds a rule for, and what
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
/// half does not decode or `tag` names no rule of this module's. The other
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
/// since retiring it needs an anchor session of that account. `false` for a
/// key of no row.
pub fn key_decodes(key: &PublicKey) -> bool {
    key.sig_alg().is_some_and(|row| {
        decode_ed25519_half(key).is_some() && decode_pq_half(row.tag, key).is_some()
    })
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
/// `signature::Verifier::verify`, `ed25519-dalek`'s `verify_strict` and this
/// crate's own `session::verify` take them: the two are `&[u8]` the compiler
/// cannot tell apart, so the order a Rust caller already knows is the one
/// that holds.
pub fn verify(tag: u8, key: &PublicKey, msg: &[u8], sig: &[u8]) -> Result<(), HybridFault> {
    let row = token_of_sig_alg(tag).ok_or(HybridFault::WrongRow)?;
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

/// The widths one tag's rule fixes — [`pq_widths`]' answer. Named, not a
/// triple: three `usize`s meaning three things, printed into a report that
/// is transcribed.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PqWidths {
    /// The PQ half's verifying key.
    pub key: usize,
    /// The PQ half's signature.
    pub sig: usize,
    /// The PQ signing key in its crate's encoding — the expanded key's for
    /// ML-DSA-65, which the signer holds decoded, and the bytes the signer
    /// stores for the FN-DSA-512 preview.
    pub signing_key: usize,
}

/// TEST HOOK (the `fuzz_support` standing: `#[doc(hidden)]`, not a stable
/// API) — the widths a tag's rule fixes, READ OFF each pinned crate's own
/// sizes — `ml-dsa`'s encoded-array types for tag 1, `fn-dsa`'s size
/// functions for tag 3 — so a bump of either crate that moved one fails
/// `sizes_and_timings_per_tag`'s literal pin by name. `None` for a tag this
/// build holds no rule for.
#[doc(hidden)]
pub fn pq_widths(tag: u8) -> Option<PqWidths> {
    Some(match Rule::of(tag)? {
        Rule::MlDsa65Ed25519 => PqWidths {
            key: EncodedVerifyingKey::<MlDsa65>::default().len(),
            sig: EncodedSignature::<MlDsa65>::default().len(),
            signing_key: ExpandedSigningKeyBytes::<MlDsa65>::default().len(),
        },
        Rule::FnDsa512PreviewEd25519 => PqWidths {
            key: vrfy_key_size(FN_DSA_LOGN_512),
            sig: signature_size(FN_DSA_LOGN_512),
            signing_key: sign_key_size(FN_DSA_LOGN_512),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
            let row = token_of_sig_alg(tag).unwrap();
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
        let mut raw = s3.public_key().raw().to_vec();
        assert_eq!(raw[0], 0x09, "fn-dsa 0.4.0's degree-512 header byte");
        raw[0] = 0x0a;
        let bad = PublicKey::parse(s3.public_key().alg(), &hex_string(&raw)).expect("the row's length");
        assert!(
            decode_pq_half(TAG_FNDSA512_PREVIEW_ED25519, &bad).is_none(),
            "a bad header byte does not decode"
        );
        let s1 = HybridSigner::from_seed(TAG_MLDSA65_ED25519, &seed).unwrap();
        let mut raw = s1.public_key().raw().to_vec();
        raw[0] ^= 0xff;
        let still = PublicKey::parse(s1.public_key().alg(), &hex_string(&raw)).expect("the row's length");
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
        let mut raw = s3.public_key().raw().to_vec();
        raw[0] = 0x0a;
        let bad =
            PublicKey::parse(s3.public_key().alg(), &hex_string(&raw)).expect("the row's length");
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
}
