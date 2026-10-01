//! THE HYBRID ENTRY SIGNATURE (signed ops, the seam build 2026-09-25): the
//! two marker tags' FROZEN RULES — keygen from one seed, signing, verifying —
//! in `skep-signature`, the one crate that links the signature libraries;
//! skepd calls its verify (AUTH-2.2; the PQ crate investigation §8.4 (5)).
//! skep-identity holds the SYNTAX (the `ALGS` rows, the `SIG_ALGS` table, the
//! entry frame); this crate holds the ARITHMETIC, dispatching on the tag to
//! THAT tag's rule and to no other.
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
//! Ed25519 half's 32 bytes — [`skep_identity::PublicKey::from_halves`] writes
//! it and `pq_half`/`ed25519_half` read it, so keygen composes a key without
//! spelling the order. THE BLOB: the PQ signature THEN the Ed25519
//! signature's 64 bytes, two fixed-width fields, no length prefix (the record
//! §2.4) — the marker slot's blob and, since the hybrid handshake (the
//! hybrid-only launch, owner 2026-09-26), a session's `sig` over the session
//! bytes too (AUTH-4.32, AUTH-6.3). VERIFY is BOTH halves over the SAME bytes
//! — either failing fails (the ruled "hybrid, both halves verify"); no half
//! opens a session alone.
//!
//! THE CODE MAP — a file's build is the gate on its `mod` line below, written
//! once, so what each build holds is read off those four lines:
//!
//! * `verifier.rs` — the verify and the all-halves decode skepd calls, in
//!   every build. The verify-only build a daemon links is this file and this
//!   root, and nothing in either signs.
//! * `kdf.rs` — the KDF PIN as code, one seed to both half seeds; under
//!   `sign`, and on the crate's surface only as a test hook.
//! * `signer.rs` — keygen from a seed and signing, per tag (`HybridSigner`),
//!   under `sign`, which skepd leaves off: used by the suites' test signer
//!   and by the goldens that pin each tag's rule. Its two hooks, the Ed25519
//!   key and `sign_with_rng`, sit beside the private fields they read, each
//!   gated on `test-hooks`.
//! * `hooks.rs` — the fixtures' other hooks, the seeded stream and the widths
//!   the sizes pin reads; under `test-hooks`, which implies `sign`.
//!
//! `Rule`, below, is the one statement of the tag set all four match on.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod verifier;
#[cfg(feature = "sign")]
mod kdf;
#[cfg(feature = "sign")]
mod signer;
#[cfg(feature = "test-hooks")]
mod hooks;

pub use verifier::{key_decodes, verify, HybridFault};
#[cfg(feature = "sign")]
pub use signer::HybridSigner;
/// TEST HOOK (the `fuzz_support` standing: `#[doc(hidden)]`, not a stable
/// API) — the KDF's two half seeds, which the differential golden feeds a
/// second FIPS 204 implementation as ξ; a shipped signer derives them inside
/// `HybridSigner::from_seed` and hands neither out.
#[cfg(feature = "test-hooks")]
#[doc(hidden)]
pub use kdf::{derive_seeds, HalfSeeds};
#[cfg(feature = "test-hooks")]
#[doc(hidden)]
pub use hooks::{pq_widths, PqWidths, SeededRng06};

/// The marker tag of the PRODUCTION row, `mldsa65-ed25519` (ML-DSA-65 +
/// Ed25519).
pub const TAG_MLDSA65_ED25519: u8 = 1;
/// The marker tag of the PREVIEW row, `fndsa512-preview-ed25519` (the
/// FN-DSA-512 preview + Ed25519).
pub const TAG_FNDSA512_PREVIEW_ED25519: u8 = 3;

/// The rules this crate holds, one per marker tag — the ONE statement of
/// which tags this build can derive, keygen, decode and verify under.
/// Every per-tag step matches on it exhaustively — the PQ half's KDF label,
/// its keygen (`PqSigner::keygen`), its decode (`PqHalf::decode`), its
/// widths, a file each (the code map above) — and those two per-tag enums,
/// `PqSigner` in [`signer`] and `PqHalf` in [`verifier`], carry each tag's
/// signing and verifying arithmetic, one variant per rule, so a new tag
/// (tag 2 is free for the final FIPS 206 — whose variant takes the
/// unqualified token name, `FnDsa512Ed25519`; the preview carries `Preview`
/// in every name, as its token does, so the final standard's arms never
/// share a name with it) is one variant here and one arm in [`Rule::of`],
/// and the compiler names every step that must learn it. No step outside
/// this crate enumerates the tags: skepd's hybrid-blob parse
/// (`skepd::auth::session::HybridSig`, the handshake's `sig` and a record's)
/// admits every `SIG_ALGS` row's width, read off the table at the parse.
/// Each variant is its row's token in CamelCase.
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

/// The auto-traits this crate promises without saying so. A signer held
/// across threads depends on `HybridSigner: Send + Sync`, and no signature
/// states it — so a private field that is not `Send` would revoke it with no
/// public name changing. This is where that fails to compile instead.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    // The signer a client holds across threads, the seeds it derives from,
    // the verify's refusal, the fixtures' seeded stream, and the widths the
    // sizes pin reads.
    #[cfg(feature = "sign")]
    assert_send_sync::<signer::HybridSigner>();
    #[cfg(feature = "sign")]
    assert_send_sync::<kdf::HalfSeeds>();
    assert_send_sync::<verifier::HybridFault>();
    #[cfg(feature = "test-hooks")]
    assert_send_sync::<hooks::SeededRng06>();
    #[cfg(feature = "test-hooks")]
    assert_send_sync::<hooks::PqWidths>();
};

#[cfg(test)]
mod tests;
