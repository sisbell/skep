//! The hybrid signature of signed ops: the two marker tags' frozen rules.
//!
//! The rules — keygen from one seed, signing, verifying — are held in
//! `skep-signature`, the one crate that links the signature libraries; the
//! daemon's core, skep-core, calls its verify (AUTH-2.2; the PQ crate
//! investigation §8.4 (5)). skep-identity holds the syntax (the `ALGS` rows,
//! the `SIG_ALGS` table, the entry frame); this crate holds the arithmetic,
//! dispatching on the tag to that tag's rule and to no other.
//!
//! **The tags.** Each is one exact rule held whole (the design record §1's
//! algorithm row, the frozen-tag rule, which extends to keygen):
//!
//! * Tag 1 — ML-DSA-65 + Ed25519, production: RustCrypto `ml-dsa` `=0.1.1`
//!   (final FIPS 204; `SigningKey::from_seed` is `ML-DSA.KeyGen_internal(ξ)`,
//!   Algorithm 6) and `ed25519-dalek` 2 (`verify_strict`). The signature is
//!   FIPS 204's deterministic variant (`rnd` = 0) with an empty context
//!   string — the ctx pin: every hybrid signature the wire carries is made
//!   over bytes framed under their own framing tag (AUTH-1.11),
//!   [`ENTRY_TAG`](skep_identity::ENTRY_TAG) for an entry's and a credential
//!   record's and [`SESSION_TAG`](skep_identity::SESSION_TAG) or
//!   [`SESSION_TAG_V2`](skep_identity::SESSION_TAG_V2) for a session's, and
//!   that tag is the domain separation; `ml-dsa`'s `Signer` supports only the
//!   empty `ctx`.
//! * Tag 3 — FN-DSA-512 + Ed25519, preview: Thomas Pornin's `fn-dsa`
//!   `=0.4.0` — its 2026-07-22 "best guess" at the FN-DSA draft, which the
//!   crate itself says will change before 1.0 — so the exact version is the
//!   rule: its keygen from the 32-byte half seed (the one RNG draw
//!   `keygen_inner` makes, and nothing else), its key and signature
//!   encodings, its `verify` with `DOMAIN_NONE` and `HASH_ID_RAW` (the ctx
//!   pin again). FN-DSA signing is randomized (the draft "only allows
//!   randomized signing"), so a tag-3 signature's bytes depend on the
//!   signer's RNG and only the key and the verify are byte-stable; a seeded
//!   RNG makes a fixture reproducible.
//!
//! **The KDF pin.** `docs/wire.md`'s keygen-from-seed rule (the design
//! record §5.2 (ii)'s three inputs: the KDF, the domain-separation bytes, the
//! keygen entry point) takes one 32-byte seed to both halves, never the raw
//! seed to either:
//!
//! ```text
//! half_seed = HKDF-SHA-256(salt = "skep-kdf-v1", IKM = seed,
//!                          info = <alg token> ‖ 0x00 ‖ <half label>, L = 32)
//! ```
//!
//! with the half labels `"ed25519"`, `"ml-dsa-65"` and `"fn-dsa-512"` — so a
//! seed derives different Ed25519 halves under tag 1 and tag 3 (the token is
//! in the `info`), one derived half's leak reveals neither the seed nor the
//! other half (HKDF is one-way), and the paper backup stays one 64-hex
//! seed. The Ed25519 half's 32 bytes are its private key (RFC 8032's;
//! `ed25519-dalek`'s `SecretKey`, which `SigningKey::from_bytes` takes); the
//! ML-DSA half's are FIPS 204's ξ; the FN-DSA half's are the one 32-byte
//! draw `fn-dsa` 0.4.0's keygen makes, and nothing else.
//!
//! **The key pin.** A hybrid's raw public key is the PQ half's encoding then
//! the Ed25519 half's 32 bytes — [`skep_identity::PublicKey::from_halves`]
//! writes it and `pq_half`/`ed25519_half` read it, so keygen composes a key
//! without spelling the order.
//!
//! **The blob.** The PQ signature then the Ed25519 signature's 64 bytes, two
//! fixed-width fields, no length prefix (the design record §2.4) — one blob
//! for all three carriers: an entry's `attest`, which the daemon writes into
//! its commit's marker slot; a credential record's own `sig` (the record
//! grade); and, under the hybrid handshake (the hybrid-only launch), a
//! session's `sig` over the session bytes (AUTH-4.32, AUTH-6.3). The verify
//! is both halves over the same bytes — either failing fails (the rule
//! "hybrid, both halves verify"); no half opens a session alone.
//!
//! **The code map.** A file's build is the gate on its `mod` line below,
//! written once, so what each build holds is read off those four lines:
//!
//! * `verifier.rs` — the verify and the all-halves decode skep-core calls,
//!   in every build. The verify-only build a daemon links is this file and
//!   this root, and nothing in either signs.
//! * `kdf.rs` — the KDF as code, one seed to both half seeds; under
//!   `sign`, and on the crate's surface only as a test hook.
//! * `signer.rs` — keygen from a seed and signing, per tag (`HybridSigner`),
//!   under `sign`, which skepd leaves off and skep-client's `acting` turns
//!   on: the client's signer, the suites' test signer and the goldens that
//!   pin each tag's rule. Its hooks sit beside the private fields they read,
//!   each gated on `test-hooks`.
//! * `hooks.rs` — the fixtures' hooks that read none of the signer's private
//!   fields, and the crate's one list of every hook; under `test-hooks`,
//!   which implies `sign`.
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
/// TEST HOOK: the KDF and the two half seeds it answers, for the suites.
///
/// It has the `fuzz_support` standing: `#[doc(hidden)]`, not a stable API.
/// The tag-1 differential feeds a second FIPS 204 implementation the PQ half
/// seed as ξ, and the KDF's recomputation holds the half seeds to RFC 5869;
/// a shipped signer derives them inside `HybridSigner::from_seed` and hands
/// neither out.
#[cfg(feature = "test-hooks")]
#[doc(hidden)]
pub use kdf::{derive_half_seeds, HalfSeeds};
#[cfg(feature = "test-hooks")]
#[doc(hidden)]
pub use hooks::{pq_widths, PqWidths, SeededRng06};
/// TEST HOOK: the suites' seed, and the hybrid's Ed25519 half as they hold it.
///
/// It has the same standing. The seed keys each principal's fixtures and is
/// no key itself; the half is the hybrid's Ed25519 half as a suite holds it,
/// so no other crate's suite links `ed25519-dalek` (`tests/it/tidy.rs` holds
/// the lock to that).
#[cfg(feature = "test-hooks")]
#[doc(hidden)]
pub use hooks::{Ed25519SigningKey, Seed};

/// The marker tag of the production row, `mldsa65-ed25519`.
///
/// The row's hybrid is ML-DSA-65 + Ed25519.
pub const TAG_MLDSA65_ED25519: u8 = 1;
/// The marker tag of the preview row, `fndsa512-preview-ed25519`.
///
/// The row's hybrid is the FN-DSA-512 preview + Ed25519.
pub const TAG_FNDSA512_PREVIEW_ED25519: u8 = 3;

/// The rules this crate holds, one per marker tag.
///
/// It is the one statement of which tags this build can derive, keygen,
/// decode and verify under. Every per-tag step matches on it exhaustively —
/// the PQ half's label, its keygen (`PqSigner::keygen`), its decode
/// (`PqVerifier::decode`), its widths, a file each (the code map above) — and
/// those two per-tag enums, `PqSigner` in [`signer`] and `PqVerifier` in
/// [`verifier`], carry each tag's signing and verifying arithmetic, one
/// variant per rule, so a new tag (tag 2 is free for the final FIPS 206 —
/// whose variant takes the unqualified token name, `FnDsa512Ed25519`; the
/// preview carries `Preview` in every variant's name, as its token does, so
/// the final standard's arms never share a name with it) is one variant here
/// and one arm in [`Rule::of`], and the compiler names every step that must
/// learn it. Each variant is its row's token in CamelCase.
#[derive(Clone, Copy)]
enum Rule {
    /// Tag 1: ML-DSA-65 + Ed25519 (`mldsa65-ed25519`).
    MlDsa65Ed25519,
    /// Tag 3: the FN-DSA-512 preview + Ed25519 (`fndsa512-preview-ed25519`).
    FnDsa512PreviewEd25519,
}

impl Rule {
    /// Returns the rule `tag` names, or `None` where this build holds none.
    ///
    /// It is the one place a marker tag is read as a rule.
    fn of(tag: u8) -> Option<Rule> {
        match tag {
            TAG_MLDSA65_ED25519 => Some(Rule::MlDsa65Ed25519),
            TAG_FNDSA512_PREVIEW_ED25519 => Some(Rule::FnDsa512PreviewEd25519),
            _ => None,
        }
    }
}

/// The auto-traits this crate promises without saying so.
///
/// A signer held across threads depends on `HybridSigner: Send + Sync`, and
/// no signature states it — so a private field that is not `Send` would
/// revoke it with no public name changing. This is where that fails to
/// compile instead.
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
    // The suites' seeds and the Ed25519 half a signer hands them, shared
    // across the threads a fixture spawns.
    #[cfg(feature = "test-hooks")]
    assert_send_sync::<hooks::Seed>();
    #[cfg(feature = "test-hooks")]
    assert_send_sync::<hooks::Ed25519SigningKey>();
};

#[cfg(test)]
mod tests;
