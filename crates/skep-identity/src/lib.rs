//! # skep-identity — AUTH: the credential data model and the identity fold
//!
//! The PURE heart of AUTH (AUTH-2.1): no I/O, no clock, no config, no
//! signature library, no engine dependency. Dependencies are exactly
//! `skep-address` (M1), `sha2`, `im`, `serde` — light enough for the engine,
//! M10, checkpoint/replay, and any mirror tool to carry. AUTH-2.2 casts the
//! crates around it: `crates/skepd` the ONLY crate that calls an Ed25519
//! library, the World slice, fold hook and load check in
//! `crates/skep-engine`, the conformance pins in `crates/skep-conformance`.
//!
//! ## Composition, as built
//!
//! The build holds the fold BESIDE the engine, so this crate's production
//! collaborators are all in skepd, chiefly its `auth` module; skep-mcp reaches
//! it only from its suite, to build records and sign session payloads.
//! `auth/fold.rs` implements [`Values`]/[`FoldCtx`] over the assembled
//! `World`, rebuilds the [`IdentityState`] from the recovered world at every
//! open and for every historical `key_set` read — no checkpoint carries it —
//! from the [`LinkDeposit`]s it lifts out of the store, and advances the live
//! state from committed deposits. `auth/policy.rs` holds `IDENTITY_TYPES` and
//! the [`WriteTypes`] input, builds the precheck's [`LinkDeposit`] (the
//! committed step folds that same one) and hosts `deposits_credential_link`.
//! `auth::Mode` is derived from [`IdentityState::claimant`]. skep-engine,
//! M10's `skep-febe` and skep-conformance depend on nothing here; the I2 pins
//! ride in this crate's own `tests/it/`; no host implements [`HasIdentity`].
//! skepd's module docs record the divergence from AUTH-2.79–2.88's
//! World-seated slice, riding to the engine round. Until it lands, an element
//! card below that names the World, a checkpoint or the engine cites the
//! SPEC's cast; this section keeps the build's.
//!
//! ## What lives here
//!
//! * keys and fingerprints — [`PublicKey`] with [`ALG_ED25519`] and the two
//!   HYBRID tokens [`ALG_MLDSA65_ED25519`] (tag 1, production) and
//!   [`ALG_FNDSA512_PREVIEW_ED25519`] (tag 3, preview), its refusal
//!   [`KeyParseError`], [`ALGS`] with its row type [`AlgRow`], the marker-tag
//!   table [`SIG_ALGS`] with [`SigAlgRow`], [`Fingerprint`] (AUTH-1.1–1.10;
//!   signed ops);
//! * framing and the tag set — [`Tag`], [`framed`], [`TAGS`]
//!   (AUTH-1.11–1.17), and THE ENTRY FRAME under [`ENTRY_TAG`] —
//!   [`entry_frame`] with the byte forms of its members ([`board_bytes`],
//!   [`address_bytes`], [`value_sequence`], [`slot_bytes`]) and the bodies
//!   per op ([`entry_body_insert`], [`entry_body_link`],
//!   [`entry_body_publish`]) — the bytes a publish-class entry's signature is
//!   made over (signed ops; the design record §2.5);
//! * the record value at one name with both directions —
//!   [`canonical_record`] over a [`RecordEntry`]: the signer's `sig`-bearing
//!   record and the verifier's SIG-LESS PROJECTION (the record §4.2 (C));
//! * the credential-record constants and payload types — [`ENROLL_TYPE`],
//!   [`RETIRE_TYPE`], [`MAX_RECORD_BYTES`], [`Enrollment`] with its refusal
//!   [`LabelError`], [`PayloadError`] (AUTH-1.18–1.28) — with the JSON record
//!   schemas [`parse_enroll`]/[`parse_retire`]/[`encode_enroll`]/[`encode_retire`]
//!   (AUTH-2.15–2.19, AUTH-2.128–2.130);
//! * the ONE pinned payload read — [`record_bytes`] (AUTH-2.3–2.5,
//!   AUTH-2.36–2.45);
//! * the key set — [`Enrolled`], [`KeySet`] (AUTH-1.29–1.37);
//! * shape recognition — [`CredentialKind`], [`TypeAddrs`], [`LinkDeposit`],
//!   [`single_address`] (AUTH-2.20–2.28);
//! * the write path's type-recognition input — [`WriteTypes`]/[`TargetClass`]
//!   /[`AuditClass`] (PUB-6.30, PUB-6.64; owner ruling D3): the grant and
//!   audit-view classes a `nullify` is refused at, read off the fold's
//!   recognition with `kind_of` untouched;
//! * the fold seam — [`Values`], [`FoldCtx`], [`Owner`] (AUTH-2.29–2.35);
//! * the fold itself — [`IdentityState`] with `classify`/`step`, [`Verdict`],
//!   [`Effect`], [`Inert`], [`HasIdentity`] (AUTH-1.38–1.41, AUTH-2.51–2.60,
//!   AUTH-2.62–2.78, AUTH-2.126–2.127).
//!
//! ## In AUTH's data model, deliberately NOT in this crate
//!
//! * `AuthConfig` (AUTH-1.44–1.48) — daemon config over an HTTP `Origin`
//!   type; skepd's surface (design-sessions.md §E), never board state.
//! * `SessionEntry` / `KeyTestimony` (AUTH-1.49–1.56) — carry M10's
//!   `SessionId`/`PrincipalId`; the sessions store is skepd process memory.
//! * `deposits_credential_link` (AUTH-2.61) — "on the skepd policy surface":
//!   it takes M10's `Op`, which AUTH-2.1's dependency set cannot name, so the
//!   function cannot live here (skepd's `auth/policy.rs` holds it).
//! * Enforcement-mode derivation (AUTH-1.42–1.43) — a per-read formula over
//!   the board's claim ([`IdentityState::claimant`]) plus
//!   `AuthConfig.local_trust`, computed daemon-side with nothing stored; no
//!   signature is pinned for it here.
//! * `IDENTITY_TYPES`, the `World::apply` hook, slice-less recovery
//!   (AUTH-2.79–2.88) — the spec's engine/skepd integration over this crate's
//!   types; as built, skepd's alone (above).
//!
//! ## Traceability
//!
//! Every public item's doc-comment cites the spec rule it realizes — AUTH's
//! rule and invariant labels, and on the write path's type-recognition input
//! the publication spec's (PUB-6.30, PUB-6.64, RES-207) and owner ruling D3 —
//! so a reviewer can walk from code to spec without the documents open.
//!
//! ## Purity note
//!
//! The one `std::sync` item in the crate is a `LazyLock` holding the
//! crate-constant empty [`KeySet`] behind `IdentityState::key_set`'s
//! `&KeySet` return (AUTH-2.58): once-only initialization of a `Default`
//! value — no observable state, no effect on fold determinism (I2).

#![forbid(unsafe_code)]

mod entry;
mod framing;
mod key;
mod keyset;
mod payload;
mod read;
mod seam;
mod shape;
mod state;
mod verdict;
mod write_types;

pub use entry::{
    address_bytes, board_bytes, entry_body_insert, entry_body_link, entry_body_publish,
    entry_frame, slot_bytes, value_sequence, EntrySlot,
};
pub use framing::{
    framed, Tag, ENTRY_TAG, KEY_TAG, NODE_HELLO_TAG, SESSION_TAG, SESSION_TAG_V2, TAGS,
};
pub use key::{
    sig_alg_of, token_of_sig_alg, AlgRow, Fingerprint, KeyParseError, PublicKey, SigAlgRow, ALGS,
    ALG_ED25519, ALG_FNDSA512_PREVIEW_ED25519, ALG_MLDSA65_ED25519, ED25519_KEY_LEN,
    FNDSA512_ED25519_KEY_LEN, FNDSA512_KEY_LEN, MLDSA65_ED25519_KEY_LEN, MLDSA65_KEY_LEN,
    SIG_ALGS,
};
pub use keyset::{Enrolled, KeySet};
pub use payload::{
    canonical_record, encode_enroll, encode_retire, parse_enroll, parse_retire, Enrollment,
    LabelError, PayloadError, RecordEntry, ENROLL_TYPE, MAX_RECORD_BYTES, RETIRE_TYPE,
};
pub use read::record_bytes;
pub use seam::{FoldCtx, Owner, Values};
pub use shape::{single_address, CredentialKind, LinkDeposit, TypeAddrs};
pub use state::{HasIdentity, IdentityState};
pub use verdict::{Effect, Inert, Verdict};
pub use write_types::{AuditClass, TargetClass, WriteTypes};

/// What this crate's hosts demand of the values they keep across threads:
/// skepd holds the live [`IdentityState`] behind a lock inside its
/// `Arc<Daemon>` (`Send`), and ONE [`TypeAddrs`] and ONE [`WriteTypes`] in
/// `static`s for the daemon's life (`Send + Sync`); AUTH-2.79's World slice
/// would demand `Send + Sync + 'static` of the first. NOTHING in this crate
/// names those bounds, so a field that revoked one — an `Rc`, a `Cell`, a
/// cached `dyn` matcher — would compile here and break skepd's build at its
/// `static` or its `Arc`, never naming the field that caused it. The
/// promises are checked here instead, covering `KeySet`, `Enrolled`,
/// `PublicKey`, `Fingerprint`, `Address` and `Span` transitively.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync + 'static>() {}
    assert_send_sync::<IdentityState>();
    assert_send_sync::<TypeAddrs>();
    assert_send_sync::<WriteTypes>();
};
