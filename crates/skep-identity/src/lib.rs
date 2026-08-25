//! # skep-identity — AUTH: the credential data model and the identity fold
//!
//! The PURE heart of AUTH (AUTH-2.1): no I/O, no clock, no config, no
//! signature library, no engine dependency. Dependencies are exactly
//! `skep-address` (M1), `sha2`, `im`, `serde` — light enough for the engine,
//! M10, checkpoint/replay, and any mirror tool to carry. Per AUTH-2.2,
//! `crates/skepd` is the ONLY crate that calls an Ed25519 library; the World
//! slice, fold hook and load check live in `crates/skep-engine`; the
//! conformance pins in `crates/skep-conformance`.
//!
//! ## What lives here
//!
//! * keys and fingerprints — [`PublicKey`] with [`ALG_ED25519`] and its
//!   refusal [`KeyParseError`], [`ALGS`] with its row type [`AlgRow`],
//!   [`Fingerprint`] (AUTH-1.1–1.10);
//! * framing and the tag set — [`Tag`], [`framed`], [`TAGS`]
//!   (AUTH-1.11–1.17);
//! * the credential-record constants and payload types — [`ENROLL_HEADER`],
//!   [`RETIRE_HEADER`], [`MAX_RECORD_BYTES`], [`Enrollment`] with its refusal
//!   [`LabelError`], [`PayloadError`] (AUTH-1.18–1.28) — with the line grammar
//!   [`parse_enroll`]/[`parse_retire`]/[`encode_enroll`]/[`encode_retire`]
//!   (AUTH-2.6–2.19);
//! * the ONE pinned payload read — [`record_bytes`] (AUTH-2.3–2.5,
//!   AUTH-2.36–2.45);
//! * the key set — [`Enrolled`], [`KeySet`] (AUTH-1.29–1.37);
//! * shape recognition — [`CredentialKind`], [`TypeAddrs`], [`LinkDeposit`],
//!   [`single_address`] (AUTH-2.20–2.28);
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
//!   it takes M10's `Op`, and `skep-operation` depends on THIS crate
//!   (AUTH-2.2), so the function cannot live below it.
//! * Enforcement-mode derivation (AUTH-1.42–1.43) — a per-read formula over
//!   [`HasIdentity`] plus `AuthConfig.local_trust`, computed daemon-side with
//!   nothing stored; no signature is pinned for it here.
//! * `IDENTITY_TYPES`, the `World::apply` hook, slice-less recovery
//!   (AUTH-2.79–2.88) — engine/skepd integration over this crate's types.
//!
//! ## Traceability
//!
//! Every public item's doc-comment cites the AUTH rule and invariant labels
//! it realizes, so a reviewer can walk from code to spec without the
//! documents open.
//!
//! ## Purity note
//!
//! The one `std::sync` item in the crate is a `LazyLock` holding the
//! crate-constant empty [`KeySet`] behind `IdentityState::key_set`'s
//! `&KeySet` return (AUTH-2.58): once-only initialization of a `Default`
//! value — no observable state, no effect on fold determinism (I2).

#![forbid(unsafe_code)]

mod framing;
mod key;
mod keyset;
mod payload;
mod read;
mod seam;
mod shape;
mod state;
mod verdict;

pub use framing::{framed, Tag, KEY_TAG, NODE_HELLO_TAG, SESSION_TAG, TAGS};
pub use key::{AlgRow, Fingerprint, KeyParseError, PublicKey, ALGS, ALG_ED25519};
pub use keyset::{Enrolled, KeySet};
pub use payload::{
    encode_enroll, encode_retire, parse_enroll, parse_retire, Enrollment, LabelError, PayloadError,
    ENROLL_HEADER, MAX_RECORD_BYTES, RETIRE_HEADER,
};
pub use read::record_bytes;
pub use seam::{FoldCtx, Owner, Values};
pub use shape::{single_address, CredentialKind, LinkDeposit, TypeAddrs};
pub use state::{HasIdentity, IdentityState};
pub use verdict::{Effect, Inert, Verdict};
