//! # skep-identity — AUTH: the credential data model and the identity fold
//!
//! The PURE heart of AUTH (AUTH-2.1): no I/O, no clock, no config, no
//! signature library, no engine dependency. Dependencies are exactly
//! `skep-address` (M1), `sha2`, `im`, `serde` and `serde_json` — the last
//! answering one question, which JSON value a record's bytes are, with every
//! verdict written here (`payload.rs`) — light enough for the engine, M10,
//! checkpoint/replay, and any mirror tool to carry. AUTH-2.2 casts the crates
//! around it: `crates/skep-signature` the one crate that links the signature
//! libraries (Ed25519, ML-DSA, FN-DSA), whose verify `crates/skepd` calls —
//! the fence is the SESSION verify's, `verify`/`find_signer`, the daemon's
//! check of a handshake against the fold's key sets — the World slice, fold
//! hook and load check in `crates/skep-engine`, and the conformance pins in
//! the crates' own suites, `crates/skep-conformance` depending on nothing
//! here.
//!
//! ## Composition, as built
//!
//! The build holds the fold BESIDE the engine, so this crate's production
//! collaborators are skepd — chiefly its session layer (`auth`; the
//! workspace's `ARCHITECTURE.md`, §The daemon) — and `skep-signature`, the
//! signature arithmetic skepd calls; skep-mcp reaches it only from its
//! suite, to build records and sign session payloads. skepd implements
//! [`Values`]/[`FoldCtx`] over the assembled `World`; rebuilds the
//! [`IdentityState`] from the recovered world at every open and for every
//! historical `key_set` read — no checkpoint carries it — from the
//! [`LinkDeposit`]s it lifts out of the store, and advances the live state
//! from committed deposits; holds the ONE [`TypeAddrs`] (`IDENTITY_TYPES`)
//! and the [`WriteTypes`] input; builds the precheck's [`LinkDeposit`] (the
//! committed step folds that same one); hosts `deposits_credential_link`; and
//! derives its enforcement mode from [`IdentityState::claimant`]. skep-engine,
//! M10's `skep-febe` and skep-conformance depend on nothing here; the I2 pins
//! ride in this crate's own `tests/it/`; no host implements [`HasIdentity`].
//! skepd's module docs record the divergence from AUTH-2.79–2.88's
//! World-seated slice, riding to the engine round. Until it lands, an element
//! card below that names the World, a checkpoint or the engine cites the
//! SPEC's cast; this section keeps the build's.
//!
//! Signed ops' declarations are consumed in skepd as well, at both grades. It
//! composes the ENTRY frame it verifies through [`entry_frame`], over the
//! locked snapshot's [`BoardTerm`], the principal's account, and the op's
//! [`DocTerm`] and [`EntryBody`] — a link write's slots as the transaction
//! stores them, each a [`unit_span`] or a resolved extent; a `publish`'s
//! built piece by piece within its budget through [`PublishBody`], whose
//! [`PublishRefusal`] tells it which answer a refused shot is owed. At a
//! credential deposit above the claim it
//! checks the RECORD grade: it reads the record's atom through
//! [`record_bytes`], its entries and `sig` through [`parse_record_value`] and
//! the link's type and target through [`single_address`], and frames the
//! sig-less projection ([`canonical_record`] with no `sig`) as the
//! [`entry_body_record`] body under the home's account and the home; at the
//! atom's own `insert`, the same parse tells it whether the record carries a
//! `sig` at all. Its write-path check reads a presented attestation's row off
//! the marker tag, and its codec lifts a request's `attest.alg` token to that
//! tag and back, through [`SigAlgRow::of_token`] and [`SigAlgRow::of_tag`];
//! each marker tag's arithmetic over [`SIG_ALGS`]' rows and a key's two
//! halves — composing them at keygen ([`PublicKey::from_halves`]) and reading
//! them to verify ([`PublicKey::pq_half`], [`PublicKey::ed25519_half`]) — is
//! `skep-signature`'s, whose verify it calls; and it sizes the handshake's
//! hybrid blob by the rows' widths.
//!
//! This section says what skepd USES, not which of its files does it: that is
//! skepd's arrangement, and `grep -rn skep_identity crates/skepd/src` answers
//! it however skepd is cut.
//!
//! Some public items are public for a reason a grep for callers cannot see,
//! so finding no caller is no reason to narrow one. [`Tag`],
//! [`ParseKeyError`], [`LabelError`], [`PayloadError`], [`PublishRefusal`]
//! and [`RecordEntry`] are public because a public signature names them. The
//! rest the spec or the design record declares for a reader OUTSIDE the
//! workspace: [`canonical_record`], [`parse_enroll`], [`parse_retire`] and
//! [`parse_record_value`] with its [`RecordValue`] for the signing client and
//! the verifier beside the table, which parses a committed record, reads its
//! `sig` and composes its sig-less projection (the design record §4.2 (C));
//! [`record_bytes`] for a non-folding reader, which LINKS the read rather
//! than re-implementing it (AUTH-2.37); [`single_address`] for every
//! discovery caller, beside [`TypeAddrs::kind_of`] (AUTH-2.28);
//! [`HasIdentity`] for a host that seats the slice (AUTH-2.60);
//! [`NODE_HELLO_TAG`] for bebe (AUTH-2.118); the tables and constants the
//! spec declares as this crate's surface — [`ALGS`] and its [`AlgRow`]
//! (AUTH-1.5), [`TAGS`], [`KEY_TAG`] and [`ENTRY_TAG`] (AUTH-1.11, AUTH-1.17),
//! [`ENROLL_TYPE`] and [`RETIRE_TYPE`] (AUTH-1.18); and the five `*_KEY_LEN`
//! constants the design record declares beside them (AUTH-1.5's cite). The
//! outside reader is why each of these is public, whether or not a crate of
//! this workspace also calls it, and the suite's `surface.rs` names each of
//! them from outside the crate, so narrowing one fails the build there.
//!
//! ## What lives here
//!
//! One bullet per module, named first. `state` — the fold — sits on top and
//! no module imports it; `entry` imports only `framing`, and `write_types`
//! only `shape`, so the signed-ops frame and the write path's classes read no
//! fold state and write none. The suite's `tidy.rs` checks all three, and
//! this list against `src/`.
//!
//! * `key`: keys and fingerprints — [`PublicKey`] with the two HYBRID tokens
//!   [`ALG_MLDSA65_ED25519`] (tag 1, production) and
//!   [`ALG_FNDSA512_PREVIEW_ED25519`] (tag 3, preview) — the key kinds are
//!   the two hybrid rows, the classical `ed25519` row DELETED at the
//!   hybrid-only launch (AUTH-1.1, AUTH-1.5) — its refusal
//!   [`ParseKeyError`], [`ALGS`] with its row type [`AlgRow`], the marker-tag
//!   table [`SIG_ALGS`] with [`SigAlgRow`], [`Fingerprint`] (AUTH-1.1–1.10;
//!   signed ops);
//! * `framing`: framing and the tag set — [`Tag`], [`framed`], [`TAGS`]
//!   (AUTH-1.11–1.17);
//! * `entry`: THE ENTRY FRAME under [`ENTRY_TAG`] — [`entry_frame`], which
//!   spells every member from the values a signer or verifier holds: the
//!   [`BoardTerm`], the account address, the [`DocTerm`] (one document, or
//!   an `edit_link`'s two homes as the pair's row), and an [`EntryBody`] —
//!   a grammar's token paired with its body, one per publish-class op
//!   kind: [`entry_body_empty`] (over a [`ContentFreeOp`]: the three mints'
//!   EMPTY body), [`entry_body_insert`], [`entry_body_make_link`] and
//!   [`entry_body_make_link_replacing`] (over a [`LinkSlots`] naming three
//!   [`EntrySlot`]s — each the slot's spans AS STORED, a [`unit_span`] per
//!   address named or the extents resolved — the second with the op's
//!   `replaces` member), [`entry_body_emit`], [`entry_body_nullify`] and
//!   [`entry_body_assert_sup`] (the same four rows over the stored link,
//!   under the op's own token), [`entry_body_edit_link`] (the successor's
//!   rows then the claim's `from` slot), [`entry_body_publish`] (over
//!   [`ShotSegmentPiece`]s — the shot's address form, one copied position's
//!   value or one window at a time, the pieces its segments are built from
//!   — and the shot's base), or piece by piece under a byte budget by
//!   [`PublishBody`], with its refusal [`PublishRefusal`], and
//!   [`entry_body_record`], over a [`RecordRows`] naming the record grade's
//!   five rows, under the `record` token — the bytes a publish-class
//!   entry's signature, or a record's `sig`, is made over (signed ops; the
//!   design record §2.5; the frame merge);
//! * `payload`: the credential-record constants and payload types —
//!   [`ENROLL_TYPE`], [`RETIRE_TYPE`], [`MAX_RECORD_BYTES`], [`Enrollment`]
//!   with its refusal [`LabelError`], [`PayloadError`] (AUTH-1.18–1.28) —
//!   with the JSON record schemas
//!   [`parse_enroll`]/[`parse_retire`]/[`encode_enroll`]/[`encode_retire`]
//!   (AUTH-2.15–2.19, AUTH-2.128–2.130), and the record value at one name
//!   with both directions — [`canonical_record`] over a [`RecordEntry`]: the
//!   signer's `sig`-bearing record and the verifier's SIG-LESS PROJECTION
//!   (the design record §4.2 (C)) — with the verifier's parse,
//!   [`parse_record_value`], answering a body's entries and its `sig`
//!   together as a [`RecordValue`];
//! * `read`: the ONE pinned payload read — [`record_bytes`] (AUTH-2.3–2.5,
//!   AUTH-2.36–2.45);
//! * `keyset`: the key set — [`Enrolled`], [`KeySet`] (AUTH-1.29–1.37);
//! * `shape`: shape recognition — [`CredentialKind`], [`TypeAddrs`],
//!   [`LinkDeposit`], [`single_address`] (AUTH-2.20–2.28);
//! * `write_types`: the write path's type-recognition input —
//!   [`WriteTypes`]/[`TargetClass`]/[`AuditClass`] (PUB-6.30, PUB-6.64; owner
//!   ruling D3): the grant and audit-view classes a `nullify` is refused at
//!   — the registry's binding, takedown record and policy link among them
//!   (REG-1.44, REG-1.46) — read off the fold's recognition with `kind_of`
//!   untouched;
//! * `seam`: the fold seam — [`Values`], [`FoldCtx`], [`Owner`]
//!   (AUTH-2.29–2.34);
//! * `verdict`: the fold's answers — [`Verdict`], [`Effect`], [`Inert`]
//!   (AUTH-2.51–2.55);
//! * `state`: the fold itself — [`IdentityState`] with `classify`/`step`,
//!   [`HasIdentity`], and the fold's ω projections and doc-1 address, private
//!   to it (AUTH-1.38–1.41, AUTH-2.35, AUTH-2.56–2.60, AUTH-2.62–2.78,
//!   AUTH-2.126–2.127).
//!
//! ## In AUTH's data model, deliberately NOT in this crate
//!
//! * `AuthConfig` (AUTH-1.44–1.48) — daemon config over an HTTP `Origin`
//!   type; skepd's surface (design-sessions.md §E), never board state.
//! * `SessionEntry` / `KeyTestimony` (AUTH-1.49–1.56) — carry M10's
//!   `SessionId`/`PrincipalId`; the sessions store is skepd process memory.
//! * `deposits_credential_link` (AUTH-2.61) — "on the skepd policy surface":
//!   it takes M10's `Op`, which AUTH-2.1's dependency set cannot name, so the
//!   function cannot live here (skepd's session layer holds it).
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
//! Every public item's doc-comment cites the authority it realizes: AUTH's
//! rule and invariant labels; on the write path's type-recognition input the
//! publication spec's (PUB-6.30, PUB-6.64, RES-207) and owner ruling D3; and
//! on signed ops' declarations — the marker-tag table, a key's halves, the
//! length constants, the entry frame and the record projection, which the
//! AUTH spec declares in no rule and whose authority AUTH-1.5 assigns, by
//! cite, to the signed-ops design record — that record, cited as "the design
//! record" with its section or ruling, and never as "the record" or "its
//! record" alone: in this crate a record is a credential record (AUTH-1.18),
//! and the suite's `tidy.rs` holds every comment to that rule. So a reviewer
//! can walk from code to its authority without the documents open.
//!
//! ## Purity note
//!
//! The one `std::sync` item in the crate is a `LazyLock` holding the
//! crate-constant empty [`KeySet`] behind `IdentityState::key_set`'s
//! `&KeySet` return (AUTH-2.58): once-only initialization of a `Default`
//! value — no observable state, no effect on fold determinism (I2). The
//! suite's `tidy.rs` holds the crate to this note and to the first
//! paragraph: it reads the dependency set off the manifest, and every
//! `std::` and `core::` path `src/`'s code names.

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
    entry_body_assert_sup, entry_body_edit_link, entry_body_emit, entry_body_empty,
    entry_body_insert, entry_body_make_link, entry_body_make_link_replacing, entry_body_nullify,
    entry_body_publish, entry_body_record, entry_frame, unit_span, BoardTerm, ContentFreeOp,
    DocTerm, EntryBody, EntrySlot, LinkSlots, PublishBody, PublishRefusal, RecordRows, ShotBase,
    ShotSegmentPiece,
};
pub use framing::{
    framed, Tag, ENTRY_TAG, KEY_TAG, NODE_HELLO_TAG, SESSION_TAG, SESSION_TAG_V2, TAGS,
};
pub use key::{
    AlgRow, Fingerprint, ParseKeyError, PublicKey, SigAlgRow, ALGS, ALG_FNDSA512_PREVIEW_ED25519,
    ALG_MLDSA65_ED25519, ED25519_KEY_LEN, FNDSA512_PREVIEW_ED25519_KEY_LEN,
    FNDSA512_PREVIEW_KEY_LEN, MLDSA65_ED25519_KEY_LEN, MLDSA65_KEY_LEN, SIG_ALGS,
};
pub use keyset::{Enrolled, KeySet};
pub use payload::{
    canonical_record, encode_enroll, encode_retire, parse_enroll, parse_record_value,
    parse_retire, Enrollment, LabelError, PayloadError, RecordEntry, RecordValue, ENROLL_TYPE,
    MAX_RECORD_BYTES, RETIRE_TYPE,
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
