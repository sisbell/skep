//! # skep-identity — AUTH: the credential data model and the identity fold
//!
//! The PURE heart of AUTH (AUTH-2.1): no I/O, no clock, no config, no
//! signature library, and no dependency on the engine — the edge runs the
//! other way, the engine seating this crate's fold as its World's identity
//! slice. Dependencies are exactly `skep-address` (M1), `sha2`, `im`,
//! `serde` and `serde_json` — the last answering one question, which JSON
//! value a record's bytes are, with every verdict written here
//! (`payload.rs`) — light enough for the engine, M10, checkpoint/replay, and
//! any mirror tool to carry. AUTH-2.2 casts the crates around it:
//! `crates/skep-signature` the one crate that links the signature libraries
//! (Ed25519, ML-DSA, FN-DSA), whose verify `crates/skepd` calls — the fence
//! is the SESSION verify's, `verify`/`find_signer`, the daemon's check of a
//! handshake against the fold's key sets — the World slice, fold hook and
//! load check in `crates/skep-engine`, and the conformance pins in the
//! crates' own suites, `crates/skep-conformance` depending on nothing here.
//!
//! ## Composition, as built
//!
//! Who depends on this crate, and for what: one bullet per dependent, at the
//! grain of a role, so the list moves only when an edge does. What each does
//! with what it takes is that crate's own to say, and the workspace's
//! `ARCHITECTURE.md`, §Code map, draws every crate's edges.
//!
//! * `skep-engine` SEATS THE FOLD, as the spec casts it (AUTH-2.79–2.88): its
//!   `World` carries the [`IdentityState`] as its identity slice — `Some` on
//!   every loaded World, checkpointed with the world and never rebuilt from
//!   the deposits — implements [`Values`], [`FoldCtx`] and [`HasIdentity`]
//!   over its own slices, holds the ONE [`TypeAddrs`] (`IDENTITY_TYPES`,
//!   beside the three credential type pins in its commons ledger), and steps
//!   the slice through [`IdentityState::step`] at every credential deposit's
//!   commit, inside the transaction that deposits the link (AUTH-2.80,
//!   AUTH-2.66) — so a reopen and every historical read carry the table the
//!   live fold answered. At load a checkpoint written WITHOUT the slice is
//!   resolved — the empty table over no credential deposit — or refused as a
//!   start point (AUTH-2.83, AUTH-2.84), through M2's fallible seed seam
//!   (AUTH-2.85).
//! * `skepd` reads the slice off whichever World snapshot it holds, through
//!   [`HasIdentity`], and guards the write path from its session layer
//!   (`auth`; the workspace's `ARCHITECTURE.md`, §The daemon): it prechecks
//!   each credential deposit through the fold the engine's hook applies to
//!   the same deposit at the commit, classifies a `nullify`'s target link,
//!   derives its enforcement mode from the board's claim, and composes every
//!   preimage it verifies — a session handshake's, and both signed-ops
//!   grades' — with each signature and marker tag read against this crate's
//!   tables.
//! * `skep-signature`, the one crate that links the signature libraries
//!   (AUTH-2.2), holds each marker tag's frozen rules — its verification and
//!   its keygen-from-seed — over the marker-tag table's rows and a hybrid
//!   key's two halves, composing a key at keygen and reading its halves to
//!   verify; skepd, the signing client and the resolver call its verify.
//! * `skep-client`, the SIGNING CLIENT, holds keys, spells credential records
//!   and composes the frames it signs; its reader's verifier composes the
//!   same frames back and checks each record's `sig` over them.
//! * `skep-resolve`, the registry resolver, reads the key set that opens an
//!   account as of a record's LOG position, finds an account's doc 1, and
//!   checks each registry record's `sig` over its frame.
//! * `skep-cli`, the `skep` command, names keys by their fingerprints and
//!   spells the enrollment records its key commands print.
//! * From their suites only: `skep-mcp`, to build records and sign session
//!   payloads, and `skep-search`, to sign the writes its budgets suite
//!   commits to a dev board.
//! * Nothing here: M10's `skep-febe` and `skep-conformance`. The I2 pins ride
//!   in this crate's own `tests/it/`, and the World's slice bytes beside them.
//!
//! Which file of a dependent takes what is that crate's arrangement:
//! `grep -rln skep_identity crates/*/src` answers it however each is cut.
//!
//! Some public items are public for a reason a grep for callers cannot see,
//! so finding no caller is no reason to narrow one. [`Tag`],
//! [`ParseKeyError`], [`LabelError`], [`PayloadError`], [`PublishRefusal`]
//! and [`RecordEntry`] are public because a public signature names them. The
//! rest the spec or the design record declares for a reader it names — in
//! this workspace `skep-client` is a signing client with a verifier beside
//! the table and `skep-resolve` a mirror; outside it, bebe and any mirror or
//! audit tool: [`canonical_record`], [`parse_enroll`], [`parse_retire`] and
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
//! constants the design record declares beside them (AUTH-1.5's cite). One
//! item the spec declares crate-private is published too: [`doc_1_of`]
//! (AUTH-2.126), since every honored credential link is homed in a doc 1
//! (AUTH-2.127) and a reader holding no M3 — a mirror or an audit tool
//! embedding this crate — computes that address here. M3 computes the same
//! address as `first_document_address`, which AUTH-2.1's dependency set
//! keeps out of this crate, and skepd's suite holds the two equal at every
//! account. The named reader is why each of these is public, whether or not
//! a crate of this workspace calls it today, and the suite's `surface.rs`
//! names each of them from outside the crate, so narrowing one fails the
//! build there.
//!
//! ## What lives here
//!
//! One bullet per module, named first: what the module is for, the items a
//! caller starts from, and the rules it realizes — never what each item does,
//! which is that item's own card, nor everything it exports, which is its
//! `pub use` line below — so a bullet moves when its module's job does, not
//! each time an item's card does. `state` — the fold — sits on top and no
//! module imports it; `entry` imports only `framing`, and `write_types` only
//! `shape`, so the signed-ops frame and the write path's classes read no fold
//! state and write none. The suite's `tidy.rs` checks all three, and this list
//! against `src/`.
//!
//! * `key`: keys and fingerprints — [`PublicKey`] with its refusal
//!   [`ParseKeyError`]; the algorithm table [`ALGS`] with its row type
//!   [`AlgRow`] and its rows' `ALG_*` tokens; the marker-tag table
//!   [`SIG_ALGS`] with [`SigAlgRow`], and the [`HybridBlob`] its widths
//!   admit; and [`Fingerprint`] (AUTH-1.1–1.10, AUTH-4.34, AUTH-6.3; signed
//!   ops);
//! * `framing`: framing and the tag set — [`Tag`], [`framed`], [`TAGS`]
//!   (AUTH-1.11–1.17);
//! * `entry`: THE ENTRY FRAME under [`ENTRY_TAG`] — the bytes a publish-class
//!   entry's signature, or a record's `sig`, is made over: [`entry_frame`],
//!   its terms [`BoardTerm`] and [`DocTerm`], and the [`EntryBody`] each
//!   grammar's builders return; the `publish` body's budgeted builder
//!   [`PublishBody`], with its refusal [`PublishRefusal`], in the child module
//!   `entry::publish`, the one module its fields are visible to; and
//!   [`RecordFrame`], the record grade's frame (signed ops; the design record
//!   §2.5; the frame merge);
//! * `payload`: the credential records — [`ENROLL_TYPE`], [`RETIRE_TYPE`],
//!   [`MAX_RECORD_BYTES`], [`Enrollment`] with its refusal [`LabelError`],
//!   [`PayloadError`] (AUTH-1.18–1.28) — and their JSON schemas and canonical
//!   encoding: the fold's [`parse_enroll`]/[`parse_retire`], the encoders
//!   [`encode_enroll`]/[`encode_retire`], the verifier's
//!   [`parse_record_value`] with its [`RecordValue`], and [`canonical_record`]
//!   (AUTH-2.15–2.19, AUTH-2.128–2.130; the design record §4.2 (C));
//! * `read`: the ONE pinned payload read — [`record_bytes`] (AUTH-2.3–2.5,
//!   AUTH-2.36–2.45);
//! * `keyset`: the key set — [`Enrolled`], [`KeySet`] (AUTH-1.29–1.37);
//! * `shape`: shape recognition — [`CredentialKind`], [`TypeAddrs`],
//!   [`LinkDeposit`], [`single_address`] (AUTH-2.20–2.28);
//! * `write_types`: the write path's type-recognition input —
//!   [`WriteTypes`]/[`TargetClass`]/[`AuditClass`] (PUB-6.30, PUB-6.64,
//!   REG-1.44, REG-1.46; owner ruling D3): the grant and audit-view classes a
//!   `nullify` is refused at, read off the fold's recognition with `kind_of`
//!   untouched;
//! * `seam`: the fold seam — [`Values`], [`FoldCtx`], [`Owner`]
//!   (AUTH-2.29–2.34);
//! * `verdict`: the fold's answers — [`Verdict`], [`Effect`], [`Inert`]
//!   (AUTH-2.51–2.55);
//! * `state`: the fold itself — [`IdentityState`] with `classify`/`step`,
//!   [`HasIdentity`], the doc-1 address [`doc_1_of`], and the fold's ω
//!   projections, private to it (AUTH-1.38–1.41, AUTH-2.35, AUTH-2.56–2.60,
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
//!   function cannot live here (skepd's session layer holds it).
//! * Enforcement-mode derivation (AUTH-1.42–1.43) — a per-read formula over
//!   the board's claim ([`IdentityState::claimant`]) plus
//!   `AuthConfig.local_trust`, computed daemon-side with nothing stored; no
//!   signature is pinned for it here.
//! * `IDENTITY_TYPES`, the `World::apply` hook, slice-less recovery
//!   (AUTH-2.79–2.88) — the engine's integration over this crate's types
//!   (`skep-engine`'s `world::identity` and `types`), and skepd's startup
//!   warnings over the engine's report (AUTH-2.86).
//!
//! ## Traceability
//!
//! Every public item's doc-comment cites the authority it realizes: AUTH's
//! rule and invariant labels; on the write path's type-recognition input the
//! publication spec's (PUB-6.30, PUB-6.64, RES-207) and owner ruling D3; and
//! on signed ops' declarations — the marker-tag table, a key's halves, the
//! length constants, the entry frame and the record projection, which the
//! AUTH spec declares in no rule and whose authority AUTH-1.5 assigns, by
//! cite, to the signed-ops design record — that document, cited as "the
//! design record" with its section or ruling, and never as "the record" or
//! "its record" alone: in this crate a record is one a board holds — a
//! credential record (AUTH-1.18), or a registry record the record grade signs
//! beside it — never a design document, and the suite's `tidy.rs` holds every
//! comment to that rule. So a reviewer can walk from code to its authority
//! without the documents open.
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
    DocTerm, EntryBody, EntrySlot, LinkSlots, PublishBody, PublishRefusal, RecordFrame, RecordRows,
    ShotBase, ShotSegmentPiece,
};
pub use framing::{
    framed, Tag, ENTRY_TAG, KEY_TAG, NODE_HELLO_TAG, SESSION_TAG, SESSION_TAG_V2, TAGS,
};
pub use key::{
    AlgRow, Fingerprint, HybridBlob, ParseKeyError, PublicKey, SigAlgRow, ALGS,
    ALG_FNDSA512_PREVIEW_ED25519, ALG_MLDSA65_ED25519, ED25519_KEY_LEN,
    FNDSA512_PREVIEW_ED25519_KEY_LEN, FNDSA512_PREVIEW_KEY_LEN, MLDSA65_ED25519_KEY_LEN,
    MLDSA65_KEY_LEN, SIG_ALGS,
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
pub use state::{doc_1_of, HasIdentity, IdentityState};
pub use verdict::{Effect, Inert, Verdict};
pub use write_types::{AuditClass, TargetClass, WriteTypes};

/// What this crate's hosts demand of the values they keep across threads:
/// the engine's `World` carries the [`IdentityState`] as a slice under M2's
/// `WorldState: Send + Sync + 'static` (AUTH-2.79), and the engine and skepd
/// hold ONE [`TypeAddrs`] and ONE [`WriteTypes`] in `static`s for the
/// process's life (`Send + Sync`). NOTHING in this crate names those bounds,
/// so a field that revoked one — an `Rc`, a `Cell`, a cached `dyn` matcher —
/// would compile here and break the engine's or skepd's build at its
/// `static` or its `WorldState` impl, never naming the field that caused it.
/// The promises are checked here instead, covering `KeySet`, `Enrolled`,
/// `PublicKey`, `Fingerprint`, `Address` and `Span` transitively.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync + 'static>() {}
    assert_send_sync::<IdentityState>();
    assert_send_sync::<TypeAddrs>();
    assert_send_sync::<WriteTypes>();
};
