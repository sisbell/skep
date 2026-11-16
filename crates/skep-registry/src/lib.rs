//! # skep-registry — the registry's stable core, as values
//!
//! What the registry's two halves — the daemon that verifies and commits a
//! registry deposit, and the client's half, a resolver that reads it back —
//! both read and neither owns: THE ROWS the registry allocates in the
//! commons — its kinds and their subtype rows at the addresses commons-map
//! pins, counted off one list and written as a tally nowhere (REG-1.14,
//! REG-1.15, REG-1.24 to REG-1.26) — THE BODIES parsed at the record grade
//! (REG-1.86 (a)), the binding's, the endpoint's and the registration
//! kind's six, under ONE canonical rule (REG-1.86 (h)), THE DOOR'S POLICY
//! DOCUMENT under that same rule, THE SEEDING CHECK's three arms (REG-1.28
//! to REG-1.32), THE VOCABULARY — every link type the build names in the
//! commons, the one table the daemon seeds the registry document from at
//! every open and a client reads a type's name by — and THE VECTOR SETS
//! every parser of the bodies is held to (`tests/vectors/records.json`,
//! `registration.json`, `policy.json`).
//!
//! A LEAF: it depends on `skep-address` and `serde_json` and on nothing
//! else — no engine, no daemon, no signature library — so the daemon's
//! parse and a resolver that links no daemon read one table and hold one
//! `b == encode(parse(b))`.
//!
//! * `rows` — the table ([`rows()`], [`Row`] with the [`RowOf`] it is the
//!   row of, its computed [`Row::carries_deposits`] and its
//!   [`Row::ordinal_path`], [`Kind`] and [`Subtype`], each naming its own
//!   row — [`Kind::row`], [`Subtype::row`] — a subtype its parent row where
//!   it stands under one ([`Subtype::parent`]), and [`row_at`], the row an
//!   address is), its held readers, `t_registration` … `t_successor_of`,
//!   one per row, and [`commons_type`], a commons type address at one or
//!   more positive ordinals;
//! * `body` — [`Binding`], [`Endpoint`] with its [`Origins`], [`Body`] and
//!   [`Record`], the kind [`BodyKind`] a parse is named under, the one parser
//!   [`parse`] under the canonical rule, the encoder [`encode`], [`Member`] —
//!   each member's one name, which a parse and an encoder spell it by and
//!   a refusal names — the refusals [`ParseRefusal`], the cap
//!   [`MAX_REGISTRY_RECORD_BYTES`] and the top of the exactly-representable
//!   range [`MAX_EXACT_NUMBER`] — and the canonical machinery every body of
//!   the crate is parsed and encoded through;
//! * `registration` — the registration kind's six bodies as types of their
//!   own: [`RegistrationKind`], [`RegistrationBody`] over [`Fresh`],
//!   [`BoardCarriesOn`], [`Approved`] with its [`ProvisionedBoard`] and
//!   [`Disposition`], [`Refused`] with its [`Fault`], [`Denied`] and
//!   [`Vouch`], [`RegistrationRecord`], the parser [`parse_registration`]
//!   and the encoder [`encode_registration`], a request's members as one
//!   view ([`RequestMembers`]), the forms the parse holds a member to and
//!   the types carry — [`Hex64`], [`HexDigits`], [`Digits`], [`Principal`]
//!   — and the request's own cap [`MAX_REGISTRATION_REQUEST_BYTES`];
//! * `policy` — the door's policy document as a parsed value,
//!   [`AdmissionPolicy`] with its [`Admission`] mode, the one parser
//!   [`parse_policy`] and the encoder [`encode_policy`], the document's
//!   `type` string [`POLICY_TYPE`], and the approval's hand as its reader
//!   honors it, [`AdmissionPolicy::approval_hand`] answering an
//!   [`ApprovalHand`];
//! * `check` — [`seeding_check`] and its refusal [`SeedingRefusal`], run by
//!   the daemon ahead of every genesis;
//! * `vocabulary` — THE VOCABULARY, every link type this build names in the
//!   commons as one table ([`vocabulary()`], a [`Definition`] per row with
//!   its address, path, name, purpose and endset shape, and the section the
//!   daemon writes for it, [`Definition::section`]), [`definition_at`], the
//!   row an address is, and [`defines_type`], the meta-type `3.50` every
//!   definition link is typed by — what the daemon seeds into the registry
//!   document at every open, and what a client reads a type's name by.
//!
//! The kinds' and subtypes' addresses are commons-map's and are never
//! decided here; a row that moves is a changed line in the map's table and
//! the one table in `rows.rs`, and the vocabulary's row with it.

#![forbid(unsafe_code)]

mod body;
mod check;
mod policy;
mod registration;
mod rows;
mod vocabulary;

pub use body::{
    encode, parse, Binding, Body, BodyKind, Endpoint, Member, Origins, ParseRefusal, Record,
    MAX_EXACT_NUMBER, MAX_REGISTRY_RECORD_BYTES,
};
pub use check::{seeding_check, SeedingRefusal};
pub use policy::{
    encode_policy, parse_policy, Admission, AdmissionPolicy, ApprovalHand, POLICY_TYPE,
};
pub use registration::{
    encode_registration, parse_registration, Approved, BoardCarriesOn, Denied, Digits,
    Disposition, Fault, Fresh, Hex64, HexDigits, Principal, ProvisionedBoard, Refused,
    RegistrationBody, RegistrationKind, RegistrationRecord, RequestMembers, Vouch,
    MAX_REGISTRATION_REQUEST_BYTES,
};
pub use rows::{
    commons_type, row_at, rows, t_approval, t_binding, t_disavowal, t_endpoint,
    t_expulsion_ground, t_policy_link, t_policy_link_own, t_registration, t_reply,
    t_reply_approved, t_reply_denied, t_reply_refused, t_request, t_request_board_carries_on,
    t_request_fresh, t_succession_ground, t_succession_policy, t_successor_of, t_takedown_base,
    t_takedown_lifted, t_takedown_record, t_vouch, Kind, Row, RowOf, Subtype,
};
pub use vocabulary::{defines_type, definition_at, vocabulary, Definition};
