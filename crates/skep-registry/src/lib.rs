//! # skep-registry — the registry's stable core, as values
//!
//! What the registry's two halves — the daemon that verifies and commits a
//! registry deposit, and the client's half, a resolver that reads it back —
//! both read and neither owns: THE TWELVE ROWS the registry allocates in the
//! commons — five kinds and seven subtype rows at the addresses commons-map
//! pins (REG-1.14, REG-1.15, REG-1.24) — THE TWO BODIES parsed at the
//! record grade (REG-1.86 (a)), the binding's and the endpoint's, under ONE
//! canonical rule (REG-1.86 (h)), THE SEEDING CHECK's three arms (REG-1.28
//! to REG-1.32), THE VOCABULARY — every link type the build names in the
//! commons, the one table the daemon seeds the registry document from at
//! every open and a client reads a type's name by — and THE VECTOR SET every
//! parser of the bodies is held to (`tests/vectors/records.json`).
//!
//! A LEAF: it depends on `skep-address` and `serde_json` and on nothing
//! else — no engine, no daemon, no signature library — so the daemon's
//! parse and a resolver that links no daemon read one table and hold one
//! `b == encode(parse(b))`.
//!
//! * `rows` — the table ([`rows()`], [`Row`] with the [`RowOf`] it is the
//!   row of and its computed [`Row::carries_deposits`], [`Kind`] and
//!   [`Subtype`], each naming its own row — [`Kind::row`], [`Subtype::row`]
//!   — and [`row_at`], the row an address is), its held readers,
//!   `t_binding` … `t_successor_of`, one per row, and [`commons_type`], a
//!   commons type address at one or more positive ordinals;
//! * `body` — [`Binding`], [`Endpoint`] with its [`Origins`], [`Body`] and
//!   [`Record`], the kind [`BodyKind`] a parse is named under, the one parser
//!   [`parse`] under the canonical rule, the encoder [`encode`], [`Member`] —
//!   each member's one name, which the parse and the encoder spell it by and
//!   a refusal names — the refusals [`ParseRefusal`], and the cap
//!   [`MAX_REGISTRY_RECORD_BYTES`];
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
mod rows;
mod vocabulary;

pub use body::{
    encode, parse, Binding, Body, BodyKind, Endpoint, Member, Origins, ParseRefusal, Record,
    MAX_REGISTRY_RECORD_BYTES,
};
pub use check::{seeding_check, SeedingRefusal};
pub use rows::{
    commons_type, row_at, rows, t_binding, t_disavowal, t_endpoint, t_expulsion_ground,
    t_policy_link, t_policy_link_own, t_succession_ground, t_succession_policy, t_successor_of,
    t_takedown_base, t_takedown_lifted, t_takedown_record, Kind, Row, RowOf, Subtype,
};
pub use vocabulary::{defines_type, definition_at, vocabulary, Definition};
