//! # skep-registry — the registry's stable core, as values
//!
//! What the registry's daemon half and its FRONTEND half both read and
//! neither owns: THE TWELVE ROWS the registry allocates in the commons —
//! five kinds and seven subtype rows at the addresses commons-map pins
//! (REG-1.14, REG-1.15, REG-1.24) — THE TWO BODIES the core deposits, the
//! binding's and the endpoint's, under ONE canonical rule (REG-1.86), THE
//! SEEDING CHECK's three arms (REG-1.28 to REG-1.32), and THE VECTOR SET
//! every parser of the bodies is held to (`tests/vectors/records.json`).
//!
//! A LEAF: it depends on `skep-address` and `serde_json` and on nothing
//! else — no engine, no daemon, no signature library — so the daemon's
//! parse and a resolver that links no daemon read one table and hold one
//! `b == encode(parse(b))`.
//!
//! * `rows` — the table ([`rows`], [`Row`], [`Kind`], [`Subtype`]) and its
//!   held readers, `t_binding` … `t_successor_of`, one per row;
//! * `body` — [`Binding`], [`Endpoint`], [`Body`] and [`Record`], the one
//!   parser [`parse`] under the canonical rule, the encoder [`encode`], the
//!   refusals [`Refusal`] and the cap [`MAX_REGISTRY_RECORD_BYTES`];
//! * `check` — [`seeding_check`] and its refusal [`SeedingRefusal`], run by
//!   the daemon ahead of every genesis.
//!
//! The kinds' and subtypes' addresses are commons-map's and are never
//! decided here; a row that moves is a changed line in the map's table and
//! the one table in `rows.rs`.

#![forbid(unsafe_code)]

mod body;
mod check;
mod rows;

pub use body::{
    encode, parse, Binding, Body, BodyKind, Endpoint, Record, Refusal, MAX_REGISTRY_RECORD_BYTES,
};
pub use check::{seeding_check, SeedingRefusal};
pub use rows::{
    commons_type, row, rows, t_binding, t_disavowal, t_endpoint, t_expulsion_ground,
    t_policy_link, t_policy_link_own, t_succession_ground, t_succession_policy, t_successor_of,
    t_takedown, t_takedown_base, t_takedown_lifted, Kind, Row, Subtype, COMMONS_TYPE_PREFIX,
    RESERVE,
};
