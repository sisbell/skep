//! The merge internals the `history` module uses.
//!
//! The restore and the diff's read of the records ride the merge's reader,
//! its read of the correspondence records and its mapping through them, and
//! the take-backs' judgement of their one write; this module names each, so
//! the edge between `history` and `merge` is this list. It holds re-exports
//! alone.

pub(crate) use super::reads::{owners_records, records_of, runs_of, session_ended, OnEnd, Reader};
pub(crate) use super::undo::{judge, Act};
pub use super::reads::mapped;
