//! The merge internals the `history` module uses.
//!
//! The restore and the diff's read of the records ride the merge's reader,
//! its read of the correspondence records, its mapping of an image and of
//! the core's runs through them, and the take-backs' spelling and judgement
//! of their one write, with the one change over a draft's whole content;
//! this module names each, so the edge between
//! `history` and `merge` is this list. It holds re-exports alone.

pub(crate) use super::reads::{owners_records, runs_of, session_ended, OnEnd, Reader};
pub(crate) use super::undo::{judge, whole_change, Act};
pub use super::reads::{mapped, mapped_image};
pub use super::undo::written_runs;
