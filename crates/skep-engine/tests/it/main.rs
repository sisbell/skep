//! The crate's one integration-test target: every suite below is a module of
//! this binary, not a target of its own, so the gate links these tests once
//! instead of once per file. Nothing but module declarations belongs here.

mod common;
mod dump_class;
mod editions;
mod febe_demand;
mod fires;
mod genesis;
mod grants;
mod lifecycle;
mod publication;
// The suite's own crate-level `#![cfg(feature = "dump")]` rides its `mod` line
// here: with the feature off the file is not compiled at all.
#[cfg(feature = "dump")]
mod recovery_dump;
