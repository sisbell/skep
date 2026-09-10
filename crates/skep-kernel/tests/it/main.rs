//! The crate's one integration-test target: every suite below is a module of
//! this binary, not a target of its own, so the gate links these tests once
//! instead of once per file. Nothing but module declarations belongs here.

mod hazard;
// Shared plumbing, not a suite: `hazard` uses a subset, so the allow that was
// this file's own crate-level attribute rides its `mod` line here.
#[allow(dead_code)]
mod hazard_util;
mod kernel;
