//! The crate's one integration-test target: every suite below is a module of
//! this binary, not a target of its own, so the gate links these tests once
//! instead of once per file. Nothing but module declarations belongs here.

mod chain;
// The engine fixture, not a suite: `hazard`, `golden` and `chain` each use a
// subset of it, so the `dead_code` allow rides its `mod` line.
#[allow(dead_code)]
mod fixture;
mod golden;
mod hazard;
mod kernel;
mod mutilate;
