//! The crate's one integration-test target: every suite below is a module of
//! this binary, not a target of its own, so the gate links these tests once
//! instead of once per file. Nothing but module declarations belongs here.

mod arithmetic;
mod common;
mod errors;
mod hostile_shapes;
mod laws;
mod serde_boundary;
mod spans;
mod spansets;
mod values;
