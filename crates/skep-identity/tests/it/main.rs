//! The crate's one integration-test target: every suite below is a module of
//! this binary, not a target of its own, so the gate links these tests once
//! instead of once per file. Nothing but module declarations belongs here.

mod checkpoint;
mod common;
mod fold;
mod grammar;
mod props;
mod read;
mod surface;
mod tidy;
mod write_types;
