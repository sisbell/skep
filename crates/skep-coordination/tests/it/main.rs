//! The crate's one integration-test target: every suite below is a module of
//! this binary, not a target of its own, so the gate links these tests once
//! instead of once per file. The three suites follow the interface's three
//! capability groups; `common` is the assembled world, `terms` the shared
//! term builders. Nothing but module declarations belongs here.

mod common;
mod terms;

mod defs;
mod engine;
mod pl;
