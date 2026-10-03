//! The crate's one integration-test target: every suite below is a module of
//! this binary, not a target of its own, so the gate links these tests once
//! instead of once per file. Three suites follow the interface's three
//! capability groups — `pl` (A), `defs` (B), `engine` (C) — and `surface`
//! holds what the root publishes across them; each group suite holds its
//! claims as children, one concern each. `tidy` checks the source
//! tree's module map, and that every file in either tree is declared.
//! `common` is the assembled world, `terms` the shared term builders. Nothing
//! but module declarations belongs here.

mod common;
mod terms;

mod defs;
mod engine;
mod pl;
mod surface;
mod tidy;
