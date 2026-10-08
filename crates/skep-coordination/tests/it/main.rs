//! The crate's one integration-test target: every suite below is a module of
//! this binary, not a target of its own, so the gate links these tests once
//! instead of once per file. Three suites follow the interface's three
//! capability groups — `pl` (A), `defs` (B), `engine` (C) — and `surface`
//! holds what the root publishes across them; each group suite holds its
//! claims as children, one concern each, named in its doc. `tidy` checks both
//! trees' module maps, that every file in either tree is declared, that the
//! guest axis keeps its own words, and that the def decoder reads every tag by
//! its path. `common` is the assembled world and the 2 MiB thread the depth
//! tests measure on; `terms` the shared term builders and rule fixtures.
//! Nothing but module declarations belongs here.

mod common;
mod terms;

mod defs;
mod engine;
mod pl;
mod surface;
mod tidy;
