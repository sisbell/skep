//! The crate's one integration-test target: every suite below is a module of
//! this binary, not a target of its own, so the gate links these tests once
//! instead of once per file. Each test states ONE claim the design or
//! interface makes (§-references inline), in a name that reads as the claim,
//! so a failure names the broken promise. `common` is the minimal engine
//! assembly the composition contract prescribes and the fixtures every suite
//! shares; `tidy` checks the module map — every file declared, each `src/`
//! declaration with its line, the order, and each item named by its home
//! module — that one file alone names the content store, and that one alone
//! compares a count to a budget; each other module holds the claims about one
//! operation, or about one rule that crosses the operations, and the module
//! names are the table of contents.
//! Nothing but module declarations belongs here.

mod common;

mod compare;
mod compare_refusals;
mod deletions;
mod extent;
mod find;
mod head_float;
mod origin;
mod query;
mod retrieve;
mod tidy;
mod traits;
