//! The crate's one integration-test target: every suite below is a module of
//! this binary, not a target of its own, so the gate links these tests once
//! instead of once per file. Each test states a claim the design or interface
//! makes (§-references inline). Where a debug build's assertion panics,
//! release does something else, and the test says what each build does; the
//! gate runs the suite in both. `common` is the minimal engine assembly the
//! composition contract prescribes and the helpers every suite shares; each
//! other module is one surface. Nothing but module declarations belongs here.

mod common;

mod recovery;
mod standalone;
mod store;
