//! The crate's one integration-test target: every suite below is a module of
//! this binary, not a target of its own, so the gate links these tests once
//! instead of once per file. Nothing but module declarations belongs here.

// The board both suites spawn, shared plumbing rather than a suite.
mod common;
mod fuzz_mcp;
mod mcp;
