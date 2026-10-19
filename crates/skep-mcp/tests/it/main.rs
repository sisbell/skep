//! The crate's one integration-test target: every suite below is a module of
//! this binary, not a target of its own, so the gate links these tests once
//! instead of once per file. Nothing but module declarations belongs here.

// The board the suites spawn and claim, and the adapter driver: shared
// plumbing rather than a suite.
mod common;
// The fence: the signed session, the seam, the tools, the pull, the
// settings, the session's life, a refusal as a result, the stream.
mod agent;
mod fuzz_mcp;
mod mcp;
