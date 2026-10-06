//! The crate's one integration-test target: every suite below is a module of
//! this binary, not a target of its own, so the gate links these tests once
//! instead of once per file. Nothing but module declarations belongs here.
//!
//! The suites spawn skepd IN-PROCESS on an ephemeral port over a temp data
//! dir, as skep-mcp's suite does, and drive THE LIBRARY — the walks with the
//! scripted `Person`, the compositions by their own calls; another hand is
//! the wire transcript re-driven (`common`'s `wire_*`), never a ceremony.
//! Two need no daemon: `backup`, the moment alone, and `tidy`, which reads
//! the crate's own source for the arrangement it promises.

mod backup;
mod claim;
mod common;
mod enroll;
mod handoff;
mod handshake;
mod hosted;
mod loss;
mod recover;
mod retire;
mod rotate;
mod tidy;
mod verifier;
