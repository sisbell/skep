//! The crate's one integration-test target: every suite below is a module of
//! this binary, not a target of its own, so the gate links these tests once
//! instead of once per file. Each test states a claim the design or interface
//! makes (§-references inline): what constructors and gates admit and reject,
//! which rejection wins on a multiply-defective input (the pinned orders),
//! that the journaled types survive a serde round trip, and that each part of
//! the interface does its ordinary job. `common` is the minimal engine
//! assembly and the helpers every suite shares, and `heap` the binary's
//! allocator, which counts the heap bytes each thread asks for so a cost
//! claim is a number, and tests that it does; each other module is one
//! surface. Nothing but module declarations belongs here.

mod common;
mod heap;

mod allocation;
mod create_new_document;
mod delegate;
mod genesis;
mod ghost;
mod handle;
mod ownership;
mod publication;
mod recovery;
mod register_node;
