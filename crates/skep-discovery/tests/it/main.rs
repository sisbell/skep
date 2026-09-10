//! The crate's one integration-test target: every suite below is a module of
//! this binary, not a target of its own, so the gate links these tests once
//! instead of once per file. Nothing but module declarations belongs here.

mod common;
mod consumer;
mod descriptor;
mod endsets;
mod home_rule;
mod lineage;
mod pointwise;
mod region;
mod survival;
mod window;
