//! The crate's one integration-test target: every suite below is a module of
//! this binary, not a target of its own, so the gate links these tests once
//! instead of once per file. The target requires the `dump` feature — the
//! manifest's `[[test]]` entry states it, and why — so every module here is
//! compiled against the dump surface. Nothing but module declarations belongs
//! here.

mod common;
mod dump_visible;
mod editions;
mod febe_demand;
mod fires;
mod genesis;
mod grants;
mod lifecycle;
mod publication;
mod recovery_dump;
