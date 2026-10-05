//! The crate's one integration-test target: every suite below is a module of
//! this binary, not a target of its own, so the gate links these tests once
//! instead of once per file. Nothing but module declarations belongs here.
//!
//! The kernel-backed suites are cut by the part of the surface each
//! exercises: one module per op family — `makelink`, `emit`, `nullify`, and
//! `supersession` for the `[K_sup]` op pair and the graph it builds — one per
//! gate that crosses them — `dedup` at the caller's visibility class,
//! `ownership`, the sole-writer `fences`, the per-slot `budget` — and
//! `attested` for the commit marker, `recovery` for the hints a checkpoint
//! must rebuild, the typed reads in `reads` and the §G primitives in
//! `discovery`. Beside them, `carrier` holds the carrier-type, registry and
//! rejection contracts that need no kernel, `common` the assembled test world
//! every suite shares and every kernel the suites open over it, and `tidy` the
//! module map `src/lib.rs` declares — that every file of this tree and of
//! `src/` is declared, each module naming only the modules above it, and that
//! `emit_core` alone mints a link.

mod common;

mod attested;
mod budget;
mod carrier;
mod dedup;
mod discovery;
mod emit;
mod fences;
mod makelink;
mod nullify;
mod ownership;
mod reads;
mod recovery;
mod supersession;
mod tidy;
