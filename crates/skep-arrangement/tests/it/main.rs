//! The crate's one integration-test target: every suite below is a module of
//! this binary, not a target of its own, so the gate links these tests once
//! instead of once per file. Each test states a claim the design or interface
//! makes (§-references inline): what each op admits and rejects (and WHICH
//! error wins when several conditions fail at once), that every mutation is
//! one committed composite whose rejection leaves no state change, the
//! J-couplings observable through one snapshot (J0/J1★/J-LV),
//! transclusion-by-reference, NonDestruction, the fork share, the level-class
//! discipline surfaces, the version-chain model's three write-path refusals
//! with the declared-deposit exemption (PUB round 2, lane 3.1), the publish
//! shot, and that the journaled slice survives serde plus M2's real
//! checkpoint-and-replay recovery. `common` is the minimal engine assembly the
//! composition contract prescribes and the helpers every suite shares; `tidy`
//! checks the module order `src/lib.rs` declares; each other module is one
//! surface. Nothing but module declarations belongs here.
//!
//! This binary compiles as a FOREIGN crate, so it also witnesses the sealing
//! claims: `M5Rec` cannot be built here, `Run` fields cannot be reached or
//! mutated (accessors only), and every suite drives the system through
//! `Vstream`/`stage_seat_link`/`seat_link` alone. It witnesses the other half
//! of the surface too — the standard traits the public values carry, which a
//! foreign crate could not add for itself.

mod common;

mod attested;
mod copy;
mod delete;
mod head_float;
mod insert;
mod ownership;
mod published_target;
mod reads;
mod rearrange;
mod recovery;
mod seat;
mod shot;
mod shot_refusals;
mod tidy;
mod traits;
mod version;
