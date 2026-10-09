//! The crate's one integration-test target: every suite below is a module of
//! this binary, not a target of its own, so the gate links these tests once
//! instead of once per file. Each test states a claim the design or interface
//! makes (§-references inline): what each op admits and rejects (and WHICH
//! error wins when several conditions fail at once), that every mutation is
//! one committed composite whose rejection leaves no state change, the
//! J-couplings observable through one snapshot (J0/J1★/J-LV),
//! transclusion-by-reference, NonDestruction, the fork share, the reads the
//! level-class discipline governs, the version-chain model's three
//! write-path refusals with the declared-deposit exemption (PUB round 2,
//! lane 3.1), the publish shot, and that the journaled slice survives serde
//! plus M2's real checkpoint-and-replay recovery. `common` is the minimal
//! engine assembly the composition contract prescribes and the helpers every
//! suite shares; `tidy` checks the module tree — every file declared, every
//! `src/` declaration with its map line, the order `src/lib.rs` declares —
//! and the `M5State` method calls no path records; each other module is one
//! subject. Nothing but module declarations belongs here.
//!
//! This binary compiles as a FOREIGN crate, so it drives M5 as one does —
//! through `Vstream`, `stage_seat_link` and `seat_link` — and witnesses the
//! half of the public API a foreign crate could not add for itself: the
//! standard traits the public values carry. The seals a foreign crate meets
//! cannot be witnessed by code that compiles; the `compile_fail` pairs on
//! `Run` and `M5Rec` pin them, and the gate runs them as doctests.

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
