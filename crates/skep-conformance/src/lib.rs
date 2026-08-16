//! # skep-conformance — the golden-scenario conformance harness
//!
//! Plays the 297 vendored udanax-green golden scenarios
//! (`skep/conformance/golden/`: the original 263 plus the 34-scenario
//! corpus extension of 2026-08-15 — multisession, n-ary/cross-document
//! links, compare fan-out, provenance surface, depth and boundary probes)
//! against skep's real command surface — `Operation<World>::execute` from
//! skep-febe over a fresh `skep-engine` world per scenario — and reports,
//! honestly, scenario by scenario, where the two systems agree and where
//! they diverge. Multisession scenarios drive several sessions against the
//! ONE engine: `account` ops bind golden session labels to accounts, and
//! each op routes through its label's session.
//!
//! One discipline governs everything: **the harness never negotiates with
//! the goldens and never negotiates with skep.** A divergence is a finding
//! to record, not a failure to fix. The five mechanisms:
//!
//! * [`loader`] — dynamic-JSON scenario loading; every op label is either
//!   normalized to a canonical verb or classified `inexpressible` with the
//!   label recorded, never silently skipped.
//! * [`ground`] — the shadow-only pre-pass that reconstructs the recording
//!   scripts' UNRECORDED setup (implied creates, derived initial content,
//!   macro-op expansion plans) from the scenario's own recorded evidence;
//!   every inference is tagged into the report's `groundings` list.
//! * [`translate`] — the canonical-verb catalogue: one boring arm per verb,
//!   with every adaptation policy named and recorded per-op ([`fields`]
//!   holds the shared field-bag / decorated-description grammar both passes
//!   read through).
//! * [`alpha`] — the per-scenario golden↔skep address bijection; the three
//!   α-failure classes are findings with their own report classes.
//! * [`compare`] — one comparator per result type; a failed comparison
//!   carries expected, actual (with bijection state), and the comparator
//!   that judged it.
//! * [`allowlist`] — `skep/conformance/allowlist.toml`; a divergence with a
//!   matching entry is verdict `allowlisted`, without one `divergent`.
//!
//! The gate (`tests/gate.rs`) asserts **harness integrity only** — goldens
//! load, every op is classified, no scenario panics, the report and summary
//! are written. Divergent scenarios are the run's *product*, not its
//! failure.

pub mod allowlist;
pub mod alpha;
pub mod compare;
pub mod fields;
pub mod ground;
pub mod harness;
pub mod loader;
pub mod outcome;
pub mod report;
pub mod runner;
pub mod shadow;
pub mod translate;
pub mod tum;

use std::path::PathBuf;

/// `skep/conformance/` located from this crate — the golden tree and the
/// allowlist live here.
pub fn conformance_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance")
}

/// `skep/target/conformance/` — where the report and summary are written.
pub fn output_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/conformance")
}
