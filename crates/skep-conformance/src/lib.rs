//! # skep-conformance — the golden-scenario conformance harness
//!
//! Plays the 297 vendored udanax-green golden scenarios
//! (`skep/conformance/golden/`: the original 263 plus the 34-scenario
//! corpus extension of 2026-08-15 — multisession, n-ary/cross-document
//! links, compare fan-out, provenance surface, depth and boundary probes)
//! against skep's real command surface — `OperationSurface<World>::execute`
//! from skep-febe over a fresh `skep-engine` world per scenario — and
//! reports, honestly, scenario by scenario, where the two systems agree and
//! where they diverge. Multisession scenarios drive several sessions
//! against the ONE engine: `account` ops bind golden session labels to
//! accounts, and each op routes through its label's session.
//!
//! One discipline governs everything: **the harness never negotiates with
//! the goldens and never negotiates with skep.** A divergence is a finding
//! to record, not a failure to fix.
//!
//! ## How a scenario runs
//!
//! `loader::load_all` reads every scenario. `ground::ground` walks one in
//! shadow space alone and rebuilds the setup its recording script performed
//! but never recorded — implied creates, initial content, expansion plans —
//! each inference tagged into the report's `groundings`. A fresh
//! `rig::Rig` opens an in-memory engine and its operation surface, and
//! the α-bijection is seeded with udanax's default account, `1.1.0.1`,
//! bound to the rig's own; the implied creates and the lead-in execute
//! through the rig. `play::run_op` then plays each op in order:
//! normalized to a canonical verb (or classified inexpressible, the reason
//! recorded), executed, and judged by `compare`'s comparator for its result
//! type. `runner` folds each op's α-findings into its outcome and asks the
//! allowlist which adjudicated classes cover it — a disagreement an entry
//! covers is `allowlisted`, one no entry covers stays `divergent` — and
//! folds the outcomes into one verdict per scenario; `report` writes
//! `report.jsonl` and `summary.md`.
//!
//! ## What holds across files
//!
//! * **One door to skep.** The engine and its operation surface are private
//!   fields of `rig::Rig`: every request the harness makes goes through
//!   `OperationSurface::execute` inside a `Rig` method, and nothing else in
//!   the crate holds either. Each request passes one function, the rig's
//!   `execute`, the crate's only call of the surface: a panic raised inside
//!   skep leaves it as `rig::EnginePanic`, naming the request, and `runner`
//!   reports the scenario stopped by skep at that op — never as a harness
//!   bug, and never as a finding an allowlist entry could cover.
//! * **The shadow is golden-side, and has one owner.** Whether a recorded op
//!   changed the golden-side world is one answer, `evidence::took_effect`,
//!   which an `evidence::Effect` carries into every change, and in the play
//!   pass the shadow changes only through the `Cx` world-change methods in
//!   `play`, which `tests/it/tidy.rs` holds every other play-pass file to.
//!   Content follows the recording, whatever skep answers; a created
//!   document, version or link enters the shadow only when skep made it
//!   too, so a version skep refuses leaves its later name-references
//!   ungroundable — the class rulings 20 and 20a freeze. In both passes a
//!   document is minted once (`Shadow::create_doc` stops a second mint),
//!   and an edit of a document the shadow does not hold changes nothing.
//! * **Both passes read an op the same way.** The pre-pass and the play
//!   pass share one grammar for an op's fields (`fields`: the verb an op's
//!   name reads as, the document an op aims at, an op's arguments, a vcopy's
//!   sources, the content a read's recording answers with) and one set of
//!   policies for what its recorded evidence says it did (`evidence`: where
//!   an insert lands, what a delete removed). `ground`'s simulation still
//!   restates each verb's effect on the shadow and decides which ops probe
//!   it; nothing but review keeps those alike: change them together.
//! * **Harness infrastructure never reaches a comparison.** The types
//!   document, each rig account's home and the setup grant it holds, the rig
//!   accounts, and the grants class address are told apart by one
//!   predicate, `Rig::is_infra_addr`; an answer that can carry them is
//!   filtered through it once, at receipt, by the handler that asked —
//!   before it is compared or bound into α — and `compare`'s comparators
//!   take an answer so filtered as their precondition.
//! * **One outcome per op; one place judges.** `play::run_op` returns
//!   exactly one `OpOutcome` per recorded op it plays to an end — a panic
//!   instead stops the scenario at that op, verdict `error` — and an op
//!   judged part by part settles through one `Tally` — a part judged as an
//!   op of its own folds in whole, its adaptations and notes included — so
//!   `agreed` always means compared and matched. A read ends `not-compared`
//!   only when its recording kept no answer: one whose recorded answer no
//!   reader reaches is `inexpressible`, the unread keys named (`play`'s
//!   `compared_nothing`). Only `runner` drains α's findings and asks the
//!   allowlist, `Allowlist::classify`, which classes cover an outcome — for
//!   a scenario named by its key, `category/name` (`outcome::ScenarioKey`),
//!   the identity every adjudication uses — and folds the outcomes into one
//!   verdict by the order `outcome::Verdict` states.
//! * **Scenario documents are minted private** — `published: Some(false)`
//!   (PUB-8.16) — by the one method that creates them,
//!   `Rig::create_private_document`, in the current session's own account.
//! * **Names have one home.** Every adaptation policy is named in `play`'s
//!   module doc and recorded per op when applied; the standing divergence
//!   analyses are `compare`'s constants, each citing its ruling, which
//!   `report` finds in the op notes by containment.
//!
//! ## The gate
//!
//! The integration binary under `tests/it/` holds the gate, `gate.rs`, the
//! oracle's own suite, `oracle.rs`, and this map's check, `tidy.rs`. The gate's
//! three tests over the sweep: `harness_integrity` — the instrument works:
//! every golden loads, every op yields one outcome, no scenario is stopped by a
//! panic, skep's or the harness's, the report is written;
//! `report_is_deterministic` — a replay of every scenario renders
//! byte-identical records; and `conformance_ratchet`, where conformance is
//! enforced against `conformance/ratchet.toml` — an `error` verdict fails it
//! for every scenario, `[pending]` included; a `divergent` verdict fails it
//! unless `[pending]` lists the scenario; an `allowlisted` or `inexpressible`
//! verdict fails it unless the file freezes the scenario in that section or
//! `[pending]`; and so do a frozen key no golden carries, a key the file lists
//! twice, and an allowlist entry that rules on no golden op. A `[pending]`
//! scenario's other verdicts are reported, not enforced, so a green gate admits
//! every divergent scenario `[pending]` lists. The ratchet freezes verdicts, so
//! it reads a scenario turning `pass` as an improvement; `oracle.rs` holds what
//! it cannot — hand-built scenarios, played through the real engine, pinning
//! how op outcomes become a verdict, which agreements the harness may record,
//! and which references it refuses rather than re-aims. `tidy.rs` holds the
//! module map below to the code — every file declared, every declaration with
//! its line, every module naming only itself and the modules above it — holds
//! `rig.rs`'s door to being the crate's one call of
//! `OperationSurface::execute`, holds every file but `rig.rs` to building no
//! CREATENEWDOCUMENT request of its own, holds the play pass to changing the
//! shadow through its one owner, and holds every adaptation tag the crate can
//! record to an entry in `play`'s catalogue.

// Golden dotted strings ⇄ skep tumblers, addresses and spans; golden address shapes.
mod tum;
// The record shapes the report serializes — op outcomes, scenario verdicts — and a scenario's key.
pub mod outcome;
// The vendored conformance tree, and its golden scenarios loaded as dynamic JSON.
pub mod loader;
// allowlist.toml: adjudicated divergences, their classes and declared adjustments; TOML-like.
pub mod allowlist;
// The per-scenario golden ↔ skep address bijection and its findings.
mod alpha;
// The golden-side shadow: bytes, names, the current-document register.
mod shadow;
// Deleted content's I-history, captured at delete time and keyed by golden document.
mod deletions;
// The field-bag grammar both passes read an op through.
mod fields;
// The recorded-evidence policies both passes apply.
mod evidence;
// One comparator per result type; the standing divergence analyses.
mod compare;
// The rig: engine, operation surface, sessions, types document — the one door to skep.
mod rig;
// The grounding pre-pass: unrecorded setup rebuilt from recorded evidence.
mod ground;
// The play pass: each op normalized to a verb, executed, compared.
mod play;
// report.jsonl and summary.md: rendered, and published under target/conformance/.
pub mod report;
// The per-scenario loop: pre-pass, rig, lead-in, ops, verdict.
pub mod runner;
