//! The per-scenario loop: the grounding pre-pass, one fresh engine per
//! scenario, implied creates + lead-in setup, ops played in order,
//! α-findings folded into the op they arose on, each outcome judged against
//! the allowlist, one verdict per scenario. A harness panic is caught and
//! becomes verdict `error` — a harness bug, never a finding.

use std::error::Error;
use std::fmt;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;

use crate::allowlist::{load as load_allowlist, Allowlist, AllowlistError};
use crate::alpha::Alpha;
use crate::deletions::Deletions;
use crate::evidence::Effect;
use crate::ground::{ground, SetupStep};
use crate::loader::{conformance_dir, load_all, LoadError, Scenario};
use crate::outcome::{Finding, OpOutcome, ScenarioKey, ScenarioRecord, Status, Verdict};
use crate::play::{run_op, Cx};
use crate::report::{output_dir, render_table, write_reports, ReportError, ReportPaths};
use crate::rig::Rig;
use crate::shadow::Shadow;

/// udanax-green's default account in the golden address space; every
/// scenario's document addresses live under it. Seeded into α at scenario
/// start, bound to the rig's bootstrap-delegated skep account.
const GOLDEN_DEFAULT_ACCOUNT: &str = "1.1.0.1";

#[derive(Debug)]
pub struct RunOutput {
    pub records: Vec<ScenarioRecord>,
    pub jsonl: PathBuf,
    pub summary: PathBuf,
    /// Scenario op counts as loaded, by scenario key — for the gate's
    /// every-op-classified integrity assertion.
    pub loaded_op_counts: Vec<(ScenarioKey, usize)>,
}

/// Why a sweep did not run to its report.
#[derive(Debug)]
#[non_exhaustive]
pub enum RunError {
    /// The golden tree did not load.
    Load(LoadError),
    /// The allowlist did not load.
    Allowlist(AllowlistError),
    /// The report could not be written.
    Report(ReportError),
}

impl fmt::Display for RunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            RunError::Load(_) => "the golden scenarios did not load",
            RunError::Allowlist(_) => "the allowlist did not load",
            RunError::Report(_) => "the report was not written",
        })
    }
}

impl Error for RunError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            RunError::Load(e) => Some(e),
            RunError::Allowlist(e) => Some(e),
            RunError::Report(e) => Some(e),
        }
    }
}

impl From<LoadError> for RunError {
    fn from(e: LoadError) -> RunError {
        RunError::Load(e)
    }
}

impl From<AllowlistError> for RunError {
    fn from(e: AllowlistError) -> RunError {
        RunError::Allowlist(e)
    }
}

impl From<ReportError> for RunError {
    fn from(e: ReportError) -> RunError {
        RunError::Report(e)
    }
}

/// Load, play, report. The library entry the gate test drives.
pub fn run_all() -> Result<RunOutput, RunError> {
    let golden = conformance_dir().join("golden");
    let allow_path = conformance_dir().join("allowlist.toml");
    let scenarios = load_all(&golden)?;
    let allow = load_allowlist(&allow_path)?;
    let loaded_op_counts: Vec<(ScenarioKey, usize)> =
        scenarios.iter().map(|s| (s.key(), s.operations.len())).collect();

    let records = run_scenarios(&scenarios, &allow);

    let ReportPaths { jsonl, summary } = write_reports(&records, &output_dir())?;
    eprintln!("\nskep conformance — category × verdict\n");
    eprintln!("{}", render_table(&records));
    eprintln!("report:  {}", jsonl.display());
    eprintln!("summary: {}", summary.display());
    Ok(RunOutput { records, jsonl, summary, loaded_op_counts })
}

/// Play a scenario list without touching the report files — the determinism
/// test replays a subset through this and byte-compares renderings.
pub fn run_scenarios(scenarios: &[Scenario], allow: &Allowlist) -> Vec<ScenarioRecord> {
    let mut records = Vec::with_capacity(scenarios.len());
    for scn in scenarios {
        let rec = catch_unwind(AssertUnwindSafe(|| run_scenario(scn, allow)));
        records.push(match rec {
            Ok(r) => r,
            Err(payload) => {
                let msg = payload
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_else(|| "panic with non-string payload".to_string());
                harness_error(scn, msg)
            }
        });
    }
    records
}

/// The record of a scenario the HARNESS failed on — a panic, or a rig that
/// would not bootstrap: verdict `error`, the failure its one content.
fn harness_error(scn: &Scenario, error: String) -> ScenarioRecord {
    ScenarioRecord {
        category: scn.category.clone(),
        name: scn.name.clone(),
        verdict: Verdict::Error,
        bijection_size: 0,
        ops: Vec::new(),
        first_finding: None,
        error: Some(error),
        groundings: Vec::new(),
    }
}

fn run_scenario(scn: &Scenario, allow: &Allowlist) -> ScenarioRecord {
    let mut rig = match Rig::new() {
        Ok(r) => r,
        Err(e) => return harness_error(scn, format!("rig bootstrap: {e}")),
    };
    let mut alpha = Alpha::new();
    let mut shadow = Shadow::new();
    let mut deletions = Deletions::default();
    alpha.bind(GOLDEN_DEFAULT_ACCOUNT, rig.default_account());

    // The grounding pre-pass: shadow-only, derives implied setup from the
    // scenario's own recorded evidence (see ground.rs module docs).
    let setup = ground(&scn.operations);
    let mut groundings = setup.tags.clone();
    let mut cx = Cx {
        rig: &mut rig,
        alpha: &mut alpha,
        shadow: &mut shadow,
        deletions: &mut deletions,
        ops: &scn.operations,
        plans: &setup.plans,
    };

    // Implied creates + lead-in, executed through the same op surface the
    // scenario uses — inferred setup, golden-side by construction. A failure
    // here is recorded and the run continues — the affected ops then
    // disagree honestly.
    for docid in &setup.implied_creates {
        if cx.alpha.peek(docid).is_some() {
            continue; // already bound (defensive; should not happen)
        }
        let r = cx.create_document(docid, None, Effect::Inferred);
        if !matches!(r, skep_febe::Response::AckAddr { .. }) {
            groundings
                .push(format!("implied-create FAILED for {docid}: {}", crate::rig::brief(&r)));
        }
    }
    'lead_in: for step in &setup.lead_in {
        // Lead-in inserts may target docs the scenario creates itself
        // later only via implied paths; ensure existence first. (Link
        // steps live in expansion plans, never the lead-in, but the
        // match stays total.)
        if let SetupStep::Insert { doc, .. } | SetupStep::Copy { doc, .. } = step {
            if !cx.shadow.knows(doc) {
                let r = cx.create_document(doc, None, Effect::Inferred);
                if !matches!(r, skep_febe::Response::AckAddr { .. }) {
                    groundings.push(format!(
                        "lead-in create FAILED for {doc}: {}",
                        crate::rig::brief(&r)
                    ));
                    continue 'lead_in;
                }
            }
        }
        if let Err(e) = cx.exec_setup_step(step) {
            groundings.push(format!("lead-in FAILED: {e}"));
        }
    }
    // The register belongs to the first document the SCENARIO names,
    // not the last lead-in target.
    if let Some(first) = cx.shadow.created.first().cloned() {
        cx.shadow.set_current(&first);
    }

    let key = scn.key();
    let mut ops: Vec<OpOutcome> = Vec::with_capacity(scn.operations.len());
    for (i, op) in scn.operations.iter().enumerate() {
        let adjustments = allow.adjustments(&key, i);
        let mut out = run_op(&mut cx, i, op, &adjustments);
        // Fold α-findings into the op they arose on: they are divergence
        // evidence, not harness failures.
        let findings: Vec<String> = cx
            .alpha
            .drain_findings()
            .map(|f| format!("{}: {}", f.kind.as_str(), f.detail))
            .collect();
        if !findings.is_empty() {
            if !matches!(out.status, Status::Disagreed | Status::Inexpressible) {
                out.status = Status::Disagreed;
                out.comparator = Some("alpha");
            }
            out.add_note(findings.join("; "));
        }
        // The allowlist judges the outcome α's findings left: which
        // adjudicated classes, if any, cover it.
        out.allowlisted = allow.classify(&key, i, &out);
        ops.push(out);
    }
    let bijection_size = cx.alpha.len();

    let any_inexpressible = ops.iter().any(|o| o.status == Status::Inexpressible);
    let any_raw_divergence = ops.iter().any(OpOutcome::is_unadjudicated);
    let any_allowlisted = ops.iter().any(|o| o.allowlisted.is_some());
    let verdict = if any_inexpressible {
        Verdict::Inexpressible
    } else if any_raw_divergence {
        Verdict::Divergent
    } else if any_allowlisted {
        Verdict::Allowlisted
    } else {
        Verdict::Pass
    };
    // The summary's divergent list leads with the first UNADJUDICATED
    // disagreement — a first-finding line showing an allowlisted op reads as
    // the scenario's open finding and misdirects (round 6's item 1 was
    // diagnosed off exactly that). Allowlisted disagreements are the
    // fallback only when nothing unadjudicated exists (allowlisted/
    // inexpressible verdicts).
    let first_finding = ops
        .iter()
        .find(|o| o.status == Status::Inexpressible || o.is_unadjudicated())
        .or_else(|| {
            ops.iter().find(|o| matches!(o.status, Status::Disagreed | Status::Inexpressible))
        })
        .map(|o| Finding { index: o.index, op_name: o.op_name.clone(), detail: o.detail() });
    ScenarioRecord {
        category: scn.category.clone(),
        name: scn.name.clone(),
        verdict,
        bijection_size,
        ops,
        first_finding,
        error: None,
        groundings,
    }
}
