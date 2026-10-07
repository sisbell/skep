//! The per-scenario loop: the grounding pre-pass, one fresh engine per
//! scenario, implied creates + lead-in setup, ops played in order,
//! α-findings folded into the op they arose on, each outcome judged against
//! the allowlist, one verdict per scenario. A panic is caught where it lands
//! — inside an op, which it stops the scenario at, or outside every op — and
//! becomes verdict `error`, naming who raised it: one raised inside skep's
//! operation surface ([`EnginePanic`]) is a failure in skep, any other a
//! harness bug, and neither a finding an allowlist entry could cover.

use std::any::Any;
use std::error::Error;
use std::fmt;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;

use serde_json::Value;

use crate::allowlist::{load as load_allowlist, Allowlist, AllowlistError};
use crate::alpha::Alpha;
use crate::deletions::Deletions;
use crate::evidence::Effect;
use crate::fields::op_name;
use crate::ground::{ground, SetupStep};
use crate::loader::{conformance_dir, load_all, LoadError, Scenario};
use crate::outcome::{Finding, OpOutcome, ScenarioKey, ScenarioRecord, Status, Verdict};
use crate::play::{run_op, Cx};
use crate::report::{output_dir, render_table, write_reports, ReportError, ReportPaths};
use crate::rig::{panic_message, EnginePanic, Rig};
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
        records.push(rec.unwrap_or_else(|payload| stopped_outside_ops(scn, panic_text(payload))));
    }
    records
}

/// A panic's account of itself, naming the party that raised it: skep's
/// operation surface, executing a request of the kind it names (an
/// [`EnginePanic`] from the rig's door), or the harness.
fn panic_text(payload: Box<dyn Any + Send>) -> String {
    match payload.downcast::<EnginePanic>() {
        Ok(p) => format!("skep panicked executing {:?}: {}", p.kind, p.message),
        Err(other) => format!("the harness panicked: {}", panic_message(&*other)),
    }
}

/// The record of a scenario stopped outside every op — a rig that would not
/// bootstrap, or a panic in the pre-pass, the rig's own setup or the
/// lead-in: verdict `error`, what stopped it its one content.
fn stopped_outside_ops(scn: &Scenario, error: String) -> ScenarioRecord {
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

/// The record of a scenario a panic stopped at op `index` (`op`): verdict
/// `error`, the outcomes of the ops before it kept as judged, and the
/// stopped op both its first finding and its error, naming who panicked
/// ([`panic_text`]). Nothing after a stop mid-change can be trusted, so the
/// scenario ends there.
fn stopped_at_op(
    scn: &Scenario,
    outcomes: Vec<OpOutcome>,
    index: usize,
    op: &Value,
    payload: Box<dyn Any + Send>,
    groundings: Vec<String>,
    bijection_size: usize,
) -> ScenarioRecord {
    let finding = Finding { index, op_name: op_name(op).to_string(), detail: panic_text(payload) };
    let error = format!("op {} `{}`: {}", finding.index, finding.op_name, finding.detail);
    ScenarioRecord {
        category: scn.category.clone(),
        name: scn.name.clone(),
        verdict: Verdict::Error,
        bijection_size,
        ops: outcomes,
        first_finding: Some(finding),
        error: Some(error),
        groundings,
    }
}

fn run_scenario(scn: &Scenario, allow: &Allowlist) -> ScenarioRecord {
    let mut rig = match Rig::new() {
        Ok(r) => r,
        Err(e) => return stopped_outside_ops(scn, format!("rig bootstrap: {e}")),
    };
    let mut alpha = Alpha::new();
    let mut shadow = Shadow::new();
    let mut deletions = Deletions::default();
    alpha.bind(GOLDEN_DEFAULT_ACCOUNT, rig.default_account());

    // The grounding pre-pass: shadow-only, derives implied setup from the
    // scenario's own recorded evidence (see ground.rs module docs).
    let setup = ground(&scn.operations);
    let mut groundings = setup.groundings.clone();
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
        if cx.alpha.peek_exact(docid).is_some() {
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
    let mut outcomes: Vec<OpOutcome> = Vec::with_capacity(scn.operations.len());
    for (i, op) in scn.operations.iter().enumerate() {
        // Everything about op `i` — playing it, folding its findings,
        // judging it — runs under one catch, so a panic anywhere in it stops
        // the scenario AT that op, named.
        let judged = catch_unwind(AssertUnwindSafe(|| {
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
            out
        }));
        match judged {
            Ok(out) => outcomes.push(out),
            Err(payload) => {
                return stopped_at_op(scn, outcomes, i, op, payload, groundings, cx.alpha.len());
            }
        }
    }
    let bijection_size = cx.alpha.len();

    let any_inexpressible = outcomes.iter().any(|o| o.status == Status::Inexpressible);
    let any_unadjudicated = outcomes.iter().any(OpOutcome::is_unadjudicated);
    let any_allowlisted = outcomes.iter().any(|o| o.allowlisted.is_some());
    let verdict = if any_inexpressible {
        Verdict::Inexpressible
    } else if any_unadjudicated {
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
    let first_finding = outcomes
        .iter()
        .find(|o| o.status == Status::Inexpressible || o.is_unadjudicated())
        .or_else(|| {
            outcomes.iter().find(|o| matches!(o.status, Status::Disagreed | Status::Inexpressible))
        })
        .map(|o| Finding { index: o.index, op_name: o.op_name.clone(), detail: o.detail() });
    ScenarioRecord {
        category: scn.category.clone(),
        name: scn.name.clone(),
        verdict,
        bijection_size,
        ops: outcomes,
        first_finding,
        error: None,
        groundings,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use skep_febe::OpKind;

    use super::*;

    fn engine_panic() -> Box<dyn Any + Send> {
        Box::new(EnginePanic { kind: OpKind::Insert, message: "boom".into() })
    }

    /// A panic names the party that raised it: skep, executing a request of
    /// the kind its door recorded, or the harness, whatever its payload.
    #[test]
    fn a_panic_names_the_party_that_raised_it() {
        assert_eq!(panic_text(engine_panic()), "skep panicked executing Insert: boom");
        assert_eq!(panic_text(Box::new("boom")), "the harness panicked: boom");
        assert_eq!(panic_text(Box::new(String::from("boom"))), "the harness panicked: boom");
        let opaque = panic_text(Box::new(7u8));
        assert_eq!(opaque, "the harness panicked: panic with non-string payload");
    }

    /// A scenario a panic stops mid-play keeps the outcomes judged before
    /// it, is an error and nothing an allowlist could cover, and names the
    /// op it stopped at and who panicked there.
    #[test]
    fn a_stopped_scenario_keeps_its_ops_and_names_the_op() {
        let scn = Scenario {
            category: "cat".into(),
            name: "s".into(),
            description: String::new(),
            operations: vec![
                json!({"op": "create_document"}),
                json!({"op": "insert"}),
                json!({"op": "insert"}),
            ],
        };
        let outcomes = vec![OpOutcome::new(0, "create_document"), OpOutcome::new(1, "insert")];
        let op = &scn.operations[2];
        let record = stopped_at_op(&scn, outcomes, 2, op, engine_panic(), Vec::new(), 1);
        assert_eq!(record.verdict, Verdict::Error);
        assert_eq!(record.ops.len(), 2);
        let detail = "skep panicked executing Insert: boom";
        let finding = Finding { index: 2, op_name: "insert".into(), detail: detail.into() };
        assert_eq!(record.first_finding, Some(finding));
        assert_eq!(record.error.as_deref(), Some(format!("op 2 `insert`: {detail}").as_str()));
    }
}
