//! The per-scenario loop: the grounding pre-pass, one fresh engine per
//! scenario, implied creates + lead-in setup, ops played in order,
//! α-findings folded into the op they arose on, each outcome judged against
//! the allowlist, one verdict per scenario. A harness panic is caught and
//! becomes verdict `error` — a harness bug, never a finding.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;

use crate::allowlist::{load as load_allowlist, Allowlist};
use crate::alpha::Alpha;
use crate::deletions::Deletions;
use crate::ground::{ground, SetupStep};
use crate::harness::Rig;
use crate::loader::{conformance_dir, load_all, Scenario};
use crate::outcome::{OpOutcome, ScenarioRecord, Status, Verdict};
use crate::report::{output_dir, render_table, write_reports};
use crate::shadow::Shadow;
use crate::translate::{run_op, Cx};

/// udanax-green's default account in the golden address space; every
/// scenario's document addresses live under it. Seeded into α at scenario
/// start, bound to the rig's bootstrap-delegated skep account.
const GOLDEN_DEFAULT_ACCOUNT: &str = "1.1.0.1";

pub struct RunOutput {
    pub records: Vec<ScenarioRecord>,
    pub jsonl: PathBuf,
    pub summary: PathBuf,
    /// Scenario op counts as loaded — for the gate's every-op-classified
    /// integrity assertion.
    pub loaded_op_counts: Vec<(String, usize)>,
}

/// Load, play, report. The library entry the gate test drives.
pub fn run_all() -> Result<RunOutput, String> {
    let golden = conformance_dir().join("golden");
    let allow_path = conformance_dir().join("allowlist.toml");
    let scenarios = load_all(&golden)?;
    let allow = load_allowlist(&allow_path)?;
    let loaded_op_counts: Vec<(String, usize)> =
        scenarios.iter().map(|s| (s.name.clone(), s.operations.len())).collect();

    let records = run_scenarios(&scenarios, &allow);

    let (jsonl, summary) = write_reports(&records, &output_dir())?;
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
                ScenarioRecord {
                    category: scn.category.clone(),
                    name: scn.name.clone(),
                    verdict: Verdict::Error,
                    bijection_size: 0,
                    ops: Vec::new(),
                    first_failure: None,
                    error: Some(msg),
                    groundings: Vec::new(),
                }
            }
        });
    }
    records
}

fn run_scenario(scn: &Scenario, allow: &Allowlist) -> ScenarioRecord {
    let mut rig = match Rig::new() {
        Ok(r) => r,
        Err(e) => {
            return ScenarioRecord {
                category: scn.category.clone(),
                name: scn.name.clone(),
                verdict: Verdict::Error,
                bijection_size: 0,
                ops: Vec::new(),
                first_failure: None,
                error: Some(format!("rig bootstrap: {e}")),
                groundings: Vec::new(),
            }
        }
    };
    let mut alpha = Alpha::new();
    let mut shadow = Shadow::new();
    let mut deletions = Deletions::default();
    alpha.bind(GOLDEN_DEFAULT_ACCOUNT, &rig.default_account());

    // The grounding pre-pass: shadow-only, derives implied setup from the
    // scenario's own recorded evidence (see ground.rs module docs).
    let grounding = ground(&scn.operations);
    let mut groundings = grounding.tags.clone();

    // Implied creates + lead-in, executed through the same op surface the
    // scenario uses. A failure here is recorded and the run continues — the
    // affected ops then disagree honestly.
    {
        let mut cx = Cx {
            rig: &mut rig,
            alpha: &mut alpha,
            shadow: &mut shadow,
            deletions: &mut deletions,
            ops: &scn.operations,
            plans: &grounding.plans,
        };
        for docid in &grounding.implied_creates {
            if cx.alpha.peek(docid).is_some() {
                continue; // already bound (defensive; should not happen)
            }
            let r = cx.create_document(docid, None, true);
            if !matches!(r, skep_febe::Response::AckAddr { .. }) {
                groundings.push(format!(
                    "implied-create FAILED for {docid}: {}",
                    crate::harness::brief(&r)
                ));
            }
        }
        'lead_in: for step in &grounding.lead_in {
            // Lead-in inserts may target docs the scenario creates itself
            // later only via implied paths; ensure existence first. (Link
            // steps live in expansion plans, never the lead-in, but the
            // match stays total.)
            if let SetupStep::Insert { doc, .. } | SetupStep::Copy { doc, .. } = step {
                if !cx.shadow.knows(doc) {
                    let r = cx.create_document(doc, None, true);
                    if !matches!(r, skep_febe::Response::AckAddr { .. }) {
                        groundings.push(format!(
                            "lead-in create FAILED for {doc}: {}",
                            crate::harness::brief(&r)
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
    }

    let mut ops: Vec<OpOutcome> = Vec::with_capacity(scn.operations.len());
    for (i, op) in scn.operations.iter().enumerate() {
        let grants = allow.grants(&scn.name, i);
        let mut out = {
            let mut cx = Cx {
                rig: &mut rig,
                alpha: &mut alpha,
                shadow: &mut shadow,
                deletions: &mut deletions,
                ops: &scn.operations,
                plans: &grounding.plans,
            };
            run_op(&mut cx, i, op, &grants)
        };
        // Fold α-findings into the op they arose on: they are divergence
        // evidence, not harness failures.
        let findings: Vec<String> =
            alpha.findings.drain(..).map(|f| format!("{}: {}", f.class, f.detail)).collect();
        if !findings.is_empty() {
            let joined = findings.join("; ");
            match out.status {
                Status::Disagreed | Status::Inexpressible => out.add_note(joined),
                _ => {
                    out.status = Status::Disagreed;
                    out.comparator = Some("alpha".into());
                    out.note = Some(joined);
                }
            }
        }
        // The allowlist judges the outcome α's findings left: which
        // adjudicated classes, if any, cover it.
        out.allowlisted = allow.grant(&scn.name, i, &out);
        ops.push(out);
    }

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
    // disagreement — a first-failure line showing an allowlisted op reads as
    // the scenario's finding and misdirects (round 6's item 1 was diagnosed
    // off exactly that). Allowlisted disagreements are the fallback only
    // when nothing unadjudicated exists (allowlisted/inexpressible verdicts).
    let first_failure = ops
        .iter()
        .find(|o| o.status == Status::Inexpressible || o.is_unadjudicated())
        .or_else(|| {
            ops.iter().find(|o| matches!(o.status, Status::Disagreed | Status::Inexpressible))
        })
        .map(|o| (o.index, o.label.clone(), o.detail()));
    ScenarioRecord {
        category: scn.category.clone(),
        name: scn.name.clone(),
        verdict,
        bijection_size: alpha.len(),
        ops,
        first_failure,
        error: None,
        groundings,
    }
}
