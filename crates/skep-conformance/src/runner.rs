//! The per-scenario loop: one fresh engine per scenario, ops played in
//! order, α-findings folded into the op they arose on, allowlist grants
//! applied to disagreements, one verdict per scenario. A harness panic is
//! caught and becomes verdict `error` — a harness bug, never a finding.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;

use crate::allowlist::{load as load_allowlist, Allowlist};
use crate::alpha::Alpha;
use crate::harness::Rig;
use crate::loader::{load_all, Scenario};
use crate::outcome::{OpOutcome, ScenarioRecord, Status, Verdict};
use crate::report::{render_table, write_reports};
use crate::shadow::Shadow;
use crate::translate::{run_op, Cx, Grants};

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
    let golden = crate::conformance_dir().join("golden");
    let allow_path = crate::conformance_dir().join("allowlist.toml");
    let scenarios = load_all(&golden)?;
    let allow = load_allowlist(&allow_path)?;
    let loaded_op_counts: Vec<(String, usize)> =
        scenarios.iter().map(|s| (s.name.clone(), s.operations.len())).collect();

    let mut records = Vec::with_capacity(scenarios.len());
    for scn in &scenarios {
        let rec = catch_unwind(AssertUnwindSafe(|| run_scenario(scn, &allow)));
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
                }
            }
        });
    }

    let (jsonl, summary) = write_reports(&records, &crate::output_dir())?;
    eprintln!("\nskep conformance — category × verdict\n");
    eprintln!("{}", render_table(&records));
    eprintln!("report:  {}", jsonl.display());
    eprintln!("summary: {}", summary.display());
    Ok(RunOutput { records, jsonl, summary, loaded_op_counts })
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
            }
        }
    };
    let mut alpha = Alpha::new();
    let mut shadow = Shadow::new();
    alpha.bind(GOLDEN_DEFAULT_ACCOUNT, &rig.default_account());

    let mut ops: Vec<OpOutcome> = Vec::with_capacity(scn.operations.len());
    for (i, op) in scn.operations.iter().enumerate() {
        let entries = allow.matching(&scn.name, i);
        let grants = Grants {
            width_tolerance: entries.iter().filter_map(|e| e.width_tolerance).max().unwrap_or(0),
            count_delta: entries.iter().filter_map(|e| e.count_delta).next().unwrap_or(0),
            classes: entries.iter().map(|e| e.class.clone()).collect(),
        };
        let adjusted = grants.width_tolerance != 0 || grants.count_delta != 0;
        let mut out = {
            let mut cx = Cx { rig: &mut rig, alpha: &mut alpha, shadow: &mut shadow };
            run_op(&mut cx, i, op, &grants)
        };
        // Fold α-findings into the op they arose on: they are divergence
        // evidence, not harness failures.
        let findings: Vec<String> = alpha
            .findings
            .drain(..)
            .map(|f| format!("{}: {}", f.class, f.detail))
            .collect();
        if !findings.is_empty() {
            let joined = findings.join("; ");
            match out.status {
                Status::Disagreed | Status::Inexpressible => {
                    out.note = Some(match out.note.take() {
                        Some(n) => format!("{n}; {joined}"),
                        None => joined,
                    });
                }
                _ => {
                    out.status = Status::Disagreed;
                    out.comparator = Some("alpha".into());
                    out.note = Some(joined);
                }
            }
        }
        // Allowlist: a disagreement with a matching entry is allowlisted; an
        // agreement reached only through a declared adjustment is too (the
        // entry's existence IS the adjudicated divergence).
        if out.status == Status::Disagreed && !grants.classes.is_empty() {
            out.allowlisted = Some(grants.classes[0].clone());
        } else if out.status == Status::Agreed && adjusted && !grants.classes.is_empty() {
            out.allowlisted = Some(grants.classes[0].clone());
        }
        ops.push(out);
    }

    let any_inexpressible = ops.iter().any(|o| o.status == Status::Inexpressible);
    let any_raw_divergence =
        ops.iter().any(|o| o.status == Status::Disagreed && o.allowlisted.is_none());
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
    let first_failure = ops
        .iter()
        .find(|o| matches!(o.status, Status::Disagreed | Status::Inexpressible))
        .map(|o| {
            let detail = match (&o.expected, &o.actual, &o.note) {
                (Some(e), Some(a), _) => format!("expected {e} / actual {a}"),
                (_, _, Some(n)) => n.clone(),
                _ => String::from("(no detail)"),
            };
            (o.index, o.label.clone(), detail)
        });
    ScenarioRecord {
        category: scn.category.clone(),
        name: scn.name.clone(),
        verdict,
        bijection_size: alpha.len(),
        ops,
        first_failure,
        error: None,
    }
}
