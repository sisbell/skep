//! Report emission: one JSONL record per scenario
//! (`target/conformance/report.jsonl`) plus the human summary
//! (`target/conformance/summary.md`), whose table is also printed to stderr
//! when the run completes. [`output_dir`] locates `target/conformance/`.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::json;

use crate::compare::{COLLAPSED_SUBSPACE_ANALYSIS, VERSION_LINK_CARRYOVER_ANALYSIS};
use crate::outcome::{OpOutcome, ScenarioRecord, Status, Verdict};

/// `skep/target/conformance/` — where the report and summary are written.
pub fn output_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/conformance")
}

/// Where a sweep's report and summary were published.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportPaths {
    /// `report.jsonl`: one record per scenario.
    pub jsonl: PathBuf,
    /// `summary.md`: the human summary.
    pub summary: PathBuf,
}

/// A report file that could not be written: the path, and why.
#[derive(Debug)]
#[non_exhaustive]
pub struct ReportError {
    pub path: PathBuf,
    pub source: io::Error,
}

impl fmt::Display for ReportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cannot write {}", self.path.display())
    }
}

impl Error for ReportError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

/// The full JSONL body, one line per scenario — a pure function of the
/// records, so the determinism test can byte-compare two runs without
/// touching the report files.
pub fn render_jsonl(records: &[ScenarioRecord]) -> String {
    let mut out = String::new();
    for r in records {
        let ops: Vec<serde_json::Value> = r
            .ops
            .iter()
            .map(|o| {
                json!({
                    "index": o.index,
                    "op": o.op_name,
                    "verb": o.verb,
                    "status": o.status.as_str(),
                    "comparator": o.comparator,
                    "adaptations": o.adaptations,
                    "expected": o.disagreement.as_ref().map(|d| &d.expected),
                    "actual": o.disagreement.as_ref().map(|d| &d.actual),
                    "note": o.note,
                    "allowlisted": o.allowlisted,
                })
            })
            .collect();
        let rec = json!({
            "scenario": r.name,
            "category": r.category,
            "verdict": r.verdict.as_str(),
            "bijection_size": r.bijection_size,
            "groundings": r.groundings,
            "first_finding": r.first_finding.as_ref().map(|f| json!({
                "op_index": f.index, "op": f.op_name, "detail": f.detail,
            })),
            "error": r.error,
            "ops": ops,
        });
        out.push_str(&rec.to_string());
        out.push('\n');
    }
    out
}

/// Render the records and publish `report.jsonl` and `summary.md` under
/// `out_dir`, creating it if need be.
pub fn write_reports(
    records: &[ScenarioRecord],
    out_dir: &Path,
) -> Result<ReportPaths, ReportError> {
    fs::create_dir_all(out_dir)
        .map_err(|source| ReportError { path: out_dir.to_path_buf(), source })?;
    let paths =
        ReportPaths { jsonl: out_dir.join("report.jsonl"), summary: out_dir.join("summary.md") };
    publish(&paths.jsonl, &render_jsonl(records))?;
    publish(&paths.summary, &render_summary(records))?;
    Ok(paths)
}

/// Write `body` to `path` so that no concurrent reader ever observes a
/// partial one: into a sibling temp file first, then `rename`, which POSIX
/// makes atomic within a directory. A plain `fs::write` truncates in place,
/// so a reader that `stat`s between the truncate and the write sees length 0.
///
/// That reader is a sibling TEST. The two gate tests both drive the full
/// sweep over this one canonical artifact — deliberately, so operators read
/// one report — and a test runner that gives each test its own PROCESS runs
/// them concurrently, which no in-process lock can serialize.
///
/// The temp name carries the pid AND a per-call counter, so no two writers
/// share it: colliding on the temp would reintroduce the torn read one step
/// earlier, where a rename would then publish it.
fn publish(path: &Path, body: &str) -> Result<(), ReportError> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let tmp = path.with_extension(format!(
        "tmp.{}.{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::write(&tmp, body).map_err(|source| ReportError { path: tmp.clone(), source })?;
    fs::rename(&tmp, path).map_err(|source| {
        let _ = fs::remove_file(&tmp);
        ReportError { path: path.to_path_buf(), source }
    })
}

/// The category × verdict table, as printed to summary.md and stderr.
pub fn render_table(records: &[ScenarioRecord]) -> String {
    let mut by_cat: BTreeMap<&str, [usize; 5]> = BTreeMap::new();
    for r in records {
        let row = by_cat.entry(r.category.as_str()).or_default();
        let i = match r.verdict {
            Verdict::Pass => 0,
            Verdict::Allowlisted => 1,
            Verdict::Divergent => 2,
            Verdict::Inexpressible => 3,
            Verdict::Error => 4,
        };
        row[i] += 1;
    }
    let mut s = String::new();
    s.push_str("| category | pass | allowlisted | divergent | inexpressible | error | total |\n");
    s.push_str("|---|---:|---:|---:|---:|---:|---:|\n");
    let mut totals = [0usize; 5];
    for (cat, row) in &by_cat {
        let total: usize = row.iter().sum();
        s.push_str(&format!(
            "| {cat} | {} | {} | {} | {} | {} | {total} |\n",
            row[0], row[1], row[2], row[3], row[4]
        ));
        for (t, v) in totals.iter_mut().zip(row) {
            *t += v;
        }
    }
    let grand: usize = totals.iter().sum();
    s.push_str(&format!(
        "| **all** | {} | {} | {} | {} | {} | {grand} |\n",
        totals[0], totals[1], totals[2], totals[3], totals[4]
    ));
    s
}

fn trunc(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        let mut cut = n;
        while cut > 0 && !s.is_char_boundary(cut) {
            cut -= 1;
        }
        format!("{}…", &s[..cut])
    }
}

fn render_summary(records: &[ScenarioRecord]) -> String {
    let mut s = String::from("# skep conformance summary\n\n");
    s.push_str(&format!(
        "{} scenarios played against skep's `OperationSurface<World>::execute`.\n\n",
        records.len()
    ));
    s.push_str("## Category × verdict\n\n");
    s.push_str(&render_table(records));

    s.push_str("\n## Divergent scenarios (first disagreement)\n\n");
    let mut any = false;
    for r in records {
        if r.verdict != Verdict::Divergent {
            continue;
        }
        any = true;
        match &r.first_finding {
            Some(f) => s.push_str(&format!(
                "- `{}/{}` — op {} `{}`: {}\n",
                r.category,
                r.name,
                f.index,
                f.op_name,
                trunc(&f.detail, 300)
            )),
            None => s.push_str(&format!("- `{}/{}`\n", r.category, r.name)),
        }
    }
    if !any {
        s.push_str("(none)\n");
    }

    // An inexpressible verdict outranks a divergent one, so a scenario frozen
    // inexpressible can carry disagreements no allowlist entry covers. They
    // are listed here — the scenario's first one, and how many follow — so
    // the verdict never keeps them out of the summary.
    s.push_str("\n## Unadjudicated disagreements under an inexpressible verdict\n\n");
    let mut any = false;
    for r in records {
        if r.verdict != Verdict::Inexpressible {
            continue;
        }
        let raw: Vec<&OpOutcome> = r.ops.iter().filter(|o| o.is_unadjudicated()).collect();
        let Some(first) = raw.first() else { continue };
        any = true;
        let more = match raw.len() {
            1 => String::new(),
            n => format!(" (+{} more)", n - 1),
        };
        s.push_str(&format!(
            "- `{}/{}` — op {} `{}`: {}{more}\n",
            r.category,
            r.name,
            first.index,
            first.op_name,
            trunc(&first.detail(), 300)
        ));
    }
    if !any {
        s.push_str("(none)\n");
    }

    // The standing cluster analyses: each surfaced once, with the affected
    // scenarios listed, so each family's ruling reads beside the scenarios
    // it covers. Notes may carry the analysis alongside other evidence, so
    // the match is containment, not equality.
    for (title, analysis) in [
        ("udanax two-subspace vspanset shape", COLLAPSED_SUBSPACE_ANALYSIS),
        (
            "udanax version link carryover vs skep content-only Version",
            VERSION_LINK_CARRYOVER_ANALYSIS,
        ),
    ] {
        let affected: Vec<&ScenarioRecord> = records
            .iter()
            .filter(|r| {
                r.ops
                    .iter()
                    .any(|o| o.note.as_deref().is_some_and(|n| n.contains(analysis)))
            })
            .collect();
        if !affected.is_empty() {
            s.push_str(&format!("\n## Standing analysis — {title}\n\n"));
            s.push_str(analysis);
            s.push_str("\n\nAffected scenarios:\n\n");
            for r in &affected {
                s.push_str(&format!("- `{}/{}`\n", r.category, r.name));
            }
        }
    }

    s.push_str("\n## Inexpressible scenarios (first inexpressible op)\n\n");
    let mut any = false;
    for r in records {
        if r.verdict != Verdict::Inexpressible {
            continue;
        }
        any = true;
        let first = r
            .ops
            .iter()
            .find(|o| o.status == Status::Inexpressible)
            .map(|o| {
                format!(
                    "op {} `{}`: {}",
                    o.index,
                    o.op_name,
                    trunc(o.note.as_deref().unwrap_or("-"), 200)
                )
            })
            .unwrap_or_default();
        s.push_str(&format!("- `{}/{}` — {first}\n", r.category, r.name));
    }
    if !any {
        s.push_str("(none)\n");
    }

    s.push_str("\n## Harness errors\n\n");
    let mut any = false;
    for r in records {
        if r.verdict != Verdict::Error {
            continue;
        }
        any = true;
        s.push_str(&format!(
            "- `{}/{}` — {}\n",
            r.category,
            r.name,
            trunc(r.error.as_deref().unwrap_or("-"), 300)
        ));
    }
    if !any {
        s.push_str("(none)\n");
    }
    s
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::outcome::{Disagreement, Finding};

    fn op(index: usize, status: Status, allowlisted: Option<&str>) -> OpOutcome {
        let mut o = OpOutcome::new(index, &format!("op{index}"));
        o.status = status;
        let (expected, actual) = (format!("want{index}"), format!("got{index}"));
        o.disagreement = Some(Disagreement { expected, actual });
        o.allowlisted = allowlisted.map(str::to_string);
        o
    }

    fn record(name: &str, verdict: Verdict, ops: Vec<OpOutcome>) -> ScenarioRecord {
        ScenarioRecord {
            category: "cat".into(),
            name: name.into(),
            verdict,
            bijection_size: 0,
            ops,
            first_finding: None,
            error: None,
            groundings: Vec::new(),
        }
    }

    fn section(summary: &str) -> &str {
        let head = "## Unadjudicated disagreements under an inexpressible verdict\n\n";
        let start = summary.find(head).expect("the section is rendered") + head.len();
        let rest = &summary[start..];
        &rest[..rest.find("\n## ").unwrap_or(rest.len())]
    }

    /// An inexpressible verdict cannot keep an uncovered disagreement out of
    /// the summary: the first one is listed with the count that follows,
    /// while a covered one, or one under another verdict, is not.
    #[test]
    fn an_inexpressible_verdict_never_hides_an_uncovered_disagreement() {
        let records = vec![
            record(
                "hidden",
                Verdict::Inexpressible,
                vec![
                    op(0, Status::Agreed, None),
                    op(1, Status::Disagreed, Some("ruled")),
                    op(2, Status::Disagreed, None),
                    op(3, Status::Inexpressible, None),
                    op(4, Status::Disagreed, None),
                ],
            ),
            record(
                "covered",
                Verdict::Inexpressible,
                vec![op(0, Status::Disagreed, Some("ruled")), op(1, Status::Inexpressible, None)],
            ),
            record("divergent", Verdict::Divergent, vec![op(0, Status::Disagreed, None)]),
        ];
        let summary = render_summary(&records);
        assert_eq!(
            section(&summary),
            "- `cat/hidden` — op 2 `op2`: expected want2 / actual got2 (+1 more)\n"
        );
        let clean = vec![record("covered", Verdict::Inexpressible, Vec::new())];
        assert_eq!(section(&render_summary(&clean)), "(none)\n");
    }

    /// A divergent record with its first finding, as the runner leaves it.
    fn divergent(name: &str) -> ScenarioRecord {
        let mut o = op(0, Status::Disagreed, None);
        o.comparator = Some("content");
        let finding = Finding { index: 0, op_name: o.op_name.clone(), detail: o.detail() };
        ScenarioRecord { first_finding: Some(finding), ..record(name, Verdict::Divergent, vec![o]) }
    }

    /// The report is the harness's product: one JSON record per scenario,
    /// its verdict, first finding and every op — a disagreement with both
    /// sides, each under its own key.
    #[test]
    fn a_disagreement_reaches_the_report_with_both_sides() {
        let jsonl = render_jsonl(&[divergent("d")]);
        assert_eq!(jsonl.lines().count(), 1);
        let rec: serde_json::Value = serde_json::from_str(jsonl.trim_end()).expect("JSON");
        assert_eq!(rec["category"], "cat");
        assert_eq!(rec["scenario"], "d");
        assert_eq!(rec["verdict"], "divergent");
        let detail = "expected want0 / actual got0";
        assert_eq!(rec["first_finding"], json!({"op_index": 0, "op": "op0", "detail": detail}));
        let disagreed = json!({
            "index": 0, "op": "op0", "verb": "?", "status": "disagreed", "comparator": "content",
            "adaptations": [], "expected": "want0", "actual": "got0", "note": null,
            "allowlisted": null,
        });
        assert_eq!(rec["ops"], json!([disagreed]));
    }

    /// A divergent scenario is counted in its category's row and the total,
    /// and the summary lists it with its first finding.
    #[test]
    fn a_divergent_scenario_is_counted_and_listed_with_its_first_finding() {
        let records = vec![divergent("d"), record("p", Verdict::Pass, Vec::new())];
        let table = render_table(&records);
        assert!(table.contains("| cat | 1 | 0 | 1 | 0 | 0 | 2 |\n"), "{table}");
        assert!(table.contains("| **all** | 1 | 0 | 1 | 0 | 0 | 2 |\n"), "{table}");
        let summary = render_summary(&records);
        let listed = "- `cat/d` — op 0 `op0`: expected want0 / actual got0\n";
        assert!(summary.contains(listed), "{summary}");
    }
}
