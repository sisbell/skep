//! Report emission: one JSONL record per scenario
//! (`target/conformance/report.jsonl`) plus the human summary
//! (`target/conformance/summary.md`), whose table is also printed to stderr
//! when the run completes.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::json;

use crate::compare::{COLLAPSED_SUBSPACE_ANALYSIS, VERSION_LINK_CARRYOVER_ANALYSIS};
use crate::outcome::{ScenarioRecord, Status, Verdict};

fn status_str(s: &Status) -> &'static str {
    match s {
        Status::Agreed => "agreed",
        Status::NotCompared => "not-compared",
        Status::Meta => "meta",
        Status::Inexpressible => "inexpressible",
        Status::Disagreed => "disagreed",
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
                    "label": o.label,
                    "verb": o.verb,
                    "status": status_str(&o.status),
                    "comparator": o.comparator,
                    "adaptations": o.adaptations,
                    "expected": o.expected,
                    "actual": o.actual,
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
            "first_failure": r.first_failure.as_ref().map(|(i, l, d)| json!({
                "op_index": i, "label": l, "detail": d,
            })),
            "error": r.error,
            "ops": ops,
        });
        out.push_str(&rec.to_string());
        out.push('\n');
    }
    out
}

pub fn write_reports(
    records: &[ScenarioRecord],
    out_dir: &Path,
) -> Result<(PathBuf, PathBuf), String> {
    fs::create_dir_all(out_dir).map_err(|e| format!("create {}: {e}", out_dir.display()))?;
    let jsonl_path = out_dir.join("report.jsonl");
    let summary_path = out_dir.join("summary.md");

    publish(&jsonl_path, &render_jsonl(records))?;
    publish(&summary_path, &render_summary(records))?;
    Ok((jsonl_path, summary_path))
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
fn publish(path: &Path, body: &str) -> Result<(), String> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let tmp = path.with_extension(format!(
        "tmp.{}.{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::write(&tmp, body).map_err(|e| format!("write {}: {e}", tmp.display()))?;
    fs::rename(&tmp, path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!("publish {}: {e}", path.display())
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
        "{} scenarios played against skep's `Operation<World>::execute` surface.\n\n",
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
        match &r.first_failure {
            Some((i, label, detail)) => s.push_str(&format!(
                "- `{}/{}` — op {i} `{label}`: {}\n",
                r.category,
                r.name,
                trunc(detail, 300)
            )),
            None => s.push_str(&format!("- `{}/{}`\n", r.category, r.name)),
        }
    }
    if !any {
        s.push_str("(none)\n");
    }

    // The standing cluster analyses: each surfaced once, with the affected
    // scenarios listed, so the operators adjudicate a family in one sitting.
    // Notes may carry the analysis alongside other evidence, so the match is
    // containment, not equality.
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

    s.push_str("\n## Inexpressible scenarios (first untranslatable op)\n\n");
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
                    o.label,
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
