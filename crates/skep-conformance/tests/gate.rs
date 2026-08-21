//! The gate — HARNESS INTEGRITY ONLY.
//!
//! This test asserts that the instrument works: the goldens all load, every
//! op is translated or classified, no scenario panics, and the report and
//! summary are written. It does NOT assert conformance: divergent scenarios
//! are the run's *product*, not its failure, and they reach the operators
//! through target/conformance/report.jsonl and summary.md.

use skep_conformance::outcome::Verdict;
use skep_conformance::runner::run_all;

/// `harness_integrity` and `conformance_ratchet` both drive [`run_all`],
/// which writes the ONE operator-facing report under `target/conformance/`.
/// Cargo runs them on parallel threads of this binary, so without this lock
/// the second run truncates the file the first is about to `stat` — observed
/// as a one-in-many flake, 2026-08-21.
///
/// Serialized rather than given separate output directories ON PURPOSE: the
/// report is a single canonical artifact operators read (the harness's
/// product, §gate docs above), and fragmenting it per test would trade a
/// real property for a test convenience. Both tests run the full sweep, so
/// parallelism bought little here anyway.
///
/// `report_is_deterministic` writes no files and is deliberately NOT gated.
static REPORT: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Take the report lock, ignoring poisoning: if a sibling test panicked, that
/// panic is the finding — the other test should still run and report its own
/// verdict rather than fail with a lock error.
fn report_guard() -> std::sync::MutexGuard<'static, ()> {
    REPORT.lock().unwrap_or_else(|e| e.into_inner())
}

#[test]
fn harness_integrity() {
    // Held for the WHOLE body: the metadata assertions below read the file
    // this run wrote, so releasing after `run_all` would leave exactly the
    // truncate-while-stat window this lock exists to close.
    let _report = report_guard();
    let out = run_all().expect("the harness must load goldens, run, and write reports");

    // The vendored corpus: 263 original + 34 corpus-extension scenarios. A
    // different count means the vendoring changed underneath the harness —
    // surface it here.
    assert_eq!(out.records.len(), 297, "expected the 297 vendored golden scenarios");
    assert_eq!(out.loaded_op_counts.len(), out.records.len());

    // Every op classified: one outcome per recorded operation, for every
    // scenario the harness itself did not crash on (an `error` verdict is
    // asserted against below, with its own message).
    for (rec, (name, n_ops)) in out.records.iter().zip(&out.loaded_op_counts) {
        assert_eq!(&rec.name, name, "record order must match load order");
        if rec.verdict != Verdict::Error {
            assert_eq!(
                rec.ops.len(),
                *n_ops,
                "scenario {}: every op must yield exactly one outcome",
                rec.name
            );
        }
    }

    // No scenario panics the harness. A failure here is a harness bug to
    // fix — never a conformance finding.
    let errors: Vec<String> = out
        .records
        .iter()
        .filter(|r| r.verdict == Verdict::Error)
        .map(|r| {
            format!("{}/{}: {}", r.category, r.name, r.error.as_deref().unwrap_or("?"))
        })
        .collect();
    assert!(errors.is_empty(), "harness errors (harness bugs, fix them): {errors:#?}");

    // The report and summary exist and are non-empty.
    let report = std::fs::metadata(&out.jsonl).expect("report.jsonl written");
    assert!(report.len() > 0, "report.jsonl must be non-empty");
    let summary = std::fs::metadata(&out.summary).expect("summary.md written");
    assert!(summary.len() > 0, "summary.md must be non-empty");
}

/// Determinism: the same scenarios replay to byte-identical report records.
/// The no-archival policy for reports rests on this — a re-run IS the
/// archive. A representative slice (every 10th scenario, ≥ one per run) is
/// played twice into rendered JSONL and compared byte for byte.
#[test]
fn report_is_deterministic() {
    use skep_conformance::allowlist;
    use skep_conformance::loader::load_all;
    use skep_conformance::report::render_jsonl;
    use skep_conformance::runner::run_scenarios;

    let golden = skep_conformance::conformance_dir().join("golden");
    let allow_path = skep_conformance::conformance_dir().join("allowlist.toml");
    let scenarios = load_all(&golden).expect("goldens load");
    let allow = allowlist::load(&allow_path).expect("allowlist loads");

    let subset: Vec<_> = scenarios.into_iter().step_by(10).collect();
    assert!(!subset.is_empty());
    let first = render_jsonl(&run_scenarios(&subset, &allow));
    let second = render_jsonl(&run_scenarios(&subset, &allow));
    assert_eq!(first, second, "two identical runs must render byte-identical reports");
}

/// The RATCHET — conformance as an enforced property (frozen 2026-08-15,
/// adjudication complete: decisions.md rulings 1–15, zero divergent).
///
/// `conformance/ratchet.toml` freezes the expected non-pass set. This test
/// FAILS on any scenario that is `Divergent` or `Error`, on any
/// `Allowlisted`/`Inexpressible` scenario not in the frozen lists, and it
/// reports (without failing) frozen entries that improved to `Pass` so the
/// file can be trimmed. Growing the frozen set requires a human ruling in
/// adjudication/decisions.md — never an edit made to turn this test green.
#[test]
fn conformance_ratchet() {
    use std::collections::HashSet;
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/ratchet.toml");
    let raw = std::fs::read_to_string(&path).expect("ratchet.toml must exist");
    let (mut section, mut allow, mut inexpr, mut pending) =
        (String::new(), HashSet::new(), HashSet::new(), HashSet::new());
    for line in raw.lines() {
        let l = line.trim();
        if l.starts_with('#') || l.is_empty() {
            continue;
        } else if let Some(s) = l.strip_prefix('[').and_then(|x| x.strip_suffix(']')) {
            section = s.to_string();
        } else if let Some(v) = l.strip_prefix("scenario = \"").and_then(|x| x.strip_suffix('"')) {
            match section.as_str() {
                "allowlisted" => allow.insert(v.to_string()),
                "inexpressible" => inexpr.insert(v.to_string()),
                "pending" => pending.insert(v.to_string()),
                other => panic!("ratchet.toml: unknown section [{other}]"),
            };
        } else {
            panic!("ratchet.toml: unparseable line: {l}");
        }
    }

    let _report = report_guard();
    let out = run_all().expect("sweep must run");
    let mut violations = Vec::new();
    let mut improved = Vec::new();
    let mut pending_seen = Vec::new();
    for r in &out.records {
        if pending.contains(&r.name) {
            if r.verdict != Verdict::Pass {
                pending_seen.push(format!("{}/{}: {:?}", r.category, r.name, r.verdict));
            }
            continue; // corpus extension awaiting adjudication — exempt, visible
        }
        match r.verdict {
            Verdict::Pass => {
                if allow.contains(&r.name) || inexpr.contains(&r.name) {
                    improved.push(r.name.clone());
                }
            }
            Verdict::Allowlisted if allow.contains(&r.name) => {}
            Verdict::Inexpressible if inexpr.contains(&r.name) => {}
            v => violations.push(format!("{}/{}: {v:?} not permitted by ratchet", r.category, r.name)),
        }
    }
    if !pending_seen.is_empty() {
        eprintln!("ratchet: {} PENDING scenario(s) need adjudication:\n{}",
                  pending_seen.len(), pending_seen.join("\n"));
    }
    if !improved.is_empty() {
        eprintln!("ratchet: {} frozen scenario(s) improved to Pass — trim ratchet.toml: {improved:?}",
                  improved.len());
    }
    assert!(violations.is_empty(),
            "CONFORMANCE RATCHET VIOLATED — a new divergence requires a human ruling \
             (adjudication/decisions.md) before the frozen set may grow:\n{}",
            violations.join("\n"));
}
