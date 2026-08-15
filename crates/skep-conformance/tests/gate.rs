//! The gate — HARNESS INTEGRITY ONLY.
//!
//! This test asserts that the instrument works: the goldens all load, every
//! op is translated or classified, no scenario panics, and the report and
//! summary are written. It does NOT assert conformance: divergent scenarios
//! are the run's *product*, not its failure, and they reach the operators
//! through target/conformance/report.jsonl and summary.md.

use skep_conformance::outcome::Verdict;
use skep_conformance::runner::run_all;

#[test]
fn harness_integrity() {
    let out = run_all().expect("the harness must load goldens, run, and write reports");

    // The vendored corpus: 263 scenarios. A different count means the
    // vendoring changed underneath the harness — surface it here.
    assert_eq!(out.records.len(), 263, "expected the 263 vendored golden scenarios");
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
