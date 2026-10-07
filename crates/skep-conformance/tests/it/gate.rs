//! The gate: three tests over the golden sweep, and one over the ratchet
//! file's own reading.
//!
//! * `harness_integrity` — the instrument works: the goldens all load, every
//!   op yields exactly one outcome, no scenario is stopped by a panic — skep's
//!   or the harness's — and the report and summary are written. It judges no
//!   verdict: the verdicts are the sweep's *product*, and they reach the
//!   operators through target/conformance/report.jsonl and summary.md.
//! * `report_is_deterministic` — every scenario replays to byte-identical
//!   report records, so a re-run is the archive.
//! * `conformance_ratchet` — conformance, enforced against
//!   `conformance/ratchet.toml`: an `error` verdict fails it for every
//!   scenario, `[pending]` included; a `divergent` verdict fails it unless
//!   `[pending]` lists the scenario; an `allowlisted` or `inexpressible`
//!   verdict fails it unless the file freezes the scenario in that section or
//!   `[pending]`; and a frozen key no golden scenario carries fails it, as
//!   does an allowlist entry that rules on no golden op. A `[pending]`
//!   scenario's other verdicts are reported, not enforced. Every scenario is
//!   named by its key, `category/name` — two goldens can share a name — and
//!   named once: a key the file lists twice is refused as the file is read,
//!   which `a_key_the_ratchet_lists_twice_is_refused` holds; the rule itself
//!   is `an_error_is_never_permitted_and_pending_admits_the_rest`'s.

use std::collections::HashSet;

use skep_conformance::allowlist;
use skep_conformance::outcome::{ScenarioKey, Verdict};
use skep_conformance::runner::run_all;

/// `harness_integrity` and `conformance_ratchet` both drive [`run_all`],
/// which writes the ONE operator-facing report under `target/conformance/`.
/// Under a THREADED runner they share this binary, and this lock keeps the
/// second sweep from starting while the first still has assertions to make
/// about the files it wrote.
///
/// It cannot reach a runner that gives each test its own PROCESS, which is
/// the arrangement the workspace's own runner uses — there the two sweeps
/// genuinely overlap. What makes the report safe to read under either is
/// that `write_reports` PUBLISHES by rename rather than truncating in place,
/// so the path never names a partial file; this lock only spares a threaded
/// run the redundant second sweep.
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
    // Held for the WHOLE body: the metadata assertions below read the files
    // this run wrote, so a threaded runner must not start the sibling sweep
    // underneath them. A sibling PROCESS may, and the rename-publish in
    // `write_reports` is what keeps those assertions true when it does.
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
    for (rec, (key, n_ops)) in out.records.iter().zip(&out.loaded_op_counts) {
        assert_eq!(&rec.key(), key, "record order must match load order");
        if rec.verdict != Verdict::Error {
            assert_eq!(
                rec.ops.len(),
                *n_ops,
                "scenario {}: every op must yield exactly one outcome",
                rec.key()
            );
        }
    }

    // No scenario is stopped by a panic. Each error names who panicked: one
    // naming skep is a failure in skep's operation surface, which must
    // answer every request it is handed (M10's totality); any other is a
    // harness bug. Neither is a conformance finding the allowlist could
    // cover.
    let errors: Vec<String> = out
        .records
        .iter()
        .filter(|r| r.verdict == Verdict::Error)
        .map(|r| format!("{}: {}", r.key(), r.error.as_deref().unwrap_or("?")))
        .collect();
    assert!(errors.is_empty(), "scenarios stopped short (skep's or the harness's): {errors:#?}");

    // The report and summary exist and are non-empty.
    let report = std::fs::metadata(&out.jsonl).expect("report.jsonl written");
    assert!(report.len() > 0, "report.jsonl must be non-empty");
    let summary = std::fs::metadata(&out.summary).expect("summary.md written");
    assert!(summary.len() > 0, "summary.md must be non-empty");
}

/// Determinism: the same scenarios replay to byte-identical report records.
/// The no-archival policy for reports rests on this — a re-run IS the
/// archive — so it holds for every scenario: the whole corpus is played
/// twice into rendered JSONL and compared byte for byte.
#[test]
fn report_is_deterministic() {
    use skep_conformance::loader::load_all;
    use skep_conformance::report::render_jsonl;
    use skep_conformance::runner::run_scenarios;

    let golden = skep_conformance::loader::conformance_dir().join("golden");
    let allow_path = skep_conformance::loader::conformance_dir().join("allowlist.toml");
    let scenarios = load_all(&golden).expect("goldens load");
    let allow = allowlist::load(&allow_path).expect("allowlist loads");

    assert!(!scenarios.is_empty());
    let first = render_jsonl(&run_scenarios(&scenarios, &allow));
    let second = render_jsonl(&run_scenarios(&scenarios, &allow));
    assert_eq!(first, second, "two identical runs must render byte-identical reports");
}

/// The RATCHET — conformance as an enforced property, against the verdicts
/// `conformance/ratchet.toml` freezes.
///
/// The file names each scenario by its key, once — a line naming no key is
/// refused as the file is read, and so is a key already listed, in its
/// section or another: a key copied rather than moved between sections would
/// let it take either section's verdict, and `[pending]` exempts it from
/// both, so the copy would widen what the gate permits with no line saying
/// so. Against it, scenario by scenario, this test FAILS on:
///
/// * an `Error`, for any scenario, whatever section lists it — `[pending]`
///   included: a scenario a panic stopped, or whose rig would not bootstrap,
///   is never admitted;
/// * a `Divergent`, unless `[pending]` lists the scenario;
/// * an `Allowlisted` or `Inexpressible`, unless the file freezes the
///   scenario in that very section or in `[pending]`;
///
/// and on a frozen key no golden scenario carries (a renamed or removed
/// golden would otherwise leave a line that guards nothing), or an allowlist
/// entry that rules on no golden op (`Allowlist::unanchored`). A `[pending]`
/// scenario's other verdicts are reported, not enforced, and so is a frozen
/// scenario that improved to `Pass`, so its line can be trimmed. Growing
/// `[allowlisted]` or `[inexpressible]` requires a human ruling in
/// adjudication/decisions.md — never an edit made to turn this test green; a
/// scenario enters `[pending]` only beside a recorded (not ruled) entry there
/// naming it — a rule of the ledger, which this test does not check.
#[test]
fn conformance_ratchet() {
    let conformance = skep_conformance::loader::conformance_dir();
    let raw =
        std::fs::read_to_string(conformance.join("ratchet.toml")).expect("ratchet.toml must exist");
    let frozen = parse_ratchet(&raw);
    let allow = allowlist::load(&conformance.join("allowlist.toml")).expect("allowlist loads");

    let _report = report_guard();
    let out = run_all().expect("sweep must run");
    let mut violations = Vec::new();
    let mut improved = Vec::new();
    let mut pending_seen = Vec::new();
    for r in &out.records {
        let key = r.key();
        match rule(&frozen, &key, r.verdict) {
            Ruling::Permitted => {}
            Ruling::Pending => pending_seen.push(format!("{key}: {:?}", r.verdict)),
            Ruling::Improved => improved.push(key),
            Ruling::Violation => {
                violations.push(format!("{key}: {:?} not permitted by ratchet", r.verdict))
            }
        }
    }
    let keys: HashSet<ScenarioKey> = out.records.iter().map(|r| r.key()).collect();
    for (section, listed) in frozen.sections() {
        let mut missing: Vec<&ScenarioKey> =
            listed.iter().filter(|k| !keys.contains(*k)).collect();
        missing.sort();
        for k in missing {
            violations
                .push(format!("[{section}] {k}: frozen, but no golden scenario carries the key"));
        }
    }
    // An allowlist entry that rules on no golden op covers nothing today,
    // and would cover a golden that later took its key or its op with no
    // ruling behind it.
    violations.extend(allow.unanchored(&out.loaded_op_counts));
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
             (adjudication/decisions.md) before the frozen set may grow, and a frozen \
             key no golden carries, or an allowlist entry ruling on no golden op, \
             guards nothing until it is corrected:\n{}",
            violations.join("\n"));
}

/// The verdicts `ratchet.toml` freezes: each section's keys.
#[derive(Debug, Default)]
struct Frozen {
    allowlisted: HashSet<ScenarioKey>,
    inexpressible: HashSet<ScenarioKey>,
    pending: HashSet<ScenarioKey>,
}

impl Frozen {
    /// Each section, named as the file names it.
    fn sections(&self) -> [(&'static str, &HashSet<ScenarioKey>); 3] {
        [
            ("allowlisted", &self.allowlisted),
            ("inexpressible", &self.inexpressible),
            ("pending", &self.pending),
        ]
    }
}

/// What the ratchet says of one scenario's verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ruling {
    /// Permitted, and nothing to report.
    Permitted,
    /// Permitted and reported: a `[pending]` scenario that does not pass.
    Pending,
    /// Permitted and reported: a frozen scenario that improved to `Pass`,
    /// whose line can be trimmed.
    Improved,
    /// Not permitted: the gate fails.
    Violation,
}

/// The ratchet's rule for scenario `key`'s `verdict` against `frozen`, in
/// order: an `Error` is a violation for any scenario, listed or not; a
/// `[pending]` scenario is otherwise reported unless it passes; a `Pass` is
/// permitted, reported when the file freezes the scenario; an `Allowlisted`
/// or `Inexpressible` is permitted only where the file freezes the scenario
/// in that very section; anything else is a violation.
fn rule(frozen: &Frozen, key: &ScenarioKey, verdict: Verdict) -> Ruling {
    if verdict == Verdict::Error {
        return Ruling::Violation;
    }
    if frozen.pending.contains(key) {
        return if verdict == Verdict::Pass { Ruling::Permitted } else { Ruling::Pending };
    }
    let frozen_in = |section: &HashSet<ScenarioKey>| section.contains(key);
    match verdict {
        Verdict::Pass if frozen_in(&frozen.allowlisted) || frozen_in(&frozen.inexpressible) => {
            Ruling::Improved
        }
        Verdict::Pass => Ruling::Permitted,
        Verdict::Allowlisted if frozen_in(&frozen.allowlisted) => Ruling::Permitted,
        Verdict::Inexpressible if frozen_in(&frozen.inexpressible) => Ruling::Permitted,
        _ => Ruling::Violation,
    }
}

/// An `Error` is never admitted, `[pending]` included; `[pending]` admits
/// every other verdict, reported; an `Allowlisted` or `Inexpressible`
/// verdict is admitted only in its own section, a `Divergent` one nowhere
/// else; and a frozen scenario that passes is reported for trimming.
#[test]
fn an_error_is_never_permitted_and_pending_admits_the_rest() {
    let frozen = parse_ratchet(
        "[allowlisted]\nscenario = \"cat/a\"\n[inexpressible]\nscenario = \"cat/i\"\n\
         [pending]\nscenario = \"cat/p\"\n",
    );
    let ruled = |key: &str, verdict| rule(&frozen, &key.parse().expect("a key"), verdict);
    use Ruling::{Improved, Pending, Permitted, Violation};
    use Verdict::{Allowlisted, Divergent, Error, Inexpressible, Pass};
    assert_eq!(ruled("cat/p", Error), Violation);
    assert_eq!(ruled("cat/p", Divergent), Pending);
    assert_eq!(ruled("cat/p", Inexpressible), Pending);
    assert_eq!(ruled("cat/p", Pass), Permitted);
    assert_eq!(ruled("cat/a", Allowlisted), Permitted);
    assert_eq!(ruled("cat/a", Inexpressible), Violation);
    assert_eq!(ruled("cat/a", Divergent), Violation);
    assert_eq!(ruled("cat/a", Error), Violation);
    assert_eq!(ruled("cat/a", Pass), Improved);
    assert_eq!(ruled("cat/i", Inexpressible), Permitted);
    assert_eq!(ruled("cat/i", Allowlisted), Violation);
    assert_eq!(ruled("cat/i", Pass), Improved);
    assert_eq!(ruled("cat/u", Pass), Permitted);
    assert_eq!(ruled("cat/u", Divergent), Violation);
    assert_eq!(ruled("cat/u", Error), Violation);
}

/// `ratchet.toml`'s text, read into its sections — refusing, by the gate's
/// own failure, a line it does not speak: an unknown section, a line naming
/// no key, and a key already listed, in its section or another.
fn parse_ratchet(raw: &str) -> Frozen {
    let mut frozen = Frozen::default();
    let mut section = String::new();
    let mut listed: HashSet<ScenarioKey> = HashSet::new();
    for line in raw.lines() {
        let l = line.trim();
        if l.starts_with('#') || l.is_empty() {
            continue;
        } else if let Some(s) = l.strip_prefix('[').and_then(|x| x.strip_suffix(']')) {
            section = s.to_string();
        } else if let Some(v) = l.strip_prefix("scenario = \"").and_then(|x| x.strip_suffix('"')) {
            let key: ScenarioKey = v.parse().unwrap_or_else(|e| panic!("ratchet.toml: {e}"));
            assert!(listed.insert(key.clone()), "ratchet.toml: `{key}` is listed twice");
            match section.as_str() {
                "allowlisted" => frozen.allowlisted.insert(key),
                "inexpressible" => frozen.inexpressible.insert(key),
                "pending" => frozen.pending.insert(key),
                other => panic!("ratchet.toml: unknown section [{other}]"),
            };
        } else {
            panic!("ratchet.toml: unparseable line: {l}");
        }
    }
    frozen
}

/// A key copied between sections rather than moved is refused as the file
/// is read: kept, it would take either section's verdict, or none.
#[test]
#[should_panic(expected = "ratchet.toml: `cat/a` is listed twice")]
fn a_key_the_ratchet_lists_twice_is_refused() {
    parse_ratchet("[allowlisted]\nscenario = \"cat/a\"\n\n[pending]\nscenario = \"cat/a\"\n");
}
