//! The allowlist — `skep/conformance/allowlist.toml`. Entries name
//! ADJUDICATED divergences: a divergence with a matching entry earns verdict
//! `allowlisted`; without one it stays `divergent`. The harness itself never
//! adds entries.
//!
//! The file is a restricted TOML subset, parsed here directly so the harness
//! carries no TOML dependency: `[[allow]]` blocks of `key = value` lines
//! (string / integer values), `#` comments, blank lines. Keys:
//!
//! * `scenario`  (required) — the golden scenario's key, `category/name`
//!   (`outcome::scenario_key`) — a bare name is refused, since two goldens
//!   can share one;
//! * `op_index`  (optional) — restrict to one op (0-based); absent = all ops;
//! * `class`     (required) — a short divergence class;
//! * `rationale` (required) — one sentence citing the adjudication source;
//! * `count_delta`     (optional) — declared count adjustment (golden+delta);
//! * `width_tolerance` (optional) — span-width tolerance granted;
//! * `expected_matches` (optional) — a substring of the op's rendered
//!   EXPECTED value. When present the entry applies to any DISAGREED op of
//!   the scenario whose expected value contains it (op_index, if also
//!   present, must match too) — a signature key that survives op-index
//!   shifts across harness rounds. Signature entries classify only; their
//!   `count_delta`/`width_tolerance` never apply (adjustments run before
//!   comparison, when the expected value is not yet known).
//!
//! An entry applies twice. Before an op runs, [`Allowlist::grants`] hands
//! its comparators the adjustments the op's entries declare; after, a
//! comparator that agreed only because it used one records so
//! ([`GRANT_WIDTH`], [`GRANT_COUNT`]), and [`Allowlist::grant`] names the
//! classes covering the outcome.

use std::fs;
use std::path::Path;

use crate::outcome::{OpOutcome, Status};

/// The adjustments the allowlist grants one op's comparators, resolved
/// before the op runs from its non-signature entries: the widest width
/// tolerance any of them declares, and the first count delta.
#[derive(Clone, Copy, Debug, Default)]
pub struct Grants {
    pub width_tolerance: u64,
    pub count_delta: i64,
}

/// The adaptation a span comparator records when a granted width tolerance,
/// not the raw widths, made its agreement.
pub const GRANT_WIDTH: &str = "allowlist-grant:width";

/// The adaptation a count comparator records when a granted count delta,
/// not the raw count, made its agreement.
pub const GRANT_COUNT: &str = "allowlist-grant:count";

#[derive(Clone, Debug, Default)]
pub struct Entry {
    pub scenario: String,
    pub op_index: Option<usize>,
    pub class: String,
    pub rationale: String,
    pub count_delta: Option<i64>,
    pub width_tolerance: Option<u64>,
    pub expected_matches: Option<String>,
}

#[derive(Default)]
pub struct Allowlist {
    pub entries: Vec<Entry>,
}

impl Allowlist {
    /// The adjustments granted to the comparators of (scenario, op index).
    pub fn grants(&self, scenario: &str, op_index: usize) -> Grants {
        let entries = self.matching(scenario, op_index);
        Grants {
            width_tolerance: entries.iter().filter_map(|e| e.width_tolerance).max().unwrap_or(0),
            count_delta: entries.iter().filter_map(|e| e.count_delta).next().unwrap_or(0),
        }
    }

    /// The class or classes covering one op's outcome, `+`-joined; `None`
    /// when no entry covers it. A disagreement is covered by every entry
    /// matching its op, then by every signature entry its rendered expected
    /// value matches. An agreement is covered only when one of its
    /// comparators recorded that a granted adjustment made it — the entry's
    /// existence IS the adjudicated divergence. Every covering class is
    /// surfaced, so the ruling behind a verdict is auditable from the report
    /// alone.
    pub fn grant(&self, scenario: &str, op_index: usize, out: &OpOutcome) -> Option<String> {
        let disagreed = out.status == Status::Disagreed;
        let adjusted = out.status == Status::Agreed
            && out.adaptations.iter().any(|a| a == GRANT_WIDTH || a == GRANT_COUNT);
        let mut granted: Option<String> = None;
        if disagreed || adjusted {
            let mut classes: Vec<String> =
                self.matching(scenario, op_index).iter().map(|e| e.class.clone()).collect();
            classes.dedup();
            if !classes.is_empty() {
                granted = Some(classes.join("+"));
            }
        }
        if disagreed {
            let sig = self.matching_expected(scenario, op_index, out.expected.as_deref());
            if !sig.is_empty() {
                let mut classes: Vec<String> = sig.iter().map(|e| e.class.clone()).collect();
                if let Some(prev) = granted.take() {
                    classes.insert(0, prev);
                }
                classes.dedup();
                granted = Some(classes.join("+"));
            }
        }
        granted
    }

    /// Entries applying to (scenario, op index) BEFORE execution — the
    /// adjustment-capable path. Signature entries (`expected_matches`) are
    /// excluded: they cannot be evaluated until the expected value exists.
    fn matching(&self, scenario: &str, op_index: usize) -> Vec<&Entry> {
        self.entries
            .iter()
            .filter(|e| {
                e.expected_matches.is_none()
                    && e.scenario == scenario
                    && e.op_index.is_none_or(|i| i == op_index)
            })
            .collect()
    }

    /// Signature entries applying to a DISAGREED op after execution: the
    /// scenario matches, the op index (when given) matches, and the op's
    /// rendered expected value contains the entry's substring.
    fn matching_expected(
        &self,
        scenario: &str,
        op_index: usize,
        expected: Option<&str>,
    ) -> Vec<&Entry> {
        let Some(expected) = expected else { return Vec::new() };
        self.entries
            .iter()
            .filter(|e| {
                e.scenario == scenario
                    && e.op_index.is_none_or(|i| i == op_index)
                    && e.expected_matches.as_deref().is_some_and(|m| expected.contains(m))
            })
            .collect()
    }
}

/// Parse the restricted subset. Unknown keys are a hard error — an entry
/// that silently half-applies would be a quiet comparator widening.
pub fn load(path: &Path) -> Result<Allowlist, String> {
    let raw = match fs::read_to_string(path) {
        Ok(r) => r,
        // A missing file is an empty allowlist, not an error: the seed file
        // ships with the repo, but the harness must not fail on a clean
        // checkout that lacks it.
        Err(_) => return Ok(Allowlist::default()),
    };
    let mut out = Allowlist::default();
    let mut cur: Option<Entry> = None;
    for (ln, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "[[allow]]" {
            if let Some(e) = cur.take() {
                finish(e, &mut out, ln)?;
            }
            cur = Some(Entry::default());
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            return Err(format!("allowlist line {}: expected `key = value`", ln + 1));
        };
        let e = cur
            .as_mut()
            .ok_or_else(|| format!("allowlist line {}: key outside [[allow]] block", ln + 1))?;
        let k = k.trim();
        let v = v.trim();
        let s = |v: &str| -> Result<String, String> {
            let v = v.strip_prefix('"').and_then(|x| x.strip_suffix('"'));
            v.map(str::to_string)
                .ok_or_else(|| format!("allowlist line {}: expected quoted string", ln + 1))
        };
        match k {
            "scenario" => e.scenario = s(v)?,
            "class" => e.class = s(v)?,
            "rationale" => e.rationale = s(v)?,
            "op_index" => {
                e.op_index = Some(v.parse().map_err(|_| {
                    format!("allowlist line {}: op_index must be an integer", ln + 1)
                })?)
            }
            "count_delta" => {
                e.count_delta = Some(v.parse().map_err(|_| {
                    format!("allowlist line {}: count_delta must be an integer", ln + 1)
                })?)
            }
            "width_tolerance" => {
                e.width_tolerance = Some(v.parse().map_err(|_| {
                    format!("allowlist line {}: width_tolerance must be an integer", ln + 1)
                })?)
            }
            "expected_matches" => e.expected_matches = Some(s(v)?),
            other => return Err(format!("allowlist line {}: unknown key `{other}`", ln + 1)),
        }
    }
    if let Some(e) = cur.take() {
        finish(e, &mut out, raw.lines().count())?;
    }
    Ok(out)
}

fn finish(e: Entry, out: &mut Allowlist, ln: usize) -> Result<(), String> {
    if e.scenario.is_empty() || e.class.is_empty() || e.rationale.is_empty() {
        return Err(format!(
            "allowlist entry ending near line {}: scenario, class and rationale are required",
            ln + 1
        ));
    }
    let keyed = e.scenario.split_once('/').is_some_and(|(cat, name)| {
        !cat.is_empty() && !name.is_empty() && !name.contains('/')
    });
    if !keyed {
        return Err(format!(
            "allowlist entry ending near line {}: scenario `{}` is no `category/name` key",
            ln + 1,
            e.scenario
        ));
    }
    out.entries.push(e);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome(index: usize, status: Status, expected: Option<&str>) -> OpOutcome {
        let mut o = OpOutcome::new(index, "probe");
        o.status = status;
        o.expected = expected.map(str::to_string);
        o
    }

    /// A disagreement is covered by the entries matching its op and the
    /// signature entries its expected value matches; an agreement only when
    /// a comparator recorded that a granted adjustment made it.
    #[test]
    fn a_grant_covers_disagreements_and_only_the_agreements_an_adjustment_made() {
        let allow = Allowlist {
            entries: vec![
                Entry {
                    scenario: "s".into(),
                    op_index: Some(1),
                    class: "tolerated".into(),
                    rationale: "r".into(),
                    width_tolerance: Some(1),
                    ..Entry::default()
                },
                Entry {
                    scenario: "s".into(),
                    class: "shape".into(),
                    rationale: "r".into(),
                    expected_matches: Some("(\"0\"".into()),
                    ..Entry::default()
                },
            ],
        };
        assert_eq!(allow.grants("s", 1).width_tolerance, 1);
        assert_eq!(allow.grants("s", 2).width_tolerance, 0, "a signature entry adjusts nothing");

        let mut agreed = outcome(1, Status::Agreed, None);
        assert_eq!(allow.grant("s", 1, &agreed), None, "no grant made this agreement");
        agreed.adaptations.push(GRANT_WIDTH.into());
        assert_eq!(allow.grant("s", 1, &agreed).as_deref(), Some("tolerated"));

        let shaped = outcome(2, Status::Disagreed, Some("[(\"0\", \"0.1\")]"));
        assert_eq!(allow.grant("s", 2, &shaped).as_deref(), Some("shape"));
        let other = outcome(2, Status::Disagreed, Some("[(\"1.1\", \"0.3\")]"));
        assert_eq!(allow.grant("s", 2, &other), None);
        let both = outcome(1, Status::Disagreed, Some("(\"0\""));
        assert_eq!(allow.grant("s", 1, &both).as_deref(), Some("tolerated+shape"));
        assert_eq!(allow.grant("t", 1, &both), None, "entries are per scenario");
    }

    /// An entry names its scenario by key: a bare name — which two goldens
    /// can share — is refused at load, never left to match nothing.
    #[test]
    fn an_entry_names_its_scenario_by_key() {
        let dir = std::env::temp_dir().join(format!("skep-allowlist-keys-{}", std::process::id()));
        fs::create_dir_all(&dir).expect("a scratch directory");
        let entry = |scenario: &str| {
            format!("[[allow]]\nscenario = \"{scenario}\"\nclass = \"c\"\nrationale = \"r\"\n")
        };
        let path = dir.join("allowlist.toml");
        fs::write(&path, entry("discovery/find_documents_basic")).expect("an allowlist");
        let keyed = load(&path).map(|a| a.entries[0].scenario.clone());
        fs::write(&path, entry("find_documents_basic")).expect("an allowlist");
        let bare = load(&path).err();
        fs::remove_dir_all(&dir).expect("the scratch directory is removed");
        assert_eq!(keyed.as_deref(), Ok("discovery/find_documents_basic"));
        assert!(bare.is_some_and(|e| e.contains("no `category/name` key")));
    }
}
