//! The allowlist — `skep/conformance/allowlist.toml`. Entries name
//! ADJUDICATED divergences: a divergence with a matching entry earns verdict
//! `allowlisted`; without one it stays `divergent`. The harness itself never
//! adds entries.
//!
//! The file is a restricted TOML subset, parsed here directly so the harness
//! carries no TOML dependency: `[[allow]]` blocks of `key = value` lines
//! (string / integer values), `#` comments, blank lines. Keys:
//!
//! * `scenario`  (required) — the golden scenario name;
//! * `op_index`  (optional) — restrict to one op (0-based); absent = all ops;
//! * `class`     (required) — a short divergence class;
//! * `rationale` (required) — one sentence citing the adjudication source;
//! * `count_delta`     (optional) — declared count adjustment (golden+delta);
//! * `width_tolerance` (optional) — span-width tolerance granted.

use std::fs;
use std::path::Path;

#[derive(Clone, Debug, Default)]
pub struct Entry {
    pub scenario: String,
    pub op_index: Option<usize>,
    pub class: String,
    pub rationale: String,
    pub count_delta: Option<i64>,
    pub width_tolerance: Option<u64>,
}

#[derive(Default)]
pub struct Allowlist {
    pub entries: Vec<Entry>,
}

impl Allowlist {
    /// Entries applying to (scenario, op index).
    pub fn matching(&self, scenario: &str, op_index: usize) -> Vec<&Entry> {
        self.entries
            .iter()
            .filter(|e| e.scenario == scenario && e.op_index.map_or(true, |i| i == op_index))
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
    out.entries.push(e);
    Ok(())
}
