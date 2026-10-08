//! The allowlist — `skep/conformance/allowlist.toml`. Entries name
//! ADJUDICATED divergences: a divergence with a matching entry earns verdict
//! `allowlisted`; without one it stays `divergent`. The harness itself never
//! adds entries.
//!
//! The file is a TOML-like format, not TOML, parsed here directly so the
//! harness carries no TOML dependency: `[[allow]]` blocks of `key = value`
//! lines (quoted-string / integer values), `#` comments, blank lines. A
//! quoted value is everything between the line's first and last `"`, taken
//! verbatim — no escapes, no trailing comment — so a signature can hold the
//! `"`s of a rendered expected value as they stand (lines a TOML reader
//! rejects). Each key is set at most once per block. Keys:
//!
//! * `scenario`  (required) — the golden scenario's key, `category/name`
//!   (`outcome::ScenarioKey`) — a bare name is refused where it is read,
//!   since two goldens can share one;
//! * `op_index`  (optional) — restrict to one op (0-based); absent = all ops;
//! * `class`     (required) — a short divergence class;
//! * `rationale` (required) — one sentence citing the adjudication source;
//!   the file's record of the ruling, read by people — an entry the harness
//!   keeps holds what classification uses;
//! * `count_delta`     (optional) — declared count adjustment (golden+delta);
//!   two entries over one op declaring different deltas are refused, never
//!   left to file order to settle;
//! * `width_tolerance` (optional) — declared span-width tolerance;
//! * `expected_matches` (optional) — a nonempty substring of the op's
//!   rendered EXPECTED value. When present the entry applies to any
//!   DISAGREED op of the scenario whose expected value contains it
//!   (op_index, if also present, must match too) — a signature key that
//!   survives op-index shifts across harness rounds; an empty one, which
//!   every expected value contains, is refused. Signature entries classify
//!   only; their `count_delta`/`width_tolerance` never apply (adjustments
//!   run before comparison, when the expected value is not yet known).
//!
//! An entry applies twice. Before an op runs, [`Allowlist::adjustments`]
//! hands its comparators the adjustments the op's entries declare; after, a
//! comparator that agreed only because it used one records so
//! ([`WIDTH_ADJUSTED`], [`COUNT_ADJUSTED`]), and [`Allowlist::classify`]
//! names the classes covering the outcome. An entry rules on golden ops: one
//! whose key no golden carries, or whose `op_index` lies past its scenario's
//! ops, rules on nothing, and the gate's ratchet refuses it
//! ([`Allowlist::unanchored`]).

use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::outcome::{NotAScenarioKey, OpOutcome, ScenarioKey, Status};

/// The adjustments the allowlist declares for one op's comparators,
/// resolved before the op runs from its non-signature entries: the widest
/// width tolerance any of them declares, and the count delta they declare —
/// one value, since [`load`] refuses entries over one op declaring two.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Adjustments {
    pub width_tolerance: u64,
    pub count_delta: i64,
}

/// The adaptation a span comparator records when a declared width
/// tolerance, not the raw widths, made its agreement.
pub const WIDTH_ADJUSTED: &str = "allowlist-adjusted:width";

/// The adaptation a count comparator records when a declared count delta,
/// not the raw count, made its agreement.
pub const COUNT_ADJUSTED: &str = "allowlist-adjusted:count";

/// One adjudicated divergence, as classification uses it: its scenario and
/// class always present, and the line of the file its block opens at.
#[derive(Clone, Debug)]
struct Entry {
    line: usize,
    scenario: ScenarioKey,
    op_index: Option<usize>,
    class: String,
    count_delta: Option<i64>,
    width_tolerance: Option<u64>,
    expected_matches: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct Allowlist {
    entries: Vec<Entry>,
}

impl Allowlist {
    /// The adjustments declared for the comparators of (scenario, op index).
    pub fn adjustments(&self, scenario: &ScenarioKey, op_index: usize) -> Adjustments {
        let entries = self.op_entries(scenario, op_index);
        Adjustments {
            width_tolerance: entries.iter().filter_map(|e| e.width_tolerance).max().unwrap_or(0),
            count_delta: entries.iter().filter_map(|e| e.count_delta).next().unwrap_or(0),
        }
    }

    /// The class or classes covering one op's outcome, `+`-joined; `None`
    /// when no entry covers it. A disagreement is covered by every entry
    /// matching its op, then by every signature entry its rendered expected
    /// value matches. An agreement is covered only by the entries whose
    /// declared adjustment one of its comparators recorded making it — a
    /// width tolerance ([`WIDTH_ADJUSTED`]) by every entry declaring one, the
    /// count delta ([`COUNT_ADJUSTED`]) by the first entry declaring one, the
    /// delta applied — the entry's existence IS the adjudicated divergence. Every
    /// covering class is surfaced, so the ruling behind a verdict is
    /// auditable from the report alone.
    pub fn classify(
        &self,
        scenario: &ScenarioKey,
        op_index: usize,
        out: &OpOutcome,
    ) -> Option<String> {
        let disagreed = out.status() == Status::Disagreed;
        let made = |tag: &str| {
            out.status() == Status::Agreed && out.adaptations.iter().any(|a| a == tag)
        };
        let (width_made, count_made) = (made(WIDTH_ADJUSTED), made(COUNT_ADJUSTED));
        let entries = self.op_entries(scenario, op_index);
        let delta_entry = entries.iter().find(|e| e.count_delta.is_some());
        let mut classes: Vec<String> = entries
            .iter()
            .filter(|e| {
                disagreed
                    || (width_made && e.width_tolerance.is_some())
                    || (count_made && delta_entry.is_some_and(|d| std::ptr::eq(*d, **e)))
            })
            .map(|e| e.class.clone())
            .collect();
        classes.dedup();
        let mut covering = (!classes.is_empty()).then(|| classes.join("+"));
        if disagreed {
            let expected = out.disagreement().map(|d| d.expected.as_str());
            let sig = self.signature_entries(scenario, op_index, expected);
            if !sig.is_empty() {
                let mut classes: Vec<String> = sig.iter().map(|e| e.class.clone()).collect();
                if let Some(prev) = covering.take() {
                    classes.insert(0, prev);
                }
                classes.dedup();
                covering = Some(classes.join("+"));
            }
        }
        covering
    }

    /// The entries that rule on no golden op of the `loaded` scenarios —
    /// each key with its op count — one line each, naming the entry by the
    /// line its block opens at: an entry whose key no golden carries, or
    /// whose `op_index` lies past its scenario's ops. Such an entry covers
    /// nothing, and would cover — with no ruling behind it — a golden that
    /// later took its key or its op.
    pub fn unanchored(&self, loaded: &[(ScenarioKey, usize)]) -> Vec<String> {
        self.entries
            .iter()
            .filter_map(|e| {
                let ops = loaded.iter().find(|(key, _)| *key == e.scenario).map(|(_, n)| *n);
                match (ops, e.op_index) {
                    (None, _) => Some(format!(
                        "allowlist line {}: `{}` — no golden scenario carries the key",
                        e.line, e.scenario
                    )),
                    (Some(n), Some(i)) if i >= n => Some(format!(
                        "allowlist line {}: `{}` op_index {i} — the scenario has {n} ops",
                        e.line, e.scenario
                    )),
                    _ => None,
                }
            })
            .collect()
    }

    /// Entries applying to (scenario, op index) BEFORE execution — the
    /// adjustment-capable path. Signature entries (`expected_matches`) are
    /// excluded: they cannot be evaluated until the expected value exists.
    fn op_entries(&self, scenario: &ScenarioKey, op_index: usize) -> Vec<&Entry> {
        self.entries
            .iter()
            .filter(|e| {
                e.expected_matches.is_none()
                    && e.scenario == *scenario
                    && e.op_index.is_none_or(|i| i == op_index)
            })
            .collect()
    }

    /// Signature entries applying to a DISAGREED op after execution: the
    /// scenario matches, the op index (when given) matches, and the op's
    /// rendered expected value contains the entry's substring.
    fn signature_entries(
        &self,
        scenario: &ScenarioKey,
        op_index: usize,
        expected: Option<&str>,
    ) -> Vec<&Entry> {
        let Some(expected) = expected else { return Vec::new() };
        self.entries
            .iter()
            .filter(|e| {
                e.scenario == *scenario
                    && e.op_index.is_none_or(|i| i == op_index)
                    && e.expected_matches.as_deref().is_some_and(|m| expected.contains(m))
            })
            .collect()
    }
}

/// Why `allowlist.toml` did not load. A missing file is no failure: it
/// loads as the empty allowlist.
#[derive(Debug)]
#[non_exhaustive]
pub enum AllowlistError {
    /// The file is there and could not be read.
    Read { path: PathBuf, source: io::Error },
    /// Line `line` (1-based) lies outside the format, as `problem` says.
    Syntax { line: usize, problem: String },
    /// The entry whose block ends near line `line` lacks its scenario, or a
    /// nonempty class or rationale.
    Incomplete { line: usize },
    /// The `scenario` on line `line` names no scenario key.
    NotAKey { line: usize, source: NotAScenarioKey },
    /// The entry whose block opens at line `line` declares a `count_delta`
    /// an earlier entry over one of the same ops declares differently.
    Conflict { line: usize },
}

impl fmt::Display for AllowlistError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AllowlistError::Read { path, .. } => write!(f, "cannot read {}", path.display()),
            AllowlistError::Syntax { line, problem } => {
                write!(f, "allowlist line {line}: {problem}")
            }
            AllowlistError::Incomplete { line } => write!(
                f,
                "allowlist entry ending near line {line}: scenario, class and rationale are \
                 required"
            ),
            AllowlistError::NotAKey { line, .. } => {
                write!(f, "allowlist line {line}: the scenario is no scenario key")
            }
            AllowlistError::Conflict { line } => write!(
                f,
                "allowlist entry at line {line}: an earlier entry over the same op declares \
                 another count_delta"
            ),
        }
    }
}

impl Error for AllowlistError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            AllowlistError::Read { source, .. } => Some(source),
            AllowlistError::NotAKey { source, .. } => Some(source),
            AllowlistError::Syntax { .. }
            | AllowlistError::Incomplete { .. }
            | AllowlistError::Conflict { .. } => None,
        }
    }
}

/// An entry as its `[[allow]]` block is read, from the line it opens at:
/// every key optional until [`finish`] requires the ones every entry
/// carries.
#[derive(Debug, Default)]
struct PartialEntry {
    line: usize,
    scenario: Option<ScenarioKey>,
    op_index: Option<usize>,
    class: Option<String>,
    rationale: Option<String>,
    count_delta: Option<i64>,
    width_tolerance: Option<u64>,
    expected_matches: Option<String>,
}

/// Parse the format. Unknown keys are a hard error — an entry that silently
/// half-applies would be a quiet comparator widening — and so is a key set
/// twice in one block, whose second value would silently move the entry to
/// another scenario or its ruling to another op, an empty signature, which
/// would cover every disagreement in its scope, and two entries over one op
/// declaring different count deltas, which would leave the delta applied to
/// the order the file lists them in.
pub fn load(path: &Path) -> Result<Allowlist, AllowlistError> {
    let raw = match fs::read_to_string(path) {
        Ok(r) => r,
        // A missing file is an empty allowlist, not an error: the seed file
        // ships with the repo, but the harness must not fail on a clean
        // checkout that lacks it. A file there that cannot be read is an
        // error — read as empty, it would turn every adjudicated divergence
        // into an unpermitted one.
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Allowlist::default()),
        Err(source) => return Err(AllowlistError::Read { path: path.to_path_buf(), source }),
    };
    let mut out = Allowlist::default();
    let mut cur: Option<PartialEntry> = None;
    for (ln, line) in raw.lines().enumerate() {
        let line_no = ln + 1;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "[[allow]]" {
            if let Some(e) = cur.take() {
                out.entries.push(finish(e, line_no)?);
            }
            cur = Some(PartialEntry { line: line_no, ..PartialEntry::default() });
            continue;
        }
        let syntax =
            |problem: &str| AllowlistError::Syntax { line: line_no, problem: problem.to_string() };
        let Some((k, v)) = line.split_once('=') else {
            return Err(syntax("expected `key = value`"));
        };
        let e = cur.as_mut().ok_or_else(|| syntax("key outside [[allow]] block"))?;
        let (k, v) = (k.trim(), v.trim());
        let quoted = |v: &str| -> Result<String, AllowlistError> {
            let v = v.strip_prefix('"').and_then(|x| x.strip_suffix('"'));
            v.map(str::to_string).ok_or_else(|| syntax("expected quoted string"))
        };
        let twice = || syntax(&format!("`{k}` set twice in one entry"));
        let not_an_integer = |_| syntax(&format!("{k} must be an integer"));
        match k {
            "scenario" => {
                let key = quoted(v)?
                    .parse()
                    .map_err(|source| AllowlistError::NotAKey { line: line_no, source })?;
                set_once(&mut e.scenario, key, twice)?;
            }
            "class" => set_once(&mut e.class, quoted(v)?, twice)?,
            "rationale" => set_once(&mut e.rationale, quoted(v)?, twice)?,
            "op_index" => set_once(&mut e.op_index, v.parse().map_err(not_an_integer)?, twice)?,
            "count_delta" => {
                set_once(&mut e.count_delta, v.parse().map_err(not_an_integer)?, twice)?
            }
            "width_tolerance" => {
                set_once(&mut e.width_tolerance, v.parse().map_err(not_an_integer)?, twice)?
            }
            "expected_matches" => {
                let signature = quoted(v)?;
                if signature.is_empty() {
                    return Err(syntax("empty expected_matches: it would cover every disagreement"));
                }
                set_once(&mut e.expected_matches, signature, twice)?;
            }
            other => return Err(syntax(&format!("unknown key `{other}`"))),
        }
    }
    if let Some(e) = cur.take() {
        out.entries.push(finish(e, raw.lines().count() + 1)?);
    }
    if let Some(line) = conflicting_delta(&out.entries) {
        return Err(AllowlistError::Conflict { line });
    }
    Ok(out)
}

/// The line of the first entry declaring a count delta that an earlier
/// entry over one of the same ops — of its scenario, with no op index or the
/// same one — declares differently; signature entries, which never adjust,
/// aside.
fn conflicting_delta(entries: &[Entry]) -> Option<usize> {
    let adjusting = |e: &&Entry| e.expected_matches.is_none();
    entries.iter().enumerate().filter(|(_, e)| adjusting(e)).find_map(|(k, later)| {
        let delta = later.count_delta?;
        let overlaps = |earlier: &&Entry| {
            earlier.scenario == later.scenario
                && (earlier.op_index.is_none()
                    || later.op_index.is_none()
                    || earlier.op_index == later.op_index)
        };
        entries[..k]
            .iter()
            .filter(adjusting)
            .filter(overlaps)
            .any(|earlier| earlier.count_delta.is_some_and(|d| d != delta))
            .then_some(later.line)
    })
}

/// `value` into the block's `slot` — once: a key set twice in one block is
/// the `twice` error, never a second value silently moving the entry to
/// another scenario or its ruling to another op.
fn set_once<T>(
    slot: &mut Option<T>,
    value: T,
    twice: impl FnOnce() -> AllowlistError,
) -> Result<(), AllowlistError> {
    if slot.is_some() {
        return Err(twice());
    }
    *slot = Some(value);
    Ok(())
}

/// The entry a block ending near `line` declares: its scenario, a nonempty
/// class and a nonempty rationale are required. The rationale is the file's
/// record of the ruling, for people to read; the entry keeps only what
/// classification uses.
fn finish(e: PartialEntry, line: usize) -> Result<Entry, AllowlistError> {
    let present = |s: Option<String>| s.filter(|s| !s.is_empty());
    let (Some(scenario), Some(class), Some(_rationale)) =
        (e.scenario, present(e.class), present(e.rationale))
    else {
        return Err(AllowlistError::Incomplete { line });
    };
    Ok(Entry {
        line: e.line,
        scenario,
        op_index: e.op_index,
        class,
        count_delta: e.count_delta,
        width_tolerance: e.width_tolerance,
        expected_matches: e.expected_matches,
    })
}

#[cfg(test)]
mod tests;
