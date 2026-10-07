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
//! names the classes covering the outcome.

use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::outcome::{NotAScenarioKey, OpOutcome, ScenarioKey, Status};

/// The adjustments the allowlist declares for one op's comparators,
/// resolved before the op runs from its non-signature entries: the widest
/// width tolerance any of them declares, and the first count delta.
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
/// class always present.
#[derive(Clone, Debug)]
struct Entry {
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
    /// value matches. An agreement is covered only when one of its
    /// comparators recorded that a declared adjustment made it — the entry's
    /// existence IS the adjudicated divergence. Every covering class is
    /// surfaced, so the ruling behind a verdict is auditable from the report
    /// alone.
    pub fn classify(
        &self,
        scenario: &ScenarioKey,
        op_index: usize,
        out: &OpOutcome,
    ) -> Option<String> {
        let disagreed = out.status == Status::Disagreed;
        let adjusted = out.status == Status::Agreed
            && out.adaptations.iter().any(|a| a == WIDTH_ADJUSTED || a == COUNT_ADJUSTED);
        let mut covering: Option<String> = None;
        if disagreed || adjusted {
            let mut classes: Vec<String> =
                self.op_entries(scenario, op_index).iter().map(|e| e.class.clone()).collect();
            classes.dedup();
            if !classes.is_empty() {
                covering = Some(classes.join("+"));
            }
        }
        if disagreed {
            let expected = out.disagreement.as_ref().map(|d| d.expected.as_str());
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
        }
    }
}

impl Error for AllowlistError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            AllowlistError::Read { source, .. } => Some(source),
            AllowlistError::NotAKey { source, .. } => Some(source),
            AllowlistError::Syntax { .. } | AllowlistError::Incomplete { .. } => None,
        }
    }
}

/// An entry as its `[[allow]]` block is read: every key optional until
/// [`finish`] requires the ones every entry carries.
#[derive(Debug, Default)]
struct PartialEntry {
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
/// another scenario or its ruling to another op, and an empty signature,
/// which would cover every disagreement in its scope.
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
            cur = Some(PartialEntry::default());
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
    Ok(out)
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
        scenario,
        op_index: e.op_index,
        class,
        count_delta: e.count_delta,
        width_tolerance: e.width_tolerance,
        expected_matches: e.expected_matches,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outcome::Disagreement;

    fn key(s: &str) -> ScenarioKey {
        s.parse().expect("a scenario key")
    }

    fn outcome(index: usize, status: Status, expected: Option<&str>) -> OpOutcome {
        let mut o = OpOutcome::new(index, "probe");
        o.status = status;
        o.disagreement =
            expected.map(|e| Disagreement { expected: e.to_string(), actual: "got".into() });
        o
    }

    /// A disagreement is covered by the entries matching its op and the
    /// signature entries its expected value matches — a signature entry's
    /// op index restricting it too; an agreement only when a comparator
    /// recorded that a declared adjustment made it. A signature entry
    /// adjusts nothing, whatever it declares.
    #[test]
    fn an_entry_classifies_disagreements_and_only_the_agreements_an_adjustment_made() {
        let s = key("cat/s");
        let signature = |op_index: Option<usize>, class: &str| Entry {
            scenario: s.clone(),
            op_index,
            class: class.into(),
            count_delta: Some(2),
            width_tolerance: Some(5),
            expected_matches: Some("(\"0\"".into()),
        };
        let tolerated = Entry {
            scenario: s.clone(),
            op_index: Some(1),
            class: "tolerated".into(),
            count_delta: None,
            width_tolerance: Some(1),
            expected_matches: None,
        };
        let allow = Allowlist {
            entries: vec![tolerated, signature(None, "shape"), signature(Some(5), "elsewhere")],
        };
        let declared = Adjustments { width_tolerance: 1, count_delta: 0 };
        assert_eq!(allow.adjustments(&s, 1), declared);
        assert_eq!(allow.adjustments(&s, 2), Adjustments::default());

        let mut agreed = outcome(1, Status::Agreed, None);
        assert_eq!(allow.classify(&s, 1, &agreed), None, "no adjustment made this agreement");
        agreed.adaptations.push(WIDTH_ADJUSTED.into());
        assert_eq!(allow.classify(&s, 1, &agreed).as_deref(), Some("tolerated"));
        let mut counted = outcome(1, Status::Agreed, None);
        counted.adaptations.push(COUNT_ADJUSTED.into());
        assert_eq!(allow.classify(&s, 1, &counted).as_deref(), Some("tolerated"));

        let shaped = outcome(2, Status::Disagreed, Some("[(\"0\", \"0.1\")]"));
        assert_eq!(allow.classify(&s, 2, &shaped).as_deref(), Some("shape"));
        let other = outcome(2, Status::Disagreed, Some("[(\"1.1\", \"0.3\")]"));
        assert_eq!(allow.classify(&s, 2, &other), None);
        let both = outcome(1, Status::Disagreed, Some("(\"0\""));
        assert_eq!(allow.classify(&s, 1, &both).as_deref(), Some("tolerated+shape"));
        assert_eq!(allow.classify(&key("cat/t"), 1, &both), None, "entries are per scenario");
    }

    /// An entry names its scenario by key: a bare name — which two goldens
    /// can share — is refused on the line that wrote it, never left to match
    /// nothing; and an entry without its class or rationale is incomplete.
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
        fs::write(&path, "[[allow]]\nscenario = \"cat/s\"\nclass = \"c\"\n").expect("an allowlist");
        let unruled = load(&path).err();
        fs::remove_dir_all(&dir).expect("the scratch directory is removed");
        assert_eq!(keyed.ok(), Some(key("discovery/find_documents_basic")));
        assert!(matches!(bare, Some(AllowlistError::NotAKey { line: 2, .. })), "{bare:?}");
        assert!(matches!(unruled, Some(AllowlistError::Incomplete { .. })), "{unruled:?}");
    }

    /// A missing allowlist is the empty one; an allowlist that is there and
    /// cannot be read is an error, never read as empty.
    #[test]
    fn only_a_missing_allowlist_loads_empty() {
        let dir = std::env::temp_dir().join(format!("skep-allowlist-read-{}", std::process::id()));
        fs::create_dir_all(&dir).expect("a scratch directory");
        let missing = load(&dir.join("absent.toml")).map(|a| a.entries.len());
        let unreadable = load(&dir).err();
        fs::remove_dir_all(&dir).expect("the scratch directory is removed");
        assert_eq!(missing.ok(), Some(0));
        assert!(matches!(unreadable, Some(AllowlistError::Read { .. })), "{unreadable:?}");
    }

    /// The format refuses what it does not speak, each refusal at its line:
    /// an unknown key — a misspelled adjustment would otherwise widen a
    /// comparator unseen — a key outside a block, an unquoted string, a key
    /// set twice in one block, whose second value would move the ruling,
    /// and an empty signature, which every expected value contains; an
    /// empty class leaves its entry incomplete.
    #[test]
    fn a_line_outside_the_format_is_refused() {
        let scratch = format!("skep-allowlist-format-{}", std::process::id());
        let dir = std::env::temp_dir().join(scratch);
        fs::create_dir_all(&dir).expect("a scratch directory");
        let path = dir.join("allowlist.toml");
        let refusal = |text: &str| {
            fs::write(&path, text).expect("an allowlist");
            load(&path).err()
        };
        let entry = "[[allow]]\nscenario = \"cat/s\"\nclass = \"c\"\nrationale = \"r\"\n";
        let misspelled = refusal(&format!("{entry}widht_tolerance = 1\n"));
        let outside = refusal("class = \"c\"\n");
        let unquoted = refusal("[[allow]]\nscenario = cat/s\n");
        let unclassed = refusal("[[allow]]\nscenario = \"cat/s\"\nclass = \"\"\nrationale = \"r\"");
        let moved = refusal(&format!("{entry}op_index = 2\nop_index = 7\n"));
        let unsigned = refusal(&format!("{entry}expected_matches = \"\"\n"));
        fs::remove_dir_all(&dir).expect("the scratch directory is removed");
        let syntax_at = |line: usize, key: &'static str| {
            move |e: &AllowlistError| match e {
                AllowlistError::Syntax { line: l, problem } => *l == line && problem.contains(key),
                _ => false,
            }
        };
        assert!(misspelled.as_ref().is_some_and(syntax_at(5, "widht_tolerance")), "{misspelled:?}");
        assert!(matches!(outside, Some(AllowlistError::Syntax { line: 1, .. })), "{outside:?}");
        assert!(matches!(unquoted, Some(AllowlistError::Syntax { line: 2, .. })), "{unquoted:?}");
        assert!(matches!(unclassed, Some(AllowlistError::Incomplete { .. })), "{unclassed:?}");
        assert!(moved.as_ref().is_some_and(syntax_at(6, "op_index")), "{moved:?}");
        assert!(unsigned.as_ref().is_some_and(syntax_at(5, "expected_matches")), "{unsigned:?}");
    }
}
