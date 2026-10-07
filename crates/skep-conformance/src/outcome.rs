//! Per-op outcomes and per-scenario verdicts — the record shapes the report
//! serializes — and a scenario's identity, the key every adjudication names
//! it by.

use std::error::Error;
use std::fmt;
use std::str::FromStr;

/// A scenario's identity: `category/name`, its golden's directory and its
/// name. The key the allowlist and the ratchet name a scenario by, and the
/// one the report prints; a bare name is no identity — the corpus carries
/// two `find_documents_basic`, one under discovery/ and one under identity/.
/// Text becomes a key only through [`FromStr`], which refuses anything but
/// a nonempty category and a nonempty, slash-free name.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScenarioKey(String);

impl ScenarioKey {
    /// The key of the golden scenario `name` under `category`.
    pub(crate) fn of(category: &str, name: &str) -> ScenarioKey {
        ScenarioKey(format!("{category}/{name}"))
    }

    /// The key as text, `category/name`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ScenarioKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The key as its text: a key is its `category/name`, and a list of keys
/// reads as the list of names it is.
impl fmt::Debug for ScenarioKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl FromStr for ScenarioKey {
    type Err = NotAScenarioKey;

    fn from_str(s: &str) -> Result<ScenarioKey, NotAScenarioKey> {
        let keyed = s
            .split_once('/')
            .is_some_and(|(cat, name)| !cat.is_empty() && !name.is_empty() && !name.contains('/'));
        if keyed {
            Ok(ScenarioKey(s.to_string()))
        } else {
            Err(NotAScenarioKey(s.to_string()))
        }
    }
}

/// Text that names no scenario: it is no `category/name` key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotAScenarioKey(String);

impl fmt::Display for NotAScenarioKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "`{}` is no `category/name` key", self.0)
    }
}

impl Error for NotAScenarioKey {}

/// What happened to one golden operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Status {
    /// Executed, compared, and every comparison agreed.
    Agreed,
    /// Executed; the recording kept nothing to compare — a pure write, or a
    /// read whose recording holds no answer. A read whose recording holds an
    /// answer it cannot reach is `Inexpressible` instead, never this.
    NotCompared,
    /// Meta/diagnostic op — executed nothing, compared nothing.
    Meta,
    /// Part of what the golden records has no expression on skep's surface
    /// — the op itself, a part it names, or the answer its recording keeps.
    /// The reason is recorded; never silently skipped.
    Inexpressible,
    /// Executed and at least one comparison disagreed (or an α-finding
    /// surfaced on this op).
    Disagreed,
}

impl Status {
    /// The status as the report spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Agreed => "agreed",
            Status::NotCompared => "not-compared",
            Status::Meta => "meta",
            Status::Inexpressible => "inexpressible",
            Status::Disagreed => "disagreed",
        }
    }
}

/// A comparison's disagreement: what the golden recorded against what skep
/// answered, each rendered — skep's side through the bijection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Disagreement {
    /// The golden side, rendered.
    pub expected: String,
    /// skep's side, rendered through the bijection.
    pub actual: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpOutcome {
    pub index: usize,
    /// The op's name: the golden's `op` field (`fields::op_name`).
    pub op_name: String,
    /// Canonical verb the op's name normalized to ("?" when none).
    pub verb: &'static str,
    pub status: Status,
    /// Which comparator judged this op, when one ran.
    pub comparator: Option<&'static str>,
    /// Named adaptation policies applied while the op played, in order.
    pub adaptations: Vec<String>,
    /// The disagreement a comparator rendered, when one did.
    pub disagreement: Option<Disagreement>,
    /// Inexpressibility reason / α-finding kinds / free-form evidence.
    pub note: Option<String>,
    /// The allowlist class or classes covering this outcome
    /// (`Allowlist::classify`), if any.
    pub allowlisted: Option<String>,
}

impl OpOutcome {
    pub fn new(index: usize, op_name: &str) -> OpOutcome {
        OpOutcome {
            index,
            op_name: op_name.to_string(),
            verb: "?",
            status: Status::NotCompared,
            comparator: None,
            adaptations: Vec::new(),
            disagreement: None,
            note: None,
            allowlisted: None,
        }
    }

    /// A disagreement no allowlist entry covers — the runner's divergent
    /// verdict, and the summary's listing of what an inexpressible verdict
    /// would otherwise hide.
    pub fn is_unadjudicated(&self) -> bool {
        self.status == Status::Disagreed && self.allowlisted.is_none()
    }

    /// The op compared, and `comparator` matched every comparison.
    pub fn agree(&mut self, comparator: &'static str) {
        self.status = Status::Agreed;
        self.comparator = Some(comparator);
    }

    /// The op compared, and `comparator` found the disagreement `d`.
    pub fn disagree(&mut self, comparator: &'static str, d: Disagreement) {
        self.status = Status::Disagreed;
        self.comparator = Some(comparator);
        self.disagreement = Some(d);
    }

    /// The op names a golden address α never bound — skep never made it, or
    /// nothing the recording did bound it — so nothing reached skep: a
    /// disagreement the α comparator owns, `note` its evidence beside the
    /// `alpha-never-bound` finding the runner folds in.
    pub fn never_bound(&mut self, note: String) {
        self.status = Status::Disagreed;
        self.comparator = Some("alpha");
        self.add_note(note);
    }

    /// Append evidence to the op's note, after what it already says.
    pub fn add_note(&mut self, note: String) {
        self.note = Some(match self.note.take() {
            Some(n) => format!("{n}; {note}"),
            None => note,
        });
    }

    /// One line saying what went wrong on this op: expected and actual when
    /// a comparator rendered a disagreement, else the note.
    pub fn detail(&self) -> String {
        match (&self.disagreement, &self.note) {
            (Some(d), _) => format!("expected {} / actual {}", d.expected, d.actual),
            (None, Some(n)) => n.clone(),
            (None, None) => String::from("(no detail)"),
        }
    }
}

/// Exactly one per scenario.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Verdict {
    Pass,
    Allowlisted,
    Divergent,
    Inexpressible,
    /// The HARNESS itself failed (a panic, or a rig that would not
    /// bootstrap) — a harness bug, not a finding.
    Error,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Pass => "pass",
            Verdict::Allowlisted => "allowlisted",
            Verdict::Divergent => "divergent",
            Verdict::Inexpressible => "inexpressible",
            Verdict::Error => "error",
        }
    }
}

/// The op a reader of a scenario's record looks at first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    /// The op's index in the scenario.
    pub index: usize,
    /// The op's name (`OpOutcome::op_name`).
    pub op_name: String,
    /// What went wrong on it, in one line (`OpOutcome::detail`).
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScenarioRecord {
    pub category: String,
    pub name: String,
    pub verdict: Verdict,
    pub bijection_size: usize,
    pub ops: Vec<OpOutcome>,
    /// The first inexpressible op or unadjudicated disagreement, else the
    /// first adjudicated disagreement; `None` when no op disagreed or was
    /// inexpressible.
    pub first_finding: Option<Finding>,
    /// Populated only on `Verdict::Error` — the panic payload.
    pub error: Option<String>,
    /// Grounding-pre-pass inferences applied before op 0 (implied creates,
    /// derived initial content, expansion plans) — auditable per scenario.
    pub groundings: Vec<String>,
}

impl ScenarioRecord {
    /// The scenario's identity ([`ScenarioKey`]).
    pub fn key(&self) -> ScenarioKey {
        ScenarioKey::of(&self.category, &self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A key is `category/name` exactly: text parses into one only with a
    /// nonempty category and a nonempty, slash-free name, and reads back as
    /// the text it was.
    #[test]
    fn a_key_is_a_category_and_a_name() {
        let key: ScenarioKey = "discovery/find_documents_basic".parse().expect("a key");
        assert_eq!(key, ScenarioKey::of("discovery", "find_documents_basic"));
        assert_eq!(key.to_string(), "discovery/find_documents_basic");
        assert_eq!(format!("{:?}", [key]), r#"["discovery/find_documents_basic"]"#);
        for bare in ["find_documents_basic", "/name", "category/", "a/b/c"] {
            assert_eq!(bare.parse::<ScenarioKey>(), Err(NotAScenarioKey(bare.to_string())));
        }
    }
}
