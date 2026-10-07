//! Per-op outcomes and per-scenario verdicts — the record shapes the report
//! serializes — and a scenario's identity, the key every adjudication names
//! it by.

use std::error::Error;
use std::fmt;
use std::str::FromStr;

/// A scenario's identity: `category/name`, its golden's directory and its name.
/// The key the allowlist and the ratchet name a scenario by, and the one the
/// report prints; a bare name is no identity — the corpus carries two
/// `find_documents_basic`, one under discovery/ and one under identity/. Both
/// parts are nonempty and slash-free, whichever way a key is made — from its
/// parts (`ScenarioKey::from_parts`) or from text ([`FromStr`]) — so every
/// key's text reads back, through [`FromStr`], as the very same key: a key an
/// adjudication file can name.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScenarioKey(String);

/// Can `part` be a key's category or name: nonempty, and slash-free?
fn is_key_part(part: &str) -> bool {
    !part.is_empty() && !part.contains('/')
}

impl ScenarioKey {
    /// The key of the golden scenario `name` under `category`, when both are
    /// nonempty and slash-free; `None` for parts no key is made of.
    pub(crate) fn from_parts(category: &str, name: &str) -> Option<ScenarioKey> {
        (is_key_part(category) && is_key_part(name))
            .then(|| ScenarioKey(format!("{category}/{name}")))
    }

    /// The key of the golden scenario `name` under `category`. The caller
    /// owes nonempty, slash-free parts: the loader refuses a golden whose
    /// name forms no key (`LoadError::BadName`), so a scenario that breaks
    /// this was built by hand, wrongly, and is stopped here rather than
    /// carrying a key no adjudication could name.
    pub(crate) fn of(category: &str, name: &str) -> ScenarioKey {
        ScenarioKey::from_parts(category, name).unwrap_or_else(|| {
            panic!(
                "a scenario key is a nonempty, slash-free category and name: \
                 `{category}`, `{name}`"
            )
        })
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
        s.split_once('/')
            .and_then(|(category, name)| ScenarioKey::from_parts(category, name))
            .ok_or_else(|| NotAScenarioKey(s.to_string()))
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
    /// At least one comparison disagreed; or the op named a golden address
    /// α never bound, so its request never reached skep
    /// ([`OpOutcome::never_bound`]); or an α-finding surfaced on it.
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

/// One golden operation's outcome. A disagreement, once recorded, stands:
/// `disagreement` is set only on an op whose status is
/// [`Status::Disagreed`], and nothing settles a disagreed op as agreed —
/// [`OpOutcome::agree`] refuses an op already disagreed or inexpressible.
/// Code that writes `status` directly owes the same.
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

    /// The op compared, and `comparator` matched every comparison. The
    /// caller owes an op not yet disagreed or inexpressible: an agreement
    /// settled over one is a harness bug, stopped here.
    pub fn agree(&mut self, comparator: &'static str) {
        assert!(
            !matches!(self.status, Status::Disagreed | Status::Inexpressible),
            "op {} `{}` is {} already: no comparison settles it as agreed",
            self.index,
            self.op_name,
            self.status.as_str()
        );
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
    /// disagreement the α comparator owns, `note` its evidence. The caller
    /// owes that its `Alpha::translate` of that address missed on this op,
    /// which recorded the `alpha-never-bound` finding the runner folds in
    /// beside the note (a translate of text that is no address misses with
    /// no finding).
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

/// A scenario's verdict: exactly one per scenario, the first of these that
/// holds, in this order —
///
/// 1. [`Verdict::Error`] — the scenario was not played to its end;
/// 2. [`Verdict::Inexpressible`] — some op is inexpressible, whatever else
///    disagrees;
/// 3. [`Verdict::Divergent`] — some op disagrees and no allowlist entry
///    covers it;
/// 4. [`Verdict::Allowlisted`] — some op's outcome an allowlist entry covers:
///    a disagreement, or an agreement a declared adjustment made;
/// 5. [`Verdict::Pass`] — otherwise.
///
/// [`Verdict::of`] folds a played scenario's outcomes by rules 2–5; the
/// runner records `Error` for a scenario it could not play to its end.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Verdict {
    /// Nothing disagreed, nothing was inexpressible, no entry was needed.
    Pass,
    /// Every disagreement, and every agreement an adjustment made, is
    /// covered by an allowlist entry.
    Allowlisted,
    /// A disagreement no allowlist entry covers.
    Divergent,
    /// Some op, or part of one, has no expression on skep's surface.
    Inexpressible,
    /// The scenario could not be played to its end: a panic stopped it —
    /// the harness's own (a harness bug), or skep's while executing a
    /// request (its operation surface failing to answer every request it is
    /// handed, M10's totality) — or the rig would not bootstrap. No
    /// allowlist entry or ratchet line can admit it; `error` names what
    /// stopped it and, for a stopped op, which.
    Error,
}

impl Verdict {
    /// The verdict of a scenario played to its end, `outcomes` its ops'
    /// outcomes: the first of rules 2–5 of [`Verdict`]'s order that holds.
    pub fn of(outcomes: &[OpOutcome]) -> Verdict {
        if outcomes.iter().any(|o| o.status == Status::Inexpressible) {
            Verdict::Inexpressible
        } else if outcomes.iter().any(OpOutcome::is_unadjudicated) {
            Verdict::Divergent
        } else if outcomes.iter().any(|o| o.allowlisted.is_some()) {
            Verdict::Allowlisted
        } else {
            Verdict::Pass
        }
    }

    /// The verdict as the report spells it.
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
    /// The op a panic stopped the scenario at, with who panicked; else the
    /// first inexpressible op or unadjudicated disagreement, else the first
    /// adjudicated disagreement; `None` when no op disagreed, was
    /// inexpressible, or was stopped.
    pub first_finding: Option<Finding>,
    /// Populated only on `Verdict::Error`: what stopped the scenario — a
    /// panic, naming who raised it and, inside an op, which op — or the
    /// rig's bootstrap failure.
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

    /// A key is made only of a nonempty, slash-free category and name, from
    /// parts as from text — so every key's text reads back as itself.
    #[test]
    fn every_key_reads_back_as_itself() {
        let key = ScenarioKey::from_parts("cat", "name").expect("a key");
        assert_eq!(key.as_str().parse::<ScenarioKey>(), Ok(key));
        for (category, name) in [("cat", "a/b"), ("cat", ""), ("", "name"), ("a/b", "c")] {
            assert_eq!(ScenarioKey::from_parts(category, name), None, "{category:?}, {name:?}");
        }
    }

    /// A scenario whose parts form no key is a harness bug, stopped where
    /// its key is made.
    #[test]
    #[should_panic(expected = "a scenario key is a nonempty, slash-free category and name")]
    fn a_key_of_parts_forming_none_is_refused() {
        ScenarioKey::of("cat", "a/b");
    }

    fn outcome(status: Status, allowlisted: Option<&str>) -> OpOutcome {
        let mut o = OpOutcome::new(0, "op");
        o.status = status;
        o.allowlisted = allowlisted.map(str::to_string);
        o
    }

    /// A played scenario's verdict is the first of the order's rules that
    /// holds: inexpressible over every disagreement, an uncovered
    /// disagreement over every covered one, a covered outcome over a pass.
    #[test]
    fn a_verdict_is_the_first_rule_that_holds() {
        use Status::{Agreed, Disagreed, Inexpressible, NotCompared};
        let uncovered = outcome(Disagreed, None);
        let covered = outcome(Disagreed, Some("ruled"));
        let adjusted = outcome(Agreed, Some("ruled"));
        let lost = outcome(Inexpressible, None);
        let played = |ops: &[&OpOutcome]| {
            Verdict::of(&ops.iter().map(|o| (*o).clone()).collect::<Vec<_>>())
        };
        assert_eq!(played(&[&covered, &uncovered, &lost]), Verdict::Inexpressible);
        assert_eq!(played(&[&covered, &uncovered]), Verdict::Divergent);
        assert_eq!(played(&[&covered, &outcome(Agreed, None)]), Verdict::Allowlisted);
        assert_eq!(played(&[&adjusted]), Verdict::Allowlisted);
        assert_eq!(played(&[&outcome(Agreed, None), &outcome(NotCompared, None)]), Verdict::Pass);
        assert_eq!(played(&[]), Verdict::Pass);
    }

    /// A disagreement, once recorded, stands: settling the op as agreed is
    /// a harness bug, stopped where it is made.
    #[test]
    #[should_panic(expected = "op 0 `op` is disagreed already")]
    fn an_agreement_never_settles_a_disagreed_op() {
        let mut o = OpOutcome::new(0, "op");
        o.disagree("content", Disagreement { expected: "A".into(), actual: "B".into() });
        o.agree("content");
    }
}
