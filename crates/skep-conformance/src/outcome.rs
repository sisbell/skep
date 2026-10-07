//! Per-op outcomes and per-scenario verdicts — the record shapes the report
//! serializes — and a scenario's identity, the key every adjudication names
//! it by.

/// A scenario's identity: `category/name`, its golden's directory and its
/// name. The key the allowlist and the ratchet name a scenario by, and the
/// one the report prints; a bare name is no identity — the corpus carries
/// two `find_documents_basic`, one under discovery/ and one under identity/.
pub fn scenario_key(category: &str, name: &str) -> String {
    format!("{category}/{name}")
}

/// What happened to one golden operation.
#[derive(Clone, Debug, PartialEq, Eq)]
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

#[derive(Clone, Debug)]
pub struct OpOutcome {
    pub index: usize,
    /// The op's name: the golden's `op` field (`fields::op_name`).
    pub op_name: String,
    /// Canonical verb the op's name normalized to ("?" when none).
    pub verb: String,
    pub status: Status,
    /// Which comparator judged this op, when one ran.
    pub comparator: Option<String>,
    /// Named adaptation policies applied while the op played, in order.
    pub adaptations: Vec<String>,
    /// Rendered expected value (golden side) on disagreement.
    pub expected: Option<String>,
    /// Rendered actual value (skep side, through the bijection) on
    /// disagreement.
    pub actual: Option<String>,
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
            verb: "?".to_string(),
            status: Status::NotCompared,
            comparator: None,
            adaptations: Vec::new(),
            expected: None,
            actual: None,
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
    pub fn agree(&mut self, comparator: &str) {
        self.status = Status::Agreed;
        self.comparator = Some(comparator.to_string());
    }

    /// The op compared, and `comparator` found `actual` where the golden
    /// recorded `expected`.
    pub fn disagree(&mut self, comparator: &str, expected: String, actual: String) {
        self.status = Status::Disagreed;
        self.comparator = Some(comparator.to_string());
        self.expected = Some(expected);
        self.actual = Some(actual);
    }

    /// The op names a golden address α never bound — skep never made it, or
    /// nothing the recording did bound it — so nothing reached skep: a
    /// disagreement the α comparator owns, `note` its evidence beside the
    /// `alpha-never-bound` finding the runner folds in.
    pub fn never_bound(&mut self, note: String) {
        self.status = Status::Disagreed;
        self.comparator = Some("alpha".to_string());
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
    /// a comparator rendered both, else the note.
    pub fn detail(&self) -> String {
        match (&self.expected, &self.actual, &self.note) {
            (Some(e), Some(a), _) => format!("expected {e} / actual {a}"),
            (_, _, Some(n)) => n.clone(),
            _ => String::from("(no detail)"),
        }
    }
}

/// Exactly one per scenario.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

pub struct ScenarioRecord {
    pub category: String,
    pub name: String,
    pub verdict: Verdict,
    pub bijection_size: usize,
    pub ops: Vec<OpOutcome>,
    /// The first inexpressible op or unadjudicated disagreement, else the
    /// first adjudicated disagreement — (index, op name, detail); `None`
    /// when no op disagreed or was inexpressible.
    pub first_finding: Option<(usize, String, String)>,
    /// Populated only on `Verdict::Error` — the panic payload.
    pub error: Option<String>,
    /// Grounding-pre-pass inferences applied before op 0 (implied creates,
    /// derived initial content, expansion plans) — auditable per scenario.
    pub groundings: Vec<String>,
}

impl ScenarioRecord {
    /// The scenario's identity ([`scenario_key`]).
    pub fn key(&self) -> String {
        scenario_key(&self.category, &self.name)
    }
}
