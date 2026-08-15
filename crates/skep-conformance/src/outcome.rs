//! Per-op outcomes and per-scenario verdicts — the record shapes the report
//! serializes.

/// What happened to one golden operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    /// Executed and every comparison agreed.
    Agreed,
    /// Executed; the op carries no expected value to compare (pure writes).
    NotCompared,
    /// Meta/diagnostic label — executed nothing, compared nothing.
    Meta,
    /// Could not be translated to skep's surface; the label and reason are
    /// recorded. Never silently skipped.
    Inexpressible,
    /// Executed and at least one comparison disagreed (or an α-finding
    /// surfaced on this op).
    Disagreed,
}

#[derive(Clone, Debug)]
pub struct OpOutcome {
    pub index: usize,
    pub label: String,
    /// Canonical verb the label normalized to ("?" when none).
    pub verb: String,
    pub status: Status,
    /// Which comparator judged this op, when one ran.
    pub comparator: Option<String>,
    /// Named adaptation policies applied during translation, in order.
    pub adaptations: Vec<String>,
    /// Rendered expected value (golden side) on disagreement.
    pub expected: Option<String>,
    /// Rendered actual value (skep side, through the bijection) on
    /// disagreement.
    pub actual: Option<String>,
    /// Inexpressibility reason / α-finding classes / free-form evidence.
    pub note: Option<String>,
    /// Allowlist class granted to this disagreement, if any.
    pub allowlisted: Option<String>,
}

impl OpOutcome {
    pub fn new(index: usize, label: &str) -> OpOutcome {
        OpOutcome {
            index,
            label: label.to_string(),
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
}

/// Exactly one per scenario.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    Allowlisted,
    Divergent,
    Inexpressible,
    /// The HARNESS itself failed (panic / translation crash) — a harness
    /// bug, not a finding.
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
    /// First failing op (index, label, detail), if any.
    pub first_failure: Option<(usize, String, String)>,
    /// Populated only on `Verdict::Error` — the panic payload.
    pub error: Option<String>,
    /// Grounding-pre-pass inferences applied before op 0 (implied creates,
    /// derived initial content, expansion plans) — auditable per scenario.
    pub groundings: Vec<String>,
}
