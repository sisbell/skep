//! The α-bijection — golden tumbler strings ⇄ skep `Address`es, compared up
//! to consistent renaming, never literally: udanax's node field, allocation
//! order, and granfilade gaps differ from skep's genesis and gap-free
//! frontier by design.
//!
//! Three α-failures are findings, each of its own [`FindingKind`]:
//! * `alpha-double-bind-golden` — a golden address that would bind to two
//!   different skep addresses;
//! * `alpha-never-bound` — a reference to a never-bound address;
//! * `alpha-double-bind-skep` — a skep address bound to two golden ones.

use std::collections::BTreeMap;

use skep_address::{document_of, validate, Address, Level, Nat, Tumbler};

use crate::tum::parse_dotted;

/// The kind of one α-failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FindingKind {
    /// A golden address that would bind to two different skep addresses.
    DoubleBindGolden,
    /// A reference to a never-bound golden address.
    NeverBound,
    /// A skep address bound to two golden ones.
    DoubleBindSkep,
}

impl FindingKind {
    /// The kind as the report names it.
    pub fn as_str(self) -> &'static str {
        match self {
            FindingKind::DoubleBindGolden => "alpha-double-bind-golden",
            FindingKind::NeverBound => "alpha-never-bound",
            FindingKind::DoubleBindSkep => "alpha-double-bind-skep",
        }
    }
}

/// One recorded α-failure (a finding, not a panic).
#[derive(Clone, Debug)]
pub struct AlphaFinding {
    pub kind: FindingKind,
    pub detail: String,
}

#[derive(Debug, Default)]
pub struct Alpha {
    /// golden dotted string → skep address.
    fwd: BTreeMap<String, Address>,
    /// skep address → golden dotted string.
    rev: BTreeMap<Address, String>,
    /// Findings since the runner last drained them ([`Alpha::drain_findings`]).
    findings: Vec<AlphaFinding>,
}

impl Alpha {
    pub fn new() -> Alpha {
        Alpha::default()
    }

    pub fn len(&self) -> usize {
        self.fwd.len()
    }

    /// The findings recorded since the last drain, oldest first — the runner
    /// folds them into the op they arose on.
    pub fn drain_findings(&mut self) -> impl Iterator<Item = AlphaFinding> + '_ {
        self.findings.drain(..)
    }

    /// Bind golden→skep. Re-binding the same pair is a no-op (open_document
    /// legitimately re-yields an already-bound address); a conflicting bind
    /// on either side is recorded as a finding and the FIRST binding wins
    /// (deterministic, and the conflict itself is the evidence).
    pub fn bind(&mut self, golden: &str, skep: &Address) {
        if let Some(prev) = self.fwd.get(golden) {
            if prev != skep {
                self.findings.push(AlphaFinding {
                    kind: FindingKind::DoubleBindGolden,
                    detail: format!("golden {golden} already ↦ {prev}, now offered {skep}"),
                });
            }
            return;
        }
        if let Some(prev_golden) = self.rev.get(skep) {
            if prev_golden != golden {
                self.findings.push(AlphaFinding {
                    kind: FindingKind::DoubleBindSkep,
                    detail: format!(
                        "skep {skep} already ↦ golden {prev_golden}, now offered {golden}"
                    ),
                });
                return;
            }
        }
        self.fwd.insert(golden.to_string(), skep.clone());
        self.rev.insert(skep.clone(), golden.to_string());
    }

    /// Translate a golden address through the map. Exact hit first; else the
    /// element lift: golden `docid·0·⟨subspace, ordinal⟩` ↦
    /// `α(docid)·0·⟨subspace, ordinal⟩`, the docid bound to a skep DOCUMENT
    /// (both systems place elements at `doc·0·⟨subspace, ordinal⟩`, so the
    /// local part carries over structurally). A miss is recorded as an
    /// `alpha-never-bound` finding.
    pub fn translate(&mut self, golden: &str) -> Option<Address> {
        if let Some(a) = self.peek_translate(golden) {
            return Some(a);
        }
        if parse_dotted(golden).is_some() {
            self.findings.push(AlphaFinding {
                kind: FindingKind::NeverBound,
                detail: format!("reference to never-bound golden address {golden}"),
            });
        }
        None
    }

    /// [`Alpha::translate`] without the finding on a miss — for the
    /// comparators' opportunistic-binding pass, where absence is the signal
    /// that a result-carried address is bindable, not an error yet.
    pub fn peek_translate(&self, golden: &str) -> Option<Address> {
        if let Some(a) = self.fwd.get(golden) {
            return Some(a.clone());
        }
        // The element lift. The ⟨subspace, ordinal⟩ pair after the last
        // separator is nonzero, and the prefix's image must be a DOCUMENT: a
        // version address (`account·0·doc·version`) carries the same nonzero
        // pair after its account, so without the level guard a golden
        // version skep never minted would lift through the bound account
        // into a document slot of the rig's own account instead of
        // surfacing as a never-bound finding.
        let comps = parse_dotted(golden)?;
        let [prefix @ .., 0, sub, ord] = comps.as_slice() else { return None };
        if prefix.is_empty() || *sub == 0 || *ord == 0 {
            return None;
        }
        let key = prefix.iter().map(u64::to_string).collect::<Vec<_>>().join(".");
        let base = self.fwd.get(&key).filter(|b| b.level() == Level::Document)?;
        let local = [0, *sub, *ord].map(Nat::from);
        let lifted = Tumbler::new(base.tumbler().iter().cloned().chain(local)).ok()?;
        validate(lifted).ok()
    }

    /// Peek without recording a finding (used where absence is an answer).
    pub fn peek(&self, golden: &str) -> Option<Address> {
        self.fwd.get(golden).cloned()
    }

    /// Is this skep address already bound to some golden address?
    pub fn is_bound_skep(&self, a: &Address) -> bool {
        self.rev.contains_key(a)
    }

    /// Render a skep address for the report: its golden address when bound,
    /// else the REVERSE of the element lift — a skep ELEMENT
    /// `docid·0·⟨subspace, ordinal⟩` whose docid is bound renders as
    /// `golden(docid)·0·⟨subspace, ordinal⟩` (a skep-side address
    /// reverse-translates through the bijection before it reaches a
    /// comparison or the report; only a truly foreign address renders
    /// `skep:<dotted>`). The reverse runs only from an element, the image of
    /// the forward lift; a document-level address under a bound account is a
    /// document no golden names.
    pub fn render_skep(&self, a: &Address) -> String {
        if let Some(g) = self.rev.get(a) {
            return g.clone();
        }
        // Only an element carries an element field.
        if let (Some([sub, ord]), Some(doc)) = (a.element_field(), document_of(a)) {
            if let Some(g) = self.rev.get(&doc) {
                return format!("{g}.0.{sub}.{ord}");
            }
        }
        format!("skep:{a}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tum::addr;

    fn a(comps: &[u64]) -> Address {
        addr(comps).expect("a valid address")
    }

    /// The element lift goes through a bound DOCUMENT only. A golden version
    /// address carries the same ⟨nonzero, nonzero⟩ tail after its account
    /// that an element carries after its document: it surfaces as
    /// never-bound instead of lifting into a document slot of the rig's
    /// account, and the reverse renders such a skep document as foreign.
    #[test]
    fn the_element_lift_goes_through_documents_only() {
        let mut alpha = Alpha::new();
        alpha.bind("1.1.0.1", &a(&[1, 0, 1]));
        alpha.bind("1.1.0.1.0.1", &a(&[1, 0, 1, 0, 3]));

        assert_eq!(alpha.translate("1.1.0.1.0.1.0.2.1"), Some(a(&[1, 0, 1, 0, 3, 0, 2, 1])));
        assert_eq!(alpha.drain_findings().count(), 0);
        assert_eq!(alpha.translate("1.1.0.1.0.1.1"), None, "a never-minted version");
        let found: Vec<FindingKind> = alpha.drain_findings().map(|f| f.kind).collect();
        assert_eq!(found, [FindingKind::NeverBound]);
        assert_eq!(alpha.drain_findings().count(), 0, "a drain empties the findings");

        assert_eq!(alpha.render_skep(&a(&[1, 0, 1, 0, 3, 0, 2, 1])), "1.1.0.1.0.1.0.2.1");
        assert_eq!(alpha.render_skep(&a(&[1, 0, 1, 0, 1, 1])), "skep:1.0.1.0.1.1");
    }

    /// Re-binding the same pair is no finding; a conflicting bind on either
    /// side is a finding of its own kind, and the first binding stands on
    /// both sides.
    #[test]
    fn a_double_bind_is_a_finding_and_the_first_binding_stands() {
        let mut alpha = Alpha::new();
        alpha.bind("1.1.0.1.0.1", &a(&[1, 0, 1, 0, 3]));
        alpha.bind("1.1.0.1.0.1", &a(&[1, 0, 1, 0, 3]));
        alpha.bind("1.1.0.1.0.1", &a(&[1, 0, 1, 0, 4]));
        alpha.bind("1.1.0.1.0.2", &a(&[1, 0, 1, 0, 3]));
        let found: Vec<FindingKind> = alpha.drain_findings().map(|f| f.kind).collect();
        assert_eq!(found, [FindingKind::DoubleBindGolden, FindingKind::DoubleBindSkep]);
        assert_eq!(alpha.peek("1.1.0.1.0.1"), Some(a(&[1, 0, 1, 0, 3])));
        assert!(!alpha.is_bound_skep(&a(&[1, 0, 1, 0, 4])));
        assert_eq!(alpha.peek("1.1.0.1.0.2"), None);
        assert_eq!(alpha.render_skep(&a(&[1, 0, 1, 0, 3])), "1.1.0.1.0.1");
    }
}
