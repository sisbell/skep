//! The α-bijection — golden tumbler strings ⇄ skep `Address`es, compared up
//! to consistent renaming, never literally: udanax's node field, allocation
//! order, and granfilade gaps differ from skep's genesis and gap-free
//! frontier by design.
//!
//! Three α-failures are findings, each of its own kind:
//! * `alpha-double-bind-golden` — a golden address that would bind to two
//!   different skep addresses;
//! * `alpha-never-bound` — a reference to a never-bound address;
//! * `alpha-double-bind-skep` — a skep address bound to two golden ones.

use std::collections::BTreeMap;

use skep_address::{Address, Level};

use crate::tum::{addr_str, parse_dotted};

/// One recorded α-failure (a finding, not a panic).
#[derive(Clone, Debug)]
pub struct AlphaFinding {
    /// `alpha-double-bind-golden` | `alpha-never-bound` | `alpha-double-bind-skep`.
    pub kind: &'static str,
    pub detail: String,
}

pub struct Alpha {
    /// golden dotted string → skep address.
    fwd: BTreeMap<String, Address>,
    /// skep dotted string → golden dotted string.
    rev: BTreeMap<String, String>,
    /// Findings accumulated over the scenario (drained into op outcomes).
    pub findings: Vec<AlphaFinding>,
}

impl Default for Alpha {
    fn default() -> Self {
        Alpha::new()
    }
}

impl Alpha {
    pub fn new() -> Alpha {
        Alpha { fwd: BTreeMap::new(), rev: BTreeMap::new(), findings: Vec::new() }
    }

    pub fn len(&self) -> usize {
        self.fwd.len()
    }

    /// Bind golden→skep. Re-binding the same pair is a no-op (open_document
    /// legitimately re-yields an already-bound address); a conflicting bind
    /// on either side is recorded as a finding and the FIRST binding wins
    /// (deterministic, and the conflict itself is the evidence).
    pub fn bind(&mut self, golden: &str, skep: &Address) {
        let sk = addr_str(skep);
        if let Some(prev) = self.fwd.get(golden) {
            if addr_str(prev) != sk {
                self.findings.push(AlphaFinding {
                    kind: "alpha-double-bind-golden",
                    detail: format!(
                        "golden {golden} already ↦ {}, now offered {sk}",
                        addr_str(prev)
                    ),
                });
            }
            return;
        }
        if let Some(prev_golden) = self.rev.get(&sk) {
            if prev_golden != golden {
                self.findings.push(AlphaFinding {
                    kind: "alpha-double-bind-skep",
                    detail: format!("skep {sk} already ↦ golden {prev_golden}, now offered {golden}"),
                });
                return;
            }
        }
        self.fwd.insert(golden.to_string(), skep.clone());
        self.rev.insert(sk, golden.to_string());
    }

    /// Translate a golden address through the map. Exact hit first; else the
    /// longest bound DOCUMENT prefix such that the remainder begins with a
    /// zero separator — the element/sub-space lift: golden `docid·0·local` ↦
    /// `α(docid)·0·local` (both systems place elements at `doc·0·⟨subspace,
    /// ordinal⟩`, so the local part carries over structurally). A miss is
    /// recorded as an `alpha-never-bound` finding.
    pub fn translate(&mut self, golden: &str) -> Option<Address> {
        if let Some(a) = self.peek_translate(golden) {
            return Some(a);
        }
        if parse_dotted(golden).is_some() {
            self.findings.push(AlphaFinding {
                kind: "alpha-never-bound",
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
        let comps = parse_dotted(golden)?;
        // Longest bound docid prefix with a zero separator right after it.
        // The remainder must be a plausible ⟨subspace, ordinal⟩ local pair,
        // and the prefix's image must be a DOCUMENT: a version address
        // (`account·0·doc·version`) carries the same nonzero pair after its
        // account, so without the level guard a golden version skep never
        // minted would lift through the bound account into a document slot
        // of the rig's own account instead of surfacing as a never-bound
        // finding.
        for cut in (1..comps.len()).rev() {
            if comps[cut] != 0 {
                continue;
            }
            let local = &comps[cut + 1..];
            if local.len() != 2 || local[0] == 0 || local[1] == 0 {
                continue;
            }
            let prefix: Vec<String> = comps[..cut].iter().map(|c| c.to_string()).collect();
            let key = prefix.join(".");
            let Some(base) = self.fwd.get(&key).filter(|b| b.level() == Level::Document) else {
                continue;
            };
            let mut out: Vec<skep_address::Nat> = base.tumbler().iter().cloned().collect();
            out.push(skep_address::Nat::from(0u64));
            for c in local {
                out.push(skep_address::Nat::from(*c));
            }
            let lifted = skep_address::Tumbler::new(out).ok()?;
            return skep_address::validate(lifted).ok();
        }
        None
    }

    /// Peek without recording a finding (used where absence is an answer).
    pub fn peek(&self, golden: &str) -> Option<Address> {
        self.fwd.get(golden).cloned()
    }

    /// Is this skep address already bound to some golden address?
    pub fn is_bound_skep(&self, a: &Address) -> bool {
        self.rev.contains_key(&addr_str(a))
    }

    /// Render a skep address for the report: its golden address when bound,
    /// else the REVERSE of the element lift — a skep ELEMENT `docid·0·local`
    /// whose docid is rev-bound renders as `golden(docid)·0·local` (round-5
    /// item: a skep-side address must reverse-translate through the
    /// bijection before it reaches a comparison or the report; only a truly
    /// foreign address renders `skep:<dotted>`). The reverse runs only from
    /// an element, the image of the forward lift; a document-level address
    /// under a bound account is a document no golden names.
    pub fn render_skep(&self, a: &Address) -> String {
        let s = addr_str(a);
        if let Some(g) = self.rev.get(&s) {
            return g.clone();
        }
        if a.level() != Level::Element {
            return format!("skep:{s}");
        }
        let comps: Vec<u64> = a
            .tumbler()
            .iter()
            .map(|c| c.to_string().parse().unwrap_or(0))
            .collect();
        for cut in (1..comps.len()).rev() {
            if comps[cut] != 0 {
                continue;
            }
            let local = &comps[cut + 1..];
            if local.len() != 2 || local[0] == 0 || local[1] == 0 {
                continue;
            }
            let prefix: Vec<String> = comps[..cut].iter().map(|c| c.to_string()).collect();
            if let Some(g) = self.rev.get(&prefix.join(".")) {
                return format!("{g}.0.{}.{}", local[0], local[1]);
            }
        }
        format!("skep:{s}")
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
        assert!(alpha.findings.is_empty());
        assert_eq!(alpha.translate("1.1.0.1.0.1.1"), None, "a never-minted version");
        assert_eq!(alpha.findings.len(), 1);
        assert_eq!(alpha.findings[0].kind, "alpha-never-bound");

        assert_eq!(alpha.render_skep(&a(&[1, 0, 1, 0, 3, 0, 2, 1])), "1.1.0.1.0.1.0.2.1");
        assert_eq!(alpha.render_skep(&a(&[1, 0, 1, 0, 1, 1])), "skep:1.0.1.0.1.1");
    }
}
