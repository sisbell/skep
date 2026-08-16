//! The α-bijection — golden tumbler strings ⇄ skep `Address`es, compared up
//! to consistent renaming, never literally: udanax's node field, allocation
//! order, and granfilade gaps differ from skep's genesis and gap-free
//! frontier by design.
//!
//! Three α-failures are findings, each with its own report class:
//! * `alpha-double-bind-golden` — a golden address that would bind to two
//!   different skep addresses;
//! * `alpha-never-bound` — a reference to a never-bound address;
//! * `alpha-double-bind-skep` — a skep address bound to two golden ones.

use std::collections::BTreeMap;

use skep_address::Address;

use crate::tum::{addr_str, parse_dotted};

/// One recorded α-failure (a finding, not a panic).
#[derive(Clone, Debug)]
pub struct AlphaFinding {
    /// `alpha-double-bind-golden` | `alpha-never-bound` | `alpha-double-bind-skep`.
    pub class: &'static str,
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

    pub fn is_empty(&self) -> bool {
        self.fwd.is_empty()
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
                    class: "alpha-double-bind-golden",
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
                    class: "alpha-double-bind-skep",
                    detail: format!("skep {sk} already ↦ golden {prev_golden}, now offered {golden}"),
                });
                return;
            }
        }
        self.fwd.insert(golden.to_string(), skep.clone());
        self.rev.insert(sk, golden.to_string());
    }

    /// Translate a golden address through the map. Exact hit first; else the
    /// longest bound prefix `p` such that the remainder begins with a zero
    /// separator — the element/sub-space lift: golden `docid·0·local` ↦
    /// `α(docid)·0·local` (both systems place elements at `doc·0·⟨subspace,
    /// ordinal⟩`, so the local part carries over structurally). A miss is
    /// recorded as an `alpha-never-bound` finding.
    pub fn translate(&mut self, golden: &str) -> Option<Address> {
        if let Some(a) = self.peek_translate(golden) {
            return Some(a);
        }
        if parse_dotted(golden).is_some() {
            self.findings.push(AlphaFinding {
                class: "alpha-never-bound",
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
        // The remainder must be a plausible ⟨subspace, ordinal⟩ local pair —
        // without that guard, an element of an UNBOUND document would lift
        // through the bound account prefix into a wrong skep address instead
        // of surfacing as a never-bound finding.
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
            if let Some(base) = self.fwd.get(&key) {
                let mut out: Vec<skep_address::Nat> = base.tumbler().comps_vec();
                out.push(skep_address::Nat::from(0u64));
                for c in &comps[cut + 1..] {
                    out.push(skep_address::Nat::from(*c));
                }
                let lifted = skep_address::Tumbler::new(out).ok()?;
                return skep_address::validate(lifted).ok();
            }
        }
        None
    }

    /// Peek without recording a finding (used where absence is an answer).
    pub fn peek(&self, golden: &str) -> Option<Address> {
        self.fwd.get(golden).cloned()
    }

    /// Is this skep address already bound to some golden name?
    pub fn is_bound_skep(&self, a: &Address) -> bool {
        self.rev.contains_key(&addr_str(a))
    }

    /// Render a skep address for the report: its golden name when bound,
    /// else the REVERSE of the element lift — a skep `docid·0·local` whose
    /// docid is rev-bound renders as `golden(docid)·0·local` (round-5 item:
    /// a skep-side address must reverse-translate through the bijection
    /// before it reaches a comparison or the report; only a truly foreign
    /// address renders `skep:<dotted>`).
    pub fn render_skep(&self, a: &Address) -> String {
        let s = addr_str(a);
        if let Some(g) = self.rev.get(&s) {
            return g.clone();
        }
        let comps: Vec<u64> = (1..=a.tumbler().len())
            .map(|i| a.tumbler().get(i).to_string().parse().unwrap_or(0))
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

/// Extension used by [`Alpha::translate`]: clone a tumbler's components.
trait CompsVec {
    fn comps_vec(&self) -> Vec<skep_address::Nat>;
}

impl CompsVec for skep_address::Tumbler {
    fn comps_vec(&self) -> Vec<skep_address::Nat> {
        (1..=self.len()).map(|i| self.get(i).clone()).collect()
    }
}

/// Convenience: parse-or-None used by doc-reference resolution — an address
/// string is anything that parses fully as dotted decimal.
pub fn looks_like_address(s: &str) -> bool {
    parse_dotted(s).is_some()
}
