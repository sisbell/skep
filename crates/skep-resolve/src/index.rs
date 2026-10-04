//! THE DERIVED INDEX LAYER (REG-3.21 to REG-3.26; R5 (h), (j), (k)) — the
//! POSITION-ANNOTATED prefix → binding index, a MIRROR-LOCAL derived index
//! over the `/changes` feed the mirror already consumes: a client-side
//! structure and never a substrate feature, invisible to the wire and owed
//! no op. Its failure mode is slowness, never a wrong answer.
//!
//! "RESOLVE P" IS A DERIVATION (REG-3.24): the prefix rides the binding's
//! ATOM, so a reader without this index reads the atom of every candidate
//! binding on the board. The index reads each atom ONCE, at the build, and
//! never at the resolve. Its rebuild is a re-read of the feed at the
//! deposits' own positions (REG-3.25), which the mirror performs over its
//! own copy ([`crate::mirror`]).
//!
//! MEMBERSHIP IS THE RULE'S OWN TEST, the binding walk on the AUDIT view
//! (REG-2.8 to REG-2.11, REG-2.14; R2 (b), (g)) with the REPLAY CLAUSE
//! (REG-2.24): the registrar's bindings for a prefix are walked in journal
//! order, the FIRST is the allocation, and a later binding REPLACES it only
//! where it names the SAME account (a restoration) or NO account (a
//! retirement) AND names in `replaces` the binding CURRENT for that prefix at
//! its own position — the latest that STOOD, read on the audit view; a later
//! binding naming a DIFFERENT account for a held prefix is INERT (a double
//! allocation), as is one naming a state no longer current, a first binding
//! that names a state where the empty one is current, and the second of two
//! records naming one predecessor. An inert binding stands in the history
//! and moves no state. A retraction clears nothing: the view is the AUDIT
//! view, so a `nullify` of a binding is no input here.
//!
//! THE ENDPOINT'S CURRENCY (REG-1.10, REG-1.11) is read on the ACTIVE view:
//! a deposit is HONORED where its `replaces` names the deposit current in
//! that doc 1 at its own position — the latest that STOOD, nullified or not
//! — or names none where none has stood; the CURRENT endpoint is the latest
//! honored deposit still on the active view, the org's own `nullify` taking
//! a deposit off it and the one before it then standing.
//!
//! Every entry here passed the verify ([`crate::verify`]): a record whose
//! verdict is not SIGNED is suppressed from the index and counted
//! ([`Index::suppressed`]), never consulted at a resolve (rm-2).

use std::collections::BTreeMap;

use skep_address::{is_prefix, Address};
use skep_registry::BodyKind;

use crate::state::{BindingRecord, EndpointRecord, Judged, Standing};

/// Why a record was kept out of the index (rm-2): its verdict, or no record
/// at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cause {
    /// The bytes are no record of the slot's kind under the canonical rule.
    Malformed(skep_registry::Refusal),
    /// The verdict is UNSIGNED: no `sig`, a `sig` of no row's width, or a
    /// signer outside the home's set as of the position.
    Unsigned,
    /// The verdict is UNDETERMINABLE HERE: the bytes, the board term or the
    /// set as of the position could not be read.
    UndeterminableHere,
}

/// One suppressed record: its link's position and address, the kind its
/// slot named, and the cause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suppressed {
    pub position: u64,
    pub link: Address,
    pub kind: BodyKind,
    pub cause: Cause,
}

/// One prefix's bindings in journal order, and which of them the walk
/// honors.
#[derive(Debug, Clone, Default)]
struct PrefixEntries {
    entries: Vec<Judged<BindingRecord>>,
    honored: Vec<usize>,
}

/// Where a link's record stands in the index, for the retraction's lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Place {
    Binding(Address),
    Endpoint(Address),
}

/// The counts a build reports.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    pub prefixes: usize,
    pub bindings: usize,
    pub honored_bindings: usize,
    pub endpoints: usize,
    pub honored_endpoints: usize,
    pub suppressed_malformed: usize,
    pub suppressed_unsigned: usize,
    pub suppressed_undeterminable: usize,
}

/// The position-annotated prefix → binding index, with the endpoint
/// deposits per doc 1 beside it.
///
/// Its write side — the two folds, `nullify`, `suppress` — is this crate's
/// alone (rm-2): a dependent can fold nothing into an index, so every entry
/// of one it holds was folded by a mirror, after the verify. The twin builds
/// and reads everything the refusal below it does; the refusal's one
/// difference is the fold. (The `E0624` code is checked on nightly only,
/// which is why the twin rather than the annotation carries the weight.)
///
/// ```
/// use skep_resolve::{parse_address, BindingRecord, Index, Judged, Verdict};
/// let a = |s: &str| parse_address(s).unwrap();
/// let index = Index::default();
/// let unsigned = Judged {
///     position: 1,
///     link: a("1.0.1.0.1.0.2.1"),
///     home: a("1.0.1.0.1"),
///     record: BindingRecord { prefix: a("1.5"), account: Some(a("1.0.2")), replaces: None, honored: false },
///     verdict: Verdict::Unsigned,
/// };
/// assert!(index.standing(&unsigned.record.prefix).is_none());
/// ```
/// ```compile_fail,E0624
/// use skep_resolve::{parse_address, BindingRecord, Index, Judged, Verdict};
/// let a = |s: &str| parse_address(s).unwrap();
/// let mut index = Index::default();
/// let unsigned = Judged {
///     position: 1,
///     link: a("1.0.1.0.1.0.2.1"),
///     home: a("1.0.1.0.1"),
///     record: BindingRecord { prefix: a("1.5"), account: Some(a("1.0.2")), replaces: None, honored: false },
///     verdict: Verdict::Unsigned,
/// };
/// index.fold_binding(unsigned);
/// ```
#[derive(Debug, Clone, Default)]
pub struct Index {
    prefixes: BTreeMap<Address, PrefixEntries>,
    endpoints: BTreeMap<Address, Vec<Judged<EndpointRecord>>>,
    places: BTreeMap<Address, Place>,
    /// Every record kept out, in journal order.
    pub suppressed: Vec<Suppressed>,
}

impl Index {
    pub(crate) fn new() -> Index {
        Index::default()
    }

    /// Fold one VERIFIED binding at its position (REG-2.8 to REG-2.11;
    /// REG-2.24): the entry joins the prefix's history, honored or inert by
    /// the rule the module doc states; answers whether it was honored. Rows
    /// arrive in journal order — the fold's one precondition.
    pub(crate) fn fold_binding(&mut self, mut judged: Judged<BindingRecord>) -> bool {
        let prefix = judged.record.prefix.clone();
        let entries = self.prefixes.entry(prefix.clone()).or_default();
        let honored = match entries.honored.last() {
            // THE FIRST RECORD OF A KEY NAMES THE EMPTY STATE, by the member's
            // absence: an allocation.
            None => judged.record.replaces.is_none(),
            Some(&last) => {
                let stood = &entries.entries[last];
                let allocation = &entries.entries[entries.honored[0]].record.account;
                let names_current = judged.record.replaces.as_ref() == Some(&stood.link);
                let same_or_none = judged.record.account.is_none() || judged.record.account == *allocation;
                names_current && same_or_none
            }
        };
        judged.record.honored = honored;
        self.places.insert(judged.link.clone(), Place::Binding(prefix));
        entries.entries.push(judged);
        if honored {
            entries.honored.push(entries.entries.len() - 1);
        }
        honored
    }

    /// Fold one VERIFIED endpoint deposit at its position (REG-1.10): honored
    /// where `replaces` names the latest deposit that STOOD in its doc 1, or
    /// none where none has; answers whether it was honored.
    pub(crate) fn fold_endpoint(&mut self, mut judged: Judged<EndpointRecord>) -> bool {
        let deposits = self.endpoints.entry(judged.home.clone()).or_default();
        let last_stood = deposits.iter().rev().find(|d| d.record.honored).map(|d| &d.link);
        let honored = match last_stood {
            None => judged.record.replaces.is_none(),
            Some(link) => judged.record.replaces.as_ref() == Some(link),
        };
        judged.record.honored = honored;
        self.places.insert(judged.link.clone(), Place::Endpoint(judged.home.clone()));
        deposits.push(judged);
        honored
    }

    /// A `nullify` of `link` (REG-1.11): an endpoint deposit leaves the
    /// active view — answers `true`; a binding's link is read on the AUDIT
    /// view, so the retraction clears nothing (REG-2.14) and this answers
    /// `false`, as it does for a link the index does not hold.
    pub(crate) fn nullify(&mut self, link: &Address) -> bool {
        match self.places.get(link) {
            Some(Place::Endpoint(home)) => {
                let home = home.clone();
                if let Some(d) = self.endpoints.get_mut(&home).and_then(|ds| ds.iter_mut().find(|d| d.link == *link)) {
                    d.record.nullified = true;
                    return true;
                }
                false
            }
            Some(Place::Binding(_)) | None => false,
        }
    }

    /// The prefix's STANDING: the binding the walk holds current and the
    /// whole history, where any verified binding names the prefix.
    pub fn standing(&self, prefix: &Address) -> Option<Standing> {
        let entries = self.prefixes.get(prefix)?;
        let current = entries.entries[*entries.honored.last()?].clone();
        Some(Standing { prefix: prefix.clone(), current, history: entries.entries.clone() })
    }

    /// The longest PROPER prefix of `prefix` that a verified binding names —
    /// the parent a depth address's walk reaches (REG-3.82).
    pub fn longest_bound_prefix(&self, prefix: &Address) -> Option<Address> {
        self.prefixes
            .keys()
            .filter(|bound| **bound != *prefix && is_prefix(bound.tumbler(), prefix.tumbler()))
            .max_by_key(|bound| bound.tumbler().len())
            .cloned()
    }

    /// Every endpoint deposit in `home`, in journal order.
    pub fn endpoints(&self, home: &Address) -> &[Judged<EndpointRecord>] {
        self.endpoints.get(home).map(Vec::as_slice).unwrap_or(&[])
    }

    /// The CURRENT endpoint of `home` (REG-1.10, REG-1.11): the latest
    /// honored deposit still on the active view.
    pub fn current_endpoint(&self, home: &Address) -> Option<&Judged<EndpointRecord>> {
        self.endpoints(home).iter().rev().find(|d| d.record.honored && !d.record.nullified)
    }

    /// Whether any honored deposit ever stood in `home`.
    pub fn any_honored_endpoint(&self, home: &Address) -> bool {
        self.endpoints(home).iter().any(|d| d.record.honored)
    }

    /// Every prefix a verified binding names, in address order.
    pub fn prefixes(&self) -> impl Iterator<Item = &Address> {
        self.prefixes.keys()
    }

    /// Every verified binding of every prefix, in address then journal
    /// order.
    pub fn bindings(&self) -> impl Iterator<Item = &Judged<BindingRecord>> {
        self.prefixes.values().flat_map(|p| p.entries.iter())
    }

    /// Every verified endpoint deposit of every home.
    pub fn all_endpoints(&self) -> impl Iterator<Item = &Judged<EndpointRecord>> {
        self.endpoints.values().flat_map(|d| d.iter())
    }

    /// Keep a record out of the index, by cause.
    pub(crate) fn suppress(&mut self, suppressed: Suppressed) {
        self.suppressed.push(suppressed);
    }

    /// The counts.
    pub fn counts(&self) -> Counts {
        let mut c = Counts { prefixes: self.prefixes.len(), ..Counts::default() };
        for p in self.prefixes.values() {
            c.bindings += p.entries.len();
            c.honored_bindings += p.honored.len();
        }
        for d in self.endpoints.values() {
            c.endpoints += d.len();
            c.honored_endpoints += d.iter().filter(|e| e.record.honored).count();
        }
        for s in &self.suppressed {
            match s.cause {
                Cause::Malformed(_) => c.suppressed_malformed += 1,
                Cause::Unsigned => c.suppressed_unsigned += 1,
                Cause::UndeterminableHere => c.suppressed_undeterminable += 1,
            }
        }
        c
    }
}

#[cfg(test)]
mod tests {
    use skep_identity::Fingerprint;

    use super::*;
    use crate::parse_address;
    use crate::state::Verdict;

    fn a(s: &str) -> Address {
        parse_address(s).unwrap()
    }

    fn signed() -> Verdict {
        Verdict::Signed(Fingerprint::parse_hex(&"ab".repeat(32)).unwrap())
    }

    fn binding(at: u64, link: &str, prefix: &str, account: Option<&str>, replaces: Option<&str>) -> Judged<BindingRecord> {
        Judged {
            position: at,
            link: a(link),
            home: a("1.0.1.0.1"),
            record: BindingRecord {
                prefix: a(prefix),
                account: account.map(a),
                replaces: replaces.map(a),
                honored: false,
            },
            verdict: signed(),
        }
    }

    fn endpoint(at: u64, link: &str, home: &str, replaces: Option<&str>) -> Judged<EndpointRecord> {
        Judged {
            position: at,
            link: a(link),
            home: a(home),
            record: EndpointRecord { origins: vec![format!("https://{at}.example")], replaces: replaces.map(a), honored: false, nullified: false },
            verdict: signed(),
        }
    }

    /// THE REPLAY MATRIX at the binding walk (REG-2.9, REG-2.10, REG-2.24):
    /// the allocation; a double allocation inert; a same-account binding
    /// naming a stale state inert; the restoration naming the current state
    /// honored; a retirement honored; a first binding carrying `replaces`
    /// inert; a retraction clearing nothing.
    #[test]
    fn the_binding_walk_honors_by_the_replay_clause() {
        let mut index = Index::new();
        let l = |n: u32| format!("1.0.1.0.1.0.2.{n}");
        assert!(index.fold_binding(binding(10, &l(1), "1.5", Some("1.0.2"), None)), "the allocation");
        assert!(!index.fold_binding(binding(11, &l(2), "1.5", Some("1.0.3"), None)), "a double allocation is inert");
        assert!(!index.fold_binding(binding(12, &l(3), "1.5", Some("1.0.3"), Some(&l(1)))), "a different account is inert even naming the current state");
        assert!(!index.fold_binding(binding(13, &l(4), "1.5", Some("1.0.2"), Some(&l(2)))), "a stale state is inert");
        assert!(index.fold_binding(binding(14, &l(5), "1.5", Some("1.0.2"), Some(&l(1)))), "the restoration naming the current state is honored");
        assert!(!index.fold_binding(binding(15, &l(6), "1.5", Some("1.0.2"), Some(&l(1)))), "the second record naming one predecessor is inert");
        assert!(index.fold_binding(binding(16, &l(7), "1.5", None, Some(&l(5)))), "a retirement naming the current state is honored");
        assert!(index.fold_binding(binding(17, &l(8), "1.5", Some("1.0.2"), Some(&l(7)))), "a restoration after the retirement");
        assert!(!index.fold_binding(binding(18, &l(9), "1.6", Some("1.0.4"), Some(&l(1)))), "a first binding naming a state is inert: the empty state is current");
        assert!(index.fold_binding(binding(19, &l(10), "1.6", Some("1.0.4"), None)));
        let s = index.standing(&a("1.5")).expect("bound");
        assert_eq!(s.current.link, a(&l(8)));
        assert_eq!(s.history.len(), 8);
        assert_eq!(s.history.iter().filter(|b| b.record.honored).count(), 4);
        assert!(!index.nullify(&a(&l(8))), "a retraction of a binding clears nothing");
        assert_eq!(index.standing(&a("1.5")).unwrap().current.link, a(&l(8)));
        assert_eq!(index.standing(&a("1.7")), None);
        assert_eq!(index.longest_bound_prefix(&a("1.5.3")), Some(a("1.5")));
        assert_eq!(index.longest_bound_prefix(&a("1.5")), None, "a proper prefix alone");
        assert_eq!(index.longest_bound_prefix(&a("1.8.1")), None);
        assert_eq!(index.counts().honored_bindings, 5);
    }

    /// THE ENDPOINT'S CURRENCY (REG-1.10, REG-1.11): the first deposit, a
    /// second naming it current, a third naming the first inert, the
    /// nullified second leaving the view and the first standing, and the
    /// org's next deposit naming the nullified one honored.
    #[test]
    fn the_endpoint_current_is_the_latest_honored_on_the_active_view() {
        let mut index = Index::new();
        let home = "1.0.2.0.1";
        let l = |n: u32| format!("1.0.2.0.1.0.2.{n}");
        assert!(index.fold_endpoint(endpoint(20, &l(1), home, None)));
        assert!(index.fold_endpoint(endpoint(21, &l(2), home, Some(&l(1)))));
        assert!(!index.fold_endpoint(endpoint(22, &l(3), home, Some(&l(1)))), "a stale state is inert");
        assert!(!index.fold_endpoint(endpoint(23, &l(4), home, None)), "a first-form deposit where one has stood is inert");
        assert_eq!(index.current_endpoint(&a(home)).map(|d| d.position), Some(21));
        assert!(index.nullify(&a(&l(2))), "the org's own nullify is effective");
        assert_eq!(index.current_endpoint(&a(home)).map(|d| d.position), Some(20), "the one before it stands");
        assert!(index.fold_endpoint(endpoint(24, &l(5), home, Some(&l(2)))), "the next deposit names the nullified one");
        assert_eq!(index.current_endpoint(&a(home)).map(|d| d.position), Some(24));
        assert!(index.nullify(&a(&l(5))) && index.nullify(&a(&l(1))));
        assert_eq!(index.current_endpoint(&a(home)), None, "every honored deposit nullified");
        assert!(index.any_honored_endpoint(&a(home)));
        assert!(!index.nullify(&a("1.0.9.0.1.0.2.1")), "a link the index does not hold");
        assert_eq!(index.counts().honored_endpoints, 3);
    }
}
