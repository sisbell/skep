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
//! TWO ELEMENTS, one job each. THE LEDGER ([`Ledger`]) applies the rules
//! below to whatever it is handed, and promises nothing about the records it
//! holds — neither their verdicts nor their homes. THE INDEX ([`Index`]) is
//! the VERIFIED register: a ledger whose one writer is the gate, the
//! mirror's fold, beside the records the gate kept out. The guest-reading
//! resolve, which judges no record, folds into a ledger of its own and never
//! into an index.
//!
//! MEMBERSHIP IS THE RULE'S OWN TEST, the binding walk on the AUDIT view
//! (REG-2.8 to REG-2.11, REG-2.14; R2 (b), (g)) with the REPLAY CLAUSE
//! (REG-2.24): a prefix's bindings are walked in journal order, the FIRST is
//! the allocation, and a later binding REPLACES it only where it names the
//! SAME account (a restoration) or NO account (a retirement) AND names in
//! `replaces` the binding CURRENT for that prefix at its own position — the
//! latest that STOOD, read on the audit view; a later binding naming a
//! DIFFERENT account for a held prefix is INERT (a double allocation), as is
//! one naming a state no longer current, a first binding that names a state
//! where the empty one is current, and the second of two records naming one
//! predecessor. An inert binding stands in the history and moves no state. A
//! retraction clears nothing: the view is the AUDIT view, so a `nullify` of
//! a binding is no input here.
//!
//! THE ENDPOINT'S CURRENCY (REG-1.10, REG-1.11) is read on the ACTIVE view:
//! a deposit is HONORED where its `replaces` names the deposit current in
//! that doc 1 at its own position — the latest that STOOD, nullified or not
//! — or names none where none has stood; the CURRENT endpoint is the latest
//! honored deposit still on the active view, the org's own `nullify` taking
//! a deposit off it and the one before it then standing.

use std::collections::BTreeMap;

use skep_address::{is_prefix, Address};
use skep_registry::BodyKind;

use crate::state::{BindingRecord, EndpointRecord, Judged, Standing, Verdict};

/// Why a record was kept out of the index (rm-2): no record of the slot's
/// kind at all, or its VERDICT — any of the five but SIGNED, the one that
/// admits it — carried as judged and never re-worded.
///
/// Where several hold, one speaks, in the order the gate meets them: bytes
/// this reader cannot read — no atom named, no account over the home, no
/// bytes fetched — are UNDETERMINABLE HERE before any rule is asked; then
/// the canonical rule, whose refusal is [`Cause::Malformed`]; then the
/// verdict, a record being judged only once it parses. What the canonical
/// rule admits is not judged again: a record's address members are the
/// addresses they name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cause {
    /// The bytes are no record of the slot's kind under the canonical rule.
    Malformed(skep_registry::ParseRefusal),
    /// The record's verdict, any but SIGNED.
    Verdict(Verdict),
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
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Bindings {
    entries: Vec<Judged<BindingRecord>>,
    honored: Vec<usize>,
}

/// One doc 1's endpoint deposits in journal order, and the latest of them
/// that STOOD — honored, nullified or not — the one a later deposit's
/// `replaces` must name (REG-1.10): kept, so a deposit is folded without a
/// walk back over the ones before it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Deposits {
    entries: Vec<Judged<EndpointRecord>>,
    last_stood: Option<usize>,
}

/// Where a link's record stands in the ledger, for the retraction's lookup:
/// a binding's prefix, or an endpoint deposit's home and the index it was
/// first folded at among that home's deposits, which never move — so a link
/// handed twice is retracted where it stood, never at the inert copy beside
/// it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Place {
    Binding(Address),
    Endpoint(Address, usize),
}

/// The counts a build reports: the ledger's prefixes, bindings and deposits,
/// each total and honored, and the records the gate kept out — malformed,
/// and one count per verdict but SIGNED.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Counts {
    pub prefixes: usize,
    pub bindings: usize,
    pub honored_bindings: usize,
    pub endpoints: usize,
    pub honored_endpoints: usize,
    pub suppressed_malformed: usize,
    pub suppressed_unsigned: usize,
    pub suppressed_undeterminable: usize,
    pub suppressed_before_attestation: usize,
    pub suppressed_disavowed: usize,
}

/// THE LEDGER: the prefix → binding walk and the endpoint deposits per doc
/// 1, under the rules the module doc states — the rules alone. It checks no
/// verdict and no home: it holds what its writer handed it, in the order
/// handed, which must be journal order — the folds' one precondition.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Ledger {
    prefixes: BTreeMap<Address, Bindings>,
    endpoints: BTreeMap<Address, Deposits>,
    places: BTreeMap<Address, Place>,
}

impl Ledger {
    /// Fold one binding at its position (REG-2.8 to REG-2.11; REG-2.24): the
    /// entry joins the prefix's history, honored or inert by the rule the
    /// module doc states; answers whether it was honored.
    pub(crate) fn fold_binding(&mut self, mut judged: Judged<BindingRecord>) -> bool {
        let prefix = judged.record.prefix.clone();
        let bindings = self.prefixes.entry(prefix.clone()).or_default();
        let honored = match bindings.honored.last() {
            // THE FIRST RECORD OF A KEY NAMES THE EMPTY STATE, by the member's
            // absence: an allocation.
            None => judged.record.replaces.is_none(),
            Some(&last) => {
                let stood = &bindings.entries[last];
                let allocated = &bindings.entries[bindings.honored[0]].record.account;
                let names_current = judged.record.replaces.as_ref() == Some(&stood.link);
                let same_or_none = judged.record.account.is_none() || judged.record.account == *allocated;
                names_current && same_or_none
            }
        };
        judged.record.honored = honored;
        self.places.insert(judged.link.clone(), Place::Binding(prefix));
        bindings.entries.push(judged);
        if honored {
            bindings.honored.push(bindings.entries.len() - 1);
        }
        honored
    }

    /// Fold one endpoint deposit at its position (REG-1.10): honored where
    /// `replaces` names the latest deposit that STOOD in its doc 1, or none
    /// where none has; answers whether it was honored.
    pub(crate) fn fold_endpoint(&mut self, mut judged: Judged<EndpointRecord>) -> bool {
        let deposits = self.endpoints.entry(judged.home.clone()).or_default();
        let honored = match deposits.last_stood {
            None => judged.record.replaces.is_none(),
            Some(last) => judged.record.replaces.as_ref() == Some(&deposits.entries[last].link),
        };
        judged.record.honored = honored;
        let index = deposits.entries.len();
        self.places.entry(judged.link.clone()).or_insert(Place::Endpoint(judged.home.clone(), index));
        deposits.entries.push(judged);
        if honored {
            deposits.last_stood = Some(index);
        }
        honored
    }

    /// A `nullify` of `link` (REG-1.11): an endpoint deposit leaves the
    /// active view — answers `true`; a binding's link is read on the AUDIT
    /// view, so the retraction clears nothing (REG-2.14) and this answers
    /// `false`, as it does for a link the ledger does not hold.
    pub(crate) fn nullify(&mut self, link: &Address) -> bool {
        let Some(Place::Endpoint(home, index)) = self.places.get(link) else { return false };
        match self.endpoints.get_mut(home).and_then(|d| d.entries.get_mut(*index)) {
            Some(deposit) => {
                deposit.record.nullified = true;
                true
            }
            None => false,
        }
    }

    /// The prefix's STANDING: the binding the walk holds current and the
    /// whole history, where an honored binding names the prefix.
    pub(crate) fn standing(&self, prefix: &Address) -> Option<Standing> {
        let bindings = self.prefixes.get(prefix)?;
        let current = bindings.entries[*bindings.honored.last()?].clone();
        Some(Standing { prefix: prefix.clone(), current, history: bindings.entries.clone() })
    }

    /// THE PARENT PREFIX a depth address's walk reaches (REG-3.80,
    /// REG-3.82): the longest PROPER prefix of `prefix` with a standing —
    /// held or retired; a prefix whose bindings are all inert has none, and
    /// is no parent.
    fn parent_prefix(&self, prefix: &Address) -> Option<Address> {
        self.prefixes
            .iter()
            .filter(|(parent, bindings)| {
                !bindings.honored.is_empty() && *parent != prefix && is_prefix(parent.tumbler(), prefix.tumbler())
            })
            .max_by_key(|(parent, _)| parent.tumbler().len())
            .map(|(parent, _)| parent.clone())
    }

    /// Every endpoint deposit in `home`, in journal order.
    fn endpoints(&self, home: &Address) -> &[Judged<EndpointRecord>] {
        self.endpoints.get(home).map(|d| d.entries.as_slice()).unwrap_or(&[])
    }

    /// The CURRENT endpoint of `home` (REG-1.10, REG-1.11): the latest
    /// honored deposit still on the active view.
    pub(crate) fn current_endpoint(&self, home: &Address) -> Option<&Judged<EndpointRecord>> {
        self.endpoints(home).iter().rev().find(|d| d.record.stands())
    }

    /// Whether any honored deposit ever stood in `home`.
    pub(crate) fn any_honored_endpoint(&self, home: &Address) -> bool {
        self.endpoints(home).iter().any(|d| d.record.honored)
    }

    /// Every prefix a folded binding names, in address order.
    fn prefixes(&self) -> impl Iterator<Item = &Address> {
        self.prefixes.keys()
    }

    /// Every folded binding of every prefix, in address then journal order.
    fn bindings(&self) -> impl Iterator<Item = &Judged<BindingRecord>> {
        self.prefixes.values().flat_map(|p| p.entries.iter())
    }

    /// Every folded endpoint deposit of every home.
    fn all_endpoints(&self) -> impl Iterator<Item = &Judged<EndpointRecord>> {
        self.endpoints.values().flat_map(|d| d.entries.iter())
    }

    /// The ledger's counts: prefixes, bindings and deposits, each total and
    /// honored.
    fn counts(&self) -> Counts {
        let mut c = Counts { prefixes: self.prefixes.len(), ..Counts::default() };
        for p in self.prefixes.values() {
            c.bindings += p.entries.len();
            c.honored_bindings += p.honored.len();
        }
        for d in self.endpoints.values() {
            c.endpoints += d.entries.len();
            c.honored_endpoints += d.entries.iter().filter(|e| e.record.honored).count();
        }
        c
    }
}

/// THE INDEX — the VERIFIED position-annotated prefix → binding index, with
/// the endpoint deposits per doc 1 beside it: a ledger of the rules alone
/// whose ONE WRITER is the gate, the mirror's fold. The gate hands it a
/// binding only from the claimant's doc 1 (R5 (g), REG-2.8) and a record
/// only where its verdict is SIGNED (rm-2), and keeps every other record out
/// here, counted by its cause ([`Index::suppressed`]) and consulted at no
/// resolve.
///
/// Its write side — the two folds, `nullify`, `suppress` — is this crate's
/// alone: a dependent can fold nothing into an index, so every entry of one
/// it holds passed the gate. The twin builds and reads everything the
/// refusal below it does; the refusal's one difference is the fold. (The
/// `E0624` code is checked on nightly only, which is why the twin rather
/// than the annotation carries the weight.)
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
///
/// Two indexes are equal where every entry is — each binding and deposit,
/// its position, its record and the verdict beside it — and the records
/// kept out are the same, by cause: the rebuild from the copy is held to
/// the live index by that equality, not by its counts alone.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Index {
    ledger: Ledger,
    suppressed: Vec<Suppressed>,
}

impl Index {
    /// Fold one binding the gate passed, by the ledger's rule; answers
    /// whether it was honored.
    pub(crate) fn fold_binding(&mut self, judged: Judged<BindingRecord>) -> bool {
        self.ledger.fold_binding(judged)
    }

    /// Fold one endpoint deposit the gate passed, by the ledger's rule;
    /// answers whether it was honored.
    pub(crate) fn fold_endpoint(&mut self, judged: Judged<EndpointRecord>) -> bool {
        self.ledger.fold_endpoint(judged)
    }

    /// A `nullify` of `link`, by the ledger's rule.
    pub(crate) fn nullify(&mut self, link: &Address) -> bool {
        self.ledger.nullify(link)
    }

    /// Keep a record out of the index, by cause.
    pub(crate) fn suppress(&mut self, suppressed: Suppressed) {
        self.suppressed.push(suppressed);
    }

    /// Every record the gate kept out, in journal order, each beside its
    /// cause.
    pub fn suppressed(&self) -> &[Suppressed] {
        &self.suppressed
    }

    /// The prefix's STANDING: the binding the walk holds current and the
    /// whole history, where an honored binding names the prefix.
    pub fn standing(&self, prefix: &Address) -> Option<Standing> {
        self.ledger.standing(prefix)
    }

    /// THE PARENT PREFIX a depth address's walk reaches (REG-3.80,
    /// REG-3.82): the longest PROPER prefix of `prefix` with a standing —
    /// held or retired.
    pub fn parent_prefix(&self, prefix: &Address) -> Option<Address> {
        self.ledger.parent_prefix(prefix)
    }

    /// Every endpoint deposit in `home`, in journal order.
    pub fn endpoints(&self, home: &Address) -> &[Judged<EndpointRecord>] {
        self.ledger.endpoints(home)
    }

    /// The CURRENT endpoint of `home` (REG-1.10, REG-1.11): the latest
    /// honored deposit still on the active view.
    pub fn current_endpoint(&self, home: &Address) -> Option<&Judged<EndpointRecord>> {
        self.ledger.current_endpoint(home)
    }

    /// Whether any honored deposit ever stood in `home`.
    pub fn any_honored_endpoint(&self, home: &Address) -> bool {
        self.ledger.any_honored_endpoint(home)
    }

    /// Every prefix a verified binding names, in address order.
    pub fn prefixes(&self) -> impl Iterator<Item = &Address> {
        self.ledger.prefixes()
    }

    /// Every verified binding of every prefix, in address then journal
    /// order.
    pub fn bindings(&self) -> impl Iterator<Item = &Judged<BindingRecord>> {
        self.ledger.bindings()
    }

    /// Every verified endpoint deposit of every home.
    pub fn all_endpoints(&self) -> impl Iterator<Item = &Judged<EndpointRecord>> {
        self.ledger.all_endpoints()
    }

    /// The counts: the ledger's, and the records kept out by cause.
    pub fn counts(&self) -> Counts {
        let mut c = self.ledger.counts();
        for s in &self.suppressed {
            match &s.cause {
                Cause::Malformed(_) => c.suppressed_malformed += 1,
                Cause::Verdict(Verdict::Unsigned) => c.suppressed_unsigned += 1,
                Cause::Verdict(Verdict::UndeterminableHere) => c.suppressed_undeterminable += 1,
                Cause::Verdict(Verdict::BeforeAttestation) => c.suppressed_before_attestation += 1,
                Cause::Verdict(Verdict::Disavowed) => c.suppressed_disavowed += 1,
                // SIGNED admits; the gate never keeps a signed record out.
                Cause::Verdict(Verdict::Signed(_)) => {}
            }
        }
        c
    }
}

#[cfg(test)]
mod tests;
