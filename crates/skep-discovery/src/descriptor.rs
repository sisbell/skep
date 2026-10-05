//! §3 — the four-set descriptor family (ASN-0121/0132): address-keyed,
//! conjunctive, link-store-local (FL-LOC — no document gate), monotone absent
//! retraction under one predicate held fixed (FL-MON/CN-MONO; the crate
//! header states what a reader does to each law). Not a restriction of the
//! region family and not built on it (ASN-0121 is explicit; Conflicts #2) —
//! the same per-slot `stab` combined oppositely (AND vs OR), with the AND
//! owned by M7's `match_links` (Conflicts #1: M8 implements no combiner).
//!
//! The family's request lives here too — [`FourSet`] and its [`SlotSpec`]s —
//! with the two readings of its slots only this family asks: the constraint
//! list M7's AND-of-ORs takes, and the residence test the home slot answers,
//! both private beside the reads that ask them.

use im::OrdSet;
use skep_address::Address;
use skep_kernel::Snapshot;
use skep_links::{Endset, LinkState, View, FROM, TO, TYPE};

use crate::home::{home_of, home_readable};
use crate::sets::window_over;
use crate::types::{Cursor, Window};
use crate::DiscoveryWorld;

/// Per-slot request component for the four-set descriptor query — the
/// three-way distinction the conjunction needs (ASN-0121).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub enum SlotSpec {
    /// ∗ / NOSPECS — the unit: drops out of the conjunction (FL-WILD), and so
    /// the default: an unstated slot constrains nothing.
    #[default]
    Any,
    /// ∅ constrained-empty — the zero: annihilates the whole result (FL-EMP).
    Empty,
    /// Populated address-spans (M7's readable [`Endset`]). An EMPTY `Endset`
    /// is accepted and read as [`SlotSpec::Empty`] — the same zero
    /// ([`FourSet::is_unsatisfiable`] answers for both), so M7's `match_links`
    /// is never handed an empty constraint.
    Spans(Endset),
}

/// The four-set descriptor `q = (H, F, G, Θ)` (ASN-0121). `home` is the HOME
/// SLOT, which ASN-0132 calls structurally different from the three link
/// slots: it is matched against `home(a)` — an M1 `document_of` address
/// projection — so it is NOT a link slot (it never reaches M7's AND-of-ORs;
/// M8 tests it on each link M7 returns) and NOT an arrangement-presence test
/// (ASN-0132 CN-STAB: a reverse-orphaned link still satisfies a home-bounded
/// query).
///
/// WHAT SATISFIES IT (ASN-0121's `sat`): a link `a` satisfies `q` when every
/// slot holds — `Any` always (FL-WILD), the zero never (FL-EMP):
///
/// * `from`, `to` or `ty` holding `Spans(e)` holds when `a`'s stored endset
///   at that slot OVERLAPS `e` — some span of one properly overlaps, contains
///   or equals some span of the other, never merely abutting (M7's `stab`;
///   ASN-0121's `touch`) — so a link whose endset there is empty never meets
///   it;
/// * `home` holding `Spans(h)` holds when `h`'s coverage CONTAINS the address
///   `home(a)` (ASN-0121's `athome`): membership, not overlap, and one way
///   only — a span naming an account or a document admits every link whose
///   home lies at or beneath it, version members included, and an address
///   beneath a document admits none of that document's links.
///
/// The reads ask it of the ADDRESSABLE links alone — the active view, so a
/// nullified link is never returned, whatever it satisfies — and the reader's
/// home rule then narrows what they return.
///
/// `Eq`/`Hash` are REPRESENTATIONAL, not semantic: [`SlotSpec::Empty`] and a
/// `Spans` naming nothing are one query — [`FourSet::is_unsatisfiable`]
/// answers for both — and two distinct values, so a map keyed on a descriptor
/// holds two entries for that one query. A missed hit, never a wrong answer;
/// the semantic test is `is_unsatisfiable`, which reads the slots rather than
/// their spelling.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FourSet {
    pub home: SlotSpec,
    pub from: SlotSpec,
    pub to: SlotSpec,
    pub ty: SlotSpec,
}

impl FourSet {
    /// `(∗,∗,∗,∗)` — the UNIT descriptor (FL-WILD): every slot wildcard, so
    /// it matches the whole addressable slice. The counterpart to the zero
    /// [`FourSet::is_unsatisfiable`] answers for, and the base a narrowed
    /// query is built from: `FourSet { from: …, ..FourSet::any() }` names
    /// only the slots it constrains, so no slot is left at something other
    /// than the wildcard by accident.
    pub fn any() -> FourSet {
        FourSet {
            home: SlotSpec::Any,
            from: SlotSpec::Any,
            to: SlotSpec::Any,
            ty: SlotSpec::Any,
        }
    }

    /// FL-EMP: does some slot carry the zero — an explicit
    /// [`SlotSpec::Empty`], or a `Spans` that names nothing? Such a descriptor
    /// matches no link whatever the other slots say.
    ///
    /// This is what separates the two zeros ASN-0132 keeps apart: a `0` from
    /// [`crate::count_ftt_on`] over a satisfiable descriptor asserts that no
    /// addressable link the reader may see satisfies `q` (CN-ZERO), while a
    /// `0` over an unsatisfiable one says only that the REQUEST names
    /// nothing. Same number, different assertion — and this answers the
    /// second off the descriptor's own slots, with no store read at all.
    pub fn is_unsatisfiable(&self) -> bool {
        [&self.home, &self.from, &self.to, &self.ty]
            .into_iter()
            .any(|spec| match spec {
                SlotSpec::Any => false,
                SlotSpec::Empty => true,
                SlotSpec::Spans(e) => e.is_empty(),
            })
    }

    /// The constrained LINK slots as M7's AND-of-ORs takes them (FL-WILD: an
    /// `Any` slot is omitted, never handed over as an empty constraint), or
    /// `None` when the descriptor is unsatisfiable.
    ///
    /// The zero and the constraint list are answered together because they
    /// are read off the same four slots: a slot carrying `Empty` has no
    /// endset to hand M7, so a list built without first asking
    /// [`FourSet::is_unsatisfiable`] would drop that slot exactly as it drops
    /// `Any` and silently widen the query. Every endset in a `Some` list is
    /// non-empty.
    ///
    /// In FROM/TO/TYPE order: the descriptor answers what its slots say; the
    /// order M7 is asked in is `candidates`' to decide, beside its call to M7.
    fn link_constraints(&self) -> Option<Vec<(usize, &Endset)>> {
        if self.is_unsatisfiable() {
            return None;
        }
        let mut constraints = Vec::new();
        for (slot, spec) in [(FROM, &self.from), (TO, &self.to), (TYPE, &self.ty)] {
            if let SlotSpec::Spans(e) = spec {
                constraints.push((slot, e)); // e non-empty: a satisfiable descriptor has no empty Spans
            }
        }
        Some(constraints)
    }

    /// `athome(a, H)` — ASN-0121/0132's residence test, the companion of
    /// `touch`: does the home slot admit the link at `a`? `Any` admits every
    /// link (FL-WILD); a `Spans` admits those whose `home(a)` its coverage
    /// names — an ADDRESS projection, never an arrangement-presence test
    /// (CN-STAB: a reverse-orphaned link still satisfies a home-bounded
    /// query); and the zero admits none, which is FL-EMP for the home slot.
    ///
    /// Total: an address with no home — a node or an account — is at no home
    /// a `Spans` names, even one whose coverage reaches the address itself.
    /// Every address reaching it comes off M7's `match_links` and so is a link,
    /// which has a home; the test answers for the projection's partiality
    /// rather than assuming it away.
    fn at_home(&self, a: &Address) -> bool {
        match &self.home {
            SlotSpec::Any => true,
            SlotSpec::Empty => false,
            SlotSpec::Spans(h) => home_of(a).is_some_and(|home| h.covers(home.tumbler())),
        }
    }
}

/// `FourSet::default()` IS [`FourSet::any()`] — the unit descriptor, so
/// `FourSet { from: …, ..Default::default() }` reads as the wildcard base it
/// is. The domain name carries the doc; this is the std spelling of it.
impl Default for FourSet {
    fn default() -> FourSet {
        FourSet::any()
    }
}

/// ASN-0121's CANDIDATE set: the descriptor's constrained LINK slots handed
/// to M7's AND-of-ORs over the ACTIVE view, and no constraints at all
/// (`(∗,∗,∗)`) reading as the whole active slice. It is not yet the match —
/// the home slot is not a link slot, and narrowing by it is the residence
/// post-filter [`satisfying`] applies. The descriptor reads its own slots —
/// which are the zero, which drop out — in [`FourSet::link_constraints`].
///
/// The unsatisfiable case returns without touching the store. M7 would answer
/// the same way if it could be asked — `stab(slot, ⟨⟩, ·) = ∅` empties the
/// AND — but an `Empty` slot carries no endset to ask WITH, so this is where
/// FL-EMP is answered for the link slots, not merely where it is anticipated.
///
/// The constraints are handed to M7 SMALLEST FIRST, which is a cost decision
/// and not a semantic one, and this element's because it is the one that asks
/// M7: `match_links` drives one whole-store scan with the FIRST constraint and
/// narrows the survivors with the rest, at `|query spans| × |slot spans|` per
/// link tested, so the conjunct that pays the store-sized factor should be the
/// cheapest one to test. An AND is order-free, so this moves work and never
/// the answer — and the sort is stable, so equal spellings keep FROM/TO/TYPE
/// order and one descriptor still names one constraint list.
fn candidates(l: &LinkState, q: &FourSet) -> OrdSet<Address> {
    match q.link_constraints() {
        None => OrdSet::new(), // FL-EMP: some slot is the zero
        Some(mut constraints) => {
            constraints.sort_by_key(|(_, e)| e.len()); // the cheapest conjunct drives M7's scan
            l.match_links(&constraints, View::Active)
        }
    }
}

/// `sat(·, q, Σ)` — THE one definition of "matches" for the descriptor
/// family. ASN-0132's CN-ENUM forces exactly one, consumed by enumeration and
/// by count alike, so [`findlinks_ftt_on`] and [`count_ftt_on`] are two
/// read-outs of this one sequence and cannot disagree about which links
/// match. It is walked by reference, so nothing is copied until a link ships.
///
/// ASN-0121's [`candidates`] — `cand`, computed for the same `q` — narrowed
/// by the residence post-filter [`FourSet::at_home`]: the home-bound placement
/// M8 chose, since M8 owns no index dimension keyed on `home(a)` (Conflicts
/// #7: a home-only query degrades to a full active scan, accepted). The
/// post-filter reads the candidates in place, so the survivors are never
/// gathered into a set of their own.
fn satisfying<'c>(
    cand: &'c OrdSet<Address>,
    q: &'c FourSet,
) -> impl Iterator<Item = &'c Address> + 'c {
    cand.iter().filter(move |&a| q.at_home(a))
}

/// FINDLINKS over the four-set descriptor (ASN-0121): the links satisfying
/// the descriptor, in address order. Total — no doc gate (FL-LOC).
/// `(∗,∗,∗,∗)` = the whole addressable slice (FL-WILD) — under a reader, the
/// part of it homed where the reader may read; any constrained-empty slot ⇒
/// `[]` (FL-EMP). Monotone absent retraction (FL-MON): under one predicate
/// held fixed, a found link stays found unless nullified.
///
/// The result-set filter (PUB round 2, lane 3.3, §3): every satisfying link
/// whose HOME `readable` refuses is dropped at its identity. The descriptor's
/// own `home` slot is a COVERAGE constraint (CN-STAB); `readable` is the
/// authorization one, orthogonal to it.
pub fn findlinks_ftt_on<W: DiscoveryWorld>(
    s: &Snapshot<W>,
    q: &FourSet,
    readable: &dyn Fn(&Address) -> bool,
) -> Vec<Address> {
    let cand = candidates(s.world().links(), q);
    satisfying(&cand, q)
        .filter(|&a| home_readable(readable, a))
        .cloned()
        .collect()
}

/// The count operation over the descriptor family (ASN-0132 CN-*): the
/// existence census — monotone absent retraction (CN-MONO, under one
/// predicate held fixed). The cardinality of the same `sat` set
/// [`findlinks_ftt_on`] enumerates, so CN-ENUM's `count = |enumeration|`
/// holds by construction rather than by promise.
///
/// CN-ZERO: a returned `0` is a verdict over the WHOLE addressable store as
/// the reader sees it — no addressable link homed where `readable` admits
/// satisfies `q`, and under the total predicate none at all — never present
/// unreachability (which is [`crate::count_v_on`]'s D-ZERO) and never an
/// exhaustion artefact of a scan that gave up. The third zero, the
/// degenerate request that names nothing, is answerable off the descriptor
/// alone through [`FourSet::is_unsatisfiable`]: same number, different
/// assertion.
///
/// The cardinality is the FILTERED one (PUB round 2, lane 3.3, §3; PUB-6.19):
/// of the satisfying links the home rule admits, by ENUMERATION — the same
/// set [`findlinks_ftt_on`] returns under the same `readable`, given a
/// predicate that answers each home the same way in both calls (the crate
/// header states the predicate's contract).
pub fn count_ftt_on<W: DiscoveryWorld>(
    s: &Snapshot<W>,
    q: &FourSet,
    readable: &dyn Fn(&Address) -> bool,
) -> usize {
    let cand = candidates(s.world().links(), q);
    satisfying(&cand, q)
        .filter(|&a| home_readable(readable, a))
        .count()
}

/// Windowed enumeration over the descriptor family (ASN-0108, the
/// `Match = findlinks_FTT` reading — the same cursor mechanism as `window_v`
/// instantiated over the conjunctive family). `n = 0` is clamped to 1 (total
/// API, W9); a window holds at most `max(n, 1)` links, and [`Window`] states
/// what a window and a pass return.
///
/// EVERY `Address` IS A LEGAL CURSOR, and none is checked: resume is a
/// key-cut strictly past `cur`, never a lookup of it, so a cursor naming a
/// link that has since been nullified or has stopped satisfying `q` still
/// resumes at the right place (W8), and no continuously-matching link is
/// skipped or duplicated (W4/W5). A caller relaying a cursor from a request
/// owes it no validation.
///
/// The links this pages over are exactly the ones [`findlinks_ftt_on`]
/// returns under the same `readable`, given the predicate's contract the
/// crate header states.
///
/// The home rule (PUB round 2, lane 3.3, §3) is applied LAZILY during the
/// key-cut, beside the residence post-filter and BEFORE the window slice
/// (PUB-6.14), so a link it refuses is skipped rather than counted against
/// `n`.
pub fn window_ftt_on<W: DiscoveryWorld>(
    s: &Snapshot<W>,
    q: &FourSet,
    cur: Cursor,
    n: usize,
    readable: &dyn Fn(&Address) -> bool,
) -> Window {
    // The one place `sat` is spelled apart rather than composed: the window
    // seeks by key — `range` strictly past the cursor — which the candidate
    // SET supports and `satisfying`'s filtered sequence does not, so it walks
    // `candidates` itself and applies the same residence post-filter LAZILY
    // in its `keep`.
    let cand = candidates(s.world().links(), q);
    window_over(&cand, cur, n, |a| q.at_home(a) && home_readable(readable, a))
}

#[cfg(test)]
mod tests {
    use super::*;
    use skep_address::{validate, Nat, Tumbler};
    use skep_links::enc;

    fn a(comps: &[u32]) -> Address {
        let t = Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("nonempty");
        validate(t).expect("test addresses are T4-valid")
    }

    /// The descriptor answers what its slots say, in slot order: which
    /// constraint M7 is asked with first is `candidates`' decision, beside its
    /// call to M7, so a wide FROM beside a narrow TO comes back FROM first.
    #[test]
    fn link_constraints_answer_in_slot_order_whatever_their_size() {
        let wide = enc(&[a(&[1, 0, 1, 0, 1, 0, 1, 1]), a(&[1, 0, 1, 0, 1, 0, 1, 5])]);
        let narrow = enc(&[a(&[1, 0, 1, 0, 1, 0, 1, 2])]);
        assert!(wide.len() > narrow.len(), "a size order would reverse them");
        let q = FourSet {
            from: SlotSpec::Spans(wide.clone()),
            to: SlotSpec::Spans(narrow.clone()),
            ..FourSet::any()
        };
        assert_eq!(
            q.link_constraints(),
            Some(vec![(FROM, &wide), (TO, &narrow)])
        );
    }

    /// The residence test is TOTAL on an address with no home — a node or an
    /// account — which `Any` admits and a `Spans` places at no home, even the
    /// account's own subtree, which COVERS the account address: the slot is
    /// matched against `home(a)`, never against `a`. A residence test that
    /// read a home it assumed would fault here, and one that matched `a`
    /// itself would admit the account.
    #[test]
    fn at_home_places_an_address_with_no_home_at_no_home() {
        let account = a(&[1, 0, 1]);
        let under_account = FourSet {
            home: SlotSpec::Spans(enc([&account])),
            ..FourSet::any()
        };
        assert!(
            under_account.at_home(&a(&[1, 0, 1, 0, 1, 0, 2, 1])),
            "a link homed under it"
        );
        for homeless in [a(&[1]), account] {
            assert!(
                FourSet::any().at_home(&homeless),
                "{homeless:?}: the unit admits it"
            );
            assert!(
                !under_account.at_home(&homeless),
                "{homeless:?}: it has no home"
            );
        }
    }
}
