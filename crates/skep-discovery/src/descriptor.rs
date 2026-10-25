//! §3 — the four-set descriptor family (ASN-0121/0132): address-keyed,
//! conjunctive, link-store-local (FL-LOC — no document gate), monotone absent
//! retraction under one predicate held fixed (FL-MON/CN-MONO; the crate
//! header states what a reader does to each law). Not a restriction of the
//! region family and not built on it (ASN-0121 is explicit; Conflicts #2) —
//! the same per-slot stab combined oppositely (AND vs OR), with the AND
//! owned by M7's `match_links_in` over each home (Conflicts #1: M8 implements
//! no combiner).
//!
//! The family's request lives here too — [`FourSet`] and its [`SlotSpec`]s —
//! with the two readings of its slots only this family asks: the constraint
//! list M7's AND-of-ORs takes, and the home slot, which M7 answers home by
//! home off its own key order, both private beside the reads that ask them.
//! Every shape of the descriptor is read home by home: the candidate homes
//! are enumerated in address order, the reader asked of each once ahead of
//! its links, and an admitted home's satisfying links read from the store's
//! key range or the coverage index within that home alone.

use std::rc::Rc;

use im::OrdSet;
use skep_address::Address;
use skep_kernel::Snapshot;
use skep_links::{Endset, LinkState, Touch, View, FROM, TO, TYPE};

use crate::home::home_admitted;
use crate::sets::window_homes;
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
    /// ([`FourSet::is_unsatisfiable`] answers for both), so M7's matcher is
    /// never handed an empty constraint.
    Spans(Endset),
}

/// The four-set descriptor `q = (H, F, G, Θ)` (ASN-0121). `home` is the HOME
/// SLOT, which ASN-0132 calls structurally different from the three link
/// slots: it is matched against `home(a)` — an M1 `document_of` address
/// projection — so it is NOT a link slot (it never reaches M7's AND-of-ORs;
/// M7 answers it home by home, off the key order that keeps a home's links
/// together) and NOT an arrangement-presence test (ASN-0132 CN-STAB: a
/// reverse-orphaned link still satisfies a home-bounded query).
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
    /// non-empty, and so — the home slot being read by the same test — is a
    /// `Spans` the home slot carries beside a `Some`.
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
}

/// `FourSet::default()` IS [`FourSet::any()`] — the unit descriptor, so
/// `FourSet { from: …, ..Default::default() }` reads as the wildcard base it
/// is. The domain name carries the doc; this is the std spelling of it.
impl Default for FourSet {
    fn default() -> FourSet {
        FourSet::any()
    }
}

/// One candidate home of a descriptor, and how its satisfying links are read:
/// ASN-0121's CANDIDATE set as the read-outs walk it, home by home in
/// address order, the home rule not yet asked.
enum Candidate<'q> {
    /// A home the home slot covers that holds links, or a home of the whole
    /// store under the unit descriptor: its links are its key range, each
    /// tested against the link-slot constraints.
    Chain {
        home: Address,
        constraints: Rc<[(usize, &'q Endset)]>,
    },
    /// A home the driving link slot's directory walk named, with the spans
    /// that named it: its links are the per-home stab of the driver over
    /// those spans, narrowed by the other constraints.
    Driven {
        touch: Touch<'q>,
        slot: usize,
        rest: Rc<[(usize, &'q Endset)]>,
    },
}

impl Candidate<'_> {
    /// The candidate home.
    fn home(&self) -> &Address {
        match self {
            Candidate::Chain { home, .. } => home,
            Candidate::Driven { touch, .. } => touch.home(),
        }
    }

    /// `sat` within this home: the home's addressable links satisfying every
    /// link-slot constraint, in address order — the home slot's clause
    /// having been decided by the enumeration that named the home.
    fn satisfying(self, l: &LinkState) -> OrdSet<Address> {
        match self {
            Candidate::Chain { home, constraints } => l.homed_in(&home, &constraints, View::Active),
            Candidate::Driven { touch, slot, rest } => {
                l.match_links_in(touch.home(), (slot, touch.spans(0)), &rest, View::Active)
            }
        }
    }
}

/// ASN-0121's CANDIDATE set, home by home: the homes whose links the
/// descriptor's slots could admit, in address order, lazily, each knowing how
/// its satisfying links are read. The descriptor reads its own slots — which
/// are the zero, which drop out — in [`FourSet::link_constraints`].
///
/// The unsatisfiable case returns without touching the store. M7 would answer
/// the same way if it could be asked — `stab(slot, ⟨⟩, ·) = ∅` empties the
/// AND — but an `Empty` slot carries no endset to ask WITH, so this is where
/// FL-EMP is answered for the link slots, not merely where it is anticipated.
///
/// THE HOME SLOT DRIVES WHERE IT IS CONSTRAINED (PUB-7.18). A link's address
/// is its home's with three components after it, so M7 keeps a home's links
/// together in its key order: `homes_under` names each home the slot's
/// coverage contains that holds links, found by one seek apiece, and each is
/// a candidate whose links are read by `homed_in`, its own key range, each
/// tested against the link-slot constraints. So a home-constrained
/// descriptor costs the homes it names and the admitted ones' links: a
/// document's or a member's at one seek, an account's or the node's at one
/// seek per home under it, never the links of a home it does not name. The
/// home slot's clause of `sat` — `h` covers `home(a)` — is what
/// `homes_under` decides, of the home rather than of each link, so no link
/// here is tested for it again.
///
/// WHERE THE HOME SLOT IS `Any` AND A LINK SLOT IS CONSTRAINED, the
/// constraint with the fewest candidate homes drives — M7's `fewest_homes`,
/// the rule its own `match_links` chooses by, a bounded walk of directory
/// entries and a cost decision, not a semantic one: its candidate homes come
/// off M7's `homes_touching` — the coverage index's directory for `from` and
/// `to`, the typed slices for `ty` — each a candidate whose links are read
/// by `match_links_in`, the driver's per-home stab over the spans that named
/// the home, narrowed by the other constraints. WITH NO CONSTRAINT AT ALL
/// (`(∗,∗,∗)`), every home holding links is a candidate, its whole chain the
/// answer — the store's homes, one seek apiece, where the unfiltered walk of
/// the whole slice was.
///
/// In every shape the reader is asked of a home ONCE, ahead of its links,
/// by the read-outs that walk this: an unreadable home's whole candidate list
/// is dropped on that one test and never walked per link.
fn candidates<'q>(l: &'q LinkState, q: &'q FourSet) -> Box<dyn Iterator<Item = Candidate<'q>> + 'q> {
    let Some(constraints) = q.link_constraints() else {
        return Box::new(std::iter::empty()); // FL-EMP: some slot is the zero
    };
    if let SlotSpec::Spans(h) = &q.home {
        let constraints: Rc<[(usize, &'q Endset)]> = constraints.into();
        return Box::new(l.homes_under(h).into_iter().map(move |home| Candidate::Chain {
            home,
            constraints: Rc::clone(&constraints),
        }));
    }
    if constraints.is_empty() {
        let none: Rc<[(usize, &'q Endset)]> = Rc::from([]);
        return Box::new(l.homes().into_iter().map(move |home| Candidate::Chain {
            home,
            constraints: Rc::clone(&none),
        }));
    }
    let driver = l.fewest_homes(&constraints);
    let (slot, query) = constraints[driver];
    let rest: Rc<[(usize, &'q Endset)]> = constraints
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != driver)
        .map(|(_, c)| *c)
        .collect();
    Box::new(l.homes_touching([(slot, query)]).map(move |touch| Candidate::Driven {
        touch,
        slot,
        rest: Rc::clone(&rest),
    }))
}

/// `sat(·, q, Σ)` under the reader — THE one definition of "matches" for the
/// descriptor family. ASN-0132's CN-ENUM forces exactly one, consumed by
/// enumeration and by count alike, so [`findlinks_ftt_on`] and
/// [`count_ftt_on`] are two read-outs of this one sequence and cannot
/// disagree about which links match.
///
/// ASN-0121's [`candidates`] — `cand`, computed for the same `q` — each home
/// admitted by the reader once ahead of its links, and each admitted home's
/// [`Candidate::satisfying`] links in turn; the per-home sets concatenated in
/// home order are address order, a home's links being one key range.
fn satisfying<'a>(
    l: &'a LinkState,
    q: &'a FourSet,
    readable: &'a dyn Fn(&Address) -> bool,
) -> impl Iterator<Item = Address> + 'a {
    candidates(l, q)
        .filter(move |cand| home_admitted(readable, cand.home()))
        .flat_map(move |cand| cand.satisfying(l))
}

/// FINDLINKS over the four-set descriptor (ASN-0121): the links satisfying
/// the descriptor, in address order. Total — no doc gate (FL-LOC).
/// `(∗,∗,∗,∗)` = the whole addressable slice (FL-WILD) — under a reader, the
/// part of it homed where the reader may read; any constrained-empty slot ⇒
/// `[]` (FL-EMP). Monotone absent retraction (FL-MON): under one predicate
/// held fixed, a found link stays found unless nullified.
///
/// The result-set filter (PUB round 2, lane 3.3, §3; PUB-7.18): every
/// satisfying link whose HOME `readable` refuses is never read at all, the
/// rule having been asked of its home ahead of the home's links, once per
/// home whatever the descriptor's shape. The descriptor's own `home` slot is
/// a COVERAGE constraint (CN-STAB); `readable` is the authorization one,
/// orthogonal to it.
pub fn findlinks_ftt_on<W: DiscoveryWorld>(
    s: &Snapshot<W>,
    q: &FourSet,
    readable: &dyn Fn(&Address) -> bool,
) -> Vec<Address> {
    satisfying(s.world().links(), q, readable).collect()
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
    satisfying(s.world().links(), q, readable).count()
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
/// LAZY (D5 of the home-index record): the cursor names the home to resume
/// in, so the window passes the candidate homes behind it unasked, cuts the
/// cursor's home past it, and walks on home by home until `n` links are in
/// hand — paying for `n` and the homes it passes. The home rule (PUB round
/// 2, lane 3.3, §3) is asked of each home it reaches, once, BEFORE the
/// window slice (PUB-6.14), so a refused home's links are skipped unread
/// rather than counted against `n`.
pub fn window_ftt_on<W: DiscoveryWorld>(
    s: &Snapshot<W>,
    q: &FourSet,
    cur: Cursor,
    n: usize,
    readable: &dyn Fn(&Address) -> bool,
) -> Window {
    let l = s.world().links();
    window_homes(
        candidates(l, q),
        |cand| cand.home(),
        |cand| cand.satisfying(l),
        readable,
        cur,
        n,
    )
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

    /// The descriptor answers what its slots say, in slot order, whatever a
    /// constraint would cost M7: which constraint drives is `candidates`'
    /// decision, beside its call to M7, so a FROM beside a TYPE comes back
    /// FROM first, and a wide FROM beside a narrow TO comes back FROM first
    /// too.
    #[test]
    fn link_constraints_answer_in_slot_order_whatever_their_cost() {
        let wide = enc(&[a(&[1, 0, 1, 0, 1, 0, 1, 1]), a(&[1, 0, 1, 0, 1, 0, 1, 5])]);
        let narrow = enc(&[a(&[1, 0, 1, 0, 1, 0, 1, 2])]);
        let ty = enc(&[a(&[1, 1, 0, 1, 0, 1, 0, 1, 10])]);
        assert!(wide.len() > narrow.len(), "a size order would reverse them");
        let q = FourSet {
            from: SlotSpec::Spans(wide.clone()),
            to: SlotSpec::Spans(narrow.clone()),
            ty: SlotSpec::Spans(ty.clone()),
            ..FourSet::any()
        };
        assert_eq!(
            q.link_constraints(),
            Some(vec![(FROM, &wide), (TO, &narrow), (TYPE, &ty)])
        );
    }

    /// The home slot is read beside the link slots by the one zero test, so a
    /// descriptor whose home slot carries the zero hands M7 no constraint
    /// list at all, and one whose home slot carries spans hands over the link
    /// slots alone: the home is no link slot, and `candidates` answers it
    /// from M7's home ranges rather than from the list.
    #[test]
    fn link_constraints_leave_the_home_slot_out_and_answer_none_for_its_zero() {
        let home = enc(&[a(&[1, 0, 1, 0, 2])]);
        let from = enc(&[a(&[1, 0, 1, 0, 1, 0, 1, 2])]);
        let homed = FourSet {
            home: SlotSpec::Spans(home),
            from: SlotSpec::Spans(from.clone()),
            ..FourSet::any()
        };
        assert_eq!(homed.link_constraints(), Some(vec![(FROM, &from)]));
        for zero in [SlotSpec::Empty, SlotSpec::Spans(Endset::empty())] {
            let q = FourSet {
                home: zero,
                from: SlotSpec::Spans(from.clone()),
                ..FourSet::any()
            };
            assert_eq!(q.link_constraints(), None, "{q:?}: the zero");
        }
    }
}
