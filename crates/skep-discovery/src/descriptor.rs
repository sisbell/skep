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
//! list M7's AND-of-ORs takes, and the home slot, which M7 answers home by
//! home off its own key order, both private beside the reads that ask them.

use im::OrdSet;
use skep_address::Address;
use skep_kernel::Snapshot;
use skep_links::{Endset, LinkState, View, FROM, TO, TYPE};

use crate::home::{home_admitted, home_readable};
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

/// The most links a TYPE constraint's class may hold and still drive M7's
/// `stab` ahead of the other constrained slots.
///
/// A TYPE constraint's hits are counted exactly before any stab, off M7's
/// typed slices (`LinkState::type_hits`); a FROM or TO constraint's are known
/// only by the stab itself, no bounded probe of the coverage index existing
/// at this build. So the choice is made on the one side it can see: a class
/// this small drives, and a wrong guess — the other slot would have found
/// fewer — costs at most this many lifts, where the guess the other way costs
/// the whole population the other slot reaches, which one passage can set in
/// the tens of thousands. Past it the slots stand in FROM, TO, TYPE order.
const TYPE_DRIVES_UP_TO: usize = 1024;

/// Moves the constraint that should drive M7's `stab` to the front of the
/// list: the TYPE constraint, where the class it names holds at most
/// [`TYPE_DRIVES_UP_TO`] links. `match_links` answers its FIRST constraint by
/// one `stab` of M7's coverage index and narrows what it finds with the rest,
/// at `|query spans| × |slot spans|` per survivor, so the constraint with the
/// fewest hits costs the fewest lifts up front and the fewest survivors to
/// test — which of the constraints that is, this element decides, because it
/// is the one that asks M7. The others keep their slot order, and an AND is
/// order-free, so this moves work and never the answer: one descriptor still
/// names one constraint list.
fn cheapest_first(l: &LinkState, constraints: &mut Vec<(usize, &Endset)>) {
    if constraints.len() < 2 {
        return;
    }
    let small_class = constraints.iter().position(|&(slot, e)| {
        slot == TYPE && l.type_hits(e).is_some_and(|hits| hits <= TYPE_DRIVES_UP_TO)
    });
    if let Some(i) = small_class {
        let ty = constraints.remove(i);
        constraints.insert(0, ty);
    }
}

/// ASN-0121's CANDIDATE set as one read-out walks it: the links in address
/// order, and whether the reader has admitted them yet.
///
/// Where the home slot drove, the home rule ran once per home ahead of that
/// home's range (PUB-7.18) and every link here is admitted; where a link
/// slot drove, no home has been asked, and each read-out asks it of the links
/// it walks, lazily, so a window asks no further than it pages (PUB-6.14).
struct Candidates {
    links: OrdSet<Address>,
    admitted: bool,
}

impl Candidates {
    /// `sat` under the reader for one link of the set: the home rule where it
    /// has not run — the link slots and the home slot are answered by the set
    /// itself.
    fn admits(&self, readable: &dyn Fn(&Address) -> bool, a: &Address) -> bool {
        self.admitted || home_readable(readable, a)
    }
}

/// ASN-0121's CANDIDATE set: the links the descriptor's slots admit, as M7
/// answers them over the ACTIVE view, under the reader where the home slot
/// drove. The descriptor reads its own slots — which are the zero, which drop
/// out — in [`FourSet::link_constraints`].
///
/// The unsatisfiable case returns without touching the store. M7 would answer
/// the same way if it could be asked — `stab(slot, ⟨⟩, ·) = ∅` empties the
/// AND — but an `Empty` slot carries no endset to ask WITH, so this is where
/// FL-EMP is answered for the link slots, not merely where it is anticipated.
///
/// THE HOME SLOT DRIVES WHERE IT IS CONSTRAINED (PUB-7.18). A link's address
/// is its home's with three components after it, so M7 keeps a home's links
/// together in its key order: `homes_under` names each home the slot's
/// coverage contains that holds links, found by one seek apiece, and the
/// reader's predicate is asked of each home ONCE, through [`home_admitted`],
/// ahead of its links — an unreadable home's whole candidate list is dropped
/// on that one test and never walked per link. Each admitted home's links are
/// then read by `homed_in`, its own key range, each tested against the
/// link-slot constraints as `match_links` tests its later constraints. So a
/// home-constrained descriptor costs the homes it names and the readable
/// ones' links: a document's or a member's at one seek, an account's or the
/// node's at one seek per home under it, never the links of a home it does
/// not name. The home slot's clause of `sat` — `h` covers `home(a)` — is what
/// `homes_under` decides, of the home rather than of each link, so no link
/// here is tested for it again.
///
/// WHERE THE HOME SLOT IS `Any`, the link slots are handed to M7 CHEAPEST
/// FIRST, which is a cost decision and not a semantic one, and this element's
/// because it is the one that asks M7 — [`cheapest_first`] states the rule
/// and its limit. With no constraint at all (`(∗,∗,∗)`), M7 walks the whole
/// active slice.
fn candidates(l: &LinkState, q: &FourSet, readable: &dyn Fn(&Address) -> bool) -> Candidates {
    let Some(mut constraints) = q.link_constraints() else {
        return Candidates {
            links: OrdSet::new(), // FL-EMP: some slot is the zero
            admitted: true,
        };
    };
    if let SlotSpec::Spans(h) = &q.home {
        let mut links = OrdSet::new();
        for home in l.homes_under(h) {
            if home_admitted(readable, &home) {
                links = links.union(l.homed_in(&home, &constraints, View::Active));
            }
        }
        return Candidates {
            links,
            admitted: true,
        };
    }
    cheapest_first(l, &mut constraints);
    Candidates {
        links: l.match_links(&constraints, View::Active),
        admitted: false,
    }
}

/// `sat(·, q, Σ)` under the reader — THE one definition of "matches" for the
/// descriptor family. ASN-0132's CN-ENUM forces exactly one, consumed by
/// enumeration and by count alike, so [`findlinks_ftt_on`] and
/// [`count_ftt_on`] are two read-outs of this one sequence and cannot
/// disagree about which links match. It is walked by reference, so nothing
/// is copied until a link ships.
///
/// ASN-0121's [`candidates`] — `cand`, computed for the same `q` — narrowed
/// by what the set has not yet asked: the home rule at link identity where a
/// link slot drove, nothing where the home slot drove and admitted each home
/// ahead of its links. The filter reads the candidates in place, so the
/// survivors are never gathered into a set of their own.
fn satisfying<'c>(
    cand: &'c Candidates,
    readable: &'c dyn Fn(&Address) -> bool,
) -> impl Iterator<Item = &'c Address> + 'c {
    cand.links.iter().filter(move |&a| cand.admits(readable, a))
}

/// FINDLINKS over the four-set descriptor (ASN-0121): the links satisfying
/// the descriptor, in address order. Total — no doc gate (FL-LOC).
/// `(∗,∗,∗,∗)` = the whole addressable slice (FL-WILD) — under a reader, the
/// part of it homed where the reader may read; any constrained-empty slot ⇒
/// `[]` (FL-EMP). Monotone absent retraction (FL-MON): under one predicate
/// held fixed, a found link stays found unless nullified.
///
/// The result-set filter (PUB round 2, lane 3.3, §3): every satisfying link
/// whose HOME `readable` refuses is dropped at its identity — or, where the
/// descriptor's `home` slot drives, never read at all, the rule having been
/// asked of its home ahead of the home's links (PUB-7.18). The descriptor's
/// own `home` slot is a COVERAGE constraint (CN-STAB); `readable` is the
/// authorization one, orthogonal to it.
pub fn findlinks_ftt_on<W: DiscoveryWorld>(
    s: &Snapshot<W>,
    q: &FourSet,
    readable: &dyn Fn(&Address) -> bool,
) -> Vec<Address> {
    let cand = candidates(s.world().links(), q, readable);
    satisfying(&cand, readable).cloned().collect()
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
    let cand = candidates(s.world().links(), q, readable);
    satisfying(&cand, readable).count()
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
/// key-cut, BEFORE the window slice (PUB-6.14), so a link it refuses is
/// skipped rather than counted against `n` — where a link slot drove; where
/// the home slot drove, it was applied to each home ahead of the home's
/// links, and the page is cut from links already admitted.
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
    // the candidates itself and applies the same reader test LAZILY in its
    // `keep`.
    let cand = candidates(s.world().links(), q, readable);
    window_over(&cand.links, cur, n, |a| cand.admits(readable, a))
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
    /// constraint would cost M7: which constraint M7 is asked with first is
    /// `candidates`' decision, beside its call to M7, so a FROM beside a TYPE
    /// — the one constraint that may be moved ahead of it — comes back FROM
    /// first, and a wide FROM beside a narrow TO comes back FROM first too.
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
