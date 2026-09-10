//! §3 — the four-set descriptor family (ASN-0121/0132): address-keyed,
//! conjunctive, link-store-local (FL-LOC — no document gate), monotone absent
//! retraction under one predicate held fixed (FL-MON/CN-MONO; the crate
//! header states what a reader does to each law). Not a restriction of the
//! region family and not built on it (ASN-0121 is explicit; Conflicts #2) —
//! the same per-slot `stab` combined oppositely (AND vs OR), with the AND
//! owned by M7's `match_links` (Conflicts #1: M8 implements no combiner).

use im::OrdSet;
use skep_address::Address;
use skep_kernel::Snapshot;
use skep_links::{LinkState, View};

use crate::home::home_readable;
use crate::sets::window_over;
use crate::types::{Cursor, FourSet, Window};
use crate::DiscoveryWorld;

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
pub(crate) fn candidates(l: &LinkState, q: &FourSet) -> OrdSet<Address> {
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
pub(crate) fn satisfying<'c>(
    cand: &'c OrdSet<Address>,
    q: &'c FourSet,
) -> impl Iterator<Item = &'c Address> + 'c {
    cand.iter().filter(move |a| q.at_home(a))
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
        .filter(|a| home_readable(readable, a))
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
        .filter(|a| home_readable(readable, a))
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
/// The one place `sat` is spelled apart rather than composed: the window
/// seeks by key — `range` strictly past the cursor — which the candidate SET
/// supports and [`satisfying`]'s filtered sequence does not, so it walks
/// [`candidates`] itself and applies the same residence post-filter LAZILY in
/// its `keep`. The links this pages over are exactly the ones
/// [`findlinks_ftt_on`] returns under the same `readable`, given the
/// predicate's contract the crate header states.
///
/// The home rule (PUB round 2, lane 3.3, §3) joins the residence post-filter
/// in the lazy `keep`, so a link it refuses is skipped before the window
/// slice (PUB-6.14), never counted against `n`.
pub fn window_ftt_on<W: DiscoveryWorld>(
    s: &Snapshot<W>,
    q: &FourSet,
    cur: Cursor,
    n: usize,
    readable: &dyn Fn(&Address) -> bool,
) -> Window {
    let cand = candidates(s.world().links(), q);
    window_over(&cand, cur, n, |a| q.at_home(a) && home_readable(readable, a))
}
