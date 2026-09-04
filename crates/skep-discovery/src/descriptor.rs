//! §3 — the four-set descriptor family (ASN-0121/0132): address-keyed,
//! conjunctive, link-store-local (FL-LOC — no document gate), monotone absent
//! retraction (FL-MON/CN-MONO). Not a restriction of the region family and
//! not built on it (ASN-0121 is explicit; Conflicts #2) — the same per-slot
//! `stab` combined oppositely (AND vs OR), with the AND owned by M7's
//! `match_links` (Conflicts #1: M8 implements no combiner).

use im::OrdSet;
use skep_address::Address;
use skep_kernel::Snapshot;
use skep_links::{LinkState, View};

use crate::helpers::window_over;
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
pub(crate) fn candidates(l: &LinkState, q: &FourSet) -> OrdSet<Address> {
    match q.link_constraints() {
        None => OrdSet::new(), // FL-EMP: some slot is the zero
        Some(cons) => l.match_links(&cons, View::Active),
    }
}

/// `sat(·, q, Σ)` — THE one definition of "matches" for the descriptor
/// family. ASN-0132's CN-ENUM forces exactly one, consumed by enumeration and
/// by count alike, so [`findlinks_ftt_on`] and [`count_ftt_on`] are two
/// read-outs of this one set and cannot disagree about which links match.
///
/// ASN-0121's [`candidates`] narrowed by the residence post-filter
/// [`FourSet::at_home`] — the home-bound placement M8 chose, since M8 owns no
/// index dimension keyed on `home(a)` (Conflicts #7: a home-only query
/// degrades to a full active scan, accepted).
pub(crate) fn satisfying(l: &LinkState, q: &FourSet) -> OrdSet<Address> {
    candidates(l, q)
        .into_iter()
        .filter(|a| q.at_home(a))
        .collect()
}

/// FINDLINKS over the four-set descriptor (ASN-0121): the links satisfying
/// the descriptor, in address order. Total — no doc gate (FL-LOC).
/// `(∗,∗,∗,∗)` = the whole addressable slice (FL-WILD); any constrained-empty
/// slot ⇒ `[]` (FL-EMP). Monotone absent retraction (FL-MON): a found link
/// stays found unless nullified.
pub fn findlinks_ftt_on<W: DiscoveryWorld>(s: &Snapshot<W>, q: &FourSet) -> Vec<Address> {
    satisfying(s.world().links(), q).into_iter().collect()
}

/// The count operation over the descriptor family (ASN-0132 CN-*): the
/// existence census — monotone absent retraction (CN-MONO). The cardinality
/// of the same `sat` set [`findlinks_ftt_on`] enumerates, so CN-ENUM's
/// `count = |enumeration|` holds by construction rather than by promise.
///
/// CN-ZERO: a returned `0` is a verdict over the WHOLE addressable store —
/// no addressable link satisfies `q` — never present unreachability (which is
/// [`crate::count_v_on`]'s D-ZERO) and never an exhaustion artefact of a scan
/// that gave up. The third zero, the degenerate request that names nothing,
/// is answerable off the descriptor alone through
/// [`FourSet::is_unsatisfiable`]: same number, different assertion.
pub fn count_ftt_on<W: DiscoveryWorld>(s: &Snapshot<W>, q: &FourSet) -> usize {
    satisfying(s.world().links(), q).len()
}

/// Windowed enumeration over the descriptor family (ASN-0108, the
/// `Match = findlinks_FTT` reading — the same cursor mechanism as `window_v`
/// instantiated over the conjunctive family). `n = 0` is clamped to 1 (total
/// API, W9).
///
/// The one place `sat` is spelled apart rather than composed: the same
/// candidate conjunction, then the same residence post-filter, but applied
/// LAZILY during the range walk — so a home-narrow query never materializes
/// the filtered set. The links this pages over are exactly the ones
/// [`findlinks_ftt_on`] returns.
pub fn window_ftt_on<W: DiscoveryWorld>(
    s: &Snapshot<W>,
    q: &FourSet,
    cur: Cursor,
    n: usize,
) -> Window {
    let cand = candidates(s.world().links(), q);
    window_over(&cand, cur, n, |a| q.at_home(a))
}
