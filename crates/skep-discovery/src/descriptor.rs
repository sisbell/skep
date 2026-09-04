//! §3 — the four-set descriptor family (ASN-0121/0132): address-keyed,
//! conjunctive, link-store-local (FL-LOC — no document gate), monotone absent
//! retraction (FL-MON/CN-MONO). Not a restriction of the region family and
//! not built on it (ASN-0121 is explicit; Conflicts #2) — the same per-slot
//! `stab` combined oppositely (AND vs OR), with the AND owned by M7's
//! `match_links` (Conflicts #1: M8 implements no combiner).

use im::OrdSet;
use skep_address::Address;
use skep_arrangement::HasM5;
use skep_kernel::{Snapshot, WorldState};
use skep_links::{HasLinks, View};
use skep_namespace::HasM3;

use crate::helpers::window_over;
use crate::types::{Cursor, FourSet, Window};

/// The conjunctive core: the descriptor's constrained LINK slots handed to
/// M7's AND-of-ORs over the ACTIVE view, and no constraints at all (`(∗,∗,∗)`)
/// reading as the whole active slice. The descriptor reads its own slots —
/// which are the zero, which drop out — in [`FourSet::link_constraints`]; the
/// home slot is not a link slot and is filtered by [`FourSet::home_admits`]
/// at each call site.
///
/// The unsatisfiable case returns without touching the store. M7 would answer
/// the same way if it could be asked — `stab(slot, ⟨⟩, ·) = ∅` empties the
/// AND — but an `Empty` slot carries no endset to ask WITH, so this is where
/// FL-EMP is answered for the link slots, not merely where it is anticipated.
pub(crate) fn match_core<W: HasLinks>(w: &W, q: &FourSet) -> OrdSet<Address> {
    match q.link_constraints() {
        None => OrdSet::new(), // FL-EMP: some slot is the zero
        Some(cons) => w.links().match_links(&cons, View::Active),
    }
}

/// FINDLINKS over the four-set descriptor (ASN-0121): the links matching the
/// conjunction, home post-filtered (Conflicts #7 — M8 owns no index
/// dimension; a home-only query degrades to a full active scan, accepted).
/// Total — no doc gate (FL-LOC). `(∗,∗,∗,∗)` = the whole addressable slice
/// (FL-WILD); any constrained-empty slot ⇒ `[]` (FL-EMP). Monotone absent
/// retraction (FL-MON): a found link stays found unless nullified.
pub fn findlinks_ftt_on<W>(s: &Snapshot<W>, q: &FourSet) -> Vec<Address>
where
    W: WorldState + HasLinks + HasM5 + HasM3,
{
    match_core(s.world(), q)
        .iter()
        .filter(|a| q.home_admits(a)) // a: &&Address derefs to home_admits' &Address
        .cloned()
        .collect()
}

/// The count operation over the descriptor family (ASN-0132 CN-*): the
/// existence census — monotone absent retraction (CN-MONO). Exactly
/// `findlinks_ftt(q).len()` at the same snapshot.
pub fn count_ftt_on<W>(s: &Snapshot<W>, q: &FourSet) -> usize
where
    W: WorldState + HasLinks + HasM5 + HasM3,
{
    match_core(s.world(), q)
        .iter()
        .filter(|a| q.home_admits(a))
        .count()
}

/// Windowed enumeration over the descriptor family (ASN-0108, the
/// `Match = findlinks_FTT` reading — the same cursor mechanism as `window_v`
/// instantiated over the conjunctive family). The home filter is applied
/// LAZILY during the range walk, so a home-narrow query never materializes
/// the full filtered set. `n = 0` is clamped to 1 (total API, W9).
pub fn window_ftt_on<W>(s: &Snapshot<W>, q: &FourSet, cur: Cursor, n: usize) -> Window
where
    W: WorldState + HasLinks + HasM5 + HasM3,
{
    let m = match_core(s.world(), q);
    window_over(&m, cur, n, |a| q.home_admits(a))
}
