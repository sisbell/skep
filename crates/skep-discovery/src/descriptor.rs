//! §3 — the four-set descriptor family (ASN-0121/0132): address-keyed,
//! conjunctive, link-store-local (FL-LOC — no document gate), monotone absent
//! retraction (FL-MON/CN-MONO). Not a restriction of the region family and
//! not built on it (ASN-0121 is explicit; Conflicts #2) — the same per-slot
//! `stab` combined oppositely (AND vs OR), with the AND owned by M7's
//! `match_links` (Conflicts #1: M8 implements no combiner).

use im::OrdSet;
use skep_address::{document_of, Address};
use skep_arrangement::HasM5;
use skep_kernel::{Snapshot, WorldState};
use skep_links::{Endset, HasLinks, View};
use skep_namespace::HasM3;

use crate::helpers::window_over;
use crate::types::{Cursor, FourSet, SlotSpec, Window};
use crate::{FROM, TO, TYPE};

/// The conjunctive core: annihilate on any constrained-empty slot (FL-EMP —
/// an empty `Spans` endset ≡ `Empty`, so M7's `match_links` is NEVER handed
/// an empty `Endset`, which it forbids), drop `Any` slots (FL-WILD — omitted,
/// never an empty constraint), and hand the constrained slots to M7's
/// AND-of-ORs over the ACTIVE view. `[]` constraints ⇒ the whole active slice.
pub(crate) fn match_core<W: HasLinks>(w: &W, q: &FourSet) -> OrdSet<Address> {
    for s in [&q.home, &q.from, &q.to, &q.ty] {
        match s {
            SlotSpec::Empty => return OrdSet::new(),
            SlotSpec::Spans(e) if e.is_empty() => return OrdSet::new(),
            _ => {}
        }
    }
    let mut cons: Vec<(usize, &Endset)> = Vec::new();
    if let SlotSpec::Spans(e) = &q.from {
        cons.push((FROM, e)); // e non-empty (checked above)
    }
    if let SlotSpec::Spans(e) = &q.to {
        cons.push((TO, e));
    }
    if let SlotSpec::Spans(e) = &q.ty {
        cons.push((TYPE, e));
    }
    w.links().match_links(&cons, View::Active)
}

/// `athome(a, H)`: `home(a) ∈ coverage(H)` — an ADDRESS projection via M1's
/// `document_of`, never an arrangement-presence test (CN-STAB: a
/// reverse-orphaned link still satisfies a home-bounded query). `Empty` is
/// already short-circuited in [`match_core`]; the arm here is defensive.
pub(crate) fn home_ok(q: &FourSet, a: &Address) -> bool {
    match &q.home {
        SlotSpec::Any => true,
        SlotSpec::Empty => false,
        SlotSpec::Spans(h) => {
            let doc = document_of(a)
                .expect("a link address has zeros = 3, so its origin Document exists");
            h.covers(doc.tumbler())
        }
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
        .filter(|a| home_ok(q, a)) // a: &&Address derefs to home_ok's &Address
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
    match_core(s.world(), q).iter().filter(|a| home_ok(q, a)).count()
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
    window_over(&m, cur, n, |a| home_ok(q, a))
}
