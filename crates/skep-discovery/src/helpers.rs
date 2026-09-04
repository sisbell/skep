//! §Internal design — the shared free helpers every family composes: the
//! run-set stab that turns an arrangement image into matched links, the home
//! attribution, and the one windowing combinator. All pure over borrowed
//! state; nothing here snapshots (callers thread ONE snapshot per operation).

use std::ops::Bound::{Excluded, Unbounded};

use im::OrdSet;
use skep_address::{document_of, Address};
use skep_arrangement::Run;
use skep_links::{Endset, HasLinks, View};

use crate::types::{Cursor, Window};
use crate::{FROM, TO, TYPE};

/// The slots a v1 link has: every v1 link-creation path deposits an arity-3
/// link, so a disjunction over these three is exact over ALL slots and a
/// per-slot read misses nothing (§1). Nothing in M8 can check that — `stab`
/// is per-slot and M8 owns no index — so it is stated once, here, and every
/// slot-indexed read reaches the store through this list.
pub(crate) const V1_SLOTS: [usize; 3] = [FROM, TO, TYPE];

/// The links whose coverage overlaps `runs`, PAIRED with the slot each set
/// was stabbed at and kept SEPARATE (slot attribution reads them — §4), so
/// no consumer re-derives which position means which numeral.
/// `View::Active` discharges addressability — nullified links never match.
///
/// The lift from arrangement runs to M7's query `Endset` lives here, so every
/// region-shaped query reaches the spanfilade through one reading of its
/// I-extents. That endset aggregates iextents across origin documents and is
/// therefore MIXED-LENGTH by construction; no partition by level class is
/// owed because its only consumer is M7's `classify_spans` overlap, which is
/// gate-free — any level-gated operation added here (normalizing the query,
/// keying a cache on `canonical_key`) would owe the partition `Run::iextent`
/// names. Empty `runs` skip the store: M7 answers `stab(slot, ⟨⟩, ·) = ∅`
/// for the endset they lift to, so the short-circuit saves a scan rather than
/// changing an answer.
pub(crate) fn stab_runs_by_slot<W: HasLinks>(
    w: &W,
    runs: &[Run],
) -> [(usize, OrdSet<Address>); 3] {
    if runs.is_empty() {
        return V1_SLOTS.map(|i| (i, OrdSet::new()));
    }
    let q = Endset::from_spans(runs.iter().map(Run::iextent)); // coverage(q) = the runs
    V1_SLOTS.map(|i| (i, w.links().stab(i, &q, View::Active)))
}

/// The disjunctive ASN-0127 `findlinks(I)` core: OR across a v1 link's slots
/// (M7 has no slot-collapsed primitive). `im`'s sets are persistent, so
/// collapsing a borrowed triple costs sharing, not copies.
pub(crate) fn union_slots(slots: &[(usize, OrdSet<Address>); 3]) -> OrdSet<Address> {
    slots
        .iter()
        .fold(OrdSet::new(), |acc, (_, set)| acc.union(set.clone()))
}

/// `findlinks(coverage of runs)` ∩ the active view, as M7's native
/// `OrdSet<Address>` (address order — ASN-0108's permanent enumeration key):
/// the selection index every run-anchored family reads.
pub(crate) fn stab_runs<W: HasLinks>(w: &W, runs: &[Run]) -> OrdSet<Address> {
    union_slots(&stab_runs_by_slot(w, runs))
}

/// `home(a)`: the origin Document of a link address — M1's `document_of`
/// projection (EL8b), spelled once so the descriptor family's home filter and
/// the lineage read-out attribute a link the same way.
pub(crate) fn home_of(a: &Address) -> Address {
    document_of(a).expect("a link address has zeros = 3, so its origin Document exists")
}

/// The one windowing combinator (ASN-0108) driving both `window_v` and
/// `window_ftt`: a stateless key-cut over `candidates` in address order,
/// admitting those `keep` accepts. A family whose match IS its candidate set
/// (the region family) passes `keep = |_| true`.
///
/// * Resume is `range(Excluded(cursor)..)` — a key-cut, never an exact-match
///   scan, so the cursor survives orphaning by construction (W8), and no
///   continuously-matching link is duplicated or skipped (W4/W5).
/// * `n` is clamped to ≥ 1 (W9 totality): an unclamped `n = 0` would yield
///   `exhausted = (0 < 0) = false` with an empty batch and an unchanged
///   cursor — a silent non-terminating signal.
/// * `keep` applies a post-filter LAZILY during the range walk (the FTT
///   residence test), so a narrow query never materializes the filtered set.
/// * `exhausted = batch.len() < n` (a short window, zero included, W9);
///   `next` = the ≺-max of the batch, else the cursor unchanged.
pub(crate) fn window_over(
    candidates: &OrdSet<Address>,
    cur: Cursor,
    n: usize,
    keep: impl Fn(&Address) -> bool,
) -> Window {
    let n = n.max(1);
    let lo = match &cur {
        None => Unbounded,
        Some(c) => Excluded(c.clone()),
    };
    let batch: Vec<Address> = candidates
        .range((lo, Unbounded))
        .filter(|a| keep(a)) // a: &&Address → deref to &Address
        .take(n)
        .cloned()
        .collect();
    let next = batch.last().cloned().or(cur);
    Window {
        exhausted: batch.len() < n,
        batch,
        next,
    }
}
