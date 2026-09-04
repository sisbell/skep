//! §Internal design — the shared free helpers every family composes: the
//! run-set stab that turns an arrangement image into matched links, the home
//! attribution, the region gate, and the one windowing combinator. All pure
//! over borrowed state; nothing here snapshots (callers thread ONE snapshot
//! per operation).

use std::ops::Bound::{Excluded, Unbounded};

use im::OrdSet;
use skep_address::{content_subspace, document_of, Address, Span};
use skep_arrangement::{is_ordinal_vspan, Run};
use skep_links::{Endset, HasLinks, View};

use crate::types::{Cursor, QueryError, Window};
use crate::{FROM, TO, TYPE};

/// The links whose coverage overlaps `runs`, per slot over
/// `{FROM, TO, TYPE}` and kept SEPARATE (slot attribution reads them — §4).
/// Exact over ALL slots by the v1 arity-3 invariant (§1: every v1
/// link-creation path deposits an arity-3 link). `View::Active` discharges
/// addressability — nullified links never match.
///
/// The lift from arrangement runs to M7's query `Endset` lives here, so every
/// region-shaped query reaches the spanfilade through one reading of its
/// I-extents. Empty `runs` skip the store: M7 answers `stab(slot, ⟨⟩, ·) = ∅`
/// for the endset they lift to, so the short-circuit saves a scan rather than
/// changing an answer.
pub(crate) fn stab_runs_by_slot<W: HasLinks>(w: &W, runs: &[Run]) -> [OrdSet<Address>; 3] {
    if runs.is_empty() {
        return [OrdSet::new(), OrdSet::new(), OrdSet::new()];
    }
    let q = Endset::from_spans(runs.iter().map(Run::iextent)); // coverage(q) = the runs
    [FROM, TO, TYPE].map(|i| w.links().stab(i, &q, View::Active))
}

/// The disjunctive ASN-0127 `findlinks(I)` core: OR across slots
/// `{FROM, TO, TYPE}` (M7 has no slot-collapsed primitive). `im`'s sets are
/// persistent, so collapsing a borrowed triple costs sharing, not copies.
pub(crate) fn union_slots(slots: &[OrdSet<Address>; 3]) -> OrdSet<Address> {
    let [f, t, y] = slots;
    f.clone().union(t.clone()).union(y.clone())
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

/// Region gate: each span must be an ordinal-level depth-2 V-span — M5's
/// [`is_ordinal_vspan`], the shape its `resolve` reads — restricted to the
/// CONTENT subspace, else `BadRegion`. The subspace restriction is M8's one
/// added clause; the shape itself is asked of M5 rather than re-derived,
/// since a span M5 declines is folded to ⟨⟩ by `resolve` instead of refused,
/// which would turn the request into a different query (ASN-0127 F-IMG/F-V;
/// the decomposition seam). An empty region trivially passes.
pub(crate) fn check_region(region: &[Span]) -> Result<(), QueryError> {
    for s in region {
        let in_content = s.start().get(1) == Some(&content_subspace());
        if !is_ordinal_vspan(s) || !in_content {
            return Err(QueryError::BadRegion);
        }
    }
    Ok(())
}

/// The one windowing combinator (ASN-0108) driving both `window_v` and
/// `window_ftt`: a stateless key-cut over the matched set in address order.
///
/// * Resume is `range(Excluded(cursor)..)` — a key-cut, never an exact-match
///   scan, so the cursor survives orphaning by construction (W8), and no
///   continuously-matching link is duplicated or skipped (W4/W5).
/// * `n` is clamped to ≥ 1 (W9 totality): an unclamped `n = 0` would yield
///   `exhausted = (0 < 0) = false` with an empty batch and an unchanged
///   cursor — a silent non-terminating signal.
/// * `keep` applies a post-filter LAZILY during the range walk (the FTT home
///   filter), so a narrow query never materializes the full filtered set.
/// * `exhausted = batch.len() < n` (a short window, zero included, W9);
///   `next` = the ≺-max of the batch, else the cursor unchanged.
pub(crate) fn window_over(
    matched: &OrdSet<Address>,
    cur: Cursor,
    n: usize,
    keep: impl Fn(&Address) -> bool,
) -> Window {
    let n = n.max(1);
    let lo = match &cur {
        None => Unbounded,
        Some(c) => Excluded(c.clone()),
    };
    let batch: Vec<Address> = matched
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
