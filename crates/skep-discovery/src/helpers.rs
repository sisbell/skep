//! §Internal design — the shared free helpers every family composes: the
//! per-slot/union Active stabs, the region gate, and the one windowing
//! combinator. All pure over borrowed state; nothing here snapshots (callers
//! thread ONE snapshot per operation).

use std::ops::Bound::{Excluded, Unbounded};

use im::OrdSet;
use num_traits::{One, Zero};
use skep_address::{Address, Nat, Span};
use skep_links::{Endset, HasLinks, View};

use crate::types::{Cursor, QueryError, Window};
use crate::{FROM, TO, TYPE};

/// Per-slot Active stabs over `{FROM, TO, TYPE}`, kept SEPARATE (slot
/// attribution reads them — §4). Exact over ALL slots by the v1 arity-3
/// invariant (§1: every v1 link-creation path deposits an arity-3 link).
/// `View::Active` discharges addressability — nullified links never match.
pub(crate) fn stab_slots<W: HasLinks>(w: &W, q: &Endset) -> [OrdSet<Address>; 3] {
    [FROM, TO, TYPE].map(|i| w.links().stab(i, q, View::Active))
}

/// The disjunctive ASN-0127 `findlinks(I)` core ∩ the active view: OR across
/// slots `{FROM, TO, TYPE}` (M7 has no slot-collapsed primitive).
pub(crate) fn stab_union<W: HasLinks>(w: &W, q: &Endset) -> OrdSet<Address> {
    let [f, t, y] = stab_slots(w, q);
    f.union(t).union(y)
}

/// Region gate: each span must be a CONTENT-subspace, ordinal-level, depth-2
/// V-span (`start[1] = s_C = 1`, `width[1] = 0`), else `BadRegion` — M5's
/// `resolve` silently clips or folds a malformed span to ⟨⟩, which would turn
/// the request into a different query (ASN-0127 F-IMG/F-V; the decomposition
/// seam). An empty region trivially passes.
pub(crate) fn check_region(region: &[Span]) -> Result<(), QueryError> {
    for s in region {
        let (st, wd) = (s.start(), s.width());
        let ok = st.len() == 2
            && wd.len() == 2
            && st.get(1) == Some(&Nat::one())
            && wd.get(1).is_some_and(|w| w.is_zero());
        if !ok {
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
