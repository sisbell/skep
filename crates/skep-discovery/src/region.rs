//! §1/§2/§4 — the content-region discovery family (V-anchored, present-tense,
//! doc-gated, disjunctive over slots): `image` (V→I), `findlinks_v`,
//! `count_v`, `window_v`, and RETRIEVEENDSETS. Every result is
//! *foundation ∩ View::Active* = addressable — nullified links never surface
//! (Conflicts #8, a deliberate divergence from ASN-0127/0108's unfiltered
//! `findlinks_V`/`Match`).
//!
//! The shape a request must have lives here too, as the constructor/gate pair
//! [`content_vspan`]/`check_region` — the family that judges a region is the
//! family that publishes how to build one.

use std::collections::HashSet;

use im::OrdSet;
use skep_address::{content_subspace, Address, Nat, Span};
use skep_arrangement::{is_ordinal_vspan, ordinal_vspan, HasM5, Run, VPos};
use skep_kernel::{Snapshot, WorldState};
use skep_links::{Endset, HasLinks};
use skep_namespace::HasM3;

use crate::helpers::{stab_runs, stab_runs_by_slot, union_slots, window_over};
use crate::types::{Cursor, QueryError, Window};

/// The V-span shape every region-family request must have: `count` positions
/// from `at`, in the CONTENT subspace. `None` iff `count = 0` (M1 has no
/// zero-width span) or `at.subspace ≠ s_C` — the two ways a well-formed
/// V-position still names a region M8 refuses.
///
/// The constructing half of the region gate's verdict, so a caller building a
/// request and the gate that judges it cannot come apart: what this builds is
/// accepted, what it declines would be [`QueryError::BadRegion`]. M5's
/// `ordinal_vspan` does the building; the content-subspace clause is the one
/// M8 adds.
pub fn content_vspan(at: &VPos, count: &Nat) -> Option<Span> {
    if at.subspace != content_subspace() {
        return None;
    }
    ordinal_vspan(at, count)
}

/// Region gate: each span must be an ordinal-level depth-2 V-span — M5's
/// [`is_ordinal_vspan`], the shape its `resolve` reads — restricted to the
/// CONTENT subspace, else `BadRegion`. The judging half of the one shape
/// [`content_vspan`] builds.
///
/// The subspace restriction is M8's one added clause; the shape itself is
/// asked of M5 rather than re-derived, since a span M5 declines is folded to
/// ⟨⟩ by `resolve` instead of refused, which would turn the request into a
/// different query (ASN-0127 F-IMG/F-V; the decomposition seam). An empty
/// region trivially passes.
fn check_region(region: &[Span]) -> Result<(), QueryError> {
    for s in region {
        let in_content = s.start().get(1) == Some(&content_subspace());
        if !is_ordinal_vspan(s) || !in_content {
            return Err(QueryError::BadRegion);
        }
    }
    Ok(())
}

/// V→I resolution of `region` through `d`'s live arrangement (ASN-0127
/// image = `W ∩ dom M(d)` — unarranged positions contribute nothing; M5's
/// `resolve` clips silently, which the up-front gates make harmless).
///
/// The document-existence gate is the first act (`DocNotRegistered` — M5
/// conflates registered-empty with unallocated), immediately followed by the
/// region gate (`BadRegion`). A registered-but-empty `d` yields a defined
/// `Ok(vec![])`.
///
/// The result is the I-runs of the image, in region-span order and V-order
/// within each span, deduped by `Run: Eq`. The dedup compares each run
/// against those already kept, so it costs quadratically in the image size —
/// which the caller's region chooses.
///
/// Exact-`Run` equality is the extent of the set claim: overlapping INPUT
/// region spans may still yield partially-overlapping runs (not an
/// address-disjoint partition — don't sum widths for |image|; coalescing
/// would need the run-level span algebra M8 deliberately avoids).
pub fn image_on<W>(s: &Snapshot<W>, d: &Address, region: &[Span]) -> Result<Vec<Run>, QueryError>
where
    W: WorldState + HasLinks + HasM5 + HasM3,
{
    let w = s.world();
    if !w.m3().is_registered_document(d) {
        return Err(QueryError::DocNotRegistered);
    }
    check_region(region)?;
    let mut runs: Vec<Run> = Vec::new();
    for span in region {
        for r in w.m5().resolve(d, span) {
            if !runs.contains(&r) {
                runs.push(r);
            }
        }
    }
    Ok(runs)
}

/// The shared selection index of the V-anchored family: the disjunctive
/// ASN-0127 `findlinks(image(W,d))` ∩ the active view (View::Active internally
/// == addressable == `dom(L)` ∖ nullified), as M7's native `OrdSet<Address>`
/// (address order — ASN-0108's permanent enumeration key).
pub(crate) fn findlinks_v_set_on<W>(
    s: &Snapshot<W>,
    d: &Address,
    region: &[Span],
) -> Result<OrdSet<Address>, QueryError>
where
    W: WorldState + HasLinks + HasM5 + HasM3,
{
    let img = image_on(s, d, region)?; // gate + region-check + resolve, on THIS snap
    Ok(stab_runs(s.world(), &img))
}

/// Links touching `region` (ASN-0127 findlinks over the image, disjunctive
/// across slots `{FROM, TO, TYPE}` — exact by the v1 arity-3 invariant).
/// result = foundation ∩ active (`View::Active`) — nullified links never
/// surface; diverges from ASN-0127's UNFILTERED `findlinks_V` (Conflicts #8).
pub fn findlinks_v_on<W>(
    s: &Snapshot<W>,
    d: &Address,
    region: &[Span],
) -> Result<Vec<Address>, QueryError>
where
    W: WorldState + HasLinks + HasM5 + HasM3,
{
    Ok(findlinks_v_set_on(s, d, region)?.iter().cloned().collect())
}

/// Present-tense census of region-reaching links; result = foundation ∩
/// active. Non-monotone (ASN-0127 D-NONMONO); a `0` asserts present
/// unreachability over the active view, not history (D-ZERO).
pub fn count_v_on<W>(s: &Snapshot<W>, d: &Address, region: &[Span]) -> Result<usize, QueryError>
where
    W: WorldState + HasLinks + HasM5 + HasM3,
{
    Ok(findlinks_v_set_on(s, d, region)?.len())
}

/// Windowed enumeration of the region family (ASN-0108, the
/// `Match = findlinks_V` reading); result = foundation ∩ active — nullified
/// links never surface. `n = 0` is clamped to 1 (the API is total, W9).
pub fn window_v_on<W>(
    s: &Snapshot<W>,
    d: &Address,
    region: &[Span],
    cur: Cursor,
    n: usize,
) -> Result<Window, QueryError>
where
    W: WorldState + HasLinks + HasM5 + HasM3,
{
    let m = findlinks_v_set_on(s, d, region)?; // gate + region-check inside
    Ok(window_over(&m, cur, n, |_| true))
}

/// RETRIEVEENDSETS (ASN-0131): the `(slot, endset)` pairs touching `region`,
/// WITHHOLDING link identity (RE-UNIT) — value-identical endsets from
/// distinct links collapse to one pair. Endsets are surfaced WHOLE — the full
/// stored value from `readlink`, never clipped (RE-CLIP/RE-WHOLE, preserving
/// RE-UDIST) — and content-identity (I-address; V-rendering is a lossy layer
/// above). Slot attribution is read off M7's per-slot stab sets — `(i, eᵢ)`
/// surfaces iff `a ∈ stab(i, q, Active)` — so M7's overlap verdict
/// (ProperOverlap | Containment | Equal, never Adjacent) is the ONLY touch
/// test and cross-subspace disjointness (RE-NCD) is discharged by M7. Output
/// order is pinned (slot, then lexicographic span-sequence): deterministic at
/// a snapshot, no hash-iteration leak; the internal dedup is a throwaway
/// `std::collections::HashSet`, so no `im` container crosses this seam.
pub fn retrieve_endsets_on<W>(
    s: &Snapshot<W>,
    d: &Address,
    region: &[Span],
) -> Result<Vec<(usize, Endset)>, QueryError>
where
    W: WorldState + HasLinks + HasM5 + HasM3,
{
    let w = s.world();
    let img = image_on(s, d, region)?; // gate + region-check inside, on THIS snap
    let slots = stab_runs_by_slot(w, &img); // KEPT SEPARATE — slot i of a touches iff a ∈ its set
    let cand = union_slots(&slots);
    let mut out: HashSet<(usize, Endset)> = HashSet::new(); // internal throwaway dedup by structural Eq
    for c in cand.iter() {
        let link = w.links().readlink(c).expect("stab keys are resident links");
        for (i, set) in &slots {
            if set.contains(c) {
                let e = link
                    .slot(*i)
                    .expect("a link in slot i's stab set has slot i: M7's per-slot overlap is false for an absent slot");
                out.insert((*i, e.clone())); // WHOLE endset, no clip
            }
        }
    }
    let mut pairs: Vec<(usize, Endset)> = out.into_iter().collect();
    pairs.sort_by(|(i, e), (j, f)| {
        i.cmp(j).then_with(|| {
            e.spans()
                .map(|sp| (sp.start(), sp.width()))
                .cmp(f.spans().map(|sp| (sp.start(), sp.width())))
        })
    });
    Ok(pairs)
}
