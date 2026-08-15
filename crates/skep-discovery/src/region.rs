//! §1/§2/§4 — the content-region discovery family (V-anchored, present-tense,
//! doc-gated, disjunctive over slots): `image` (V→I), `findlinks_v`,
//! `count_v`, `window_v`, and RETRIEVEENDSETS. Every result is
//! *foundation ∩ View::Active* = addressable — nullified links never surface
//! (Conflicts #8, a deliberate divergence from ASN-0127/0108's unfiltered
//! `findlinks_V`/`Match`).

use std::collections::HashSet;

use im::OrdSet;
use skep_address::{validate, Address, Span, Tumbler};
use skep_arrangement::{HasM5, Run};
use skep_kernel::{Snapshot, WorldState};
use skep_links::{Endset, HasLinks};
use skep_namespace::HasM3;

use crate::helpers::{addrs, check_region, stab_slots, stab_union, window_over};
use crate::types::{Cursor, QueryError, Window};
use crate::{FROM, TO, TYPE};

/// V→I resolution of `region` through `d`'s live arrangement (ASN-0127
/// image = `W ∩ dom M(d)` — unarranged positions contribute nothing; M5's
/// `resolve` clips silently, which the up-front gates make harmless).
///
/// The document-existence gate is the first act (`DocNotRegistered` — M5
/// conflates registered-empty with unallocated), immediately followed by the
/// region gate (`BadRegion`). A registered-but-empty `d` yields a defined
/// `Ok(vec![])`.
///
/// Deduped at the boundary by `Run: Eq` — no exact-equal `Run` repeat. That
/// is the extent of the set claim: overlapping INPUT region spans may still
/// yield partially-overlapping runs (not an address-disjoint partition —
/// don't sum widths for |image|; coalescing would need the run-level span
/// algebra M8 deliberately avoids).
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
/// ASN-0127 `findlinks(image(W,d))` ∩ the active view, as M7's native
/// `OrdSet<Tumbler>` (address order — ASN-0108's permanent enumeration key).
/// F-V empty short-circuit: an empty image touches no index.
pub(crate) fn findlinks_v_set_on<W>(
    s: &Snapshot<W>,
    d: &Address,
    region: &[Span],
) -> Result<OrdSet<Tumbler>, QueryError>
where
    W: WorldState + HasLinks + HasM5 + HasM3,
{
    let w = s.world();
    let img = image_on(s, d, region)?; // gate + region-check + resolve, on THIS snap
    if img.is_empty() {
        return Ok(OrdSet::new());
    }
    let q = Endset::from_spans(img.iter().map(Run::iextent)); // coverage(q) = the image
    Ok(stab_union(w, &q)) // View::Active internally == addressable == dom(L) ∖ nullified
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
    Ok(addrs(&findlinks_v_set_on(s, d, region)?))
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
    if img.is_empty() {
        return Ok(Vec::new());
    }
    let q = Endset::from_spans(img.iter().map(Run::iextent));
    let slots = stab_slots(w, &q); // per-slot stabs KEPT SEPARATE — slot i of a touches iff a ∈ slots[i-1]
    let cand = slots[0]
        .clone()
        .union(slots[1].clone())
        .union(slots[2].clone());
    let mut out: HashSet<(usize, Endset)> = HashSet::new(); // internal throwaway dedup by structural Eq
    for c in cand.iter() {
        let ca = validate(c.clone()).expect("every §G key is T4-valid by M3's mint");
        let link = w.links().readlink(&ca).expect("stab keys are resident links");
        for i in [FROM, TO, TYPE] {
            // = ALL slots in v1 (the arity-3 invariant, §1)
            if slots[i - 1].contains(c) {
                let e = link.slot(i).expect("arity ≥ 3 covers the standard slots");
                out.insert((i, e.clone())); // WHOLE endset, no clip
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
