//! §1/§2/§4 — the content-region discovery family (V-anchored, present-tense,
//! doc-gated, disjunctive over slots): `image` (V→I), `findlinks_v`,
//! `count_v`, `window_v`, and RETRIEVEENDSETS. Every result is ASN-0131's
//! selection index `sel = findlinks_V ∩ addressable`, read out four ways —
//! nullified links never surface (Conflicts #8, a deliberate divergence from
//! ASN-0127/0108's unfiltered `findlinks_V`/`Match`).
//!
//! The shape a request must have lives here too, as the constructor/gate pair
//! [`content_vspan`]/`check_region` — the family that judges a region is the
//! family that publishes how to build one — and so do the family's two
//! budgets, [`MAX_IMAGE_RUNS`] and [`MAX_ENDSET_SPANS`], each a refusal rather
//! than a truncation: a truncated answer would silently drop links, which is
//! the one thing every read here exists to not do.

use std::collections::HashSet;

use im::OrdSet;
use skep_address::{content_subspace, Address, Nat, Span};
use skep_arrangement::{is_ordinal_vspan, ordinal_vspan, reading_surface, Run, VPos};
use skep_kernel::Snapshot;
use skep_links::Endset;

use crate::helpers::{stab_runs, stab_runs_by_slot, union_slots, window_over};
use crate::types::{Cursor, QueryError, Window};
use crate::DiscoveryWorld;

/// The most arrangement I-runs one request may make M8 materialize or join
/// against, and so the ceiling on the multiplier the REQUEST applies to the
/// world-sized scan behind it.
///
/// ONE constant, held at the three sites that read a document's runs, each
/// against the run count that site's OWN work multiplies — so the number is
/// one and the quantities are three:
///
/// * [`image_on`] counts the runs the REGION resolves, which is a
///   request-shaped multiple of `#runs(d)`, so whether a `d` is refused
///   depends on the region asked and not on `d` alone;
/// * [`crate::project_on`] counts `#content_runs(d)`, because M5's `project`
///   joins the coverage against the content runs alone;
/// * [`crate::addressably_discoverable_from_on`] counts
///   `#content_runs(d) + #link_runs(d)`, because LP12 ranges over both
///   subspaces and every one of those extents is tested.
///
/// So the three refuse DIFFERENT documents, and the inclusions run only one
/// way: the pointwise pair's counts differ by `d`'s link runs, so a `d`
/// `project_on` answers about may be one
/// [`crate::addressably_discoverable_from_on`] refuses, and neither relates
/// to `image_on`'s verdict, which the caller's region moves. Each site
/// prices the factor it multiplies; the budget is what a request may
/// multiply the world's fragmentation by, not a verdict about `d`.
///
/// The budget: the runs become one side of a join in every case — lifted into
/// a query `Endset` for M7's `stab`, which walks the whole store testing
/// every query span against every slot span of every link; lifted into an
/// I-extent apiece for the pointwise touch test; handed to M5's `project`,
/// which states the cost as `#runs(d) × |coverage|` and leaves admission
/// control to its caller. `2^12` is this workspace's existing answer for how
/// large one side of a join may be (M6's COMPARE operand and its coverage
/// budget both). It is also M7's `MAX_SLOT_SPANS`, the ceiling a STORED slot
/// is held to — a query endset costs more than a stored one, never less — and
/// M10's per-array wire cap, so a FLAT region of 4096 spans each resolving to
/// one run, the largest region the transport admits, is admitted unchanged.
///
/// What it refuses is the shape no wire cap prices: the region×image product,
/// where each admitted span resolves to the whole of a fragmented document.
///
/// THE GRANULARITY IS A REGION SPAN, as M6's coverage budget's is: the walk
/// stops at the first span whose image carries the accumulator past the
/// budget, so an over-budget request stops resolving rather than resolving
/// whole and then being measured. Within one span it bounds nothing — M5's
/// `resolve` answers that span whole, at a size that is the DOCUMENT's
/// fragmentation rather than the request's shape.
///
/// `#runs(d)` and `|links|` are the WORLD's, and no number here reaches them:
/// they stay with request rate and concurrency, which are M10's as the
/// request lifecycle's owner.
pub const MAX_IMAGE_RUNS: usize = 1 << 12;

/// The most spans one RETRIEVEENDSETS answer may carry, and so the ceiling on
/// what the pair set makes M8 hold live and what the presentation sorts.
///
/// The budget: a pair's cost is its spans, and the answer's is their sum —
/// the sort is `O(B log B)` span comparisons over `B` accumulated spans (a
/// comparison walks two span sequences to their first difference, so a long
/// endset pays its length once rather than once per comparison), each span
/// two `Tumbler`s. `2^16` is M5's `MAX_PLACED_RUNS` and M6's
/// `MAX_COMPARE_PAIRS` — the substrate's existing answer to how large one
/// REPORT may be.
///
/// Not `MAX_IMAGE_RUNS`: that budget bounds one side of a join a caller
/// supplies, and this bounds an answer the STORE supplies. One deposit may
/// legitimately carry `MAX_SLOT_SPANS` = `2^12` spans in a single slot, so a
/// `2^12` answer budget would refuse a region touched by two such links —
/// while `2^16` admits some twenty thousand ordinary small-endset links
/// through one region.
///
/// WHAT IT DOES NOT BOUND: `|links|` and any one link's endset size are the
/// WORLD's, so the candidate walk this budget rides on is world-sized whatever
/// the number — the same division M6 draws — and the answer's marshalled form
/// is M10's, which owns no ceiling of its own beyond the one this bounds.
pub const MAX_ENDSET_SPANS: usize = 1 << 16;

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
    for span in region {
        let in_content = span.start().get(1) == Some(&content_subspace());
        if !is_ordinal_vspan(span) || !in_content {
            return Err(QueryError::BadRegion);
        }
    }
    Ok(())
}

/// V→I resolution of `region` through `d`'s live arrangement (ASN-0127
/// image = `W ∩ dom M(d)` — unarranged positions contribute nothing; M5's
/// `resolve` clips silently, which the up-front gates make harmless).
///
/// REFUSES, IN THIS ORDER: `DocNotRegistered` — the document-existence gate
/// is the first act, M5 conflating registered-empty with unallocated — then
/// the region gate (`BadRegion`), then the budget (`ImageTooLarge`), which
/// comes third because it is priced on what the region RESOLVES to and so
/// cannot be asked until both gates have admitted the request. A
/// registered-but-empty `d` yields a defined `Ok(vec![])`.
///
/// The result is the I-runs of the image, in region-span order and V-order
/// within each span, deduped on `(i_start, width)` — the pair a `Run`
/// publishes, and exactly its equality. The key is spelled out because `Run`
/// is neither `Hash` nor `Ord` (M5's); keying rather than scanning is what
/// keeps the dedup one probe per resolved run, so the cost is linear in an
/// image size the caller's region chooses rather than square in it.
///
/// Exact-`Run` equality is the extent of the set claim: overlapping INPUT
/// region spans may still yield partially-overlapping runs (not an
/// address-disjoint partition — don't sum widths for |image|; coalescing
/// would need the run-level span algebra M8 deliberately avoids).
///
/// Refuses past [`MAX_IMAGE_RUNS`] with `ImageTooLarge`, counted over the
/// runs RESOLVED rather than the distinct ones kept, because that is the
/// quantity every later step is linear in — and counted AS THE IMAGE IS
/// PRODUCED, so an over-budget request stops resolving instead of resolving
/// whole and then being measured. A refusal, never a truncation: a truncated
/// image drops links from every read-out composed on it, silently.
///
/// HEAD-FLOAT (PUB round 2, lane 3.2; PUB-2.49, PUB-2.50, PUB-2.53): the
/// arrangement resolved is `d`'s READING SURFACE — M5's `reading_surface`,
/// the one pin — so a bare PUBLISHED address images its trunk head, a version
/// address its own member forever, and a memberless or private document its
/// own arrangement. The whole region family inherits it through this
/// function: `findlinks_v`, `count_v`, `window_v` and `retrieve_endsets`
/// float exactly as `image` does. The registry gate runs on the address
/// named, ahead of the float (PUB-6.37).
pub fn image_on<W: DiscoveryWorld>(
    s: &Snapshot<W>,
    d: &Address,
    region: &[Span],
) -> Result<Vec<Run>, QueryError> {
    let w = s.world();
    if !w.m3().is_registered_document(d) {
        return Err(QueryError::DocNotRegistered);
    }
    check_region(region)?;
    let surface = reading_surface(w.m3(), d);
    let mut runs: Vec<Run> = Vec::new();
    let mut seen: HashSet<(Address, Nat)> = HashSet::new(); // internal throwaway
    let mut runs_resolved: usize = 0;
    for span in region {
        let span_image = w.m5().resolve(&surface, span);
        // `>` and not `==`: one span's image adds many runs at once.
        runs_resolved += span_image.len();
        if runs_resolved > MAX_IMAGE_RUNS {
            return Err(QueryError::ImageTooLarge);
        }
        for r in span_image {
            if seen.insert((r.i_start().clone(), r.width().clone())) {
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
pub(crate) fn findlinks_v_set_on<W: DiscoveryWorld>(
    s: &Snapshot<W>,
    d: &Address,
    region: &[Span],
) -> Result<OrdSet<Address>, QueryError> {
    let image = image_on(s, d, region)?; // gate + region-check + resolve, on THIS snap
    Ok(stab_runs(s.world().links(), &image))
}

/// Links touching `region` (ASN-0127 findlinks over the image, disjunctive
/// across slots `{FROM, TO, TYPE}` — exact by the v1 arity-3 invariant), in
/// ASCENDING ADDRESS ORDER: ASN-0108's permanent enumeration key, so this
/// enumerates in the order [`window_v_on`] pages by.
/// result = `findlinks_V ∩ addressable` (`View::Active`) — nullified links
/// never surface; diverges from ASN-0127's UNFILTERED `findlinks_V`
/// (Conflicts #8).
///
/// REFUSES what [`image_on`] refuses, in its order: `DocNotRegistered`,
/// `BadRegion`, `ImageTooLarge`. There is no fourth refusal — a registered
/// `d` with a well-formed region always answers, ∅ included.
pub fn findlinks_v_on<W: DiscoveryWorld>(
    s: &Snapshot<W>,
    d: &Address,
    region: &[Span],
) -> Result<Vec<Address>, QueryError> {
    Ok(findlinks_v_set_on(s, d, region)?.into_iter().collect())
}

/// Present-tense census of region-reaching links; the cardinality of
/// `findlinks_V ∩ addressable`. Non-monotone (ASN-0127 D-NONMONO); a `0`
/// asserts present unreachability over the active view, not history (D-ZERO)
/// — the region family's zero, distinct from [`crate::count_ftt_on`]'s
/// store-wide CN-ZERO.
///
/// REFUSES what [`image_on`] refuses, in its order: `DocNotRegistered`,
/// `BadRegion`, `ImageTooLarge`. The zero above is therefore a census and
/// never a stand-in for a refusal: an unregistered `d` errs rather than
/// counting 0, which is precisely the distinction a caller collapsing this
/// `Result` to a number would lose.
pub fn count_v_on<W: DiscoveryWorld>(
    s: &Snapshot<W>,
    d: &Address,
    region: &[Span],
) -> Result<usize, QueryError> {
    Ok(findlinks_v_set_on(s, d, region)?.len())
}

/// Windowed enumeration of the region family (ASN-0108, the
/// `Match = findlinks_V` reading); result = `findlinks_V ∩ addressable` —
/// nullified links never surface. `n = 0` is clamped to 1 (the API is total,
/// W9).
///
/// EVERY `Address` IS A LEGAL CURSOR, and none is checked: resume is a
/// key-cut strictly past `cur`, never a lookup of it, so a cursor naming a
/// link that has since been nullified or has left the region still resumes
/// at the right place (W8), and no continuously-matching link is skipped or
/// duplicated (W4/W5). A caller relaying a cursor from a request owes it no
/// validation — validating would refuse exactly the case the key-cut exists
/// to serve.
///
/// REFUSES what [`image_on`] refuses, in its order: `DocNotRegistered`,
/// `BadRegion`, `ImageTooLarge`. A refusal is never reported as an empty
/// exhausted window.
pub fn window_v_on<W: DiscoveryWorld>(
    s: &Snapshot<W>,
    d: &Address,
    region: &[Span],
    cur: Cursor,
    n: usize,
) -> Result<Window, QueryError> {
    let sel = findlinks_v_set_on(s, d, region)?; // gate + region-check inside
    Ok(window_over(&sel, cur, n, |_| true))
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
///
/// Refuses past [`MAX_ENDSET_SPANS`] with `EndsetsTooLarge`, accumulated over
/// the spans of the pairs actually KEPT — what the answer carries is what the
/// budget prices, so the identity-withholding collapse counts once, as it
/// ships once — and checked AS THE ANSWER IS PRODUCED, so an over-budget
/// request stops accumulating and never reaches the sort. A refusal, never a
/// truncation: a short answer would silently withhold endsets that touch the
/// region, which is the one thing RE-UNIT does not license.
///
/// REFUSES, IN THIS ORDER: [`image_on`]'s three — `DocNotRegistered`,
/// `BadRegion`, `ImageTooLarge` — and then this read's own
/// `EndsetsTooLarge`, which comes last because it is priced on what the
/// store hands back and so cannot be known until the image is in hand.
pub fn retrieve_endsets_on<W: DiscoveryWorld>(
    s: &Snapshot<W>,
    d: &Address,
    region: &[Span],
) -> Result<Vec<(usize, Endset)>, QueryError> {
    let w = s.world();
    let image = image_on(s, d, region)?; // gate + region-check inside, on THIS snap
    let by_slot = stab_runs_by_slot(w.links(), &image); // KEPT SEPARATE — slot i of a touches iff a ∈ its set
    let sel = union_slots(&by_slot);
    let mut kept: HashSet<(usize, Endset)> = HashSet::new(); // internal throwaway dedup by structural Eq
    let mut spans_kept: usize = 0;
    for c in sel.iter() {
        let link = w.links().readlink(c).expect("stab keys are resident links");
        for (i, hits) in &by_slot {
            if hits.contains(c) {
                let e = link
                    .slot(*i)
                    .expect("a link in slot i's stab set has slot i: M7's per-slot overlap is false for an absent slot");
                if kept.insert((*i, e.clone())) {
                    // WHOLE endset, no clip
                    spans_kept += e.len();
                    if spans_kept > MAX_ENDSET_SPANS {
                        return Err(QueryError::EndsetsTooLarge);
                    }
                }
            }
        }
    }
    let mut pairs: Vec<(usize, Endset)> = kept.into_iter().collect();
    pairs.sort_by(|(i, e), (j, f)| {
        i.cmp(j).then_with(|| {
            e.spans()
                .map(|sp| (sp.start(), sp.width()))
                .cmp(f.spans().map(|sp| (sp.start(), sp.width())))
        })
    });
    Ok(pairs)
}
