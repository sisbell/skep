//! §1/§2/§4 — the content-region discovery family (V-anchored, present-tense,
//! doc-gated, disjunctive over slots): `image` (V→I), `findlinks_v`,
//! `count_v`, `window_v`, and RETRIEVEENDSETS. Every result is ASN-0131's
//! selection index `sel = findlinks_V ∩ addressable`, read out four ways —
//! nullified links never surface (Conflicts #8, a deliberate divergence from
//! ASN-0127/0108's `findlinks_V`/`Match`, which no addressability filter
//! narrows).
//!
//! The shape a request must have lives here too, as the constructor/gate pair
//! [`content_vspan`]/`check_region` — the family that judges a region is the
//! family that publishes how to build one.

use std::collections::HashSet;

use im::OrdSet;
use num_traits::ToPrimitive;
use skep_address::{content_subspace, Address, Nat, Span};
use skep_arrangement::{is_ordinal_vspan, ordinal_vspan, reading_surface, Run, VPos};
use skep_kernel::Snapshot;
use skep_links::Endset;

use crate::budget::{MAX_ENDSET_SPANS, MAX_IMAGE_RUNS, MAX_JOIN_STEPS};
use crate::home::home_readable;
use crate::sets::{stab_runs, stab_runs_by_slot, union_slots, window_over};
use crate::types::{Cursor, QueryError, Window};
use crate::DiscoveryWorld;

/// The V-span shape every region-family request must have: `count` positions
/// from `at`, in the CONTENT subspace. `None` iff `count = 0` (M1 has no
/// zero-width span) or `at.subspace ≠ s_C` — the two ways a well-formed
/// V-position still names a region M8 refuses.
///
/// The constructing half of the region gate's verdict, so a caller building a
/// request and the gate that judges it cannot come apart: what this builds
/// the region gate accepts, and what it declines would be
/// [`QueryError::BadRegion`]. That is the gate's verdict alone — the budgets
/// still judge the request the spans form, so a region built wholly here can
/// still be refused `ImageTooLarge`. M5's `ordinal_vspan` does the building;
/// the content-subspace clause is the one M8 adds.
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

/// How many runs M5's `resolve` walks past for the spans of `region`, over a
/// run-list `run_count` runs long, summed, saturating. It walks each span's
/// list from the first run and stops at the first run starting at or past the
/// span's reach `e`, and every run is at least one position wide, so one span
/// passes at most `min(run_count, e − 1)`. A reach whose ordinal cannot be
/// read, or does not fit a `usize`, prices at `run_count` — the most any walk
/// passes, never zero.
fn run_list_walk(region: &[Span], run_count: usize) -> usize {
    region.iter().fold(0usize, |steps, span| {
        let passed = span
            .reach()
            .get(2)
            .and_then(|e| e.to_usize())
            .map_or(run_count, |e| e.saturating_sub(1).min(run_count));
        steps.saturating_add(passed)
    })
}

/// V→I resolution of `region` through `d`'s READING SURFACE (ASN-0127's
/// image read there: `W ∩ dom M(reading_surface(d))`, which is `W ∩ dom M(d)`
/// itself wherever `d` is its own reading surface — unarranged positions
/// contribute nothing; M5's `resolve` clips silently, which the up-front
/// gates make harmless).
///
/// REFUSES, IN THIS ORDER: `DocNotRegistered` — the document-existence gate
/// is the first act, M5 conflating registered-empty with unallocated — then
/// the region gate (`BadRegion`), then the two budgets (`ImageTooLarge`),
/// which come third because each is priced on what the region does to `d`'s
/// reading surface — the walk it asks of M5, the runs it resolves — and so
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
/// Refuses with `ImageTooLarge` when the RUN-LIST WALK is past the square of
/// [`MAX_IMAGE_RUNS`], before the first `resolve`: M5 reaches each span by
/// walking the surface's content run-list from its first run, so a span
/// reaching `e` passes at most `min(#runs, e − 1)` runs whatever it returns,
/// and the sum over the region is what is priced. A region whose reach in
/// positions is within the square walks within it whatever the document, so
/// the ordinary request is admitted without the surface's runs being
/// counted; past that the count is taken — M5 publishes none, so it is the
/// surface's content runs read whole, the cost [`crate::project_on`] pays on
/// every call — and the walk is priced in RUNS, so a deep read of a long
/// document holding few runs is never refused for its depth.
///
/// Then refuses past [`MAX_IMAGE_RUNS`] with `ImageTooLarge`, counted over
/// the runs RESOLVED rather than the distinct ones kept, because that is the
/// quantity every later step is linear in — and counted AS THE IMAGE IS
/// PRODUCED, so an over-budget request stops resolving instead of resolving
/// whole and then being measured. A refusal, never a truncation: a truncated
/// image drops links from every read-out composed on it, silently.
///
/// HEAD-FLOAT (PUB round 2, lane 3.2; PUB-2.49, PUB-2.50, PUB-2.53): the
/// arrangement resolved is `d`'s READING SURFACE — M5's `reading_surface`,
/// the one pin. The whole region family inherits it through this function:
/// `findlinks_v`, `count_v`, `window_v` and `retrieve_endsets` float exactly
/// as `image` does. The document gate runs on the address named, ahead of the
/// float (PUB-6.37).
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
    // The walk, priced against a run-list of unbounded length first — its
    // reach in positions — and in the surface's runs only past that.
    if run_list_walk(region, usize::MAX) > MAX_JOIN_STEPS
        && run_list_walk(region, w.m5().content_runs(&surface).len()) > MAX_JOIN_STEPS
    {
        return Err(QueryError::ImageTooLarge);
    }
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
/// never surface; diverges from ASN-0127's `findlinks_V` over all of
/// `dom(L)` (Conflicts #8).
///
/// REFUSES what [`image_on`] refuses, in its order — `DocNotRegistered`,
/// `BadRegion`, `ImageTooLarge` — and nothing else: a request none of the
/// three refuses is answered, ∅ included. A registered `d` and a well-formed
/// region (one built through [`content_vspan`] included) get past only the
/// first two; the budgets still judge what the region asks of `d`'s surface,
/// so a caller that has checked both must still handle `ImageTooLarge`.
///
/// The result-set filter (PUB round 2, lane 3.3, §3; PUB-6.13): every link
/// whose HOME `readable` refuses is DROPPED, at link IDENTITY, before the
/// caller sees it. M7's link readers stay principal-free (Conflicts #1); the
/// filter is M8's, applied over the selection index.
pub fn findlinks_v_on<W: DiscoveryWorld>(
    s: &Snapshot<W>,
    d: &Address,
    region: &[Span],
    readable: &dyn Fn(&Address) -> bool,
) -> Result<Vec<Address>, QueryError> {
    let sel = findlinks_v_set_on(s, d, region)?;
    Ok(sel.iter().filter(|a| home_readable(readable, a)).cloned().collect())
}

/// Present-tense census of region-reaching links; the cardinality of
/// `findlinks_V ∩ addressable`. Non-monotone (ASN-0127 D-NONMONO); a `0`
/// asserts that, over the active view, no link the reader may see is
/// presently reachable — not history (D-ZERO) — the region family's zero,
/// distinct from [`crate::count_ftt_on`]'s store-wide CN-ZERO.
///
/// REFUSES what [`image_on`] refuses, in its order: `DocNotRegistered`,
/// `BadRegion`, `ImageTooLarge`. The zero above is therefore a census and
/// never a stand-in for a refusal: an unregistered `d` errs rather than
/// counting 0, which is precisely the distinction a caller collapsing this
/// `Result` to a number would lose.
///
/// The cardinality is the FILTERED one (PUB round 2, lane 3.3, §3;
/// PUB-6.19): of the links the home rule admits, by ENUMERATION — the same
/// set [`findlinks_v_on`] returns under the same `readable`, counted rather
/// than collected, so the two cannot disagree given a predicate that answers
/// each home the same way in both calls (the crate header states the
/// predicate's contract).
pub fn count_v_on<W: DiscoveryWorld>(
    s: &Snapshot<W>,
    d: &Address,
    region: &[Span],
    readable: &dyn Fn(&Address) -> bool,
) -> Result<usize, QueryError> {
    let sel = findlinks_v_set_on(s, d, region)?;
    Ok(sel.iter().filter(|a| home_readable(readable, a)).count())
}

/// Windowed enumeration of the region family (ASN-0108, the
/// `Match = findlinks_V` reading); result = `findlinks_V ∩ addressable` —
/// nullified links never surface. `n = 0` is clamped to 1 (the API is total,
/// W9); a window holds at most `max(n, 1)` links, and [`Window`] states what
/// a window and a pass return.
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
///
/// The result-set filter (PUB round 2, lane 3.3, §3): the home rule is
/// applied LAZILY during the key-cut, at link identity and BEFORE the window
/// slice (PUB-6.14), so a link it refuses is skipped rather than counted
/// against `n`.
pub fn window_v_on<W: DiscoveryWorld>(
    s: &Snapshot<W>,
    d: &Address,
    region: &[Span],
    cur: Cursor,
    n: usize,
    readable: &dyn Fn(&Address) -> bool,
) -> Result<Window, QueryError> {
    let sel = findlinks_v_set_on(s, d, region)?; // gate + region-check inside
    Ok(window_over(&sel, cur, n, |a| home_readable(readable, a)))
}

/// RETRIEVEENDSETS (ASN-0131): the `(slot, endset)` pairs touching `region`,
/// WITHHOLDING link identity (RE-UNIT) — value-identical endsets from
/// distinct links collapse to one pair. Endsets are surfaced WHOLE — the full
/// stored value from `readlink`, never clipped (RE-CLIP/RE-WHOLE, preserving
/// RE-UDIST) — and content-identity (I-address; V-rendering is a lossy layer
/// above). Slot attribution is read off M7's per-slot stab sets — `(i, eᵢ)`
/// surfaces iff `a ∈ stab(i, query, Active)` — so M7's overlap verdict
/// (ProperOverlap | Containment | Equal, never Adjacent) is the ONLY touch
/// test and cross-subspace disjointness (RE-NCD) is discharged by M7. Output
/// order is pinned (slot, then lexicographic span-sequence): deterministic at
/// a snapshot, no hash-iteration leak; the internal dedup is a throwaway
/// `std::collections::HashSet`, so no `im` container crosses this seam, and it
/// is keyed on borrows into the snapshot's store, so a pair is copied once,
/// when it ships.
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
///
/// The result-set filter (PUB round 2, lane 3.3, §3; PUB-6.15): filtered at
/// link HOME, UNFILTERED at origin — a link whose home the reader may not
/// read contributes no pair, but a surviving link's endset is surfaced WHOLE,
/// its spans never masked by their origin. So the home rule is asked at the
/// CANDIDATE link's identity, once, before its slots are read.
pub fn retrieve_endsets_on<W: DiscoveryWorld>(
    s: &Snapshot<W>,
    d: &Address,
    region: &[Span],
    readable: &dyn Fn(&Address) -> bool,
) -> Result<Vec<(usize, Endset)>, QueryError> {
    let w = s.world();
    let image = image_on(s, d, region)?; // gate + region-check inside, on THIS snap
    let by_slot = stab_runs_by_slot(w.links(), &image); // KEPT SEPARATE — slot i of a touches iff a ∈ its set
    let sel = union_slots(&by_slot);
    let mut kept: HashSet<(usize, &Endset)> = HashSet::new(); // dedup by structural Eq, borrowing the store's endsets
    let mut spans_kept: usize = 0;
    for a in sel.iter() {
        // The home rule, at the candidate link's identity (§3): a link whose
        // home is unreadable contributes no pair. Its endset — if it survived —
        // is unfiltered at origin (PUB-6.15).
        if !home_readable(readable, a) {
            continue;
        }
        let link = w.links().readlink(a).expect("stab keys are resident links");
        for (i, hits) in &by_slot {
            if hits.contains(a) {
                let e = link
                    .slot(*i)
                    .expect("a link in slot i's stab set has slot i: M7's per-slot overlap is false for an absent slot");
                if kept.insert((*i, e)) {
                    // WHOLE endset, no clip
                    spans_kept += e.len();
                    if spans_kept > MAX_ENDSET_SPANS {
                        return Err(QueryError::EndsetsTooLarge);
                    }
                }
            }
        }
    }
    let mut pairs: Vec<(usize, &Endset)> = kept.into_iter().collect();
    // Unstable is exact here: the pairs are distinct, and the comparator is
    // equal only on equal pairs — slot, then each span's `(start, width)`,
    // which is the whole of `Span`'s equality — so no two elements tie.
    pairs.sort_unstable_by(|(i, e), (j, f)| {
        i.cmp(j).then_with(|| {
            e.spans()
                .map(|sp| (sp.start(), sp.width()))
                .cmp(f.spans().map(|sp| (sp.start(), sp.width())))
        })
    });
    Ok(pairs.into_iter().map(|(i, e)| (i, e.clone())).collect())
}
