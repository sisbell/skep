//! §1 — the region's shape and its V→I resolution: `image`, ASN-0127's
//! REGION RESOLVER — the first phase of every region-family read, which
//! chains it into M7's matcher (`findlinks ∘ image`). It resolves a region
//! through `d`'s reading surface behind the document gate, the region gate
//! and the run budget with its square, which price what the region asks of
//! M5; it names no link, stabs nothing and asks no reader, so it is the
//! family's resolver and not a member.
//!
//! The shape a request must have lives here too, as the constructor/gate pair
//! [`content_vspan`]/`check_region` — the module that judges a region is the
//! module that publishes how to build one.

use std::collections::HashSet;

use num_traits::ToPrimitive;
use skep_address::{Address, Nat, Span};
use skep_arrangement::{as_ordinal_vspan, ordinal_vspan, reading_surface, Run, VPos};
use skep_kernel::Snapshot;

use crate::budget::{MAX_IMAGE_RUNS, MAX_JOIN_STEPS};
use crate::types::QueryError;
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
    if !at.is_content() {
        return None;
    }
    ordinal_vspan(at.clone(), count.clone())
}

/// Region gate: each span must be an ordinal-level depth-2 V-span — M5's
/// `as_ordinal_vspan`, the reading its `resolve` folds on, asked with its
/// content clause — restricted to the CONTENT subspace, else `BadRegion`.
/// The judging half of the one shape [`content_vspan`] builds.
///
/// The subspace restriction is M8's one added clause; the shape itself is
/// asked of M5 rather than re-derived, since a span M5 declines is folded to
/// ⟨⟩ by `resolve` instead of refused, which would turn the request into a
/// different query (ASN-0127 F-IMG/F-V; the decomposition seam). An empty
/// region trivially passes.
fn check_region(region: &[Span]) -> Result<(), QueryError> {
    for span in region {
        if !as_ordinal_vspan(span).is_some_and(|v| v.is_content()) {
            return Err(QueryError::BadRegion);
        }
    }
    Ok(())
}

/// How many runs M5's `iter_resolve` walks past for the spans of `region`,
/// over a run-list `run_count` runs long, summed, saturating — every run left
/// of a span's opening ordinal, as M5's card on `iter_resolve` states, and
/// then the runs it yields. It walks each span's list from the first run and
/// stops at the first run starting at or past the ordinal of the span's
/// REACH, `e` — M1's `reach`, which for an ordinal V-span is
/// `ordinal + count` — and every run is at least one position wide, so one
/// span passes at most `min(run_count, e − 1)`. A REACH ORDINAL that does not
/// fit a `usize` prices at `run_count` — the most any walk passes, never zero.
fn run_list_walk(region: &[Span], run_count: usize) -> usize {
    region.iter().fold(0usize, |steps, span| {
        let passed = as_ordinal_vspan(span)
            .and_then(|v| (v.ordinal + v.count).to_usize())
            .map_or(run_count, |e| e.saturating_sub(1).min(run_count));
        steps.saturating_add(passed)
    })
}

/// V→I resolution of `region` through `d`'s READING SURFACE (ASN-0127's
/// image read there: `W ∩ dom M(reading_surface(d))`, which is `W ∩ dom M(d)`
/// itself wherever `d` is its own reading surface — unarranged positions
/// contribute nothing; M5's `iter_resolve` clips silently, which the up-front
/// gates make harmless).
///
/// REFUSES, IN THIS ORDER: `DocNotRegistered` — the document-existence gate
/// is the first act, M5 conflating registered-empty with unallocated — then
/// the region gate (`BadRegion`), then the run budget and its square
/// (`ImageTooLarge`) — the square holding the walk the region asks of M5, the
/// budget the runs it resolves — which come third because each is priced on
/// what the region does to `d`'s reading surface, and so cannot be asked
/// until both gates have admitted the request. A registered `d` whose reading
/// surface arranges no content yields a defined `Ok(vec![])` — a bare
/// published `d` that has a member answers from its trunk head, whatever its
/// own arrangement holds.
///
/// The result is the I-runs of the image, in region-span order and V-order
/// within each span, deduped on `(i_start, width)` — the pair a `Run`
/// publishes, and exactly its equality.
///
/// Exact-`Run` equality is the extent of the set claim: overlapping INPUT
/// region spans may still yield partially-overlapping runs (not an
/// address-disjoint partition — don't sum widths for |image|; coalescing
/// would need the run-level span algebra M8 deliberately avoids).
///
/// Refuses with `ImageTooLarge` when the RUN-LIST WALK is past the square of
/// [`MAX_IMAGE_RUNS`], before the first pull: M5 reaches each span by walking
/// the surface's content run-list from its first run (M5 states that walk on
/// `iter_resolve`'s card), so a span reaching `e` passes at most
/// `min(#runs, e − 1)` runs whatever it returns, and the sum over the region
/// is what is priced — in RUNS, so a span reaching far into a long document
/// that holds few runs is never refused for its reach.
///
/// Then refuses past [`MAX_IMAGE_RUNS`] with `ImageTooLarge`, counted over the
/// runs the region RESOLVES — summed across its spans, never the distinct
/// runs kept — as they are PULLED from M5's lazy `iter_resolve`, the form M5
/// publishes for a consumer that carries a budget of its own. The run past the
/// budget is refused as it is pulled, before the next is built, so what a
/// request makes M8 hold is the budget and the one run that trips it — never
/// a span's whole image, however fragmented the surface. A refusal, never a
/// truncation: a truncated image drops links from every read-out composed on
/// it, silently.
///
/// So the accepted set is the image's: a region is answered when its walk is
/// within the square and its spans resolve at most [`MAX_IMAGE_RUNS`] runs,
/// whatever positions they name. A single position is refused only over a
/// reading surface of more than `MAX_IMAGE_RUNS²` content runs, so a region
/// past the budget can be asked in parts — the recourse [`QueryError`] states.
///
/// HEAD-FLOAT (PUB round 2, lane 3.2; PUB-2.49, PUB-2.50, PUB-2.53): the
/// arrangement resolved is `d`'s READING SURFACE — M5's `reading_surface`,
/// the one place the float is decided. The whole region family inherits it
/// through this function: `findlinks_v`, `count_v`, `window_v` and
/// `retrieve_endsets` float exactly as `image` does. The document gate runs
/// on the address named, ahead of the float (PUB-6.37).
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
    // The surface's run count, off M5's own `#runs` — one map lookup, reading
    // no run — because the walk is priced against it: M5's card on
    // `iter_resolve` names `#runs` that walk's ceiling.
    let run_count = w.m5().content_run_count(&surface);
    if run_list_walk(region, run_count) > MAX_JOIN_STEPS {
        return Err(QueryError::ImageTooLarge);
    }
    let mut runs: Vec<Run> = Vec::new();
    // Keyed on the run itself — its start AND its width, which is what `Run`'s
    // `Eq` and `Hash` compare — and keying rather than scanning is what keeps
    // the dedup one probe per resolved run, so the cost is linear in an image
    // size the caller's region chooses rather than square in it.
    let mut seen: HashSet<Run> = HashSet::new();
    let mut runs_resolved: usize = 0;
    for span in region {
        // Pulled, and counted as it is pulled: M5's `iter_resolve` builds each
        // run only when asked for it, so the run past the budget is refused
        // before the next exists, and M8 holds at most the budget and the run
        // that trips it.
        for r in w.m5().iter_resolve(&surface, span) {
            runs_resolved += 1;
            if runs_resolved > MAX_IMAGE_RUNS {
                return Err(QueryError::ImageTooLarge);
            }
            if seen.insert(r.clone()) {
                runs.push(r);
            }
        }
    }
    Ok(runs)
}
