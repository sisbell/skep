//! §1 — the region's shape and its V→I resolution: `image`, the one door the
//! region family reads through. It resolves a region through `d`'s reading
//! surface behind the document gate, the region gate and the two budgets that
//! price what the region asks of M5; it names no link and stabs nothing, so
//! it is the family's door and not a member.
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
    ordinal_vspan(at, count)
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

/// How many runs M5's `resolve` walks past for the spans of `region`, over a
/// run-list `run_count` runs long, summed, saturating. It walks each span's
/// list from the first run and stops at the first run starting at or past the
/// ordinal of the span's REACH, `e` — M1's `reach`, which for an ordinal
/// V-span is `ordinal + count` — and every run is at least one position wide,
/// so one span passes at most `min(run_count, e − 1)`. A REACH ORDINAL that
/// does not fit a `usize` prices at `run_count` — the most any walk passes,
/// never zero.
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
/// publishes, and exactly its equality.
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
/// and the sum over the region is what is priced — in RUNS, so a deep read of
/// a long document holding few runs is never refused for its depth.
///
/// Then refuses past [`MAX_IMAGE_RUNS`] with `ImageTooLarge`, priced BEFORE
/// each span resolves against the most it could yield — never against the
/// distinct runs kept — so an over-budget request stops resolving instead of
/// resolving whole and then being measured: M5 hands one span's whole image
/// back in a single `Vec`, so a budget behind the call can only refuse what
/// is already built. That ceiling is `min(count, #runs(surface))` —
/// `resolve` clips to the span, and every run it returns is at least one
/// position wide — so what the request makes M8 hold is bounded by the
/// request's own shape, and the ACCEPTED SET is the ceiling's:
/// `Σ min(countᵢ, #runs(surface)) ≤ MAX_IMAGE_RUNS`, not the image's. A
/// request whose image would be small is therefore refused when its spans
/// name more positions than the surface has runs to answer them with. A
/// refusal, never a truncation: a truncated image drops links from every
/// read-out composed on it, silently.
///
/// The count taken AFTER each resolve is the backstop on the one fact the
/// ceiling borrows and M8 cannot check: that M5's `resolve` clips to the
/// span and returns runs at least one position wide. While that holds the
/// ceiling subsumes it and it cannot fire; it is kept because the guarantee
/// is M5's, and a ceiling that silently under-estimated would truncate an
/// image — the one thing this budget exists to refuse.
///
/// So a span naming more positions than [`MAX_IMAGE_RUNS`] is refused over a
/// surface holding more runs than that, whatever its image would have been.
/// Over a surface of at most that many runs a single span is admitted
/// whatever its count, and a single position over any surface the WALK
/// admits — [`QueryError::ImageTooLarge`] states that limit: a single
/// position is refused only over a reading surface of more than
/// `MAX_IMAGE_RUNS²` content runs. A region past the ceiling is asked in
/// parts, which is the recourse [`QueryError`] states.
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
    // The surface's run count, off M5's own `#runs` — one map lookup, reading
    // no run — because both budgets below are priced against it.
    let run_count = w.m5().content_run_count(&surface);
    // The walk, priced against a run-list of unbounded length first — its
    // reach in positions — and in the surface's runs only past that. A region
    // whose reach in positions is within the square walks within it whatever
    // the document, so the ordinary request is admitted without the region
    // being walked a second time.
    if run_list_walk(region, usize::MAX) > MAX_JOIN_STEPS
        && run_list_walk(region, run_count) > MAX_JOIN_STEPS
    {
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
        // The most runs this span CAN yield: one per position it names, one
        // per run of the surface, whichever is fewer — `resolve` clips to the
        // span and every run it hands back is at least one position wide.
        // Read BEFORE the call, because the call builds that whole image into
        // one `Vec` and a budget behind it can only refuse what is already
        // built. A `count` past `usize` prices at the run count, the most any
        // span can yield; so does a span the region gate has already admitted
        // and this reading cannot re-read.
        let ceiling = as_ordinal_vspan(span)
            .and_then(|v| v.count.to_usize())
            .map_or(run_count, |count| count.min(run_count));
        if runs_resolved.saturating_add(ceiling) > MAX_IMAGE_RUNS {
            return Err(QueryError::ImageTooLarge);
        }
        let span_image = w.m5().resolve(&surface, span);
        runs_resolved += span_image.len();
        // The backstop, not the measure: the ceiling above has already
        // admitted this span against the most it could yield, so this fires
        // only if M5's clip returned more than the span named. `>` and not
        // `==` because one span's image adds many runs at once.
        if runs_resolved > MAX_IMAGE_RUNS {
            return Err(QueryError::ImageTooLarge);
        }
        for r in span_image {
            if seen.insert(r.clone()) {
                runs.push(r);
            }
        }
    }
    Ok(runs)
}
