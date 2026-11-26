//! §1 — the region's shape and its V→I resolution: `image`, ASN-0127's
//! REGION RESOLVER — the first phase of every region-family read, which
//! chains it into M7's matcher (`findlinks ∘ image`). It resolves a region
//! through `d`'s reading surface behind the document gate, the region gate
//! and the run budget with its square, which price what the region asks of
//! M5; it names no link, stabs nothing and asks no reader, so it is the
//! family's resolver and not a member.
//!
//! Beside it, [`image_page_on`], the image a reader asks for itself and no
//! family's resolver: the same gates, the same square and the same count,
//! but past the run budget it answers the page that fits and where the rest
//! begins, and it reads `d`'s own arrangement where asked, the one image
//! that does not float. Its continuation is held to one state here
//! (`continued_surface`), the one check every paged read's continuation
//! passes.
//!
//! The shape a request must have lives here too, as the constructor/gate pair
//! [`content_vspan`]/`check_region` — the module that judges a region is the
//! module that publishes how to build one.

use num_traits::{One, ToPrimitive};
use skep_address::{Address, Level, Nat, Span};
use skep_arrangement::{
    as_ordinal_vspan, ordinal_vspan, published_target, reading_surface, trunk_of, Run, VPos,
};
use skep_kernel::Snapshot;

use crate::budget::{MAX_IMAGE_RUNS, MAX_JOIN_STEPS};
use crate::types::{GoOn, ImagePage, QueryError};
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
/// The result is EVERY RUN the region resolves, in region-span order and
/// V-order within each span: the region's positions in order, never a set.
/// A run the surface places twice is answered at each place, and a span the
/// region names twice is answered twice, so a reader walking the runs end
/// to end finds each position where the surface arranges it. The region
/// family lifts the runs to its query as a set (`sets`' `extents`), a repeat
/// one span of it, so no link answer moves on one.
///
/// Within one span the runs tile the positions it arranges, so their widths
/// sum to that count; across spans they need not, since overlapping INPUT
/// spans yield overlapping runs (not an address-disjoint partition —
/// coalescing would need the run-level span algebra M8 deliberately avoids).
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
/// runs the region RESOLVES — summed across its spans, each of them answered
/// — as they are PULLED from M5's lazy `iter_resolve`, the form M5
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
///
/// [`image_page_on`] is the same resolution for a reader of the image
/// itself: it answers a region past the run budget in pages where this
/// refuses it, and reads `d`'s own arrangement where asked.
pub fn image_on<W: DiscoveryWorld>(
    s: &Snapshot<W>,
    d: &Address,
    region: &[Span],
) -> Result<Vec<Run>, QueryError> {
    let surface = |w: &W| Ok(reading_surface(w.m3(), d));
    image_of(s.world(), d, region, surface, PastBudget::Refused).map(|image| image.runs)
}

/// Returns one page of the V→I image of `region`: what fits, and the go-on.
///
/// It is [`image_on`]'s resolution for a reader of the image itself, never
/// refused for the runs its region resolves. A region resolving at most
/// [`MAX_IMAGE_RUNS`] runs is answered whole, as `image_on` answers it, and
/// `next` is `None`. One resolving more answers its first `MAX_IMAGE_RUNS`
/// runs, every one whole, and `next` names where the rest begins
/// ([`GoOn`]): the V-ordinal the first run not answered sits at, the
/// arrangement the page was read from, and that arrangement's `arranged_at`.
/// The run past the budget is pulled and counted as `image_on` pulls it, so
/// the read holds the page and one run, never the region's whole image.
///
/// **The arrangement read.** With no `cur`: `d`'s reading surface, as
/// `image_on` reads it (PUB-2.49, PUB-2.53), or with `own` the arrangement
/// of the address named, which does not float — at a bare published `d`
/// whose chain has a member, the arrangement `d` held before its first
/// version, frozen since that version's mint (PUB-2.66), which a draft begun
/// before version 1 was copied from and a shot naming `d` as its base reads
/// its extent against. A version member, a private document and a
/// memberless published document are each their own reading surface, and
/// the two answer alike. With `cur`, the arrangement it names.
///
/// **A continuation.** `cur` is the `next` of the page before, whole, and
/// `region` the rest of the region that page was cut from: its first span
/// begins at `cur.at`, the rest of the span the page stopped in, and the
/// spans after it follow. The page is read from `cur.surface`, wherever
/// `d`'s readers float by now, so a page set is one arrangement's:
///
/// * `cur.surface` is `d` itself, or — for a read that floats, of a bare
///   published `d` — a registered member of `d`'s own chain, the only
///   arrangements a first page of this read is answered from. A member
///   reads as its document does (PUB-2.15), so the continuation asks no
///   reader a second time;
/// * where that arrangement takes in-place edits — its document is not
///   published — its `arranged_at` is still `cur.arranged_at`. A published
///   document's arrangement and a member's take a deposit past their end
///   alone, their prefix never moving (PUB-2.43), so they are answered
///   whatever has landed since.
///
/// **Several spans.** They are answered in region order, as `image_on`
/// answers them, and the page ends wherever the budget does: `next.at` is
/// an ordinal of the span the first run not answered belongs to. A reader
/// finds that span as it tells any several-span answer's runs apart, by
/// their widths.
///
/// The document gate runs on the address named, ahead of the float and of
/// the continuation (PUB-6.37). No region-family read resolves through
/// this: they refuse past the budget ([`image_on`]).
///
/// # Errors
///
/// In this order, the first that holds answering:
///
/// 1. [`QueryError::DocNotRegistered`] where `d` names no registered
///    document.
/// 2. [`QueryError::BadRegion`] where a span of `region` is not the shape
///    [`content_vspan`] builds.
/// 3. For a continuation, [`QueryError::BadRegion`] where `cur.surface` is
///    not an arrangement this read of `d` is answered from, or `region`
///    does not begin at `cur.at`.
/// 4. For a continuation, [`QueryError::PageMoved`] where `cur.surface`
///    takes in-place edits and its `arranged_at` is not `cur.arranged_at`.
/// 5. [`QueryError::ImageTooLarge`] where the run-list walk the region asks
///    of the arrangement read is past the square of [`MAX_IMAGE_RUNS`] —
///    never for the runs the region resolves.
pub fn image_page_on<W: DiscoveryWorld>(
    s: &Snapshot<W>,
    d: &Address,
    region: &[Span],
    own: bool,
    cur: Option<&GoOn>,
) -> Result<ImagePage, QueryError> {
    let w = s.world();
    let surface = |w: &W| match cur {
        Some(cur) => continued_surface(w, d, region, own, cur),
        None if own => Ok(d.clone()),
        None => Ok(reading_surface(w.m3(), d)),
    };
    let Resolved { runs, surface, rest } = image_of(w, d, region, surface, PastBudget::Paged)?;
    let next = rest.map(|at| {
        let arranged_at = w.m5().arranged_at(&surface);
        GoOn { at, surface, arranged_at }
    });
    Ok(ImagePage { runs, next })
}

/// Returns the arrangement the continuation `cur` of a read of `d` reads.
///
/// It is the one check a paged read's continuation passes, whichever read
/// it continues: the arrangement `cur` names is one a first page of the
/// read is answered from, `region` goes on where `cur` says the rest
/// begins, and the arrangement is still in the state `cur` names where it
/// can leave it. [`image_page_on`] states each clause.
///
/// **Precondition.** `d` is a registered document and every span of
/// `region` an ordinal V-span: the document gate and the region gate have
/// run. M3's publication read is answered for registered addresses alone
/// (PUB-6.37), and each address it is asked of here is `d`, or a member
/// this function has found registered.
///
/// # Errors
///
/// [`QueryError::BadRegion`] where `cur.surface` is neither `d` nor, for a
/// floating read of a bare published `d`, a registered member of `d`'s own
/// chain, and where `region` holds no span or its first does not begin at
/// `cur.at`; then [`QueryError::PageMoved`] where the document of
/// `cur.surface` is not published and its `arranged_at` is not
/// `cur.arranged_at`.
pub(crate) fn continued_surface<W: DiscoveryWorld>(
    w: &W,
    d: &Address,
    region: &[Span],
    own: bool,
    cur: &GoOn,
) -> Result<Address, QueryError> {
    let m3 = w.m3();
    let named = cur.surface == *d;
    // The trunk head a floating read of the bare document answers from is a
    // member of the trunk's own chain, `d.k`: a daughter chain floats nothing.
    let floated = !own
        && !named
        && trunk_of(d) == *d
        && cur.surface.level() == Level::Document
        && cur.surface.document_field().is_some_and(|field| field.len() == 2)
        && trunk_of(&cur.surface) == *d
        && m3.is_registered_document(&cur.surface)
        && published_target(m3, d);
    if !named && !floated {
        return Err(QueryError::BadRegion);
    }
    let begins =
        region.first().and_then(as_ordinal_vspan).is_some_and(|first| *first.ordinal == cur.at);
    if !begins {
        return Err(QueryError::BadRegion);
    }
    if !published_target(m3, &cur.surface) && w.m5().arranged_at(&cur.surface) != cur.arranged_at {
        return Err(QueryError::PageMoved);
    }
    Ok(cur.surface.clone())
}

/// What the runs a region resolves past the run budget do to its read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PastBudget {
    /// The read is refused `ImageTooLarge`: the region family's resolver.
    Refused,
    /// The read ends its page at the budget and says where the rest begins.
    Paged,
}

/// A region's image over one arrangement, as far as the budget let it run.
struct Resolved {
    /// The runs, in region-span order and V-order within each span.
    runs: Vec<Run>,
    /// The arrangement they were read from.
    surface: Address,
    /// The V-ordinal the first run not answered sits at.
    ///
    /// `Some` exactly where the region resolves a run past the budget and
    /// the read is paged.
    rest: Option<Nat>,
}

/// Returns the image of `region` over the arrangement `surface` picks.
///
/// It is the gates and the resolution every image runs: the document gate,
/// then the region gate, then `surface` asked — after both gates, so it is
/// asked of a registered document and a well-shaped region alone (PUB-6.37)
/// — then the run budget's square and the budget over what that arrangement
/// holds, `past` saying what a run past the budget does. One body, so the
/// images cannot come apart in what they refuse or in which order.
///
/// # Errors
///
/// [`QueryError::DocNotRegistered`], then [`QueryError::BadRegion`], then
/// `surface`'s own refusal, then [`QueryError::ImageTooLarge`] for a walk
/// past the square, and for runs past the budget under
/// [`PastBudget::Refused`].
fn image_of<W: DiscoveryWorld>(
    w: &W,
    d: &Address,
    region: &[Span],
    surface: impl FnOnce(&W) -> Result<Address, QueryError>,
    past: PastBudget,
) -> Result<Resolved, QueryError> {
    if !w.m3().is_registered_document(d) {
        return Err(QueryError::DocNotRegistered);
    }
    check_region(region)?;
    let surface = surface(w)?;
    // The surface's run count, off M5's own `#runs` — one map lookup, reading
    // no run — because the walk is priced against it: M5's card on
    // `iter_resolve` names `#runs` that walk's ceiling.
    let run_count = w.m5().content_run_count(&surface);
    if run_list_walk(region, run_count) > MAX_JOIN_STEPS {
        return Err(QueryError::ImageTooLarge);
    }
    let mut runs: Vec<Run> = Vec::new();
    for span in region {
        // The V-ordinal the next run pulled sits at: M5 clips a span to the
        // positions from 1, and the runs it yields tile them from there
        // (D-SEQ★), so each run begins where the one before it ends.
        let mut at = as_ordinal_vspan(span)
            .map_or_else(Nat::one, |v| std::cmp::max(v.ordinal.clone(), Nat::one()));
        // Pulled, and counted as it is pulled: M5's `iter_resolve` builds each
        // run only when asked for it, so the run past the budget is met
        // before the next exists, and M8 holds at most the budget and the run
        // that trips it. Every run pulled before it is answered, so the
        // answer's length is the count.
        for r in w.m5().iter_resolve(&surface, span) {
            if runs.len() == MAX_IMAGE_RUNS {
                return match past {
                    PastBudget::Refused => Err(QueryError::ImageTooLarge),
                    PastBudget::Paged => Ok(Resolved { runs, surface, rest: Some(at) }),
                };
            }
            at += r.width();
            runs.push(r);
        }
    }
    Ok(Resolved { runs, surface, rest: None })
}
