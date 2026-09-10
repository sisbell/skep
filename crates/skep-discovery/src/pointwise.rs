//! §5 — pointwise projection & discoverability (content subspace): `project`
//! (ASN-0098 I→V, through M5's level-class-safe `project`) and
//! `addressably_discoverable_from` (ASN-0098's LP12 discoverability narrowed
//! to ASN-0121/0132's addressable population, `dom(L) ∖ nullified`). The two
//! read the active view differently, and deliberately:
//! `addressably_discoverable_from` conjoins `is_active`, while `project`
//! reports the recorded coverage M7's `followlink` hands over, retracted
//! links included.
//!
//! Both are DOC-GATED, as the region family is: `d` must be M3-registered,
//! and that is the first act of each — a registered-but-empty `d` yields a
//! defined answer (∅ / `Ok(false)`), an unregistered one yields
//! `DocNotRegistered`, and drawing those apart is the gate's whole purpose.
//! Each read states its own refusal order, since a call can be faulty in `d`
//! and in `a` at once and only one verdict speaks.
//!
//! Both read `d`'s READING SURFACE (HEAD-FLOAT — PUB-2.49, PUB-2.50,
//! PUB-2.53): M5's `reading_surface`, the one pin, which [`crate::image_on`]
//! routes the whole region family through as well. So the pair answers about
//! the arrangement a reader of `d` sees, and agrees with the region family
//! about which links reach `d`: a link `findlinks_v` finds through `d` is one
//! `addressably_discoverable_from` calls reachable from it. The document gate
//! runs on the address named, ahead of the float (PUB-6.37).
//!
//! Both take the caller's DOCUMENT predicate and apply the ABSENCE RULE
//! (PUB-6.6) — the home rule asked of `a`'s home: neither answer names a
//! link, so there is no result set to filter, and a link the reader may not
//! see is instead ABSENT as an argument.
//!
//! The per-link `classify_spans` touch test here is M8's one
//! pointwise span comparison — a level-gate-free order relation, total on
//! cross-length spans, categorically distinct from the level-gated set
//! algebra M8 avoids.

use skep_address::{classify_spans, Address, Span, SpanRel, SpanSet};
use skep_arrangement::reading_surface;
use skep_kernel::Snapshot;
use skep_links::Endset;

use crate::budget::{MAX_IMAGE_RUNS, MAX_JOIN_STEPS};
use crate::home::home_readable;
use crate::types::QueryError;
use crate::DiscoveryWorld;

/// May a join of `span_count` coverage spans against `run_count` arrangement
/// runs go ahead? The pair's one budget rule, held at both reads: the runs at
/// [`MAX_IMAGE_RUNS`], since they are read whole and joined before any test
/// answers, and the product — the span tests the join makes — at its square,
/// since the coverage side is the link's and a run count does not reach it.
fn join_within_budget(span_count: usize, run_count: usize) -> bool {
    run_count <= MAX_IMAGE_RUNS && span_count.saturating_mul(run_count) <= MAX_JOIN_STEPS
}

/// I→V projection of link `a`'s `slot` into the CONTENT subspace of the
/// arrangement a reader of `d` sees (ASN-0098 `project`).
///
/// NOT ADDRESSABLE-FILTERED — the one read here that is not narrowed to the
/// active view. The coverage comes from M7's `followlink`, which takes no
/// `View` and reports what is recorded, so a NULLIFIED link's slot still
/// projects to the V-positions it covers. That is ASN-0098's `project`, which
/// knows nothing of retraction; the addressable-filtered question — is this
/// link discoverable AND active? — is [`addressably_discoverable_from_on`],
/// and a caller who wants "the live links reaching here" asks that or the
/// region family, not this.
///
/// CONTENT-SUBSPACE ONLY — strictly weaker than ASN-0098's subspace-agnostic
/// `project`: a link reachable solely through `d`'s LINK subspace projects ∅
/// here (a non-empty projection witnesses discoverability through content
/// only; LP12's biconditional holds only within the content subspace). The
/// link-subspace POSITIONAL projection that would close that gap is NOT M7's
/// BH3 (BH3 is typed reverse *lookup*, target→sources — it yields no
/// V-positions); it is the scoped-out contextual EL11a, composed above M8.
///
/// HEAD-FLOAT: the arrangement projected into is `d`'s reading surface, so
/// the result is in the V-coordinates [`crate::image_on`] resolves for the
/// same `d`.
///
/// The ABSENCE RULE (PUB round 2, lane 3.3, §2; PUB-6.6) — the home rule
/// asked of the ARGUMENT `a`, because the answer names no link: a link whose
/// home `readable` refuses is ABSENT, and answers `Err(NotALink)` — exactly
/// what an address naming no link gets. The rule runs after the document gate
/// and AHEAD of the resident-link read. After, so the pair's precedence
/// holds: an unregistered `d` names the document fault, whatever `a` is.
/// Ahead, so a refused link and an address naming nothing under the same
/// unreadable document answer alike, and the answer says nothing about that
/// document's link chain. `d`'s own readability is the caller's doc-argument
/// consult (pre-dispatch), not this read's; an `a` with no document field has
/// no home to withhold, and the store answers for it.
///
/// REFUSES, IN THIS ORDER: `DocNotRegistered` (`d` is not M3-registered);
/// `NotALink` for an absent `a`, then for an `a` that names no link or a
/// `slot` out of range; then `ImageTooLarge`. The order is the pair's, not
/// this function's — every argument about `d` is settled before any argument
/// about `a` — so a call that is faulty in two ways names the document fault.
/// `NotALink` subsumes BOTH `a ∉ dom(L)` AND an out-of-range `slot` (M7's
/// `followlink` conflates them; a `BadSlot` split is deferred — it would cost
/// an extra `readlink` to read arity).
///
/// The result is a NORMALIZED set of depth-2 content V-spans
/// (`[s_C, ordinal] × [0, count]`) in the reading surface's V-coordinates,
/// M5's `project` guarantee handed back verbatim — so a caller reads the
/// covered positions straight off the spans. The two probe routes are
/// `SpanSet` membership (`denotes(&[s_C, k])` over the surface's content
/// positions, cross-checkable via M5's `point`) and `SpanSet::is_empty`,
/// which is total where the level-gated set comparisons can fault. M8 itself
/// never tests the projection for emptiness.
///
/// COST, IN TWO FACTORS: M5 states the work as `#runs(d) × |coverage|` and
/// leaves admission control to its caller, which is this function, and both
/// are held here (`ImageTooLarge`). `#runs(d)` is held at
/// [`crate::MAX_IMAGE_RUNS`], counted over the reading surface's CONTENT
/// runs — the runs M5's `project` actually joins against, so the factor
/// priced is the factor multiplied — and the product at that budget's square.
/// [`crate::MAX_IMAGE_RUNS`] sets the run count beside the other three.
pub fn project_on<W: DiscoveryWorld>(
    s: &Snapshot<W>,
    a: &Address,
    slot: usize,
    d: &Address,
    readable: &dyn Fn(&Address) -> bool,
) -> Result<SpanSet, QueryError> {
    let w = s.world();
    if !w.m3().is_registered_document(d) {
        return Err(QueryError::DocNotRegistered);
    }
    if !home_readable(readable, a) {
        return Err(QueryError::NotALink); // absent (PUB-6.6), ahead of the resident-link read
    }
    let coverage = w
        .links()
        .followlink(a, slot)
        .map_err(|_| QueryError::NotALink)?; // Err(Invalid) ⇒ NotALink (a ∉ dom(L) OR slot OOB)
    let surface = reading_surface(w.m3(), d); // head-float, on the registered `d`
    // CONTENT runs, because M5's `project` joins the coverage against those
    // alone — the factor priced is the factor multiplied. The count walks the
    // run set M5 publishes, which is `#content_runs` itself: bounded by the
    // quantity it prices, and one small allocation where the budget is
    // nowhere near. The product is held here as well: M7 caps a stored slot
    // at `MAX_SLOT_SPANS` on its deposit paths, which keeps today's product
    // inside the square, but that is M7's number on M7's write path, and the
    // join this function hands M5 is priced where it is incurred.
    if !join_within_budget(coverage.len(), w.m5().content_runs(&surface).len()) {
        return Err(QueryError::ImageTooLarge);
    }
    Ok(w.m5().project(&surface, &coverage)) // I→V, content subspace, level-class-safe inside M5
}

/// `coverage(e) ∩ ⋃ extents ≠ ∅` — pointwise, mirroring M7's stab overlap
/// relations (ProperOverlap | Containment | Equal, never Adjacent).
/// `classify_spans` is a pure, level-gate-free order relation, total on
/// cross-length spans (a link-address span against a content run classifies
/// by plain tumbler order — no fault), so the cross-subspace cases just work.
/// Vacuously false over an empty extent list.
///
/// `extents` are the I-extents of the document's runs, lifted by the caller:
/// this is asked once per slot of a link, and a run's extent depends on the
/// run alone, so the lift belongs where the runs are read.
fn touches(e: &Endset, extents: &[Span]) -> bool {
    e.spans().any(|span| {
        extents.iter().any(|extent| {
            matches!(
                classify_spans(span, extent),
                SpanRel::ProperOverlap | SpanRel::Containment | SpanRel::Equal
            )
        })
    })
}

/// Is `a` discoverable from `d` AND addressable? Both halves are the corpus's
/// own words in their corpus senses: `discoverable_from` is ASN-0098's LP12
/// (arrangement-reachable, derived and per-document), and `addressable` is
/// ASN-0121/0132's population `dom(L) ∖ nullified`. Their conjunction is
/// STRICTLY stronger than LP12 alone (Conflicts #8) — a nullified-but-
/// reachable link is discoverable and not addressable, so it answers
/// `Ok(false)`. Bare LP12, which predates retraction, is M7's `followlink`
/// composed with M5's `project`.
///
/// Tests LP12's characterisation directly per link —
/// `∃ i : coverage(Σ.L(a).eᵢ) ∩ ran(M(reading_surface(d))) ≠ ∅` over BOTH
/// subspaces (`content_runs` + `link_runs`) — conjoined with `is_active(a)`;
/// at most `Σᵢ|eᵢ| × |runs|` `classify_spans` calls, each rebuilding both
/// spans' endpoints. The test iterates the link's full arity, so it carries
/// no arity-3 caveat.
///
/// HEAD-FLOAT: LP12 is read at `d`'s reading surface —
/// `M(reading_surface(d))`, which is `M(d)` itself wherever `d` is its own
/// reading surface — the arrangement the region family resolves for the same
/// `d`, which is what keeps the two agreeing that a link reaches `d`.
///
/// The ABSENCE RULE (PUB round 2, lane 3.3, §2; PUB-6.6) — the home rule
/// asked of the ARGUMENT `a`: a link whose home `readable` refuses is ABSENT,
/// and absent ⟹ not discoverable, so it answers `Ok(false)`. That is the
/// RETRACTED link's answer, not the `Err(NotALink)` an address naming nothing
/// gets — so the pair's two absence shapes differ, and [`project_on`] beside
/// this answers `Err(NotALink)`. Neither shape reveals the unreadable
/// document's link chain, because the rule runs AHEAD of the resident-link
/// read: every address under an unreadable document answers `Ok(false)`
/// here, a refused link and a non-link alike. It runs after the document
/// gate, so an unregistered `d` names the document fault whatever `a` is;
/// `d`'s own readability is the caller's doc-argument consult (pre-dispatch);
/// an `a` with no document field has no home to withhold, and the store
/// answers for it.
///
/// REFUSES, IN THIS ORDER: `DocNotRegistered`, then — for an admitted `a`
/// only — `NotALink`, then `ImageTooLarge`. An absent `a` answers `Ok(false)`
/// between the first and the second, and reaches neither. A retracted `a`
/// answers `Ok(false)` between the second and the third, and never reaches
/// the budget: the addressable half is settled before any run of `d` is
/// read. Every argument about `d` is settled before any argument about `a`,
/// so an unregistered `d` with a non-link `a` names the document fault.
/// Given the document gate passes and `a` is admitted, `Err(NotALink)` iff
/// `a ∉ dom(L)` (aligned with `project`'s non-link handling).
///
/// A *nullified* link is still a link: it is still resident, so the
/// resident-link read admits it, and it returns `Ok(false)` through the
/// `is_active` conjunct — distinguishing "not a link" from "a retracted
/// link". A registered-but-empty `d` yields `Ok(false)` — nothing is
/// reachable — and never `DocNotRegistered`, which is the distinction the
/// document gate exists to draw.
///
/// `Err(ImageTooLarge)` when the join is past budget: the runs of
/// `ran(M(reading_surface(d)))` are lifted into an I-extent apiece and every
/// one of them is tested against every span of every slot, so this is where
/// a document's fragmentation becomes the multiplier M8 itself applies. Two
/// factors are held, both BEFORE the lift, so an over-budget `d` costs the
/// count and not the span set: the run count at [`crate::MAX_IMAGE_RUNS`],
/// over `#content_runs + #link_runs` of the reading surface because LP12
/// ranges over both subspaces and every extent is tested; and the product
/// with the link's WHOLE coverage, `Σᵢ|eᵢ|`, at that budget's square — every
/// slot may carry M7's `MAX_SLOT_SPANS`, so the run count alone would admit
/// three times it. [`crate::MAX_IMAGE_RUNS`] sets the run count beside the
/// other three.
pub fn addressably_discoverable_from_on<W: DiscoveryWorld>(
    s: &Snapshot<W>,
    a: &Address,
    d: &Address,
    readable: &dyn Fn(&Address) -> bool,
) -> Result<bool, QueryError> {
    let w = s.world();
    if !w.m3().is_registered_document(d) {
        return Err(QueryError::DocNotRegistered);
    }
    if !home_readable(readable, a) {
        return Ok(false); // absent ⟹ not discoverable (PUB-6.6), ahead of the resident-link read
    }
    let link = w.links().readlink(a).ok_or(QueryError::NotALink)?;
    if !w.links().is_active(a) {
        return Ok(false); // the ADDRESSABLE half (Conflicts #8)
    }
    let surface = reading_surface(w.m3(), d); // head-float, on the registered `d`
    let (content_runs, link_runs) = (w.m5().content_runs(&surface), w.m5().link_runs(&surface));
    let span_count = link.slots().map(Endset::len).sum::<usize>(); // Σᵢ|eᵢ|, the side the link supplies
    if !join_within_budget(span_count, content_runs.len() + link_runs.len()) {
        return Err(QueryError::ImageTooLarge);
    }
    // LP12's characterisation tested directly, per link — never the F-FULL
    // whole-document-stab membership route.
    let extents: Vec<Span> = content_runs
        .into_iter()
        .chain(link_runs)
        .map(|r| r.iextent())
        .collect(); // ran(M(reading_surface(d))) as I-extents, BOTH subspaces (LP12)
    Ok(link.slots().any(|e| touches(e, &extents)))
}
