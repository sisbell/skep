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
//! the arrangement a reader of `d` sees — a bare PUBLISHED address its trunk
//! head, a version address its own member, a memberless or private document
//! itself — and agrees with the region family about which links reach `d`:
//! a link `findlinks_v` finds through `d` is one
//! `addressably_discoverable_from` calls reachable from it. The registry gate
//! runs on the address named, ahead of the float (PUB-6.37).
//!
//! Both carry a `_where` twin taking the caller's DOCUMENT predicate, asked
//! of `a`'s home: neither answer names a link, so there is no result set to
//! filter, and a link the reader may not see is instead ABSENT as an
//! argument (PUB-6.6).
//!
//! The per-link `classify_spans` touch test here is M8's one
//! pointwise span comparison — a level-gate-free order relation, total on
//! cross-length spans, categorically distinct from the level-gated set
//! algebra M8 avoids.

use skep_address::{classify_spans, Address, Span, SpanRel, SpanSet};
use skep_arrangement::reading_surface;
use skep_kernel::Snapshot;
use skep_links::Endset;

use crate::helpers::home_readable;
use crate::region::MAX_IMAGE_RUNS;
use crate::types::QueryError;
use crate::DiscoveryWorld;

/// I→V projection of link `a`'s `slot` into the CONTENT subspace of the
/// arrangement a reader of `d` sees (ASN-0098 `project`).
///
/// UNFILTERED — the one read here that is not narrowed to the active view.
/// The coverage comes from M7's `followlink`, which takes no `View` and
/// reports what is recorded, so a NULLIFIED link's slot still projects to the
/// V-positions it covers. That is ASN-0098's `project`, which knows nothing of
/// retraction; the addressable-narrowed question — is this link discoverable
/// AND active? — is [`addressably_discoverable_from_on`], and a caller who
/// wants "the live links reaching here" asks that or the region family, not
/// this.
///
/// CONTENT-SUBSPACE ONLY — strictly weaker than ASN-0098's subspace-agnostic
/// `project`: a link reachable solely through `d`'s LINK subspace projects ∅
/// here (a non-empty projection witnesses discoverability through content
/// only; LP12's biconditional holds only within the content subspace). The
/// link-subspace POSITIONAL projection that would close that gap is NOT M7's
/// BH3 (BH3 is typed reverse *lookup*, target→sources — it yields no
/// V-positions); it is the scoped-out contextual EL11a, composed above M8.
///
/// HEAD-FLOAT: the arrangement projected into is `d`'s READING SURFACE (M5's
/// `reading_surface`), so a bare PUBLISHED `d` answers in its trunk head's
/// V-coordinates — the positions [`crate::image_on`] resolves for the same
/// `d` — a version address in its own, and a memberless or private document
/// in its own.
///
/// REFUSES, IN THIS ORDER: `DocNotRegistered` (`d` is not M3-registered),
/// then `NotALink`, then `ImageTooLarge`. The order is the family's, not this
/// function's — every argument about `d` is settled before any argument
/// about `a` — so a call that is faulty in two ways names the document
/// fault. `NotALink` subsumes BOTH `a ∉ dom(L)` AND an out-of-range `slot`
/// (M7's `followlink` conflates them; a `BadSlot` split is deferred — it
/// would cost an extra `readlink` to read arity).
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
/// leaves admission control to its caller, which is this function. `|coverage|`
/// is already held — M7 caps a stored slot at `MAX_SLOT_SPANS` on every
/// deposit path, so the coverage a link can hand over is bounded before it is
/// read. `#runs(d)` is not held anywhere upstream, so it is held here, at
/// [`crate::MAX_IMAGE_RUNS`] (`ImageTooLarge`), counted over the reading
/// surface's CONTENT runs — the runs M5's `project` actually joins against,
/// so the factor priced is the factor multiplied. That is a narrower count
/// than [`addressably_discoverable_from_on`]'s, which must price both
/// subspaces, so a `d` this answers about may be one that read refuses: one
/// constant, two quantities, each its own site's. The count walks the run set
/// M5 publishes, which is `#content_runs` itself: bounded by the quantity it
/// prices, and one small allocation where the budget is nowhere near.
///
/// Answers for NO READER: `a` is answered about whatever its home — the route
/// for principal-free callers. A caller answering for a reading principal
/// asks [`project_on_where`].
pub fn project_on<W: DiscoveryWorld>(
    s: &Snapshot<W>,
    a: &Address,
    slot: usize,
    d: &Address,
) -> Result<SpanSet, QueryError> {
    project_on_where(s, a, slot, d, &|_| true)
}

/// [`project_on`] with the disclosure consult (PUB round 2, lane 3.3, §2;
/// PUB-6.6), asked of the ARGUMENT `a` because the answer names no link: a
/// link whose home the reader may not read is ABSENT, and answers
/// `Err(NotALink)` — exactly what an address naming no link gets.
///
/// The consult runs after the document gate and AHEAD of the residence read.
/// After, so the family's precedence holds: an unregistered `d` names the
/// document fault, whatever `a` is. Ahead, so a masked link and an address
/// naming nothing under the same unreadable document answer alike, and the
/// answer says nothing about that document's link chain. `d`'s own
/// readability is the caller's doc-argument consult (pre-dispatch), not this
/// read's; an `a` with no document field has no home to withhold, and the
/// store answers for it.
///
/// REFUSES, IN THIS ORDER: `DocNotRegistered`; `NotALink` for a masked `a`,
/// then for an `a` that names no link or a `slot` out of range; then
/// `ImageTooLarge`.
pub fn project_on_where<W: DiscoveryWorld>(
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
        return Err(QueryError::NotALink); // absent (PUB-6.6), before residence is read
    }
    let coverage = w
        .links()
        .followlink(a, slot)
        .map_err(|_| QueryError::NotALink)?; // Err(Invalid) ⇒ NotALink (a ∉ dom(L) OR slot OOB)
    let surface = reading_surface(w.m3(), d); // head-float, on the registered `d`
    // CONTENT runs, because M5's `project` joins the coverage against those
    // alone — the factor priced is the factor multiplied.
    if w.m5().content_runs(&surface).len() > MAX_IMAGE_RUNS {
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
    e.spans().any(|s| {
        extents.iter().any(|x| {
            matches!(
                classify_spans(s, x),
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
/// `∃ i : coverage(Σ.L(a).eᵢ) ∩ ran(M(d)) ≠ ∅` over BOTH subspaces
/// (`content_runs` + `link_runs`) — conjoined with `is_active(a)`; O(arity ×
/// |runs|), never the F-FULL whole-document-stab membership route. The test
/// iterates the link's full arity, so it carries no arity-3 caveat.
///
/// HEAD-FLOAT: `M(d)` is the arrangement of `d`'s READING SURFACE (M5's
/// `reading_surface`), so a bare PUBLISHED `d` is asked about its trunk head
/// — the arrangement the region family resolves for the same `d`, which is
/// what keeps the two agreeing that a link reaches `d` — a version address
/// about itself, and a memberless or private document about itself.
///
/// REFUSES, IN THIS ORDER: `DocNotRegistered`, then `NotALink`, then
/// `ImageTooLarge` — every argument about `d` settled before any argument
/// about `a`, so an unregistered `d` with a non-link `a` names the document
/// fault. Given the document gate passes, `Err(NotALink)` iff `a ∉ dom(L)`
/// (aligned with `project`'s non-link handling).
///
/// A *nullified* link is still a link: it passes the residence gate and
/// returns `Ok(false)` through the `is_active` conjunct — distinguishing "not
/// a link" from "a retracted link". A registered-but-empty `d` yields
/// `Ok(false)` and never `DocNotRegistered` (nothing is reachable; `touches`
/// over an empty extent list is vacuously false, so the early-out is cheap,
/// not a correctness guard) — that distinction is what the document gate
/// exists to draw.
///
/// `Err(ImageTooLarge)` when `ran(M(d))` is past [`crate::MAX_IMAGE_RUNS`]:
/// the runs are lifted into an I-extent apiece and every one of them is
/// tested against every span of every slot, so this is where a document's
/// fragmentation becomes the multiplier M8 itself applies. Refused BEFORE the
/// lift, so an over-budget `d` costs the count and not the span set. The
/// count is `#content_runs + #link_runs` of the reading surface, because
/// LP12 ranges over both subspaces and every extent is tested — so it prices
/// a strictly larger quantity than [`project_on`]'s content-only count, under
/// the same constant, and refuses a superset of the documents that read
/// refuses.
///
/// Answers for NO READER: `a` is answered about whatever its home — the route
/// for principal-free callers. A caller answering for a reading principal
/// asks [`addressably_discoverable_from_on_where`].
pub fn addressably_discoverable_from_on<W: DiscoveryWorld>(
    s: &Snapshot<W>,
    a: &Address,
    d: &Address,
) -> Result<bool, QueryError> {
    addressably_discoverable_from_on_where(s, a, d, &|_| true)
}

/// [`addressably_discoverable_from_on`] with the disclosure consult (PUB
/// round 2, lane 3.3, §2; PUB-6.6), asked of the ARGUMENT `a`: a link whose
/// home the reader may not read is ABSENT, and absent ⟹ not discoverable, so
/// it answers `Ok(false)`.
///
/// That is the RETRACTED link's answer, not the `Err(NotALink)` an address
/// naming nothing gets — so the pair's two absence shapes differ, and
/// [`project_on_where`] beside this answers `Err(NotALink)`. Neither shape
/// discloses the masked document's link chain, because the consult runs
/// AHEAD of the residence read: every address under an unreadable document
/// answers `Ok(false)` here, a masked link and a non-link alike. It runs
/// after the document gate, so an unregistered `d` names the document fault
/// whatever `a` is; `d`'s own readability is the caller's doc-argument
/// consult (pre-dispatch); an `a` with no document field has no home to
/// withhold, and the store answers for it.
///
/// REFUSES, IN THIS ORDER: `DocNotRegistered`, then — for an admitted `a`
/// only — `NotALink`, then `ImageTooLarge`. A masked `a` answers `Ok(false)`
/// between the first and the second, and reaches neither.
pub fn addressably_discoverable_from_on_where<W: DiscoveryWorld>(
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
        return Ok(false); // absent ⟹ not discoverable (PUB-6.6), before residence is read
    }
    let link = w.links().readlink(a).ok_or(QueryError::NotALink)?;
    if !w.links().is_active(a) {
        return Ok(false); // the ADDRESSABLE half (Conflicts #8)
    }
    let surface = reading_surface(w.m3(), d); // head-float, on the registered `d`
    let (content_runs, link_runs) = (w.m5().content_runs(&surface), w.m5().link_runs(&surface));
    if content_runs.len() + link_runs.len() > MAX_IMAGE_RUNS {
        return Err(QueryError::ImageTooLarge);
    }
    let extents: Vec<Span> = content_runs
        .into_iter()
        .chain(link_runs)
        .map(|r| r.iextent())
        .collect(); // ran(M(d)) as I-extents, BOTH subspaces (LP12)
    if extents.is_empty() {
        return Ok(false); // registered-empty d ⇒ nothing reachable
    }
    Ok(link.slots().any(|slot| touches(slot, &extents)))
}
