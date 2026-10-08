//! §5 — pointwise projection & discoverability: `project` (ASN-0098 I→V into
//! the CONTENT subspace alone, through M5's level-class-safe `project`) and
//! `addressably_discoverable_from` (ASN-0098's LP12 discoverability, read over
//! BOTH subspaces and narrowed to ASN-0121/0132's addressable population,
//! `dom(L) ∖ nullified`). The two read the active view differently, and
//! deliberately:
//! `addressably_discoverable_from` conjoins `is_active`, while `project`
//! reports the recorded coverage M7's `followlink` hands over, retracted
//! links included.
//!
//! Both are DOC-GATED, as the region family is: `d` must be M3-registered,
//! and that is the first act of each — a registered `d` whose reading
//! surface arranges nothing yields a defined answer (∅ / `Ok(false)`), an
//! unregistered one yields `DocNotRegistered`, and drawing those apart is
//! the gate's whole purpose.
//! Each read states its own refusal order, since a call can be faulty in `d`
//! and in `a` at once and only one verdict speaks.
//!
//! Both read `d`'s READING SURFACE (HEAD-FLOAT — PUB-2.49, PUB-2.50,
//! PUB-2.53): M5's `reading_surface`, the one place the float is decided,
//! which [`crate::image_on`] routes the whole region family through as well.
//! So the pair answers about the arrangement a reader of `d` sees, and
//! `addressably_discoverable_from` agrees with the region family about which
//! links reach `d` — a link `findlinks_v` finds through `d` is one it calls
//! reachable — because both touch by M7's overlap with the runs' I-extents;
//! `project` asks membership, and the crate header states the one shape where
//! that parts them. The document gate runs on the address named, ahead of the
//! float (PUB-6.37).
//!
//! Both take the caller's DOCUMENT predicate and apply the ABSENCE RULE
//! (PUB-6.6) — the home rule asked of `a`'s home: neither answer names a
//! link, so there is no result set to filter, and a link the reader may not
//! see is instead ABSENT as an argument.
//!
//! The per-link touch test here — M7's stab overlap restated over each span's
//! bounds, derived once — is M8's one pointwise span comparison: a
//! level-gate-free order relation, total on cross-length spans, categorically
//! distinct from the level-gated set algebra M8 avoids.

use skep_address::{Address, Span, SpanSet, Tumbler};
use skep_arrangement::reading_surface;
use skep_kernel::Snapshot;
use skep_links::Endset;

use crate::budget::{MAX_ANSWER_SPANS, MAX_IMAGE_RUNS, MAX_JOIN_STEPS};
use crate::home::home_readable;
use crate::types::QueryError;
use crate::DiscoveryWorld;

/// May a join of `span_count` coverage spans against `run_count` arrangement
/// runs go ahead? The pair's one budget rule, held at both reads: the runs at
/// [`MAX_IMAGE_RUNS`], since they are read whole and joined before any test
/// answers, and the product — one per (run, coverage span) pair — at
/// `max_product`, since the coverage side is the link's and a run count does
/// not reach it.
///
/// The two reads pass different caps: [`addressably_discoverable_from_on`]
/// the square, [`MAX_JOIN_STEPS`], and [`project_on`] the answer budget,
/// [`MAX_ANSWER_SPANS`]. [`MAX_IMAGE_RUNS`] states why the square holds the
/// touch test, and [`MAX_ANSWER_SPANS`] why the answer budget holds the
/// projection.
fn join_within_budget(span_count: usize, run_count: usize, max_product: usize) -> bool {
    run_count <= MAX_IMAGE_RUNS && span_count.saturating_mul(run_count) <= max_product
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
/// BY MEMBERSHIP, as ASN-0098's `project` is: a position answers when the
/// coverage CONTAINS the address arranged there, which is what the
/// biconditional above rests on. [`addressably_discoverable_from_on`] and the
/// region family touch by M7's overlap with each run's I-extent instead, which
/// reaches one shape this does not — a coverage strictly beneath an arranged
/// address, projected ∅ here in every slot — and the crate header states it.
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
/// which is total where the level-gated set comparisons can fault.
///
/// COST, IN TWO FACTORS: M5 states the work as `#runs(d) × |coverage|` and
/// leaves admission control to its caller, which is this function, and both
/// are held here (`ImageTooLarge`): the reading surface's CONTENT runs — the
/// runs M5's `project` joins against, so the factor priced is the factor
/// multiplied — at [`crate::MAX_IMAGE_RUNS`], which sets that count beside
/// the others it holds; and their product with the slot's spans at
/// [`crate::MAX_ANSWER_SPANS`], which states why the answer's budget and not
/// the run budget's square holds this join. So a large-slot projection into
/// a heavily fragmented document is refused, and a pointwise refusal has no
/// split axis ([`crate::QueryError`]).
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
    // CONTENT runs, the ones M5's `project` joins against, off M5's own
    // `#runs`, so no run is touched to be counted.
    let run_count = w.m5().content_run_count(&surface);
    if !join_within_budget(coverage.len(), run_count, MAX_ANSWER_SPANS) {
        return Err(QueryError::ImageTooLarge);
    }
    Ok(w.m5().project(&surface, &coverage)) // I→V, content subspace, level-class-safe inside M5
}

/// One span as the two bounds the touch test compares: its start, borrowed,
/// and its reach, derived ONCE — M1's derived `(start, reach)` form, which M1
/// keeps crate-private. M1's `classify_spans` derives both operands' bounds
/// afresh on every call, a copy of each start and an addition for each reach,
/// so a join run through it allocates four tumblers per (coverage span, run)
/// PAIR. Derived once per span instead — as M6's COMPARE stores each block's
/// reach, for the same reason — a test compares borrowed tumblers and builds
/// nothing, which is the step [`MAX_JOIN_STEPS`] is argued at. Named for the
/// span's bounds rather than M1's `Endpoints`, since an endpoint in this crate
/// is a supersession claim's (`lineage`'s `Endpoint`).
struct SpanBounds<'s> {
    start: &'s Tumbler,
    reach: Tumbler,
}

impl<'s> SpanBounds<'s> {
    fn of(span: &'s Span) -> SpanBounds<'s> {
        SpanBounds {
            start: span.start(),
            reach: span.reach(),
        }
    }

    /// M7's stab overlap — ProperOverlap | Containment | Equal, never
    /// Adjacent — over the two spans' bounds. M1's classification answers
    /// one of those three relations exactly when `max start < min reach`, and
    /// over non-empty spans — which T12 makes every `Span`, its reach strictly
    /// past its start — that is each span starting before the other reaches:
    /// at most two tumbler comparisons, the first deciding every pair whose
    /// first span lies wholly past the second. Pure tumbler order, total on
    /// cross-length operands as `classify_spans` is, so a link-address span
    /// against a content run compares without fault. M7 keeps its own
    /// statement of the relation private, so this is a second one and the two
    /// change together: `tests/it/pointwise.rs` holds discoverability to the
    /// region family's stab on every relation `classify_spans` draws, and the
    /// test below holds this to M1's classification on every pair of a
    /// mixed-length grid.
    fn overlaps(&self, other: &SpanBounds<'_>) -> bool {
        self.start < &other.reach && other.start < &self.reach
    }
}

/// `coverage(e) ∩ ⋃ extents ≠ ∅` — pointwise, by [`SpanBounds::overlaps`].
/// Vacuously false over an empty extent list.
///
/// `extent_bounds` are the bounds of the document's runs' I-extents, derived
/// by the caller: this is asked once per slot of a link, and a run's extent
/// depends on the run alone, so the derivation belongs where the runs are
/// read. Each span of `e` derives its own bounds once, ahead of every extent
/// it is tested against.
fn touches(e: &Endset, extent_bounds: &[SpanBounds<'_>]) -> bool {
    e.spans().any(|span| {
        let span = SpanBounds::of(span);
        extent_bounds.iter().any(|extent| span.overlaps(extent))
    })
}

/// Is `a` discoverable from `d` AND addressable? Both halves are the corpus's
/// own words in their corpus senses: `discoverable_from` is ASN-0098's LP12
/// (arrangement-reachable, derived and per-document), and `addressable` is
/// ASN-0121/0132's population `dom(L) ∖ nullified`. Their conjunction is
/// STRICTLY stronger than LP12 alone (Conflicts #8) — a nullified-but-
/// reachable link is discoverable and not addressable, so it answers
/// `Ok(false)`. Bare LP12, which predates retraction, has no read of its own
/// here, and it is NOT M7's `followlink` composed with M5's `project`: that
/// composition reads `d`'s content runs alone, so it calls unreachable a link
/// whose only witness in `d` is a link address `d` seats — which LP12 calls
/// reachable ([`project_on`] states the restriction).
///
/// Tests LP12's characterisation directly per link —
/// `∃ i : coverage(Σ.L(a).eᵢ) ∩ ran(M(reading_surface(d))) ≠ ∅` over BOTH
/// subspaces (`content_runs` + `link_runs`) — conjoined with `is_active(a)`,
/// and reads the intersection as the region family's touch: M7's overlap with
/// each run's I-extent. That is wider than LP12 on the one shape the crate
/// header states — a coverage strictly beneath an arranged address, which an
/// extent covers and `ran(M(·))` does not hold — and there this answers
/// `Ok(true)` where [`project_on`], which asks membership, projects ∅. Each
/// span's bounds are derived once, `Σᵢ|eᵢ| + |runs|` reaches, and then at
/// most `Σᵢ|eᵢ| × |runs|` tests of at most two tumbler comparisons apiece,
/// building nothing. The test iterates the link's full arity, so it carries
/// no arity-3 caveat.
///
/// HEAD-FLOAT: LP12 is read at `d`'s reading surface —
/// `M(reading_surface(d))`, which is `M(d)` itself wherever `d` is its own
/// reading surface — the arrangement the region family resolves for the same
/// `d`, which is what keeps the two agreeing that a link reaches `d`.
///
/// The ABSENCE RULE (PUB round 2, lane 3.3, §2; PUB-6.6) — the home rule
/// asked of the ARGUMENT `a`, because the answer names no link: a link whose
/// home `readable` refuses is ABSENT, and answers `Err(NotALink)` — exactly
/// what an address naming no link gets, and what [`project_on`] beside this
/// answers for the same `a`. NOT `Ok(false)`: that is the RETRACTED link's
/// answer, and a reader handed it for an unreadable home would learn that a
/// link occupies the address (PUB-6.6's table pins `not_a_link` here). The
/// rule runs AHEAD of the resident-link read, so every address under an
/// unreadable document answers `Err(NotALink)`, a refused link and a
/// non-link alike, and the answer says nothing about that document's link
/// chain. It runs after the document gate, so an unregistered `d` names the
/// document fault whatever `a` is; `d`'s own readability is the caller's
/// doc-argument consult (pre-dispatch); an `a` with no document field has no
/// home to withhold, and the store answers for it.
///
/// REFUSES, IN THIS ORDER: `DocNotRegistered`; then `NotALink`, for an
/// absent `a` first and then for an admitted `a` that names no link; then
/// `ImageTooLarge`. A retracted `a` — resident, so admitted, in a home the
/// reader may read — answers `Ok(false)` between `NotALink` and the budget,
/// and never reaches the budget: the addressable half is settled before any
/// run of `d` is read. Every argument about `d` is settled before any
/// argument about `a`, so an unregistered `d` with a non-link `a` names the
/// document fault. Given the document gate passes and `a` is admitted,
/// `Err(NotALink)` iff `a ∉ dom(L)` (aligned with `project`'s non-link
/// handling).
///
/// A registered `d` whose reading surface arranges nothing yields
/// `Ok(false)` — nothing is reachable — and never `DocNotRegistered`, which
/// is the distinction the document gate exists to draw.
///
/// `Err(ImageTooLarge)` when the join is past budget: the runs of
/// `ran(M(reading_surface(d)))` are lifted into an I-extent apiece and every
/// one of them is tested against every span of every slot. Two factors are
/// held, both BEFORE the lift, so an over-budget `d` costs the count and not
/// the span set: the run count — `#content_runs + #link_runs` of the reading
/// surface, because LP12 ranges over both subspaces and every extent is
/// tested — at [`crate::MAX_IMAGE_RUNS`], and its product with the link's
/// WHOLE coverage, `Σᵢ|eᵢ|`, at that constant's square.
/// [`crate::MAX_IMAGE_RUNS`] states why the square holds this join, and sets
/// the run count beside the others it holds.
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
        return Err(QueryError::NotALink); // absent (PUB-6.6), ahead of the resident-link read
    }
    let link = w.links().readlink(a).ok_or(QueryError::NotALink)?;
    if !w.links().is_active(a) {
        return Ok(false); // the ADDRESSABLE half (Conflicts #8)
    }
    let surface = reading_surface(w.m3(), d); // head-float, on the registered `d`
    let span_count = link.slots().map(Endset::len).sum::<usize>(); // Σᵢ|eᵢ|, the side the link supplies
    // Both counts off M5's own `#runs`, so the budget is asked before a run is
    // read.
    let run_count = w.m5().content_run_count(&surface) + w.m5().link_run_count(&surface);
    if !join_within_budget(span_count, run_count, MAX_JOIN_STEPS) {
        return Err(QueryError::ImageTooLarge);
    }
    // LP12's characterisation tested directly, per link — never the F-FULL
    // whole-document-stab membership route.
    let extents: Vec<Span> = w
        .m5()
        .content_runs(&surface)
        .chain(w.m5().link_runs(&surface))
        .map(|r| r.iextent())
        .collect(); // ran(M(reading_surface(d))) as I-extents, BOTH subspaces (LP12)
    let extent_bounds: Vec<SpanBounds<'_>> = extents.iter().map(SpanBounds::of).collect();
    Ok(link.slots().any(|e| touches(e, &extent_bounds)))
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use skep_address::{classify_spans, subtree_of, Nat, SpanRel};

    fn t(comps: &[u32]) -> Tumbler {
        Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("nonempty")
    }

    /// `count` positions from `start`, counted at its last component.
    fn wide(start: &[u32], count: u32) -> Span {
        let mut width = vec![0; start.len()];
        *width.last_mut().expect("nonempty") = count;
        Span::new(t(start), t(&width)).expect("a width at the last component is T12-valid")
    }

    /// The restated overlap answers as M1's classification does on every pair
    /// of a grid that mixes lengths — a node's subtree, an account's, a
    /// document's, a trailing-zero carrier's, content runs of eight components
    /// and of nine, a link address, the zero sentinel's span — and meets all
    /// five relations in both orders of their operands, so each of the two
    /// comparisons `overlaps` makes is asked on both sides of its boundary: a
    /// `<=` in either would take Adjacent for a touch, and either comparison
    /// alone would take Separated for one.
    #[test]
    fn overlaps_answers_as_classify_spans_on_every_pair_of_mixed_lengths() {
        let grid = [
            subtree_of(&t(&[1])),
            subtree_of(&t(&[1, 0, 1])),
            subtree_of(&t(&[1, 0, 1, 0, 1])),
            subtree_of(&t(&[1, 0, 1, 0, 1, 0])),
            wide(&[1, 0, 1, 0, 1, 0, 1, 1], 3), // positions 1 to 3
            wide(&[1, 0, 1, 0, 1, 0, 1, 3], 2), // 3 and 4: overlaps the one above
            subtree_of(&t(&[1, 0, 1, 0, 1, 0, 1, 4])), // abuts 1 to 3
            subtree_of(&t(&[1, 0, 1, 0, 1, 0, 2, 1])), // a link address
            subtree_of(&t(&[1, 0, 1, 1, 0, 1, 0, 1, 1])), // nine components
            wide(&[0], 1),
        ];
        let mut met = HashSet::new();
        for a in &grid {
            for b in &grid {
                let relation = classify_spans(a, b);
                met.insert(relation);
                assert_eq!(
                    SpanBounds::of(a).overlaps(&SpanBounds::of(b)),
                    matches!(
                        relation,
                        SpanRel::ProperOverlap | SpanRel::Containment | SpanRel::Equal
                    ),
                    "{a:?} against {b:?}: {relation:?}"
                );
            }
        }
        assert_eq!(met.len(), 5, "every relation is met: {met:?}");
    }
}
