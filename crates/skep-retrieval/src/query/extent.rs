//! §B RETRIEVEDOCVSPAN (ASN-0112) and RETRIEVEDOCVSPANSET (ASN-0113): a
//! document's extents, read off M5's counts, and the D-SEQ★ tripwire the
//! counts stand on.

use num_traits::{One, Zero};
use skep_address::{Address, Nat, Span, SpanSet};
use skep_arrangement::{ordinal_vspan, reading_surface, M5State, Run, VPos};

use super::{Query, RetrievalWorld};
use crate::error::ExtentError;
use crate::vspan::Subspace;

/// `ext(d, S) = ([S, 1], [0, n_S])` — the per-subspace exact extent span
/// (ASN-0113 W2/W4: a count fixes an extent under sequential positions), or
/// `None` for an unoccupied subspace (`n_S = 0`), which has no extent — so
/// nothing in [`Query::doc_vspanset`]'s answer, which is `⟨⟩` when both
/// subspaces are unoccupied. The anchor `[S, 1]` — ASN-0113's `start_S` — is
/// written ONCE, here, never absorbed into a confluent summary, which is how
/// the hazard ASN-0112 OQ5 records against its bounding-span start `origin_d`
/// (a POSITION, not ASN-0077's origin) is designed out.
///
/// Built with M5's `ordinal_vspan`, so the extent M6 REPORTS is the shape M5's
/// `resolve` READS: the constructor and the recognizer every request span is
/// folded through are the two halves of one definition and cannot come apart
/// — and the unoccupied case is that constructor's own `None`, not a
/// precondition this function asks its caller to keep.
///
/// The subspace arrives CLASSIFIED rather than as a numeral, so the two
/// arguments have different types and `ext_span(count, subspace)` fails to
/// compile — the hazard M5 designs out of `ordinal_vspan` by taking a `VPos`,
/// since a swap here builds a well-formed span naming a subspace that selects
/// nothing and reports as emptiness far downstream.
fn ext_span(s: Subspace, n: &Nat) -> Option<Span> {
    ordinal_vspan(
        &VPos {
            subspace: s.numeral().clone(),
            ordinal: Nat::one(),
        },
        n,
    )
}

/// D-SEQ★ defense-in-depth for the extent queries (open build decision,
/// documented default: trust `content_count`/`link_count` in release, assert
/// in debug).
///
/// D-SEQ★ (PerSubspaceSequentialPositions, ASN-0047) is the invariant the
/// counts stand on: an occupied subspace's V-positions are exactly the dense
/// prefix anchored at `[S, 1]`, `V_S(d) = {[S, k] : 1 ≤ k ≤ n_S}` — which is
/// what ASN-0113 W4 forces, and which ASN-0047 derives from contiguity D-CTG★
/// plus minimum-position D-MIN★. Its two ingredients are what the two assertions
/// check: each subspace's run widths sum to its count (density — a hole would
/// make the count over-report the extent), and an occupied subspace anchors
/// at ordinal 1 (D-MIN★ itself; ASN-0112 V8 origin permanence, append-only
/// link seating). The whole body is compiled out of release builds, which
/// read the counts directly.
fn debug_assert_sequential_positions(m5: &M5State, doc: &Address) {
    if cfg!(debug_assertions) {
        for sub in [Subspace::Content, Subspace::Link] {
            // Each subspace asks M5 for its OWN count and runs, so the two
            // reads compared below cannot be paired across subspaces.
            let (count, runs) = (sub.count(m5, doc), sub.runs(m5, doc));
            let width_sum: Nat = runs.map(Run::width).sum();
            debug_assert!(
                width_sum == count,
                "D-SEQ★: a subspace's run widths must sum to its count"
            );
            debug_assert!(
                count.is_zero()
                    || m5
                        .point(
                            doc,
                            &VPos {
                                subspace: sub.numeral().clone(),
                                ordinal: Nat::one(),
                            },
                        )
                        .is_some(),
                "D-MIN★: an occupied subspace must anchor at ordinal 1"
            );
        }
    }
}

impl<W: RetrievalWorld> Query<'_, W> {
    /// RETRIEVEDOCVSPAN (ASN-0112) — the whole-document bounding span:
    /// singleton `⟨σ_d⟩`, or `⟨⟩` for a registered-empty document; a document
    /// that is not registered ⇒ Err. Across subspaces it is a bounding box
    /// bridging the inter-subspace void.
    ///
    /// Answers from `doc`'s READING SURFACE (crate doc, *Which arrangement an
    /// operation answers from*), because it is the hull of
    /// [`Query::doc_vspanset`]'s answer and that is the arrangement the
    /// extents are read from; the gate runs on the address named.
    ///
    /// WHAT THE BOX CANNOT SHOW (V9). Being a function of the two EXTREMES
    /// alone, the cross-subspace box is fixed at `[[s_C, 1], [s_L, n_L + 1])`
    /// under any content edit that leaves `n_C ≥ 1`, while
    /// [`Query::doc_vspanset`]'s content extent moves with `n_C` — so a caller
    /// that must observe a CONTENT-COUNT change asks for the extents, not the
    /// box. Neither reports run structure: under D-SEQ★ both are functions of
    /// `n_C` and `n_L` alone, and a document's fragmentation is M5's
    /// `content_runs`, which is not part of M6's surface.
    ///
    /// σ_d IS the hull of the per-subspace extents [`Query::doc_vspanset`]
    /// reports: the first extent's start to the last extent's reach.
    pub fn doc_vspan(&self, doc: &Address) -> Result<SpanSet, ExtentError> {
        // Taken from `doc_vspanset` rather than derived a second time, so the
        // registry gate, the D-SEQ★ trust and the count-read all happen once,
        // in one place. Those extents are W13-normalized, so the FIRST
        // extent's start is the anchor `[s, 1]` of the lowest occupied
        // subspace and the LAST extent's reach is one ordinal step past the
        // highest occupied position.
        let extents = self.doc_vspanset(doc)?;
        let (Some(first), Some(last)) = (extents.iter().next(), extents.iter().next_back()) else {
            return Ok(SpanSet::empty()); // registered-empty ⇒ ⟨⟩
        };
        // `from_endpoints` is INFALLIBLE on that pair: both endpoints are
        // depth-2 (no `LevelMismatch`) and `first.start ≤ last.start <
        // last.reach` (no `NotIncreasing`); the stored width `reach ⊖ start`
        // round-trips exactly — `divergence(start, reach) ≤ #start` discharges
        // D1, INCLUDING the cross-subspace box — so the singleton is faithfully
        // ASN-0112's `σ_d = (origin_d, extent_d)`.
        Ok(SpanSet::singleton(
            Span::from_endpoints(first.start().clone(), &last.reach())
                .expect("first.start < last.reach at one depth-2 length"),
        ))
    }

    /// RETRIEVEDOCVSPANSET (ASN-0113) — the per-subspace exact extents, one
    /// per occupied subspace (content, then link), already W13-normalized;
    /// `⟨⟩` for a registered-empty document; a document that is not registered
    /// ⇒ Err.
    ///
    /// The extents are the READING SURFACE's (crate doc, *Which arrangement an
    /// operation answers from*): a bare published address with a head reports
    /// the head's counts, a version address its own member's, and a published
    /// address whose own arrangement is empty reports `⟨⟩` only while it has
    /// no head. The registry gate runs on the address named.
    ///
    /// No predicate is threaded and none belongs: the extents COUNT the
    /// positions a masked-origin run occupies and are never shrunk to the
    /// deliverable ones (PUB-6.15, PUB-6.41); [`Query::doc_vspan`] inherits
    /// this as the hull.
    ///
    /// The count-read core of both extent queries: exact because each
    /// subspace's occupied V-positions form the dense run anchored at
    /// `[S, 1]`, `[S, 1..n_S]` (D-SEQ★ — the sequential-position occupancy
    /// ASN-0113 W4 forces; M5's write-path property, trusted here and
    /// tripwired in debug), so M5's O(1) counts ARE the extents.
    pub fn doc_vspanset(&self, doc: &Address) -> Result<SpanSet, ExtentError> {
        let w = self.0.world();
        let (m3, m5) = (w.m3(), w.m5());
        if !m3.is_registered_document(doc) {
            return Err(ExtentError::DocNotRegistered); // not registered ⇒ fail
        }
        // Gated on the address named; the surface answers.
        let surface = reading_surface(m3, doc);
        debug_assert_sequential_positions(m5, &surface);
        // Each subspace asks M5 for its OWN count inside the one closure that
        // hands it to `ext_span` classified rather than as a numeral — so no
        // site pairs a subspace with another's count by hand,
        // `ext_span(count, subspace)` does not compile, and an unoccupied
        // subspace is `ext_span`'s own `None`. The occupied ones are
        // `collect`ed through M1's `FromIterator<Span>`, which collects AS
        // GIVEN — preserving the already-disjoint, content-before-link normal
        // form asserted below; no invented M1 constructor.
        let extents: SpanSet = [Subspace::Content, Subspace::Link]
            .into_iter()
            .filter_map(|s| ext_span(s, &s.count(m5, &surface)))
            .collect();
        debug_assert!(
            extents.is_normalized(),
            "W13: content-before-link, subspace-separated ⇒ already normal"
        );
        Ok(extents)
    }
}
