//! COPY (§B; ASN-0118): transclusion by reference, the self-copy, and each of
//! its guards in their documented order.

use skep_address::{Address, Span, SpanSet};
use skep_arrangement::{CopyError, HasM5, Run, VSpec};
use skep_content::HasContent;

use crate::common::*;

#[test]
fn copy_transcludes_by_reference_and_records_provenance() {
    // ASN-0118 CP1/CP2: no content allocated; the destination references the
    // SOURCE's I-addresses; provenance makes the destination discoverable.
    let k = mem_kernel();
    let vs = insert_abc(&k);
    let stored_before = k.snapshot().world().content().len();
    let seq = vs
        .copy(
            P1,
            &doc2(),
            vp(1, 1),
            &[VSpec {
                source: doc1(),
                span: vspan(1, 1, 2),
            }],
        )
        .expect("copy commits");
    let s = k.snapshot();
    assert_eq!(s.seq(), seq);
    assert_eq!(s.world().content().len(), stored_before); // nothing minted/written
    let m5 = s.world().m5();
    assert_eq!(m5.content_count(&doc2()), n(2));
    let runs: Vec<&Run> = m5.content_runs(&doc2()).collect();
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].i_start(), &ca(1)); // doc1's address, carried verbatim (S7)
    assert_eq!(read_v(&s, &doc2(), 2), b"b".to_vec());
    // Both the origin and the transcluder are R-candidates for the region.
    let cov = SpanSet::singleton(runs[0].iextent());
    assert_eq!(m5.docs_ever_containing(&cov), vec![doc1(), doc2()]);
}

#[test]
fn self_copy_resolves_against_the_pre_edit_arrangement_preserving_multiplicity() {
    // §5: resolution precedes staging, so a self-copy sees the pre-edit
    // state; the duplicate placement survives as a second run (S5/V2-style
    // multiplicity, no cross-placement coalesce of the same origin twice).
    let k = mem_kernel();
    let vs = insert_abc(&k);
    vs.copy(
        P1,
        &doc1(),
        vp(1, 1),
        &[VSpec {
            source: doc1(),
            span: vspan(1, 1, 3),
        }],
    )
    .expect("self-copy commits");
    let s = k.snapshot();
    let m5 = s.world().m5();
    assert_eq!(m5.content_count(&doc1()), n(6));
    assert_eq!(m5.content_runs(&doc1()).len(), 2); // [ca1..3][ca1..3] — no value merge (S4)
    assert_eq!(read_v(&s, &doc1(), 1), b"a".to_vec());
    assert_eq!(read_v(&s, &doc1(), 4), b"a".to_vec());
}

#[test]
fn copy_rejects_each_documented_guard() {
    let k = mem_kernel();
    let vs = insert_abc(&k);
    let unregistered_doc = a(&[1, 0, 1, 0, 9]);
    // Destination checks first (as INSERT, minus EmptyContent).
    assert!(matches!(
        rejected(vs.copy(P1, &unregistered_doc, vp(1, 1), &[])),
        CopyError::DocNotRegistered
    ));
    assert!(matches!(
        rejected(vs.copy(P1, &doc2(), vp(2, 1), &[])),
        CopyError::NotContentSubspace
    ));
    assert!(matches!(
        rejected(vs.copy(P1, &doc2(), vp(1, 2), &[])),
        CopyError::OutOfBounds
    ));
    // Subspace before bounds: the destination position is BOTH in the link
    // subspace and past doc2's only admissible boundary (n_C + 1 = 1).
    assert!(matches!(
        rejected(vs.copy(P1, &doc2(), vp(2, 99), &[])),
        CopyError::NotContentSubspace
    ));
    let spec = |source: Address, span: Span| VSpec { source, span };
    // Below the first boundary as well as past the last: ordinal 0 is no
    // placement position, whatever the spec. Admitted, the splice would
    // clamp it to 1 and place at the front.
    assert!(matches!(
        rejected(vs.copy(P1, &doc2(), vp(1, 0), &[spec(doc1(), vspan(1, 1, 1))])),
        CopyError::OutOfBounds
    ));
    assert!(matches!(
        rejected(vs.copy(P1, &doc2(), vp(1, 1), &[spec(unregistered_doc.clone(), vspan(1, 1, 1))])),
        CopyError::SourceNotRegistered
    ));
    // Destination before spec: a link-subspace destination beside a spec
    // whose source is unregistered. "Destination first, then per spec" is
    // the documented order; the other reading gives SourceNotRegistered.
    assert!(matches!(
        rejected(vs.copy(P1, &doc2(), vp(2, 1), &[spec(unregistered_doc.clone(), vspan(1, 1, 1))])),
        CopyError::NotContentSubspace
    ));
    // …the destination's bounds included: a position past doc2's only
    // admissible boundary beside the same unregistered source.
    assert!(matches!(
        rejected(vs.copy(P1, &doc2(), vp(1, 2), &[spec(unregistered_doc.clone(), vspan(1, 1, 1))])),
        CopyError::OutOfBounds
    ));
    // NotOrdinalVSpan: a T12-legal [m, n] width with m > 0 is action-point-1 —
    // not an ordinal-level depth-2 V-span (Conflicts #7's precise verdict).
    let action_point_1 = Span::new(t(&[1, 1]), t(&[1, 0])).expect("T12-legal");
    assert!(matches!(
        rejected(vs.copy(P1, &doc2(), vp(1, 1), &[spec(doc1(), action_point_1)])),
        CopyError::NotOrdinalVSpan
    ));
    // NotOrdinalVSpan also on a T12-legal span whose WIDTH is deeper than two: its
    // start is a well-formed V-position and its width position 1 is zero, so
    // the width-length clause is the only thing refusing it — and admitting
    // it would resolve five ordinals for a span reaching [1, 6, 0].
    let deep_width = Span::new(t(&[1, 1]), t(&[0, 5, 0])).expect("T12-legal");
    assert!(matches!(
        rejected(vs.copy(P1, &doc2(), vp(1, 1), &[spec(doc1(), deep_width)])),
        CopyError::NotOrdinalVSpan
    ));
    // Content-residence guard (§5).
    assert!(matches!(
        rejected(vs.copy(P1, &doc2(), vp(1, 1), &[spec(doc1(), vspan(2, 1, 1))])),
        CopyError::SourceNotContentSubspace
    ));
    // Registered-but-content-empty source is a typed verdict, not a skip.
    assert!(matches!(
        rejected(vs.copy(P1, &doc1(), vp(1, 1), &[spec(doc2(), vspan(1, 1, 1))])),
        CopyError::EmptySource
    ));
    // Which of the per-spec verdicts wins, in each documented pair.
    // Registration before shape: the source names no document AND the span
    // is mis-shaped. Shape first would answer NotOrdinalVSpan.
    let action_point_1 = Span::new(t(&[1, 1]), t(&[1, 0])).expect("T12-legal");
    assert!(matches!(
        rejected(vs.copy(P1, &doc2(), vp(1, 1), &[spec(unregistered_doc.clone(), action_point_1)])),
        CopyError::SourceNotRegistered
    ));
    // Shape before residence: this span is BOTH mis-shaped (action-point-1)
    // and in the link subspace, and the shape check runs first.
    let action_point_1_in_link = Span::new(t(&[2, 1]), t(&[1, 0])).expect("T12-legal");
    assert!(matches!(
        rejected(vs.copy(P1, &doc2(), vp(1, 1), &[spec(doc1(), action_point_1_in_link)])),
        CopyError::NotOrdinalVSpan
    ));
    // Residence before emptiness: doc2 is content-empty AND asked for in the
    // link subspace, and the residence check runs first.
    assert!(matches!(
        rejected(vs.copy(P1, &doc1(), vp(1, 1), &[spec(doc2(), vspan(2, 1, 1))])),
        CopyError::SourceNotContentSubspace
    ));
    // Shape before emptiness: doc2 is BOTH content-empty and asked for with
    // a mis-shaped span.
    let action_point_1 = Span::new(t(&[1, 1]), t(&[1, 0])).expect("T12-legal");
    assert!(matches!(
        rejected(vs.copy(P1, &doc1(), vp(1, 1), &[spec(doc2(), action_point_1)])),
        CopyError::NotOrdinalVSpan
    ));
    // WHICH SPEC speaks when two are defective: the list is walked, and the
    // first spec to fail any guard decides. Here the FIRST spec's span is
    // mis-shaped and the SECOND spec's source is unregistered; the answer is
    // the first spec's verdict. Read the other way — guards outermost, specs
    // within — `SourceNotRegistered` would win, since it precedes
    // `NotOrdinalVSpan` in the per-spec order.
    let action_point_1 = Span::new(t(&[1, 1]), t(&[1, 0])).expect("T12-legal");
    assert!(matches!(
        rejected(vs.copy(
            P1,
            &doc2(),
            vp(1, 1),
            &[spec(doc1(), action_point_1), spec(unregistered_doc.clone(), vspan(1, 1, 1))]
        )),
        CopyError::NotOrdinalVSpan
    ));
    // Span-level out-of-range stays accept-and-intersect: clipping to
    // nothing is EmptyResult…
    assert!(matches!(
        rejected(vs.copy(P1, &doc2(), vp(1, 1), &[spec(doc1(), vspan(1, 5, 2))])),
        CopyError::EmptyResult
    ));
    // …as is an empty spec list.
    assert!(matches!(
        rejected(vs.copy(P1, &doc2(), vp(1, 1), &[])),
        CopyError::EmptyResult
    ));
    // Two of COPY's guards are not exercised from here, both in `ops::tests`
    // instead. `DanglingSource` needs a world whose arrangement and content
    // store are seeded APART, which no engine reaches — every address this
    // one arranges was written by INSERT in the same composite, and `M5Rec`
    // cannot be built in a foreign crate. `TooManyRuns` needs a spec list
    // past `MAX_PLACED_RUNS`, which is a claim about the accumulator rather
    // than about this assembly.
}
