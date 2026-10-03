//! §B the document extents (ASN-0112, ASN-0113): the per-subspace extents
//! and the bounding box that is their hull.

use skep_address::{Span, SpanSet};
use skep_arrangement::seat_link;
use skep_retrieval::{ExtentError, Query};

use crate::common::*;

#[test]
fn doc_vspan_is_the_bounding_hull_of_the_per_subspace_extents() {
    // ASN-0112: σ_d — the whole-document bounding span, a bounding box
    // bridging the inter-subspace void once links exist (D-SEQ★ makes the
    // counts the extents; the anchor is `[S, 1]`, never negative).
    let k = mem_kernel();
    insert3(&k);
    {
        let s = k.snapshot();
        let q = Query::new(&s);
        // Content only: ([1,1], reach [1,4)).
        let got = ok_of(q.doc_vspan(&doc1()));
        let want = SpanSet::singleton(
            Span::from_endpoints(t(&[1, 1]), &t(&[1, 4])).expect("well-formed"),
        );
        assert_eq!(got, want);
    }
    seat_link(&k, &doc1(), &la(1)).expect("seat commits");
    seat_link(&k, &doc1(), &la(2)).expect("seat commits");
    let s = k.snapshot();
    let q = Query::new(&s);
    // Cross-subspace bounding box: [1,1] .. [2, n_L + 1).
    let got = ok_of(q.doc_vspan(&doc1()));
    let want =
        SpanSet::singleton(Span::from_endpoints(t(&[1, 1]), &t(&[2, 3])).expect("well-formed"));
    assert_eq!(got, want);
    // σ_d IS the hull of the per-subspace extents — the same first start and
    // the same last reach, never a second derivation that could disagree.
    let extents = ok_of(q.doc_vspanset(&doc1()));
    let (first, last) = (
        extents.iter().next().expect("occupied ⇒ a first extent"),
        extents
            .iter()
            .next_back()
            .expect("occupied ⇒ a last extent"),
    );
    assert_eq!(
        got,
        SpanSet::singleton(
            Span::from_endpoints(first.start().clone(), &last.reach()).expect("well-formed")
        )
    );
    // Link-only document: the anchor moves to [2,1].
    seat_link(&k, &doc2(), &doc2_la(1)).expect("seat commits");
    let s = k.snapshot();
    let q = Query::new(&s);
    let got = ok_of(q.doc_vspan(&doc2()));
    let want =
        SpanSet::singleton(Span::from_endpoints(t(&[2, 1]), &t(&[2, 2])).expect("well-formed"));
    assert_eq!(got, want);
}

#[test]
fn doc_vspanset_reports_per_subspace_exact_extents_prenormalized() {
    // ASN-0113 W2/W4/W13: one extent per occupied subspace, content before
    // link, exact ext(d,S) = ([S,1],[0,n_S]), already normal; ⟨⟩ for
    // registered-empty;
    // not registered ⇒ Err (both extent ops).
    let k = mem_kernel();
    insert3(&k);
    seat_link(&k, &doc1(), &la(1)).expect("seat commits");
    seat_link(&k, &doc1(), &la(2)).expect("seat commits");
    let s = k.snapshot();
    let q = Query::new(&s);
    let got = ok_of(q.doc_vspanset(&doc1()));
    let want: SpanSet = vec![
        Span::new(t(&[1, 1]), t(&[0, 3])).expect("T12"),
        Span::new(t(&[2, 1]), t(&[0, 2])).expect("T12"),
    ]
    .into_iter()
    .collect();
    assert_eq!(got, want);
    assert!(got.is_normalized());
    // Registered-empty ⇒ ⟨⟩ for both operations.
    assert_eq!(ok_of(q.doc_vspanset(&doc2())), SpanSet::empty());
    assert_eq!(ok_of(q.doc_vspan(&doc2())), SpanSet::empty());
    // Not registered ⇒ fail, for both.
    assert!(matches!(
        err_of(q.doc_vspan(&unregistered())),
        ExtentError::DocNotRegistered
    ));
    assert!(matches!(
        err_of(q.doc_vspanset(&unregistered())),
        ExtentError::DocNotRegistered
    ));
}

#[test]
fn a_content_edit_under_links_moves_the_extent_and_not_the_bounding_box() {
    // ASN-0112 V9, which is the whole of the routing `doc_vspan` states: the
    // cross-subspace box is a function of the two EXTREMES, so a content edit
    // keeping n_C ≥ 1 leaves it fixed while `doc_vspanset`'s content extent
    // moves with n_C. A caller that must observe a content-count change asks
    // for the extents; asking for the box would tell it nothing happened.
    let k = mem_kernel();
    let vs = insert3(&k); // n_C = 3
    seat_link(&k, &doc1(), &la(1)).expect("seat commits");
    seat_link(&k, &doc1(), &la(2)).expect("seat commits"); // n_L = 2
    let before = k.snapshot();
    let q_before = Query::new(&before);
    vs.delete(P1, &doc1(), vp(1, 3), n(1))
        .expect("delete commits"); // n_C = 2, still ≥ 1
    let after = k.snapshot();
    let q_after = Query::new(&after);
    // The box is [1,1] .. [2, n_L + 1) on both sides of the edit.
    let box_ = SpanSet::singleton(
        Span::from_endpoints(t(&[1, 1]), &t(&[2, 3])).expect("well-formed"),
    );
    assert_eq!(ok_of(q_before.doc_vspan(&doc1())), box_);
    assert_eq!(ok_of(q_after.doc_vspan(&doc1())), box_);
    // The extents are not: the content extent follows n_C.
    let extents = |q: &Query<'_, World>| {
        ok_of(q.doc_vspanset(&doc1()))
            .iter()
            .next()
            .expect("occupied ⇒ a content extent")
            .clone()
    };
    assert_eq!(
        extents(&q_before),
        Span::new(t(&[1, 1]), t(&[0, 3])).expect("T12")
    );
    assert_eq!(
        extents(&q_after),
        Span::new(t(&[1, 1]), t(&[0, 2])).expect("T12")
    );
}
