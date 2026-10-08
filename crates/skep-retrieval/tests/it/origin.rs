//! §C SHOWORIGIN, V-arity (ASN-0077): deduplicated origins in tumbler order,
//! each reported by its address whether or not this node registers it, and
//! WF_V's inadmissible cases, each refused distinctly and never clipped.

use skep_address::Span;
use skep_arrangement::seat_link;
use skep_namespace::{HasM3, PrincipalId};
use skep_retrieval::{ExtentError, OriginError, Query, SpanFault};

use crate::common::*;

#[test]
fn show_origin_v_projects_deduplicated_origins_in_tumbler_order() {
    // ASN-0077 O2/O5: one origin per run (block uniformity), deduplicated,
    // tumbler-ordered; the link arity reports the home document (CL-OWN).
    let k = mem_kernel();
    three_runs(&k); // doc2 = [doc2_ca1][ca1, ca2][ca1]
    seat_link(&k, &doc2(), &doc2_la(1)).expect("seat commits");
    let s = k.snapshot();
    let q = Query::new(&s);
    // Three runs, origins {doc2, doc1, doc1} → deduped, T1-sorted.
    assert_eq!(
        ok_of(q.show_origin_v(&doc2(), &vspan(1, 1, 4))),
        vec![doc1(), doc2()]
    );
    // A sub-span lying wholly in transcluded content names doc1 alone.
    assert_eq!(
        ok_of(q.show_origin_v(&doc2(), &vspan(1, 2, 2))),
        vec![doc1()]
    );
    // Link subspace: origin is the home document, uniformly.
    assert_eq!(
        ok_of(q.show_origin_v(&doc2(), &vspan(2, 1, 1))),
        vec![doc2()]
    );
}

#[test]
fn show_origin_v_projects_an_origin_at_whatever_depth_its_document_sits() {
    // ASN-0077 O2 through M1's `document_of`: the origin is the DOCUMENT
    // PREFIX of a run's I-start, at whatever depth that document sits. A
    // version fork is a document one component deeper than its source and
    // mints LENGTH-9 content elements, so a projection that assumed the
    // source's shape would name doc1 for content doc1 never allocated — and
    // every other origin case in this suite would still pass, all of them
    // being five-component documents over eight-component elements. The
    // source is the PUBLISHED edition — the one owned source `version`
    // admits (PUB-2.9) — and the fork, a published member, is grown by a
    // declared deposit at its fresh position (PUB-2.66).
    let k = mem_kernel();
    let vs = deposit3(&k);
    let (fork, _) = vs.version(PrincipalId(1), &pdoc(), None).expect("fork commits");
    assert_eq!(fork, vdoc()); // one component deeper than its source…
    let (start, _) = vs
        .insert(P1, &fork, vp(1, 4), vec![val(b"z")], declared())
        .expect("fork deposit commits");
    assert_eq!(start, vca(1)); // …and its own chain one component longer
    let s = k.snapshot();
    let q = Query::new(&s);
    // The fork's own position: the origin is the FORK, never its source.
    assert_eq!(ok_of(q.show_origin_v(&fork, &vspan(1, 4, 1))), vec![vdoc()]);
    // The shared prefix alone names only the source.
    assert_eq!(ok_of(q.show_origin_v(&fork, &vspan(1, 1, 3))), vec![pdoc()]);
    // Both runs: two origins at two depths, T1-ordered — and pdoc is a PREFIX
    // of vdoc, so the listing is the shorter-first rule rather than a
    // same-length comparison.
    assert_eq!(
        ok_of(q.show_origin_v(&fork, &vspan(1, 1, 4))),
        vec![pdoc(), vdoc()]
    );
}

#[test]
fn show_origin_v_reports_an_origin_registered_nowhere_here_by_its_address() {
    // ASN-0077 O0/O3: an origin is the DOCUMENT PREFIX of a run's I-start,
    // read off the address with no registry consulted (PUB-6.38), so
    // SHOWORIGIN reports it whether or not this node registers it — whole, as
    // PUB-6.15 has every origin come back, and never dropped, which would
    // answer a span with fewer origins than its runs have. RES-162's unheld
    // origin is the case: a guest-class mirror's published window onto a
    // draft it never held. It is the read that names that origin NEXT that is
    // refused `DocNotRegistered` — PUB-8.9's probe answer at a mirror.
    let k = mem_kernel();
    unheld_origin_head(&k); // pdoc's head vdoc = [pca1][two positions under the unheld member]
    let s = k.snapshot();
    let q = Query::new(&s);
    assert!(
        !s.world().m3().is_registered_document(&unheld_member()),
        "the premise: the second run's origin is registered nowhere on this node"
    );
    // pdoc is a proper prefix of the unheld member, so T1 lists it first.
    assert_eq!(
        ok_of(q.show_origin_v(&pdoc(), &vspan(1, 1, 3))),
        vec![pdoc(), unheld_member()]
    );
    // The probe a reader would follow it with is refused, not answered emptily.
    assert_eq!(
        err_of(q.doc_vspanset(&unheld_member())),
        ExtentError::DocNotRegistered
    );
    assert_eq!(
        err_of(q.show_origin_v(&unheld_member(), &vspan(1, 1, 1))),
        OriginError::DocNotRegistered
    );
}

#[test]
fn show_origin_v_admits_the_exact_extent_and_rejects_one_position_past_it() {
    // ASN-0077 WF_V(vi): the test is `resolved < count` — the span's nominal
    // extent (ASN-0115), the count it names — so a span covering the bound
    // prefix EXACTLY is admissible and one position more is rejected — never
    // clipped to the surviving sub-span as RETRIEVEV's R6 would (O13). The
    // equal case and the overrun-by-one are the two sides of that inequality.
    let k = mem_kernel();
    insert3(&k);
    let s = k.snapshot();
    let q = Query::new(&s);
    assert_eq!(
        ok_of(q.show_origin_v(&doc1(), &vspan(1, 1, 3))),
        vec![doc1()]
    );
    assert_eq!(
        ok_of(q.show_origin_v(&doc1(), &vspan(1, 3, 1))),
        vec![doc1()]
    );
    assert!(matches!(
        err_of(q.show_origin_v(&doc1(), &vspan(1, 1, 4))),
        OriginError::RangeNotPresent
    ));
    assert!(matches!(
        err_of(q.show_origin_v(&doc1(), &vspan(1, 3, 2))),
        OriginError::RangeNotPresent
    ));
}

#[test]
fn show_origin_v_rejects_each_inadmissible_case_distinctly() {
    // ASN-0077 WF_V(i–vi)/O13 — reject, never clip; the checks run in the
    // documented order: registered → well-formed → subspace → empty →
    // depth → range.
    let k = mem_kernel();
    insert3(&k);
    let s = k.snapshot();
    let q = Query::new(&s);
    // (i) not registered — checked first, even with a malformed span.
    assert!(matches!(
        err_of(q.show_origin_v(&unregistered(), &vspan(1, 1, 1))),
        OriginError::DocNotRegistered
    ));
    assert!(matches!(
        err_of(q.show_origin_v(&unregistered(), &not_ordinal_level_span())),
        OriginError::DocNotRegistered
    ));
    // (ii/iv) malformed — before any subspace reading (a malformed span in
    // a foreign subspace is MalformedSpan, not NoSuchSubspace).
    assert!(matches!(
        err_of(q.show_origin_v(&doc1(), &not_ordinal_level_span())),
        OriginError::MalformedSpan(SpanFault::NotOrdinalLevel)
    ));
    let foreign_malformed = Span::new(t(&[3, 1]), t(&[1, 0])).expect("T12-legal");
    assert!(matches!(
        err_of(q.show_origin_v(&doc1(), &foreign_malformed)),
        OriginError::MalformedSpan(SpanFault::NotOrdinalLevel)
    ));
    // Foreign subspace ∉ {s_C, s_L} — distinct from a real-but-empty one,
    // and checked before empty/depth (a deep foreign span is still foreign).
    assert!(matches!(
        err_of(q.show_origin_v(&doc1(), &vspan(3, 1, 1))),
        OriginError::NoSuchSubspace
    ));
    assert!(matches!(
        err_of(q.show_origin_v(&doc1(), &deep_span(3))),
        OriginError::NoSuchSubspace
    ));
    // (iii) a real but EMPTY subspace: the link side of doc1 (no links) and
    // the content side of registered-empty doc2.
    assert!(matches!(
        err_of(q.show_origin_v(&doc1(), &vspan(2, 1, 1))),
        OriginError::EmptySubspace
    ));
    assert!(matches!(
        err_of(q.show_origin_v(&doc2(), &vspan(1, 1, 1))),
        OriginError::EmptySubspace
    ));
    // Empty is checked BEFORE depth: a deep LINK span over link-less doc1 is
    // EmptySubspace, not DepthIncompatible.
    assert!(matches!(
        err_of(q.show_origin_v(&doc1(), &deep_span(2))),
        OriginError::EmptySubspace
    ));
    // (v) depth-incompatible: well-formed #start = 3 over the occupied
    // content subspace — its own verdict, distinct from the range case.
    assert!(matches!(
        err_of(q.show_origin_v(&doc1(), &deep_span(1))),
        OriginError::DepthIncompatible
    ));
    // (vi) a depth-2 span overrunning the bound prefix — partial resolution
    // is REJECTED, never clipped to the surviving sub-span (O13).
    assert!(matches!(
        err_of(q.show_origin_v(&doc1(), &vspan(1, 2, 5))),
        OriginError::RangeNotPresent
    ));
    assert!(matches!(
        err_of(q.show_origin_v(&doc1(), &vspan(1, 4, 1))),
        OriginError::RangeNotPresent
    ));
}
