//! The composed queries (§D/§E): the historical candidates and the
//! present-tense filter, the level-class discipline, absent documents, and
//! the lazy resolution.

use skep_address::{subtree_of, Span, SpanSet};
use skep_arrangement::{seat_link, HasM5, Run, VSpec};
use skep_namespace::PrincipalId;

use crate::common::*;

#[test]
fn find_docs_containing_composes_candidates_with_the_present_tense_filter() {
    // §9: docs_ever_containing is the historical superset (P2 keeps the
    // deleter as a candidate); arranges_any is the current-containment
    // filter, the non-emptiness of project's footprint — all off ONE
    // snapshot.
    let k = mem_kernel();
    let vs = insert_abc(&k);
    vs.copy(
        P1,
        &doc2(),
        vp(1, 1),
        &[VSpec {
            source: doc1(),
            span: vspan(1, 1, 3),
        }],
    )
    .expect("copy commits");
    // doc1 deletes the region; doc2 still holds it.
    vs.delete(P1, &doc1(), vp(1, 1), n(3)).expect("delete commits");
    let s = k.snapshot();
    let m5 = s.world().m5();
    let region = SpanSet::singleton(
        Span::from_endpoints(ca(1).tumbler().clone(), ca(4).tumbler())
            .expect("well-formed I-extent"),
    );
    // Candidate superset: both docs have ever contained the region, doc1 as
    // FD-GHOST's ghost.
    assert_eq!(m5.docs_ever_containing(&region), vec![doc1(), doc2()]);
    // Current-containment narrows to doc2, and the footprint says the same.
    assert!(!m5.arranges_any(&doc1(), &region));
    assert!(m5.arranges_any(&doc2(), &region));
    assert!(m5.project(&doc1(), &region).is_empty());
    assert!(!m5.project(&doc2(), &region).is_empty());
    // And doc1's loss is exactly what SHOWDELETIONS reports.
    let d = m5.deletions(&doc1());
    let spans: Vec<Span> = d.iter().cloned().collect();
    assert_eq!(spans.len(), 1);
    assert_eq!(spans[0].start(), ca(1).tumbler());
}

#[test]
fn mixed_length_transclusion_flows_through_the_level_class_discipline() {
    // §2/§9: a document transcluding across heterogeneous-depth origins has
    // mixed-length covers; deletions differences per class, project stays
    // total under cross-length coverage. The deeper origin is the owned fork
    // of the published edition (a member's elements are length 9).
    let k = mem_kernel();
    let vs = deposit_abc(&k);
    let (fork, _) = vs.version(PrincipalId(1), &pdoc(), None).expect("fork commits");
    vs.insert(P1, &fork, vp(1, 4), vec![val(b"y"), val(b"z")], declared())
        .expect("a deposit at the fork's fresh positions commits"); // mints vca(1..2), length 9
    vs.copy(
        P1,
        &doc2(),
        vp(1, 1),
        &[
            VSpec {
                source: pdoc(),
                span: vspan(1, 1, 2),
            },
            VSpec {
                source: fork.clone(),
                span: vspan(1, 4, 2),
            },
        ],
    )
    .expect("mixed copy commits");
    {
        let s = k.snapshot();
        let m5 = s.world().m5();
        assert_eq!(m5.content_count(&doc2()), n(4));
        let runs: Vec<&Run> = m5.content_runs(&doc2()).collect();
        assert_eq!(runs.len(), 2); // cross-length runs never coalesce
        assert_eq!(runs[0].i_start(), &pca(1));
        assert_eq!(runs[1].i_start(), &vca(1));
        // The resolution's lift is the RAW mixed-length cover.
        let cov: SpanSet = m5
            .iter_resolve(&doc2(), &vspan(1, 1, 4))
            .map(|r| r.iextent())
            .collect();
        let lens: Vec<usize> = cov.iter().map(|span| span.start().len()).collect();
        assert_eq!(lens, vec![8, 9]);
        // project is fault-free under a cross-length prefix cover: pdoc's
        // content-base subtree picks out only the length-8 positions.
        let content_base = SpanSet::singleton(subtree_of(&t(&[1, 0, 1, 0, 3, 0, 1])));
        let got = m5.project(&doc2(), &content_base);
        let spans: Vec<Span> = got.iter().cloned().collect();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].start(), &t(&[1, 1]));
        assert_eq!(spans[0].width(), &t(&[0, 2]));
    }
    // Delete everything in doc2: BOTH classes surface in deletions.
    vs.delete(P1, &doc2(), vp(1, 1), n(4)).expect("delete commits");
    let s = k.snapshot();
    let d = s.world().m5().deletions(&doc2());
    let mut lens: Vec<usize> = d.iter().map(|span| span.start().len()).collect();
    lens.sort_unstable();
    assert_eq!(lens, vec![8, 9]);
}

#[test]
fn reads_fold_an_absent_document_to_empty_results() {
    // §D/§E: absent doc ⇒ ⟨⟩/None/0 — M5 does not distinguish
    // registered-empty from unallocated (that is M6's, via M3).
    let k = mem_kernel();
    // doc1 is populated in BOTH subspaces and has a deletion on record, so
    // every answer below is about doc2's ABSENCE rather than about an empty
    // store: against a genesis world these reads would pass even if they
    // ignored the document they are asked about.
    let vs = insert_abc(&k);
    seat_link(&k, &doc1(), &a(&[1, 0, 1, 0, 1, 0, 2, 1])).expect("seat commits");
    vs.delete(P1, &doc1(), vp(1, 1), n(1)).expect("delete commits");
    let s = k.snapshot();
    let m5 = s.world().m5();
    assert!(m5.resolve(&doc2(), &vspan(1, 1, 1)).is_empty());
    assert_eq!(m5.point(&doc2(), &vp(1, 1)), None);
    assert_eq!(m5.content_runs(&doc2()).len(), 0);
    assert_eq!(m5.link_runs(&doc2()).len(), 0);
    assert_eq!(m5.content_count(&doc2()), n(0));
    assert_eq!(m5.link_count(&doc2()), n(0));
    assert!(m5.deletions(&doc2()).is_empty());
    assert!(m5
        .project(&doc2(), &SpanSet::singleton(subtree_of(doc2().tumbler())))
        .is_empty());
    assert!(m5.docs_ever_containing(&SpanSet::empty()).is_empty());
    // The positive control: R is not empty, and the reads that answer ⟨⟩ for
    // doc2 answer for doc1 — so the sweep above is about the document asked
    // for, not about a store with nothing in it.
    let placed = SpanSet::singleton(
        Span::from_endpoints(ca(1).tumbler().clone(), ca(4).tumbler())
            .expect("well-formed I-extent"),
    );
    assert_eq!(m5.docs_ever_containing(&placed), vec![doc1()]);
    assert!(!m5.deletions(&doc1()).is_empty());
    assert_eq!(m5.content_count(&doc1()), n(2));
    assert_eq!(m5.link_count(&doc1()), n(1));
}

#[test]
fn the_lazy_resolution_yields_what_resolve_collects_and_a_prefix_when_stopped() {
    // §2: a consumer with a budget of its own — M6's COMPARE blocks and
    // FINDDOCSCONTAINING coverage, M7's and M10's slot spans — pulls runs
    // one at a time and stops at that budget: what it pulls is `resolve`'s
    // answer, run for run, and what it holds on stopping is a prefix of it.
    // Asked from a foreign crate, which is where those budgets live, over
    // both subspaces, a clamped opening, one run's interior, the seam of a
    // self-transclusion and the empty resolution past the arranged end.
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
    .expect("self-copy commits"); // [ca1..3][ca1..3]: two runs
    seat_link(&k, &doc1(), &a(&[1, 0, 1, 0, 1, 0, 2, 1])).expect("seat commits");
    let s = k.snapshot();
    let m5 = s.world().m5();
    assert_eq!(m5.content_run_count(&doc1()), 2, "the premise: a seam to resolve across");
    for span in [
        vspan(1, 1, 6),
        vspan(1, 2, 4),
        vspan(1, 0, 3),
        vspan(1, 4, 1),
        vspan(1, 7, 2),
        vspan(2, 1, 1),
    ] {
        let whole = m5.resolve(&doc1(), &span);
        assert_eq!(m5.iter_resolve(&doc1(), &span).collect::<Vec<_>>(), whole, "{span:?}");
        for take in 0..=whole.len() {
            assert_eq!(
                m5.iter_resolve(&doc1(), &span).take(take).collect::<Vec<_>>(),
                whole[..take],
                "{span:?} stopped after {take}"
            );
        }
    }
    // The resolutions are what their spans name — so the agreement above is
    // not two empty answers agreeing.
    assert_eq!(m5.resolve(&doc1(), &vspan(1, 2, 4)).len(), 2, "across the seam");
    assert!(m5.resolve(&doc1(), &vspan(1, 7, 2)).is_empty(), "past the arranged end");
    assert_eq!(m5.resolve(&doc1(), &vspan(2, 1, 1)).len(), 1, "the link subspace");
}
