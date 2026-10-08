//! §E FINDDOCSCONTAINING (ASN-0124): present-tense containers, at chosen
//! requests and as a law over every window; the union of a region's spans;
//! the container filter and its consult; the gate; and the coverage and walk
//! budgets.

use std::cell::RefCell;

use skep_address::{Address, Span};
use skep_arrangement::{seat_link, HasM5, VSpec};
use skep_namespace::PrincipalId;
use skep_retrieval::{
    FindError, Query, RegionSpec, SpanFault, MAX_COMPARE_OPERAND_BLOCKS, MAX_FIND_COVERAGE_SPANS,
};

use crate::common::*;

#[test]
fn find_docs_containing_filters_to_present_tense_containers() {
    // ASN-0124 FD-SOUND: docs_ever_containing's historical superset is
    // narrowed by the present-tense filter to CURRENT holders; the raw union may
    // be mixed-length (M5 owns the level-class discipline); bare identities,
    // tumbler-ordered.
    // The length-9 origin is the owned fork of the PUBLISHED edition (the
    // one owned source `version` admits, PUB-2.9), grown by a declared
    // deposit; the draft doc1 supplies the length-8 half.
    let k = mem_kernel();
    let vs = insert3(&k); // doc1 = [ca1, ca2, ca3]
    deposit3(&k); // pdoc = [pca1, pca2, pca3]
    let (fork, _) = vs.version(PrincipalId(1), &pdoc(), None).expect("fork commits");
    assert_eq!(fork, vdoc()); // shares pdoc's three
    let (start, _) = vs
        .insert(P1, &fork, vp(1, 4), vec![val(b"z")], declared())
        .expect("fork deposit commits");
    assert_eq!(start, vca(1)); // the fork's chain mints LENGTH-9 elements
    vs.copy(
        P1,
        &doc2(),
        vp(1, 1),
        &[
            VSpec {
                source: doc1(),
                span: vspan(1, 1, 1),
            },
            VSpec {
                source: fork.clone(),
                span: vspan(1, 4, 1),
            },
        ],
    )
    .expect("mixed copy commits"); // doc2 = [ca1, vca1]
    {
        let s = k.snapshot();
        let q = Query::new(&s);
        // Mixed-length coverage {[ca1,ca2), [vca1,vca2)} passes raw through
        // M6; all three docs currently hold some of it, tumbler-ordered.
        assert_eq!(
            ok_of(q.find_docs_containing(&[region_spec(doc2(), vec![vspan(1, 1, 2)])])),
            vec![doc1(), doc2(), vdoc()]
        );
    }
    // doc1 drops ca1 — it stays an R-candidate (permanence) but the
    // present-tense filter removes it.
    vs.delete(P1, &doc1(), vp(1, 1), n(1)).expect("delete commits");
    let s = k.snapshot();
    let q = Query::new(&s);
    assert_eq!(
        ok_of(q.find_docs_containing(&[region_spec(doc2(), vec![vspan(1, 1, 2)])])),
        vec![doc2(), vdoc()]
    );
    // A depth-incompatible span contributes nothing — never a rejection.
    assert_eq!(
        ok_of(q.find_docs_containing(&[
            region_spec(doc1(), vec![deep_span(1)]),
            region_spec(doc2(), vec![vspan(1, 1, 2)]),
        ])),
        vec![doc2(), vdoc()]
    );
    // A link-subspace span passes the gate and stays inert: link placement
    // is R-uncoupled (J-LV), so it can add no spurious container.
    seat_link(&k, &doc1(), &la(1)).expect("seat commits");
    let s = k.snapshot();
    let q = Query::new(&s);
    assert_eq!(
        ok_of(q.find_docs_containing(&[region_spec(doc1(), vec![vspan(2, 1, 1)])])),
        Vec::<Address>::new()
    );
}

#[test]
fn find_docs_containing_unions_every_span_of_a_region() {
    // ASN-0124 FD-CONVEX/FD-COMPLETE: a region carries a SET of spans and
    // phase 1 unions every one of their images. Answering from the first span
    // alone would silently under-resolve and drop containers, which is the
    // hazard the operation names.
    let k = mem_kernel();
    three_runs(&k);
    let s = k.snapshot();
    let q = Query::new(&s);
    // Span 0 covers doc2's OWN content (doc2 alone holds it); span 1 covers
    // ca1, which doc1 holds too. Only the union names both containers.
    assert_eq!(
        ok_of(q.find_docs_containing(&[region_spec(doc2(), vec![vspan(1, 1, 1), vspan(1, 2, 1)])])),
        vec![doc1(), doc2()]
    );
    // The control that makes the line above mean something: the first span's
    // coverage alone names doc2 and nobody else.
    assert_eq!(
        ok_of(q.find_docs_containing(&[region_spec(doc2(), vec![vspan(1, 1, 1)])])),
        vec![doc2()]
    );
    // An empty request names no coverage and finds nothing.
    assert_eq!(ok_of(q.find_docs_containing(&[])), Vec::<Address>::new());
}

#[test]
fn find_docs_containing_answers_exactly_the_documents_holding_a_covered_address_now() {
    // ASN-0124 FD-SOUND and FD-COMPLETE together say the answer IS the set of
    // documents that currently hold some address the regions resolve to — a
    // law over every request, asked here of every window of both documents,
    // in T1 order. The oracle reads each document's positions off M5's
    // `point` alone, so it shares nothing with the coverage M6 builds, R, its
    // reverse index or the present-tense filter.
    //
    // The world is chosen so that a container can hold a run's SECOND
    // address and not its first: doc1 drops ca1 and keeps ca2, so it
    // contains doc2's run [ca1, ca2] through ca2 alone — the container a
    // coverage cut short of a run's whole extent would drop — and R, which
    // never shrinks, still names doc1 for ca1, so doc2's ca1 windows meet a
    // ghost the present-tense filter must drop.
    let k = mem_kernel();
    let vs = three_runs(&k); // doc1 = [ca1, ca2, ca3]; doc2 = [doc2_ca1][ca1, ca2][ca1]
    vs.delete(P1, &doc1(), vp(1, 1), n(1))
        .expect("delete commits"); // doc1 = [ca2, ca3]
    let s = k.snapshot();
    let q = Query::new(&s);
    let m5 = s.world().m5();
    // Every address `d`'s content arrangement binds now, position by position.
    let held = |d: &Address| -> Vec<Address> {
        let count = m5.content_count(d);
        (1u32..)
            .take_while(|&o| n(o) <= count)
            .map(|o| m5.point(d, &vp(1, o)).expect("D-SEQ★: [1, n_C] is bound"))
            .collect()
    };
    // The premise. doc1 and doc2 are the only documents the fixture
    // arranges, so they are every container the oracle can name.
    assert_eq!(held(&doc1()), vec![ca(2), ca(3)]);
    assert_eq!(held(&doc2()), vec![doc2_ca(1), ca(1), ca(2), ca(1)]);
    assert!(
        m5.docs_ever_containing(&m5.image(&doc2(), &vspan(1, 2, 1)))
            .contains(&doc1()),
        "the premise: R still names doc1 for ca1, which it no longer holds"
    );
    let documents = [doc1(), doc2()];
    for doc in &documents {
        let position_count = u32::try_from(held(doc).len()).expect("a small world");
        // Every start up to one past the last position, at every width up to
        // one more than the document holds: windows that open past the end
        // and windows that run over it are met as well as the ones inside.
        for start in 1..=position_count + 1 {
            for width in 1..=position_count + 1 {
                let window = vspan(1, start, width);
                let covered: Vec<Address> = (start..start + width)
                    .filter_map(|o| m5.point(doc, &vp(1, o)))
                    .collect();
                let want: Vec<Address> = documents
                    .iter()
                    .filter(|&d| held(d).iter().any(|a| covered.contains(a)))
                    .cloned()
                    .collect();
                let request = [region_spec(doc.clone(), vec![window.clone()])];
                assert_eq!(
                    ok_of(q.find_docs_containing(&request)),
                    want,
                    "the containers of {doc}'s window {window:?}"
                );
            }
        }
    }
}

#[test]
fn find_docs_containing_filtered_drops_a_container_at_its_identity() {
    // PUB-6.13/6.19, the door M10 calls: a CONTAINER the reader may not read
    // is dropped at its identity, and the answer is otherwise the unfiltered
    // one. M6 decides nothing about who may read: it applies the predicate it
    // is handed, per container.
    let k = mem_kernel();
    three_runs(&k);
    let s = k.snapshot();
    let q = Query::new(&s);
    let request = || vec![region_spec(doc2(), vec![vspan(1, 2, 1)])]; // ca1: held by both
    assert_eq!(
        ok_of(q.find_docs_containing(&request())),
        vec![doc1(), doc2()]
    );
    assert_eq!(
        ok_of(q.find_docs_containing_filtered(&request(), &|d| *d != doc1())),
        vec![doc2()]
    );
    // doc2 is also the region's own document, and is dropped like any
    // container.
    assert_eq!(
        ok_of(q.find_docs_containing_filtered(&request(), &|d| *d != doc2())),
        vec![doc1()]
    );
    // The identity predicate IS the unfiltered door.
    assert_eq!(
        ok_of(q.find_docs_containing_filtered(&request(), &|_| true)),
        ok_of(q.find_docs_containing(&request()))
    );
}

#[test]
fn find_docs_containing_filtered_consults_its_predicate_of_every_candidate_ahead_of_the_present_tense_filter(
) {
    // `find_docs_containing_filtered`'s card (PUB-6.17): the predicate is
    // asked of each CANDIDATE — M5's historical superset, ghosts included —
    // FIRST, before `arranges_any` is paid, and only after the gate has passed
    // the whole request. A ghost is therefore consulted and then dropped; a
    // filter that paid `arranges_any` first would never ask about it.
    let k = mem_kernel();
    let vs = three_runs(&k); // doc2 = [x][ca1, ca2][ca1]; doc1 = [ca1, ca2, ca3]
    vs.delete(P1, &doc1(), vp(1, 1), n(3))
        .expect("delete commits"); // doc1 holds nothing now: a GHOST for ca1
    let s = k.snapshot();
    let q = Query::new(&s);
    let asked: RefCell<Vec<Address>> = RefCell::new(Vec::new());
    let recording = |d: &Address| {
        asked.borrow_mut().push(d.clone());
        true
    };
    // Rejected on its second region: consulted of nothing.
    let _ = err_of(q.find_docs_containing_filtered(
        &[
            region_spec(doc2(), vec![vspan(1, 2, 1)]),
            region_spec(unregistered(), vec![]),
        ],
        &recording,
    ));
    assert!(
        asked.borrow().is_empty(),
        "a rejected request consults the predicate of nothing"
    );
    // Answered: the ghost doc1 is consulted as a candidate and dropped by
    // `arranges_any`; the answer names doc2 alone.
    assert_eq!(
        ok_of(q.find_docs_containing_filtered(
            &[region_spec(doc2(), vec![vspan(1, 2, 1)])],
            &recording
        )),
        vec![doc2()]
    );
    let mut consulted = asked.borrow().clone();
    consulted.sort(); // the candidate ORDER is M5's promise; the SET is this claim's
    assert_eq!(consulted, vec![doc1(), doc2()]);
}

#[test]
fn find_docs_containing_rejects_unregistered_and_malformed_regions() {
    // ASN-0124 FD-COMPLETE: a malformed span is a typed rejection with
    // (region, index) attribution — never a silent under-resolution; a
    // registered-empty region contributes nothing.
    let k = mem_kernel();
    insert3(&k);
    let s = k.snapshot();
    let q = Query::new(&s);
    assert!(matches!(
        err_of(q.find_docs_containing(&[region_spec(unregistered(), vec![vspan(1, 1, 1)])])),
        FindError::DocNotRegistered(d) if d == unregistered()
    ));
    let zeroed = Span::new(t(&[1, 0, 1]), t(&[0, 0, 1])).expect("T12-legal");
    assert!(matches!(
        err_of(q.find_docs_containing(&[region_spec(doc1(), vec![vspan(1, 1, 1), zeroed])])),
        FindError::MalformedSpan {
            region: 0,
            index: 1,
            fault: SpanFault::StartNotZeroFree
        }
    ));
    assert!(matches!(
        err_of(q.find_docs_containing(&[
            region_spec(doc1(), vec![vspan(1, 1, 1)]),
            region_spec(doc1(), vec![not_ordinal_level_span()]),
        ])),
        FindError::MalformedSpan {
            region: 1,
            index: 0,
            fault: SpanFault::NotOrdinalLevel
        }
    ));
    // Registered-but-empty doc2: nothing resolves, nothing contains.
    assert_eq!(
        ok_of(q.find_docs_containing(&[region_spec(doc2(), vec![vspan(1, 1, 1)])])),
        Vec::<Address>::new()
    );
    // A region with NO spans still names its document, and the registry gate
    // runs on it: nothing to resolve is not nothing to check.
    assert_eq!(
        err_of(q.find_docs_containing(&[
            region_spec(doc1(), vec![vspan(1, 1, 1)]),
            region_spec(unregistered(), vec![]),
        ])),
        FindError::DocNotRegistered(unregistered())
    );
}

#[test]
fn find_docs_containing_refuses_a_request_past_its_budget() {
    // The coverage is one side of a join against the WHOLE of R, and it is the
    // request's only factor in it — capped by nothing upstream, since a region
    // set nests two wire caps whose product only a body cap bounds. The
    // refusal is WHOLE: a truncated coverage would drop containers, which is
    // exactly FD-COMPLETE's hazard.
    let k = mem_kernel();
    insert3(&k); // doc1 is ONE run, so one span ⇒ one coverage span
    let s = k.snapshot();
    let q = Query::new(&s);
    let request = |count: usize| vec![region_spec(doc1(), vec![vspan(1, 1, 1); count])];
    // At the budget the same shape still answers, and answers completely.
    assert_eq!(
        ok_of(q.find_docs_containing(&request(MAX_FIND_COVERAGE_SPANS))),
        vec![doc1()]
    );
    // One span past it is refused, and the refusal names its own budget, as
    // COMPARE's two do, so a client narrows against the number rather than
    // guessing it.
    let e = err_of(q.find_docs_containing(&request(MAX_FIND_COVERAGE_SPANS + 1)));
    assert_eq!(e, FindError::TooMuchCoverage);
    assert!(e.to_string().contains(&MAX_FIND_COVERAGE_SPANS.to_string()));
}

#[test]
fn find_docs_containing_refuses_a_request_whose_coverage_outnumbers_the_budget_though_its_spans_do_not(
) {
    // The budget's own card: beyond M10's per-array wire cap it refuses "the
    // multi-run expansion, where one span over a fragmented document resolves
    // to many coverage spans from a single span on the wire", and the COVERAGE
    // count is what refuses it. doc2 resolves to THREE runs, so the two
    // requests below are `MAX/3` and `MAX/3 + 1` SPANS — both under the
    // budget's own span count and under any wire cap — and `MAX - (MAX mod 3)`
    // and three more COVERAGE spans, which is the only unit that explains one
    // being answered and the other refused. (The span count's own boundary is
    // pinned by the test that follows.)
    let k = mem_kernel();
    three_runs(&k); // doc2 = [doc2_ca1][ca1, ca2][ca1] — three runs
    let s = k.snapshot();
    let q = Query::new(&s);
    let request = |count: usize| vec![region_spec(doc2(), vec![vspan(1, 1, 4); count])];
    let under = MAX_FIND_COVERAGE_SPANS / 3;
    // The admitted request answers completely — both containers, not merely
    // "not refused".
    assert_eq!(
        ok_of(q.find_docs_containing(&request(under))),
        vec![doc1(), doc2()]
    );
    assert_eq!(
        err_of(q.find_docs_containing(&request(under + 1))),
        FindError::TooMuchCoverage
    );
}

#[test]
fn find_docs_containing_refuses_a_request_whose_spans_outnumber_the_budget_though_they_resolve_to_nothing(
) {
    // The budget's other count. Every span handed to M5 is one resolution
    // whether or not it yields coverage — a span opening past the arranged
    // extent yields none — so a coverage count alone would admit any number
    // of empty-resolving spans, from a nested region×span request the body
    // cap alone sizes. Over doc1's one run the walk budget prices each such
    // span at a single step and admits them all, so the SPAN count is what
    // refuses it, before phase 1 resolves past the budget.
    let k = mem_kernel();
    insert3(&k); // doc1 holds three positions
    let s = k.snapshot();
    let q = Query::new(&s);
    let past_end = || vspan(1, 1000, 1);
    // The premise: a past-end span images to NO coverage, so the coverage
    // count never moves and only the span count can explain a refusal below.
    assert!(
        s.world().m5().image(&doc1(), &past_end()).is_empty(),
        "the premise: a span past the arranged extent images to nothing"
    );
    let over = vec![region_spec(
        doc1(),
        vec![past_end(); MAX_FIND_COVERAGE_SPANS + 1],
    )];
    assert_eq!(
        err_of(q.find_docs_containing(&over)),
        FindError::TooMuchCoverage
    );
    // At the budget the same shape still answers — emptily, every span
    // imaging to nothing — so the resolutions are made, their number
    // bounded at the budget.
    let at = vec![region_spec(
        doc1(),
        vec![past_end(); MAX_FIND_COVERAGE_SPANS],
    )];
    assert_eq!(
        ok_of(q.find_docs_containing(&at)),
        Vec::<Address>::new()
    );
    // The NESTED region×span product past the budget — one span per region,
    // a region list no per-array wire cap prices — is refused the same way.
    let nested: Vec<RegionSpec> = (0..=MAX_FIND_COVERAGE_SPANS)
        .map(|_| region_spec(doc1(), vec![past_end()]))
        .collect();
    assert_eq!(
        err_of(q.find_docs_containing(&nested)),
        FindError::TooMuchCoverage
    );
    // A span M5 folds to nothing at once — a well-formed depth-3 span, or a
    // foreign-subspace one, both of which pass this gate — is handed to M5's
    // resolution and counted all the same.
    for folded in [deep_span(1), vspan(3, 1, 1)] {
        assert!(
            s.world().m5().image(&doc1(), &folded).is_empty(),
            "the premise: M5 folds it to nothing"
        );
        let over = vec![region_spec(
            doc1(),
            vec![folded.clone(); MAX_FIND_COVERAGE_SPANS + 1],
        )];
        assert_eq!(
            err_of(q.find_docs_containing(&over)),
            FindError::TooMuchCoverage
        );
        let at = vec![region_spec(doc1(), vec![folded; MAX_FIND_COVERAGE_SPANS])];
        assert_eq!(
            ok_of(q.find_docs_containing(&at)),
            Vec::<Address>::new()
        );
    }
}

#[test]
fn find_docs_containing_refuses_a_request_whose_spans_would_walk_past_the_walk_budget() {
    // The walk budget: M5 reaches a span by walking the run list from its
    // first run, so a span opening past the end of a fragmented document walks
    // every run and covers nothing — and with no coverage the candidate scan
    // is free, so the walk is the request's whole bill. The walk budget is the
    // operand budget's square, so over doc2's 8192 runs one span more than
    // `MAX_COMPARE_OPERAND_BLOCKS² / 8192` such spans is past it, and the
    // request is refused before any span is walked.
    let k = mem_kernel();
    fragmented_doc2(&k); // doc2 = 8192 one-position runs, every one ca1
    let s = k.snapshot();
    let q = Query::new(&s);
    let run_count = s.world().m5().content_run_count(&doc2());
    assert_eq!(run_count, 8192, "the premise: doc2 is 8192 runs");
    let past_budget = MAX_COMPARE_OPERAND_BLOCKS * MAX_COMPARE_OPERAND_BLOCKS / run_count + 1;
    assert_eq!(
        err_of(
            q.find_docs_containing(&[region_spec(doc2(), vec![vspan(1, 8193, 1); past_budget])])
        ),
        FindError::TooMuchCoverage
    );
    // The control: a span at doc2's first position walks two runs and is
    // answered — kept to a few, since the candidate scan behind it runs the
    // coverage against all of R, which holds a span for every run this
    // fixture placed.
    assert_eq!(
        ok_of(q.find_docs_containing(&[region_spec(doc2(), vec![vspan(1, 1, 1); 16])])),
        vec![doc1(), doc2()]
    );
}

#[test]
fn find_docs_containing_gates_the_whole_request_before_its_budget_can_refuse() {
    // §Errors, the budget clause: TooMuchCoverage fires only after the gate
    // has completed over the WHOLE request, so a gate fault outranks it
    // wherever it sits — here in a second region behind a first that alone
    // exceeds the budget. COMPARE's twin is pinned; this is
    // FINDDOCSCONTAINING's.
    let k = mem_kernel();
    insert3(&k);
    let s = k.snapshot();
    let q = Query::new(&s);
    let over = region_spec(doc1(), vec![vspan(1, 1, 1); MAX_FIND_COVERAGE_SPANS + 1]);
    assert_eq!(
        err_of(q.find_docs_containing(&[
            over.clone(),
            region_spec(doc1(), vec![not_ordinal_level_span()]),
        ])),
        FindError::MalformedSpan {
            region: 1,
            index: 0,
            fault: SpanFault::NotOrdinalLevel
        }
    );
    // The control: with the second region well-formed, the first is refused
    // for its size.
    assert_eq!(
        err_of(q.find_docs_containing(&[over, region_spec(doc1(), vec![vspan(1, 1, 1)])])),
        FindError::TooMuchCoverage
    );
}
