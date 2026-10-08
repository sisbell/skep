//! The `Query` handle — one pinned snapshot, never a write, a borrow that
//! copies — the registry gate every operation opens with, the request gate's
//! precedence across the operations that take a whole request, and the walk
//! budget's price and precedence, which cross the three budgeted operations.

use skep_address::{Address, Span, SpanSet};
use skep_arrangement::{seat_link, Deposit, HasM5, VSpec};
use skep_kernel::Seq;
use skep_namespace::HasM3;
use skep_retrieval::{
    CompareError, DeletionsError, Delivery, DeliveryItem, ExtentError, FindError, Operand,
    OriginError, Query, RetrieveError, SpanFault, MAX_COMPARE_OPERAND_BLOCKS,
};

use crate::common::*;

#[test]
fn as_of_reports_the_pinned_seq_and_queries_never_mutate() {
    // §Public interface: as_of is the committed index this query reads (V1
    // retrospective); every operation is a pure read — no commit, ever.
    let k = mem_kernel();
    let vs = insert3(&k);
    seat_link(&k, &doc1(), &la(1)).expect("seat commits");
    vs.copy(
        P1,
        &doc2(),
        vp(1, 1),
        &[VSpec {
            source: doc1(),
            span: vspan(1, 1, 2),
        }],
    )
    .expect("copy commits");
    let before = k.current_seq();
    let s = k.snapshot();
    let q = Query::new(&s);
    assert_eq!(q.as_of(), s.seq());
    assert_eq!(q.as_of(), before);
    // Run every operation off the one snapshot…
    let _ = ok_of(q.retrieve_v(&[spec(doc1(), vspan(1, 1, 3))]));
    let _ = ok_of(q.doc_vspan(&doc1()));
    let _ = ok_of(q.doc_vspanset(&doc1()));
    let _ = ok_of(q.show_origin_v(&doc1(), &vspan(1, 1, 3)));
    let _ = ok_of(q.show_deletions(&doc1(), &doc2()));
    let _ = ok_of(q.compare(
        &[region_spec(doc1(), vec![vspan(1, 1, 3)])],
        &[region_spec(doc2(), vec![vspan(1, 1, 2)])],
    ));
    let _ = ok_of(q.find_docs_containing(&[region_spec(doc2(), vec![vspan(1, 1, 2)])]));
    // …and nothing committed.
    assert_eq!(k.current_seq(), before);
}

#[test]
fn the_query_handle_is_a_borrow_and_copies_like_one() {
    // §Public interface: a Query owns nothing and holds one borrow, so it
    // copies rather than moves, and every copy reads the SAME pinned
    // snapshot — which is the whole of what "one Query per logical query"
    // protects. It renders as the coordinate it is pinned to, since the
    // snapshot behind it has no Debug of its own.
    let k = mem_kernel();
    insert3(&k);
    let s = k.snapshot();
    let q = Query::new(&s);
    fn consume(q: Query<'_, World>) -> Seq {
        q.as_of()
    }
    assert_eq!(consume(q), s.seq()); // by value…
    assert_eq!(q.as_of(), s.seq()); // …and q is still usable: Copy, not moved.
    let copy = q;
    assert_eq!(copy.as_of(), q.as_of());
    assert_eq!(format!("{q:?}"), format!("Query {{ as_of: {:?}, .. }}", s.seq()));
}

#[test]
fn a_query_answers_from_its_pinned_snapshot_after_later_commits() {
    // §Public interface: every operation is a pure function of ONE consistent
    // M2 snapshot — the discharge of M2's clause 6 and the single-Σ
    // requirement of ASN-0075/0122/0124. A handle taken before a commit
    // answers from the state it pinned, never from the state that followed.
    let k = mem_kernel();
    let vs = insert3(&k);
    let s = k.snapshot();
    let q = Query::new(&s);
    vs.insert(P1, &doc1(), vp(1, 4), vec![val(b"d")], Deposit::Undeclared)
        .expect("insert commits");
    assert_ne!(
        k.current_seq(),
        q.as_of(),
        "the fixture committed after the pin"
    );
    // Three positions, not four: the fourth is not in this query's world.
    assert_eq!(
        ok_of(q.retrieve_v(&[spec(doc1(), vspan(1, 1, 4))])),
        Delivery(vec![
            DeliveryItem::Content(val(b"a")),
            DeliveryItem::Content(val(b"b")),
            DeliveryItem::Content(val(b"c")),
        ])
    );
    // The extent is the pinned count, not the live one.
    assert_eq!(
        ok_of(q.doc_vspanset(&doc1())),
        SpanSet::singleton(Span::new(t(&[1, 1]), t(&[0, 3])).expect("T12"))
    );
    // The control: a handle taken now sees all four.
    let s2 = k.snapshot();
    let q2 = Query::new(&s2);
    assert_eq!(
        ok_of(q2.retrieve_v(&[spec(doc1(), vspan(1, 1, 4))])).len(),
        4
    );
}

#[test]
fn every_operation_refuses_an_allocated_address_that_is_not_a_document() {
    // §The distinction every operation opens with: M6 gates on M3's
    // `is_registered_document`, which is NARROWER than `is_allocated` — an
    // account address and a content element are both allocated and neither is
    // a document. Reading the wider oracle turns each of these rejections
    // into a spurious empty success.
    let k = mem_kernel();
    insert3(&k);
    let s = k.snapshot();
    let q = Query::new(&s);
    for d in [a(&[1, 0, 1]), ca(1)] {
        // an ACCOUNT (genesis), an ELEMENT (insert3)
        let m3 = s.world().m3();
        assert!(m3.is_allocated(&d), "the premise: {d} IS allocated");
        assert!(!m3.is_registered_document(&d), "…and is not a document");
        assert_eq!(
            err_of(q.retrieve_v(&[spec(d.clone(), vspan(1, 1, 1))])),
            RetrieveError::DocNotRegistered(d.clone())
        );
        assert_eq!(err_of(q.doc_vspan(&d)), ExtentError::DocNotRegistered);
        assert_eq!(err_of(q.doc_vspanset(&d)), ExtentError::DocNotRegistered);
        assert_eq!(
            err_of(q.show_origin_v(&d, &vspan(1, 1, 1))),
            OriginError::DocNotRegistered
        );
        assert_eq!(
            err_of(q.show_deletions(&d, &doc1())),
            DeletionsError::DocNotRegistered(d.clone())
        );
        assert_eq!(
            err_of(q.compare(&[region_spec(d.clone(), vec![vspan(1, 1, 1)])], &[])),
            CompareError::DocNotRegistered(d.clone())
        );
        assert_eq!(
            err_of(q.find_docs_containing(&[region_spec(d.clone(), vec![vspan(1, 1, 1)])])),
            FindError::DocNotRegistered(d.clone())
        );
    }
}

#[test]
fn the_request_gate_reports_the_first_fault_in_request_order() {
    // The gate walks the request IN ORDER and the FIRST fault wins, whatever
    // its kind — which is what makes `index` / `(region, index)` /
    // `(operand, region, index)` localization mean anything. Within ONE spec
    // the registry check precedes the span gate; ACROSS specs, request order
    // decides. Each request below carries two faults that would be reported
    // differently, so only the ordering can explain which is reported.
    let k = mem_kernel();
    insert3(&k);
    let s = k.snapshot();
    let q = Query::new(&s);
    assert!(matches!(
        err_of(q.retrieve_v(&[
            spec(doc1(), not_ordinal_level_span()),
            spec(unregistered(), vspan(1, 1, 1))
        ])),
        RetrieveError::MalformedSpec {
            index: 0,
            fault: SpanFault::NotOrdinalLevel
        }
    ));
    assert!(matches!(
        err_of(q.retrieve_v(&[
            spec(unregistered(), vspan(1, 1, 1)),
            spec(doc1(), not_ordinal_level_span()),
        ])),
        RetrieveError::DocNotRegistered(d) if d == unregistered()
    ));
    assert!(matches!(
        err_of(q.find_docs_containing(&[
            region_spec(doc1(), vec![not_ordinal_level_span()]),
            region_spec(unregistered(), vec![vspan(1, 1, 1)]),
        ])),
        FindError::MalformedSpan {
            region: 0,
            index: 0,
            fault: SpanFault::NotOrdinalLevel
        }
    ));
    assert!(matches!(
        err_of(q.compare(
            &[region_spec(doc1(), vec![not_ordinal_level_span()])],
            &[region_spec(unregistered(), vec![vspan(1, 1, 1)])],
        )),
        CompareError::MalformedSpan {
            operand: Operand::First,
            region: 0,
            index: 0,
            fault: SpanFault::NotOrdinalLevel
        }
    ));
    // Within ONE operand, request order runs across its regions and their
    // spans too, not only from ρ₁ to ρ₂: region 0's malformed span outranks
    // region 1's unregistered document, and a malformed span outranks a
    // link-started span listed after it — so a gate that checked an
    // operand's documents, or a region's residences, in a pass of their own
    // would speak for the later fault.
    assert_eq!(
        err_of(q.compare(
            &[
                region_spec(doc1(), vec![not_ordinal_level_span()]),
                region_spec(unregistered(), vec![vspan(1, 1, 1)]),
            ],
            &[],
        )),
        CompareError::MalformedSpan {
            operand: Operand::First,
            region: 0,
            index: 0,
            fault: SpanFault::NotOrdinalLevel
        }
    );
    assert_eq!(
        err_of(q.compare(
            &[region_spec(
                doc1(),
                vec![not_ordinal_level_span(), vspan(2, 1, 1)]
            )],
            &[],
        )),
        CompareError::MalformedSpan {
            operand: Operand::First,
            region: 0,
            index: 0,
            fault: SpanFault::NotOrdinalLevel
        }
    );
    // …and within one FINDDOCSCONTAINING region, the first malformed span
    // speaks, not the last.
    let zeroed = Span::new(t(&[1, 0, 1]), t(&[0, 0, 1])).expect("T12-legal");
    let two_malformed = [region_spec(doc1(), vec![zeroed, not_ordinal_level_span()])];
    assert_eq!(
        err_of(q.find_docs_containing(&two_malformed)),
        FindError::MalformedSpan {
            region: 0,
            index: 0,
            fault: SpanFault::StartNotZeroFree
        }
    );
    // ρ₂'s documents are gated too, after ρ₁'s — the operand-2 registry
    // check no single-operand request can reach.
    assert!(matches!(
        err_of(q.compare(
            &[region_spec(doc1(), vec![vspan(1, 1, 1)])],
            &[region_spec(unregistered(), vec![])],
        )),
        CompareError::DocNotRegistered(d) if d == unregistered()
    ));
}

#[test]
fn the_request_gate_checks_the_registry_before_the_spans_of_its_own_region() {
    // §Errors: within one operation enum, declaration order IS check order —
    // so `CompareError::DocNotRegistered` outranks BOTH `NotContentSubspace`
    // and `MalformedSpan`, and `FindError`'s outranks `MalformedSpan`. Each
    // request below is faulty two ways in the SAME region, so only the
    // within-region order can explain the verdict; every other gate test puts
    // its two faults in different regions, where request order decides instead.
    // (RETRIEVEV's spec-level twin is pinned in
    // `retrieve_v_rejects_the_whole_request_on_any_malformed_spec`.)
    let k = mem_kernel();
    insert3(&k);
    let s = k.snapshot();
    let q = Query::new(&s);
    assert_eq!(
        err_of(q.compare(
            &[region_spec(unregistered(), vec![not_ordinal_level_span()])],
            &[],
        )),
        CompareError::DocNotRegistered(unregistered())
    );
    // …and above the residence check too, which itself outranks
    // well-formedness: a link-started span in an unregistered region reports
    // the registry, not the subspace.
    assert_eq!(
        err_of(q.compare(&[region_spec(unregistered(), vec![vspan(2, 1, 1)])], &[])),
        CompareError::DocNotRegistered(unregistered())
    );
    assert_eq!(
        err_of(q.find_docs_containing(&[region_spec(
            unregistered(),
            vec![not_ordinal_level_span()]
        )])),
        FindError::DocNotRegistered(unregistered())
    );
}

#[test]
fn the_walk_budget_prices_a_span_that_resolves_to_nothing_like_any_other() {
    // Crate doc, *What M6 refuses for size*: the walk refusal answers a PRICE
    // read before the walk, and a span that resolves to nothing is priced too
    // — a depth-incompatible one (R6's silent degradation, X12's
    // consulting-state success) at its whole run list, a foreign-subspace one
    // against both lists up to its reach. None is refused for what it names;
    // enough of them over a fragmented document refuse the request for its
    // size. Exactly the budget is admitted.
    let k = mem_kernel();
    fragmented_doc2(&k); // doc2 = 8192 one-position runs
    let s = k.snapshot();
    let q = Query::new(&s);
    let run_count = s.world().m5().content_run_count(&doc2());
    assert_eq!(run_count, 8192, "the premise: doc2 is 8192 runs");
    let at_budget = MAX_COMPARE_OPERAND_BLOCKS * MAX_COMPARE_OPERAND_BLOCKS / run_count;
    for degraded in [deep_span(1), vspan(3, 8193, 1)] {
        assert!(
            ok_of(q.retrieve_v(&[spec(doc2(), degraded.clone())])).is_empty(),
            "the premise: the spec degrades to nothing (R6)"
        );
        assert!(ok_of(q.retrieve_v(&vec![spec(doc2(), degraded.clone()); at_budget])).is_empty());
        assert_eq!(
            err_of(q.retrieve_v(&vec![spec(doc2(), degraded.clone()); at_budget + 1])),
            RetrieveError::TooManyItems
        );
        assert_eq!(
            ok_of(
                q.find_docs_containing(&[region_spec(doc2(), vec![degraded.clone(); at_budget])])
            ),
            Vec::<Address>::new()
        );
        assert_eq!(
            err_of(q.find_docs_containing(&[region_spec(doc2(), vec![degraded; at_budget + 1])])),
            FindError::TooMuchCoverage
        );
    }
    // COMPARE's gate admits only the depth-incompatible one.
    let one = vec![region_spec(doc1(), vec![vspan(1, 1, 1)])];
    assert!(
        ok_of(q.compare(&[region_spec(doc2(), vec![deep_span(1); at_budget])], &one)).is_empty()
    );
    assert_eq!(
        err_of(q.compare(
            &[region_spec(doc2(), vec![deep_span(1); at_budget + 1])],
            &one
        )),
        CompareError::TooManyBlocks {
            operand: Operand::First
        }
    );
}

#[test]
fn a_gate_fault_outranks_the_walk_refusal_at_every_operation() {
    // §Errors: a budget refusal fires only after the gate has passed the
    // WHOLE request, so a gate fault outranks it wherever it sits — here
    // behind a first unit whose walk alone is priced past the budget. Each
    // operation's gate-before-budget test pins the span count; this is the
    // walk.
    let k = mem_kernel();
    fragmented_doc2(&k); // doc2 = 8192 one-position runs
    let s = k.snapshot();
    let q = Query::new(&s);
    let run_count = s.world().m5().content_run_count(&doc2());
    assert_eq!(run_count, 8192, "the premise: doc2 is 8192 runs");
    let past_budget = MAX_COMPARE_OPERAND_BLOCKS * MAX_COMPARE_OPERAND_BLOCKS / run_count + 1;
    let past_end = || vspan(1, 8193, 1);
    let mut specs = vec![spec(doc2(), past_end()); past_budget];
    specs.push(spec(doc1(), not_ordinal_level_span()));
    assert_eq!(
        err_of(q.retrieve_v(&specs)),
        RetrieveError::MalformedSpec {
            index: past_budget,
            fault: SpanFault::NotOrdinalLevel
        }
    );
    assert_eq!(
        err_of(q.find_docs_containing(&[
            region_spec(doc2(), vec![past_end(); past_budget]),
            region_spec(doc1(), vec![not_ordinal_level_span()]),
        ])),
        FindError::MalformedSpan {
            region: 1,
            index: 0,
            fault: SpanFault::NotOrdinalLevel
        }
    );
    assert_eq!(
        err_of(q.compare(
            &[region_spec(doc2(), vec![past_end(); past_budget])],
            &[region_spec(doc1(), vec![not_ordinal_level_span()])],
        )),
        CompareError::MalformedSpan {
            operand: Operand::Second,
            region: 0,
            index: 0,
            fault: SpanFault::NotOrdinalLevel
        }
    );
    // The controls: with the gate fault removed, each request is refused for
    // its walk — so the first unit IS past the walk budget, and only the
    // precedence can explain the verdicts above.
    specs.pop();
    assert_eq!(err_of(q.retrieve_v(&specs)), RetrieveError::TooManyItems);
    assert_eq!(
        err_of(q.find_docs_containing(&[region_spec(doc2(), vec![past_end(); past_budget])])),
        FindError::TooMuchCoverage
    );
    assert_eq!(
        err_of(q.compare(
            &[region_spec(doc2(), vec![past_end(); past_budget])],
            &[region_spec(doc1(), vec![vspan(1, 1, 1)])],
        )),
        CompareError::TooManyBlocks {
            operand: Operand::First
        }
    );
}
