//! What reaching a span costs, across the operations that resolve spans:
//! nothing a budget prices. M5 reaches a span by a descent of the run-list
//! and reads from there the runs the span yields, so RETRIEVEV, COMPARE and
//! FINDDOCSCONTAINING are refused for what they produce and for the spans
//! they hand over, never for the fragmentation of the documents their spans
//! name. Requests whose spans resolve to nothing over a document of 8192
//! runs — in numbers whose product with those runs passes `2^24` — are
//! answered, whichever arrangement the operation answers from; a gate fault
//! speaks ahead of every budget; and the walk budget, the line read's
//! alone, is rendered by the line read's refusal and by no other. Each
//! operation's own budgets sit in `retrieve`, `compare_refusals` and `find`.

use skep_address::{Address, Nat, Span, Tumbler};
use skep_arrangement::HasM5;
use skep_retrieval::{
    CompareError, CompareRegion, Delivery, FindError, LinesError, Operand, Query, RegionSpec,
    RetrieveError, SpanFault, MAX_COMPARE_OPERAND_BLOCKS,
};

use crate::common::*;

/// The walk budget's number, which no constant publishes: the operand
/// budget's square.
const WALK_BUDGET: usize = MAX_COMPARE_OPERAND_BLOCKS * MAX_COMPARE_OPERAND_BLOCKS;

#[test]
fn spans_that_resolve_to_nothing_are_answered_whatever_runs_their_document_holds() {
    // Crate doc, *What M6 refuses for size*: a span that resolves to nothing
    // reads no run and counts as one span handed over. Over doc2's 8192 runs,
    // more such spans than `2^24 / 8192` — a depth-incompatible one (R6's
    // silent degradation, X12's consulting-state success), a
    // foreign-subspace one, one opening past the arranged end, one whose
    // reach passes a machine word — are answered, empty, by each operation
    // whose gate admits them, in one region and one a region.
    let k = mem_kernel();
    fragmented_doc2(&k); // doc2 = 8192 one-position runs, each ca1; doc1 = [a, b, c], one run
    let s = k.snapshot();
    let q = Query::new(&s);
    let run_count = s.world().m5().content_run_count(&doc2());
    assert_eq!(run_count, 8192, "the premise: doc2 is 8192 runs");
    let many = WALK_BUDGET / run_count + 1;
    assert!(many * run_count > WALK_BUDGET && many <= MAX_COMPARE_OPERAND_BLOCKS, "premise: past 2^24 in runs, inside every span count");
    let past_any_word = Span::new(
        Tumbler::new([n(1), Nat::from(usize::MAX)]).expect("a nonempty start"),
        t(&[0, 1]),
    )
    .expect("T12-legal");
    for nothing in [deep_span(1), vspan(3, 8193, 1), vspan(1, 8193, 1), past_any_word] {
        assert!(
            ok_of(q.retrieve_v(&[spec(doc2(), nothing.clone())])).is_empty(),
            "the premise: the spec resolves to nothing"
        );
        assert_eq!(ok_of(q.retrieve_v(&vec![spec(doc2(), nothing.clone()); many])), Delivery::default());
        assert_eq!(
            ok_of(q.find_docs_containing(&[region_spec(doc2(), vec![nothing.clone(); many])])),
            Vec::<Address>::new()
        );
        // One span a region: the same spans, the nested shape.
        let regions: Vec<RegionSpec> = (0..many).map(|_| region_spec(doc2(), vec![nothing.clone()])).collect();
        assert_eq!(ok_of(q.find_docs_containing(&regions)), Vec::<Address>::new());
    }
    // COMPARE's gate admits the content-subspace ones, in either operand.
    let one = vec![region_spec(doc1(), vec![vspan(1, 1, 1)])];
    for nothing in [deep_span(1), vspan(1, 8193, 1)] {
        let over = vec![region_spec(doc2(), vec![nothing.clone(); many])];
        assert!(ok_of(q.compare(&over, &one)).is_empty());
        assert!(ok_of(q.compare(&one, &over)).is_empty());
        let regions: Vec<RegionSpec> = (0..many).map(|_| region_spec(doc2(), vec![nothing.clone()])).collect();
        assert!(ok_of(q.compare(&regions, &regions)).is_empty());
    }
    // Beside them, spans that do resolve are delivered: a spec-set of the
    // empty-resolving ones with a position of doc1 and one far along doc2
    // among them answers those two positions and nothing else.
    let mut specs = vec![spec(doc2(), deep_span(1)); many];
    specs.push(spec(doc1(), vspan(1, 1, 1)));
    specs.extend(vec![spec(doc2(), vspan(1, 8193, 1)); many]);
    specs.push(spec(doc2(), vspan(1, 8190, 1)));
    assert_eq!(ok_of(q.retrieve_v(&specs)), Delivery(vec![text(b"a"), text(b"a")]));
}

#[test]
fn a_floating_operation_is_answered_over_a_fragmented_head_as_over_any_arrangement() {
    // An operation resolves the arrangement it answers from (crate doc,
    // *Which arrangement an operation answers from*): RETRIEVEV and COMPARE
    // resolve a bare published address against its HEAD, FINDDOCSCONTAINING
    // and a COMPARE region flagged `own` against the address named. pdoc's
    // own arrangement is one run and its head 8192: spans past the end of
    // both, more of them than `2^24 / 8192`, are answered by all four,
    // whichever arrangement each reads.
    let k = mem_kernel();
    fragmented_head(&k); // pdoc's own arrangement: one run; its head vdoc: 8192
    let s = k.snapshot();
    let q = Query::new(&s);
    let m5 = s.world().m5();
    assert_eq!(
        m5.content_run_count(&pdoc()),
        1,
        "the premise: pdoc's own arrangement is one run"
    );
    let run_count = m5.content_run_count(&vdoc());
    assert_eq!(run_count, 8192, "the premise: pdoc's head is 8192 runs");
    assert_eq!(
        ok_of(q.retrieve_v(&[spec(pdoc(), vspan(1, 4, 1))])),
        Delivery(vec![text(b"a")]),
        "the premise: named pdoc, RETRIEVEV reads the head's fourth position, \
         which pdoc's own arrangement lacks"
    );
    let many = WALK_BUDGET / run_count + 1;
    let past_end = || vspan(1, 8193, 1); // past the head's end, and pdoc's own
    assert_eq!(ok_of(q.retrieve_v(&vec![spec(pdoc(), past_end()); many])), Delivery::default());
    assert!(ok_of(q.compare(&[region_spec(pdoc(), vec![past_end(); many])], &[])).is_empty());
    assert_eq!(
        ok_of(q.find_docs_containing(&[region_spec(pdoc(), vec![past_end(); many])])),
        Vec::<Address>::new()
    );
    let region = |own: bool| {
        vec![CompareRegion {
            region: region_spec(pdoc(), vec![past_end(); many]),
            own,
        }]
    };
    assert!(ok_of(q.compare_named(&region(true), &[])).is_empty());
    assert!(ok_of(q.compare_named(&region(false), &[])).is_empty());
}

#[test]
fn a_gate_fault_speaks_and_the_same_request_without_it_is_answered() {
    // §Errors: a gate fault speaks wherever it sits — here behind a first
    // unit of more spans past the end of a fragmented document than
    // `2^24 / 8192`. With the fault removed each request is answered, the
    // spans resolving to nothing: no budget stood between the gate and the
    // answer.
    let k = mem_kernel();
    fragmented_doc2(&k); // doc2 = 8192 one-position runs
    let s = k.snapshot();
    let q = Query::new(&s);
    let run_count = s.world().m5().content_run_count(&doc2());
    assert_eq!(run_count, 8192, "the premise: doc2 is 8192 runs");
    let many = WALK_BUDGET / run_count + 1;
    let past_end = || vspan(1, 8193, 1);
    let mut specs = vec![spec(doc2(), past_end()); many];
    specs.push(spec(doc1(), not_ordinal_level_span()));
    assert_eq!(
        err_of(q.retrieve_v(&specs)),
        RetrieveError::MalformedSpec {
            index: many,
            fault: SpanFault::NotOrdinalLevel
        }
    );
    assert_eq!(
        err_of(q.find_docs_containing(&[
            region_spec(doc2(), vec![past_end(); many]),
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
            &[region_spec(doc2(), vec![past_end(); many])],
            &[region_spec(doc1(), vec![not_ordinal_level_span()])],
        )),
        CompareError::MalformedSpan {
            operand: Operand::Second,
            region: 0,
            index: 0,
            fault: SpanFault::NotOrdinalLevel
        }
    );
    specs.pop();
    assert_eq!(ok_of(q.retrieve_v(&specs)), Delivery::default());
    assert_eq!(
        ok_of(q.find_docs_containing(&[region_spec(doc2(), vec![past_end(); many])])),
        Vec::<Address>::new()
    );
    assert!(ok_of(q.compare(
        &[region_spec(doc2(), vec![past_end(); many])],
        &[region_spec(doc1(), vec![vspan(1, 1, 1)])],
    ))
    .is_empty());
}

#[test]
fn the_line_reads_refusal_alone_renders_the_walk_budget() {
    // Crate doc, *What M6 refuses for size*: the walk budget is not
    // published as a constant, and "its refusal renders it" — the line
    // read's, which is the walk's alone. The three operations that resolve
    // spans are refused at their own budgets and name no walk budget.
    let walk_budget = WALK_BUDGET.to_string();
    assert!(
        LinesError::TooManyItems.to_string().contains(&walk_budget),
        "{} names no walk budget",
        LinesError::TooManyItems
    );
    for message in [
        RetrieveError::TooManyItems.to_string(),
        CompareError::TooManyBlocks {
            operand: Operand::First,
        }
        .to_string(),
        FindError::TooMuchCoverage.to_string(),
    ] {
        assert!(!message.contains(&walk_budget) && !message.contains("run-list steps"), "{message} names a walk budget");
    }
}
