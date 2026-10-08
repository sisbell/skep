//! The walk budget across the three operations priced against it: every
//! span is charged an upper bound on its walk before the first is walked —
//! one that resolves to nothing included — and a gate fault outranks the
//! refusal. Each operation's own walk refusal sits beside its other
//! budgets, in `retrieve`, `compare_refusals` and `find`.

use skep_address::Address;
use skep_arrangement::HasM5;
use skep_retrieval::{
    CompareError, FindError, Operand, Query, RetrieveError, SpanFault, MAX_COMPARE_OPERAND_BLOCKS,
};

use crate::common::*;

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
