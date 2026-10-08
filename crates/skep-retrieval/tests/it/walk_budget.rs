//! The walk budget across the three operations priced against it. Every
//! span is priced before the first is walked, at exactly the bound the crate
//! doc states — the runs of its list capped at its reach, or the whole list
//! for a span M5's reader declines or whose reach passes a machine word, a
//! span that resolves to nothing included — and against the arrangement its
//! walk is made over. The count runs across an operand's or a request's
//! regions and stops at the operand; a gate fault outranks the refusal; and
//! every refusal renders the budget's number. Each operation's own walk
//! refusal sits beside its other budgets, in `retrieve`, `compare_refusals`
//! and `find`.

use skep_address::{Address, Nat, Span, Tumbler};
use skep_arrangement::HasM5;
use skep_retrieval::{
    CompareError, Delivery, DeliveryItem, FindError, Operand, Query, RegionSpec, RetrieveError,
    SpanFault, MAX_COMPARE_OPERAND_BLOCKS,
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
fn the_walk_price_is_exactly_the_documented_bound_at_each_of_its_arms() {
    // Crate doc, *What M6 refuses for size*, and `walk_price`'s card: a span
    // is priced at the runs of its list CAPPED AT ITS REACH ORDINAL — M5's
    // walk examines every run opening before the reach and the one that stops
    // it — at the whole list when M5's reader declines it, and at the whole
    // list when its reach does not fit a `usize`: the wire admits such a span,
    // a span's components being `Nat`, and M5 walks it to the end of the list
    // like any span opening past it. The other walk tests count whole lists
    // against the budget, so each arm is pinned only to within thousands of
    // steps — and the machine-word arm has no input at all. Here each arm
    // lands a request EXACTLY on the budget, and one step more is refused.
    let k = mem_kernel();
    fragmented_doc2(&k); // doc2 = 8192 one-position runs, each ca1; doc1 = [a, b, c], one run
    let s = k.snapshot();
    let q = Query::new(&s);
    let m5 = s.world().m5();
    let run_count = m5.content_run_count(&doc2());
    assert_eq!(run_count, 8192, "the premise: doc2 is 8192 runs");
    assert_eq!(
        m5.content_run_count(&doc1()),
        1,
        "the premise: doc1 is one run, a single step to walk"
    );
    let budget = MAX_COMPARE_OPERAND_BLOCKS * MAX_COMPARE_OPERAND_BLOCKS;
    let one_step = || spec(doc1(), vspan(1, 1, 1));
    let lists = |count: usize| vec![spec(doc2(), deep_span(1)); count];
    // The DECLINED arm, which the two below stand on: a depth-incompatible
    // spec, which M5 walks not at all, is priced at doc2's whole list — a
    // budget's worth of them is admitted, and one step more is refused.
    let mut specs = lists(budget / run_count);
    assert_eq!(
        ok_of(q.retrieve_v(&specs)),
        Delivery::default(),
        "the declined arm, at the budget"
    );
    specs.push(one_step());
    assert_eq!(
        err_of(q.retrieve_v(&specs)),
        RetrieveError::TooManyItems,
        "the declined arm, a step past"
    );
    // The REACH arm: one list short of the budget, a span reaching ordinal
    // 8191 — short of the list's 8192 runs — is priced at 8191, so one step
    // lands the request on the budget and a second passes it.
    let mut specs = lists(budget / run_count - 1);
    specs.push(spec(doc2(), vspan(1, 8190, 1)));
    specs.push(one_step());
    assert_eq!(
        ok_of(q.retrieve_v(&specs)),
        Delivery(vec![
            DeliveryItem::Content(val(b"a")),
            DeliveryItem::Content(val(b"a")),
        ]),
        "the reach arm, at the budget"
    );
    specs.push(one_step());
    assert_eq!(
        err_of(q.retrieve_v(&specs)),
        RetrieveError::TooManyItems,
        "the reach arm, a step past"
    );
    // The MACHINE-WORD arm: a content span opening at the largest ordinal a
    // `usize` holds, whose reach is the first that does not fit. It passes
    // the gate, resolves to nothing, and is priced at the whole list.
    let past_any_word = Span::new(
        Tumbler::new([n(1), Nat::from(usize::MAX)]).expect("a nonempty start"),
        t(&[0, 1]),
    )
    .expect("T12-legal");
    let mut specs = lists(budget / run_count - 1);
    specs.push(spec(doc2(), past_any_word));
    assert_eq!(
        ok_of(q.retrieve_v(&specs)),
        Delivery::default(),
        "the machine-word arm, at the budget"
    );
    specs.push(one_step());
    assert_eq!(
        err_of(q.retrieve_v(&specs)),
        RetrieveError::TooManyItems,
        "the machine-word arm, a step past"
    );
}

#[test]
fn every_operation_prices_its_walk_against_the_arrangement_it_walks() {
    // A span is priced at an upper bound on the walk M5 makes, and an
    // operation walks the arrangement it answers from (crate doc, *Which
    // arrangement an operation answers from*): RETRIEVEV and COMPARE resolve
    // a bare published address against its HEAD, so they price its spans
    // against the head's run list; FINDDOCSCONTAINING reads the address
    // named, so it prices against that. Every other walk test names a private
    // document, whose surface is itself, so a floating operation priced
    // against the address named would pass them all — and 2049 spans named at
    // a published document whose head is fragmented would be priced at 2049
    // steps and walk 16.8 million.
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
        Delivery(vec![DeliveryItem::Content(val(b"a"))]),
        "the premise: named pdoc, RETRIEVEV reads the head's fourth position, \
         which pdoc's own arrangement lacks"
    );
    let past_budget = MAX_COMPARE_OPERAND_BLOCKS * MAX_COMPARE_OPERAND_BLOCKS / run_count + 1;
    let past_end = || vspan(1, 8193, 1); // past the head's end, and pdoc's own
    assert_eq!(
        err_of(q.retrieve_v(&vec![spec(pdoc(), past_end()); past_budget])),
        RetrieveError::TooManyItems
    );
    assert_eq!(
        err_of(q.compare(&[region_spec(pdoc(), vec![past_end(); past_budget])], &[])),
        CompareError::TooManyBlocks {
            operand: Operand::First
        }
    );
    // FINDDOCSCONTAINING does not float: the same spans, priced against
    // pdoc's own one run, are admitted and answered.
    assert_eq!(
        ok_of(q.find_docs_containing(&[region_spec(pdoc(), vec![past_end(); past_budget])])),
        Vec::<Address>::new()
    );
}

#[test]
fn the_walk_budget_counts_across_regions_but_per_operand() {
    // MAX_WALK_STEPS' card: the walk is priced per COMPARE OPERAND and per
    // FINDDOCSCONTAINING REQUEST, over every region each names. The NESTED
    // shape — one span a region, over a list of regions — is the region×span
    // product the operand budget's card says the transport leaves to M6, and
    // the one a count opened per region would admit, each region's walk alone
    // being under the budget. Every other walk test puts its spans in one
    // region, where the two scopes agree. And the scope stops at the operand:
    // two operands priced at the budget apiece are both admitted.
    let k = mem_kernel();
    fragmented_doc2(&k); // doc2 = 8192 one-position runs
    let s = k.snapshot();
    let q = Query::new(&s);
    let run_count = s.world().m5().content_run_count(&doc2());
    assert_eq!(run_count, 8192, "the premise: doc2 is 8192 runs");
    let at_budget = MAX_COMPARE_OPERAND_BLOCKS * MAX_COMPARE_OPERAND_BLOCKS / run_count;
    // One depth-incompatible span a region: priced at doc2's whole list, and
    // walked not at all.
    let regions = |count: usize| -> Vec<RegionSpec> {
        (0..count)
            .map(|_| region_spec(doc2(), vec![deep_span(1)]))
            .collect()
    };
    assert!(ok_of(q.compare(&regions(at_budget), &[])).is_empty());
    assert_eq!(
        err_of(q.compare(&regions(at_budget + 1), &[])),
        CompareError::TooManyBlocks {
            operand: Operand::First
        }
    );
    assert_eq!(
        ok_of(q.find_docs_containing(&regions(at_budget))),
        Vec::<Address>::new()
    );
    assert_eq!(
        err_of(q.find_docs_containing(&regions(at_budget + 1))),
        FindError::TooMuchCoverage
    );
    assert!(ok_of(q.compare(&regions(at_budget), &regions(at_budget))).is_empty());
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

#[test]
fn every_walk_refusal_renders_the_walk_budget() {
    // Crate doc, *What M6 refuses for size*: the walk budget is not published
    // as a constant, and "its refusal renders it" — so each of the three
    // refusals that fold the walk in names the walk budget's number beside
    // its own budget's. Every other budget's number is read off its refusal
    // in its own operation's suite; this is the walk's.
    let walk_budget = (MAX_COMPARE_OPERAND_BLOCKS * MAX_COMPARE_OPERAND_BLOCKS).to_string();
    for message in [
        RetrieveError::TooManyItems.to_string(),
        CompareError::TooManyBlocks {
            operand: Operand::First,
        }
        .to_string(),
        FindError::TooMuchCoverage.to_string(),
    ] {
        assert!(
            message.contains(&walk_budget),
            "{message} names no walk budget"
        );
    }
}
