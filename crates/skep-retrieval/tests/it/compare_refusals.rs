//! §D COMPARE's refusals: the gate's `(operand, region, index)` attribution,
//! and the operand, walk and pair budgets — each a refusal, never a
//! truncation, and outranked by every gate fault.

use skep_address::Span;
use skep_arrangement::{is_ordinal_vspan, HasM5};
use skep_retrieval::{
    CompareError, Operand, Query, RegionSpec, SpanFault, MAX_COMPARE_OPERAND_BLOCKS,
    MAX_COMPARE_PAIRS,
};

use crate::common::*;

#[test]
fn compare_rejects_with_operand_region_index_attribution() {
    // ASN-0122 precondition: registered docs, content-subspace starts,
    // well-formed spans — each span fault localized by (operand, region,
    // index); the subspace residence check runs BEFORE the well-formedness
    // gate.
    let k = mem_kernel();
    insert3(&k);
    let s = k.snapshot();
    let q = Query::new(&s);
    assert!(matches!(
        err_of(q.compare(&[region_spec(unregistered(), vec![vspan(1, 1, 1)])], &[])),
        CompareError::DocNotRegistered(d) if d == unregistered()
    ));
    assert!(matches!(
        err_of(q.compare(
            &[region_spec(doc1(), vec![vspan(1, 1, 1)])],
            &[region_spec(doc1(), vec![vspan(2, 1, 1)])],
        )),
        CompareError::NotContentSubspace {
            operand: Operand::Second,
            region: 0,
            index: 0
        }
    ));
    assert!(matches!(
        err_of(q.compare(
            &[region_spec(
                doc1(),
                vec![vspan(1, 1, 1), not_ordinal_level_span()]
            )],
            &[region_spec(doc1(), vec![vspan(1, 1, 1)])],
        )),
        CompareError::MalformedSpan {
            operand: Operand::First,
            region: 0,
            index: 1,
            fault: SpanFault::NotOrdinalLevel
        }
    ));
    // A link-START span that is ALSO malformed: subspace residence wins.
    let link_malformed = Span::new(t(&[2, 1]), t(&[1, 0])).expect("T12-legal");
    assert!(matches!(
        err_of(q.compare(&[region_spec(doc1(), vec![link_malformed])], &[])),
        CompareError::NotContentSubspace {
            operand: Operand::First,
            region: 0,
            index: 0
        }
    ));
    // Position 1 IS the subspace at any start depth (Tumbler indexing is
    // 1-based and #start ≥ 1 always), so residence is decidable for every
    // span the gate loop sees, including a one-component start.
    let shallow_foreign = Span::new(t(&[5]), t(&[1])).expect("T12-legal");
    assert!(matches!(
        err_of(q.compare(&[region_spec(doc1(), vec![shallow_foreign])], &[])),
        CompareError::NotContentSubspace {
            operand: Operand::First,
            region: 0,
            index: 0
        }
    ));
    let shallow_content = Span::new(t(&[1]), t(&[1])).expect("T12-legal");
    assert!(matches!(
        err_of(q.compare(&[region_spec(doc1(), vec![shallow_content])], &[])),
        CompareError::MalformedSpan {
            operand: Operand::First,
            region: 0,
            index: 0,
            fault: SpanFault::StartTooShallow
        }
    ));
    // All three coordinates off zero at once: the SECOND span of the SECOND
    // region of the SECOND operand. Every other case here sits at region 0, so
    // nothing else can tell `region` from a constant — or from `index`, which
    // would be 2 if the span count ran globally rather than per region.
    assert!(matches!(
        err_of(q.compare(
            &[region_spec(doc1(), vec![vspan(1, 1, 1)])],
            &[
                region_spec(doc1(), vec![vspan(1, 1, 1)]),
                region_spec(doc1(), vec![vspan(1, 1, 1), not_ordinal_level_span()]),
            ],
        )),
        CompareError::MalformedSpan {
            operand: Operand::Second,
            region: 1,
            index: 1,
            fault: SpanFault::NotOrdinalLevel
        }
    ));
}

#[test]
fn compare_refuses_an_operand_past_its_budget() {
    // The join is |P|·|Q| and BOTH factors are the request's: a region names
    // a span list and a spec-set names a region list, each capped separately
    // upstream, so their product is capped by nothing upstream. Each operand
    // is refused on its own, and the refusal names WHICH — a client cannot
    // narrow the operand it was not told about.
    let k = mem_kernel();
    insert3(&k);
    let s = k.snapshot();
    let q = Query::new(&s);
    let one = || vec![region_spec(doc1(), vec![vspan(1, 1, 1)])];
    let over = vec![region_spec(
        doc1(),
        vec![vspan(1, 1, 1); MAX_COMPARE_OPERAND_BLOCKS + 1],
    )];
    assert_eq!(
        err_of(q.compare(&over, &one())),
        CompareError::TooManyBlocks {
            operand: Operand::First
        }
    );
    assert_eq!(
        err_of(q.compare(&one(), &over)),
        CompareError::TooManyBlocks {
            operand: Operand::Second
        }
    );
    // Both over budget: ρ₁ is resolved FIRST, so ρ₁ is the operand named —
    // the one request that can tell the two resolution orders apart, since
    // either order answers the two above identically.
    assert_eq!(
        err_of(q.compare(&over, &over)),
        CompareError::TooManyBlocks {
            operand: Operand::First
        }
    );
    // The budget refuses only what is PAST it, and refuses the request
    // WHOLE: at the budget the same shape still answers, and answers
    // completely (one pair per block — a truncating budget would answer with
    // fewer and break X12 R2).
    let at = vec![region_spec(
        doc1(),
        vec![vspan(1, 1, 1); MAX_COMPARE_OPERAND_BLOCKS],
    )];
    assert_eq!(
        ok_of(q.compare(&at, &one())).len(),
        MAX_COMPARE_OPERAND_BLOCKS
    );
    // The refusal says which budget and how large it is, so a client sizing
    // its next request reads the number rather than guessing it.
    let e = err_of(q.compare(&over, &one()));
    assert!(e
        .to_string()
        .contains(&MAX_COMPARE_OPERAND_BLOCKS.to_string()));
}

#[test]
fn compare_refuses_an_operand_whose_blocks_outnumber_the_budget_though_its_spans_do_not() {
    // The budget's own card: beyond M10's per-array wire cap it refuses "the
    // multi-run expansion, where one span over a fragmented document resolves
    // to many blocks from a single span on the wire", and the BLOCK count is
    // what refuses it. doc2 resolves to THREE runs, so the two operands below are
    // `MAX/3` and `MAX/3 + 1` SPANS — both under the budget's own span count
    // and under any wire cap — and `MAX - (MAX mod 3)` and three more BLOCKS,
    // which is the only unit that explains one being answered and the other
    // refused. (The span count's own boundary is pinned by
    // `compare_refuses_an_operand_whose_spans_outnumber_the_budget_though_they_resolve_to_nothing`.)
    let k = mem_kernel();
    three_runs(&k); // doc2 = [doc2_ca1][ca1, ca2][ca1] — three runs
    let s = k.snapshot();
    let q = Query::new(&s);
    let one = vec![region_spec(doc1(), vec![vspan(1, 1, 1)])];
    let side = |count: usize| vec![region_spec(doc2(), vec![vspan(1, 1, 4); count])];
    let under = MAX_COMPARE_OPERAND_BLOCKS / 3;
    // Two of doc2's three runs hold ca1 (the third is its own content, on a
    // chain doc1 never touches), so the admitted operand reports the full
    // cross-product and is not merely "not refused".
    assert_eq!(ok_of(q.compare(&side(under), &one)).len(), 2 * under);
    assert_eq!(
        err_of(q.compare(&side(under + 1), &one)),
        CompareError::TooManyBlocks {
            operand: Operand::First
        }
    );
    // Which operand speaks when ρ₁ is over on BLOCKS and ρ₂ over on SPANS:
    // ρ₁ resolves first and is refused as it resolves, before ρ₂'s spans are
    // counted — the one request that tells "resolve ρ₁ whole, then ρ₂" from
    // "count every span first, then resolve".
    let over_on_spans = vec![region_spec(
        doc1(),
        vec![vspan(1, 1000, 1); MAX_COMPARE_OPERAND_BLOCKS + 1],
    )];
    assert_eq!(
        err_of(q.compare(&side(under + 1), &over_on_spans)),
        CompareError::TooManyBlocks {
            operand: Operand::First
        }
    );
}

#[test]
fn compare_refuses_an_operand_whose_spans_outnumber_the_budget_though_they_resolve_to_nothing() {
    // The budget's other count. Every span handed to M5 is one walk of up to
    // #runs(doc) steps whether or not it yields a block — a span opening past
    // the arranged extent walks the whole list and yields none — so a block
    // count alone would admit any number of empty-resolving spans and their
    // walks with them, from a nested region×span request the body cap alone
    // sizes. The SPAN count refuses it, before either operand resolves past
    // the budget, naming the operand.
    let k = mem_kernel();
    insert3(&k); // doc1 holds three positions
    let s = k.snapshot();
    let q = Query::new(&s);
    let past_end = || vspan(1, 1000, 1);
    // The premise: a past-end span resolves to NO run, so the block count
    // never moves and only the span count can explain a refusal below.
    assert!(
        s.world().m5().resolve(&doc1(), &past_end()).is_empty(),
        "the premise: a span past the arranged extent resolves to nothing"
    );
    let one = || vec![region_spec(doc1(), vec![vspan(1, 1, 1)])];
    let over = vec![region_spec(
        doc1(),
        vec![past_end(); MAX_COMPARE_OPERAND_BLOCKS + 1],
    )];
    assert_eq!(
        err_of(q.compare(&over, &one())),
        CompareError::TooManyBlocks {
            operand: Operand::First
        }
    );
    assert_eq!(
        err_of(q.compare(&one(), &over)),
        CompareError::TooManyBlocks {
            operand: Operand::Second
        }
    );
    // At the budget the same shape still answers — emptily, every span
    // resolving to nothing — so the walks are done, and bounded at the budget.
    let at = vec![region_spec(
        doc1(),
        vec![past_end(); MAX_COMPARE_OPERAND_BLOCKS],
    )];
    assert!(ok_of(q.compare(&at, &one())).is_empty());
    // The NESTED region×span product past the budget — one span per region,
    // a region list no per-array wire cap prices — is refused the same way.
    let nested: Vec<RegionSpec> = (0..=MAX_COMPARE_OPERAND_BLOCKS)
        .map(|_| region_spec(doc1(), vec![past_end()]))
        .collect();
    assert_eq!(
        err_of(q.compare(&nested, &one())),
        CompareError::TooManyBlocks {
            operand: Operand::First
        }
    );
    // A span M5's READER declines — well-formed, content-started, depth 3 —
    // is never handed to `resolve` and is counted all the same: the count is
    // of spans handed to M5, an upper bound on its walks, so M5's fold
    // conditions are restated nowhere here.
    assert!(
        !is_ordinal_vspan(&deep_span(1)),
        "the premise: M5's reader declines a depth-3 span"
    );
    let declined_over = vec![region_spec(
        doc1(),
        vec![deep_span(1); MAX_COMPARE_OPERAND_BLOCKS + 1],
    )];
    assert_eq!(
        err_of(q.compare(&declined_over, &one())),
        CompareError::TooManyBlocks {
            operand: Operand::First
        }
    );
    let declined_at = vec![region_spec(
        doc1(),
        vec![deep_span(1); MAX_COMPARE_OPERAND_BLOCKS],
    )];
    assert!(ok_of(q.compare(&declined_at, &one())).is_empty());
}

#[test]
fn compare_refuses_an_operand_whose_spans_would_walk_past_the_walk_budget() {
    // The walk budget: M5 reaches a span by walking the run list from its
    // first run, so a span opening past the end of a fragmented document walks
    // every run and yields no block — one span on the span count, nothing on
    // the block count. The walk budget is the operand budget's square, so over
    // doc2's 8192 runs one span more than `MAX_COMPARE_OPERAND_BLOCKS² / 8192`
    // such spans is past it, and the operand is refused before any span is
    // walked, naming the operand.
    let k = mem_kernel();
    fragmented_doc2(&k); // doc2 = 8192 one-position runs, every one ca1
    let s = k.snapshot();
    let q = Query::new(&s);
    let run_count = s.world().m5().content_run_count(&doc2());
    assert_eq!(run_count, 8192, "the premise: doc2 is 8192 runs");
    let past_budget = MAX_COMPARE_OPERAND_BLOCKS * MAX_COMPARE_OPERAND_BLOCKS / run_count + 1;
    let one = || vec![region_spec(doc1(), vec![vspan(1, 1, 1)])];
    let over = vec![region_spec(doc2(), vec![vspan(1, 8193, 1); past_budget])];
    assert_eq!(
        err_of(q.compare(&over, &one())),
        CompareError::TooManyBlocks {
            operand: Operand::First
        }
    );
    assert_eq!(
        err_of(q.compare(&one(), &over)),
        CompareError::TooManyBlocks {
            operand: Operand::Second
        }
    );
    // The control: a span at doc2's first position walks two runs, so the
    // operand budget's whole 4096 are priced well inside the walk budget and
    // answered — one pair per block, every block holding ca1.
    let near = vec![region_spec(
        doc2(),
        vec![vspan(1, 1, 1); MAX_COMPARE_OPERAND_BLOCKS],
    )];
    assert_eq!(
        ok_of(q.compare(&near, &one())).len(),
        MAX_COMPARE_OPERAND_BLOCKS
    );
}

#[test]
fn compare_refuses_a_fanout_past_its_pair_budget() {
    // 257 × 257 = 66,049 pairs from 514 blocks — a block count the operand
    // budget admits many times over. Fan-out is bounded ONLY by counting the
    // pairs as they are produced, which is why the second budget exists and
    // why the first cannot stand in for it.
    let k = mem_kernel();
    insert3(&k);
    let s = k.snapshot();
    let q = Query::new(&s);
    let side = |count: usize| vec![region_spec(doc1(), vec![vspan(1, 1, 1); count])];
    let e = err_of(q.compare(&side(257), &side(257)));
    assert_eq!(e, CompareError::TooManyPairs);
    // The refusal names its own budget, as the operand budget's refusal does,
    // so a client narrows against the number rather than guessing it.
    assert!(e.to_string().contains(&MAX_COMPARE_PAIRS.to_string()));
    // Under the budget, the same shape reports the FULL cross-product
    // (X12 R2): the budget refuses, and never thins a report it admits.
    assert_eq!(ok_of(q.compare(&side(16), &side(16))).len(), 256);
    // The EQUAL case, where the two budgets must agree: a report of exactly
    // the budget is answered and only the pair PAST it refused. The premise is
    // asserted, so a change to the constant fails here rather than silently
    // leaving this an interior point.
    assert_eq!(256 * 256, MAX_COMPARE_PAIRS, "256 × 256 IS the boundary");
    assert_eq!(
        ok_of(q.compare(&side(256), &side(256))).len(),
        MAX_COMPARE_PAIRS
    );
}

#[test]
fn compare_gates_both_operands_whole_before_either_budget_can_refuse() {
    // §COMPARE, which refusal speaks: both operands are gated in FULL before
    // either is resolved, so a GATE fault always outranks a BUDGET refusal. An
    // over-budget ρ₁ beside a malformed ρ₂ span reports the span — telling a
    // client that ρ₂ was examined too, which is the promise `TooManyBlocks`
    // rests on.
    let k = mem_kernel();
    insert3(&k);
    let s = k.snapshot();
    let q = Query::new(&s);
    let over = vec![region_spec(
        doc1(),
        vec![vspan(1, 1, 1); MAX_COMPARE_OPERAND_BLOCKS + 1],
    )];
    assert_eq!(
        err_of(q.compare(
            &over,
            &[region_spec(doc1(), vec![not_ordinal_level_span()])],
        )),
        CompareError::MalformedSpan {
            operand: Operand::Second,
            region: 0,
            index: 0,
            fault: SpanFault::NotOrdinalLevel,
        }
    );
    // The control: with ρ₂ well-formed, the same ρ₁ is refused for its size.
    assert_eq!(
        err_of(q.compare(&over, &[region_spec(doc1(), vec![vspan(1, 1, 1)])])),
        CompareError::TooManyBlocks {
            operand: Operand::First
        }
    );
}
