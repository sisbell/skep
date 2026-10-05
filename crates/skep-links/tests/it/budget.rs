//! The two per-slot budgets over a real kernel (InMemory): the span budget at
//! its exact boundary on every op and slot form that carries one, beside the
//! resolve-work budget that bounds what the span count cannot.

use crate::common;

use common::*;
use skep_address::Address;
use skep_kernel::TxnError;
use skep_links::{
    enc, Edit, EditLinkError, EmitError, Endset, HasLinks, Link, MakeLinkError, SlotArg,
};

#[test]
fn a_resolve_slot_past_the_span_budget_is_refused() {
    // The budget itself, at its exact boundary. doc1 is fragmented into 64
    // runs and copied into doc2 64 times — a copy carries the source's run
    // decomposition, so 128 writes put doc2 exactly at the budget, and one
    // more copy puts the same query past it.
    let k = kernel();
    let budget = skep_links::MAX_SLOT_SPANS as u32;
    let per_copy = 64u32;
    fragment_content(&k, &doc1(), per_copy);
    copy_prefix(&k, &doc1(), per_copy, &doc2(), budget / per_copy);
    let w = writer(&k);
    let resolve_doc2 = |width: u32| SlotArg::Resolve(vec![spec(&doc2(), 1, 1, width)]);

    let (at_budget, _) = w
        .makelink(
            P1,
            &doc2(),
            resolve_doc2(budget),
            SlotArg::Addrs(vec![]),
            SlotArg::Addrs(vec![unregistered_ta(10)]),
        )
        .expect("exactly the budget is admitted");
    {
        let snap = k.snapshot();
        let links = snap.world().links();
        assert_eq!(
            links.readlink(&at_budget).expect("resident").from_slot().len(),
            skep_links::MAX_SLOT_SPANS,
            "the admitted slot really did expand to the whole budget"
        );
    }

    copy_prefix(&k, &doc1(), per_copy, &doc2(), 1);
    let over = budget + per_copy;
    let before = k.current_seq();
    assert!(matches!(
        w.makelink(
            P1,
            &doc2(),
            resolve_doc2(over),
            SlotArg::Addrs(vec![]),
            SlotArg::Addrs(vec![unregistered_ta(10)])
        ),
        Err(TxnError::Rejected(MakeLinkError::SlotTooLarge))
    ));
    assert_eq!(k.current_seq(), before, "the refusal is pre-deposit");
    // The bound is on the SLOT, not on the FROM position: the same
    // over-budget resolution in the type slot is refused the same way.
    assert!(matches!(
        w.makelink(
            P1,
            &doc2(),
            SlotArg::Addrs(vec![ca(1)]),
            SlotArg::Addrs(vec![]),
            resolve_doc2(over)
        ),
        Err(TxnError::Rejected(MakeLinkError::SlotTooLarge))
    ));
    // ...and a slot inside the budget is admitted whichever form built it:
    // the bound counts spans, and is not a property of the `Resolve` arm.
    w.makelink(
        P1,
        &doc2(),
        SlotArg::Addrs(vec![ca(1); 16]),
        SlotArg::Addrs(vec![]),
        SlotArg::Addrs(vec![unregistered_ta(10)]),
    )
    .expect("sixteen names is well inside the budget");
}

#[test]
fn a_resolve_slot_is_refused_on_the_work_it_commands_not_only_the_spans_it_keeps() {
    // The span budget counts what a slot KEEPS, and the work is not the
    // result: a spec opening PAST a fragmented source's last arranged ordinal
    // keeps nothing and walks the whole run list to find that out (M5 states
    // the cost at its one clip — `Θ(#runs left of the opening ordinal)`). So a
    // slot of such specs is unbounded in work at ZERO span count, and every
    // step of it runs inside the transact under M2's applier lock, where it
    // stalls every writer in the engine rather than only the caller.
    let k = kernel();
    let runs = 64u32;
    fragment_content(&k, &doc1(), runs); // 64 runs, none I-contiguous
    let w = writer(&k);
    // Opens at ordinal 1000 over a 64-position document: binds nothing, walks
    // all 64. The budget is charged per slot, so the spec count that crosses
    // it is `MAX_SLOT_RESOLVE_STEPS / runs` plus one.
    let past_the_end = || spec(&doc1(), 1, 1_000, 1);
    let charges = skep_links::MAX_SLOT_RESOLVE_STEPS / runs as usize;

    let before = k.current_seq();
    assert!(matches!(
        w.makelink(
            P1,
            &doc1(),
            SlotArg::Resolve(vec![past_the_end(); charges + 1]),
            SlotArg::Addrs(vec![]),
            SlotArg::Addrs(vec![unregistered_ta(10)])
        ),
        Err(TxnError::Rejected(MakeLinkError::SlotTooLarge))
    ));
    assert_eq!(k.current_seq(), before, "the refusal is pre-deposit");

    // The control, one charge short: admitted, and the slot it builds is
    // EMPTY — so the refusal above is the work budget and not the span
    // budget, which sees both calls as a slot of no spans at all.
    let (l, _) = w
        .makelink(
            P1,
            &doc1(),
            SlotArg::Resolve(vec![past_the_end(); charges]),
            SlotArg::Addrs(vec![]),
            SlotArg::Addrs(vec![unregistered_ta(10)]),
        )
        .expect("one charge short is admitted");
    let snap = k.snapshot();
    assert!(
        snap.world().links().readlink(&l).expect("resident").from_slot().is_empty(),
        "the admitted slot kept nothing, which is what the span budget would have seen"
    );
}

#[test]
fn an_addrs_slot_past_the_span_budget_is_refused() {
    // The name form's own amplification, and it is not the span COUNT: that
    // is one per name, linear in the request. It is the BYTES — a dotted
    // address is ~19 wire bytes and the span it becomes is two 8-component
    // `BigUint` tumblers, order half a kilobyte live — so a slot bounded only
    // by the request body would name hundreds of thousands of spans, and
    // build them inside the transact under M2's applier lock.
    let k = kernel();
    let w = writer(&k);
    let names = |n: u32| -> Vec<Address> { (1..=n).map(ca).collect() };
    let budget = skep_links::MAX_SLOT_SPANS as u32;

    let (at_budget, _) = w
        .makelink(
            P1,
            &doc1(),
            SlotArg::Addrs(names(budget)),
            SlotArg::Addrs(vec![]),
            SlotArg::Addrs(vec![unregistered_ta(10)]),
        )
        .expect("exactly the budget is admitted");
    {
        let snap = k.snapshot();
        let links = snap.world().links();
        assert_eq!(
            links.readlink(&at_budget).expect("resident").from_slot().len(),
            skep_links::MAX_SLOT_SPANS,
            "the admitted slot really did carry the whole budget"
        );
    }

    let before = k.current_seq();
    assert!(matches!(
        w.makelink(
            P1,
            &doc1(),
            SlotArg::Addrs(names(budget + 1)),
            SlotArg::Addrs(vec![]),
            SlotArg::Addrs(vec![unregistered_ta(10)])
        ),
        Err(TxnError::Rejected(MakeLinkError::SlotTooLarge))
    ));
    assert_eq!(k.current_seq(), before, "the refusal is pre-deposit");
    // The bound is on the SLOT, not on a position: the same over-budget list
    // in the type slot is refused the same way.
    assert!(matches!(
        w.makelink(
            P1,
            &doc1(),
            SlotArg::Addrs(vec![ca(1)]),
            SlotArg::Addrs(vec![]),
            SlotArg::Addrs(names(budget + 1))
        ),
        Err(TxnError::Rejected(MakeLinkError::SlotTooLarge))
    ));
}

#[test]
fn emit_rejects_a_to_list_past_the_span_budget() {
    // `to` is one of the two managed slots a caller sizes (`ty` is the other,
    // and `enc({from})` is one span). The per-slot span budget sits here
    // PRE-TRANSACT — ahead of the shape gate, which every registered class in
    // this format would also refuse a nonempty `to` under.
    let k = kernel();
    let w = writer(&k);
    let targets = |n: u32| -> Vec<Address> { (1..=n).map(ca).collect() };
    let budget = skep_links::MAX_SLOT_SPANS as u32;

    let before = k.current_seq();
    assert!(matches!(
        w.emit(P1, &doc1(), &pred_def_ty(), &ca(2), &targets(budget + 1)),
        Err(TxnError::Rejected(EmitError::SlotTooLarge))
    ));
    assert_eq!(k.current_seq(), before, "the refusal is pre-deposit");
    // The boundary itself. `to` has no ADMIT case — every registered class in
    // this format is Unary or Binary, so no `|G|` this wide is depositable —
    // but the budget is pinnable all the same, because passing the fence and
    // failing it give DIFFERENT rejections: exactly the budget is not "past"
    // it, so the value reaches the shape gate, where a `>=` fence would answer
    // `SlotTooLarge` here too and silently make the published budget 4095.
    assert!(matches!(
        w.emit(P1, &doc1(), &pred_def_ty(), &ca(1), &targets(budget)),
        Err(TxnError::Rejected(EmitError::ShapeViolation))
    ));
    // ...and each verdict is separately reachable, so the above is the
    // precedence and not the only answer the input can get.
    assert!(matches!(
        w.emit(P1, &doc1(), &pred_def_ty(), &ca(3), &[ca(4), ca(5)]),
        Err(TxnError::Rejected(EmitError::ShapeViolation))
    ));
}

#[test]
fn emit_rejects_a_ty_endset_past_the_span_budget() {
    // `ty` is the OTHER managed slot a caller sizes, and it is stored VERBATIM
    // as e₃. Its CLASS collapses repeated addresses, so a registered class is
    // no bound on the slot naming it — and no gate reads e₃'s span count:
    // `is_address_denoting` admits any number of unit-depth spans, and
    // `sh_conf` reads the FROM and TO counts only. So the budget is the whole
    // of what stands between a request and an arbitrarily wide permanent slot.
    let k = kernel();
    let w = writer(&k);
    let budget = skep_links::MAX_SLOT_SPANS as u32;
    // One distinct denoted address, repeated: the class is pred_def's —
    // registered Unary, idem⊤ — whatever the span count.
    let wide_ty = |n: u32| -> Endset { enc(&vec![ra(1); n as usize]) };
    assert_eq!(
        skep_links::coverage_class(&wide_ty(budget)),
        skep_links::coverage_class(&pred_def_ty()),
        "the span count does not change the class, which is why it needs its own bound"
    );

    let (at_budget, _) = w
        .emit(P1, &doc1(), &wide_ty(budget), &ca(1), &[])
        .expect("exactly the budget is admitted");
    {
        let snap = k.snapshot();
        let links = snap.world().links();
        assert_eq!(
            links.readlink(&at_budget).expect("resident").type_slot().len(),
            skep_links::MAX_SLOT_SPANS,
            "the admitted slot really is stored verbatim at the whole budget"
        );
    }

    let before = k.current_seq();
    assert!(matches!(
        w.emit(P1, &doc1(), &wide_ty(budget + 1), &ca(3), &[]),
        Err(TxnError::Rejected(EmitError::SlotTooLarge))
    ));
    assert_eq!(k.current_seq(), before, "the refusal is pre-deposit");
    // The control: the same class at an in-budget width deposits, so the
    // refusal above is the slot and not the class.
    w.emit(P1, &doc1(), &pred_def_ty(), &ca(3), &[])
        .expect("a narrow ty of the same class is admitted");
}

#[test]
fn editlink_rejects_a_successor_slot_past_the_span_budget() {
    // The successor's slots are the CALLER's, resolve-built (M10 expands
    // V-specs into them), so their span count is a source document's
    // fragmentation rather than the request's size — the same expansion
    // MAKELINK's `Resolve` slots are bounded against, one op over. Every
    // per-span step after this check runs inside the transact: the
    // level-uniformity walk over all three slots, the DC guard's
    // `coverage_class`, and the fold's dedup key over all three again.
    let k = kernel();
    let w = writer(&k);
    let (orig, _) = w
        .emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[])
        .expect("orig");
    let spans = |n: u32| -> Endset {
        (1..=n)
            .map(|i| skep_address::subtree_of(ca(i).tumbler()))
            .collect()
    };
    let budget = skep_links::MAX_SLOT_SPANS as u32;

    let at_budget =
        Link::new([spans(budget), enc(&[ca(1)]), unregistered_ty(30)]).expect("arity 3");
    let (Edit { successor: s, .. }, _) = w
        .editlink(P1, &orig, at_budget, &doc1(), &doc1())
        .expect("exactly the budget is admitted");
    {
        let snap = k.snapshot();
        let links = snap.world().links();
        assert_eq!(
            links.readlink(&s).expect("resident").from_slot().len(),
            skep_links::MAX_SLOT_SPANS,
            "the admitted slot really did carry the whole budget"
        );
    }

    // One span more, refused before anything is staged — and refused ahead of
    // `IllFormedSuccessor`, which is where the per-span walk lives.
    let before = k.current_seq();
    let over = Link::new([spans(budget + 1), enc(&[ca(1)]), unregistered_ty(30)]).expect("arity 3");
    assert!(matches!(
        w.editlink(P1, &orig, over, &doc1(), &doc1()),
        Err(TxnError::Rejected(EditLinkError::SlotTooLarge))
    ));
    assert_eq!(k.current_seq(), before, "the refusal is pre-deposit");
    // The bound is on ANY slot, not on the one the DC guard classifies.
    let over_ty = Link::new([enc(&[ca(1)]), enc(&[ca(2)]), spans(budget + 1)]).expect("arity 3");
    assert!(matches!(
        w.editlink(P1, &orig, over_ty, &doc1(), &doc1()),
        Err(TxnError::Rejected(EditLinkError::SlotTooLarge))
    ));
}
