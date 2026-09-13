//! The `[K_sup]` op pair and the reads over the graph they build (ASN-0125),
//! over a real kernel (InMemory): `assert_sup`'s schema preconditions and its
//! home-excluded dedup, the BH2 walk at each of its three halts and its abort
//! on an off-contract `ty`, the endpoint
//! retraction that leaves an edge operative against the claim retraction that
//! removes it, `editlink`'s atomic composite, its two distinct homes and
//! their canonical lock order, its hoisted home check and its DC guard clause
//! by clause, and EL14 currency disclosure — every operative claim on a sink,
//! a nullified sink with its own activity, a node whose only claim is
//! retracted, and the denotation regime the inbound claim relation reads.

use crate::common;

use common::*;
use skep_arrangement::HasM5;
use skep_kernel::TxnError;
use skep_links::{enc, AssertSupError, Edit, EditLinkError, Endset, HasLinks, Link, Tip, View};

#[test]
fn assert_sup_claims_dedup_across_homes_and_a_retracted_claim_leaves_the_walk() {
    let k = kernel();
    let w = writer(&k);
    let sup = supersedes_ty();
    let (x, _) = w.emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[]).expect("x");
    let (y, _) = w.emit(P1, &doc1(), &pred_def_ty(), &ca(2), &[]).expect("y");
    // Schema preconditions.
    assert!(matches!(
        w.assert_sup(P1, &doc1(), &x, &la(9)),
        Err(TxnError::Rejected(AssertSupError::EndpointNotResident))
    ));
    assert!(matches!(
        w.assert_sup(P1, &doc1(), &x, &x),
        Err(TxnError::Rejected(AssertSupError::SelfSupersession))
    ));
    // The claim: F = old, G = new; edges run old → new.
    let (c1, _) = w.assert_sup(P1, &doc1(), &x, &y).expect("claim");
    {
        let snap = k.snapshot();
        let links = snap.world().links();
        assert_eq!(links.succs(&sup, &x), vec![y.clone()]);
        assert_eq!(links.chain(&sup, &x), vec![x.clone(), y.clone()]);
        assert_eq!(links.tip(&sup, &x), Tip::Sink(y.clone()));
        // is_in_chain: membership in the walk's result list, never a
        // coverage test; edges run old → new only.
        assert!(links.is_in_chain(&sup, &x, &y));
        assert!(!links.is_in_chain(&sup, &y, &x));
        // The walk family serves only the shipped Supersedes class in v1 —
        // for any other ty the chain is empty, so nothing is a member.
        assert!(links.succs(&pred_def_ty(), &x).is_empty());
        assert!(links.chain(&pred_def_ty(), &x).is_empty());
        assert!(!links.is_in_chain(&pred_def_ty(), &x, &x));
        assert_eq!(links.tip(&pred_def_ty(), &x), Tip::Indeterminate);
    }
    // Dedup excludes home: the same (old, new) from ANOTHER home hits the
    // first claim (Conflicts §9).
    let (c1b, _) = w.assert_sup(P1, &doc2(), &x, &y).expect("cross-home duplicate");
    assert_eq!(c1b, c1);
    // Retraction stability: nullifying the claim removes the operative edge;
    // x becomes its own sink.
    w.nullify(P1, &doc1(), &c1).expect("retract claim");
    {
        let snap = k.snapshot();
        let links = snap.world().links();
        assert!(links.succs(&sup, &x).is_empty());
        assert_eq!(links.tip(&sup, &x), Tip::Sink(x.clone()));
    }
    // Claim resurrection + mutual standoff: re-assert (fresh claim — the
    // nullified one is invisible to dedup), then the reverse claim; the
    // closure then has no sink and current() legitimately returns 0 members.
    let (c2, _) = w.assert_sup(P1, &doc1(), &x, &y).expect("re-assert");
    assert_ne!(c2, c1);
    w.assert_sup(P1, &doc1(), &y, &x).expect("reverse claim");
    let snap = k.snapshot();
    assert!(snap.world().links().current(&x).is_empty());
}

#[test]
fn assert_sup_reports_a_non_resident_endpoint_before_irreflexivity() {
    // The design pins the order: residence, then old ≠ new. A pair that
    // fails both reads as EndpointNotResident.
    let k = kernel();
    let w = writer(&k);
    assert!(matches!(
        w.assert_sup(P1, &doc1(), &la(9), &la(9)),
        Err(TxnError::Rejected(AssertSupError::EndpointNotResident))
    ));
}

#[test]
fn the_walk_halts_indeterminate_on_a_supersession_cycle() {
    // Sink and branch are the walk's other two halts; the cycle arm is two
    // assert_sup calls from any caller, and the visited set is the only thing
    // between it and an unbounded loop inside a read.
    let k = kernel();
    let w = writer(&k);
    let sup = supersedes_ty();
    let (x, _) = w.emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[]).expect("x");
    let (y, _) = w.emit(P1, &doc1(), &pred_def_ty(), &ca(2), &[]).expect("y");
    w.assert_sup(P1, &doc1(), &x, &y).expect("x → y");
    w.assert_sup(P1, &doc1(), &y, &x)
        .expect("y → x closes the cycle");
    let snap = k.snapshot();
    let links = snap.world().links();
    assert_eq!(
        links.chain(&sup, &x),
        vec![x.clone(), y.clone()],
        "the walk halts on revisit"
    );
    assert_eq!(links.tip(&sup, &x), Tip::Indeterminate, "a cycle claims no head");
    assert_eq!(links.chain(&sup, &y), vec![y.clone(), x.clone()]);
    assert_eq!(links.tip(&sup, &y), Tip::Indeterminate);
}

#[test]
#[should_panic(expected = "level-uniform")]
fn the_walk_scope_test_panics_on_an_off_contract_ty_rather_than_reading_as_out_of_scope() {
    // `succs`/`chain`/`tip` share one classification site, and their contract
    // names the wrong answer as well as the right one: the out-of-scope reply
    // is the empty vec, so a guard added to "avoid the panic" would answer a
    // caller error with a truthful-looking claim about the store.
    let k = kernel();
    let snap = k.snapshot();
    let skew = Endset::from_spans([
        skep_address::Span::new(t(&[5, 3]), t(&[0, 2, 7])).expect("T12 admits this span")
    ]);
    let _ = snap.world().links().succs(&skew, &la(1));
}

#[test]
fn nullifying_an_endpoint_leaves_its_claim_s_edge_operative() {
    // Df-SUCC reads the CLAIM's activity and never the ENDPOINT's, so a link
    // plays two roles in the supersession graph and retraction reaches only
    // one of them. Nullifying a successor tombstones it and drops it from
    // every active slice, and the edge naming it stays operative: the walk
    // still names it and `tip` still reports it as a positive sink.
    let k = kernel();
    let w = writer(&k);
    let sup = supersedes_ty();
    let (x, _) = w.emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[]).expect("x");
    let (y, _) = w.emit(P1, &doc1(), &pred_def_ty(), &ca(2), &[]).expect("y");
    let (c, _) = w.assert_sup(P1, &doc1(), &x, &y).expect("claim");
    w.nullify(P1, &doc1(), &y).expect("retract the successor");
    {
        let snap = k.snapshot();
        let links = snap.world().links();
        assert!(links.is_nullified(&y));
        assert!(!links.type_slice(&pred_def_ty(), View::Active).contains(&y));
        assert_eq!(
            links.succs(&sup, &x),
            vec![y.clone()],
            "the edge is operative: its CLAIM is unnullified"
        );
        assert_eq!(links.chain(&sup, &x), vec![x.clone(), y.clone()]);
        assert_eq!(
            links.tip(&sup, &x),
            Tip::Sink(y.clone()),
            "a nullified successor is still a positive head"
        );
    }
    // The control, one call away: retracting the CLAIM is what removes the
    // edge, and then x is its own sink.
    w.nullify(P1, &doc1(), &c).expect("retract the claim");
    let snap = k.snapshot();
    let links = snap.world().links();
    assert!(links.succs(&sup, &x).is_empty());
    assert_eq!(links.tip(&sup, &x), Tip::Sink(x.clone()));
}

#[test]
fn editlink_commits_successor_and_claim_together_and_guards_the_successor_type() {
    let k = kernel();
    let w = writer(&k);
    let sup = supersedes_ty();
    let retraction = retraction_ty();
    let (orig, _) = w.emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[]).expect("orig");

    // One atomic composite: fresh successor + claim; original untouched.
    let successor_value =
        Link::new([enc(&[ca(3)]), enc(&[ca(4)]), unregistered_ty(30)]).expect("arity 3");
    let (Edit { successor: s1, claim: c1 }, _) = w
        .editlink(P1, &orig, successor_value.clone(), &doc1(), &doc1())
        .expect("editlink");
    {
        let snap = k.snapshot();
        let links = snap.world().links();
        assert_eq!(links.readlink(&s1), Some(&successor_value)); // supplied value verbatim
        let claim = links.readlink(&c1).expect("claim resident");
        assert_eq!(claim.from_slot(), &enc([&orig])); // F = old
        assert_eq!(claim.to_slot(), &enc([&s1])); // G = new (fresh successor)
        assert_eq!(claim.type_slot(), &sup);
        assert_eq!(links.chain(&sup, &orig), vec![orig.clone(), s1.clone()]);
        // Successor born UNSEATED.
        assert_eq!(snap.world().m5().link_count(&doc1()), n(0));
    }

    // Fork permanence: a second edit of the same original yields a distinct
    // successor and a co-visible claim; the walk reports the branch.
    let fork_value =
        Link::new([enc(&[ca(5)]), enc(&[ca(6)]), unregistered_ty(31)]).expect("arity 3");
    let (Edit { successor: s2, claim: c2 }, _) =
        w.editlink(P1, &orig, fork_value, &doc1(), &doc1()).expect("fork");
    {
        let snap = k.snapshot();
        let links = snap.world().links();
        assert_eq!(links.succs(&sup, &orig), vec![s1.clone(), s2.clone()]);
        assert_eq!(links.tip(&sup, &orig), Tip::Indeterminate); // branch
        assert_eq!(links.chain(&sup, &orig), vec![orig.clone()]); // halt at the branch
        // EL14 disclosure: both sinks, each with its full operative inbound
        // claim set.
        let cur = links.current(&orig);
        assert_eq!(cur.len(), 2);
        assert_eq!(cur[0].member, s1);
        assert!(cur[0].active);
        assert_eq!(cur[0].claims, vec![c1.clone()]);
        assert_eq!(cur[1].member, s2);
        assert_eq!(cur[1].claims, vec![c2.clone()]);
    }

    // A [K_sup]-typed successor is admitted iff schema-conforming (DC): both
    // endpoints resident, distinct, unit-depth single-addr F/G.
    let (z, _) = w.emit(P1, &doc1(), &pred_def_ty(), &ca(7), &[]).expect("z");
    let conforming = Link::new([enc([&orig]), enc([&z]), sup.clone()]).expect("arity 3");
    w.editlink(P1, &orig, conforming, &doc1(), &doc1())
        .expect("schema-conforming claim-typed successor");
    {
        let snap = k.snapshot();
        assert!(snap.world().links().succs(&sup, &orig).contains(&z));
    }

    // Rejections (each leaves no state change by M2's Rejected contract).
    let valid_successor =
        Link::new([enc(&[ca(3)]), enc(&[ca(4)]), unregistered_ty(32)]).expect("arity 3");
    assert!(matches!(
        w.editlink(P1, &la(90), valid_successor.clone(), &doc1(), &doc1()),
        Err(TxnError::Rejected(EditLinkError::OriginalNotResident))
    ));
    assert!(matches!(
        w.editlink(P1, &orig, valid_successor.clone(), &a(&[1, 0, 1, 0, 7]), &doc1()),
        Err(TxnError::Rejected(EditLinkError::HomeNotRegistered))
    ));
    let arity4 = Link::new(vec![
        enc(&[ca(3)]),
        enc(&[ca(4)]),
        unregistered_ty(33),
        enc(&[ca(5)]),
    ])
    .expect("capacity admits arity 4");
    assert!(matches!(
        w.editlink(P1, &orig, arity4, &doc1(), &doc1()),
        Err(TxnError::Rejected(EditLinkError::IllFormedSuccessor))
    ));
    let empty_ty = Link::new([enc(&[ca(3)]), enc(&[ca(4)]), Endset::empty()]).expect("arity 3");
    assert!(matches!(
        w.editlink(P1, &orig, empty_ty, &doc1(), &doc1()),
        Err(TxnError::Rejected(EditLinkError::IllFormedSuccessor))
    ));
    let retraction_typed =
        Link::new([enc(&[ca(3)]), enc(&[ca(4)]), retraction.clone()]).expect("arity 3");
    assert!(matches!(
        w.editlink(P1, &orig, retraction_typed, &doc1(), &doc1()),
        Err(TxnError::Rejected(EditLinkError::DcViolation))
    ));
    let self_sup = Link::new([enc([&orig]), enc([&orig]), sup.clone()]).expect("arity 3");
    assert!(matches!(
        w.editlink(P1, &orig, self_sup, &doc1(), &doc1()),
        Err(TxnError::Rejected(EditLinkError::DcViolation))
    ));
}

#[test]
fn editlink_deposits_the_successor_in_d_s_and_the_claim_in_d_a() {
    // The two homes are not interchangeable: the successor deposits into
    // `d_s`, the claim into `d_a`. Every other editlink case passes one
    // document twice, where an exchange is invisible — and permanent, in an
    // append-only store, against the wrong document's link chain.
    let k = kernel();
    let w = writer(&k);
    let sup = supersedes_ty();
    let (orig, _) = w
        .emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[])
        .expect("orig");
    assert_eq!(orig, la(1)); // so doc1's next mint is la(2), doc2's first la2(1)
    let successor_value =
        Link::new([enc(&[ca(3)]), enc(&[ca(4)]), unregistered_ty(30)]).expect("arity 3");
    let (edit, _) = w
        .editlink(P1, &orig, successor_value.clone(), &doc1(), &doc2())
        .expect("P1 owns both homes");
    assert_eq!(edit.successor, la(2), "the successor lands on d_s's link chain");
    assert_eq!(edit.claim, la2(1), "the claim lands on d_a's");
    let snap = k.snapshot();
    let links = snap.world().links();
    assert_eq!(links.readlink(&edit.successor), Some(&successor_value));
    let claim = links.readlink(&edit.claim).expect("claim resident");
    assert_eq!(claim.from_slot(), &enc([&orig]));
    assert_eq!(claim.to_slot(), &enc([&edit.successor]));
    assert_eq!(claim.type_slot(), &sup);
    assert_eq!(
        links.chain(&sup, &orig),
        vec![orig.clone(), edit.successor.clone()]
    );
}

#[test]
fn editlink_locks_two_homes_in_one_canonical_order() {
    // The one op that hands M2 two keys of a SINGLE space, so the only one
    // whose key order would otherwise be the caller's. Two edits naming the
    // same pair of homes in opposite orders present the same key set; each
    // still deposits into the homes its own arguments name, so canonicalizing
    // the pair changed no outcome. (The race itself is not reachable from a
    // single-threaded in-memory kernel; what is checkable here is that the
    // ordering is invisible to the op.)
    let k = kernel();
    let w = writer(&k);
    let (orig, _) = w
        .emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[])
        .expect("orig");
    assert_eq!(orig, la(1)); // doc1's next mint is la(2); doc2's first is la2(1)
    let successor_value =
        || Link::new([enc(&[ca(3)]), enc(&[ca(4)]), unregistered_ty(30)]).expect("arity 3");

    let (edit1, _) = w
        .editlink(P1, &orig, successor_value(), &doc1(), &doc2())
        .expect("d_s = doc1, d_a = doc2");
    assert_eq!(edit1.successor, la(2), "the successor on d_s's chain");
    assert_eq!(edit1.claim, la2(1), "the claim on d_a's");

    let (edit2, _) = w
        .editlink(P1, &orig, successor_value(), &doc2(), &doc1())
        .expect("the same pair of homes, named the other way round");
    assert_eq!(edit2.successor, la2(2), "the successor still follows d_s");
    assert_eq!(edit2.claim, la(3), "and the claim still follows d_a");
}

#[test]
fn editlink_reports_an_unregistered_home_before_a_non_resident_original() {
    // `OriginalNotResident` is declared first, and the home/ω pair is hoisted
    // ahead of every other in-transaction verdict — so editlink is the one op
    // where the declared and realized orders diverge, and the one place the
    // hoist is observable.
    let k = kernel();
    let w = writer(&k);
    let successor_value =
        Link::new([enc(&[ca(3)]), enc(&[ca(4)]), unregistered_ty(30)]).expect("arity 3");
    assert!(matches!(
        w.editlink(P1, &la(90), successor_value, &a(&[1, 0, 1, 0, 7]), &doc1()),
        Err(TxnError::Rejected(EditLinkError::HomeNotRegistered))
    ));
}

#[test]
fn editlink_rejects_a_non_level_uniform_successor_type_slot() {
    // The third IllFormedSuccessor cause, and the one whose absence is an
    // abort rather than a wrong answer: this clause is what keeps the DC
    // guard's coverage_class total, off the pinned off-contract panic.
    let k = kernel();
    let w = writer(&k);
    let (orig, _) = w
        .emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[])
        .expect("orig");
    let skew = skep_address::Span::new(t(&[5, 3]), t(&[0, 2, 7])).expect("T12 admits this span");
    let successor_value =
        Link::new([enc(&[ca(3)]), enc(&[ca(4)]), Endset::from_spans([skew])]).expect("arity 3");
    assert!(matches!(
        w.editlink(P1, &orig, successor_value, &doc1(), &doc1()),
        Err(TxnError::Rejected(EditLinkError::IllFormedSuccessor))
    ));
}

#[test]
fn editlink_rejects_a_non_level_uniform_span_in_any_slot() {
    // Level-uniformity is required of every slot, not only the one the DC
    // guard classifies: the hint fold keys a registered idem⊤ deposit on all
    // three, so a skew span in F or G would reach `coverage_class`'s pinned
    // off-contract abort from inside the transact — a panic where the design
    // has a typed rejection.
    let k = kernel();
    let w = writer(&k);
    let (orig, _) = w
        .emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[])
        .expect("orig");
    let skew =
        || Endset::from_spans([skep_address::Span::new(t(&[5, 3]), t(&[0, 2, 7])).expect("T12")]);
    // `retired` is registered idem⊤, so the fold WOULD build a dedup key
    // over all three slots of this successor.
    let idem_top = enc(&[reserved().retired]);
    for (label, successor_value) in [
        (
            "skew F",
            Link::new([skew(), enc(&[ca(4)]), idem_top.clone()]).expect("arity 3"),
        ),
        (
            "skew G",
            Link::new([enc(&[ca(3)]), skew(), idem_top.clone()]).expect("arity 3"),
        ),
        (
            "skew TYPE",
            Link::new([enc(&[ca(3)]), enc(&[ca(4)]), skew()]).expect("arity 3"),
        ),
    ] {
        let got = w.editlink(P1, &orig, successor_value, &doc1(), &doc1());
        assert!(
            matches!(
                got,
                Err(TxnError::Rejected(EditLinkError::IllFormedSuccessor))
            ),
            "{label}: expected IllFormedSuccessor, got {got:?}"
        );
    }
}

#[test]
fn editlink_rejects_a_claim_typed_successor_with_a_non_resident_endpoint() {
    // DC's Df-DISC(ii) schema is three clauses, and residence is one of
    // them: a [K_sup]-typed successor naming a ghost link is refused even
    // though its F and G are distinct unit-depth single addresses.
    let k = kernel();
    let w = writer(&k);
    let sup = supersedes_ty();
    let (orig, _) = w
        .emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[])
        .expect("orig");
    let (z, _) = w.emit(P1, &doc1(), &pred_def_ty(), &ca(7), &[]).expect("z");
    let ghost_endpoint = Link::new([enc([&la(90)]), enc([&z]), sup.clone()]).expect("arity 3");
    assert!(matches!(
        w.editlink(P1, &orig, ghost_endpoint, &doc1(), &doc1()),
        Err(TxnError::Rejected(EditLinkError::DcViolation))
    ));
    // Residence is required of BOTH endpoints, not only F: the schema check
    // reads `resident(f) && resident(g)`, and a ghost in the `new` position
    // would enter the adjacency as a successor no walk could ever read back.
    let ghost_new = Link::new([enc([&z]), enc([&la(90)]), sup]).expect("arity 3");
    assert!(matches!(
        w.editlink(P1, &orig, ghost_new, &doc1(), &doc1()),
        Err(TxnError::Rejected(EditLinkError::DcViolation))
    ));
}

#[test]
fn editlink_rejects_a_claim_typed_successor_whose_endpoint_denotes_several_addresses() {
    // Df-DISC(ii) is "exactly one DISTINCT denoted address" per endpoint, not
    // "at least one": a claim whose F names two links would enter the
    // supersession adjacency with an F the walk family reads as one vertex,
    // and the fold would build an edge per FROM×TO pair — the amplification
    // the [K_sup] fence exists to stop, through the surface it admits.
    let k = kernel();
    let w = writer(&k);
    let sup = supersedes_ty();
    let (orig, _) = w
        .emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[])
        .expect("orig");
    let (z, _) = w.emit(P1, &doc1(), &pred_def_ty(), &ca(7), &[]).expect("z");
    let multi_f = Link::new([enc([&orig, &z]), enc([&z]), sup.clone()]).expect("arity 3");
    assert!(matches!(
        w.editlink(P1, &orig, multi_f, &doc1(), &doc1()),
        Err(TxnError::Rejected(EditLinkError::DcViolation))
    ));
    let multi_g = Link::new([enc([&orig]), enc([&orig, &z]), sup.clone()]).expect("arity 3");
    assert!(matches!(
        w.editlink(P1, &orig, multi_g, &doc1(), &doc1()),
        Err(TxnError::Rejected(EditLinkError::DcViolation))
    ));
    // ...and the rule turns on DISTINCT: the same address named twice denotes
    // one, so it conforms — and the admitted claim enters the adjacency.
    let repeated = Link::new([enc([&z, &z]), enc([&orig]), sup.clone()]).expect("arity 3");
    let (Edit { successor: s, .. }, _) = w
        .editlink(P1, &orig, repeated, &doc1(), &doc1())
        .expect("one distinct address, named twice");
    let snap = k.snapshot();
    let links = snap.world().links();
    assert_eq!(
        links.succs(&sup, &z),
        vec![orig.clone()],
        "ONE edge out of a slot that names z twice — a repeated span cannot add one"
    );
    assert!(links.is_active(&s));
}

#[test]
fn current_discloses_every_operative_claim_targeting_a_sink() {
    // EL14: `claims` is the FULL operative out(sink), computed per sink from
    // the index — so a claim asserted from OUTSIDE reach_o(y) is disclosed
    // too. Walk-side accumulation would report only the reachable one.
    let k = kernel();
    let w = writer(&k);
    let sup = supersedes_ty();
    let (orig, _) = w
        .emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[])
        .expect("orig");
    let successor_value =
        Link::new([enc(&[ca(3)]), enc(&[ca(4)]), unregistered_ty(30)]).expect("arity 3");
    let (Edit { successor: s1, claim: c1 }, _) = w
        .editlink(P1, &orig, successor_value, &doc1(), &doc1())
        .expect("editlink");
    // `outsider` is unreachable from orig, and its claim names the SINK as
    // successor.
    let (outsider, _) = w
        .emit(P1, &doc1(), &pred_def_ty(), &ca(8), &[])
        .expect("outsider");
    let (outside_claim, _) = w
        .assert_sup(P1, &doc1(), &outsider, &s1)
        .expect("outsider → s1, asserted from outside the closure");
    let snap = k.snapshot();
    let links = snap.world().links();
    assert_eq!(
        links.chain(&sup, &orig),
        vec![orig.clone(), s1.clone()],
        "reach_o(orig) does not contain the outsider"
    );
    let cur = links.current(&orig);
    assert_eq!(cur.len(), 1);
    assert_eq!(cur[0].member, s1);
    assert_eq!(
        cur[0].claims,
        vec![c1, outside_claim],
        "both operative inbound claims, not only the reachable one"
    );
}

#[test]
fn current_discloses_a_nullified_sink_with_its_own_activity() {
    // EL14e: a member can be a current sink and itself nullified. M7
    // discloses the sink and carries its activity; the reader narrows.
    let k = kernel();
    let w = writer(&k);
    let (orig, _) = w
        .emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[])
        .expect("orig");
    let successor_value =
        Link::new([enc(&[ca(3)]), enc(&[ca(4)]), unregistered_ty(30)]).expect("arity 3");
    let (Edit { successor: s1, claim: c1 }, _) = w
        .editlink(P1, &orig, successor_value, &doc1(), &doc1())
        .expect("editlink");
    w.nullify(P1, &doc1(), &s1).expect("retract the successor");
    let snap = k.snapshot();
    let links = snap.world().links();
    let cur = links.current(&orig);
    assert_eq!(cur.len(), 1, "a nullified sink is still disclosed");
    assert_eq!(cur[0].member, s1);
    assert!(!cur[0].active, "and carries its own activity");
    // The CLAIM is untouched, so the edge stays operative and s1 stays the sink.
    assert_eq!(cur[0].claims, vec![c1]);
}

#[test]
fn a_node_whose_only_claim_is_retracted_is_its_own_sink() {
    // Df-SUCC on the SINK test: it is the claim's activity that makes an
    // edge operative, so the endpoint of a retracted claim is not a
    // successor and the source is successor-free. The complement of the
    // test above — there the successor was nullified and the claim stood;
    // here the claim is nullified and the successor stands.
    let k = kernel();
    let w = writer(&k);
    let (x, _) = w.emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[]).expect("x");
    let (y, _) = w.emit(P1, &doc1(), &pred_def_ty(), &ca(2), &[]).expect("y");
    let (c, _) = w.assert_sup(P1, &doc1(), &x, &y).expect("claim");
    {
        // The control: while the claim is operative, x is not a sink and y is.
        let snap = k.snapshot();
        let cur = snap.world().links().current(&x);
        assert_eq!(cur.len(), 1);
        assert_eq!(cur[0].member, y);
        assert_eq!(cur[0].claims, vec![c.clone()]);
    }
    w.nullify(P1, &doc1(), &c).expect("retract the claim");
    let snap = k.snapshot();
    let links = snap.world().links();
    let cur = links.current(&x);
    assert_eq!(cur.len(), 1, "x is now successor-free");
    assert_eq!(cur[0].member, x);
    assert!(cur[0].active);
    assert!(
        cur[0].claims.is_empty(),
        "a retracted claim is not an operative inbound claim either"
    );
    // ...and y, still resident, discloses as its own sink with no claim on it.
    let at_y = links.current(&y);
    assert_eq!(at_y.len(), 1);
    assert_eq!(at_y[0].member, y);
    assert!(at_y[0].claims.is_empty());
}

#[test]
fn current_discloses_inbound_claims_by_denotation_never_by_coverage() {
    // A claim's `new` is a single denoted address (Df-DISC(ii)), so the
    // inbound relation is denotation — and the difference is visible exactly
    // where an overlap probe would over-match: a document-level argument,
    // whose subtree span CONTAINS every link address beneath it. doc1 holds
    // both endpoints and the claim, and is a successor-free node, so it
    // discloses as its own sink; no claim names it.
    let k = kernel();
    let w = writer(&k);
    let (x, _) = w.emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[]).expect("x");
    let (y, _) = w.emit(P1, &doc1(), &pred_def_ty(), &ca(2), &[]).expect("y");
    let (c, _) = w.assert_sup(P1, &doc1(), &x, &y).expect("claim");
    let snap = k.snapshot();
    let links = snap.world().links();
    // The control: the claim is operative and IS disclosed at the address it
    // names, so the empty answer below is the matching rule, not absence.
    let at_sink = links.current(&x);
    assert_eq!(at_sink.len(), 1);
    assert_eq!(at_sink[0].member, y);
    assert_eq!(at_sink[0].claims, vec![c]);
    let at_doc = links.current(&doc1());
    assert_eq!(at_doc.len(), 1);
    assert_eq!(at_doc[0].member, doc1());
    assert!(
        at_doc[0].claims.is_empty(),
        "no claim's `new` denotes doc1; coverage answers with every claim beneath it"
    );
}
