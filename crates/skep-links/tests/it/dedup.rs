//! Idempotent dedup over a real kernel (InMemory): the value-keyed gates at
//! the caller's visibility class — the earliest READABLE incumbent, a fresh
//! mint beside a hidden one, `editlink` and `nullify` at any class — and the
//! incumbent a hit returns: resurrection, the T1-least ACTIVE tuple of the
//! class, and the open surface's deposits a hit may meet.

use crate::common;

use common::*;
use skep_address::{document_of, Address};
use skep_links::{enc, HasLinks, Link, SlotArg, Tip, View};

// ---- the value-keyed gates at the caller's visibility class (lane 3.3b) ----

/// PUB-6.25/PUB-6.26: the idempotency lookup runs over the I0 class FILTERED
/// by the caller's visibility predicate at link-home identity, inside the
/// write transaction. An incumbent homed in a document the caller cannot read
/// is invisible — the emit mints fresh beside it, and value-identical tuples
/// coexist across the boundary; a hit is the EARLIEST incumbent the caller's
/// visibility class can read, never merely the earliest; and the answer is
/// deterministic given the visibility class.
#[test]
fn a_dedup_hit_is_the_earliest_incumbent_the_caller_can_read() {
    let k = kernel();
    let hide_doc1 = |_: &World, home: &Address| *home != doc1();
    let hide_both = |_: &World, home: &Address| *home != doc1() && *home != doc2();
    let all = writer(&k);
    let no_doc1 = writer_at(&k, &hide_doc1);
    let no_p1_docs = writer_at(&k, &hide_both);

    // The incumbent: P1's tuple, homed in doc1.
    let (first, _) = all.emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[]).expect("incumbent");
    assert_eq!(first, la(1));

    // A visibility class blind to doc1 mints the same value afresh, in its
    // own home — the ack never names an address inside a home the caller
    // cannot read.
    let before = k.current_seq();
    let (second, seq) = no_doc1
        .emit(P1, &doc2(), &pred_def_ty(), &ca(1), &[])
        .expect("fresh beside an invisible incumbent");
    assert_eq!(second, la2(1));
    assert!(seq > before, "a fresh deposit commits");
    {
        // Both stand ACTIVE: value-identical tuples coexist across the
        // visibility boundary, and the coverage-class-keyed reads — which
        // take no visibility class — see one member.
        let snap = k.snapshot();
        let links = snap.world().links();
        assert!(links.is_active(&first) && links.is_active(&second));
        assert_eq!(links.members(&pred_def_ty(), View::Active), vec![ca(1)]);
    }

    // EARLIEST READABLE, not earliest: the all-visible class acks the
    // T1-least (doc1's) …
    let before = k.current_seq();
    let (hit, seq) = all.emit(P1, &doc2(), &pred_def_ty(), &ca(1), &[]).expect("hit");
    assert_eq!(hit, first);
    assert_eq!(seq, before);
    assert_eq!(k.current_seq(), before, "zero-step: nothing committed");
    // … the visibility class blind to doc1 acks doc2's, the earliest it can
    // read …
    let (hit, seq) = no_doc1
        .emit(P1, &doc2(), &pred_def_ty(), &ca(1), &[])
        .expect("a hit within the visibility class");
    assert_eq!(hit, second);
    assert_eq!(seq, before);
    assert_eq!(k.current_seq(), before, "still zero-step");
    // … and, asked again, answers the same — deterministic given the
    // visibility class.
    let (again, _) = no_doc1.emit(P1, &doc2(), &pred_def_ty(), &ca(1), &[]).expect("hit again");
    assert_eq!(again, second);

    // A visibility class blind to both of P1's homes mints a THIRD, in the
    // sibling's own home …
    let (third, _) = no_p1_docs
        .emit(P2, &sib_doc(), &pred_def_ty(), &ca(1), &[])
        .expect("fresh in the sibling's home");
    assert_eq!(document_of(&third), Some(sib_doc()));
    assert!(k.current_seq() > before);
    // … while the sibling at the all-visible class acks doc1's tuple — an
    // address in a home it does not own, exactly what an entitled reader is
    // handed (PUB-6.26): the incumbent's ω is not consulted, its readability
    // is.
    let (hit, _) = all
        .emit(P2, &sib_doc(), &pred_def_ty(), &ca(1), &[])
        .expect("the entitled sibling's hit");
    assert_eq!(hit, first);
}

/// PUB-6.25 at `assert_sup`: its cross-home dedup — the same `(old, new)`
/// from another home hits the first claim — holds WITHIN a visibility class
/// only. Blind to the first claim's home, a caller mints a claim of its own;
/// each visibility class then acks the earliest claim it can read; and the
/// supersession walk, which takes no visibility class, reads the two claims
/// as one edge.
#[test]
fn assert_sup_dedups_only_within_the_caller_s_visibility_class() {
    let k = kernel();
    let hide_doc1 = |_: &World, home: &Address| *home != doc1();
    let all = writer(&k);
    let no_doc1 = writer_at(&k, &hide_doc1);
    let sup = supersedes_ty();
    let (x, _) = all.emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[]).expect("x");
    let (y, _) = all.emit(P1, &doc1(), &pred_def_ty(), &ca(2), &[]).expect("y");
    let (c1, _) = all.assert_sup(P1, &doc1(), &x, &y).expect("the claim, homed in doc1");

    // Cross-home dedup within the all-visible class (Conflicts §9) …
    let (hit, _) = all.assert_sup(P1, &doc2(), &x, &y).expect("cross-home hit");
    assert_eq!(hit, c1);
    // … and not across the boundary: blind to doc1, the same (old, new) from
    // doc2 is a second, coexisting claim.
    let before = k.current_seq();
    let (c2, seq) = no_doc1.assert_sup(P1, &doc2(), &x, &y).expect("a claim of its own");
    assert_ne!(c2, c1);
    assert_eq!(document_of(&c2), Some(doc2()));
    assert!(seq > before, "a fresh claim commits");

    // Each visibility class acks the earliest claim it can read.
    let before = k.current_seq();
    let (hit, _) = no_doc1
        .assert_sup(P1, &doc2(), &x, &y)
        .expect("hit within the visibility class");
    assert_eq!(hit, c2);
    let (hit, _) = all.assert_sup(P1, &doc2(), &x, &y).expect("hit at the all-visible class");
    assert_eq!(hit, c1);
    assert_eq!(k.current_seq(), before, "both hits are zero-step");

    // The supersession graph is the world's, not a visibility class's: two
    // claims, one operative edge, and retracting one leaves the other's edge
    // standing.
    let snap = k.snapshot();
    assert_eq!(snap.world().links().succs(&sup, &x), vec![y.clone()]);
    all.nullify(P1, &doc1(), &c1).expect("retract the first claim");
    let snap = k.snapshot();
    assert_eq!(snap.world().links().succs(&sup, &x), vec![y.clone()]);
    assert_eq!(snap.world().links().tip(&sup, &x), Tip::Sink(y));
}

/// PUB-6.27: `editlink`'s claim meets no incumbent whatever the visibility
/// class — its I0 carries a successor minted in the same transaction — so
/// both of its acks land in the homes the caller named, never in another
/// home's link subspace, even beside a standing claim over the same original
/// that the caller cannot read.
#[test]
fn editlink_s_acks_land_in_the_caller_s_homes_whatever_the_visibility_class() {
    let k = kernel();
    let hide_doc1 = |_: &World, home: &Address| *home != doc1();
    let all = writer(&k);
    let no_doc1 = writer_at(&k, &hide_doc1);
    let (x, _) = all.emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[]).expect("x");
    let (y, _) = all.emit(P1, &doc1(), &pred_def_ty(), &ca(2), &[]).expect("y");
    all.assert_sup(P1, &doc1(), &x, &y).expect("a doc1-homed claim over x");
    let successor_value = Link::triple(enc(&[ca(3)]), enc(&[ca(4)]), unregistered_ty(30));
    for w in [&all, &no_doc1] {
        let (edit, _) = w
            .editlink(P1, &x, successor_value.clone(), &doc2(), &doc2())
            .expect("an edit from doc2, at either visibility class");
        assert_eq!(document_of(&edit.successor), Some(doc2()));
        assert_eq!(document_of(&edit.claim), Some(doc2()));
    }
}

/// The `Visibility` contract's second half is a CONDITION and not an
/// obligation, and this is the whole of the difference: a predicate blind to
/// the home the caller writes to costs `nullify` a FRESH retraction tuple
/// where a hit would have been zero-step, and costs its postcondition nothing
/// — the target is tombstoned either way. Every `[R]` incumbent of one
/// identity is homed in the retraction's own `home`, so blinding the
/// visibility class to that one document is exactly what hides them all.
#[test]
fn a_predicate_blind_to_the_caller_s_own_home_costs_nullify_a_fresh_retraction_never_its_postcondition(
) {
    let k = kernel();
    let hide_doc1 = |_: &World, home: &Address| *home != doc1();
    let all = writer(&k);
    let blind = writer_at(&k, &hide_doc1);
    let (target, _) = all.emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[]).expect("target");

    // The control: at a visibility class that reads doc1, the second
    // retraction is a zero-step hit on the first.
    let (r1, _) = all.nullify(P1, &doc1(), &target).expect("retract");
    let before = k.current_seq();
    let (hit, seq) = all
        .nullify(P1, &doc1(), &target)
        .expect("hit within the visibility class");
    assert_eq!(hit, r1);
    assert_eq!(seq, before);
    assert_eq!(k.current_seq(), before, "zero-step: nothing committed");

    // Blind to doc1 — the home every [R] incumbent of this identity sits in —
    // the same retraction mints fresh: correct, and not zero-step.
    let (r2, seq) = blind
        .nullify(P1, &doc1(), &target)
        .expect("fresh beside a hidden incumbent");
    assert_ne!(r2, r1);
    assert!(seq > before, "a fresh retraction commits");
    let snap = k.snapshot();
    let links = snap.world().links();
    assert!(
        links.is_nullified(&target),
        "the postcondition never rested on the predicate"
    );
    assert!(!links.is_active(&target));
    assert!(links.is_active(&r1) && links.is_active(&r2), "both retractions stand");
}

// ---- idempotent dedup: the incumbent a hit returns ----

#[test]
fn an_idem_top_duplicate_returns_the_incumbent_and_a_nullified_one_resurrects() {
    let k = kernel();
    let w = writer(&k);
    // idem⊤: a duplicate returns the incumbent with the base Seq and commits
    // nothing. Every registered class in this format is idem⊤, so the dedup
    // discipline is the managed surface's whole deposit behavior.
    let (a1, s1) = w.emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[]).expect("first emit");
    assert_eq!(k.current_seq(), s1);
    let (hit, seq) = w.emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[]).expect("dedup hit");
    assert_eq!(hit, a1);
    assert_eq!(seq, s1);
    assert_eq!(k.current_seq(), s1); // zero-step: nothing committed
    // The open surface is the fresh-always contrast (ML0): the identical
    // deposit lands at a new address every time, dedup lock and check alike
    // absent.
    let deposit = || open_deposit(&w, &[ca(1)], &[ca(2)], &[unregistered_ta(1)]);
    let first = deposit();
    let second = deposit();
    assert_ne!(first, second);
    // Resurrection (I2): dedup reads the ACTIVE view — a nullified incumbent
    // is invisible, so re-emitting lands at a fresh address; audit keeps both.
    w.nullify(P1, &doc1(), &a1).expect("nullify the idem⊤ tuple");
    let (a3, _) = w.emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[]).expect("re-emit");
    assert_ne!(a3, a1);
    let snap = k.snapshot();
    let links = snap.world().links();
    assert!(links.readlink(&a1).is_some()); // permanence: the audit slice keeps it
    assert!(links.is_nullified(&a1));
    assert!(links.is_active(&a3));
}

#[test]
fn a_dedup_hit_returns_the_t1_least_active_tuple_of_the_class() {
    // The incumbent is specified as the T1-LEAST ACTIVE match rather than as
    // "the one", because a registered idem⊤ class may hold several active
    // tuples: the open surface deposits into it with neither the dedup lock
    // nor the check (ML0), and the fold indexes by CLASS whatever surface a
    // deposit arrived through. Both halves of that specification need the
    // multiplicity to be visible at all.
    let k = kernel();
    let w = writer(&k);
    // Typed pred_def — registered Unary, idem⊤ — through the open surface,
    // which runs no dedup check.
    let deposit = || open_deposit(&w, &[ca(1)], &[], &[ra(1)]);
    let first = deposit();
    let second = deposit(); // ML0: distinct links always
    assert!(first < second, "T1 order follows the mint order on one chain");

    // LEAST: both are active members of the one I0 class the emit builds.
    let before = k.current_seq();
    let (hit, seq) = w
        .emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[])
        .expect("dedup hit");
    assert_eq!(hit, first, "the T1-least of the class's several active tuples");
    assert_eq!(seq, before);
    assert_eq!(k.current_seq(), before, "zero-step: nothing committed");

    // ACTIVE: retract the least, and the NEXT one is the incumbent — not a
    // fresh deposit, which is what resurrection gives once none is left.
    w.nullify(P1, &doc1(), &first).expect("retract the incumbent");
    let before = k.current_seq();
    let (hit, _) = w
        .emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[])
        .expect("the next active tuple of the class");
    assert_eq!(hit, second);
    assert_eq!(k.current_seq(), before, "still a hit, so still zero-step");
}

#[test]
fn makelink_into_a_registered_idem_top_class_deposits_and_never_dedups() {
    // Conflicts §1's degenerate coincidence: a MAKELINK deposit whose type
    // slot lands in a registered idem⊤ class folds an in-memory dedup key,
    // possibly carrying an extent-classed component. No such key reaches a
    // LockKey — the open surface takes no dedup lock — and this one is no
    // Emit_K incumbent either, because the I0 key is the whole triple and
    // this F is extent-classed where an emit's is denoted.
    let k = kernel();
    seed_content(&k, &doc1(), 3);
    let w = writer(&k);
    let (l, _) = w
        .makelink(
            P1,
            &doc1(),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 1, 2)]), // a wide, Extents-classed F
            SlotArg::Addrs(vec![]),
            SlotArg::Addrs(vec![ra(1)]), // pred_def — registered Unary, idem⊤
        )
        .expect("the open surface has no registration or shape gate");
    let (fresh, _) = w
        .emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[])
        .expect("emit into the same class");
    assert_ne!(fresh, l, "a distinct I0 class, so the emit deposits fresh");
    let snap = k.snapshot();
    let links = snap.world().links();
    assert!(links.is_active(&l) && links.is_active(&fresh));
    let slice = links.type_slice(&pred_def_ty(), View::Active);
    assert!(slice.contains(&l) && slice.contains(&fresh));
}

#[test]
fn an_emit_hit_may_return_a_link_its_own_shape_gate_would_have_refused() {
    // The other half of the same coincidence, and the one an `emit` caller
    // can observe: when the MAKELINK deposit's I0 triple DOES match, the
    // folded key is the incumbent that emit's dedup check hits. The open
    // surface applies no shape gate, so what comes back is a link this very
    // call would have been refused for — which is why `emit` documents its
    // hit as returning the class's incumbent rather than a tuple it admitted.
    let k = kernel();
    let w = writer(&k);
    // enc([ca1, ca1]) denotes {ca1}, so this F shares an I0 class with
    // emit's own enc({ca1}) — while storing two spans, where Unary's shape
    // gate forces one; the open surface has no shape gate. Typed pred_def —
    // registered Unary, idem⊤.
    let l = open_deposit(&w, &[ca(1), ca(1)], &[], &[ra(1)]);
    let before = k.current_seq();
    let (hit, seq) = w
        .emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[])
        .expect("the emit's own value is Unary-conformant");
    assert_eq!(hit, l, "the MAKELINK deposit IS the incumbent this emit hits");
    assert_eq!(seq, before, "zero-step: nothing committed");
    assert_eq!(k.current_seq(), before);
    let snap = k.snapshot();
    let incumbent = snap.world().links().readlink(&hit).expect("resident");
    assert_eq!(
        incumbent.from_slot().len(),
        2,
        "and it carries an F the shape gate this call passed would refuse"
    );
    // The control: the same emit against a shape-conformant store deposits,
    // so the equality above is the dedup hit and not an absent write path.
    let (fresh, _) = w
        .emit(P1, &doc1(), &pred_def_ty(), &ca(3), &[])
        .expect("a distinct I0 class");
    assert_ne!(fresh, hit);
}
