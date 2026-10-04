//! Q7's scoped quiescence: exact over a sort-homogeneous scoped set and a safe
//! over-approximation wherever a body and a rule's element shape disagree, Q9's
//! four scope bodies and the one address each reads, the view a scope is read
//! at, and the precondition's four conjuncts, each refused at the door.

use crate::common::*;
use crate::terms::*;

use skep_address::Address;
use skep_coordination::{
    Arg, Dom, FireAction, FireOutcome, Occurrence, Rule, ScopeBody, Sort, Term, Trigger, TypedTerm,
    View,
};
use skep_links::{Caller, SlotArg};

/// Q7: scoped quiescence is exact for a sort-homogeneous scoped set, and a
/// strict over-approximation (never false quiescence) wherever a body and a
/// rule's element shape disagree — a tuple body over an address domain, or
/// `PerAddress` once a tuple-domained rule joins the registry.
#[test]
fn quiescent_scoped_is_exact_then_over_approximates_in_the_safe_direction() {
    let k = kernel();
    let mut c = coord(&k);
    let writer = link_writer(&k);
    writer.emit(Caller::System, &doc1(), &pred_stable_ty(), &ca(1), &[]).expect("rel 1");
    writer.emit(Caller::System, &doc1(), &pred_stable_ty(), &ca(3), &[]).expect("rel 2");

    let trig = Trigger::Inline(
        c.type_check_trigger((v(1), Sort::Addr), not(is_k(&marker_ty(), var(1))))
            .expect("trigger"),
    );
    let id = c
        .register_rule(Rule {
            domain: Dom::MembersDom(concrete(&pred_stable_ty())),
            trigger: trig,
            view: View::Audit,
            action: marker_action(),
        })
        .expect("register");

    let scope: TypedTerm = c
        .type_check(vec![(v(9), Sort::Addr)], addr_eq(var(9), lit_addr(&ca(1))))
        .expect("one-Addr-param Bool scope");
    assert!(!c.quiescent_scoped(&scope, ScopeBody::PerAddress, &k.snapshot()));
    // The other shape mismatch is unscoped too: a TUPLE body cannot scope this
    // address-domained rule, so its work counts even under a scope that holds
    // of nothing — while the address body, exact here, scopes all of it out.
    let nowhere = c.type_check(vec![(v(9), Sort::Addr)], fls()).expect("a scope of nothing");
    for body in [ScopeBody::PerEmitter, ScopeBody::PerTarget, ScopeBody::PerSource] {
        assert!(!c.quiescent_scoped(&nowhere, body, &k.snapshot()), "{body:?} over addresses");
    }
    assert!(c.quiescent_scoped(&nowhere, ScopeBody::PerAddress, &k.snapshot()));

    // Discharge the in-scope work only: scoped-quiescent, globally not.
    match c.fire(&Occurrence { rule: id, arg: Arg::Addr(ca(1)) }).expect("fire ca1") {
        FireOutcome::Fired { .. } => {}
        other => panic!("expected Fired, got {other:?}"),
    }
    let s2 = k.snapshot();
    assert!(c.quiescent_scoped(&scope, ScopeBody::PerAddress, &s2));
    assert!(!c.quiescent(&s2));

    // A Tup-domain rule is sort-incompatible with PerAddress: left UNSCOPED,
    // its enabled occurrence keeps the scoped verdict false — more work
    // reported, never false quiescence.
    deposit_rel(&k, PRED_DEF, &ca(5), &ca(6)); // a pred_def-classed tuple
    let trig_t = Trigger::Inline(
        c.type_check_trigger((v(2), Sort::Tup), tru()).expect("Tup trigger"),
    );
    c.register_rule(Rule {
        domain: Dom::ActiveSlice(concrete(&pred_def_ty())),
        trigger: trig_t,
        view: View::Active,
        action: FireAction::Nullify { home: doc1() },
    })
    .expect("register");
    assert!(!c.quiescent_scoped(&scope, ScopeBody::PerAddress, &k.snapshot()));
}

/// Q9's tuple bodies read one slot each: the emitter is the tuple's own
/// address, the source its F, the target its G — a tuple-domained rule's
/// work is reported under exactly the scope that names that slot's address,
/// and always under `PerAddress`, which cannot scope it.
#[test]
fn the_tuple_scope_bodies_read_emitter_source_and_target() {
    let k = kernel();
    let mut c = coord(&k);
    let l1 = deposit_rel(&k, PRED_STABLE, &ca(1), &ca(2));
    c.register_rule(Rule {
        domain: Dom::ActiveSlice(concrete(&pred_stable_ty())),
        trigger: always_tup(&c),
        view: View::Active,
        action: FireAction::Nullify { home: doc1() },
    })
    .expect("register");
    let s = k.snapshot();
    let scope = |x: &Address| c.type_check(vec![(v(9), Sort::Addr)], addr_eq(var(9), lit_addr(x))).expect("scope");
    let quiet = |x: &Address, body: ScopeBody| c.quiescent_scoped(&scope(x), body, &s);
    for (x, source, target, emitter) in [
        (ca(1), false, true, true),
        (ca(2), true, false, true),
        (l1.clone(), true, true, false),
    ] {
        assert_eq!(quiet(&x, ScopeBody::PerSource), source, "PerSource at {x}");
        assert_eq!(quiet(&x, ScopeBody::PerTarget), target, "PerTarget at {x}");
        assert_eq!(quiet(&x, ScopeBody::PerEmitter), emitter, "PerEmitter at {x}");
        assert!(!quiet(&x, ScopeBody::PerAddress), "unscoped under PerAddress: its work is always reported");
    }
}

/// Q9's `PerTarget` and `PerSource` read their slot with `any`: a tuple with
/// two targets is in scope when EITHER is. An `all` would scope the rule's
/// work out and report a quiescence that is not there, which Q7 promises
/// never happens.
#[test]
fn a_multi_address_slot_is_in_scope_when_any_of_its_addresses_is() {
    let k = kernel();
    let mut c = coord(&k);
    link_writer(&k)
        .makelink(
            Caller::System,
            &doc1(),
            SlotArg::Addrs(vec![ca(1), ca(3)]),
            SlotArg::Addrs(vec![ca(2), ca(4)]),
            SlotArg::Addrs(vec![ra(PRED_STABLE)]),
        )
        .expect("a tuple with two sources and two targets");
    c.register_rule(Rule {
        domain: Dom::ActiveSlice(concrete(&pred_stable_ty())),
        trigger: always_tup(&c),
        view: View::Active,
        action: FireAction::Nullify { home: doc1() },
    })
    .expect("register");
    let s = k.snapshot();
    let scope = |x: &Address| {
        c.type_check(vec![(v(9), Sort::Addr)], addr_eq(var(9), lit_addr(x))).expect("scope")
    };
    for (x, body) in [
        (ca(2), ScopeBody::PerTarget),
        (ca(4), ScopeBody::PerTarget),
        (ca(1), ScopeBody::PerSource),
        (ca(3), ScopeBody::PerSource),
    ] {
        assert!(!c.quiescent_scoped(&scope(&x), body, &s), "{x} under {body:?}");
    }
    assert!(c.quiescent_scoped(&scope(&ca(9)), ScopeBody::PerTarget, &s));
    assert!(c.quiescent_scoped(&scope(&ca(9)), ScopeBody::PerSource, &s));
}

/// `PerEmitter` asks `S` about the tuple's OWN address, a LINK address: a
/// scope naming the home document, `x = D`, holds of no tuple, and the rule's
/// work drops out of it; the scope `ScopeBody::PerEmitter` names for a home,
/// `D ≼ x`, keeps that work in view — and leaves out a tuple homed elsewhere.
#[test]
fn per_emitter_asks_about_the_link_address_not_its_home() {
    let k = kernel();
    let mut c = coord(&k);
    deposit_rel(&k, PRED_STABLE, &ca(1), &ca(2)); // homed in doc1
    c.register_rule(Rule {
        domain: Dom::ActiveSlice(concrete(&pred_stable_ty())),
        trigger: always_tup(&c),
        view: View::Active,
        action: FireAction::Nullify { home: doc1() },
    })
    .expect("register");
    let s = k.snapshot();
    let quiet = |body: Term| {
        let scope = c.type_check(vec![(v(9), Sort::Addr)], body).expect("scope");
        c.quiescent_scoped(&scope, ScopeBody::PerEmitter, &s)
    };
    assert!(quiet(addr_eq(var(9), lit_addr(&doc1()))), "a link address is never its home's");
    assert!(!quiet(prefix(lit_addr(&doc1()), var(9))), "doc1 ≼ the link: the work is in scope");
    assert!(quiet(prefix(lit_addr(&doc2()), var(9))), "a doc1 tuple is outside doc2's scope");
}

/// The scope is read at `View::Active` — the documented default of an OPEN
/// decision, which a state-reading scope observes. `S(y) := is_K(Retired, y)`
/// over an element retired and then un-retired holds at audit and not at
/// active, so the rule's one argument is out of scope as built — and would be
/// in it were the scope read at audit, or at the rule's own view (audit here).
/// A settlement of the decision should turn this red, deliberately; the
/// control scope, which holds at both views, keeps the work in view.
#[test]
fn a_state_reading_scope_is_read_at_the_active_view() {
    let k = kernel();
    let mut c = coord(&k);
    let writer = link_writer(&k);
    writer.emit(Caller::System, &doc1(), &pred_stable_ty(), &ca(1), &[]).expect("a member");
    let (retirement, _) =
        writer.emit(Caller::System, &doc1(), &retired_ty(), &ca(1), &[]).expect("retire ca1");
    writer.nullify(Caller::System, &doc1(), &retirement).expect("un-retire ca1");
    c.register_rule(Rule {
        domain: Dom::MembersDom(concrete(&pred_stable_ty())),
        trigger: always_addr(&c),
        view: View::Audit,
        action: marker_action(),
    })
    .expect("register");
    let scope = |body: Term| c.type_check(vec![(v(9), Sort::Addr)], body).expect("a scope");
    let s = k.snapshot();
    assert!(!c.quiescent(&s), "the rule has work: ca1");
    let retired_now = scope(is_k(&retired_ty(), var(9)));
    assert!(
        c.quiescent_scoped(&retired_now, ScopeBody::PerAddress, &s),
        "ca1 is retired only in the audit record"
    );
    let a_member = scope(is_k(&pred_stable_ty(), var(9)));
    assert!(
        !c.quiescent_scoped(&a_member, ScopeBody::PerAddress, &s),
        "the control: ca1 is a member at both views"
    );
}

/// Q7's ref-free conjunct, refused at the door — asked, as each conjunct here
/// is, of an IDLE registry, where `quiescent_scoped` evaluates no scope: a
/// missing door would answer a verdict in silence rather than panic later, so
/// only the door can make these red.
#[test]
#[should_panic(expected = "quiescent_scoped precondition violated (Q7): the scope is ref-bearing")]
fn quiescent_scoped_panics_on_a_ref_bearing_scope() {
    let k = kernel();
    let c = coord(&k);
    let (p, _) =
        c.define_predicate(&doc1(), &c.type_check(vec![], tru()).expect("P")).expect("define P");
    let body = and(fls(), Term::Ref { addr: p, args: vec![] });
    let scope = c.type_check(vec![(v(9), Sort::Addr)], body).expect("a ref-bearing scope");
    let _ = c.quiescent_scoped(&scope, ScopeBody::PerAddress, &k.snapshot());
}

/// The arity conjunct, asked before the parameter is indexed: a closed scope
/// is named, never an index panic.
#[test]
#[should_panic(
    expected = "quiescent_scoped precondition violated (Q7): the scope binds 0 parameters, not 1"
)]
fn quiescent_scoped_panics_on_a_closed_scope() {
    let k = kernel();
    let c = coord(&k);
    let scope = c.type_check(vec![], tru()).expect("a closed term");
    let _ = c.quiescent_scoped(&scope, ScopeBody::PerAddress, &k.snapshot());
}

/// The parameter conjunct.
#[test]
#[should_panic(
    expected = "quiescent_scoped precondition violated (Q7): the scope's parameter is Nat, not Addr"
)]
fn quiescent_scoped_panics_on_a_nat_parameter_scope() {
    let k = kernel();
    let c = coord(&k);
    let scope = c.type_check(vec![(v(9), Sort::Nat)], tru()).expect("a Nat-parameter term");
    let s = k.snapshot();
    let _ = c.quiescent_scoped(&scope, ScopeBody::PerAddress, &s);
}

/// The codomain conjunct.
#[test]
#[should_panic(
    expected = "quiescent_scoped precondition violated (Q7): the scope's codomain is Nat, not Bool"
)]
fn quiescent_scoped_panics_on_a_non_boolean_scope() {
    let k = kernel();
    let c = coord(&k);
    let scope = c.type_check(vec![(v(9), Sort::Addr)], lit_nat(1)).expect("an ℕ-valued term");
    let _ = c.quiescent_scoped(&scope, ScopeBody::PerAddress, &k.snapshot());
}
