//! The monitors: the key a peeked occurrence hands the divergence count, that
//! count recomputed from the store under its attribution key, a foreign
//! `RuleId`'s two answers (`fire` panics, `fire_count` counts 0), and the
//! armer graph's edge rule.

use crate::common::*;
use crate::terms::*;

use skep_coordination::{
    Arg, Coordinator, Dom, FireAction, Occurrence, Rule, RuleId, Sort, StepOutcome, Term, Trigger,
    View,
};
use skep_links::{Caller, SlotArg};

/// `Arg::key_addr` bridges the peek to the monitor: `next_enabled` hands back
/// a bound argument of either shape, and `fire_count` keys on an address —
/// the tuple's `t.addr` (R1), never a slot endpoint. A driver outside the
/// crate reaches the rule engine's own key through this accessor rather than
/// re-deriving the projection by matching the shapes.
#[test]
fn a_peeked_occurrence_yields_the_key_the_monitor_counts_by() {
    // A `Tup` domain: the key is the tuple's own address, not its F endpoint.
    let k = kernel();
    let mut c = coord(&k);
    let l1 = deposit_rel(&k, PRED_STABLE, &ca(1), &ca(2));
    let tup_rule = c
        .register_rule(Rule {
            domain: Dom::ActiveSlice(concrete(&pred_stable_ty())),
            trigger: always_tup(&c),
            view: View::Active,
            action: FireAction::Nullify { home: doc1() },
        })
        .expect("register");
    let peeked = c.next_enabled(&k.snapshot()).expect("enabled");
    assert!(matches!(peeked.arg, Arg::Tuple(_)), "a Tup domain binds a tuple");
    assert_ne!(peeked.arg, Arg::Addr(l1.clone()), "the key is not the element");
    assert_eq!(peeked.arg.key_addr(), &l1);
    assert!(matches!(c.step(&k.snapshot()), StepOutcome::Fired { .. }));
    assert_eq!(c.fire_count(tup_rule, peeked.arg.key_addr()), 1);

    // An `Addr` domain: the key is the address itself.
    let k = kernel();
    let mut c = coord(&k);
    link_writer(&k).emit(Caller::System, &doc1(), &pred_stable_ty(), &ca(1), &[]).expect("rel");
    let addr_rule = c
        .register_rule(Rule {
            domain: Dom::MembersDom(concrete(&pred_stable_ty())),
            trigger: not_marked(&c),
            view: View::Audit,
            action: marker_action(),
        })
        .expect("register");
    let peeked = c.next_enabled(&k.snapshot()).expect("enabled");
    assert_eq!(peeked.arg.key_addr(), &ca(1));
    assert!(matches!(c.step(&k.snapshot()), StepOutcome::Fired { .. }));
    assert_eq!(c.fire_count(addr_rule, peeked.arg.key_addr()), 1);
}

/// `fire`'s precondition: an occurrence aimed at a rule this coordinator
/// never registered panics at the door.
#[test]
#[should_panic(expected = "fire precondition")]
fn fire_panics_on_a_rule_id_from_another_coordinator() {
    let k = kernel();
    let mut c1 = coord(&k);
    let id = c1
        .register_rule(Rule {
            domain: Dom::MembersDom(concrete(&pred_stable_ty())),
            trigger: always_addr(&c1),
            view: View::Audit,
            action: marker_action(),
        })
        .expect("register");
    let c2 = coord(&k);
    let _ = c2.fire(&Occurrence { rule: id, arg: Arg::Addr(ca(1)) });
}

/// The contrast: `fire_count`, a monitor, answers 0 for the same foreign id.
#[test]
fn fire_count_answers_zero_for_a_foreign_rule_id() {
    let k = kernel();
    let mut c1 = coord(&k);
    let id = c1
        .register_rule(Rule {
            domain: Dom::MembersDom(concrete(&pred_stable_ty())),
            trigger: always_addr(&c1),
            view: View::Audit,
            action: marker_action(),
        })
        .expect("register");
    let c2 = coord(&k);
    assert_eq!(c2.fire_count(id, &ca(1)), 0);
}

/// The attribution key is exact — `F = {x}` in the action's home — and three
/// same-typed tuples are outside the count: one whose F merely COVERS the
/// argument; one whose F denotes it beside an address under it, which has the
/// argument's coverage class (the def probes' key) and is not `{x}`; and one
/// with the exact F homed elsewhere (a draft's, invisible to the fire's
/// dedup).
#[test]
fn fire_count_keys_on_exact_denotation_and_home() {
    let k = kernel();
    let mut c = coord_with_guest(&k, |_, d| *d != doc2());
    let writer = link_writer(&k);
    writer.emit(Caller::System, &doc1(), &pred_stable_ty(), &ca(1), &[]).expect("rel");
    writer.emit(Caller::System, &doc2(), &marker_ty(), &ca(1), &[]).expect("the draft's marker, ahead of the fire");
    let id = c
        .register_rule(Rule {
            domain: Dom::MembersDom(concrete(&pred_stable_ty())),
            trigger: not_marked(&c),
            view: View::Audit,
            action: marker_action(),
        })
        .expect("register");
    assert!(matches!(c.step(&k.snapshot()), StepOutcome::Fired { .. }));
    writer.emit(Caller::System, &doc1(), &marker_ty(), &doc1(), &[]).expect("a marker covering ca1 without naming it");
    writer
        .makelink(
            Caller::System,
            &doc1(),
            SlotArg::Addrs(vec![ca(1), a(&[1, 0, 1, 0, 1, 0, 1, 1, 7])]),
            SlotArg::Addrs(vec![]),
            SlotArg::Addrs(vec![ra(RETIRED)]),
        )
        .expect("a marker denoting ca1 beside an address under it");
    assert_eq!(c.fire_count(id, &ca(1)), 1);
}

/// `fire_count` is RECOMPUTED from M7's journal-recovered slices at every ask
/// — M9 owns no authoritative state — not tallied as fires happen: a handle
/// that fired nothing reports the same count for the same rule, and a
/// non-rule writer at the same attribution key `(ty, home, F = {x})` is
/// counted too, which is the documented OVER-count behind "flags
/// misbehaviour, does not certify it". An in-memory tally produces neither
/// number.
#[test]
fn fire_counts_are_recomputed_from_the_store_not_tallied_in_memory() {
    let k = kernel();
    let mut c = coord(&k);
    link_writer(&k).emit(Caller::System, &doc1(), &pred_stable_ty(), &ca(1), &[]).expect("rel");
    let rule = Rule {
        domain: Dom::MembersDom(concrete(&pred_stable_ty())),
        trigger: not_marked(&c),
        view: View::Audit,
        action: marker_action(),
    };
    let id = c.register_rule(rule.clone()).expect("register");
    assert!(matches!(c.step(&k.snapshot()), StepOutcome::Fired { .. }));
    assert_eq!(c.fire_count(id, &ca(1)), 1);

    // A handle that fired nothing recomputes the same count from the store.
    let mut fresh = coord(&k);
    let id2 = fresh.register_rule(rule).expect("the same rule, a new handle");
    assert_eq!(id2, id, "ids are minted per handle — two coordinators over one kernel collide");
    assert_eq!(fresh.fire_count(id2, &ca(1)), 1);

    // A non-rule writer at the same (type, home, exact F) — the Marker class
    // IS the Retired class here — collides with the key, and the recompute
    // says so where a tally would still say one.
    deposit_rel(&k, RETIRED, &ca(1), &ca(2));
    assert_eq!(c.fire_count(id, &ca(1)), 2);
    assert_eq!(fresh.fire_count(id2, &ca(1)), 2);
}

/// The armer graph's edge rule: an empty footprint is armed by nothing;
/// emitting one class while reading another's audit slice makes no edge;
/// the Default reading charges the BH1 filter slice — the class emitted, a
/// self-loop; a Marker landing in a Nullify rule's active footprint, whose
/// retraction arms any active-reading trigger, closes a two-rule cycle; a
/// whole-audit read is armed by any deposit; and a Nullify's own `[R]` tuple
/// arms a reader of `[R]`'s audit slice through its class. Disjoint cycles
/// come back ordered by their least member.
#[test]
fn armer_cycles_follow_the_edge_rule() {
    let rule = |c: &Coordinator<World>, body: Term, view: View, action: FireAction| Rule {
        domain: Dom::MembersDom(concrete(&pred_stable_ty())),
        trigger: Trigger::Inline(c.type_check_trigger((v(1), Sort::Addr), body).expect("trigger")),
        view,
        action,
    };
    let none: Vec<Vec<RuleId>> = Vec::new();

    let k = kernel();
    let mut c = coord(&k);
    c.register_rule(rule(&c, tru(), View::Audit, marker_action())).expect("register");
    assert_eq!(c.armer_cycles(), none);

    let k = kernel();
    let mut c = coord(&k);
    c.register_rule(rule(&c, is_k(&pred_stable_ty(), var(1)), View::Audit, marker_action())).expect("register");
    assert_eq!(c.armer_cycles(), none);

    let k = kernel();
    let mut c = coord(&k);
    let id = c
        .register_rule(rule(&c, is_k(&pred_stable_ty(), var(1)), View::Default, marker_action()))
        .expect("register");
    assert_eq!(c.armer_cycles(), vec![vec![id]]);

    let k = kernel();
    let mut c = coord(&k);
    let a_id = c
        .register_rule(rule(&c, is_k(&marker_ty(), var(1)), View::Active, FireAction::Nullify { home: doc1() }))
        .expect("A");
    let b_id = c
        .register_rule(rule(&c, is_k(&pred_stable_ty(), var(1)), View::Active, marker_action()))
        .expect("B");
    assert_eq!(c.armer_cycles(), vec![vec![a_id, b_id]]);
    // The stated ordering, checked as a property rather than by transcribing
    // the ids: a `RuleId` orders by registration, so each component ascends.
    assert!(a_id < b_id, "a RuleId orders by registration");
    for scc in c.armer_cycles() {
        assert!(scc.windows(2).all(|w| w[0] < w[1]), "each component ascends by RuleId");
    }

    // The whole-audit read: a trigger over `L_dom` is armed by ANY deposit,
    // the rule's own marker included — a cataloged link lands in the sublayer.
    let k = kernel();
    let mut c = coord(&k);
    let id = c
        .register_rule(rule(&c, exists(2, Dom::LinkDom, tru()), View::Audit, marker_action()))
        .expect("register");
    assert_eq!(c.armer_cycles(), vec![vec![id]]);

    // Two disjoint cycles — a Marker rule arms the Nullify rule, whose
    // retraction arms only active readers — returned ordered by their least
    // member, which is not the order the search finishes them in.
    let k = kernel();
    let mut c = coord(&k);
    let marker = c
        .register_rule(rule(&c, is_k(&marker_ty(), var(1)), View::Audit, marker_action()))
        .expect("reads its own class at audit");
    let nullify = c
        .register_rule(rule(
            &c,
            is_k(&marker_ty(), var(1)),
            View::Active,
            FireAction::Nullify { home: doc1() },
        ))
        .expect("reads that class at active");
    assert_eq!(c.armer_cycles(), vec![vec![marker], vec![nullify]]);

    // A Nullify emission lands in `[R]` itself, so it arms a trigger reading
    // `[R]`'s AUDIT slice through that class — with no active read in sight.
    let k = kernel();
    let mut c = coord(&k);
    let id = c
        .register_rule(rule(
            &c,
            is_k(&retraction_ty(), var(1)),
            View::Audit,
            FireAction::Nullify { home: doc1() },
        ))
        .expect("reads [R] at audit");
    assert_eq!(c.armer_cycles(), vec![vec![id]]);
}
