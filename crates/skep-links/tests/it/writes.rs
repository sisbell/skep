//! The deposit ops over a real kernel (InMemory): the two write disciplines
//! and their gates (the reachable shape cells, the pre-transact fences in
//! their firing order, the hoisted home/ω checks on hit AND miss and ahead of
//! an op's own declared-first verdict), idempotent dedup at the caller's
//! visibility class with resurrection and the T1-least ACTIVE incumbent a hit
//! returns, retraction — its irreversibility, its target precedence and the
//! active view — MAKELINK end-to-end (wf over every slot's specs, multi-spec
//! resolution, deposit, seat) and the ratio a `Resolve` slot amplifies by,
//! and the families that span every op and so live together: the ownership
//! gate with the ω-on-the-home-and-nothing-else capability `assert_sup` and
//! `editlink` publish, the `[R]` and `[K_sup]` sole-writer fences on BOTH
//! surfaces, the per-slot span budget at its exact boundary on every op and
//! slot form that carries one, the rejection family's `Display`/`source`
//! chaining, and the checkpoint-roundtrip + rebuild_derived discipline over
//! the hints the writes maintain. The supersession ops' graph, the typed
//! reads and the §G primitives each have a module of their own.
//!
//! The registry's population is the compiled shipped five (owner ruling,
//! 2026-08-26 — the app-decl seam is deleted): the managed surface's
//! reachable registered classes are the three Unary idem⊤ ones
//! (`PredDef`/`PredStable`/`Retired`; `Supersedes` and `Retraction` are
//! sole-writer-fenced), so emit-mechanics tests run over those, and
//! Binary/Multi tuples enter through the open surface.

use crate::common;

use common::*;
use skep_address::{document_of, Address, SpanSet};
use skep_arrangement::HasM5;
use skep_kernel::TxnError;
use skep_links::{
    enc, AssertSupError, Caller, Edit, EditLinkError, EmitError, Endset, HasLinks, Invalid, Link,
    MakeLinkError, NotBh4, NullifyError, Pattern, RetractStaleError, SlotArg, Tip, View,
};

// ---- the value-keyed gates at the caller's visibility class (lane 3.3b) ----

/// PUB-6.25/PUB-6.26: the idempotency lookup runs over the I0 class FILTERED
/// by the caller's visibility predicate at link-home identity, inside the
/// write transaction. An incumbent homed in a document the caller cannot read
/// is invisible — the emit mints fresh beside it, and value-identical tuples
/// coexist across the boundary; a hit is the EARLIEST incumbent the caller's
/// class can read, never merely the earliest; and the answer is deterministic
/// given the class.
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

    // A class blind to doc1 mints the same value afresh, in its own home —
    // the ack never names an address inside a home the caller cannot read.
    let before = k.current_seq();
    let (second, seq) = no_doc1
        .emit(P1, &doc2(), &pred_def_ty(), &ca(1), &[])
        .expect("fresh beside an invisible incumbent");
    assert_eq!(second, la2(1));
    assert!(seq > before, "a fresh deposit commits");
    {
        // Both stand ACTIVE: value-identical tuples coexist across the
        // visibility boundary, and the class-keyed reads — which take no
        // class — see one member.
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
    // … the class blind to doc1 acks doc2's, the earliest it can read …
    let (hit, seq) = no_doc1
        .emit(P1, &doc2(), &pred_def_ty(), &ca(1), &[])
        .expect("a hit within the class");
    assert_eq!(hit, second);
    assert_eq!(seq, before);
    assert_eq!(k.current_seq(), before, "still zero-step");
    // … and, asked again, answers the same — deterministic given the class.
    let (again, _) = no_doc1.emit(P1, &doc2(), &pred_def_ty(), &ca(1), &[]).expect("hit again");
    assert_eq!(again, second);

    // A class blind to both of P1's homes mints a THIRD, in the sibling's own
    // home …
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
/// each class then acks the earliest claim it can read; and the supersession
/// walk, which takes no class, reads the two claims as one edge.
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

    // Each class acks the earliest claim it can read.
    let before = k.current_seq();
    let (hit, _) = no_doc1.assert_sup(P1, &doc2(), &x, &y).expect("hit within the class");
    assert_eq!(hit, c2);
    let (hit, _) = all.assert_sup(P1, &doc2(), &x, &y).expect("hit at the all-visible class");
    assert_eq!(hit, c1);
    assert_eq!(k.current_seq(), before, "both hits are zero-step");

    // The supersession graph is the world's, not a class's: two claims, one
    // operative edge, and retracting one leaves the other's edge standing.
    let snap = k.snapshot();
    assert_eq!(snap.world().links().succs(&sup, &x), vec![y.clone()]);
    all.nullify(P1, &doc1(), &c1).expect("retract the first claim");
    let snap = k.snapshot();
    assert_eq!(snap.world().links().succs(&sup, &x), vec![y.clone()]);
    assert_eq!(snap.world().links().tip(&sup, &x), Tip::Sink(y));
}

/// PUB-6.27: `editlink`'s claim meets no incumbent whatever the class — its
/// I0 carries a successor minted in the same transaction — so both of its
/// acks land in the homes the caller named, never in another home's link
/// subspace, even beside a standing claim over the same original that the
/// caller cannot read.
#[test]
fn editlink_s_acks_land_in_the_caller_s_homes_whatever_the_class() {
    let k = kernel();
    let hide_doc1 = |_: &World, home: &Address| *home != doc1();
    let all = writer(&k);
    let no_doc1 = writer_at(&k, &hide_doc1);
    let (x, _) = all.emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[]).expect("x");
    let (y, _) = all.emit(P1, &doc1(), &pred_def_ty(), &ca(2), &[]).expect("y");
    all.assert_sup(P1, &doc1(), &x, &y).expect("a doc1-homed claim over x");
    let successor_value =
        Link::new([enc(&[ca(3)]), enc(&[ca(4)]), unregistered_ty(30)]).expect("arity 3");
    for w in [&all, &no_doc1] {
        let (edit, _) = w
            .editlink(P1, &x, successor_value.clone(), &doc2(), &doc2())
            .expect("an edit from doc2, at either class");
        assert_eq!(document_of(&edit.successor), Some(doc2()));
        assert_eq!(document_of(&edit.claim), Some(doc2()));
    }
}

/// The `Visibility` contract's second half is a CONDITION and not an
/// obligation, and this is the whole of the difference: a predicate blind to
/// the home the caller writes to costs `nullify` a FRESH retraction tuple
/// where a hit would have been zero-step, and costs its postcondition nothing
/// — the target is tombstoned either way. Every `[R]` incumbent of one
/// identity is homed in the retraction's own `home`, so blinding the class
/// to that one document is exactly what hides them all.
#[test]
fn a_predicate_blind_to_the_caller_s_own_home_costs_nullify_a_fresh_retraction_never_its_postcondition(
) {
    let k = kernel();
    let hide_doc1 = |_: &World, home: &Address| *home != doc1();
    let all = writer(&k);
    let blind = writer_at(&k, &hide_doc1);
    let (target, _) = all.emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[]).expect("target");

    // The control: at a class that reads doc1, the second retraction is a
    // zero-step hit on the first.
    let (r1, _) = all.nullify(P1, &doc1(), &target).expect("retract");
    let before = k.current_seq();
    let (hit, seq) = all.nullify(P1, &doc1(), &target).expect("hit within the class");
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

// ---- Emit_K: the managed gate and its precedences ----

#[test]
fn emit_deposits_verbatim_reads_back_and_never_seats() {
    let k = kernel();
    let w = writer(&k);
    let (a1, _) = w
        .emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[])
        .expect("registered Unary emit succeeds");
    assert_eq!(a1, la(1)); // first link minted on doc1's link chain

    let snap = k.snapshot();
    let links = snap.world().links();
    // READLINK: the value verbatim — from is the canonical encoding, to the
    // empty endset a Unary emission carries, ty stored verbatim as e₃.
    let link = links.readlink(&a1).expect("deposited link is resident");
    assert_eq!(link.from_slot(), &enc(&[ca(1)]));
    assert_eq!(link.to_slot(), &Endset::empty());
    assert_eq!(link.type_slot(), &pred_def_ty());
    // Emit_K does NOT seat (MAKELINK alone seats).
    assert_eq!(snap.world().m5().link_count(&doc1()), n(0));
    // Observe: the empty pattern is no constraint; exact ⊆-coverage match.
    let all = links.observe(&pred_def_ty(), Pattern::default(), View::Active);
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].addr, a1);
    // An unmatched F-probe finds nothing.
    assert!(links
        .observe(
            &pred_def_ty(),
            Pattern {
                from: &[ca(3).tumbler().clone()],
                to: &[],
            },
            View::Active
        )
        .is_empty());
    // Default predicates D1/D2/D3.
    assert!(links.is_k(&pred_def_ty(), ca(1).tumbler()));
    assert!(!links.is_k(&pred_def_ty(), ca(2).tumbler()));
    // The probe domain is all of carrier T: a raw tumbler under subtree(ca1)
    // — not an element address — is an honest membership probe.
    assert!(links.is_k(&pred_def_ty(), &t(&[1, 0, 1, 0, 1, 0, 1, 1, 5])));
    assert_eq!(links.members(&pred_def_ty(), View::Active), vec![ca(1)]);
}

#[test]
fn emit_names_a_distinct_rejection_for_each_gate_it_fails() {
    let k = kernel();
    let w = writer(&k);
    let sup = supersedes_ty();
    let retraction = retraction_ty();

    // Pre-transact: non-address-denoting ty (before any class computation).
    let content_extent = Endset::from_spans([iext(1, 3)]);
    assert!(matches!(
        w.emit(P1, &doc1(), &content_extent, &ca(1), &[ca(2)]),
        Err(TxnError::Rejected(EmitError::NonAddressDenotingType))
    ));
    // Pre-transact: the supersession-class fence (Conflicts §10).
    assert!(matches!(
        w.emit(P1, &doc1(), &sup, &ca(1), &[ca(2)]),
        Err(TxnError::Rejected(EmitError::SupersessionClass))
    ));
    // Unregistered class — any type number outside the shipped five.
    assert!(matches!(
        w.emit(P1, &doc1(), &unregistered_ty(20), &ca(1), &[ca(2)]),
        Err(TxnError::Rejected(EmitError::NotRegistered))
    ));
    // Shape gate: Unary demands |G| = 0.
    assert!(matches!(
        w.emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[ca(2)]),
        Err(TxnError::Rejected(EmitError::ShapeViolation))
    ));
    // K ≁ R: retraction writes only through nullify.
    assert!(matches!(
        w.emit(P1, &doc1(), &retraction, &ca(1), &[ca(2)]),
        Err(TxnError::Rejected(EmitError::RetractionClass))
    ));
    // Home existence, enforced on every path.
    assert!(matches!(
        w.emit(P1, &a(&[1, 0, 1, 0, 7]), &pred_def_ty(), &ca(1), &[]),
        Err(TxnError::Rejected(EmitError::HomeNotRegistered))
    ));
}

#[test]
fn emit_refuses_a_non_level_uniform_ty_without_classifying_it() {
    // `emit` is the one op whose contract promises a REJECTION where the typed
    // reads promise a panic: `NonAddressDenotingType` fires before ANY class
    // computation, keeping `coverage_class` off its pinned off-contract abort.
    // The wide span the gate case above uses is LEVEL-UNIFORM, so it classifies
    // happily and cannot tell the order apart; this one is the design's own
    // off-contract witness, T12-valid and wire-buildable (`Op::Emit` carries an
    // arbitrary `Endset`), so hoisting the classification above the denoting
    // check turns a typed refusal into an abort inside the daemon.
    let k = kernel();
    let w = writer(&k);
    let skew = skep_address::Span::new(t(&[5, 3]), t(&[0, 2, 7])).expect("T12 admits this span");
    let before = k.current_seq();
    assert!(matches!(
        w.emit(P1, &doc1(), &Endset::from_spans([skew]), &ca(1), &[]),
        Err(TxnError::Rejected(EmitError::NonAddressDenotingType))
    ));
    assert_eq!(k.current_seq(), before, "the refusal is pre-deposit");
}

#[test]
fn the_shape_gate_admits_exactly_the_registered_span_counts() {
    // P3 Sh-conf checks the REGISTERED shape, never one inferred from the
    // tuple: every shape requires |F| = 1 (which emit forces through its own
    // enc({from})), and |G| is 0 under Unary. The Unary row is the whole
    // reachable table on this surface — the format's registered population
    // is the shipped five, its two Binary classes are sole-writer-fenced
    // ahead of the shape gate, and no Multi class exists; `sh_conf`'s own
    // unit table in the registry crate keeps the other rows. Each admitted
    // cell emits from its own source, so no case can dedup into a
    // neighbour's incumbent.
    let k = kernel();
    let w = writer(&k);
    let targets = [vec![], vec![ca(90)], vec![ca(91), ca(92)]];
    let mut from = 10;
    for ty in [pred_def_ty(), pred_stable_ty(), retired_ty()] {
        for (g, to) in targets.iter().enumerate() {
            let conforms = g == 0; // Unary: no TO span
            let got = w.emit(P1, &doc1(), &ty, &ca(from), to);
            from += 1;
            match (&got, conforms) {
                (Ok(_), true) => {}
                (Err(TxnError::Rejected(EmitError::ShapeViolation)), false) => {}
                _ => panic!(
                    "Unary type with |G| = {g}: expected {}, got {got:?}",
                    if conforms {
                        "the registered shape admitted"
                    } else {
                        "a shape violation"
                    }
                ),
            }
        }
    }
    // An empty ty is not a shape verdict: ⟨⟩ is no registered class, so it
    // lands NotRegistered — which is why the Managed gate can call its
    // EmptyType arm unreachable.
    assert!(matches!(
        w.emit(P1, &doc1(), &Endset::empty(), &ca(1), &[ca(2)]),
        Err(TxnError::Rejected(EmitError::NotRegistered))
    ));
}

#[test]
fn emit_reports_the_retraction_fence_before_the_shape_gate() {
    // The one input that satisfies two Managed-gate rejections at once, so it
    // is the one that pins their precedence: `[R]` is registered Binary, so
    // an emit into it with |G| = 2 is BOTH a K ≁ R violation and a shape
    // violation. The fence speaks (design: K ≁ R before Sh-conf).
    let k = kernel();
    let w = writer(&k);
    let retraction = retraction_ty();
    assert!(matches!(
        w.emit(P1, &doc1(), &retraction, &ca(1), &[ca(2), ca(3)]),
        Err(TxnError::Rejected(EmitError::RetractionClass))
    ));
    // ...and each rejection is separately reachable, so the verdict above is
    // a precedence and not the only answer either input can get.
    assert!(matches!(
        w.emit(P1, &doc1(), &retraction, &ca(1), &[ca(2)]),
        Err(TxnError::Rejected(EmitError::RetractionClass))
    ));
    assert!(matches!(
        w.emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[ca(2), ca(3)]),
        Err(TxnError::Rejected(EmitError::ShapeViolation))
    ));
}

#[test]
fn emit_reports_the_supersession_fence_before_the_slot_budget() {
    // The three pre-transact fences are declared in firing order, and this is
    // the one pair a caller can collide: a `ty` naming the `[K_sup]` address
    // past the budget is BOTH, because the class collapses repeats while the
    // slot keeps every span. (The other two pairs have no shared input: a
    // non-address-denoting `ty` classifies to an extent class, which is never
    // a shipped one.)
    let k = kernel();
    let w = writer(&k);
    let over = skep_links::MAX_SLOT_SPANS + 1;
    assert!(matches!(
        w.emit(P1, &doc1(), &enc(&vec![ra(4); over]), &ca(1), &[]),
        Err(TxnError::Rejected(EmitError::SupersessionClass))
    ));
    // ...and each is separately reachable, so the above is a precedence and
    // not the only answer either input can get.
    assert!(matches!(
        w.emit(P1, &doc1(), &supersedes_ty(), &ca(1), &[]),
        Err(TxnError::Rejected(EmitError::SupersessionClass))
    ));
    assert!(matches!(
        w.emit(P1, &doc1(), &enc(&vec![ra(1); over]), &ca(1), &[]),
        Err(TxnError::Rejected(EmitError::SlotTooLarge))
    ));
}

#[test]
fn emit_rejects_an_unregistered_home_on_the_dedup_hit_path() {
    // The home check is hoisted ahead of the dedup short-circuit (Conflicts
    // §8): the I0 key excludes home, so this second emit WOULD hit the
    // incumbent, and P0 refuses it all the same. That is what makes "callers
    // cannot observe the branch" a property rather than an intention.
    let k = kernel();
    let w = writer(&k);
    let (incumbent, _) = w
        .emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[])
        .expect("incumbent");
    let before = k.current_seq();
    assert!(matches!(
        w.emit(P1, &a(&[1, 0, 1, 0, 7]), &pred_def_ty(), &ca(1), &[]),
        Err(TxnError::Rejected(EmitError::HomeNotRegistered))
    ));
    assert_eq!(k.current_seq(), before);
    // The same tuple at a REGISTERED home dedups to the incumbent, so the
    // refusal above was the home check and not an absent key.
    let (hit, _) = w
        .emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[])
        .expect("dedup hit");
    assert_eq!(hit, incumbent);
}

#[test]
fn pre_transact_fences_outrank_the_home_and_owner_checks() {
    // The refusals that fire before a transaction opens keep firing when the
    // home is unregistered AND the caller is a stranger: they sit ahead of
    // P0 and ω, not behind them.
    let k = kernel();
    let w = writer(&k);
    let sup = supersedes_ty();
    let ghost_home = a(&[1, 0, 1, 0, 7]);
    assert!(matches!(
        w.emit(P2, &ghost_home, &Endset::from_spans([iext(1, 3)]), &ca(1), &[ca(2)]),
        Err(TxnError::Rejected(EmitError::NonAddressDenotingType))
    ));
    assert!(matches!(
        w.emit(P2, &ghost_home, &sup, &ca(1), &[ca(2)]),
        Err(TxnError::Rejected(EmitError::SupersessionClass))
    ));
    // The third of emit's pre-transact fences, at the same ghost home and
    // under the same stranger: the budget speaks before P0 and ω too.
    let over: Vec<Address> = (1..=(skep_links::MAX_SLOT_SPANS as u32 + 1)).map(ca).collect();
    assert!(matches!(
        w.emit(P2, &ghost_home, &pred_def_ty(), &ca(1), &over),
        Err(TxnError::Rejected(EmitError::SlotTooLarge))
    ));
    assert!(matches!(
        w.retract_stale(P2, &ghost_home, &unregistered_ty(2), 0),
        Err(TxnError::Rejected(RetractStaleError::NotBh4))
    ));
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
    let (a1b, s1b) = w.emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[]).expect("dedup hit");
    assert_eq!(a1b, a1);
    assert_eq!(s1b, s1);
    assert_eq!(k.current_seq(), s1); // zero-step: nothing committed
    // The open surface is the fresh-always contrast (ML0): the identical
    // deposit lands at a new address every time, dedup lock and check alike
    // absent.
    let open = || open_deposit(&w, &[ca(1)], &[ca(2)], &[unregistered_ta(1)]);
    let m1 = open();
    let m2 = open();
    assert_ne!(m1, m2);
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

// ---- Nullify: the sole retraction path ----

#[test]
fn nullify_tombstones_its_target_and_accepts_its_own_fresh_address() {
    let k = kernel();
    let w = writer(&k);
    // P-tgt rejects a non-resident, non-self target.
    assert!(matches!(
        w.nullify(P1, &doc1(), &ca(9)),
        Err(TxnError::Rejected(NullifyError::BadTarget))
    ));
    // P0.
    assert!(matches!(
        w.nullify(P1, &a(&[1, 0, 1, 0, 7]), &la(1)),
        Err(TxnError::Rejected(NullifyError::HomeNotRegistered))
    ));
    // Happy path: the [R] tuple nullifies exactly the target root.
    let (m1, _) = w.emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[]).expect("emit");
    let (r1, _) = w.nullify(P1, &doc1(), &m1).expect("nullify");
    {
        let snap = k.snapshot();
        let links = snap.world().links();
        assert!(links.is_nullified(&m1));
        assert!(!links.is_active(&m1));
        assert!(links.is_active(&r1)); // the retraction tuple itself is active
        // Active slices exclude the nullified tuple; audit keeps it (R3).
        assert!(!links.type_slice(&pred_def_ty(), View::Active).contains(&m1));
        assert!(links.type_slice(&pred_def_ty(), View::Audit).contains(&m1));
    }
    // idem⊤: re-retracting the same target from the same home dedups.
    let (r2, _) = w.nullify(P1, &doc1(), &m1).expect("re-nullify dedups");
    assert_eq!(r2, r1);
    // Born-nullified self-target: the target may be the address this call's
    // own retraction tuple would occupy (P-tgt's second disjunct) — doc2's
    // first link is la2(1).
    let (born_nullified, _) = w.nullify(P1, &doc2(), &la2(1)).expect("self-targeting retraction");
    assert_eq!(born_nullified, la2(1));
    {
        let snap = k.snapshot();
        assert!(snap.world().links().is_nullified(&la2(1)));
    }
    // The predicted address tracks the home's own link count, so the second
    // disjunct names a moving address, not a fixed one: doc1 holds two links
    // (m1, r1 — the dedup hit staged nothing), so its next mint is exactly
    // la(3); la(4) is neither resident nor `a_emit`.
    assert!(matches!(
        w.nullify(P1, &doc1(), &la(4)),
        Err(TxnError::Rejected(NullifyError::BadTarget))
    ));
    let (born_on_used_chain, _) = w
        .nullify(P1, &doc1(), &la(3))
        .expect("self-targeting on a used chain");
    assert_eq!(born_on_used_chain, la(3));
    let snap = k.snapshot();
    assert!(snap.world().links().is_nullified(&la(3)));
}

#[test]
fn nullify_reports_a_foreign_target_before_a_bad_one() {
    // The two checks are ordered — ω on the target precedes P-tgt — so the
    // auth verdict never depends on residence timing. This is the one input
    // that satisfies both: P2 owns the home, owns neither the target nor its
    // account, and the target is neither resident nor this call's `a_emit`.
    let k = kernel();
    let w = writer(&k);
    assert!(matches!(
        w.nullify(P2, &sib_doc(), &ca(9)),
        Err(TxnError::Rejected(NullifyError::NotOwner(d))) if d == ca(9)
    ));
    // ...and each verdict is separately reachable, so the above is the
    // precedence and not the only answer either input can get: P2's own
    // ghost target is BadTarget, and P1's foreign target is NotOwner.
    assert!(matches!(
        w.nullify(P2, &sib_doc(), &a(&[1, 0, 2, 0, 1, 0, 1, 9])),
        Err(TxnError::Rejected(NullifyError::BadTarget))
    ));
}

#[test]
fn nullify_from_a_second_home_deposits_a_distinct_retraction() {
    // The [R] dedup key carries d_retr in its canonical from-fill, so the
    // same target retracted from another home is a FRESH retraction tuple —
    // the exact opposite of assert_sup's home-excluded key, where a duplicate
    // (old, new) from another home dedups to the first claim.
    let k = kernel();
    let w = writer(&k);
    let (m1, _) = w
        .emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[])
        .expect("target");
    let (r1, _) = w.nullify(P1, &doc1(), &m1).expect("retract from doc1");
    let (r2, _) = w.nullify(P1, &doc2(), &m1).expect("retract from doc2");
    assert_ne!(r1, r2, "a second home's retraction is its own tuple");
    assert_eq!(r2, la2(1)); // doc2's own link chain
    let snap = k.snapshot();
    let links = snap.world().links();
    assert!(links.is_active(&r1) && links.is_active(&r2));
    assert!(links.is_nullified(&m1)); // one target, monotone
}

#[test]
fn nullifying_a_retraction_restores_nothing() {
    // The tombstone set is monotone (R3/R6a) and the fold re-derives it from
    // the [R] link at every replay, whether or not that link is itself
    // nullified. This is where the module's two suppression mechanisms part
    // company: retiring reads the ACTIVE retired slice and is undoable
    // (is_filtered_reads_the_active_retired_slice), nullifying is not.
    let k = kernel();
    let w = writer(&k);
    let (m1, _) = w
        .emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[])
        .expect("target");
    let (r1, _) = w.nullify(P1, &doc1(), &m1).expect("retract it");
    let (r2, _) = w
        .nullify(P1, &doc1(), &r1)
        .expect("retract the retraction — an ordinary resident, owned target");
    assert_ne!(r2, r1, "a distinct I0 class, so the retraction lands fresh");
    let snap = k.snapshot();
    let links = snap.world().links();
    assert!(links.is_nullified(&r1), "the retraction is itself retracted");
    assert!(
        links.is_nullified(&m1),
        "and its target stays nullified — the set is monotone"
    );
    assert!(!links.type_slice(&pred_def_ty(), View::Active).contains(&m1));
    // The replay half: the fold re-derives the tombstone from a nullified
    // [R] link, so recovery restores nothing either.
    let bytes = bincode::serialize(snap.world()).expect("world serializes");
    let recovered: World = bincode::deserialize(&bytes).expect("world deserializes");
    let recovered = skep_kernel::WorldState::rebuild_derived(recovered);
    assert!(recovered.links().is_nullified(&m1));
    assert!(recovered.links().is_nullified(&r1));
}

// ---- MAKELINK: the open surface ----

#[test]
fn makelink_resolves_deposits_and_seats() {
    let k = kernel();
    seed_content(&k, &doc1(), 3); // content elements ca(1)..ca(3)
    let w = writer(&k);

    let (l1, _) = w
        .makelink(
            P1,
            &doc1(),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 1, 1)]),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 2, 1)]),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 3, 1)]),
        )
        .expect("makelink");
    assert_eq!(l1, la(1));
    {
        let snap = k.snapshot();
        let links = snap.world().links();
        let link = links.readlink(&l1).expect("resident");
        // ML1 coverage-exactness: the recorded endsets are exactly the
        // resolved I-extents.
        assert_eq!(link.from_slot(), &Endset::from_spans([iext(1, 2)]));
        assert_eq!(link.to_slot(), &Endset::from_spans([iext(2, 3)]));
        assert_eq!(link.type_slot(), &Endset::from_spans([iext(3, 4)]));
        // Seated at home (K.μ⁺_L; J-LV: no provenance) — unlike Emit_K.
        assert_eq!(snap.world().m5().link_count(&doc1()), n(1));
        assert_eq!(
            snap.world().m5().link_runs(&doc1()).next().expect("a seated link run").i_start(),
            &l1
        );
        // FOLLOWLINK: coverage-exact slot read; arity bound; ⊥ for absence.
        assert_eq!(links.followlink(&l1, 3), Ok(SpanSet::singleton(iext(3, 4))));
        assert!(links.followlink(&l1, 4).is_err());
        assert!(links.followlink(&la(9), 1).is_err());
    }

    // ML0: distinct links always — no dedup on the open surface.
    let (l2, _) = w
        .makelink(
            P1,
            &doc1(),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 1, 1)]),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 2, 1)]),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 3, 1)]),
        )
        .expect("identical makelink deposits fresh");
    assert_ne!(l2, l1);

    // An empty from spec-set is a valid ⟨⟩ endset — and FOLLOWLINK's Ok-empty
    // keeps ⟨⟩ ≠ ⊥.
    let (l3, _) = w
        .makelink(
            P1,
            &doc1(),
            SlotArg::Resolve(vec![]),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 2, 1)]),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 3, 1)]),
        )
        .expect("empty from-set admitted");
    {
        let snap = k.snapshot();
        let got = snap.world().links().followlink(&l3, 1).expect("slot 1 exists");
        assert!(got.is_empty());
    }

    // ML6: a well-formed type spec resolving to nothing is a typed rejection.
    assert!(matches!(
        w.makelink(
            P1,
            &doc1(),
            SlotArg::Resolve(vec![]),
            SlotArg::Resolve(vec![]),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 9, 1)])
        ),
        Err(TxnError::Rejected(MakeLinkError::EmptyTypeResolution))
    ));
    // wf: link-subspace spec, deeper-than-2 spec, unregistered source.
    assert!(matches!(
        w.makelink(
            P1,
            &doc1(),
            SlotArg::Resolve(vec![spec(&doc1(), 2, 1, 1)]),
            SlotArg::Resolve(vec![]),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 3, 1)])
        ),
        Err(TxnError::Rejected(MakeLinkError::IllFormedSpec))
    ));
    let deep = skep_arrangement::VSpec {
        source: doc1(),
        span: skep_address::Span::new(t(&[1, 1, 1]), t(&[0, 0, 1])).expect("T12-valid"),
    };
    assert!(matches!(
        w.makelink(
            P1,
            &doc1(),
            SlotArg::Resolve(vec![deep]),
            SlotArg::Resolve(vec![]),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 3, 1)])
        ),
        Err(TxnError::Rejected(MakeLinkError::IllFormedSpec))
    ));
    assert!(matches!(
        w.makelink(
            P1,
            &doc1(),
            SlotArg::Resolve(vec![spec(&a(&[1, 0, 1, 0, 7]), 1, 1, 1)]),
            SlotArg::Resolve(vec![]),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 3, 1)])
        ),
        Err(TxnError::Rejected(MakeLinkError::IllFormedSpec))
    ));
    assert!(matches!(
        w.makelink(
            P1,
            &a(&[1, 0, 1, 0, 7]),
            SlotArg::Resolve(vec![]),
            SlotArg::Resolve(vec![]),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 3, 1)])
        ),
        Err(TxnError::Rejected(MakeLinkError::HomeNotRegistered))
    ));
}

/// The 2026-08-16 address-form amendment (L4/L8/L9/L13): an `Addrs` slot
/// deposits `enc(addrs)` — the NAMES verbatim, unresolved, no occupancy
/// requirement — so a ghost subspace-3 name can type a link, two links
/// naming the same address share a type class, and a link address is an
/// ordinary endset name. The type floor reads as-given: an empty `Addrs`
/// list rejects exactly as an empty resolution does.
#[test]
fn makelink_addrs_form_records_names_verbatim() {
    let k = kernel();
    seed_content(&k, &doc1(), 3);
    let w = writer(&k);

    // A NAME in doc1's never-occupied subspace 3 — a ghost (L9), T4-valid.
    let name = a(&[1, 0, 1, 0, 1, 0, 3, 6, 1]);
    let (l1, _) = w
        .makelink(
            P1,
            &doc1(),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 1, 1)]),
            SlotArg::Addrs(vec![]), // empty FROM/TO admitted in either form
            SlotArg::Addrs(vec![name.clone()]),
        )
        .expect("ghost-typed makelink admitted");
    {
        let snap = k.snapshot();
        let links = snap.world().links();
        let link = links.readlink(&l1).expect("resident");
        assert_eq!(link.type_slot(), &enc([&name]));
        assert_eq!(link.to_slot(), &Endset::empty());
    }

    // Mixed slots, link-to-link: TO names l1 itself; the deposit is the enc
    // of the link address (ReflexiveAddressing, L13).
    let (l2, _) = w
        .makelink(
            P1,
            &doc1(),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 2, 1)]),
            SlotArg::Addrs(vec![l1.clone()]),
            SlotArg::Addrs(vec![name.clone()]),
        )
        .expect("mixed-slot makelink admitted");
    {
        let snap = k.snapshot();
        let links = snap.world().links();
        assert_eq!(links.readlink(&l2).expect("resident").to_slot(), &enc([&l1]));
        // Shared-identity typing: both links sit in the name's type slice.
        let slice = links.type_slice(&enc([&name]), View::Active);
        assert!(slice.contains(&l1) && slice.contains(&l2));
    }

    // The as-given type floor: empty Addrs ty ⇒ EmptyTypeResolution.
    assert!(matches!(
        w.makelink(
            P1,
            &doc1(),
            SlotArg::Addrs(vec![]),
            SlotArg::Addrs(vec![]),
            SlotArg::Addrs(vec![])
        ),
        Err(TxnError::Rejected(MakeLinkError::EmptyTypeResolution))
    ));
}

#[test]
fn makelink_wf_admits_exactly_the_depth_2_ordinal_content_spec() {
    // wf is five conjuncts — a registered source, #start = 2, start₁ = s_C,
    // #width = 2, width₁ = 0 — and each row below violates exactly one.
    let k = kernel();
    seed_content(&k, &doc1(), 3);
    let w = writer(&k);
    let ty = || SlotArg::Resolve(vec![spec(&doc1(), 1, 3, 1)]);
    let raw = |start: &[u32], width: &[u32]| skep_arrangement::VSpec {
        source: doc1(),
        span: skep_address::Span::new(t(start), t(width)).expect("T12-valid"),
    };
    let rows = vec![
        ("conforming", spec(&doc1(), 1, 1, 1), true),
        (
            "unregistered source",
            spec(&a(&[1, 0, 1, 0, 7]), 1, 1, 1),
            false,
        ),
        ("#start ≠ 2", raw(&[1, 1, 1], &[0, 0, 1]), false),
        ("start₁ ≠ s_C", spec(&doc1(), 2, 1, 1), false),
        ("#width ≠ 2", raw(&[1, 1], &[0, 1, 0]), false),
        ("width₁ ≠ 0 (not an ordinal displacement)", raw(&[1, 1], &[1, 1]), false),
    ];
    for (label, from, wf) in rows {
        let got = w.makelink(
            P1,
            &doc1(),
            SlotArg::Resolve(vec![from]),
            SlotArg::Resolve(vec![]),
            ty(),
        );
        match (&got, wf) {
            (Ok(_), true) => {}
            (Err(TxnError::Rejected(MakeLinkError::IllFormedSpec)), false) => {}
            _ => panic!(
                "{label}: expected {}, got {got:?}",
                if wf { "admission" } else { "IllFormedSpec" }
            ),
        }
    }
}

#[test]
fn makelink_wf_checks_every_slot_s_specs_not_only_the_from_slot() {
    // wf runs over from ⌢ to ⌢ ty, and the TYPE slot is where its absence is
    // least visible: an unchecked ill-formed spec resolves to nothing and
    // comes back as EmptyTypeResolution — a truthful-looking answer to a
    // different question.
    let k = kernel();
    seed_content(&k, &doc1(), 3);
    let w = writer(&k);
    let bad = || spec(&a(&[1, 0, 1, 0, 7]), 1, 1, 1); // unregistered source
    assert!(matches!(
        w.makelink(
            P1,
            &doc1(),
            SlotArg::Resolve(vec![]),
            SlotArg::Resolve(vec![bad()]),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 3, 1)])
        ),
        Err(TxnError::Rejected(MakeLinkError::IllFormedSpec))
    ));
    assert!(matches!(
        w.makelink(
            P1,
            &doc1(),
            SlotArg::Resolve(vec![]),
            SlotArg::Resolve(vec![]),
            SlotArg::Resolve(vec![bad()])
        ),
        Err(TxnError::Rejected(MakeLinkError::IllFormedSpec))
    ));
}

#[test]
fn a_resolve_slot_concatenates_every_spec_in_argument_order() {
    // A `Resolve` slot flat-maps ITS specs to I-extents: every spec, in
    // argument order, un-coalesced. Every other Resolve slot in the suite
    // carries zero specs or one, where a slot that took only the first would
    // agree.
    let k = kernel();
    seed_content(&k, &doc1(), 3);
    let w = writer(&k);
    let (l, _) = w
        .makelink(
            P1,
            &doc1(),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 3, 1), spec(&doc1(), 1, 1, 1)]),
            SlotArg::Addrs(vec![]),
            SlotArg::Addrs(vec![unregistered_ta(10)]),
        )
        .expect("makelink");
    let snap = k.snapshot();
    let links = snap.world().links();
    assert_eq!(
        links.readlink(&l).expect("resident").from_slot(),
        &Endset::from_spans([iext(3, 4), iext(1, 2)]),
        "argument order, un-coalesced"
    );
}

#[test]
fn a_resolve_spec_expands_to_one_span_per_fragment() {
    // The ratio the span budget bounds on this arm: ONE ~80-byte spec stores
    // one span per I-run of the SOURCE document, so the slot's size is that
    // document's fragmentation rather than the request's. The `Addrs` form's
    // COUNT has no such ratio — one span per name the caller wrote — which is
    // why the two forms amplify differently and are held to one budget.
    let k = kernel();
    fragment_content(&k, &doc1(), 4);
    let w = writer(&k);
    let (fragmented, _) = w
        .makelink(
            P1,
            &doc1(),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 1, 4)]),
            SlotArg::Addrs(vec![]),
            SlotArg::Addrs(vec![unregistered_ta(10)]),
        )
        .expect("makelink");
    {
        let snap = k.snapshot();
        let links = snap.world().links();
        let from = links.readlink(&fragmented).expect("resident").from_slot();
        assert_eq!(from.len(), 4, "one 4-position spec, four stored spans");
        // Width-1 I-extents descending through I-space, which is what keeps
        // them un-coalesced and the expansion real.
        let starts: Vec<_> = from.spans().map(|s| s.start().clone()).collect();
        let want: Vec<_> = [ca(4), ca(3), ca(2), ca(1)]
            .iter()
            .map(|a| a.tumbler().clone())
            .collect();
        assert_eq!(starts, want);
    }
    // The control: the same coverage, contiguously allocated, costs ONE span
    // — so the count is the source's shape and not the query's width.
    seed_content(&k, &doc2(), 4);
    let (contiguous, _) = w
        .makelink(
            P1,
            &doc2(),
            SlotArg::Resolve(vec![spec(&doc2(), 1, 1, 4)]),
            SlotArg::Addrs(vec![]),
            SlotArg::Addrs(vec![unregistered_ta(10)]),
        )
        .expect("makelink");
    let snap = k.snapshot();
    let links = snap.world().links();
    assert_eq!(
        links.readlink(&contiguous).expect("resident").from_slot().len(),
        1
    );
}

#[test]
fn slot_args_compare_by_form_and_by_the_list_they_carry() {
    // The equality a caller comparing two requests wants: the same slot, asked
    // for in the same form, naming the same things in the same order. M10
    // stores this type in `Op::MakeLink`, so this is what stands between a
    // codec round trip and a value comparison at that seam.
    assert_eq!(SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![ca(1)]));
    assert_ne!(SlotArg::Addrs(vec![ca(1)]), SlotArg::Addrs(vec![ca(2)]));
    assert_eq!(
        SlotArg::Resolve(vec![spec(&doc1(), 1, 1, 1)]),
        SlotArg::Resolve(vec![spec(&doc1(), 1, 1, 1)])
    );
    // The FORM is part of the value: two empty slots of different forms are
    // not the same argument, even though both build ⟨⟩.
    assert_ne!(SlotArg::Addrs(vec![]), SlotArg::Resolve(vec![]));
    // ...and order is too — it is the order a `Resolve` slot concatenates in
    // and the order an `Addrs` slot deposits verbatim.
    assert_ne!(
        SlotArg::Addrs(vec![ca(1), ca(2)]),
        SlotArg::Addrs(vec![ca(2), ca(1)])
    );
}

// ---- the ownership gate (as amended 2026-08-16) ----

#[test]
fn deposit_ops_reject_a_foreign_home_and_commit_nothing() {
    // The probe matrix, link side: principal 2 (account [1,0,2]) deposits
    // into P1's doc1 — make_link / emit / assert_sup / editlink (d_s and
    // d_a) all reject NotOwner carrying the home that failed; nothing
    // commits; System (the M9 automation path) is exempt by architecture.
    let k = kernel();
    seed_content(&k, &doc1(), 3);
    let w = writer(&k);
    let (x, _) = w.emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[]).expect("x");
    let (y, _) = w.emit(P1, &doc1(), &pred_def_ty(), &ca(2), &[]).expect("y");
    let before = k.current_seq();
    assert!(matches!(
        w.makelink(
            P2,
            &doc1(),
            SlotArg::Resolve(vec![]),
            SlotArg::Resolve(vec![]),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 1, 1)])
        ),
        Err(TxnError::Rejected(MakeLinkError::NotOwner(d))) if d == doc1()
    ));
    assert!(matches!(
        w.emit(P2, &doc1(), &pred_def_ty(), &ca(9), &[]),
        Err(TxnError::Rejected(EmitError::NotOwner(d))) if d == doc1()
    ));
    assert!(matches!(
        w.assert_sup(P2, &doc1(), &x, &y),
        Err(TxnError::Rejected(AssertSupError::NotOwner(d))) if d == doc1()
    ));
    let successor_value =
        Link::new([enc(&[ca(3)]), enc(&[ca(4)]), unregistered_ty(30)]).expect("arity 3");
    // Foreign d_s (successor home): the error names d_s.
    assert!(matches!(
        w.editlink(P2, &x, successor_value.clone(), &doc1(), &sib_doc()),
        Err(TxnError::Rejected(EditLinkError::NotOwner(d))) if d == doc1()
    ));
    // Foreign d_a (claim home): the error names d_a.
    assert!(matches!(
        w.editlink(P2, &x, successor_value.clone(), &sib_doc(), &doc1()),
        Err(TxnError::Rejected(EditLinkError::NotOwner(d))) if d == doc1()
    ));
    // Across an op's several homes, EVERY registration is asked before ANY
    // ownership: an unregistered second home outranks an unowned first, so
    // the verdict does not depend on which home is named first.
    assert!(matches!(
        w.editlink(P1, &x, successor_value, &sib_doc(), &a(&[1, 0, 1, 0, 7])),
        Err(TxnError::Rejected(EditLinkError::HomeNotRegistered))
    ));
    assert_eq!(k.current_seq(), before, "ownership rejections leave no state change");
    // System bypasses the gate (M9 ⟂ M10 — rule fires carry no principal).
    w.emit(Caller::System, &doc1(), &pred_def_ty(), &ca(9), &[])
        .expect("the automation path deposits ungated");
}

#[test]
fn ownership_gate_holds_on_the_idem_hit_path() {
    // Like the hoisted home check, ω is enforced on hit AND miss: a foreign
    // emit whose tuple already exists still rejects NotOwner — the caller
    // cannot observe the dedup branch through the rejection.
    let k = kernel();
    let w = writer(&k);
    w.emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[]).expect("incumbent");
    assert!(matches!(
        w.emit(P2, &doc1(), &pred_def_ty(), &ca(1), &[]),
        Err(TxnError::Rejected(EmitError::NotOwner(_)))
    ));
}

#[test]
fn nullify_requires_owning_home_and_target_and_still_filters_the_active_view() {
    // v1 target policy: self-retraction only. Principal 2, from its OWN
    // home, cannot retract P1's link — the rejection names the TARGET; the
    // owner's retraction still lands and filters the active view while the
    // audit view retains everything.
    let k = kernel();
    let w = writer(&k);
    let (m1, _) = w.emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[]).expect("P1's tuple");
    // Foreign target, owned home: NotOwner carrying the target link.
    assert!(matches!(
        w.nullify(P2, &sib_doc(), &m1),
        Err(TxnError::Rejected(NullifyError::NotOwner(d))) if d == m1
    ));
    // Foreign home is rejected first, naming the home.
    assert!(matches!(
        w.nullify(P2, &doc1(), &m1),
        Err(TxnError::Rejected(NullifyError::NotOwner(d))) if d == doc1()
    ));
    {
        let snap = k.snapshot();
        assert!(snap.world().links().is_active(&m1), "no foreign retraction landed");
    }
    // The owner's own retraction: active view filtered, audit retains.
    w.nullify(P1, &doc1(), &m1).expect("owner retraction");
    let snap = k.snapshot();
    let links = snap.world().links();
    assert!(links.is_nullified(&m1));
    assert!(links.readlink(&m1).is_some());
    assert!(links.type_slice(&pred_def_ty(), View::Audit).contains(&m1));
    assert!(!links.type_slice(&pred_def_ty(), View::Active).contains(&m1));
}

#[test]
fn assert_sup_and_editlink_claim_over_links_the_caller_does_not_own() {
    // ω is required on the home(s) named and on NOTHING ELSE — a deliberate
    // permissiveness, framed by the deferred moderation question `nullify`
    // names, and the one ownership rule with no refusal to witness it. So the
    // capability is stated here, positively: without a test, the next
    // hardening pass deletes it and the suite stays green.
    let k = kernel();
    let w = writer(&k);
    let sup = supersedes_ty();
    let (x, _) = w.emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[]).expect("x");
    let (y, _) = w.emit(P1, &doc1(), &pred_def_ty(), &ca(2), &[]).expect("y");

    // P2, from a home P2 owns, claims that one of P1's links supersedes
    // another — and the walk family reports it as fact.
    let (c, _) = w
        .assert_sup(P2, &sib_doc(), &x, &y)
        .expect("ω on home only: the endpoints need not be the caller's");
    {
        let snap = k.snapshot();
        let links = snap.world().links();
        assert!(links.is_active(&c));
        assert_eq!(links.succs(&sup, &x), vec![y.clone()]);
    }
    // The endpoints' owner cannot retract it: ω on the CLAIM is the
    // asserter's, the claim's home being d_a.
    assert!(matches!(
        w.nullify(P1, &doc1(), &c),
        Err(TxnError::Rejected(NullifyError::NotOwner(d))) if d == c
    ));

    // editlink the same way: P2 edits P1's link, depositing into its own
    // homes. What it asserts about `original` needs no ω on `original`.
    let successor_value =
        Link::new([enc(&[ca(3)]), enc(&[ca(4)]), unregistered_ty(30)]).expect("arity 3");
    let (Edit { successor: s, claim }, _) = w
        .editlink(P2, &x, successor_value, &sib_doc(), &sib_doc())
        .expect("ω on d_s and d_a only");
    let snap = k.snapshot();
    let links = snap.world().links();
    assert!(links.is_active(&s) && links.is_active(&claim));
    let succs = links.succs(&sup, &x);
    assert!(succs.contains(&s), "the edit's claim entered the adjacency");
    assert!(succs.contains(&y), "and the earlier foreign claim stands");
}

// ---- the sole-writer fences, on the open surface ----

#[test]
fn makelink_cannot_forge_a_retraction_of_a_foreign_link() {
    // The hint fold recognizes a deposit by its type slot's CLASS, so the
    // K ≁ R fence has to hold on every surface that deposits, not only on
    // the one whose gate states it. Without it, a principal owning any one
    // document names the shipped `[R]` address in an `Addrs` type slot and
    // tombstones every link its TO slot denotes — with no ownership check on
    // any of them, and irreversibly, the tombstone set being monotone and
    // re-derived at every replay.
    let k = kernel();
    let w = writer(&k);
    let (victim, _) = w
        .emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[])
        .expect("P1's own tuple");
    let before = k.current_seq();
    assert!(matches!(
        w.makelink(
            P2,
            &sib_doc(), // a home P2 does own — the ω gate is satisfied
            SlotArg::Addrs(vec![sib_doc()]),
            SlotArg::Addrs(vec![victim.clone()]),
            SlotArg::Addrs(vec![reserved().retraction]),
        ),
        Err(TxnError::Rejected(MakeLinkError::RetractionClass))
    ));
    assert_eq!(k.current_seq(), before, "the refusal is pre-deposit");
    let snap = k.snapshot();
    let links = snap.world().links();
    assert!(links.is_active(&victim));
    assert!(!links.is_nullified(&victim));
    assert!(links.type_slice(&pred_def_ty(), View::Active).contains(&victim));
    // The owner's own retraction is the one path that reaches the tombstone.
    w.nullify(P1, &doc1(), &victim).expect("owner retraction");
    assert!(k.snapshot().world().links().is_nullified(&victim));
}

#[test]
fn makelink_cannot_forge_a_supersession_claim() {
    // The `[K_sup]` fence, the exact parallel. assert_sup and editlink both
    // establish the Df-DISC(ii) schema — resident endpoints, single denoted
    // addresses, irreflexivity — before a claim enters the adjacency the
    // walk family reads back as fact; the open surface establishes none of
    // it, and its slots are lists, so one deposit would fold |F|×|G| edges.
    let k = kernel();
    let w = writer(&k);
    let before = k.current_seq();
    assert!(matches!(
        w.makelink(
            P1,
            &doc1(),
            SlotArg::Addrs(vec![la(90), la(91)]), // ghosts: neither is resident
            SlotArg::Addrs(vec![la(92), la(93)]),
            SlotArg::Addrs(vec![reserved().supersedes]),
        ),
        Err(TxnError::Rejected(MakeLinkError::SupersessionClass))
    ));
    assert_eq!(k.current_seq(), before, "the refusal is pre-deposit");
    let snap = k.snapshot();
    let links = snap.world().links();
    let sup = supersedes_ty();
    assert!(links.succs(&sup, &la(90)).is_empty());
    // The ghost is its own sink with nothing claiming it: no forged edge
    // entered the adjacency, and no forged claim entered the disclosure.
    let cur = links.current(&la(90));
    assert_eq!(cur.len(), 1);
    assert_eq!(cur[0].member, la(90));
    assert!(cur[0].claims.is_empty());
    // A self-superseding claim over one ghost is refused by the same fence,
    // so irreflexivity is not reachable around it either.
    assert!(matches!(
        w.makelink(
            P1,
            &doc1(),
            SlotArg::Addrs(vec![la(90)]),
            SlotArg::Addrs(vec![la(90)]),
            SlotArg::Addrs(vec![reserved().supersedes]),
        ),
        Err(TxnError::Rejected(MakeLinkError::SupersessionClass))
    ));
}

#[test]
fn makelink_still_admits_every_class_the_fences_do_not_name() {
    // The control for the two fences above: they name two classes, not the
    // registry. A shipped class with no sole writer (Retired), a second
    // shipped class, and a class outside the registry all deposit through the
    // open surface as before.
    let k = kernel();
    let w = writer(&k);
    for ty in [reserved().retired, reserved().pred_def, unregistered_ta(10)] {
        w.makelink(
            P1,
            &doc1(),
            SlotArg::Addrs(vec![ca(1)]),
            SlotArg::Addrs(vec![ca(2)]),
            SlotArg::Addrs(vec![ty.clone()]),
        )
        .unwrap_or_else(|e| panic!("open surface admits {ty:?}: {e:?}"));
    }
}

// ---- the per-slot span budget, at every site that carries it ----

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

// ---- the rejection family, and recovery of the hints the writes maintain ----

#[test]
fn the_wrapped_rejections_chain_through_source_and_display() {
    // Every rejection promises `Display` + `Error`, and `source()` where a
    // cause exists — a promise nothing exercises, in a family where exactly
    // this went wrong once (a cause rendered through `Debug` and missing
    // from the chain). `RetractStaleError::Nullify` is the one wrapping a
    // caller can construct through M7's public surface.
    use std::error::Error;
    let inner = NullifyError::BadTarget;
    let outer: RetractStaleError = inner.clone().into();
    assert!(
        outer.to_string().contains(&inner.to_string()),
        "the wrapper renders its cause through Display, never Debug"
    );
    assert!(
        Error::source(&outer).is_some(),
        "and a chain walker reaches it"
    );
    assert!(
        Error::source(&inner).is_none(),
        "a leaf rejection carries no cause"
    );
    // The two unit markers are errors in their own right, so a caller can
    // box either without losing its sentence.
    assert!(!Invalid.to_string().is_empty());
    assert!(!NotBh4.to_string().is_empty());
    assert!(Error::source(&Invalid).is_none());
}

#[test]
fn checkpoint_roundtrip_then_rebuild_derived_restores_every_hint() {
    let k = kernel();
    let w = writer(&k);
    let sup = supersedes_ty();
    let (a1, _) = w.emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[]).expect("idem⊤");
    let (m1, _) = w.emit(P1, &doc1(), &pred_stable_ty(), &ca(3), &[]).expect("m1");
    let (m2, _) = w.emit(P1, &doc1(), &pred_stable_ty(), &ca(4), &[]).expect("m2");
    let (_unregistered, _) = w
        .makelink(
            P1,
            &doc1(),
            SlotArg::Addrs(vec![ca(5)]),
            SlotArg::Addrs(vec![ca(6)]),
            SlotArg::Addrs(vec![unregistered_ta(11)]),
        )
        .expect("an unregistered-class deposit, so its slice is rebuilt too");
    let (c, _) = w.assert_sup(P1, &doc1(), &m1, &m2).expect("claim");
    w.nullify(P1, &doc1(), &m1).expect("nullify m1");

    // The checkpoint wire format: serialize the world, deserialize (skip
    // fields default), rebuild_derived BEFORE any read/replay.
    let snap = k.snapshot();
    let bytes = bincode::serialize(snap.world()).expect("world serializes");
    let recovered: World = bincode::deserialize(&bytes).expect("world deserializes");
    let recovered = skep_kernel::WorldState::rebuild_derived(recovered);

    let live = snap.world().links();
    let back = recovered.links();
    for addr in [&a1, &m1, &m2, &c] {
        assert_eq!(live.readlink(addr), back.readlink(addr));
    }
    assert!(back.is_nullified(&m1));
    assert_eq!(back.succs(&sup, &m1), vec![m2.clone()]); // sup_fwd rebuilt
    assert_eq!(
        live.type_slice(&pred_def_ty(), View::Audit),
        back.type_slice(&pred_def_ty(), View::Audit)
    );
    assert_eq!(
        live.type_slice(&unregistered_ty(11), View::Active),
        back.type_slice(&unregistered_ty(11), View::Active)
    );
    assert!(!back.type_slice(&unregistered_ty(11), View::Active).is_empty());
    // The home-frontier hint, which age/stale and nullify's `a_emit`
    // prediction all stand on — and a live value, so the pair is not two
    // zeros agreeing.
    assert_ne!(live.age(&a1), Some(0));
    assert_eq!(live.age(&a1), back.age(&a1), "the home frontier is rebuilt");

    // The dedup hint is rebuilt too: a kernel opened over the recovered world
    // dedups the same idem⊤ emission to the ORIGINAL incumbent.
    let cfg = skep_kernel::KernelConfig {
        durability: skep_kernel::Durability::InMemory,
        checkpoint: skep_kernel::CheckpointPolicy::Manual,
    };
    let k2 = skep_kernel::Kernel::open(cfg, recovered).expect("reopen");
    let w2 = writer(&k2);
    let (again, _) = w2.emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[]).expect("dedup hit");
    assert_eq!(again, a1);
}
