//! Emit_K over a real kernel (InMemory): the managed gate and its
//! precedences — the reachable shape cells, the pre-transact fences in their
//! firing order, and the hoisted home check on hit AND miss.
//!
//! The registry's population is the compiled shipped five (owner ruling,
//! 2026-08-26 — the app-decl seam is deleted): the managed surface's
//! reachable registered classes are the three Unary idem⊤ ones
//! (`PredDef`/`PredStable`/`Retired`; `Supersedes` and `Retraction` are
//! sole-writer-fenced), so emit-mechanics tests run over those, and
//! Binary/Multi tuples enter through the open surface.

use crate::common;

use common::*;
use skep_address::Address;
use skep_arrangement::HasM5;
use skep_kernel::TxnError;
use skep_links::{emit_tuple, enc, EmitError, Endset, HasLinks, Pattern, RetractStaleError, View};

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
    // ...which is the tuple the published builder makes — the one the daemon's
    // entry-frame composer signs over.
    assert_eq!(
        *link,
        emit_tuple(&pred_def_ty(), &ca(1), &[]).expect("within budget")
    );
    // Emit_K does NOT seat (MAKELINK alone seats).
    assert_eq!(snap.world().m5().link_count(&doc1()), n(0));
    // Observe: the empty pattern is no constraint; exact ⊆-coverage match.
    let tuples = links.observe(&pred_def_ty(), Pattern::default(), View::Active);
    assert_eq!(tuples.len(), 1);
    assert_eq!(tuples[0].addr, a1);
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
    let before = k.current_seq();
    assert!(matches!(
        w.emit(P1, &doc1(), &skew(), &ca(1), &[]),
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
