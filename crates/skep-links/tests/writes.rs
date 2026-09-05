//! Op-level contracts over a real kernel (InMemory): the two write
//! disciplines and their gates (the reachable shape cells, the pre-transact
//! fences, the hoisted home/ω checks on hit AND miss and ahead of an op's
//! own declared-first verdict), the `[R]` and `[K_sup]` sole-writer fences on
//! BOTH surfaces, idempotent dedup + resurrection and the T1-least ACTIVE
//! incumbent a hit returns, retraction, its irreversibility, its target
//! precedence and the active view, supersession + the BH2 walk at each of
//! its three halts and the endpoint retraction that leaves an edge operative,
//! editlink's atomic composite, its two distinct homes and its DC guard
//! clause by clause, the ω-on-the-home-and-nothing-else capability
//! `assert_sup` and `editlink` publish, MAKELINK end-to-end (wf over every
//! slot's specs, multi-spec resolution, deposit, seat), EL14 currency
//! disclosure and the denotation regime its claim relation reads, Observe
//! over a whole slice with its AND-of-probes pattern sides and its view
//! selection, BH1's filter and the class-keyed reads over registered and
//! unregistered classes alike, the enumeration reads at the cardinality
//! their loops need, the §G discovery primitives with their
//! `Default → Active` coercion, their empty-query floor and their
//! absent-slot rule, the AND-combiner's agreement with its own conjuncts,
//! the verbatim order FOLLOWLINK folds, the ratio a `Resolve` slot amplifies
//! by and the per-slot span budget at its exact boundary on every op and
//! slot form that carries one, editlink's canonical two-home lock order,
//! BH1's whole multi-root filter domain, the rejection family's
//! `Display`/`source` chaining, and the checkpoint-roundtrip +
//! rebuild_derived discipline.
//!
//! The registry's population is the compiled shipped five (owner ruling,
//! 2026-08-26 — the app-decl seam is deleted): the managed surface's
//! reachable registered classes are the three Unary idem⊤ ones
//! (`PredDef`/`PredStable`/`Retired`; `Supersedes` and `Retraction` are
//! sole-writer-fenced), so emit-mechanics tests run over those, Binary/Multi
//! tuples enter through the open surface, arbitrary type NUMBERS are
//! unregistered classes the class-keyed reads answer for verbatim, and the
//! BH3 join and BH4 staleness gates — which no shipped class declares —
//! refuse or answer empty for every input, which is pinned below where their
//! served paths were once exercised.

mod common;

use common::*;
use skep_address::{Address, SpanSet};
use skep_arrangement::HasM5;
use skep_kernel::TxnError;
use skep_links::{
    enc, AssertSupError, Caller, Edit, EditLinkError, EmitError, Endset, HasLinks, Invalid, Link,
    LinkWriter, MakeLinkError, NotBh4, NullifyError, Pattern, RetractStaleError, SlotArg, Tip,
    Tuple, View, FROM, TO, TYPE,
};

fn writer(k: &skep_kernel::Kernel<World>) -> LinkWriter<'_, World> {
    LinkWriter::new(k)
}

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
fn the_class_keyed_reads_serve_an_unregistered_type_verbatim() {
    // A type is a number (owner ruling, 2026-08-26): the open surface
    // deposits any type name verbatim, the fold indexes a type slice for
    // EVERY coverage class, and observe/is_k/members/targets_of and the BH3
    // endpoint pair answer by CLASS with no registration consulted — what an
    // unregistered type means is its interpreting client's business, and
    // these reads are that client's surface. The two pattern sides stay
    // distinct, which no Unary emission can show.
    let k = kernel();
    let w = writer(&k);
    let rel = unregistered_ty(1);
    let (l1, _) = w
        .makelink(
            P1,
            &doc1(),
            SlotArg::Addrs(vec![ca(1)]),
            SlotArg::Addrs(vec![ca(2)]),
            SlotArg::Addrs(vec![unregistered_ta(1)]),
        )
        .expect("the open surface admits an unregistered type");
    let snap = k.snapshot();
    let links = snap.world().links();
    let one = links.observe(&rel, Pattern::default(), View::Active);
    assert_eq!(one.len(), 1);
    assert_eq!(one[0].addr, l1);
    assert_eq!(
        links
            .observe(
                &rel,
                Pattern {
                    from: &[ca(1).tumbler().clone()],
                    to: &[ca(2).tumbler().clone()],
                },
                View::Active
            )
            .len(),
        1
    );
    // The two sides are not interchangeable: ca(1) — which this tuple's F
    // covers — finds nothing as a G-probe.
    assert!(links
        .observe(
            &rel,
            Pattern {
                from: &[],
                to: &[ca(1).tumbler().clone()],
            },
            View::Active
        )
        .is_empty());
    assert!(links.is_k(&rel, ca(1).tumbler()));
    assert_eq!(links.members(&rel, View::Active), vec![ca(1)]);
    assert_eq!(links.targets_of(&rel, &ca(1), View::Active), vec![ca(2)]);
    // The BH3 endpoint pair answers for any class — only the keyed JOIN
    // reads declarations back.
    assert_eq!(links.sources_to(&rel, &ca(2)), vec![ca(1)]);
    assert_eq!(links.target_of(&rel, &ca(1)), Some(ca(2)));
}

#[test]
fn emit_names_a_distinct_rejection_for_each_gate_it_fails() {
    let k = kernel();
    let w = writer(&k);
    let sup = supersedes_ty();
    let retraction = retraction_ty();

    // Pre-transact: non-address-denoting ty (before any class computation).
    let wide = skep_address::Span::from_endpoints(ca(1).tumbler().clone(), ca(3).tumbler())
        .expect("well-formed span");
    let content_extent = Endset::from_spans([wide]);
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
    let wide = skep_address::Span::from_endpoints(ca(1).tumbler().clone(), ca(3).tumbler())
        .expect("well-formed span");
    assert!(matches!(
        w.emit(P2, &ghost_home, &Endset::from_spans([wide]), &ca(1), &[ca(2)]),
        Err(TxnError::Rejected(EmitError::NonAddressDenotingType))
    ));
    assert!(matches!(
        w.emit(P2, &ghost_home, &sup, &ca(1), &[ca(2)]),
        Err(TxnError::Rejected(EmitError::SupersessionClass))
    ));
    assert!(matches!(
        w.retract_stale(P2, &ghost_home, &unregistered_ty(2), 0),
        Err(TxnError::Rejected(RetractStaleError::NotBh4))
    ));
}

#[test]
fn view_defaults_to_the_default_view() {
    // The std name means the variant the module calls the default view, not
    // `Audit` — which is merely the one declaration order puts first, and is
    // what a derive would have picked.
    assert_eq!(View::default(), View::Default);
}

#[test]
fn observe_coerces_default_to_active_and_never_filters() {
    // Raw Observe is an index probe, so BH1's result-side rewrite is
    // undefined for it: Default reads as Active even when every match's F is
    // retired — which members(), on the same store, subtracts.
    let k = kernel();
    let w = writer(&k);
    let retired = retired_ty();
    let rel = unregistered_ty(1);
    w.makelink(
        P1,
        &doc1(),
        SlotArg::Addrs(vec![ca(1)]),
        SlotArg::Addrs(vec![ca(2)]),
        SlotArg::Addrs(vec![unregistered_ta(1)]),
    )
    .expect("relation");
    w.emit(P1, &doc1(), &retired, &ca(1), &[])
        .expect("retire ca1");
    let snap = k.snapshot();
    let links = snap.world().links();
    assert!(links.is_filtered(ca(1).tumbler()));
    assert!(links.members(&rel, View::Default).is_empty());
    assert_eq!(
        links.observe(&rel, Pattern::default(), View::Default),
        links.observe(&rel, Pattern::default(), View::Active)
    );
    assert_eq!(links.observe(&rel, Pattern::default(), View::Default).len(), 1);
}

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
    let open = || {
        w.makelink(
            P1,
            &doc1(),
            SlotArg::Addrs(vec![ca(1)]),
            SlotArg::Addrs(vec![ca(2)]),
            SlotArg::Addrs(vec![unregistered_ta(1)]),
        )
        .expect("open deposit")
        .0
    };
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
fn editlink_commits_successor_and_claim_together_and_guards_the_successor_type() {
    let k = kernel();
    let w = writer(&k);
    let sup = supersedes_ty();
    let retraction = retraction_ty();
    let (orig, _) = w.emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[]).expect("orig");

    // One atomic composite: fresh successor + claim; original untouched.
    let succ_value = Link::new([enc(&[ca(3)]), enc(&[ca(4)]), unregistered_ty(30)]).expect("arity 3");
    let (Edit { successor: s1, claim: c1 }, _) = w
        .editlink(P1, &orig, succ_value.clone(), &doc1(), &doc1())
        .expect("editlink");
    {
        let snap = k.snapshot();
        let links = snap.world().links();
        assert_eq!(links.readlink(&s1), Some(&succ_value)); // supplied value verbatim
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
    let succ2 = Link::new([enc(&[ca(5)]), enc(&[ca(6)]), unregistered_ty(31)]).expect("arity 3");
    let (Edit { successor: s2, claim: c2 }, _) =
        w.editlink(P1, &orig, succ2, &doc1(), &doc1()).expect("fork");
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
    let ok_succ = Link::new([enc(&[ca(3)]), enc(&[ca(4)]), unregistered_ty(32)]).expect("arity 3");
    assert!(matches!(
        w.editlink(P1, &la(90), ok_succ.clone(), &doc1(), &doc1()),
        Err(TxnError::Rejected(EditLinkError::OriginalNotResident))
    ));
    assert!(matches!(
        w.editlink(P1, &orig, ok_succ.clone(), &a(&[1, 0, 1, 0, 7]), &doc1()),
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
    let successor =
        Link::new([enc(&[ca(3)]), enc(&[ca(4)]), Endset::from_spans([skew])]).expect("arity 3");
    assert!(matches!(
        w.editlink(P1, &orig, successor, &doc1(), &doc1()),
        Err(TxnError::Rejected(EditLinkError::IllFormedSuccessor))
    ));
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
    let succ_value = Link::new([enc(&[ca(3)]), enc(&[ca(4)]), unregistered_ty(30)]).expect("arity 3");
    let (Edit { successor: s1, claim: c1 }, _) = w
        .editlink(P1, &orig, succ_value, &doc1(), &doc1())
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
    let succ_value = Link::new([enc(&[ca(3)]), enc(&[ca(4)]), unregistered_ty(30)]).expect("arity 3");
    let (Edit { successor: s1, claim: c1 }, _) = w
        .editlink(P1, &orig, succ_value, &doc1(), &doc1())
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

#[test]
fn targets_keyed_joins_only_the_reverse_lookup_classes() {
    // The join covers registered Binary classes DECLARING ReverseLookup — a
    // fact about registrations, so the registry names them. The shipped
    // Retraction class is Binary too, and a retraction tuple denotes its own
    // home in F, so a join that read shape alone would reach it here.
    let k = kernel();
    let w = writer(&k);
    let (m1, _) = w
        .emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[])
        .expect("m1");
    w.nullify(P1, &doc1(), &m1).expect("retract it from doc1");
    let snap = k.snapshot();
    let links = snap.world().links();
    // The control: that class DOES answer target_of for doc1, so its absence
    // from the join is the behavior scope and not an empty class.
    let retraction = retraction_ty();
    assert_eq!(links.target_of(&retraction, &doc1()), Some(m1));
    assert!(links.targets_keyed(&doc1()).is_empty());
}

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
        let iext = |lo: u32, hi: u32| {
            skep_address::Span::from_endpoints(ca(lo).tumbler().clone(), ca(hi).tumbler())
                .expect("well-formed")
        };
        assert_eq!(link.from_slot(), &Endset::from_spans([iext(1, 2)]));
        assert_eq!(link.to_slot(), &Endset::from_spans([iext(2, 3)]));
        assert_eq!(link.type_slot(), &Endset::from_spans([iext(3, 4)]));
        // Seated at home (K.μ⁺_L; J-LV: no provenance) — unlike Emit_K.
        assert_eq!(snap.world().m5().link_count(&doc1()), n(1));
        assert_eq!(snap.world().m5().link_runs(&doc1())[0].i_start(), &l1);
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
    let (e, _) = w
        .emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[])
        .expect("emit into the same class");
    assert_ne!(e, l, "a distinct I0 class, so the emit deposits fresh");
    let snap = k.snapshot();
    let links = snap.world().links();
    assert!(links.is_active(&l) && links.is_active(&e));
    let slice = links.type_slice(&pred_def_ty(), View::Active);
    assert!(slice.contains(&l) && slice.contains(&e));
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
    // gate forces one.
    let (l, _) = w
        .makelink(
            P1,
            &doc1(),
            SlotArg::Addrs(vec![ca(1), ca(1)]),
            SlotArg::Addrs(vec![]),
            SlotArg::Addrs(vec![ra(1)]), // pred_def — registered Unary, idem⊤
        )
        .expect("the open surface has no shape gate");
    let before = k.current_seq();
    let (e, seq) = w
        .emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[])
        .expect("the emit's own value is Unary-conformant");
    assert_eq!(e, l, "the MAKELINK deposit IS the incumbent this emit hits");
    assert_eq!(seq, before, "zero-step: nothing committed");
    assert_eq!(k.current_seq(), before);
    let snap = k.snapshot();
    let incumbent = snap.world().links().readlink(&e).expect("resident");
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
    assert_ne!(fresh, e);
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
    let deposit = || {
        w.makelink(
            P1,
            &doc1(),
            SlotArg::Addrs(vec![ca(1)]),
            SlotArg::Addrs(vec![]),
            SlotArg::Addrs(vec![ra(1)]), // pred_def — registered Unary, idem⊤
        )
        .expect("the open surface runs no dedup check")
        .0
    };
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
fn stab_and_match_links_match_overlap_but_never_adjacency() {
    let k = kernel();
    seed_content(&k, &doc1(), 3);
    let w = writer(&k);
    // from covers [ca1, ca3); to and ty cover [ca3, ca4).
    let (l, _) = w
        .makelink(
            P1,
            &doc1(),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 1, 2)]),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 3, 1)]),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 3, 1)]),
        )
        .expect("makelink");
    {
        let snap = k.snapshot();
        let links = snap.world().links();
        // Overlap = ProperOverlap | Containment | Equal.
        assert!(links.stab(FROM, &enc(&[ca(1)]), View::Audit).contains(&l));
        assert!(links.stab(FROM, &enc(&[ca(2)]), View::Audit).contains(&l));
        // NOT Adjacent: subtree(ca3) abuts [ca1, ca3) and must not match
        // FROM — but does match TO.
        assert!(!links.stab(FROM, &enc(&[ca(3)]), View::Audit).contains(&l));
        assert!(links.stab(TO, &enc(&[ca(3)]), View::Audit).contains(&l));
        // AND-combiner over constrained slots only; empty constraints ⇒ the
        // whole slice.
        assert!(links
            .match_links(&[(FROM, &enc(&[ca(2)])), (TO, &enc(&[ca(3)]))], View::Audit)
            .contains(&l));
        assert!(!links
            .match_links(&[(FROM, &enc(&[ca(2)])), (TO, &enc(&[ca(2)]))], View::Audit)
            .contains(&l));
        assert!(links.match_links(&[], View::Audit).contains(&l));
        // The content type is queryable by its coverage: ty resolved to the
        // single address ca(3), so its class is Addrs({ca3}).
        assert!(links.type_slice(&enc(&[ca(3)]), View::Audit).contains(&l));
    }
    // Active view filters nullified results.
    w.nullify(P1, &doc1(), &l).expect("nullify the link");
    let snap = k.snapshot();
    let links = snap.world().links();
    assert!(!links.stab(FROM, &enc(&[ca(1)]), View::Active).contains(&l));
    assert!(links.stab(FROM, &enc(&[ca(1)]), View::Audit).contains(&l));
    assert!(!links.match_links(&[], View::Active).contains(&l));
}

#[test]
fn age_answers_ungated_and_the_staleness_family_refuses_every_class() {
    // BH4 splits down the middle of its corpus name, and this format makes
    // the split total: `age` reads no registration and answers for any
    // resident link, while `stale` — and `retract_stale`, which builds its
    // batch from it — GATES on an Age declaration that no class in the
    // compiled shipped population carries (all five are idem⊤, and BH4
    // demands idem⊥). So the staleness family refuses every type a caller
    // can name, shipped and unregistered alike, and the refusal fires
    // pre-transact with nothing committed.
    let k = kernel();
    let w = writer(&k);
    let sup = supersedes_ty();
    // Three tuples on doc2's chain: ordinals 1..3.
    let (t1, _) = w.emit(P1, &doc2(), &pred_def_ty(), &ca(1), &[]).expect("t1");
    let (t2, _) = w.emit(P1, &doc2(), &pred_def_ty(), &ca(2), &[]).expect("t2");
    let (t3, _) = w.emit(P1, &doc2(), &pred_stable_ty(), &ca(3), &[]).expect("t3");
    let (m1, _) = w
        .makelink(
            P1,
            &doc2(),
            SlotArg::Addrs(vec![ca(4)]),
            SlotArg::Addrs(vec![]),
            SlotArg::Addrs(vec![unregistered_ta(4)]),
        )
        .expect("an open deposit ages like any other");
    {
        let snap = k.snapshot();
        let links = snap.world().links();
        // age = home-relative chain distance (ordinal time): count 4 so far.
        assert_eq!(links.age(&t1), Some(3));
        assert_eq!(links.age(&t2), Some(2));
        assert_eq!(links.age(&t3), Some(1));
        assert_eq!(links.age(&m1), Some(0));
        assert_eq!(links.age(&ca(1)), None); // non-resident ⇒ None
        // stale refuses EVERY class: the registered idem⊤ five and an
        // unregistered number alike — an empty stale set is never conflated
        // with "not a BH4 type".
        assert_eq!(links.stale(&pred_def_ty(), 0), Err(NotBh4));
        assert_eq!(links.stale(&retired_ty(), 0), Err(NotBh4));
        assert_eq!(links.stale(&sup, 0), Err(NotBh4));
        assert_eq!(links.stale(&unregistered_ty(4), 0), Err(NotBh4));
    }
    // The batch nullifier rejects every ty PRE-TRANSACT: typed refusal, no
    // transaction, no effect — the fence that keeps it from ever being aimed
    // at an idem⊤/other class to mass-nullify, and in this format the whole
    // of the op's reachable behavior.
    let before = k.current_seq();
    assert!(matches!(
        w.retract_stale(P1, &doc2(), &pred_def_ty(), 0),
        Err(TxnError::Rejected(RetractStaleError::NotBh4))
    ));
    assert!(matches!(
        w.retract_stale(P1, &doc2(), &sup, 0),
        Err(TxnError::Rejected(RetractStaleError::NotBh4))
    ));
    assert!(matches!(
        w.retract_stale(P1, &doc2(), &unregistered_ty(4), 0),
        Err(TxnError::Rejected(RetractStaleError::NotBh4))
    ));
    // ...even at an unregistered home: NotBh4 outranks the home check, so
    // no transaction opens anywhere on this surface.
    assert!(matches!(
        w.retract_stale(P1, &a(&[1, 0, 1, 0, 7]), &pred_def_ty(), 2),
        Err(TxnError::Rejected(RetractStaleError::NotBh4))
    ));
    assert_eq!(k.current_seq(), before);
    let snap = k.snapshot();
    let links = snap.world().links();
    assert!(!links.is_nullified(&t1), "no batch ever fires");
}

#[test]
fn is_filtered_reads_the_active_retired_slice() {
    // BH1's filter is retractable: the filter slice is ACTIVE, so nullifying
    // a retirement restores the probe and the Default view with it.
    let k = kernel();
    let w = writer(&k);
    let retired = retired_ty();
    let rel = unregistered_ty(1);
    w.makelink(
        P1,
        &doc1(),
        SlotArg::Addrs(vec![ca(1)]),
        SlotArg::Addrs(vec![ca(2)]),
        SlotArg::Addrs(vec![unregistered_ta(1)]),
    )
    .expect("relation");
    let (r, _) = w
        .emit(P1, &doc1(), &retired, &ca(1), &[])
        .expect("retire ca1");
    {
        let snap = k.snapshot();
        let links = snap.world().links();
        assert!(links.is_filtered(ca(1).tumbler()));
        assert!(links.members(&rel, View::Default).is_empty());
    }
    w.nullify(P1, &doc1(), &r)
        .expect("retract the retirement itself");
    let snap = k.snapshot();
    let links = snap.world().links();
    assert!(
        !links.is_filtered(ca(1).tumbler()),
        "a nullified retired root filters nothing"
    );
    assert_eq!(links.members(&rel, View::Default), vec![ca(1)]);
}

#[test]
fn default_view_subtracts_a_filtered_target() {
    // The result-side half of Default = active ∖ filtered: retiring the
    // TARGET, not the source, is what the targets_of subtraction can see.
    let k = kernel();
    let w = writer(&k);
    let retired = retired_ty();
    let rel = unregistered_ty(1);
    w.makelink(
        P1,
        &doc1(),
        SlotArg::Addrs(vec![ca(1)]),
        SlotArg::Addrs(vec![ca(2)]),
        SlotArg::Addrs(vec![unregistered_ta(1)]),
    )
    .expect("relation");
    w.emit(P1, &doc1(), &retired, &ca(2), &[])
        .expect("retire the target");
    let snap = k.snapshot();
    let links = snap.world().links();
    assert_eq!(links.targets_of(&rel, &ca(1), View::Active), vec![ca(2)]);
    assert!(links.targets_of(&rel, &ca(1), View::Default).is_empty());
    // The source is untouched, so the members side still answers.
    assert_eq!(links.members(&rel, View::Default), vec![ca(1)]);
}

#[test]
fn retired_filter_rewrites_default_views_only() {
    let k = kernel();
    let w = writer(&k);
    let retired = retired_ty();
    let rel = unregistered_ty(1);
    w.makelink(
        P1,
        &doc1(),
        SlotArg::Addrs(vec![ca(1)]),
        SlotArg::Addrs(vec![ca(2)]),
        SlotArg::Addrs(vec![unregistered_ta(1)]),
    )
    .expect("relation");
    {
        let snap = k.snapshot();
        assert!(!snap.world().links().is_filtered(ca(1).tumbler()));
    }
    // Retire ca(1) through the shipped Unary/idem⊤ BH1 class.
    w.emit(P1, &doc1(), &retired, &ca(1), &[]).expect("retire ca1");
    let snap = k.snapshot();
    let links = snap.world().links();
    assert!(links.is_filtered(ca(1).tumbler()));
    assert!(!links.is_filtered(ca(2).tumbler()));
    // T-wide probe: any tumbler under a retired root is filtered, address
    // or not.
    assert!(links.is_filtered(&t(&[1, 0, 1, 0, 1, 0, 1, 1, 7])));
    // Default = active ∖ filtered — on members/targets_of only.
    assert_eq!(links.members(&rel, View::Active), vec![ca(1)]);
    assert!(links.members(&rel, View::Default).is_empty());
    assert_eq!(links.targets_of(&rel, &ca(1), View::Default), vec![ca(2)]);
    // is_k is never filtered (BH1 Rewrite scope).
    assert!(links.is_k(&rel, ca(1).tumbler()));
    // J ≠ K′: the filter class itself is not self-subtracted.
    assert_eq!(links.members(&retired, View::Default), vec![ca(1)]);
}

#[test]
fn bh3_endpoint_reads_are_exact_over_the_active_typed_slice_and_the_join_covers_nothing() {
    // The BH3 endpoint pair answers by CLASS for any type number; only the
    // keyed JOIN reads declarations back, and no class in the compiled
    // shipped population declares ReverseLookup — so `targets_keyed` covers
    // nothing, however cleanly a class's tuples would qualify.
    let k = kernel();
    let w = writer(&k);
    let rel = unregistered_ty(13);
    let other = unregistered_ty(14);
    let deposit = |to: u32, ty: u32| {
        w.makelink(
            P1,
            &doc1(),
            SlotArg::Addrs(vec![ca(1)]),
            SlotArg::Addrs(vec![ca(to)]),
            SlotArg::Addrs(vec![unregistered_ta(ty)]),
        )
        .expect("open deposit")
        .0
    };
    deposit(2, 13);
    // A same-source tuple of ANOTHER type must not disturb the typed reads.
    deposit(3, 14);
    {
        let snap = k.snapshot();
        let links = snap.world().links();
        assert_eq!(links.target_of(&rel, &ca(1)), Some(ca(2)));
        assert_eq!(links.sources_to(&rel, &ca(2)), vec![ca(1)]);
        assert_eq!(links.target_of(&other, &ca(1)), Some(ca(3)));
        // The join is empty — not because these classes lack qualifying
        // tuples, but because nothing declares BH3 in this format.
        assert!(links.targets_keyed(&ca(1)).is_empty());
    }
    // A second active tuple of the same class denoting the same source makes
    // target_of ⊥ ("exactly one active K-tuple").
    deposit(4, 13);
    let snap = k.snapshot();
    let links = snap.world().links();
    assert_eq!(links.target_of(&rel, &ca(1)), None);
    assert!(links.targets_keyed(&ca(1)).is_empty());
}

#[test]
fn targets_of_collects_every_target_of_every_matching_tuple() {
    // D3 is two nested loops — every tuple whose F covers the source, and
    // every address that tuple's G denotes — and a one-target result cannot
    // tell either of them from a `next()`. The open surface is what lets
    // |G| > 1 exist at all in this format.
    let k = kernel();
    let w = writer(&k);
    let rel = unregistered_ty(11);
    let deposit = |from: u32, to: &[u32]| {
        w.makelink(
            P1,
            &doc1(),
            SlotArg::Addrs(vec![ca(from)]),
            SlotArg::Addrs(to.iter().map(|&i| ca(i)).collect()),
            SlotArg::Addrs(vec![unregistered_ta(11)]),
        )
        .expect("open deposit")
        .0
    };
    deposit(1, &[2, 3]);
    deposit(1, &[3, 5]);
    deposit(4, &[9]);
    let snap = k.snapshot();
    let links = snap.world().links();
    assert_eq!(
        links.targets_of(&rel, &ca(1), View::Active),
        vec![ca(2), ca(3), ca(5)],
        "every target of every matching tuple, ca(3) deduplicated across the two"
    );
    // The control: the excluded tuple IS in the slice, so ca(9)'s absence is
    // the F-coverage test and not an absent tuple.
    assert_eq!(links.targets_of(&rel, &ca(4), View::Active), vec![ca(9)]);
}

#[test]
fn sources_to_collects_every_source_deduplicated() {
    // BH3's reverse lookup walks the WHOLE active typed slice: every tuple
    // whose G covers the target contributes its F, deduplicated. The open
    // surface never dedups (ML0), so the repeated tuple deposits fresh.
    let k = kernel();
    let w = writer(&k);
    let rel = unregistered_ty(13);
    let other = unregistered_ty(11);
    let deposit = |from: u32, ty: u32| {
        w.makelink(
            P1,
            &doc1(),
            SlotArg::Addrs(vec![ca(from)]),
            SlotArg::Addrs(vec![ca(9)]),
            SlotArg::Addrs(vec![unregistered_ta(ty)]),
        )
        .expect("open deposit")
        .0
    };
    deposit(1, 13);
    deposit(4, 13);
    deposit(1, 13); // a third tuple repeating the first source
    // Another type, same target — the typed slice is the domain.
    deposit(7, 11);
    let snap = k.snapshot();
    let links = snap.world().links();
    assert_eq!(
        links.sources_to(&rel, &ca(9)),
        vec![ca(1), ca(4)],
        "every source of every matching tuple, deduplicated, in Tumbler order"
    );
    // The control: that other tuple answers for its OWN type, so ca(7)'s
    // absence above is the typed slice and not an absent tuple.
    assert_eq!(links.sources_to(&other, &ca(9)), vec![ca(7)]);
}

#[test]
fn sources_to_matches_a_target_by_coverage() {
    // AM's reverse-lookup rule: sources_to is the one member of the BH3
    // family matched by COVERAGE, so a target part-way through a multi-
    // element G extent is a hit — though that extent denotes no address at
    // all. MAKELINK builds it: the open surface has no shape gate.
    let k = kernel();
    seed_content(&k, &doc1(), 4);
    let w = writer(&k);
    let (l, _) = w
        .makelink(
            P1,
            &doc1(),
            SlotArg::Addrs(vec![ca(1)]),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 2, 2)]), // one span, [ca2, ca4)
            SlotArg::Addrs(vec![unregistered_ta(13)]),      // a type is a number
        )
        .expect("makelink");
    let snap = k.snapshot();
    let links = snap.world().links();
    assert!(links.type_slice(&unregistered_ty(13), View::Active).contains(&l));
    assert_eq!(
        links.sources_to(&unregistered_ty(13), &ca(2)),
        vec![ca(1)],
        "the extent's first tumbler"
    );
    assert_eq!(
        links.sources_to(&unregistered_ty(13), &ca(3)),
        vec![ca(1)],
        "mid-extent: no denotation reaches it, coverage does"
    );
    assert!(
        links.sources_to(&unregistered_ty(13), &ca(4)).is_empty(),
        "the extent is half-open"
    );
}

#[test]
fn target_of_matches_a_source_by_denotation() {
    // AM's source-vertex rule: target_of matches `source ∈ F.addrs()`, so a
    // tuple whose F merely COVERS the source is not that source's tuple —
    // ⊥, not the target a coverage match would hand back.
    let k = kernel();
    seed_content(&k, &doc1(), 3);
    let w = writer(&k);
    let (l, _) = w
        .makelink(
            P1,
            &doc1(),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 1, 2)]), // one span, [ca1, ca3)
            SlotArg::Addrs(vec![ca(9)]),
            SlotArg::Addrs(vec![unregistered_ta(13)]),
        )
        .expect("makelink");
    let snap = k.snapshot();
    let links = snap.world().links();
    // The control: the tuple IS in the active typed slice and its F covers
    // the probe, so the ⊥ below is the matching rule and not an absent tuple.
    assert!(links.type_slice(&unregistered_ty(13), View::Active).contains(&l));
    let link = links.readlink(&l).expect("resident");
    assert!(link.from_slot().covers(ca(1).tumbler()));
    assert_eq!(
        links.target_of(&unregistered_ty(13), &ca(1)),
        None,
        "F covers ca(1) and denotes nothing"
    );
    assert!(links.targets_keyed(&ca(1)).is_empty());
}

#[test]
fn checkpoint_roundtrip_then_rebuild_derived_restores_every_hint() {
    let k = kernel();
    let w = writer(&k);
    let sup = supersedes_ty();
    let (a1, _) = w.emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[]).expect("idem⊤");
    let (m1, _) = w.emit(P1, &doc1(), &pred_stable_ty(), &ca(3), &[]).expect("m1");
    let (m2, _) = w.emit(P1, &doc1(), &pred_stable_ty(), &ca(4), &[]).expect("m2");
    let (o1, _) = w
        .makelink(
            P1,
            &doc1(),
            SlotArg::Addrs(vec![ca(5)]),
            SlotArg::Addrs(vec![ca(6)]),
            SlotArg::Addrs(vec![unregistered_ta(11)]),
        )
        .expect("an unregistered-class deposit, so its slice is rebuilt too");
    let _ = &o1;
    let (c, _) = w.assert_sup(P1, &doc1(), &m1, &m2).expect("claim");
    w.nullify(P1, &doc1(), &m1).expect("nullify m1");

    // The checkpoint wire format: serialize the world, deserialize (skip
    // fields default), rebuild_derived BEFORE any read/replay.
    let snap = k.snapshot();
    let bytes = bincode::serialize(snap.world()).expect("world serializes");
    let recovered: World = bincode::deserialize(&bytes).expect("world deserializes");
    let recovered = skep_kernel::WorldState::rebuild_derived(recovered);

    let orig = snap.world().links();
    let back = recovered.links();
    for addr in [&a1, &m1, &m2, &c] {
        assert_eq!(orig.readlink(addr), back.readlink(addr));
    }
    assert!(back.is_nullified(&m1));
    assert_eq!(back.succs(&sup, &m1), vec![m2.clone()]); // sup_fwd rebuilt
    assert_eq!(
        orig.type_slice(&pred_def_ty(), View::Audit),
        back.type_slice(&pred_def_ty(), View::Audit)
    );
    assert_eq!(
        orig.type_slice(&unregistered_ty(11), View::Active),
        back.type_slice(&unregistered_ty(11), View::Active)
    );
    assert!(!back.type_slice(&unregistered_ty(11), View::Active).is_empty());
    // The home-frontier hint, which age/stale and nullify's `a_emit`
    // prediction all stand on — and a live value, so the pair is not two
    // zeros agreeing.
    assert_ne!(orig.age(&a1), Some(0));
    assert_eq!(orig.age(&a1), back.age(&a1), "the home frontier is rebuilt");

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
    let succ = Link::new([enc(&[ca(3)]), enc(&[ca(4)]), unregistered_ty(30)]).expect("arity 3");
    // Foreign d_s (successor home): the error names d_s.
    assert!(matches!(
        w.editlink(P2, &x, succ.clone(), &doc1(), &sib_doc()),
        Err(TxnError::Rejected(EditLinkError::NotOwner(d))) if d == doc1()
    ));
    // Foreign d_a (claim home): the error names d_a.
    assert!(matches!(
        w.editlink(P2, &x, succ.clone(), &sib_doc(), &doc1()),
        Err(TxnError::Rejected(EditLinkError::NotOwner(d))) if d == doc1()
    ));
    // Across an op's several homes, EVERY registration is asked before ANY
    // ownership: an unregistered second home outranks an unowned first, so
    // the verdict does not depend on which home is named first.
    assert!(matches!(
        w.editlink(P1, &x, succ, &sib_doc(), &a(&[1, 0, 1, 0, 7])),
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
    let succ = Link::new([enc(&[ca(3)]), enc(&[ca(4)]), unregistered_ty(30)]).expect("arity 3");
    let (Edit { successor: s, claim }, _) = w
        .editlink(P2, &x, succ, &sib_doc(), &sib_doc())
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
    for (label, successor) in [
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
        let got = w.editlink(P1, &orig, successor, &doc1(), &doc1());
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
fn match_links_narrows_to_the_same_set_its_conjuncts_intersect() {
    // The AND is a conjunction, so narrowing the accumulator by a slot's own
    // overlap predicate and intersecting whole-store `stab` results are the
    // same set — over every subset of the constraint pool, in both views,
    // with a nullified link present so the Active/Audit split is exercised.
    let k = kernel();
    let w = writer(&k);
    let deposit = |from: &[Address], to: &[Address], ty: &[Address]| {
        w.makelink(
            P1,
            &doc1(),
            SlotArg::Addrs(from.to_vec()),
            SlotArg::Addrs(to.to_vec()),
            SlotArg::Addrs(ty.to_vec()),
        )
        .expect("open-surface deposit")
        .0
    };
    let l1 = deposit(&[ca(1)], &[ca(2)], &[ca(7)]);
    let l2 = deposit(&[ca(1)], &[ca(4)], &[ca(7)]);
    let l3 = deposit(&[ca(5)], &[ca(2)], &[ca(8)]);
    let l4 = deposit(&[ca(1), ca(5)], &[ca(2), ca(4)], &[ca(7)]);
    w.nullify(P1, &doc1(), &l3).expect("nullify one");

    let pool = [
        (FROM, enc(&[ca(1)])),
        (TO, enc(&[ca(2)])),
        (TYPE, enc(&[ca(7)])),
    ];
    let snap = k.snapshot();
    let links = snap.world().links();
    for view in [View::Audit, View::Active] {
        for mask in 0u8..8 {
            let constraints: Vec<(usize, &Endset)> = (0..pool.len())
                .filter(|i| mask & (1u8 << i) != 0)
                .map(|i| (pool[i].0, &pool[i].1))
                .collect();
            let got = links.match_links(&constraints, view);
            if constraints.is_empty() {
                continue; // the unconstrained branch has no conjuncts to agree with
            }
            let want = constraints
                .iter()
                .map(|&(slot, query)| links.stab(slot, query, view))
                .reduce(|acc, s| acc.iter().filter(|t| s.contains(*t)).cloned().collect())
                .expect("nonempty");
            assert_eq!(got, want, "{view:?} constraints {mask:#05b}");
        }
    }
    // ...and the sets are not all equal, so the agreement above is not
    // vacuous: the three-slot AND admits l1 and l4 only, and Active drops
    // the nullified link from the one-slot answer.
    let every: Vec<(usize, &Endset)> = pool.iter().map(|(slot, query)| (*slot, query)).collect();
    let all = links.match_links(&every, View::Audit);
    assert!(all.contains(&l1) && all.contains(&l4));
    assert!(!all.contains(&l2) && !all.contains(&l3));
    let to_query = enc(&[ca(2)]);
    let to_only = [(TO, &to_query)];
    assert!(links.match_links(&to_only, View::Audit).contains(&l3));
    assert!(!links.match_links(&to_only, View::Active).contains(&l3));
}

#[test]
fn an_observed_tuple_carries_the_link_s_own_f_and_g_in_those_roles() {
    // A Tuple's `from` and `to` are the matched link's F and G slots IN THOSE
    // ROLES — two same-typed fields read off two same-typed sources, so
    // nothing but this pins which is which. A Multi tuple with |F| ≠ |G| is
    // what makes an exchange fail on arity as well as on content.
    let k = kernel();
    let w = writer(&k);
    let (a1, _) = w
        .makelink(
            P1,
            &doc1(),
            SlotArg::Addrs(vec![ca(1)]),
            SlotArg::Addrs(vec![ca(2), ca(3)]),
            SlotArg::Addrs(vec![unregistered_ta(11)]),
        )
        .expect("the open surface admits |G| = 2");
    let snap = k.snapshot();
    let links = snap.world().links();
    let tuples = links.observe(&unregistered_ty(11), Pattern::default(), View::Active);
    assert_eq!(tuples.len(), 1);
    assert_eq!(tuples[0].addr, a1);
    assert_eq!(tuples[0].from, enc(&[ca(1)]), "the F slot, verbatim");
    assert_eq!(tuples[0].to, enc(&[ca(2), ca(3)]), "the G slot, verbatim");
    // ...and each is the link's own slot, so the tuple cannot disagree with
    // the value READLINK returns.
    let link = links.readlink(&a1).expect("resident");
    assert_eq!(&tuples[0].from, link.from_slot());
    assert_eq!(&tuples[0].to, link.to_slot());
}

#[test]
fn observe_returns_every_match_in_ascending_tuple_address_order() {
    // ASN-0086's central read, at the cardinality every real type has. Three
    // claims meet here and none of them is visible at a one-tuple result: the
    // slice is walked WHOLE, each pattern side is an AND of its probes, and
    // the view selects the slice.
    let k = kernel();
    let w = writer(&k);
    let tuple_addrs =
        |tuples: Vec<Tuple>| tuples.into_iter().map(|tuple| tuple.addr).collect::<Vec<_>>();
    let rel = unregistered_ty(11);
    let deposit = |from: u32, to: &[u32]| {
        w.makelink(
            P1,
            &doc1(),
            SlotArg::Addrs(vec![ca(from)]),
            SlotArg::Addrs(to.iter().map(|&i| ca(i)).collect()),
            SlotArg::Addrs(vec![unregistered_ta(11)]),
        )
        .expect("open deposit")
        .0
    };
    let a1 = deposit(1, &[2, 3]);
    let a2 = deposit(4, &[2]);
    let a3 = deposit(1, &[3]);
    {
        let snap = k.snapshot();
        let links = snap.world().links();
        // EVERY match, not the first — and ascending by tuple address.
        assert_eq!(
            tuple_addrs(links.observe(&rel, Pattern::default(), View::Active)),
            vec![a1.clone(), a2.clone(), a3.clone()]
        );
        // One F-probe selects two of the three.
        let f = [ca(1).tumbler().clone()];
        assert_eq!(
            tuple_addrs(links.observe(&rel, Pattern { from: &f, to: &[] }, View::Active)),
            vec![a1.clone(), a3.clone()]
        );
        // A pattern side is an AND of its probes, not an OR: a1's G covers
        // ca(2) AND ca(3); a3's covers only ca(3), so an OR would keep it.
        let g = [ca(2).tumbler().clone(), ca(3).tumbler().clone()];
        assert_eq!(
            tuple_addrs(links.observe(&rel, Pattern { from: &f, to: &g }, View::Active)),
            vec![a1.clone()]
        );
    }
    // The view selects the slice: Audit keeps a nullified tuple, Active drops
    // it. Every other observe case in the suite reads one view only.
    w.nullify(P1, &doc1(), &a2).expect("retract the middle tuple");
    let snap = k.snapshot();
    let links = snap.world().links();
    assert_eq!(
        tuple_addrs(links.observe(&rel, Pattern::default(), View::Audit)),
        vec![a1.clone(), a2.clone(), a3.clone()]
    );
    assert_eq!(
        tuple_addrs(links.observe(&rel, Pattern::default(), View::Active)),
        vec![a1, a3]
    );
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
    let succ_value = Link::new([enc(&[ca(3)]), enc(&[ca(4)]), unregistered_ty(30)]).expect("arity 3");
    let (edit, _) = w
        .editlink(P1, &orig, succ_value.clone(), &doc1(), &doc2())
        .expect("P1 owns both homes");
    assert_eq!(edit.successor, la(2), "the successor lands on d_s's link chain");
    assert_eq!(edit.claim, la2(1), "the claim lands on d_a's");
    let snap = k.snapshot();
    let links = snap.world().links();
    assert_eq!(links.readlink(&edit.successor), Some(&succ_value));
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

#[test]
fn the_discovery_primitives_read_default_as_active() {
    // `View::Default` is undefined for a raw index probe, so all three §G
    // primitives coerce it to `Active` — which M8 depends on, `View`'s own
    // `Default` impl being `Default`. An uncoerced view falls through to the
    // Audit branch and a nullified link reappears in a discovery result.
    let k = kernel();
    let w = writer(&k);
    let (kept, _) = w
        .emit(P1, &doc1(), &pred_stable_ty(), &ca(1), &[])
        .expect("kept");
    let (gone, _) = w
        .emit(P1, &doc1(), &pred_stable_ty(), &ca(3), &[])
        .expect("gone");
    w.nullify(P1, &doc1(), &gone).expect("nullify one");
    let snap = k.snapshot();
    let links = snap.world().links();
    // Both links share a TYPE slot, so one query reaches both.
    let query = pred_stable_ty();
    assert!(
        links.stab(TYPE, &query, View::Audit).contains(&gone),
        "the Audit answer is not vacuous"
    );
    assert!(links.stab(TYPE, &query, View::Default).contains(&kept));
    assert_eq!(
        links.stab(TYPE, &query, View::Default),
        links.stab(TYPE, &query, View::Active)
    );
    assert!(!links.stab(TYPE, &query, View::Default).contains(&gone));
    let constraints = [(TYPE, &query)];
    assert_eq!(
        links.match_links(&constraints, View::Default),
        links.match_links(&constraints, View::Active)
    );
    assert!(!links.match_links(&constraints, View::Default).contains(&gone));
    // The unconstrained branch coerces on its own — the constrained one hands
    // its view to `stab`, which would coerce for it.
    assert!(links.match_links(&[], View::Audit).contains(&gone));
    assert!(!links.match_links(&[], View::Default).contains(&gone));
    assert_eq!(
        links.match_links(&[], View::Default),
        links.match_links(&[], View::Active)
    );
    assert!(links.type_slice(&pred_stable_ty(), View::Audit).contains(&gone));
    assert_eq!(
        links.type_slice(&pred_stable_ty(), View::Default),
        links.type_slice(&pred_stable_ty(), View::Active)
    );
    assert!(!links.type_slice(&pred_stable_ty(), View::Default).contains(&gone));
}

#[test]
fn editlink_reports_an_unregistered_home_before_a_non_resident_original() {
    // `OriginalNotResident` is declared first, and the home/ω pair is hoisted
    // ahead of every other in-transaction verdict — so editlink is the one op
    // where the declared and realized orders diverge, and the one place the
    // hoist is observable.
    let k = kernel();
    let w = writer(&k);
    let succ = Link::new([enc(&[ca(3)]), enc(&[ca(4)]), unregistered_ty(30)]).expect("arity 3");
    assert!(matches!(
        w.editlink(P1, &la(90), succ, &a(&[1, 0, 1, 0, 7]), &doc1()),
        Err(TxnError::Rejected(EditLinkError::HomeNotRegistered))
    ));
}

#[test]
fn stab_with_an_empty_query_matches_nothing() {
    // The premise of `match_links`' caller contract: an unconstrained slot is
    // OMITTED, never passed as ⟨⟩, because `stab(slot, ⟨⟩, ·) = ∅` would
    // empty the AND.
    let k = kernel();
    let w = writer(&k);
    w.emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[])
        .expect("a link to miss");
    let snap = k.snapshot();
    let links = snap.world().links();
    assert!(links.stab(FROM, &Endset::empty(), View::Audit).is_empty());
    assert!(
        !links.match_links(&[], View::Audit).is_empty(),
        "omitting the slot is the contract, and the store is not empty"
    );
    assert!(
        links
            .match_links(&[(FROM, &Endset::empty())], View::Audit)
            .is_empty(),
        "passing ⟨⟩ is not"
    );
}

#[test]
fn stab_matches_nothing_at_a_slot_the_link_does_not_have() {
    // "Absent slot ⇒ no match" — never probed, because the store holds only
    // arity-3 links and every call in the suite passes 1, 2 or 3. The
    // 1-based convention makes slot 0 absent too, so it must not read as
    // slot 1.
    let k = kernel();
    let w = writer(&k);
    let (l, _) = w
        .emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[])
        .expect("a link to miss");
    let snap = k.snapshot();
    let links = snap.world().links();
    let query = enc(&[ca(1)]);
    // The control: this query DOES match at the slot the link has.
    assert!(links.stab(FROM, &query, View::Audit).contains(&l));
    assert!(
        links.stab(4, &query, View::Audit).is_empty(),
        "past the arity"
    );
    assert!(
        links.stab(0, &query, View::Audit).is_empty(),
        "below the 1-based floor — never slot 1"
    );
}

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
fn followlink_folds_the_whole_slot_in_its_recorded_order() {
    // The fold is concatenation, order-preserving (RL1's verbatim read-back
    // through F1/F3) — so a deliberately unsorted multi-span slot reads back
    // unsorted, uncoalesced and whole. Every other followlink case is one
    // span or none, where a normalizing fold would agree.
    let k = kernel();
    let w = writer(&k);
    let (l, _) = w
        .makelink(
            P1,
            &doc1(),
            SlotArg::Addrs(vec![ca(2), ca(1)]), // unsorted, on purpose
            SlotArg::Addrs(vec![]),
            SlotArg::Addrs(vec![unregistered_ta(10)]),
        )
        .expect("open-surface deposit");
    let want: SpanSet = [
        skep_address::subtree_of(ca(2).tumbler()),
        skep_address::subtree_of(ca(1).tumbler()),
    ]
    .into_iter()
    .collect();
    let snap = k.snapshot();
    assert_eq!(snap.world().links().followlink(&l, FROM), Ok(want));
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
    let iext = |lo: u32, hi: u32| {
        skep_address::Span::from_endpoints(ca(lo).tumbler().clone(), ca(hi).tumbler())
            .expect("well-formed")
    };
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
    // PRE-TRANSACT — ahead of the shape gate, which every registered class
    // in this format would also refuse a nonempty `to` under; the at-budget
    // ADMIT case needs a registered non-Unary class and so lives on the open
    // surface (`an_addrs_slot_past_the_span_budget_is_refused` carries it).
    let k = kernel();
    let w = writer(&k);
    let targets = |n: u32| -> Vec<Address> { (1..=n).map(ca).collect() };
    let budget = skep_links::MAX_SLOT_SPANS as u32;

    let before = k.current_seq();
    assert!(matches!(
        w.emit(P1, &doc1(), &pred_def_ty(), &ca(2), &targets(budget + 1)),
        Err(TxnError::Rejected(EmitError::SlotTooLarge))
    ));
    assert_eq!(k.current_seq(), before, "pre-transact: nothing opened");
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
    assert_eq!(k.current_seq(), before, "pre-transact: nothing opened");
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
    let succ = || Link::new([enc(&[ca(3)]), enc(&[ca(4)]), unregistered_ty(30)]).expect("arity 3");

    let (edit1, _) = w
        .editlink(P1, &orig, succ(), &doc1(), &doc2())
        .expect("d_s = doc1, d_a = doc2");
    assert_eq!(edit1.successor, la(2), "the successor on d_s's chain");
    assert_eq!(edit1.claim, la2(1), "the claim on d_a's");

    let (edit2, _) = w
        .editlink(P1, &orig, succ(), &doc2(), &doc1())
        .expect("the same pair of homes, named the other way round");
    assert_eq!(edit2.successor, la2(2), "the successor still follows d_s");
    assert_eq!(edit2.claim, la(3), "and the claim still follows d_a");
}

#[test]
fn the_default_view_subtracts_under_every_active_retired_root() {
    // BH1's filter domain is the WHOLE active Retired slice, and the
    // result-side subtraction derives it once for the whole result rather
    // than once per element — so a result filtered by the second or third
    // root must be subtracted exactly as one filtered by the first.
    let k = kernel();
    let w = writer(&k);
    let retired = retired_ty();
    let rel = unregistered_ty(11);
    for (source, target) in [(ca(1), ca(5)), (ca(2), ca(6)), (ca(3), ca(7))] {
        w.makelink(
            P1,
            &doc1(),
            SlotArg::Addrs(vec![source]),
            SlotArg::Addrs(vec![target]),
            SlotArg::Addrs(vec![unregistered_ta(11)]),
        )
        .expect("relation");
    }
    for root in [ca(2), ca(3), ca(7)] {
        w.emit(P1, &doc1(), &retired, &root, &[])
            .expect("retire a root");
    }
    let snap = k.snapshot();
    let links = snap.world().links();
    assert_eq!(
        links.members(&rel, View::Active),
        vec![ca(1), ca(2), ca(3)],
        "the unfiltered control"
    );
    assert_eq!(
        links.members(&rel, View::Default),
        vec![ca(1)],
        "the second and third roots subtract as surely as the first"
    );
    // The third root reaches the targets side, which collects the domain of
    // its own accord.
    assert_eq!(links.targets_of(&rel, &ca(3), View::Active), vec![ca(7)]);
    assert!(links.targets_of(&rel, &ca(3), View::Default).is_empty());
    // Each root still answers the single-probe read, which short-circuits
    // rather than collecting.
    for root in [ca(2), ca(3), ca(7)] {
        assert!(links.is_filtered(root.tumbler()));
    }
    assert!(!links.is_filtered(ca(1).tumbler()));
}
