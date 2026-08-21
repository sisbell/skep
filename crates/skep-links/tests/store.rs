//! Op-level contracts over a real kernel (InMemory): the two write
//! disciplines and their gates, idempotent dedup + resurrection, retraction
//! and the active view, supersession + the BH2 walk, editlink's atomic
//! composite and DC guard, MAKELINK end-to-end (resolve/deposit/seat),
//! BH1/BH3/BH4 behaviors, the §G discovery primitives, and the
//! checkpoint-roundtrip + rebuild_derived discipline.

mod common;

use common::*;
use skep_address::SpanSet;
use skep_arrangement::HasM5;
use skep_kernel::TxnError;
use skep_links::{
    enc, AssertSupError, Caller, EditLinkError, EmitError, Endset, HasLinks, Link, LinkStore,
    MakeLinkError, NotBh4, NullifyError, RetractStaleError, ShippedType, SlotArg, Tip, View,
};

fn store(k: &skep_kernel::Kernel<World>) -> LinkStore<'_, World> {
    LinkStore::new(k)
}

#[test]
fn emit_deposits_verbatim_reads_back_and_never_seats() {
    let k = kernel();
    let s = store(&k);
    let (a1, _) = s
        .emit(P1, &doc1(), &rel_ty(), &ca(1), &[ca(2)])
        .expect("registered Binary emit succeeds");
    assert_eq!(a1, la(1)); // first link minted on doc1's link chain

    let snap = k.snapshot();
    let ls = snap.world().links();
    // READLINK: the value verbatim — from/to are the canonical encodings, ty
    // stored verbatim as e₃.
    let link = ls.readlink(&a1).expect("deposited link is resident");
    assert_eq!(link.from_slot(), &enc(&[ca(1)]));
    assert_eq!(link.to_slot(), &enc(&[ca(2)]));
    assert_eq!(link.type_slot(), &rel_ty());
    // Emit_K does NOT seat (MAKELINK alone seats).
    assert_eq!(snap.world().m5().link_count(&doc1()), n(0));
    // Observe: empty patterns are no constraint; exact ⊆-coverage match.
    let all = ls.observe(&rel_ty(), &[], &[], View::Active);
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].addr, a1);
    assert_eq!(
        ls.observe(
            &rel_ty(),
            &[ca(1).tumbler().clone()],
            &[ca(2).tumbler().clone()],
            View::Active
        )
        .len(),
        1
    );
    assert!(ls
        .observe(&rel_ty(), &[ca(3).tumbler().clone()], &[], View::Active)
        .is_empty());
    // Default predicates D1/D2/D3.
    assert!(ls.is_k(&rel_ty(), ca(1).tumbler()));
    assert!(!ls.is_k(&rel_ty(), ca(2).tumbler())); // membership is over F, not G
    // The probe domain is all of carrier T: a raw tumbler under subtree(ca1)
    // — not an element address — is an honest membership probe.
    assert!(ls.is_k(&rel_ty(), &t(&[1, 0, 1, 0, 1, 0, 1, 1, 5])));
    assert_eq!(ls.members(&rel_ty(), View::Active), vec![ca(1)]);
    assert_eq!(ls.targets_of(&rel_ty(), &ca(1), View::Active), vec![ca(2)]);
    // BH3 endpoint projections.
    assert_eq!(ls.sources_to(&rel_ty(), &ca(2)), vec![ca(1)]);
    assert_eq!(ls.target_of(&rel_ty(), &ca(1)), Some(ca(2)));
}

#[test]
fn emit_typed_rejections() {
    let k = kernel();
    let s = store(&k);
    let snap = k.snapshot();
    let sup = snap
        .world()
        .links()
        .reserved_type(ShippedType::Supersedes)
        .clone();
    let retraction = snap
        .world()
        .links()
        .reserved_type(ShippedType::Retraction)
        .clone();

    // Pre-transact: non-address-denoting ty (before any class computation).
    let wide = skep_address::Span::from_endpoints(ca(1).tumbler().clone(), ca(3).tumbler())
        .expect("well-formed span");
    let content_extent = Endset::from_spans([wide]);
    assert!(matches!(
        s.emit(P1, &doc1(), &content_extent, &ca(1), &[ca(2)]),
        Err(TxnError::Rejected(EmitError::NonAddressDenotingType))
    ));
    // Pre-transact: the supersession-class fence (Conflicts §10).
    assert!(matches!(
        s.emit(P1, &doc1(), &sup, &ca(1), &[ca(2)]),
        Err(TxnError::Rejected(EmitError::SupersessionClass))
    ));
    // Unregistered class.
    assert!(matches!(
        s.emit(P1, &doc1(), &enc(&[ra(20)]), &ca(1), &[ca(2)]),
        Err(TxnError::Rejected(EmitError::NotRegistered))
    ));
    // Shape gate: Binary demands |G| = 1.
    assert!(matches!(
        s.emit(P1, &doc1(), &rel_ty(), &ca(1), &[ca(2), ca(3)]),
        Err(TxnError::Rejected(EmitError::ShapeViolation))
    ));
    // K ≁ R: retraction writes only through nullify.
    assert!(matches!(
        s.emit(P1, &doc1(), &retraction, &ca(1), &[ca(2)]),
        Err(TxnError::Rejected(EmitError::RetractionClass))
    ));
    // Home existence, enforced on every path.
    assert!(matches!(
        s.emit(P1, &a(&[1, 0, 1, 0, 7]), &rel_ty(), &ca(1), &[ca(2)]),
        Err(TxnError::Rejected(EmitError::HomeNotRegistered))
    ));
}

#[test]
fn emit_idem_dedup_zero_step_and_resurrection() {
    let k = kernel();
    let s = store(&k);
    // idem⊤: a duplicate returns the incumbent with the base Seq and commits
    // nothing.
    let (a1, s1) = s.emit(P1, &doc1(), &rel_ty(), &ca(1), &[ca(2)]).expect("first emit");
    assert_eq!(k.current_seq(), s1);
    let (a1b, s1b) = s.emit(P1, &doc1(), &rel_ty(), &ca(1), &[ca(2)]).expect("dedup hit");
    assert_eq!(a1b, a1);
    assert_eq!(s1b, s1);
    assert_eq!(k.current_seq(), s1); // zero-step: nothing committed
    // idem⊥ (Multi app type): every emit deposits fresh (ML0's analogue).
    let (m1, _) = s.emit(P1, &doc1(), &multi_ty(), &ca(1), &[ca(2)]).expect("multi 1");
    let (m2, _) = s.emit(P1, &doc1(), &multi_ty(), &ca(1), &[ca(2)]).expect("multi 2");
    assert_ne!(m1, m2);
    // Resurrection (I2): dedup reads the ACTIVE view — a nullified incumbent
    // is invisible, so re-emitting lands at a fresh address; audit keeps both.
    s.nullify(P1, &doc1(), &a1).expect("nullify the rel tuple");
    let (a3, _) = s.emit(P1, &doc1(), &rel_ty(), &ca(1), &[ca(2)]).expect("re-emit");
    assert_ne!(a3, a1);
    let snap = k.snapshot();
    let ls = snap.world().links();
    assert!(ls.readlink(&a1).is_some()); // permanence: the audit slice keeps it
    assert!(ls.is_nullified(&a1));
    assert!(ls.is_active(&a3));
}

#[test]
fn nullify_contract_active_view_and_born_nullified_self_emit() {
    let k = kernel();
    let s = store(&k);
    // P-tgt rejects a non-resident, non-self target.
    assert!(matches!(
        s.nullify(P1, &doc1(), &ca(9)),
        Err(TxnError::Rejected(NullifyError::BadTarget))
    ));
    // P0.
    assert!(matches!(
        s.nullify(P1, &a(&[1, 0, 1, 0, 7]), &la(1)),
        Err(TxnError::Rejected(NullifyError::HomeNotRegistered))
    ));
    // Happy path: the [R] tuple nullifies exactly the target root.
    let (m1, _) = s.emit(P1, &doc1(), &multi_ty(), &ca(1), &[ca(2)]).expect("emit");
    let (r1, _) = s.nullify(P1, &doc1(), &m1).expect("nullify");
    {
        let snap = k.snapshot();
        let ls = snap.world().links();
        assert!(ls.is_nullified(&m1));
        assert!(!ls.is_active(&m1));
        assert!(ls.is_active(&r1)); // the retraction emitter itself is active
        // Active slices exclude the nullified tuple; audit keeps it (R3).
        assert!(!ls.type_slice(&multi_ty(), View::Active).contains(m1.tumbler()));
        assert!(ls.type_slice(&multi_ty(), View::Audit).contains(m1.tumbler()));
    }
    // idem⊤: re-retracting the same target from the same home dedups.
    let (r2, _) = s.nullify(P1, &doc1(), &m1).expect("re-nullify dedups");
    assert_eq!(r2, r1);
    // Born-nullified self-emit: the target may be the call's own would-be
    // fresh emitter (P-tgt's second disjunct) — doc2's first link is la2(1).
    let (e, _) = s.nullify(P1, &doc2(), &la2(1)).expect("self-emit retraction");
    assert_eq!(e, la2(1));
    let snap = k.snapshot();
    assert!(snap.world().links().is_nullified(&la2(1)));
}

#[test]
fn assert_sup_dedup_walk_and_standoff() {
    let k = kernel();
    let s = store(&k);
    let snap0 = k.snapshot();
    let sup = snap0
        .world()
        .links()
        .reserved_type(ShippedType::Supersedes)
        .clone();
    let (x, _) = s.emit(P1, &doc1(), &multi_ty(), &ca(1), &[ca(2)]).expect("x");
    let (y, _) = s.emit(P1, &doc1(), &multi_ty(), &ca(1), &[ca(3)]).expect("y");
    // Schema preconditions.
    assert!(matches!(
        s.assert_sup(P1, &doc1(), &x, &la(9)),
        Err(TxnError::Rejected(AssertSupError::EndpointNotResident))
    ));
    assert!(matches!(
        s.assert_sup(P1, &doc1(), &x, &x),
        Err(TxnError::Rejected(AssertSupError::SelfSupersession))
    ));
    // The claim: F = old, G = new; edges run old → new.
    let (c1, _) = s.assert_sup(P1, &doc1(), &x, &y).expect("claim");
    {
        let snap = k.snapshot();
        let ls = snap.world().links();
        assert_eq!(ls.succs(&sup, &x), vec![y.clone()]);
        assert_eq!(ls.chain(&sup, &x), vec![x.clone(), y.clone()]);
        assert_eq!(ls.tip(&sup, &x), Tip::Sink(y.clone()));
        // is_in_chain: membership in the walk's result list, never a
        // coverage test; edges run old → new only.
        assert!(ls.is_in_chain(&sup, &x, &y));
        assert!(!ls.is_in_chain(&sup, &y, &x));
        // The walk family serves only the shipped Supersedes class in v1 —
        // for any other ty the chain is empty, so nothing is a member.
        assert!(ls.succs(&rel_ty(), &x).is_empty());
        assert!(ls.chain(&rel_ty(), &x).is_empty());
        assert!(!ls.is_in_chain(&rel_ty(), &x, &x));
        assert_eq!(ls.tip(&rel_ty(), &x), Tip::Indeterminate);
    }
    // Dedup excludes home: the same (old, new) from ANOTHER home hits the
    // first claim (Conflicts §9).
    let (c1b, _) = s.assert_sup(P1, &doc2(), &x, &y).expect("cross-home duplicate");
    assert_eq!(c1b, c1);
    // Retraction stability: nullifying the claim removes the operative edge;
    // x becomes its own sink.
    s.nullify(P1, &doc1(), &c1).expect("retract claim");
    {
        let snap = k.snapshot();
        let ls = snap.world().links();
        assert!(ls.succs(&sup, &x).is_empty());
        assert_eq!(ls.tip(&sup, &x), Tip::Sink(x.clone()));
    }
    // Claim resurrection + mutual standoff: re-assert (fresh claim — the
    // nullified one is invisible to dedup), then the reverse claim; the
    // closure then has no sink and current() legitimately returns 0 members.
    let (c2, _) = s.assert_sup(P1, &doc1(), &x, &y).expect("re-assert");
    assert_ne!(c2, c1);
    s.assert_sup(P1, &doc1(), &y, &x).expect("reverse claim");
    let snap = k.snapshot();
    assert!(snap.world().links().current(&x).is_empty());
}

#[test]
fn editlink_composite_dc_guard_and_currency() {
    let k = kernel();
    let s = store(&k);
    let snap0 = k.snapshot();
    let sup = snap0
        .world()
        .links()
        .reserved_type(ShippedType::Supersedes)
        .clone();
    let retraction = snap0
        .world()
        .links()
        .reserved_type(ShippedType::Retraction)
        .clone();
    let (orig, _) = s.emit(P1, &doc1(), &multi_ty(), &ca(1), &[ca(2)]).expect("orig");

    // One atomic composite: fresh successor + claim; original untouched.
    let succ_value = Link::new([enc(&[ca(3)]), enc(&[ca(4)]), enc(&[ra(30)])]).expect("arity 3");
    let (s1, c1, _) = s
        .editlink(P1, &orig, succ_value.clone(), &doc1(), &doc1())
        .expect("editlink");
    {
        let snap = k.snapshot();
        let ls = snap.world().links();
        assert_eq!(ls.readlink(&s1).as_ref(), Some(&succ_value)); // supplied value verbatim
        let claim = ls.readlink(&c1).expect("claim resident");
        assert_eq!(claim.from_slot(), &enc(&[orig.clone()])); // F = old
        assert_eq!(claim.to_slot(), &enc(&[s1.clone()])); // G = new (fresh successor)
        assert_eq!(claim.type_slot(), &sup);
        assert_eq!(ls.chain(&sup, &orig), vec![orig.clone(), s1.clone()]);
        // Successor born UNSEATED.
        assert_eq!(snap.world().m5().link_count(&doc1()), n(0));
    }

    // Fork permanence: a second edit of the same original yields a distinct
    // successor and a co-visible claim; the walk reports the branch.
    let succ2 = Link::new([enc(&[ca(5)]), enc(&[ca(6)]), enc(&[ra(31)])]).expect("arity 3");
    let (s2, c2, _) = s.editlink(P1, &orig, succ2, &doc1(), &doc1()).expect("fork");
    {
        let snap = k.snapshot();
        let ls = snap.world().links();
        assert_eq!(ls.succs(&sup, &orig), vec![s1.clone(), s2.clone()]);
        assert_eq!(ls.tip(&sup, &orig), Tip::Indeterminate); // branch
        assert_eq!(ls.chain(&sup, &orig), vec![orig.clone()]); // halt at the branch
        // EL14 disclosure: both sinks, each with its full operative inbound
        // claim set.
        let cur = ls.current(&orig);
        assert_eq!(cur.len(), 2);
        assert_eq!(cur[0].member, s1);
        assert!(cur[0].active);
        assert_eq!(cur[0].claims, vec![c1.clone()]);
        assert_eq!(cur[1].member, s2);
        assert_eq!(cur[1].claims, vec![c2.clone()]);
    }

    // A [K_sup]-typed successor is admitted iff schema-conforming (DC): both
    // endpoints resident, distinct, unit-depth single-addr F/G.
    let (z, _) = s.emit(P1, &doc1(), &multi_ty(), &ca(1), &[ca(7)]).expect("z");
    let conforming = Link::new([enc(&[orig.clone()]), enc(&[z.clone()]), sup.clone()]).expect("arity 3");
    s.editlink(P1, &orig, conforming, &doc1(), &doc1())
        .expect("schema-conforming claim-typed successor");
    {
        let snap = k.snapshot();
        assert!(snap.world().links().succs(&sup, &orig).contains(&z));
    }

    // Rejections (each leaves no state change by M2's Rejected contract).
    let ok_succ = Link::new([enc(&[ca(3)]), enc(&[ca(4)]), enc(&[ra(32)])]).expect("arity 3");
    assert!(matches!(
        s.editlink(P1, &la(90), ok_succ.clone(), &doc1(), &doc1()),
        Err(TxnError::Rejected(EditLinkError::OriginalNotResident))
    ));
    assert!(matches!(
        s.editlink(P1, &orig, ok_succ.clone(), &a(&[1, 0, 1, 0, 7]), &doc1()),
        Err(TxnError::Rejected(EditLinkError::HomeNotRegistered))
    ));
    let arity4 = Link::new(vec![
        enc(&[ca(3)]),
        enc(&[ca(4)]),
        enc(&[ra(33)]),
        enc(&[ca(5)]),
    ])
    .expect("capacity admits arity 4");
    assert!(matches!(
        s.editlink(P1, &orig, arity4, &doc1(), &doc1()),
        Err(TxnError::Rejected(EditLinkError::IllFormedSuccessor))
    ));
    let empty_ty = Link::new([enc(&[ca(3)]), enc(&[ca(4)]), Endset::empty()]).expect("arity 3");
    assert!(matches!(
        s.editlink(P1, &orig, empty_ty, &doc1(), &doc1()),
        Err(TxnError::Rejected(EditLinkError::IllFormedSuccessor))
    ));
    let retraction_typed =
        Link::new([enc(&[ca(3)]), enc(&[ca(4)]), retraction.clone()]).expect("arity 3");
    assert!(matches!(
        s.editlink(P1, &orig, retraction_typed, &doc1(), &doc1()),
        Err(TxnError::Rejected(EditLinkError::DcViolation))
    ));
    let self_sup = Link::new([enc(&[orig.clone()]), enc(&[orig.clone()]), sup.clone()]).expect("arity 3");
    assert!(matches!(
        s.editlink(P1, &orig, self_sup, &doc1(), &doc1()),
        Err(TxnError::Rejected(EditLinkError::DcViolation))
    ));
}

#[test]
fn makelink_resolves_deposits_and_seats() {
    let k = kernel();
    seed_content(&k, &doc1(), 3); // content elements ca(1)..ca(3)
    let s = store(&k);

    let (l1, _) = s
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
        let ls = snap.world().links();
        let link = ls.readlink(&l1).expect("resident");
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
        assert_eq!(ls.followlink(&l1, 3), Ok(SpanSet::singleton(iext(3, 4))));
        assert!(ls.followlink(&l1, 4).is_err());
        assert!(ls.followlink(&la(9), 1).is_err());
    }

    // ML0: distinct links always — no dedup on the open surface.
    let (l2, _) = s
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
    let (l3, _) = s
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
        s.makelink(
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
        s.makelink(
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
        s.makelink(
            P1,
            &doc1(),
            SlotArg::Resolve(vec![deep]),
            SlotArg::Resolve(vec![]),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 3, 1)])
        ),
        Err(TxnError::Rejected(MakeLinkError::IllFormedSpec))
    ));
    assert!(matches!(
        s.makelink(
            P1,
            &doc1(),
            SlotArg::Resolve(vec![spec(&a(&[1, 0, 1, 0, 7]), 1, 1, 1)]),
            SlotArg::Resolve(vec![]),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 3, 1)])
        ),
        Err(TxnError::Rejected(MakeLinkError::IllFormedSpec))
    ));
    assert!(matches!(
        s.makelink(
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
    let s = store(&k);

    // A NAME in doc1's never-occupied subspace 3 — a ghost (L9), T4-valid.
    let name = a(&[1, 0, 1, 0, 1, 0, 3, 6, 1]);
    let (l1, _) = s
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
        let ls = snap.world().links();
        let link = ls.readlink(&l1).expect("resident");
        assert_eq!(link.type_slot(), &enc(&[name.clone()]));
        assert_eq!(link.to_slot(), &Endset::empty());
    }

    // Mixed slots, link-to-link: TO names l1 itself; the deposit is the enc
    // of the link address (ReflexiveAddressing, L13).
    let (l2, _) = s
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
        let ls = snap.world().links();
        assert_eq!(ls.readlink(&l2).expect("resident").to_slot(), &enc(&[l1.clone()]));
        // Shared-identity typing: both links sit in the name's type slice.
        let slice = ls.type_slice(&enc(&[name.clone()]), View::Active);
        assert!(slice.contains(l1.tumbler()) && slice.contains(l2.tumbler()));
    }

    // The as-given type floor: empty Addrs ty ⇒ EmptyTypeResolution.
    assert!(matches!(
        s.makelink(
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
fn stab_and_match_links_overlap_excludes_adjacency() {
    let k = kernel();
    seed_content(&k, &doc1(), 3);
    let s = store(&k);
    // from covers [ca1, ca3); to and ty cover [ca3, ca4).
    let (l, _) = s
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
        let ls = snap.world().links();
        // Overlap = ProperOverlap | Containment | Equal.
        assert!(ls.stab(1, &enc(&[ca(1)]), View::Audit).contains(l.tumbler()));
        assert!(ls.stab(1, &enc(&[ca(2)]), View::Audit).contains(l.tumbler()));
        // NOT Adjacent: subtree(ca3) abuts [ca1, ca3) and must not match
        // slot 1 — but does match slot 2.
        assert!(!ls.stab(1, &enc(&[ca(3)]), View::Audit).contains(l.tumbler()));
        assert!(ls.stab(2, &enc(&[ca(3)]), View::Audit).contains(l.tumbler()));
        // AND-combiner over constrained slots only; empty constraints ⇒ the
        // whole slice.
        assert!(ls
            .match_links(&[(1, enc(&[ca(2)])), (2, enc(&[ca(3)]))], View::Audit)
            .contains(l.tumbler()));
        assert!(!ls
            .match_links(&[(1, enc(&[ca(2)])), (2, enc(&[ca(2)]))], View::Audit)
            .contains(l.tumbler()));
        assert!(ls.match_links(&[], View::Audit).contains(l.tumbler()));
        // The content type is queryable by its coverage: ty resolved to the
        // single address ca(3), so its class is Addrs({ca3}).
        assert!(ls.type_slice(&enc(&[ca(3)]), View::Audit).contains(l.tumbler()));
    }
    // Active view filters nullified results.
    s.nullify(P1, &doc1(), &l).expect("nullify the link");
    let snap = k.snapshot();
    let ls = snap.world().links();
    assert!(!ls.stab(1, &enc(&[ca(1)]), View::Active).contains(l.tumbler()));
    assert!(ls.stab(1, &enc(&[ca(1)]), View::Audit).contains(l.tumbler()));
    assert!(!ls.match_links(&[], View::Active).contains(l.tumbler()));
}

#[test]
fn bh4_age_stale_and_the_typed_batch_fence() {
    let k = kernel();
    let s = store(&k);
    let snap0 = k.snapshot();
    let sup = snap0
        .world()
        .links()
        .reserved_type(ShippedType::Supersedes)
        .clone();
    // Three idem⊥ BH4 tuples on doc2's chain: ordinals 1..3.
    let (t1, _) = s.emit(P1, &doc2(), &bh4_ty(), &ca(1), &[]).expect("t1");
    let (t2, _) = s.emit(P1, &doc2(), &bh4_ty(), &ca(2), &[]).expect("t2");
    let (t3, _) = s.emit(P1, &doc2(), &bh4_ty(), &ca(3), &[]).expect("t3");
    // Two idem⊥ Multi tuples so an UNFENCED batch would have stale targets.
    let (m1, _) = s.emit(P1, &doc2(), &multi_ty(), &ca(4), &[]).expect("m1");
    {
        let snap = k.snapshot();
        let ls = snap.world().links();
        // age = home-relative chain distance (ordinal time): count 4 so far.
        assert_eq!(ls.age(&t1), Some(3));
        assert_eq!(ls.age(&t3), Some(1));
        assert_eq!(ls.age(&m1), Some(0));
        assert_eq!(ls.age(&ca(1)), None); // non-resident ⇒ None
        // stale = age > h over the ACTIVE type slice, BH4-registered only.
        assert_eq!(ls.stale(&bh4_ty(), 2).expect("BH4-registered"), vec![t1.clone()]);
        assert_eq!(
            ls.stale(&bh4_ty(), 1).expect("BH4-registered"),
            vec![t1.clone(), t2.clone()]
        );
        // Served only where declared: a non-BH4 ty is a typed rejection —
        // its tuples have positive ages, but an empty stale set is never
        // conflated with "not a BH4 type".
        assert_eq!(ls.stale(&multi_ty(), 0), Err(NotBh4));
        assert_eq!(ls.stale(&sup, 0), Err(NotBh4));
    }
    // The batch nullifier rejects a non-BH4 ty PRE-TRANSACT: typed refusal,
    // no transaction, no effect (the fence that keeps it from ever being
    // aimed at an idem⊤/other class to mass-nullify).
    let before = k.current_seq();
    assert!(matches!(
        s.retract_stale(P1, &doc2(), &multi_ty(), 0),
        Err(TxnError::Rejected(RetractStaleError::NotBh4))
    ));
    assert!(matches!(
        s.retract_stale(P1, &doc2(), &sup, 0),
        Err(TxnError::Rejected(RetractStaleError::NotBh4))
    ));
    // A constituent nullify's rejection lifts through Nullify (nothing
    // committed here either: the first nullify rejects on P0).
    assert!(matches!(
        s.retract_stale(P1, &a(&[1, 0, 1, 0, 7]), &bh4_ty(), 2),
        Err(TxnError::Rejected(RetractStaleError::Nullify(
            NullifyError::HomeNotRegistered
        )))
    ));
    assert_eq!(k.current_seq(), before);
    // On a BH4 ty it nullifies exactly the stale set snapshotted at entry.
    let out = s.retract_stale(P1, &doc2(), &bh4_ty(), 2).expect("batch");
    assert_eq!(out.len(), 1);
    let snap = k.snapshot();
    let ls = snap.world().links();
    assert!(ls.is_nullified(&t1));
    assert!(!ls.is_nullified(&t2));
    assert!(!ls.is_nullified(&t3));
}

#[test]
fn retired_filter_rewrites_default_views_only() {
    let k = kernel();
    let s = store(&k);
    let snap0 = k.snapshot();
    let retired = snap0
        .world()
        .links()
        .reserved_type(ShippedType::Retired)
        .clone();
    s.emit(P1, &doc1(), &multi_ty(), &ca(1), &[ca(2)]).expect("relation");
    {
        let snap = k.snapshot();
        assert!(!snap.world().links().is_filtered(ca(1).tumbler()));
    }
    // Retire ca(1) through the shipped Unary/idem⊤ BH1 class.
    s.emit(P1, &doc1(), &retired, &ca(1), &[]).expect("retire ca1");
    let snap = k.snapshot();
    let ls = snap.world().links();
    assert!(ls.is_filtered(ca(1).tumbler()));
    assert!(!ls.is_filtered(ca(2).tumbler()));
    // T-wide probe: any tumbler under a retired root is filtered, address
    // or not.
    assert!(ls.is_filtered(&t(&[1, 0, 1, 0, 1, 0, 1, 1, 7])));
    // Default = active ∖ filtered — on members/targets_of only.
    assert_eq!(ls.members(&multi_ty(), View::Active), vec![ca(1)]);
    assert!(ls.members(&multi_ty(), View::Default).is_empty());
    assert_eq!(ls.targets_of(&multi_ty(), &ca(1), View::Default), vec![ca(2)]);
    // is_k is never filtered (BH1 Rewrite scope).
    assert!(ls.is_k(&multi_ty(), ca(1).tumbler()));
    // J ≠ K′: the filter class itself is not self-subtracted.
    assert_eq!(ls.members(&retired, View::Default), vec![ca(1)]);
}

#[test]
fn bh3_reverse_family_is_exact_over_the_active_typed_slice() {
    let k = kernel();
    let s = store(&k);
    s.emit(P1, &doc1(), &bh3_ty(), &ca(1), &[ca(2)]).expect("bh3 tuple");
    // A same-source tuple of ANOTHER type must not disturb the typed reads.
    s.emit(P1, &doc1(), &rel_ty(), &ca(1), &[ca(3)]).expect("rel tuple");
    {
        let snap = k.snapshot();
        let ls = snap.world().links();
        assert_eq!(ls.target_of(&bh3_ty(), &ca(1)), Some(ca(2)));
        assert_eq!(ls.sources_to(&bh3_ty(), &ca(2)), vec![ca(1)]);
        // targets_keyed joins BH3-registered Binary types only, keyed by the
        // public coverage_class.
        let keyed = ls.targets_keyed(&ca(1));
        assert_eq!(keyed.len(), 1);
        assert_eq!(
            keyed.get(&skep_links::coverage_class(&bh3_ty())),
            Some(&ca(2))
        );
    }
    // A second active tuple of the same class denoting the same source makes
    // target_of ⊥ ("exactly one active K-tuple").
    s.emit(P1, &doc1(), &bh3_ty(), &ca(1), &[ca(4)]).expect("second bh3 tuple");
    let snap = k.snapshot();
    let ls = snap.world().links();
    assert_eq!(ls.target_of(&bh3_ty(), &ca(1)), None);
    assert!(ls.targets_keyed(&ca(1)).is_empty());
}

#[test]
fn checkpoint_roundtrip_then_rebuild_derived_restores_every_hint() {
    let k = kernel();
    let s = store(&k);
    let snap0 = k.snapshot();
    let sup = snap0
        .world()
        .links()
        .reserved_type(ShippedType::Supersedes)
        .clone();
    let (a1, _) = s.emit(P1, &doc1(), &rel_ty(), &ca(1), &[ca(2)]).expect("rel");
    let (m1, _) = s.emit(P1, &doc1(), &multi_ty(), &ca(1), &[ca(3)]).expect("m1");
    let (m2, _) = s.emit(P1, &doc1(), &multi_ty(), &ca(1), &[ca(4)]).expect("m2");
    let (c, _) = s.assert_sup(P1, &doc1(), &m1, &m2).expect("claim");
    s.nullify(P1, &doc1(), &m1).expect("nullify m1");

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
        orig.type_slice(&rel_ty(), View::Audit),
        back.type_slice(&rel_ty(), View::Audit)
    );
    assert_eq!(
        orig.type_slice(&multi_ty(), View::Active),
        back.type_slice(&multi_ty(), View::Active)
    );

    // The dedup hint is rebuilt too: a kernel opened over the recovered world
    // dedups the same idem⊤ emission to the ORIGINAL incumbent.
    let cfg = skep_kernel::KernelConfig {
        durability: skep_kernel::Durability::InMemory,
        checkpoint: skep_kernel::CheckpointPolicy::Manual,
    };
    let k2 = skep_kernel::Kernel::open(cfg, recovered).expect("reopen");
    let s2 = store(&k2);
    let (again, _) = s2.emit(P1, &doc1(), &rel_ty(), &ca(1), &[ca(2)]).expect("dedup hit");
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
    let s = store(&k);
    let p2 = P2;
    let (x, _) = s.emit(P1, &doc1(), &multi_ty(), &ca(1), &[ca(2)]).expect("x");
    let (y, _) = s.emit(P1, &doc1(), &multi_ty(), &ca(1), &[ca(3)]).expect("y");
    let before = k.current_seq();
    assert!(matches!(
        s.makelink(
            p2,
            &doc1(),
            SlotArg::Resolve(vec![]),
            SlotArg::Resolve(vec![]),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 1, 1)])
        ),
        Err(TxnError::Rejected(MakeLinkError::NotOwner(d))) if d == doc1()
    ));
    assert!(matches!(
        s.emit(p2, &doc1(), &rel_ty(), &ca(1), &[ca(2)]),
        Err(TxnError::Rejected(EmitError::NotOwner(d))) if d == doc1()
    ));
    assert!(matches!(
        s.assert_sup(p2, &doc1(), &x, &y),
        Err(TxnError::Rejected(AssertSupError::NotOwner(d))) if d == doc1()
    ));
    let succ = Link::new([enc(&[ca(3)]), enc(&[ca(4)]), enc(&[ra(30)])]).expect("arity 3");
    // Foreign d_s (successor home): the error names d_s.
    assert!(matches!(
        s.editlink(p2, &x, succ.clone(), &doc1(), &sib_doc()),
        Err(TxnError::Rejected(EditLinkError::NotOwner(d))) if d == doc1()
    ));
    // Foreign d_a (claim home): the error names d_a.
    assert!(matches!(
        s.editlink(p2, &x, succ, &sib_doc(), &doc1()),
        Err(TxnError::Rejected(EditLinkError::NotOwner(d))) if d == doc1()
    ));
    assert_eq!(k.current_seq(), before, "ownership rejections leave no state change");
    // System bypasses the gate (M9 ⟂ M10 — rule fires carry no principal).
    s.emit(Caller::System, &doc1(), &rel_ty(), &ca(1), &[ca(2)])
        .expect("the automation path deposits ungated");
}

#[test]
fn ownership_gate_holds_on_the_idem_hit_path() {
    // Like the hoisted home check, ω is enforced on hit AND miss: a foreign
    // emit whose tuple already exists still rejects NotOwner — the caller
    // cannot observe the dedup branch through the rejection.
    let k = kernel();
    let s = store(&k);
    let p2 = P2;
    s.emit(P1, &doc1(), &rel_ty(), &ca(1), &[ca(2)]).expect("incumbent");
    assert!(matches!(
        s.emit(p2, &doc1(), &rel_ty(), &ca(1), &[ca(2)]),
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
    let s = store(&k);
    let p2 = P2;
    let (m1, _) = s.emit(P1, &doc1(), &multi_ty(), &ca(1), &[ca(2)]).expect("P1's tuple");
    // Foreign target, owned home: NotOwner carrying the target link.
    assert!(matches!(
        s.nullify(p2, &sib_doc(), &m1),
        Err(TxnError::Rejected(NullifyError::NotOwner(d))) if d == m1
    ));
    // Foreign home is rejected first, naming the home.
    assert!(matches!(
        s.nullify(p2, &doc1(), &m1),
        Err(TxnError::Rejected(NullifyError::NotOwner(d))) if d == doc1()
    ));
    {
        let snap = k.snapshot();
        assert!(snap.world().links().is_active(&m1), "no foreign retraction landed");
    }
    // The owner's own retraction: active view filtered, audit retains.
    s.nullify(P1, &doc1(), &m1).expect("owner retraction");
    let snap = k.snapshot();
    let ls = snap.world().links();
    assert!(ls.is_nullified(&m1));
    assert!(ls.readlink(&m1).is_some());
    assert!(ls.type_slice(&multi_ty(), View::Audit).contains(m1.tumbler()));
    assert!(!ls.type_slice(&multi_ty(), View::Active).contains(m1.tumbler()));
}
