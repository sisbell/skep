//! MAKELINK, the open surface, over a real kernel (InMemory): end to end —
//! wf over every slot's specs, multi-spec resolution, deposit, seat — the
//! address form recorded verbatim, the ratio a `Resolve` slot amplifies by,
//! and the slot argument's equality.

use crate::common;

use common::*;
use skep_address::SpanSet;
use skep_arrangement::HasM5;
use skep_kernel::TxnError;
use skep_links::{enc, Endset, HasLinks, MakeLinkError, SlotArg, View};

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
        // READLINK's own ⊥: total, `None` on absence — the branch an
        // unauthenticated wire `read_link` on a ghost address takes, and the
        // one the infallible `link_at` twin would turn into a panic.
        assert!(links.readlink(&la(9)).is_none());
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
