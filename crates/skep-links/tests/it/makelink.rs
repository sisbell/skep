//! MAKELINK, the open surface, over a real kernel (InMemory): end to end —
//! wf over every slot's specs, multi-spec resolution, deposit, seat — the
//! address form recorded verbatim, the I-span form recorded verbatim under
//! its content clause and reading nothing of the document it names (the
//! read check's store channel and its counting cell, W6 (a)), the ratio a
//! `Resolve` slot amplifies by, and the slot argument's equality.

use crate::common;
use crate::heap::settled_heap_bytes;

use common::*;
use skep_address::{subtree_of, Span, SpanSet};
use skep_arrangement::HasM5;
use skep_kernel::TxnError;
use skep_links::{
    enc, replaces_type, slot_endset, Endset, HasLinks, MakeLinkError, SlotArg, View, FROM,
    MAX_SLOT_SPANS, TO, TYPE,
};

/// The I-extent of content positions `lo..hi` of the document `doc` spells —
/// [`iext`] for a document other than doc1. Half-open, as [`iext`] is.
fn iext_in(doc: &[u32], lo: u32, hi: u32) -> Span {
    let pos = |k: u32| {
        let mut comps = doc.to_vec();
        comps.extend([0, 1, k]);
        a(&comps)
    };
    Span::from_endpoints(pos(lo).tumbler().clone(), pos(hi).tumbler()).expect("test extents are well-formed")
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
    // The third form is a form of its own: the same spans, asked for as
    // I-spans, are not the V-specs that would resolve to them.
    assert_eq!(SlotArg::Spans(vec![iext(1, 2)]), SlotArg::Spans(vec![iext(1, 2)]));
    assert_ne!(SlotArg::Spans(vec![]), SlotArg::Addrs(vec![]));
    assert_ne!(SlotArg::Spans(vec![]), SlotArg::Resolve(vec![]));
    assert_ne!(SlotArg::Spans(vec![iext(1, 2), iext(2, 3)]), SlotArg::Spans(vec![iext(2, 3), iext(1, 2)]));
    assert_eq!(SlotArg::from(vec![spec(&doc1(), 1, 1, 1)]), SlotArg::Resolve(vec![spec(&doc1(), 1, 1, 1)]));
}

/// THE I-SPAN FORM (the link-sets ruling W6 (a)): a `Spans` slot deposits
/// its content I-spans VERBATIM — the shape a `Resolve` slot over the same
/// positions stores, so the two content forms meet in one stored endset —
/// in argument order, un-coalesced, and with NO SOURCE: the document the
/// spans name is never consulted, so positions past doc1's frontier and
/// positions of a document no one registered deposit exactly as doc1's own
/// occupied positions do, and read back as given (the address form's "no
/// occupancy requirement", widened to a run). A width-1 content span is the
/// position's own unit span and deposits too.
#[test]
fn makelink_ispan_form_records_content_spans_verbatim_and_consults_no_document() {
    let k = kernel();
    seed_content(&k, &doc1(), 3); // content elements ca(1)..ca(3)
    let w = writer(&k);
    let ty = || SlotArg::Addrs(vec![unregistered_ta(10)]);

    // doc1's own occupied positions, as I-spans and as the V-spec that
    // resolves to them: one stored shape.
    let (by_spans, _) = w
        .makelink(P1, &doc1(), SlotArg::Spans(vec![iext(1, 3)]), SlotArg::Spans(vec![]), ty())
        .expect("the I-span form deposits");
    let (by_specs, _) = w
        .makelink(P1, &doc1(), SlotArg::Resolve(vec![spec(&doc1(), 1, 1, 2)]), SlotArg::Resolve(vec![]), ty())
        .expect("the V-spec form deposits");
    {
        let snap = k.snapshot();
        let links = snap.world().links();
        let spans = links.readlink(&by_spans).expect("resident");
        let specs = links.readlink(&by_specs).expect("resident");
        assert_eq!(spans.from_slot(), &Endset::from_spans([iext(1, 3)]), "the spans as given");
        assert_eq!(spans.from_slot(), specs.from_slot(), "one stored shape across the two content forms");
        assert_eq!(spans.to_slot(), &Endset::empty(), "an empty I-span slot is ⟨⟩");
        assert_eq!(links.followlink(&by_spans, 1), Ok(SpanSet::singleton(iext(1, 3))));
        assert_eq!(snap.world().m5().link_count(&doc1()), n(2), "both seated");
    }

    // Ghosts past doc1's frontier, and a document no one registered: valid
    // names, nothing consulted. doc2 is registered but unarranged — its
    // positions are ghosts too.
    let elsewhere = iext_in(&[1, 0, 1, 0, 7], 1, 4);
    for (label, span) in [
        ("past the frontier", iext(9, 12)),
        ("an unregistered document", elsewhere),
        ("a registered, unarranged document", iext_in(&[1, 0, 1, 0, 2], 1, 2)),
    ] {
        let (l, _) = w
            .makelink(P1, &doc1(), SlotArg::Spans(vec![span.clone()]), SlotArg::Spans(vec![span.clone()]), ty())
            .unwrap_or_else(|e| panic!("{label}: no registration or occupancy check: {e:?}"));
        let snap = k.snapshot();
        let link = snap.world().links().readlink(&l).expect("resident");
        assert_eq!(link.from_slot(), &Endset::from_spans([span.clone()]), "{label}");
        assert_eq!(link.to_slot(), &Endset::from_spans([span]), "{label}");
    }

    // Several spans: argument order, un-coalesced, a width-1 span among them.
    let (l, _) = w
        .makelink(
            P1,
            &doc1(),
            SlotArg::Spans(vec![iext(2, 3), subtree_of(ca(1).tumbler()), iext(1, 3)]),
            SlotArg::Spans(vec![]),
            ty(),
        )
        .expect("several spans");
    let snap = k.snapshot();
    assert_eq!(
        snap.world().links().readlink(&l).expect("resident").from_slot(),
        &Endset::from_spans([iext(2, 3), subtree_of(ca(1).tumbler()), iext(1, 3)]),
        "argument order, un-coalesced, the unit span kept as given"
    );
    assert_eq!(subtree_of(ca(1).tumbler()), iext(1, 2), "a width-1 content span IS the position's unit span");
}

/// THE CONTENT CLAUSE (the wire-lane decision 5, REQUIRED): a span of a
/// `Spans` slot is admitted iff it is a content I-span — its start a
/// CONTENT-subspace element position `Run::new` admits, its width the
/// ordinal displacement of at least one position at the start's own length
/// — decided on the span's bytes alone, refused by slot and index, nothing
/// committed. Each row below breaks one clause; the subspace-3 rows are the
/// ones the clause exists for — a credential type's and the `replaces`
/// class's unit spans have the I-span shape, and without the clause a slot
/// spelling one would reach the plain path as a deposit the credential and
/// registry classifiers, which read the address form alone, never judged.
#[test]
fn makelink_ispan_form_admits_exactly_the_content_ispan_shape() {
    let k = kernel();
    seed_content(&k, &doc1(), 3);
    let w = writer(&k);
    let ty = || SlotArg::Addrs(vec![unregistered_ta(10)]);
    let before = k.current_seq();
    let span = |start: &[u32], width: &[u32]| Span::new(t(start), t(width)).expect("T12-valid");
    let rows = [
        ("a link-subspace element", subtree_of(la(1).tumbler())),
        ("a document address", subtree_of(doc1().tumbler())),
        ("an account address", subtree_of(a(&[1, 0, 1]).tumbler())),
        ("a subspace-3 type address — the enroll credential's", subtree_of(a(&[1, 1, 0, 1, 0, 1, 0, 3, 1]).tumbler())),
        ("the replaces class", subtree_of(replaces_type().tumbler())),
        ("a width crossing the subspace (no ordinal displacement)", span(&[1, 0, 1, 0, 1, 0, 1, 1], &[0, 0, 0, 0, 0, 0, 1, 0])),
        ("a width with a nonzero interior component", span(&[1, 0, 1, 0, 1, 0, 1, 1], &[0, 0, 0, 0, 0, 0, 1, 2])),
        ("a width shorter than its start (not level-uniform)", span(&[1, 0, 1, 0, 1, 0, 1, 1], &[0, 2])),
        ("a start that is no T4-valid address", span(&[1, 0, 0, 1, 0, 1, 1], &[0, 0, 0, 0, 0, 0, 2])),
    ];
    for (label, bad) in rows {
        let got = w.makelink(P1, &doc1(), SlotArg::Spans(vec![iext(1, 2), bad.clone()]), SlotArg::Spans(vec![]), ty());
        assert!(
            matches!(got, Err(TxnError::Rejected(MakeLinkError::NotContentSpan { slot: FROM, index: 1 }))),
            "{label}: {got:?}"
        );
    }
    // The slot is named in declared order, the span by its index: the TO
    // slot's second span, then the TYPE slot's first.
    let got = w.makelink(
        P1,
        &doc1(),
        SlotArg::Spans(vec![iext(1, 2)]),
        SlotArg::Spans(vec![iext(2, 3), subtree_of(la(1).tumbler())]),
        ty(),
    );
    assert!(matches!(got, Err(TxnError::Rejected(MakeLinkError::NotContentSpan { slot: TO, index: 1 }))), "{got:?}");
    let got = w.makelink(
        P1,
        &doc1(),
        SlotArg::Spans(vec![]),
        SlotArg::Spans(vec![]),
        SlotArg::Spans(vec![subtree_of(a(&[1, 1, 0, 1, 0, 1, 0, 3, 1]).tumbler())]),
    );
    assert!(matches!(got, Err(TxnError::Rejected(MakeLinkError::NotContentSpan { slot: TYPE, index: 0 }))), "{got:?}");
    // Precedence: the home gate, then a Resolve spec's wf, ahead of the
    // clause — a stranger to the home is told that, and an ill-formed spec
    // speaks before an ill-formed span.
    assert!(matches!(
        w.makelink(P2, &doc1(), SlotArg::Spans(vec![subtree_of(la(1).tumbler())]), SlotArg::Spans(vec![]), ty()),
        Err(TxnError::Rejected(MakeLinkError::NotOwner(_)))
    ));
    assert!(matches!(
        w.makelink(
            P1,
            &doc1(),
            SlotArg::Resolve(vec![spec(&doc1(), 2, 1, 1)]),
            SlotArg::Spans(vec![subtree_of(la(1).tumbler())]),
            ty()
        ),
        Err(TxnError::Rejected(MakeLinkError::IllFormedSpec))
    ));
    assert_eq!(k.current_seq(), before, "every refusal is pre-deposit");
}

/// The I-span form's budget: a `Spans` slot is held to [`MAX_SLOT_SPANS`]
/// as the other two forms are — at the budget it deposits whole, one past
/// it is `SlotTooLarge` — and the count is the request's own.
#[test]
fn an_ispan_slot_is_held_to_the_span_budget() {
    let k = kernel();
    seed_content(&k, &doc1(), 3);
    let w = writer(&k);
    let ty = || SlotArg::Addrs(vec![unregistered_ta(10)]);
    let spans = |count: usize| vec![iext(1, 2); count];
    let (at, _) = w
        .makelink(P1, &doc1(), SlotArg::Spans(spans(MAX_SLOT_SPANS)), SlotArg::Spans(vec![]), ty())
        .expect("a slot at the budget");
    assert_eq!(k.snapshot().world().links().readlink(&at).expect("resident").from_slot().len(), MAX_SLOT_SPANS);
    assert!(matches!(
        w.makelink(P1, &doc1(), SlotArg::Spans(spans(MAX_SLOT_SPANS + 1)), SlotArg::Spans(vec![]), ty()),
        Err(TxnError::Rejected(MakeLinkError::SlotTooLarge))
    ));
}

/// THE READ CHECK's COUNTING CELL (W6 (a); the daemon's `ispan_slot` suite
/// holds the wire's channels, this the store's, in the home-index suites'
/// allocation-counting form): the `Spans` path reads NOTHING of the world —
/// no `is_registered_document`, no `iter_resolve`, no content read — so the
/// heap bytes of building a `Spans` slot's endset are exactly the bytes of
/// copying the request's spans into an endset, and the same figure over a
/// document that is registered and arranged with the named positions
/// occupied (i), past its frontier (ii), one no one registered (iii) and the
/// writer's own (iv). The shape check costs the same across the four too.
/// A mutant that consulted the document — `document_of` of a start for a
/// registry lookup, a resolve, a byte read — allocates the address it
/// derives or the runs it pulls, and the figure moves off the baseline.
#[test]
fn building_an_ispan_slot_costs_exactly_the_endset_it_stores_whatever_the_world_holds() {
    let k = kernel();
    seed_content(&k, &doc1(), 3);
    seed_content(&k, &doc2(), 2);
    let snap = k.snapshot();
    let m5 = snap.world().m5();
    let cases = [
        ("(i) a registered, arranged document's occupied positions", iext(1, 3)),
        ("(ii) ghosts past that document's frontier", iext(9, 11)),
        ("(iii) a document no one registered", iext_in(&[1, 0, 1, 0, 7], 1, 3)),
        ("(iv) the writer's own home's positions", iext_in(&[1, 0, 1, 0, 2], 1, 3)),
    ];
    let mut figures = Vec::new();
    for (label, span) in cases {
        let spans = vec![span.clone(), span];
        let baseline = settled_heap_bytes(|| Endset::from_spans(spans.iter().cloned())).1;
        let arg = SlotArg::Spans(spans.clone());
        let (built, bytes) = settled_heap_bytes(|| slot_endset(m5, &arg));
        assert_eq!(built, Some(Endset::from_spans(spans.iter().cloned())), "{label}: the spans as given");
        assert_eq!(bytes, baseline, "{label}: the slot costs its endset and nothing more — no read of the world");
        let (fault, shape_bytes) = settled_heap_bytes(|| SlotArg::ill_formed_span(&spans));
        assert_eq!(fault, None, "{label}: content I-spans pass the clause");
        figures.push((bytes, shape_bytes));
    }
    assert!(
        figures.iter().all(|f| *f == figures[0]),
        "one figure across the four worlds — the path reads none of them: {figures:?}"
    );
}

/// THE READ CHECK's COUNTING CELL, THE SOURCE: the two heap cells beside
/// this one cannot see a registry lookup that allocates nothing — M3's
/// `is_registered_document` is a map probe — so the `Spans` path is held to
/// its promise as text too: the store's three sites of the form (the shape
/// check, its per-span test, and `slot_endset`'s `Spans` arm) name no world
/// accessor — no `m3()`, `m5()`, `is_registered_document`, `iter_resolve`,
/// `content_run_count` or `readlink` — between their markers. A mutant that
/// consults the spans' document at any of the three reddens this cell; one
/// that moves the path out from under its markers reddens the marker checks
/// (SP-29: a reader that finds nothing fails).
#[test]
fn the_stores_spans_path_names_no_world_accessor() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/writes/makelink.rs");
    let text = std::fs::read_to_string(path).expect("makelink.rs is readable");
    let region = |open: &str| -> &str {
        let start = text.find(open).unwrap_or_else(|| panic!("the marker {open:?} stands in makelink.rs"));
        let body = &text[start + open.len()..];
        // The region ends at the first closing brace at the marker's own
        // indentation or less — the block's own close.
        let indent = open.trim_start_matches('\n').chars().take_while(|c| *c == ' ').count();
        let close = body
            .match_indices('\n')
            .map(|(i, _)| i)
            .find(|&i| {
                let line = &body[i + 1..];
                let lead = line.chars().take_while(|c| *c == ' ').count();
                line.trim_start().starts_with('}') && lead <= indent
            })
            .unwrap_or_else(|| panic!("the block opened by {open:?} closes"));
        &body[..close]
    };
    let accessors = ["m3()", "m5()", "is_registered_document", "iter_resolve", "content_run_count", "readlink"];
    for (what, open) in [
        ("the per-span test", "\nfn is_content_ispan(span: &Span) -> bool {"),
        ("the shape check", "\n    pub fn ill_formed_span(spans: &[Span]) -> Option<usize> {"),
        ("the store's Spans loop", "\n            if let SlotArg::Spans(spans) = arg {"),
        ("slot_endset's Spans arm", "\n        SlotArg::Spans(spans) => {"),
    ] {
        let body = region(open);
        assert!(!body.trim().is_empty(), "{what}: the region holds code");
        for accessor in accessors {
            assert!(!body.contains(accessor), "{what} reads the world through `{accessor}`:\n{body}");
        }
    }
}

/// THE READ CHECK's COUNTING CELL, THE WHOLE WRITE: the heap bytes a
/// `makelink` with a `Spans` slot asks for are the same whether the spans
/// name (i) a registered document's occupied positions, (ii) ghosts past its
/// frontier, (iii) a document no one registered or (iv) the home's own —
/// four kernels built alike, one write each, after a warm-up that pays
/// every process-wide lazy once. A registration or occupancy check of the
/// spans' document anywhere on the write's path — the store's `stage_record`
/// included — would read a different structure in (i) than in (iii) and
/// allocate for the address it derives, and the four figures would part.
#[test]
fn a_makelink_in_the_ispan_form_costs_the_same_whatever_its_spans_name() {
    let world = || {
        let k = kernel();
        seed_content(&k, &doc1(), 3);
        seed_content(&k, &doc2(), 2);
        k
    };
    let ty = || SlotArg::Addrs(vec![unregistered_ta(10)]);
    let write = |k: &skep_kernel::Kernel<World>, span: Span| {
        writer(k)
            .makelink(P1, &doc2(), SlotArg::Spans(vec![span.clone()]), SlotArg::Spans(vec![span]), ty())
            .expect("the write lands")
    };
    // The warm-up: the registry, the class constants and every other
    // process-wide lazy are paid here, on a kernel the figures never read.
    write(&world(), iext(1, 3));
    let cases = [
        ("(i) a registered, arranged document's occupied positions", iext(1, 3)),
        ("(ii) ghosts past its frontier", iext(9, 11)),
        ("(iii) a document no one registered", iext_in(&[1, 0, 1, 0, 7], 1, 3)),
        ("(iv) the home's own positions", iext_in(&[1, 0, 1, 0, 2], 1, 3)),
    ];
    let figures: Vec<(&str, u64)> = cases
        .iter()
        .map(|(label, span)| {
            let k = world();
            let (_, bytes) = crate::heap::heap_bytes(|| write(&k, span.clone()));
            (*label, bytes)
        })
        .collect();
    assert!(
        figures.iter().all(|(_, bytes)| *bytes == figures[0].1),
        "one figure across the four worlds — the write reads nothing of the spans' document: {figures:?}"
    );
}
