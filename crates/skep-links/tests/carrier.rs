//! Carrier-type and registry contracts, stated by the documents: the Link
//! arity floor, the 1-based slot range and the whole-value slot walk, Endset
//! readback (verbatim decomposition, `enc(X).addrs() = X` over every subset
//! of a family, ⟨⟩ distinctness), coverage-class identity (exact denoted
//! antichain; conservative extent partition, keyed per `#start` so a
//! mixed-length endset classifies rather than aborts; invariance under span
//! permutation; structural derives ≠ coverage identity; the pinned
//! off-contract panic and the address-denoting projection a caller discharges
//! it with), the five shipped registrations §B pins over the compiled
//! ghost-tumbler constants (owner ruling, 2026-08-26 — the decl rejection
//! matrix went with the retired `GenesisConfig` seam), the module registry
//! every assembler shares, and the serde/journal round trips. (The fold's
//! freshness gate is watched from inside the crate: the one store invariant
//! that would otherwise fail silently is witnessed by a deposit no foreign
//! crate can construct.)

mod common;

use std::collections::BTreeSet;

use common::*;
use skep_address::Span;
use skep_links::{
    coverage_class, enc, Behavior, CoverageClass, Endset, Link, LinkState, Registration, Shape,
    ShippedType, TypeRegistry, FROM, TO, TYPE,
};

fn span(from: &skep_address::Address, to: &skep_address::Address) -> Span {
    Span::from_endpoints(from.tumbler().clone(), to.tumbler())
        .expect("test spans are well-formed")
}

#[test]
fn link_enforces_only_the_arity_floor_with_one_based_slots() {
    // Link::new: None ⇔ arity < 3 (the type floor; e₃ ≠ ∅ is a write-boundary
    // check, not the type's).
    assert!(Link::new([Endset::empty(), Endset::empty()]).is_none());
    let l = Link::new([enc(&[ca(1)]), Endset::empty(), enc(&[ra(10)])])
        .expect("arity 3 is admitted, empty slots included");
    assert_eq!(l.arity(), 3);
    // slot(i) is 1-based, and the published numerals name exactly the three
    // positional accessors: None iff i < 1 ∨ i > arity.
    assert!(l.slot(0).is_none());
    assert!(l.slot(4).is_none());
    assert_eq!(l.slot(FROM), Some(l.from_slot()));
    assert_eq!(l.slot(TO), Some(l.to_slot()));
    assert_eq!(l.slot(TYPE), Some(l.type_slot()));
    // Arity > 3 is admitted by the TYPE (L3 capacity)...
    let wide = Link::new(vec![Endset::empty(); 4]).expect("capacity admits arity 4");
    assert_eq!(wide.arity(), 4);
}

#[test]
fn triple_is_the_creation_shape_and_needs_no_arity_discharge() {
    // The store's one creation shape, infallible: same value the general
    // constructor yields, with no Option for a caller to discharge.
    let (f, g, ty) = (enc(&[ca(1)]), enc(&[ca(2)]), enc(&[ra(10)]));
    let triple = Link::triple(f.clone(), g.clone(), ty.clone());
    assert_eq!(triple.arity(), 3);
    assert_eq!(Link::new([f, g, ty]), Some(triple.clone()));
    assert_eq!(triple.from_slot(), &enc(&[ca(1)]));
    assert_eq!(triple.to_slot(), &enc(&[ca(2)]));
    assert_eq!(triple.type_slot(), &enc(&[ra(10)]));
    // Empty slots are the type's business only at the arity floor: triple
    // admits ⟨⟩ anywhere, and e₃ ≠ ∅ stays a write-boundary check.
    assert!(Link::triple(Endset::empty(), Endset::empty(), Endset::empty())
        .type_slot()
        .is_empty());
}

#[test]
fn enc_reads_addresses_from_any_shape_of_argument() {
    // A slice, an owned Vec's borrow and a one-address array name the same
    // encoding — the single-address call needs no slice dance.
    let one = [ca(1)];
    let owned = vec![ca(1)];
    assert_eq!(enc(&one), enc([&ca(1)]));
    assert_eq!(enc(&owned), enc([&ca(1)]));
    assert_eq!(enc(one.as_slice()), enc([&ca(1)]));
}

#[test]
fn endset_reads_back_verbatim_and_enc_round_trips() {
    // ⟨⟩ basics.
    assert!(Endset::empty().is_empty());
    assert_eq!(Endset::empty().len(), 0);
    // from_spans is verbatim: decomposition and order preserved.
    let s1 = span(&ca(1), &ca(3));
    let s2 = span(&ca(5), &ca(6));
    let e = Endset::from_spans([s1.clone(), s2.clone()]);
    let read: Vec<&Span> = e.spans().collect();
    assert_eq!(read, vec![&s1, &s2]);
    // covers is the half-open coverage projection.
    assert!(e.covers(ca(1).tumbler()));
    assert!(e.covers(ca(2).tumbler()));
    assert!(!e.covers(ca(3).tumbler()));
    assert!(e.covers(ca(5).tumbler()));
    // enc(X).addrs() = X (order preserved, unit-depth spans only).
    let x = [ca(2), ca(7)];
    let got: Vec<_> = enc(&x).addrs().cloned().collect();
    assert_eq!(got, vec![ca(2).tumbler().clone(), ca(7).tumbler().clone()]);
    // A non-unit span contributes nothing to addrs(); a unit span does.
    let mixed = Endset::from_spans(
        [span(&ca(1), &ca(3))]
            .into_iter()
            .chain(enc(&[ca(9)]).spans().cloned()),
    );
    let addrs: Vec<_> = mixed.addrs().cloned().collect();
    assert_eq!(addrs, vec![ca(9).tumbler().clone()]);
}

#[test]
fn derived_equality_is_structural_never_coverage() {
    // Two coverage-equal address-denoting endsets in different span order:
    // UNEQUAL under the derived Eq (structural — serde/container plumbing
    // only), EQUAL under coverage_class (the identity every seam keys on).
    let ab = enc(&[ca(1), ca(2)]);
    let ba = enc(&[ca(2), ca(1)]);
    assert_ne!(ab, ba);
    assert_eq!(coverage_class(&ab), coverage_class(&ba));
}

#[test]
fn coverage_class_addrs_is_the_minimal_antichain() {
    // Duplicates collapse.
    assert_eq!(
        coverage_class(&enc(&[ca(1), ca(1)])),
        coverage_class(&enc(&[ca(1)]))
    );
    // A denoted address under another denoted prefix is dropped (I0a): doc1
    // is a prefix of its own content element.
    assert_eq!(
        coverage_class(&enc(&[doc1(), ca(5)])),
        coverage_class(&enc(&[doc1()]))
    );
    // Distinct classes stay distinct.
    assert_ne!(
        coverage_class(&enc(&[ca(1)])),
        coverage_class(&enc(&[ca(2)]))
    );
}

#[test]
fn coverage_class_extents_is_canonical_per_length_and_variant_distinct() {
    // Same coverage, different decompositions (both containing a non-unit
    // span): one extent class (canonical form merges the adjacent split).
    let whole = Endset::from_spans([span(&ca(1), &ca(4))]);
    let split = Endset::from_spans([span(&ca(1), &ca(3)), span(&ca(3), &ca(4))]);
    assert_ne!(whole, split); // structural
    assert_eq!(coverage_class(&whole), coverage_class(&split));
    // An all-unit decomposition of the SAME coverage lands in the denoted
    // regime — a different class, deliberately distinct (over-discrimination
    // is the safe direction; class coherence keeps every guard and fold on
    // the same verdict).
    let units = enc(&[ca(1), ca(2), ca(3)]);
    assert_ne!(coverage_class(&units), coverage_class(&whole));
    assert!(coverage_class(&units).denoted().is_some());
    assert!(coverage_class(&whole).denoted().is_none());
    // A width-1 iextent IS the unit span: single content addresses land in
    // the exact denoted path.
    let one = Endset::from_spans([span(&ca(3), &ca(4))]);
    assert_eq!(coverage_class(&one), coverage_class(&enc(&[ca(3)])));
}

#[test]
#[should_panic(expected = "level-uniform")]
fn coverage_class_panics_on_an_off_contract_span() {
    // The design's pinned off-contract behavior: a hand-built
    // non-level-uniform span (T12-valid ([5,3],[0,2,7])) PANICS — never a
    // skipped span, never a coarser class.
    let s = Span::new(t(&[5, 3]), t(&[0, 2, 7])).expect("T12 admits this span");
    let _ = coverage_class(&Endset::from_spans([s]));
}

#[test]
fn genesis_seeds_the_five_shipped_classes_at_the_format_constants() {
    let state = LinkState::genesis();
    // The five shipped endsets read back through reserved_type, at the ghost
    // tumblers the 2026-08-26 ruling pins, in its assignment order.
    for (ty, addr) in [
        (ShippedType::PredDef, ra(1)),
        (ShippedType::PredStable, ra(2)),
        (ShippedType::Retired, ra(3)),
        (ShippedType::Supersedes, ra(4)),
        (ShippedType::Retraction, ra(5)),
    ] {
        assert_eq!(state.reserved_type(ty), &enc(&[addr]));
    }
}

#[test]
fn the_published_registry_answers_before_any_rebuild() {
    // The registry an assembler SHARES instead of building a second one. It is
    // the module's compiled format constant, so it answers as the format
    // lookup on a RAW-deserialized slice — no rebuild first — which is the
    // state a recovering assembler reads it out of.
    let state = LinkState::genesis();
    let bytes = bincode::serialize(&state).expect("the slice serializes");
    let raw: LinkState = bincode::deserialize(&bytes).expect("the slice deserializes");
    for ty in ShippedType::ALL {
        let endset = skep_links::registry().reserved_type(ty);
        // Non-vacuous: each shipped type names a real endset, not ⟨⟩.
        assert!(!endset.is_empty(), "{ty:?} names a real endset");
        // A raw slice and a genesis one read the same shipped endsets,
        // because neither carries a registry to differ about.
        assert_eq!(raw.reserved_type(ty), endset, "{ty:?}");
        assert_eq!(state.reserved_type(ty), endset, "{ty:?}");
        assert!(
            skep_links::registry().registration(&coverage_class(endset)).is_some(),
            "{ty:?} is registered in the published registry"
        );
    }
    // One instance, so an assembler that clones it and the store's own fold
    // cannot come apart: agreement is a construction, not a comparison.
    assert!(std::sync::Arc::ptr_eq(skep_links::registry(), skep_links::registry()));
}

#[test]
fn shipped_types_carry_their_pinned_registrations() {
    // §B's note-pinned registrations, including the PredLayer registration
    // agreement (PredDef = PredStable = Unary/⊤/{}) — an M9-negotiated
    // constant, never a local M7 edit. The endsets are read back elsewhere;
    // these are the registrations they are seeded under.
    let reg = TypeRegistry::build();
    let unary_top = |behaviors| Registration {
        shape: Shape::Unary,
        idem: true,
        behaviors,
    };
    for (ty, want) in [
        (
            ShippedType::Retired,
            unary_top(BTreeSet::from([Behavior::ReadFilter])),
        ),
        (
            ShippedType::Supersedes,
            Registration {
                shape: Shape::Binary,
                idem: true,
                behaviors: BTreeSet::from([Behavior::Walk]),
            },
        ),
        (
            ShippedType::Retraction,
            Registration {
                shape: Shape::Binary,
                idem: true,
                behaviors: BTreeSet::new(),
            },
        ),
        (ShippedType::PredDef, unary_top(BTreeSet::new())),
        (ShippedType::PredStable, unary_top(BTreeSet::new())),
    ] {
        assert_eq!(
            reg.registration(&coverage_class(reg.reserved_type(ty))),
            Some(&want),
            "{ty:?}"
        );
    }
}

#[test]
fn is_address_denoting_answers_the_question_the_module_asks_its_callers() {
    // The published admission rule the managed surface refuses on: a caller
    // can ask it of an endset of its own making instead of learning the
    // answer from a rejection (`NonAddressDenotingType` at `emit`).
    assert!(Endset::empty().is_address_denoting()); // vacuous on ⟨⟩
    assert!(enc(&[ca(1), ra(1)]).is_address_denoting());
    assert!(!Endset::from_spans([span(&ca(1), &ca(3))]).is_address_denoting());
    let skew = Endset::from_spans([Span::new(t(&[5, 3]), t(&[0, 2, 7])).expect("T12-valid")]);
    assert!(!skew.is_address_denoting());
}

#[test]
fn is_level_uniform_is_coverage_class_s_precondition_and_denotation_is_stronger() {
    // The two tests are not interchangeable, and the difference decides
    // whether a legal input is refused: a content endset of iextent-shaped
    // spans is NOT address-denoting, IS level-uniform, and classifies without
    // panicking — so is_address_denoting over-refuses as a discharge test and
    // is_level_uniform is the one that matches the precondition exactly.
    let extent = Endset::from_spans([span(&ca(1), &ca(3))]);
    assert!(!extent.is_address_denoting());
    assert!(extent.is_level_uniform());
    assert!(
        coverage_class(&extent).denoted().is_none(),
        "a content extent classifies into the conservative partition, which denotes nothing"
    );

    // Denotation implies level-uniformity (a unit-depth span is its own
    // start's subtree, so start and width share a length) — ⟨⟩ vacuously.
    assert!(Endset::empty().is_level_uniform());
    assert!(enc(&[ca(1), ra(10)]).is_level_uniform());

    // The one input coverage_class aborts on fails BOTH, so the precondition
    // and its test agree exactly where it matters.
    let skew = Endset::from_spans([Span::new(t(&[5, 3]), t(&[0, 2, 7])).expect("T12-valid")]);
    assert!(!skew.is_address_denoting());
    assert!(!skew.is_level_uniform());
}

#[test]
fn single_denoted_is_stricter_than_the_first_denoted_address() {
    // The Df-DISC(ii) slot test M8 reads a stored claim's endpoints back
    // through, published so the reliance is on M7's rule rather than on a
    // transcription of it. It is STRICTLY stronger than `addrs().next()`, and
    // this is the whole of the difference: several DISTINCT denoted addresses
    // is ⊥, where taking the first would answer with one of them.
    let two = enc(&[ca(1), ca(2)]);
    assert_eq!(two.addrs().next(), Some(ca(1).tumbler()));
    assert_eq!(two.single_denoted(), None, "two distinct addresses denote no one");

    // "Exactly one DISTINCT address", not "exactly one span": a repeated name
    // denotes one, which is the reading `editlink`'s DC guard admits.
    assert_eq!(enc(&[ca(1)]).single_denoted(), Some(ca(1).tumbler()));
    assert_eq!(enc(&[ca(1), ca(1)]).single_denoted(), Some(ca(1).tumbler()));

    // ⟨⟩ denotes nothing, and a non-unit-depth span is refused OUTRIGHT
    // rather than skipped — the endset below denotes ca(9) to `addrs`, and
    // this test is unit-depth-ALL, so it answers ⊥.
    assert_eq!(Endset::empty().single_denoted(), None);
    let mixed = Endset::from_spans(
        [span(&ca(1), &ca(3))]
            .into_iter()
            .chain(enc(&[ca(9)]).spans().cloned()),
    );
    assert_eq!(mixed.addrs().next(), Some(ca(9).tumbler()));
    assert_eq!(mixed.single_denoted(), None);
}

#[test]
fn enc_round_trips_every_address_set() {
    // AD is a law over sets, not three examples: `enc(X).addrs() = X` for
    // every subset of a deliberately UNSORTED family, ⟨⟩ and singletons
    // included — so an encoding that reordered or coalesced would show.
    let family = [ca(3), ca(1), ca(9), ca(2)];
    for mask in 0u8..16 {
        let x: Vec<skep_address::Address> = (0..family.len())
            .filter(|i| mask & (1u8 << i) != 0)
            .map(|i| family[i].clone())
            .collect();
        let got: Vec<_> = enc(&x).addrs().cloned().collect();
        let want: Vec<_> = x.iter().map(|a| a.tumbler().clone()).collect();
        assert_eq!(got, want, "enc(X).addrs() = X for subset {mask:#06b}");
    }
}

#[test]
fn coverage_class_is_invariant_under_span_permutation() {
    // Identity is coverage, never decomposition — a law over the whole
    // permutation group, and on BOTH sides of the classifier: the exact
    // denoted antichain and the conservative extent partition alike.
    const PERMS: [[usize; 3]; 6] = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];
    let units = [ca(1), ca(2), ca(3)];
    let extents = [
        span(&ca(1), &ca(3)),
        span(&ca(5), &ca(7)),
        span(&ca(9), &ca(11)),
    ];
    let unit_class = coverage_class(&enc(&units));
    let extent_class = coverage_class(&Endset::from_spans(extents.iter().cloned()));
    assert!(
        extent_class.denoted().is_none(),
        "the second family exercises the conservative partition"
    );
    for p in PERMS {
        let u: Vec<_> = p.iter().map(|&i| units[i].clone()).collect();
        assert_eq!(
            coverage_class(&enc(&u)),
            unit_class,
            "denoted class under permutation {p:?}"
        );
        let e = Endset::from_spans(p.iter().map(|&i| extents[i].clone()));
        assert_eq!(
            coverage_class(&e),
            extent_class,
            "extent class under permutation {p:?}"
        );
    }
}

#[test]
fn slot_is_none_outside_the_one_based_arity_range() {
    // `slot(i)` is `Some` iff `1 ≤ i ≤ arity` — a law over the index, stated
    // at the store's own shape and at a wider L3 capacity.
    for arity in [3usize, 4] {
        let l = Link::new(vec![enc(&[ca(1)]); arity]).expect("capacity admits arity ≥ 3");
        for i in 0..=6usize {
            assert_eq!(
                l.slot(i).is_some(),
                (1..=arity).contains(&i),
                "arity {arity}, slot {i}"
            );
        }
    }
}

#[test]
fn slots_walks_the_whole_value_in_positional_order() {
    // The whole-value projection, for the reads that are about the value
    // rather than about a position in it. Its two obligations: it yields
    // EVERY slot, and it yields them in the order the positional accessors
    // name — so a caller walking it and a caller indexing `1..=arity` cannot
    // disagree. Stated at the store's own shape and at a wider L3 capacity.
    let l = Link::new([enc(&[ca(1)]), enc(&[ca(2), ca(3)]), enc(&[ra(10)])]).expect("arity 3");
    let walked: Vec<&Endset> = l.slots().collect();
    assert_eq!(walked, vec![l.from_slot(), l.to_slot(), l.type_slot()]);
    for arity in [3usize, 4] {
        let wide = Link::new((1..=arity as u32).map(|k| enc(&[ca(k)])).collect::<Vec<_>>())
            .expect("capacity admits arity ≥ 3");
        let indexed: Vec<&Endset> =
            (1..=arity).map(|i| wide.slot(i).expect("1..=arity is in range")).collect();
        assert_eq!(wide.slots().collect::<Vec<_>>(), indexed, "arity {arity}");
        assert_eq!(wide.slots().count(), arity, "every slot, arity {arity}");
    }
}

#[test]
fn carrier_types_survive_the_journal_wire_format() {
    // bincode is M2's actual wire format.
    let e = Endset::from_spans([span(&ca(1), &ca(3)), span(&ca(4), &ca(5))]);
    let bytes = bincode::serialize(&e).expect("endset serializes");
    let back: Endset = bincode::deserialize(&bytes).expect("endset deserializes");
    assert_eq!(back, e); // structural round trip, decomposition preserved

    let l = Link::new([enc(&[ca(1)]), enc(&[ca(2)]), enc(&[ra(10)])]).expect("arity 3");
    let bytes = bincode::serialize(&l).expect("link serializes");
    let back: Link = bincode::deserialize(&bytes).expect("link deserializes");
    assert_eq!(back, l);
}

#[test]
fn the_arity_floor_holds_at_the_wire_boundary() {
    // Deserialization is a mint path: a two-slot sequence in the shape a Link
    // serializes as is REFUSED, so the positional slot accessors keep their
    // floor against a decoded checkpoint, not only against the constructors.
    let two = im::Vector::from(vec![enc(&[ca(1)]), enc(&[ca(2)])]);
    let bytes = bincode::serialize(&two).expect("the slot sequence serializes");
    assert!(bincode::deserialize::<Link>(&bytes).is_err());

    // Arity 3 through the same bytes is admitted, so the refusal is the floor
    // and not the shape.
    let three = im::Vector::from(vec![enc(&[ca(1)]), enc(&[ca(2)]), enc(&[ra(10)])]);
    let bytes = bincode::serialize(&three).expect("the slot sequence serializes");
    let back: Link = bincode::deserialize(&bytes).expect("arity 3 deserializes");
    assert_eq!(back, Link::new(three).expect("arity 3"));
}

#[test]
fn endset_collects_from_a_span_pipeline_and_the_format_constants_compare_by_value() {
    // Default is ⟨⟩, and collecting a span pipeline is the same verbatim
    // construction from_spans performs.
    assert_eq!(Endset::default(), Endset::empty());
    let spans = [span(&ca(1), &ca(3)), span(&ca(5), &ca(6))];
    let collected: Endset = spans.iter().cloned().collect();
    assert_eq!(collected, Endset::from_spans(spans.iter().cloned()));

    // The format constants compare as the plain data they are — one value,
    // every call.
    assert_eq!(reserved(), reserved());
    let mut other = reserved();
    other.retired = ca(9);
    assert_ne!(other, reserved());
}

#[test]
fn coverage_class_hashes_by_coverage_not_decomposition() {
    // CoverageClass is the map key M9 indexes targets_keyed with — Hash + Eq
    // must agree with coverage equality.
    let mut m: im::HashMap<CoverageClass, u32> = im::HashMap::new();
    m.insert(coverage_class(&enc(&[ca(1), ca(2)])), 7);
    assert_eq!(m.get(&coverage_class(&enc(&[ca(2), ca(1)]))), Some(&7));
}

#[test]
fn coverage_class_addrs_is_i0a_stated_as_its_definition() {
    // I0a computed two ways over the same families: once by the classifier,
    // once by the definition it implements — "drop every denoted address
    // that has a distinct denoted prefix", written out in full. The families
    // interleave roots, their extensions and unrelated siblings in Tumbler
    // order, and repeat addresses, so an encoding that read only adjacent
    // pairs, or only the first root, or that let a duplicate mask a root,
    // would separate the two answers.
    let acct = a(&[1, 0, 1]);
    let families: Vec<Vec<skep_address::Address>> = vec![
        vec![],
        vec![ca(1)],
        vec![ca(1), ca(1), ca(1)],
        vec![ca(3), ca(1), ca(2)],
        // Two roots, each swallowing several extensions, with the second
        // root sorting AFTER all of the first's — the contiguity the single
        // ascending pass depends on.
        vec![doc1(), ca(9), ca(1), la(4), doc2(), la2(3), la2(1), ca(1)],
        // A root arriving after its own extension in argument order.
        vec![ca(1), doc1(), la(4)],
        // One account-level root above everything, two documents deep.
        vec![acct.clone(), doc1(), ca(1), doc2(), la2(1)],
        vec![doc2(), la2(1), doc1(), ca(2), acct.clone()],
        // Roots with no extensions present, mixed with a swallowed pair.
        vec![ra(1), doc1(), ca(5), ra(2)],
    ];
    for x in &families {
        let denoted: im::OrdSet<skep_address::Tumbler> =
            x.iter().map(|addr| addr.tumbler().clone()).collect();
        let want: im::OrdSet<skep_address::Tumbler> = denoted
            .iter()
            .filter(|p| {
                !denoted
                    .iter()
                    .any(|y| y != *p && skep_address::is_prefix(y, p))
            })
            .cloned()
            .collect();
        let class = coverage_class(&enc(x));
        let got = class
            .denoted()
            .unwrap_or_else(|| panic!("an enc'd address set is address-denoting: {x:?}"));
        assert_eq!(*got, want, "I0a over {x:?}");
    }
    // ...and the families are not all antichains already, so the agreement
    // above is not vacuous.
    let swallowed = coverage_class(&enc(&[doc1(), ca(1), ca(2)]));
    assert_eq!(swallowed, coverage_class(&enc(&[doc1()])));
}

#[test]
fn coverage_class_partitions_a_mixed_length_endset_by_start_length() {
    // The conservative branch is a partition BY `#start`, each part folded
    // and canonicalized on its own — because M1's canonical form is defined
    // within one length class and refuses a heterogeneous set outright. A
    // mixed-length endset is legal, level-uniform input (editlink checks
    // level-uniformity per span, not a shared length), so classifying it must
    // answer rather than abort.
    let shallow = vspan(1, 1, 2); // #start = 2 — level-uniform, not unit-depth
    let deep = span(&ca(1), &ca(3)); // #start = 8
    let mixed = Endset::from_spans([shallow.clone(), deep.clone()]);
    assert!(mixed.is_level_uniform(), "every span, on its own");
    assert!(!mixed.is_address_denoting());
    let class = coverage_class(&mixed); // must not abort: canonical_key is per part
    assert!(class.denoted().is_none(), "a content extent denotes nothing");
    // Each part contributes: the class is neither part's own.
    assert_ne!(
        class,
        coverage_class(&Endset::from_spans([shallow.clone()]))
    );
    assert_ne!(class, coverage_class(&Endset::from_spans([deep.clone()])));
    // The partition is keyed by LENGTH, not by position.
    assert_eq!(class, coverage_class(&Endset::from_spans([deep, shallow])));
}

