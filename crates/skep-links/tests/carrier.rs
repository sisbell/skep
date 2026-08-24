//! Carrier-type and registry contracts, stated by the documents: the Link
//! arity floor and 1-based slots, Endset readback (verbatim decomposition,
//! `enc(X).addrs() = X`, ⟨⟩ distinctness), coverage-class identity (exact
//! `Addrs` antichain; conservative `Extents` partition; structural derives ≠
//! coverage identity; the pinned off-contract panic), `TypeRegistry::build`'s
//! rejection matrix, and the serde/journal round trips.

mod common;

use common::*;
use skep_address::Span;
use skep_links::{
    coverage_class, enc, CoverageClass, Endset, Link, LinkState, Registration, RegistryError,
    ReservedAddrs, Shape, TypeDecl, FROM, TO, TYPE,
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
    let t = Link::triple(f.clone(), g.clone(), ty.clone());
    assert_eq!(t.arity(), 3);
    assert_eq!(Link::new([f, g, ty]), Some(t.clone()));
    assert_eq!(t.from_slot(), &enc(&[ca(1)]));
    assert_eq!(t.to_slot(), &enc(&[ca(2)]));
    assert_eq!(t.type_slot(), &enc(&[ra(10)]));
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
    // span): one Extents class (canonical form merges the adjacent split).
    let whole = Endset::from_spans([span(&ca(1), &ca(4))]);
    let split = Endset::from_spans([span(&ca(1), &ca(3)), span(&ca(3), &ca(4))]);
    assert_ne!(whole, split); // structural
    assert_eq!(coverage_class(&whole), coverage_class(&split));
    // An all-unit decomposition of the SAME coverage lands in Addrs — a
    // different variant, deliberately distinct (over-discrimination is the
    // safe direction; class coherence keeps every guard and fold on the same
    // verdict).
    let units = enc(&[ca(1), ca(2), ca(3)]);
    assert_ne!(coverage_class(&units), coverage_class(&whole));
    // A width-1 iextent IS the unit span: single content addresses land in
    // the exact Addrs path.
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
fn registry_build_accepts_the_shipped_config_and_seeds_five_classes() {
    let state = LinkState::genesis(reserved(), decls()).expect("valid config builds");
    // The five shipped endsets read back through reserved_type.
    use skep_links::ShippedType as S;
    for (ty, addr) in [
        (S::PredDef, ra(1)),
        (S::PredStable, ra(2)),
        (S::Retired, ra(3)),
        (S::Supersedes, ra(4)),
        (S::Retraction, ra(5)),
    ] {
        assert_eq!(state.reserved_type(ty), &enc(&[addr]));
    }
}

#[test]
fn registry_build_rejection_matrix() {
    let ok_reg = Registration {
        shape: Shape::Multi,
        idem: false,
        behaviors: im::OrdSet::new(),
    };
    let build = |reserved: ReservedAddrs, decls: Vec<TypeDecl>| LinkState::genesis(reserved, decls);

    // ReservedSubspaceClash: a reserved address inside the content subspace.
    let mut bad = reserved();
    bad.retired = ca(1);
    assert!(matches!(
        build(bad, vec![]),
        Err(RegistryError::ReservedSubspaceClash)
    ));
    // ...and a non-element reserved address.
    let mut bad = reserved();
    bad.retraction = doc1();
    assert!(matches!(
        build(bad, vec![]),
        Err(RegistryError::ReservedSubspaceClash)
    ));

    // EmptyKey.
    let d = TypeDecl {
        key: Endset::empty(),
        reg: ok_reg.clone(),
    };
    assert!(matches!(build(reserved(), vec![d]), Err(RegistryError::EmptyKey)));

    // NonAddressDenotingKey: a non-unit span in the key.
    let d = TypeDecl {
        key: Endset::from_spans([span(&ca(1), &ca(3))]),
        reg: ok_reg.clone(),
    };
    assert!(matches!(
        build(reserved(), vec![d]),
        Err(RegistryError::NonAddressDenotingKey)
    ));

    // ReservedClassClash: an app key coverage-equal to a shipped class (R-C1).
    let d = TypeDecl {
        key: enc(&[ra(3)]),
        reg: ok_reg.clone(),
    };
    assert!(matches!(
        build(reserved(), vec![d]),
        Err(RegistryError::ReservedClassClash)
    ));

    // KeyCollision: two app decls sharing one coverage class (C0).
    let d1 = TypeDecl {
        key: enc(&[ra(20)]),
        reg: ok_reg.clone(),
    };
    let d2 = TypeDecl {
        key: enc(&[ra(20)]),
        reg: ok_reg.clone(),
    };
    assert!(matches!(
        build(reserved(), vec![d1, d2]),
        Err(RegistryError::KeyCollision)
    ));

    // BadBehavior (R-C0): ReadFilter on a non-Unary shape...
    let d = TypeDecl {
        key: enc(&[ra(21)]),
        reg: Registration {
            shape: Shape::Binary,
            idem: true,
            behaviors: im::OrdSet::unit(skep_links::Behavior::ReadFilter),
        },
    };
    assert!(matches!(
        build(reserved(), vec![d]),
        Err(RegistryError::BadBehavior)
    ));
    // ...and Age with idem⊤.
    let d = TypeDecl {
        key: enc(&[ra(22)]),
        reg: Registration {
            shape: Shape::Multi,
            idem: true,
            behaviors: im::OrdSet::unit(skep_links::Behavior::Age),
        },
    };
    assert!(matches!(
        build(reserved(), vec![d]),
        Err(RegistryError::BadBehavior)
    ));

    // v1 serving fence — declared ⇒ served: app Walk rejected...
    let d = TypeDecl {
        key: enc(&[ra(23)]),
        reg: Registration {
            shape: Shape::Binary,
            idem: false,
            behaviors: im::OrdSet::unit(skep_links::Behavior::Walk),
        },
    };
    assert!(matches!(
        build(reserved(), vec![d]),
        Err(RegistryError::UnservedWalk)
    ));
    // ...and app ReadFilter (a second BH1) rejected.
    let d = TypeDecl {
        key: enc(&[ra(24)]),
        reg: Registration {
            shape: Shape::Unary,
            idem: true,
            behaviors: im::OrdSet::unit(skep_links::Behavior::ReadFilter),
        },
    };
    assert!(matches!(
        build(reserved(), vec![d]),
        Err(RegistryError::UnservedSecondFilter)
    ));
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
fn coverage_class_keys_hash_containers() {
    // CoverageClass is the map key M9 indexes targets_keyed with — Hash + Eq
    // must agree with coverage equality.
    let mut m: im::HashMap<CoverageClass, u32> = im::HashMap::new();
    m.insert(coverage_class(&enc(&[ca(1), ca(2)])), 7);
    assert_eq!(m.get(&coverage_class(&enc(&[ca(2), ca(1)]))), Some(&7));
}
