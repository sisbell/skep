//! §A/§B/§C — tumbler admission and order (T0–T3), validation and
//! classification (T4/ASN-0045), field projection (T4b/T7), containment
//! (T6 a–d), and decomposition.

mod common;

use std::collections::{BTreeSet, HashMap, HashSet};

use common::*;
use skep_address::*;

// ---- T0: carrier admission -------------------------------------------------

#[test]
fn tumbler_new_rejects_the_empty_sequence() {
    assert_eq!(Tumbler::new(std::iter::empty::<Nat>()), Err(EmptySequence));
}

#[test]
fn tumbler_new_admits_zero_and_leading_zero_sequences() {
    // Legal carrier elements (span sentinels) even though they are not addresses.
    assert!(Tumbler::new([n(0)]).is_ok());
    assert!(Tumbler::new([n(0), n(1)]).is_ok());
}

#[test]
fn get_is_one_based() {
    let x = t(&[7, 0, 9]);
    assert_eq!(x.len(), 3);
    assert_eq!(x.get(1), Some(&n(7)));
    assert_eq!(x.get(3), Some(&n(9)));
}

/// Out of range is an answer, not a fault: the two ends a 1-based index can
/// fall off both read `None`, so a caller need not establish `#t` before it
/// asks for a component.
#[test]
fn get_out_of_range_is_none() {
    let x = t(&[1]);
    assert_eq!(x.get(0), None); // below t₁
    assert_eq!(x.get(2), None); // past t_{#t}
}

/// The component walk, `t₁..t_{#t}` in order — the one every rendering and
/// encoding path needs, available directly and through `&Tumbler` in a `for`.
#[test]
fn tumbler_iterates_its_components_in_order() {
    let x = t(&[7, 0, 9]);
    assert_eq!(x.iter().cloned().collect::<Vec<_>>(), vec![n(7), n(0), n(9)]);
    assert_eq!(x.iter().count(), x.len());
    let mut walked = Vec::new();
    for c in &x {
        walked.push(c.clone());
    }
    assert_eq!(walked, vec![n(7), n(0), n(9)]);
    // The walk agrees with the indexed reads, position for position.
    for (i, c) in x.iter().enumerate() {
        assert_eq!(x.get(i + 1), Some(c));
    }
}

/// Dotted decimal is the canonical text (T3): no aliases, so the rendering
/// and the value determine each other. `Display`, so a tumbler interpolates
/// into any message without a per-crate helper.
#[test]
fn tumbler_renders_as_dotted_decimal() {
    assert_eq!(t(&[1, 0, 2, 0, 5]).to_string(), "1.0.2.0.5");
    assert_eq!(t(&[7]).to_string(), "7");
    assert_eq!(t(&[0, 0]).to_string(), "0.0"); // carrier sentinels render too
    assert_eq!(format!("{}", t(&[1, 0])), "1.0");
    // Distinct tumblers render distinctly — no leading-zero alias collapses.
    assert_ne!(t(&[0, 1]).to_string(), t(&[1]).to_string());
    // An address renders as its tumbler; the derived level is never shown.
    let a = addr(&[1, 0, 2, 0, 5, 0, 1, 9]);
    assert_eq!(a.to_string(), a.tumbler().to_string());
    assert_eq!(a.to_string(), "1.0.2.0.5.0.1.9");
}

// ---- T1/T2/T3: order and identity ------------------------------------------

#[test]
fn order_is_lexicographic_prefix_smaller() {
    assert!(t(&[1]) < t(&[1, 0])); // a proper prefix is smaller (T1)
    assert!(t(&[1, 0]) < t(&[1, 0, 2]));
    assert!(t(&[1, 9, 9]) < t(&[2])); // first divergence decides
    assert!(t(&[0]) < t(&[1])); // TA-PosDom: positive > zero
    assert!(t(&[0, 0]) < t(&[0, 1])); // total over zero tumblers too
    assert!(t(&[0, 1]) < t(&[1])); // a leading-zero tumbler is NOT an alias of [1]
}

#[test]
fn equality_is_sequence_equality() {
    assert_eq!(t(&[1, 0, 2]), t(&[1, 0, 2]));
    assert_ne!(t(&[1]), t(&[1, 0])); // T3: no normalization, no aliasing
}

#[test]
fn is_prefix_examples() {
    assert!(is_prefix(&t(&[1, 0]), &t(&[1, 0, 2])));
    assert!(is_prefix(&t(&[1]), &t(&[1]))); // ≼ is reflexive
    assert!(!is_prefix(&t(&[1, 0, 2]), &t(&[1, 0])));
    assert!(!is_prefix(&t(&[2]), &t(&[1, 2])));
}

// ---- T4/ASN-0045: zeros, validity, classification ---------------------------

#[test]
fn zeros_counts_separators_unbounded() {
    assert_eq!(zeros(&t(&[1, 2])), 0);
    assert_eq!(zeros(&t(&[1, 0, 2, 0, 5, 0, 1, 9])), 3);
    // 6 separators: the true count is reported (usize, T0(b)) and the
    // classifier lands on Invalid — never a wrapped level, never a fault.
    let garbage = t(&[1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7]);
    assert_eq!(zeros(&garbage), 6);
    assert_eq!(classify(&garbage), Class::Invalid);
}

#[test]
fn classify_all_levels() {
    assert_eq!(classify(&t(&[1])), Class::Node);
    assert_eq!(classify(&t(&[1, 2, 3])), Class::Node); // any zero-free sequence
    assert_eq!(classify(&t(&[1, 0, 2])), Class::Account);
    assert_eq!(classify(&t(&[1, 0, 2, 0, 5])), Class::Document);
    assert_eq!(classify(&t(&[1, 0, 2, 0, 5, 3])), Class::Document); // versioned document
    assert_eq!(classify(&t(&[1, 0, 2, 0, 5, 0, 1, 9])), Class::Element);
}

/// The Partition embedding is a conversion, so a caller holding a `Level` can
/// reach the `Class` without re-deriving the four-arm map — and `Invalid`
/// stays unreachable through it, being the classifier's answer alone.
#[test]
fn every_level_embeds_as_its_class() {
    let pairs = [
        (Level::Node, Class::Node, t(&[1])),
        (Level::Account, Class::Account, t(&[1, 0, 2])),
        (Level::Document, Class::Document, t(&[1, 0, 2, 0, 5])),
        (Level::Element, Class::Element, t(&[1, 0, 2, 0, 5, 0, 1, 9])),
    ];
    for (level, class, tumbler) in pairs {
        assert_eq!(Class::from(level), class);
        // The embedding agrees with the classifier on every valid address.
        assert_eq!(classify(&tumbler), class);
        assert_eq!(Class::from(validate(tumbler).unwrap().level()), class);
    }
}

/// Classification answers key a map: grouping addresses by what they are is
/// the obvious use, and only the type can supply the `Hash` that allows it.
#[test]
fn classification_answers_key_a_map() {
    let mut by_level: HashMap<Level, Vec<Address>> = HashMap::new();
    for a in [
        addr(&[1]),
        addr(&[2]),
        addr(&[1, 0, 2]),
        addr(&[1, 0, 2, 0, 5]),
        addr(&[1, 0, 2, 0, 5, 0, 1, 9]),
    ] {
        by_level.entry(a.level()).or_default().push(a);
    }
    assert_eq!(by_level[&Level::Node].len(), 2);
    assert_eq!(by_level[&Level::Element].len(), 1);
    assert_eq!(by_level.get(&Level::Account).map(Vec::len), Some(1));
    // The other three classification answers hash too.
    let classes: HashSet<Class> = [t(&[1]), t(&[1, 0, 2]), t(&[0, 1])]
        .iter()
        .map(classify)
        .collect();
    assert_eq!(classes.len(), 3);
    let e = validate(t(&[0])).unwrap_err();
    let clauses: HashSet<T4Clause> = e.clauses().iter().copied().collect();
    assert_eq!(clauses.len(), 2);
}

#[test]
fn classify_rejects_each_t4_clause() {
    assert_eq!(classify(&t(&[0, 1])), Class::Invalid); // leading zero
    assert_eq!(classify(&t(&[1, 0])), Class::Invalid); // trailing zero
    assert_eq!(classify(&t(&[1, 0, 0, 2])), Class::Invalid); // adjacent zeros
    assert_eq!(classify(&t(&[1, 0, 2, 0, 3, 0, 4, 0, 5])), Class::Invalid); // over depth
    assert!(is_t4_valid(&t(&[1, 0, 2])));
    assert!(!is_t4_valid(&t(&[0, 1])));
}

#[test]
fn validate_mints_classified_addresses() {
    let a = validate(t(&[1, 0, 2, 0, 5, 0, 1, 9])).unwrap();
    assert_eq!(a.level(), Level::Element);
    assert_eq!(a.tumbler(), &t(&[1, 0, 2, 0, 5, 0, 1, 9]));
}

#[test]
fn validate_reports_the_violated_clauses() {
    // [0] violates both boundary clauses (the design's co-occurrence example).
    let e = validate(t(&[0])).unwrap_err();
    assert_eq!(e.clauses().len(), 2);
    assert!(e.clauses().contains(&T4Clause::LeadingZero));
    assert!(e.clauses().contains(&T4Clause::TrailingZero));
    // [0,0] adds adjacency.
    let e = validate(t(&[0, 0])).unwrap_err();
    assert_eq!(e.clauses().len(), 3);
    assert!(e.clauses().contains(&T4Clause::AdjacentZeros));
    // Over-depth garbage reports OverDepth.
    let e = validate(t(&[1, 0, 2, 0, 3, 0, 4, 0, 5])).unwrap_err();
    assert!(e.clauses().contains(&T4Clause::OverDepth));
}

#[test]
fn address_orders_by_the_tumbler_order() {
    let mut v = vec![addr(&[2]), addr(&[1, 0, 2]), addr(&[1])];
    v.sort();
    assert_eq!(v, vec![addr(&[1]), addr(&[1, 0, 2]), addr(&[2])]);
    // `level` plays no part: an Element sorts directly under its Document.
    assert!(addr(&[1, 0, 2, 0, 5]) < addr(&[1, 0, 2, 0, 5, 0, 1, 9]));
}

/// The order is `Ord`, not a comparator every caller supplies: an `Address`
/// keys an ordered collection directly — no `.tumbler()` detour, no
/// `sort_by`, and the walk comes out in T1 order.
#[test]
fn address_keys_an_ordered_collection_directly() {
    let s: BTreeSet<Address> = [addr(&[2]), addr(&[1, 0, 2]), addr(&[1]), addr(&[2])]
        .into_iter()
        .collect();
    assert_eq!(s.len(), 3); // Ord agrees with Eq, so the repeat collapses
    assert_eq!(
        s.into_iter().collect::<Vec<_>>(),
        vec![addr(&[1]), addr(&[1, 0, 2]), addr(&[2])]
    );
}

// ---- T4b/T7: field projection -----------------------------------------------

#[test]
fn field_projections_by_zero_count() {
    let e = addr(&[1, 0, 2, 0, 5, 0, 1, 9]);
    assert_eq!(e.node_field(), &[n(1)][..]);
    assert_eq!(e.account_field().unwrap(), &[n(2)][..]);
    assert_eq!(e.document_field().unwrap(), &[n(5)][..]);
    assert_eq!(e.element_field().unwrap(), &[n(1), n(9)][..]);
    assert_eq!(e.subspace(), Some(&content_subspace())); // T7: the content subspace

    let d = addr(&[1, 0, 2, 0, 5, 3]);
    assert_eq!(d.document_field().unwrap(), &[n(5), n(3)][..]); // version components included
    assert_eq!(d.element_field(), None);
    assert_eq!(d.subspace(), None);

    let node = addr(&[1, 2]);
    assert_eq!(node.node_field(), &[n(1), n(2)][..]);
    assert_eq!(node.account_field(), None);
    assert_eq!(node.document_field(), None);
}

/// T7's two subspaces are named values, so an element is routed by asking
/// which subspace it names rather than by a numeral each caller re-derives.
#[test]
fn the_two_subspaces_are_named() {
    let content = addr(&[1, 0, 2, 0, 5, 0, 1, 9]);
    let link = addr(&[1, 0, 2, 0, 5, 0, 2, 4]);
    assert_eq!(content.subspace(), Some(&content_subspace()));
    assert_eq!(link.subspace(), Some(&link_subspace()));
    assert_ne!(content_subspace(), link_subspace()); // disjoint by 1 < 2 (T7)

    // Both are mint-side too: the numeral an element field opens with is the
    // one `ElemPos` carries into it.
    let minted = elem_addr(ElemPos {
        doc: addr(&[1, 0, 2, 0, 5]),
        subspace: link_subspace(),
        ordinal: n(4),
    })
    .unwrap();
    assert_eq!(minted, link);
    // An address below Element level names no subspace at all.
    assert_eq!(addr(&[1, 0, 2, 0, 5]).subspace(), None);
}

// ---- T6 a–d: containment ----------------------------------------------------

#[test]
fn containment_field_absence_is_decisive() {
    let node_a = addr(&[1]);
    let node_b = addr(&[1]);
    assert!(same_node(&node_a, &node_b));
    // T6(b): two Node addresses do NOT report "same account".
    assert!(!same_account(&node_a, &node_b));
    // T6(c)/(d): an account has no document field on either side.
    let acct = addr(&[1, 0, 2]);
    assert!(!same_document(&acct, &acct));
    let d = addr(&[1, 0, 2, 0, 5]);
    assert!(!under_document(&acct, &d));
}

#[test]
fn containment_positive_and_negative() {
    let d = addr(&[1, 0, 2, 0, 5]);
    let v = addr(&[1, 0, 2, 0, 5, 3]); // a version of d
    let e = addr(&[1, 0, 2, 0, 5, 0, 1, 9]); // an element under d
    let other = addr(&[1, 0, 2, 0, 6]); // a sibling document

    assert!(same_node(&d, &other));
    assert!(same_account(&d, &other));
    assert!(!same_document(&d, &other));
    assert!(!same_document(&d, &v)); // document fields [5] vs [5,3] differ
    assert!(same_document(&e, &d)); // the element's D is [5]

    assert!(under_document(&e, &d)); // T6(d)
    assert!(under_document(&v, &d)); // the version sits under the base document
    assert!(!under_document(&d, &v)); // not conversely
}

/// `under_document` compares a document prefix and `document_of` mints one.
/// Both read the same projection, so the predicate and the constructor cannot
/// disagree about where a document begins — asserted over every ordered pair
/// of a battery spanning all four levels.
#[test]
fn under_document_agrees_with_document_of() {
    let battery = [
        addr(&[1]),
        addr(&[1, 2]),
        addr(&[1, 0, 2]),
        addr(&[1, 0, 2, 0, 5]),
        addr(&[1, 0, 2, 0, 5, 3]),
        addr(&[1, 0, 2, 0, 5, 0, 1, 9]),
        addr(&[1, 0, 2, 0, 6]),
        addr(&[1, 0, 2, 0, 6, 0, 2, 4]),
        addr(&[2, 0, 2, 0, 5, 0, 1, 9]),
    ];
    for a in &battery {
        for b in &battery {
            let via_mint = matches!(a.level(), Level::Document | Level::Element)
                && document_of(b).is_some_and(|d| is_prefix(d.tumbler(), a.tumbler()));
            assert_eq!(
                under_document(a, b),
                via_mint,
                "under_document({a:?}, {b:?}) disagrees with document_of"
            );
        }
    }
}

// ---- §C: decomposition ------------------------------------------------------

#[test]
fn parent_peels_one_structural_step() {
    let e = addr(&[1, 0, 2, 0, 5, 0, 1, 9]);
    let sub_base = parent(&e).unwrap();
    assert_eq!(sub_base.tumbler(), &t(&[1, 0, 2, 0, 5, 0, 1]));
    assert_eq!(sub_base.level(), Level::Element); // still Element-class: NOT a level-coarsening
    let doc = parent(&sub_base).unwrap();
    assert_eq!(doc.tumbler(), &t(&[1, 0, 2, 0, 5]));
    assert_eq!(doc.level(), Level::Document);
    let acct = parent(&doc).unwrap();
    assert_eq!(acct.tumbler(), &t(&[1, 0, 2]));
    let node = parent(&acct).unwrap();
    assert_eq!(node.tumbler(), &t(&[1]));
    assert_eq!(parent(&node), None); // a 1-component node has no proper prefix

    // A multi-component node peels within its field.
    assert_eq!(parent(&addr(&[1, 2])).unwrap().tumbler(), &t(&[1]));
    // A versioned document peels to its base document.
    assert_eq!(
        parent(&addr(&[1, 0, 2, 0, 5, 3])).unwrap().tumbler(),
        &t(&[1, 0, 2, 0, 5])
    );
}

#[test]
fn document_of_truncates_to_the_origin_document() {
    let e = addr(&[1, 0, 2, 0, 5, 0, 1, 9]);
    let d = document_of(&e).unwrap();
    assert_eq!(d.tumbler(), &t(&[1, 0, 2, 0, 5]));
    assert_eq!(d.level(), Level::Document);
    assert_eq!(document_of(&d), Some(d.clone())); // a Document input returns itself
    assert_eq!(document_of(&addr(&[1, 0, 2])), None); // zeros < 2
}

#[test]
fn ordinal_and_level() {
    assert_eq!(ordinal(&t(&[1, 0, 2, 0, 5, 3])), &n(3));
    assert_eq!(ordinal(&t(&[7])), &n(7));
    // The hierarchical level is the enum, never a numeric nesting count: this
    // three-component address reads as Account, not as 3.
    assert_eq!(addr(&[1, 0, 2]).level(), Level::Account);
}
