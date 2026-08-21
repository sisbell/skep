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

/// The walk runs backwards, reports its exact length, and is fused. That
/// matters here more than for a general sequence: the tail of a tumbler is
/// where the meaning is — `sig` reads an `rposition`, the ordinal is the last
/// component — so a consumer holding only the published walk reads from that
/// end directly rather than cloning every component to reach it.
#[test]
fn the_component_walk_runs_both_ways_and_reports_its_length() {
    fn double_ended_exact_and_fused<I>(_: I)
    where
        I: DoubleEndedIterator + ExactSizeIterator + std::iter::FusedIterator,
    {
    }

    let x = t(&[1, 0, 2, 0, 5]);
    double_ended_exact_and_fused(x.iter());
    assert_eq!(x.iter().len(), x.len()); // exact, before a single step
    assert_eq!(
        x.iter().cloned().rev().collect::<Vec<_>>(),
        vec![n(5), n(0), n(2), n(0), n(1)]
    );
    // The two reads a caller wants from the tail, neither copying the head.
    assert_eq!(x.iter().next_back(), x.get(x.len()));
    assert_eq!(x.iter().rposition(|c| *c == n(0)), Some(3));
    // A cursor walked from both ends still knows what is left.
    let mut walk = x.iter();
    walk.next();
    walk.next_back();
    assert_eq!(walk.len(), 3);
    assert_eq!(walk.cloned().collect::<Vec<_>>(), vec![n(0), n(2), n(0)]);
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

/// T0(a) — the value layer holds components no fixed-width representation
/// does. The order is what a wrap would break first (two distinct tumblers
/// comparing equal), and the dotted-decimal rendering is where a narrowed
/// component would be truncated silently: it is the daemon's wire form and
/// what the conformance harness compares against the golden.
#[test]
fn values_are_exact_above_any_fixed_width() {
    assert!(tumbler([beyond_u64()]) > tumbler([Nat::from(u64::MAX)]));
    assert_ne!(tumbler([beyond_u64()]), tumbler([Nat::from(u64::MAX)]));
    assert_eq!(
        tumbler([n(1), beyond_u64()]).to_string(),
        "1.18446744073709551616"
    );
    // The zero scan reads magnitude-free, so a wide component is a separator
    // to nobody and the classification is unchanged by the size of a field.
    assert_eq!(
        classify(&tumbler([beyond_u64(), n(0), beyond_u64()])),
        Class::Account
    );
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
fn is_prefix_is_reflexive_and_directional() {
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
fn classify_reads_the_level_off_the_separator_count() {
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
    for (level, class, example) in pairs {
        assert_eq!(Class::from(level), class);
        // The embedding agrees with the classifier on every valid address.
        assert_eq!(classify(&example), class);
        assert_eq!(Class::from(validate(example).unwrap().level()), class);
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

/// The whole of T4 admission — the separator count, the validity verdict, the
/// class, and the exact clause set of a rejection — against a reading of the
/// four clauses written from T4 itself, over EVERY zero/nonzero pattern of
/// length 1..=9. T4 reads nothing but which components are zero, so this
/// family is exhaustive in the only thing the scan can see.
#[test]
fn t4_admission_agrees_with_the_clause_by_clause_reading() {
    for len in 1..=9usize {
        for bits in 0..(1u32 << len) {
            let comps: Vec<u32> = (0..len).map(|i| (bits >> i) & 1).collect();
            let candidate = t(&comps);

            let z = comps.iter().filter(|&&c| c == 0).count();
            let mut want: Vec<T4Clause> = Vec::new();
            if comps[0] == 0 {
                want.push(T4Clause::LeadingZero);
            }
            if comps[len - 1] == 0 {
                want.push(T4Clause::TrailingZero);
            }
            if comps.windows(2).any(|w| w[0] == 0 && w[1] == 0) {
                want.push(T4Clause::AdjacentZeros);
            }
            if z > 3 {
                want.push(T4Clause::OverDepth);
            }

            assert_eq!(zeros(&candidate), z, "zeros({candidate})");
            assert_eq!(
                is_t4_valid(&candidate),
                want.is_empty(),
                "is_t4_valid({candidate})"
            );
            let want_class = match (want.is_empty(), z) {
                (false, _) => Class::Invalid,
                (true, 0) => Class::Node,
                (true, 1) => Class::Account,
                (true, 2) => Class::Document,
                (true, _) => Class::Element,
            };
            assert_eq!(classify(&candidate), want_class, "classify({candidate})");

            match validate(candidate.clone()) {
                Ok(a) => {
                    assert!(
                        want.is_empty(),
                        "validate admitted {candidate}, violating {want:?}"
                    );
                    assert_eq!(a.tumbler(), &candidate);
                    assert_eq!(Class::from(a.level()), want_class);
                }
                Err(e) => {
                    // Exact vector equality: the full set, each clause at most
                    // once, in `T4Clause` declaration order.
                    assert_eq!(e.clauses(), want.as_slice(), "clauses of {candidate}");
                }
            }
        }
    }
}

/// A rejection renders every clause it carries, comma-separated — the text a
/// caller puts in front of a user, and the one place a clause set is read by
/// something other than a `match`.
#[test]
fn t4_error_renders_every_violated_clause() {
    let e = validate(t(&[0, 0])).unwrap_err();
    assert_eq!(
        e.clauses(),
        &[
            T4Clause::LeadingZero,
            T4Clause::TrailingZero,
            T4Clause::AdjacentZeros
        ][..]
    );
    assert_eq!(
        e.to_string(),
        "tumbler is not T4-valid; violated clause(s): LeadingZero, TrailingZero, AdjacentZeros"
    );
    let e = validate(t(&[0])).unwrap_err();
    assert_eq!(
        e.to_string(),
        "tumbler is not T4-valid; violated clause(s): LeadingZero, TrailingZero"
    );
    // The fourth clause, which co-occurs with none of the others: four
    // separators, with no leading, trailing or adjacent zero.
    let e = validate(t(&[1, 0, 2, 0, 3, 0, 4, 0, 5])).unwrap_err();
    assert_eq!(e.clauses(), &[T4Clause::OverDepth][..]);
    assert_eq!(
        e.to_string(),
        "tumbler is not T4-valid; violated clause(s): OverDepth"
    );
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

/// T3 — identity is the component sequence, so a tumbler keys a hash map: one
/// sequence built two ways is one key, and distinct sequences stay distinct.
/// Three crates key maps by `Tumbler` (M4's content store, M2's memo table,
/// M6's origin dedup), and only M1 can supply the `Hash` that allows it.
/// `Address` hashes the tumbler alone through a hand-written impl, so its
/// agreement with `Eq` is asserted beside it.
#[test]
fn tumblers_and_addresses_key_a_hash_map() {
    // One value, two construction paths: the public constructor, and the
    // internal one every arithmetic result comes out of.
    let literal = t(&[1, 0, 2, 0, 6]);
    let computed = inc(&t(&[1, 0, 2, 0, 5]), 0);
    assert_eq!(literal, computed);
    let mut by_tumbler: HashMap<Tumbler, &str> = HashMap::new();
    by_tumbler.insert(literal, "here");
    assert_eq!(by_tumbler.get(&computed), Some(&"here")); // Eq ⇒ equal hashes

    // No alias collapses (T3): three distinct sequences are three keys, and
    // only the repeat folds.
    let distinct: HashSet<Tumbler> = [t(&[1]), t(&[1, 0]), t(&[0, 1]), t(&[1, 0])]
        .into_iter()
        .collect();
    assert_eq!(distinct.len(), 3);

    // An Address hashes as its tumbler, so the same two paths agree for it.
    let mut by_address: HashMap<Address, &str> = HashMap::new();
    by_address.insert(addr(&[1, 0, 2, 0, 5]), "doc");
    let minted = checked_inc(&addr(&[1, 0, 2, 0, 4]), 0).unwrap();
    assert_eq!(by_address.get(&minted), Some(&"doc"));
}

// ---- T4b/T7: field projection -----------------------------------------------

#[test]
fn field_projections_return_the_components_between_the_separators() {
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

/// T4b — the four fields are present exactly per the separator count, and
/// together they CARVE the address: rejoined across the separators they drop,
/// they reproduce the component sequence exactly. An index off by one at any
/// separator loses or repeats a component, which no single projection read in
/// isolation would show.
#[test]
fn field_projections_carve_the_address_at_its_separators() {
    let battery = [
        addr(&[1, 2]),
        addr(&[1, 0, 2]),
        addr(&[1, 0, 2, 0, 5]),
        addr(&[1, 0, 2, 0, 5, 3]),
        addr(&[1, 0, 2, 0, 5, 0, 1, 9]),
        addr(&[1, 0, 2, 0, 5, 0, 2, 4, 7]),
    ];
    for a in &battery {
        let z = zeros(a.tumbler());
        assert_eq!(a.account_field().is_some(), z >= 1, "U presence on {a}");
        assert_eq!(a.document_field().is_some(), z >= 2, "D presence on {a}");
        assert_eq!(a.element_field().is_some(), z == 3, "E presence on {a}");

        let mut rejoined: Vec<Nat> = a.node_field().to_vec();
        for f in [a.account_field(), a.document_field(), a.element_field()]
            .into_iter()
            .flatten()
        {
            rejoined.push(n(0)); // the separator the projection dropped
            rejoined.extend(f.iter().cloned());
        }
        assert_eq!(&tumbler(rejoined), a.tumbler(), "fields do not carve {a}");
    }
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

/// Addresses spanning all four levels, including a second node and a second
/// account carrying the SAME numerals below them — the shapes that tell
/// "these fields match" apart from "these are the same account".
fn containment_battery() -> Vec<Address> {
    vec![
        addr(&[1]),
        addr(&[1, 2]),
        addr(&[1, 0, 2]),
        addr(&[1, 0, 2, 0, 5]),
        addr(&[1, 0, 2, 0, 5, 3]),
        addr(&[1, 0, 2, 0, 5, 0, 1, 9]),
        addr(&[1, 0, 2, 0, 6]),
        addr(&[1, 0, 2, 0, 6, 0, 2, 4]),
        addr(&[1, 0, 3, 0, 5]),
        addr(&[2, 0, 2, 0, 5, 0, 1, 9]),
    ]
}

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
fn containment_holds_under_the_document_and_fails_across_siblings() {
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

/// T6(b)/(c) conjoin every ENCLOSING level: an account is the same account
/// only under the same node, and a document only under the same account.
/// Matching numerals are not the claim — two nodes routinely allocate the
/// same numbers, and two accounts under one node routinely allocate the same
/// document number.
#[test]
fn containment_requires_agreement_at_every_enclosing_level() {
    let a = addr(&[1, 0, 2, 0, 5]);
    let cross_node = addr(&[2, 0, 2, 0, 5]); // same U and D, different N
    let cross_acct = addr(&[1, 0, 3, 0, 5]); // same N and D, different U

    assert!(!same_node(&a, &cross_node));
    assert!(same_node(&a, &cross_acct));

    assert!(!same_account(&a, &cross_node)); // T6(b) conjoins N
    assert!(!same_account(&a, &cross_acct)); // U itself differs

    assert!(!same_document(&a, &cross_node)); // T6(c) conjoins N
    assert!(!same_document(&a, &cross_acct)); // T6(c) conjoins U

    // Another node's like-numbered document encloses nothing of a's.
    assert!(!under_document(&addr(&[2, 0, 2, 0, 5, 0, 1, 9]), &a));
    assert!(!under_document(&addr(&[1, 0, 3, 0, 5, 0, 1, 9]), &a));
}

/// T6(b)/(c) read straight from their clauses — `N, U equal` and
/// `N, U, D equal` — rather than through the implementation's chaining, so a
/// dropped conjunct has an independent statement to disagree with. Asserted
/// over every ordered pair of the battery.
#[test]
fn same_account_and_same_document_agree_with_the_t6_clauses() {
    let battery = containment_battery();
    for a in &battery {
        for b in &battery {
            let t6b = match (a.account_field(), b.account_field()) {
                (Some(ua), Some(ub)) => a.node_field() == b.node_field() && ua == ub,
                _ => false, // field absence ⇒ NO
            };
            let t6c = match (a.document_field(), b.document_field()) {
                (Some(da), Some(db)) => {
                    a.node_field() == b.node_field()
                        && a.account_field() == b.account_field()
                        && da == db
                }
                _ => false,
            };
            assert_eq!(same_account(a, b), t6b, "T6(b) on ({a:?}, {b:?})");
            assert_eq!(same_document(a, b), t6c, "T6(c) on ({a:?}, {b:?})");
        }
    }
}

/// `under_document` compares a document prefix and `document_of` mints one.
/// Both read the same projection, so the predicate and the constructor cannot
/// disagree about where a document begins — asserted over every ordered pair
/// of a battery spanning all four levels.
#[test]
fn under_document_agrees_with_document_of() {
    let battery = containment_battery();
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
fn ordinal_is_the_last_component_and_level_is_not_a_count() {
    assert_eq!(ordinal(&t(&[1, 0, 2, 0, 5, 3])), &n(3));
    assert_eq!(ordinal(&t(&[7])), &n(7));
    // The hierarchical level is the enum, never a numeric nesting count: this
    // three-component address reads as Account, not as 3.
    assert_eq!(addr(&[1, 0, 2]).level(), Level::Account);
}

// ---- what T4 discharges, over the whole family ------------------------------

/// Every §B/§C discharge that rests on a T4 clause, over the whole space T4
/// can see. `separator` counts separators in its own loop and the validating
/// scan counts them in another; `field`'s window, `subspace`'s index into the
/// element field, and the truncations behind `document_of` and `parent` are
/// each total only while the two agree and the leading/trailing-zero clauses
/// hold. Asserted over EVERY zero/nonzero pattern of length 1..=9 — exhaustive
/// in the only thing the scan reads — rather than over the addresses a test
/// author would have picked.
#[test]
fn every_t4_derived_projection_holds_over_the_whole_family() {
    for len in 1..=9usize {
        for bits in 0..(1u32 << len) {
            let comps: Vec<u32> = (0..len).map(|i| (bits >> i) & 1).collect();
            let Ok(a) = validate(t(&comps)) else { continue };
            let z = zeros(a.tumbler());

            // T4b presence, against the count the validating scan reported.
            assert_eq!(a.account_field().is_some(), z >= 1, "U presence on {a}");
            assert_eq!(a.document_field().is_some(), z >= 2, "D presence on {a}");
            assert_eq!(a.element_field().is_some(), z == 3, "E presence on {a}");
            // No field is empty, and the fields carve the address: the
            // leading-, trailing- and adjacent-zero clauses are exactly what
            // leaves a component on both sides of every separator.
            assert!(!a.node_field().is_empty(), "empty N on {a}");
            let mut rejoined: Vec<Nat> = a.node_field().to_vec();
            for f in [a.account_field(), a.document_field(), a.element_field()]
                .into_iter()
                .flatten()
            {
                assert!(!f.is_empty(), "empty field on {a}");
                rejoined.push(n(0)); // the separator the projection dropped
                rejoined.extend(f.iter().cloned());
            }
            assert_eq!(&tumbler(rejoined), a.tumbler(), "fields do not carve {a}");
            // T7's index into the element field is total exactly at Element level.
            assert_eq!(a.subspace().is_some(), z == 3, "subspace presence on {a}");

            // §C: both projectors total on their stated domains, and neither
            // mints an address the validator would refuse.
            assert_eq!(document_of(&a).is_some(), z >= 2, "document_of on {a}");
            if let Some(d) = document_of(&a) {
                assert_eq!(d.level(), Level::Document, "document_of level on {a}");
                assert!(is_prefix(d.tumbler(), a.tumbler()), "document_of prefix on {a}");
            }
            assert_eq!(parent(&a).is_some(), a.tumbler().len() > 1, "parent on {a}");
            if let Some(p) = parent(&a) {
                assert!(p.tumbler().len() < a.tumbler().len(), "peel shortens {a}");
                assert!(is_prefix(p.tumbler(), a.tumbler()), "peel of {a} is a prefix");
                assert!(is_t4_valid(p.tumbler()), "peel of {a} is T4-valid");
            }
        }
    }
}
