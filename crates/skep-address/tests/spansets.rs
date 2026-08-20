//! §G — span-sets: structural reads, union-as-concatenation, normalization
//! (S8/S9 with the pinned edges), the set-level algebra, canonical identity,
//! hull (S0), and cover (S7).

mod common;

use std::collections::HashMap;

use common::*;
use skep_address::*;

#[test]
fn empty_singleton_len_iter() {
    let e = SpanSet::empty();
    assert!(e.is_empty());
    assert_eq!(e.len(), 0);
    assert_eq!(e.iter().count(), 0);
    let s = SpanSet::singleton(sp(&[1], &[3]));
    assert_eq!(s.len(), 1);
    assert!(!s.is_empty());
}

#[test]
fn from_iterator_collects_as_given() {
    let ss: SpanSet = set(&[sp(&[5], &[9]), sp(&[1], &[3])]);
    let stored: Vec<Span> = ss.iter().cloned().collect();
    assert_eq!(stored, vec![sp(&[5], &[9]), sp(&[1], &[3])]); // insertion order, no normalization
    assert!(!ss.is_normalized()); // N1 violated (descending starts)
}

#[test]
fn union_is_concatenation_only() {
    let a = SpanSet::singleton(sp(&[1], &[5]));
    let b = SpanSet::singleton(sp(&[3], &[9])); // overlaps a
    let u = union(&a, &b);
    assert_eq!(u.len(), 2); // never coalesces, never fails
    assert!(!u.is_normalized());
}

#[test]
fn normalize_sorts_and_coalesces_to_the_unique_form() {
    let raw = set(&[sp(&[5], &[9]), sp(&[1], &[3]), sp(&[3], &[5])]);
    let norm = raw.normalize().unwrap();
    assert_eq!(norm, set(&[sp(&[1], &[9])])); // overlap AND adjacency coalesce (N2)
    assert!(norm.is_normalized());
    assert_eq!(norm.normalize().unwrap(), norm); // idempotent (unique form, S9)
    // Pinned edges: S8's n = 0 case.
    assert_eq!(SpanSet::empty().normalize().unwrap(), SpanSet::empty());
    assert!(SpanSet::empty().is_normalized());
}

/// `level_class` answers the S8 gate directly, with the same verdict
/// `normalize` reaches through it.
#[test]
fn level_class_is_the_s8_gate_answered_directly() {
    assert_eq!(SpanSet::empty().level_class(), Ok(None)); // ⟨⟩: no class
    let flat = set(&[sp(&[1], &[3]), sp(&[7], &[9])]);
    assert_eq!(flat.level_class(), Ok(Some(1)));
    let deep = set(&[sp(&[1, 0, 2], &[1, 0, 5])]);
    assert_eq!(deep.level_class(), Ok(Some(3)));
    // The two ways a set falls outside S8's domain, each refused by both.
    let mixed = set(&[sp(&[1], &[3]), sp(&[1, 0], &[1, 5])]);
    assert_eq!(mixed.level_class(), Err(LevelMismatch));
    assert_eq!(mixed.normalize(), Err(LevelMismatch));
    let nu = SpanSet::singleton(Span::new(t(&[1, 0, 2]), t(&[0, 1])).unwrap());
    assert_eq!(nu.level_class(), Err(LevelMismatch));
    assert_eq!(nu.normalize(), Err(LevelMismatch));
}

/// `by_level_class` decomposes a set S8 refuses whole into the pieces S8
/// admits — the partition every mixed-depth consumer needs.
#[test]
fn by_level_class_partitions_into_normalizable_pieces() {
    assert!(SpanSet::empty().by_level_class().is_empty());
    let mixed = cover(&[t(&[1]), t(&[2, 0]), t(&[3])]);
    assert_eq!(mixed.normalize(), Err(LevelMismatch)); // refused whole
    let parts = mixed.by_level_class();
    assert_eq!(parts.keys().copied().collect::<Vec<_>>(), vec![1, 2]);
    assert_eq!(parts[&1].len(), 2);
    assert_eq!(parts[&2].len(), 1);
    for (len, part) in &parts {
        assert_eq!(part.level_class(), Ok(Some(*len))); // each piece is inside S8
        assert!(part.normalize().is_ok());
    }
    // Every member survives, in its own class and no other.
    assert!(parts[&1].denotes(&t(&[1])));
    assert!(parts[&2].denotes(&t(&[2, 0, 9])));
    assert!(!parts[&1].denotes(&t(&[2, 0, 9])));
    // TOTAL: a non-level-uniform member is partitioned by its start, then
    // refused by its own class's gate — exactly as the whole set refused it.
    let with_nu = set(&[
        Span::new(t(&[1, 0, 2]), t(&[0, 1])).unwrap(),
        sp(&[1], &[3]),
    ]);
    let parts = with_nu.by_level_class();
    assert_eq!(parts[&3].level_class(), Err(LevelMismatch));
    assert_eq!(parts[&1].level_class(), Ok(Some(1)));
}

#[test]
fn normalize_gate_is_the_full_s8_precondition() {
    // Mutually incompatible length classes.
    let mixed = set(&[sp(&[1], &[3]), sp(&[1, 0], &[1, 5])]);
    assert_eq!(mixed.normalize(), Err(LevelMismatch));
    assert!(!mixed.is_normalized());
    // A non-level-uniform component span.
    let nu = SpanSet::singleton(Span::new(t(&[1, 0, 2]), t(&[0, 1])).unwrap());
    assert_eq!(nu.normalize(), Err(LevelMismatch));
}

#[test]
fn denotes_is_membership_in_some_component() {
    let ss = set(&[sp(&[1], &[3]), sp(&[7], &[9])]);
    assert!(ss.denotes(&t(&[1])));
    assert!(ss.denotes(&t(&[2, 5]))); // deeper extension inside a component
    assert!(!ss.denotes(&t(&[5])));
    assert!(ss.denotes(&t(&[7])));
    assert!(!ss.denotes(&t(&[9])));
    assert!(!SpanSet::empty().denotes(&t(&[1]))); // ⟨⟩ denotes nothing
}

#[test]
fn intersect_sets_normalizes_internally_and_emits_normalized() {
    let a = set(&[sp(&[5], &[9]), sp(&[1], &[4])]); // deliberately un-normalized input
    let b = set(&[sp(&[3], &[7])]);
    let r = intersect_sets(&a, &b).unwrap();
    assert_eq!(r, set(&[sp(&[3], &[4]), sp(&[5], &[7])]));
    assert!(r.is_normalized());
    assert_eq!(intersect_sets(&a, &SpanSet::empty()).unwrap(), SpanSet::empty());
    // The two sets must be mutually level-compatible.
    let cross = set(&[sp(&[1, 0], &[1, 5])]);
    assert_eq!(intersect_sets(&a, &cross), Err(LevelMismatch));
}

#[test]
fn difference_sets_carves_and_emits_normalized() {
    let a = set(&[sp(&[1], &[9])]);
    let b = set(&[sp(&[3], &[5])]);
    let r = difference_sets(&a, &b).unwrap();
    assert_eq!(r, set(&[sp(&[1], &[3]), sp(&[5], &[9])]));
    assert!(r.is_normalized());
    // One b-span crossing the gap between two a-spans.
    let a2 = set(&[sp(&[1], &[3]), sp(&[5], &[7])]);
    let b2 = set(&[sp(&[2], &[6])]);
    assert_eq!(
        difference_sets(&a2, &b2).unwrap(),
        set(&[sp(&[1], &[2]), sp(&[6], &[7])])
    );
    assert_eq!(difference_sets(&a, &a).unwrap(), SpanSet::empty());
    assert_eq!(
        difference_sets(&a, &SpanSet::empty()).unwrap(),
        a.normalize().unwrap()
    );
    assert_eq!(difference_sets(&SpanSet::empty(), &a).unwrap(), SpanSet::empty());
    let cross = set(&[sp(&[1, 0], &[1, 5])]);
    assert_eq!(difference_sets(&a, &cross), Err(LevelMismatch));
}

#[test]
fn equiv_compares_canonical_forms() {
    let x = set(&[sp(&[1], &[3]), sp(&[3], &[5])]);
    let y = set(&[sp(&[1], &[5])]);
    assert_eq!(equiv(&x, &y), Ok(true)); // same denotation, different structure
    assert_ne!(x, y); // raw Eq is structural, NOT denotational
    assert_eq!(equiv(&x, &set(&[sp(&[1], &[4])])), Ok(false));
    // Two internally-uniform sets in DIFFERENT length classes: Ok(false), not Err (§7).
    let other_class = set(&[sp(&[1, 0], &[1, 5])]);
    assert_eq!(equiv(&y, &other_class), Ok(false));
    // An internally mixed set is still an error.
    let mixed = set(&[sp(&[1], &[3]), sp(&[1, 0], &[1, 5])]);
    assert_eq!(equiv(&mixed, &y), Err(LevelMismatch));
}

#[test]
fn canonical_key_is_the_denotational_dedup_identity() {
    let x = set(&[sp(&[3], &[5]), sp(&[1], &[3])]);
    let y = set(&[sp(&[1], &[5])]);
    let kx = canonical_key(&x).unwrap();
    let ky = canonical_key(&y).unwrap();
    assert_eq!(kx, ky); // S9: one canonical form per denotation
    assert!(kx.as_set().is_normalized()); // the read-only normalized view
    // Usable directly as an in-memory dedup/cache key (Hash + Eq).
    let mut m = HashMap::new();
    m.insert(kx, 1);
    assert_eq!(m.get(&ky), Some(&1));
    assert!(canonical_key(&SpanSet::empty()).is_ok()); // ⟨⟩ → the empty canonical form
    assert_eq!(canonical_key(&set(&[sp(&[1], &[3]), sp(&[1, 0], &[1, 5])])), Err(LevelMismatch));
}

#[test]
fn hull_is_the_tight_single_span_cover() {
    assert_eq!(hull(&[]), None);
    let p = [t(&[3]), t(&[1]), t(&[1, 5, 5])];
    let h = hull(&p).unwrap();
    assert_eq!(h.start(), &t(&[1]));
    assert_eq!(h.reach(), t(&[4])); // shift(max, 1)
    assert!(p.iter().all(|x| h.contains(x))); // covers the mixed-length interior point too
    assert_eq!(hull(&[t(&[0, 1]), t(&[5])]), None); // #min ≠ #max
    // Tight on a trailing-zero max: reach = [2,1], not inc(max,0) = [3,0].
    let h2 = hull(&[t(&[1, 0]), t(&[2, 0])]).unwrap();
    assert_eq!(h2.reach(), t(&[2, 1]));
    assert!(h2.contains(&t(&[2, 0, 7])));
    assert!(!h2.contains(&t(&[2, 5])));
}

#[test]
fn cover_is_one_unit_span_per_point() {
    assert_eq!(cover(&[]), SpanSet::empty());
    let p = [t(&[1]), t(&[2]), t(&[1])]; // duplicates allowed: |Σ| = slice length
    let c = cover(&p);
    assert_eq!(c.len(), 3);
    assert!(p.iter().all(|x| c.denotes(x))); // ⟦Σ⟧ ⊇ P
    let first = c.iter().next().unwrap();
    assert_eq!(first, &subtree_of(&t(&[1]))); // each unit span IS subtree_of(t)
    assert!(!c.is_normalized()); // left un-normalized (duplicates + adjacency)
    // Mixed-length P is admitted, but the output is un-normalizable BY DESIGN
    // (S8's gate fires).
    let mixed = cover(&[t(&[1]), t(&[2, 0])]);
    assert_eq!(mixed.len(), 2);
    assert!(mixed.denotes(&t(&[2, 0, 9])));
    assert_eq!(mixed.normalize(), Err(LevelMismatch));
}
