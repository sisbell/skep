//! §G — span-sets: structural reads, union-as-concatenation, normalization
//! (S8/S9 with the pinned edges), the set-level algebra, canonical identity,
//! hull (S0), and cover (S7).

mod common;

use std::collections::{BTreeSet, HashMap};

use common::*;
use skep_address::*;

#[test]
fn empty_has_no_component_spans_and_a_singleton_has_one() {
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
    let ss: SpanSet = spanset(&[sp(&[5], &[9]), sp(&[1], &[3])]);
    let stored: Vec<Span> = ss.iter().cloned().collect();
    assert_eq!(stored, vec![sp(&[5], &[9]), sp(&[1], &[3])]); // insertion order, no normalization
    assert!(!ss.is_normalized()); // N1 violated (descending starts)
}

/// A span-set is a collection and reads like one: `for` drives it borrowed or
/// owned, `collect` closes the round trip, and `⟨⟩` is what it defaults to.
#[test]
fn span_set_is_iterable_borrowed_and_owned() {
    let ss = spanset(&[sp(&[1], &[3]), sp(&[7], &[9])]);
    let mut walked: Vec<&Span> = Vec::new();
    for s in &ss {
        walked.push(s);
    }
    assert_eq!(walked, ss.iter().collect::<Vec<_>>());
    // Owned: the component spans move out, and re-collecting recovers the set.
    let moved: Vec<Span> = ss.clone().into_iter().collect();
    assert_eq!(moved, vec![sp(&[1], &[3]), sp(&[7], &[9])]);
    assert_eq!(moved.into_iter().collect::<SpanSet>(), ss);
    assert_eq!(SpanSet::empty().into_iter().count(), 0);
    // `Default` is the empty designation, not a second spelling of it.
    assert_eq!(SpanSet::default(), SpanSet::empty());
    assert!(SpanSet::default().is_empty());
}

/// Both walks run backwards, report their exact length, and are fused — so a
/// consumer reading a normalized set from its high end (N1 puts the greatest
/// start last) works with the walk instead of collecting it first, borrowed or
/// owned alike.
#[test]
fn both_span_walks_run_both_ways_and_report_their_length() {
    fn double_ended_exact_and_fused<I>(_: I)
    where
        I: DoubleEndedIterator + ExactSizeIterator + std::iter::FusedIterator,
    {
    }

    let ss = spanset(&[sp(&[1], &[3]), sp(&[5], &[7]), sp(&[9], &[12])]);
    double_ended_exact_and_fused(ss.iter());
    double_ended_exact_and_fused(ss.clone().into_iter());

    assert_eq!(ss.iter().len(), ss.len()); // exact, before a single step
    assert_eq!(ss.iter().next_back(), Some(&sp(&[9], &[12]))); // greatest start, no collect
    let descending = vec![sp(&[9], &[12]), sp(&[5], &[7]), sp(&[1], &[3])];
    assert_eq!(ss.iter().cloned().rev().collect::<Vec<_>>(), descending);
    // Owned from the high end: the component spans move out in reverse.
    assert_eq!(ss.clone().into_iter().rev().collect::<Vec<_>>(), descending);
    assert_eq!(ss.clone().into_iter().len(), 3);
    // A cursor walked from both ends still knows what is left.
    let mut walk = ss.iter();
    walk.next();
    walk.next_back();
    assert_eq!(walk.len(), 1);
    assert_eq!(walk.next(), Some(&sp(&[5], &[7])));
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
    let raw = spanset(&[sp(&[5], &[9]), sp(&[1], &[3]), sp(&[3], &[5])]);
    let norm = raw.normalize().unwrap();
    assert_eq!(norm, spanset(&[sp(&[1], &[9])])); // overlap AND adjacency coalesce (N2)
    assert!(norm.is_normalized());
    assert_eq!(norm.normalize().unwrap(), norm); // idempotent (unique form, S9)
    // Pinned edges: S8's n = 0 case.
    assert_eq!(SpanSet::empty().normalize().unwrap(), SpanSet::empty());
    assert!(SpanSet::empty().is_normalized());
}

/// S8's coalescing step extends the running reach to the MAXIMUM of the two,
/// so a span nested inside its predecessor cannot shorten it. Nesting is the
/// only shape where the choice shows, and the equal-start pair is the tie S8
/// breaks arbitrarily and S9 says must not matter.
#[test]
fn normalize_keeps_the_widest_reach_of_a_coalesced_run() {
    let whole = spanset(&[sp(&[1], &[9])]);
    let nested = [
        spanset(&[sp(&[1], &[9]), sp(&[3], &[5])]), // wide first
        spanset(&[sp(&[3], &[5]), sp(&[1], &[9])]), // narrow first
        spanset(&[sp(&[1], &[9]), sp(&[1], &[5])]), // equal starts, wide first
        spanset(&[sp(&[1], &[5]), sp(&[1], &[9])]), // equal starts, narrow first
    ];
    for raw in nested {
        assert_eq!(raw.normalize().unwrap(), whole, "swallowed reach of {raw:?}");
    }
}

/// S8's loop invariant J is denotation preservation, and S9 makes the result
/// unique — so it cannot depend on the order the component spans arrive in.
/// Asserted over every ordered triple drawn from a pool of six, which visits
/// nested, overlapping, adjacent, separated and duplicated shapes nobody chose.
#[test]
fn normalize_preserves_the_denotation_in_any_order() {
    let pool = [
        sp(&[1], &[3]),
        sp(&[2], &[5]),
        sp(&[4], &[9]),
        sp(&[9], &[12]),
        sp(&[1], &[30]),
        sp(&[20], &[30]),
    ];
    let probes: Vec<Tumbler> = (0u32..32)
        .map(|x| t(&[x]))
        .chain([t(&[2, 5]), t(&[29, 9])])
        .collect();
    let mut seen: HashMap<Vec<usize>, SpanSet> = HashMap::new();
    for i in 0..pool.len() {
        for j in 0..pool.len() {
            for k in 0..pool.len() {
                let idx = [i, j, k];
                let raw = spanset(&idx.map(|x| pool[x].clone()));
                let norm = raw.normalize().unwrap();
                for probe in &probes {
                    assert_eq!(
                        raw.denotes(probe),
                        norm.denotes(probe),
                        "normalize({raw:?}) changed the denotation at {probe:?}"
                    );
                }
                assert!(norm.is_normalized(), "normalize({raw:?}) is not normalized");
                assert_eq!(norm.normalize().unwrap(), norm, "normalize is idempotent");
                // N1 ∧ N2 read directly: starts ascend and no two component
                // spans touch, which is what `is_normalized` decides via
                // equality.
                let component_spans: Vec<&Span> = norm.iter().collect();
                for w in component_spans.windows(2) {
                    assert!(
                        w[0].reach() < *w[1].start(),
                        "N1/N2: {:?} and {:?} should have coalesced",
                        w[0],
                        w[1]
                    );
                }
                // S9: one canonical form per multiset, whatever the order.
                let mut key = idx.to_vec();
                key.sort_unstable();
                match seen.get(&key) {
                    Some(first) => assert_eq!(&norm, first, "order changed the canonical form"),
                    None => {
                        seen.insert(key, norm);
                    }
                }
            }
        }
    }
}

/// `level_class` answers the S8 gate directly, with the same verdict
/// `normalize` reaches through it.
#[test]
fn level_class_is_the_s8_gate_answered_directly() {
    assert_eq!(SpanSet::empty().level_class(), Ok(None)); // ⟨⟩: no class
    let flat = spanset(&[sp(&[1], &[3]), sp(&[7], &[9])]);
    assert_eq!(flat.level_class(), Ok(Some(1)));
    let deep = spanset(&[sp(&[1, 0, 2], &[1, 0, 5])]);
    assert_eq!(deep.level_class(), Ok(Some(3)));
    // The two ways a set falls outside S8's domain, each refused by both.
    let mixed = spanset(&[sp(&[1], &[3]), sp(&[1, 0], &[1, 5])]);
    assert_eq!(mixed.level_class(), Err(LevelMismatch));
    assert_eq!(mixed.normalize(), Err(LevelMismatch));
    let non_uniform = SpanSet::singleton(Span::new(t(&[1, 0, 2]), t(&[0, 1])).unwrap());
    assert_eq!(non_uniform.level_class(), Err(LevelMismatch));
    assert_eq!(non_uniform.normalize(), Err(LevelMismatch));
    // The per-span clause at a position past the first. The partner is
    // level-uniform and shares its `#start`, so nothing but the uniformity
    // clause can refuse this set, and the clause is therefore asked of every
    // component span rather than only of the one the shared length is read
    // from. A set that got past this gate would reach `normalize`'s sweep,
    // where a component span whose reach is a different length fails WF inside
    // an `expect`.
    let non_uniform_second = spanset(&[
        sp(&[1, 0, 2], &[1, 0, 5]),
        Span::new(t(&[1, 0, 2]), t(&[0, 1])).unwrap(),
    ]);
    assert_eq!(non_uniform_second.level_class(), Err(LevelMismatch));
    assert_eq!(non_uniform_second.normalize(), Err(LevelMismatch));
    assert!(!non_uniform_second.is_normalized());
    assert_eq!(canonical_key(&non_uniform_second), Err(LevelMismatch));
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
    // Every component span survives, in its own class and no other.
    assert!(parts[&1].denotes(&t(&[1])));
    assert!(parts[&2].denotes(&t(&[2, 0, 9])));
    assert!(!parts[&1].denotes(&t(&[2, 0, 9])));
    // TOTAL: a non-level-uniform component span is partitioned by its start,
    // then refused by its own class's gate — exactly as the whole set refused
    // it.
    let with_non_uniform = spanset(&[
        Span::new(t(&[1, 0, 2]), t(&[0, 1])).unwrap(),
        sp(&[1], &[3]),
    ]);
    let parts = with_non_uniform.by_level_class();
    assert_eq!(parts[&3].level_class(), Err(LevelMismatch));
    assert_eq!(parts[&1].level_class(), Ok(Some(1)));
}

#[test]
fn normalize_gate_is_the_full_s8_precondition() {
    // Mutually incompatible length classes.
    let mixed = spanset(&[sp(&[1], &[3]), sp(&[1, 0], &[1, 5])]);
    assert_eq!(mixed.normalize(), Err(LevelMismatch));
    assert!(!mixed.is_normalized());
    // A non-level-uniform component span.
    let non_uniform = SpanSet::singleton(Span::new(t(&[1, 0, 2]), t(&[0, 1])).unwrap());
    assert_eq!(non_uniform.normalize(), Err(LevelMismatch));
}

#[test]
fn denotes_is_membership_in_some_component_span() {
    let ss = spanset(&[sp(&[1], &[3]), sp(&[7], &[9])]);
    assert!(ss.denotes(&t(&[1])));
    assert!(ss.denotes(&t(&[2, 5]))); // deeper extension inside a component span
    assert!(!ss.denotes(&t(&[5])));
    assert!(ss.denotes(&t(&[7])));
    assert!(!ss.denotes(&t(&[9])));
    assert!(!SpanSet::empty().denotes(&t(&[1]))); // ⟨⟩ denotes nothing
}

#[test]
fn intersect_sets_normalizes_internally_and_emits_normalized() {
    let a = spanset(&[sp(&[5], &[9]), sp(&[1], &[4])]); // deliberately un-normalized input
    let b = spanset(&[sp(&[3], &[7])]);
    let r = intersect_sets(&a, &b).unwrap();
    assert_eq!(r, spanset(&[sp(&[3], &[4]), sp(&[5], &[7])]));
    assert!(r.is_normalized());
    assert_eq!(intersect_sets(&a, &SpanSet::empty()).unwrap(), SpanSet::empty());
    // The two sets must be mutually level-compatible.
    let cross = spanset(&[sp(&[1, 0], &[1, 5])]);
    assert_eq!(intersect_sets(&a, &cross), Err(LevelMismatch));
}

#[test]
fn difference_sets_carves_and_emits_normalized() {
    let a = spanset(&[sp(&[1], &[9])]);
    let b = spanset(&[sp(&[3], &[5])]);
    let r = difference_sets(&a, &b).unwrap();
    assert_eq!(r, spanset(&[sp(&[1], &[3]), sp(&[5], &[9])]));
    assert!(r.is_normalized());
    // One b-span crossing the gap between two a-spans.
    let a2 = spanset(&[sp(&[1], &[3]), sp(&[5], &[7])]);
    let b2 = spanset(&[sp(&[2], &[6])]);
    assert_eq!(
        difference_sets(&a2, &b2).unwrap(),
        spanset(&[sp(&[1], &[2]), sp(&[6], &[7])])
    );
    assert_eq!(difference_sets(&a, &a).unwrap(), SpanSet::empty());
    // An empty subtrahend leaves every a-span whole. The sweep carries each
    // one out through its derived (start, reach) form and back, so this also
    // pins that the round trip is the IDENTITY on a level-uniform span — a
    // multi-span, deeper-class case as well as the flat one.
    assert_eq!(
        difference_sets(&a, &SpanSet::empty()).unwrap(),
        a.normalize().unwrap()
    );
    let deep = spanset(&[sp(&[1, 0, 7], &[1, 0, 9]), sp(&[2, 5, 1], &[2, 5, 8])]);
    assert_eq!(
        difference_sets(&deep, &SpanSet::empty()).unwrap(),
        deep.normalize().unwrap()
    );
    assert_eq!(difference_sets(&SpanSet::empty(), &a).unwrap(), SpanSet::empty());
    let cross = spanset(&[sp(&[1, 0], &[1, 5])]);
    assert_eq!(difference_sets(&a, &cross), Err(LevelMismatch));
}

/// The two set-level sweeps interleave two canonical forms, and their cursor
/// logic decides which regions survive — so both are asserted pointwise
/// against the denotations they promise, over every ordered pair of a pool
/// carrying multi-span operands, set-scale adjacency, nesting, duplication
/// and un-normalized input on both sides.
#[test]
fn set_algebra_agrees_pointwise_with_the_denotations() {
    let pool = [
        SpanSet::empty(),
        spanset(&[sp(&[1], &[9])]),                                 // one wide span
        spanset(&[sp(&[2], &[3]), sp(&[5], &[6])]),                 // two separated
        spanset(&[sp(&[5], &[6]), sp(&[2], &[3])]),                 // the same two, un-normalized
        spanset(&[sp(&[1], &[3])]),
        spanset(&[sp(&[3], &[5])]),                                 // touching the previous
        spanset(&[sp(&[1], &[5]), sp(&[3], &[9]), sp(&[1], &[5])]), // overlapping + duplicated
        spanset(&[sp(&[1], &[9]), sp(&[3], &[5])]),                 // nested
        spanset(&[sp(&[9], &[12])]),
    ];
    let probes: Vec<Tumbler> = (0u32..14)
        .map(|x| t(&[x]))
        .chain([t(&[2, 5]), t(&[8, 0, 1])])
        .collect();
    for a in &pool {
        for b in &pool {
            let both = intersect_sets(a, b).unwrap();
            let only_a = difference_sets(a, b).unwrap();
            for probe in &probes {
                assert_eq!(
                    both.denotes(probe),
                    a.denotes(probe) && b.denotes(probe),
                    "intersect_sets({a:?}, {b:?}) disagrees at {probe:?}"
                );
                assert_eq!(
                    only_a.denotes(probe),
                    a.denotes(probe) && !b.denotes(probe),
                    "difference_sets({a:?}, {b:?}) disagrees at {probe:?}"
                );
            }
            assert!(both.is_normalized(), "intersect_sets({a:?}, {b:?}) is not normalized");
            assert!(
                only_a.is_normalized(),
                "difference_sets({a:?}, {b:?}) is not normalized"
            );
            // The carve's published fan-out: at most one gap per b-span (a
            // b-start lies strictly inside at most one a-span) plus at most
            // one tail per a-span, and normalizing never grows either side.
            assert!(
                only_a.len() <= a.len() + b.len(),
                "difference_sets({a:?}, {b:?}) fan-out"
            );
        }
    }
}

#[test]
fn equiv_compares_canonical_forms() {
    let x = spanset(&[sp(&[1], &[3]), sp(&[3], &[5])]);
    let y = spanset(&[sp(&[1], &[5])]);
    assert_eq!(equiv(&x, &y), Ok(true)); // same denotation, different structure
    assert_ne!(x, y); // raw Eq is structural, NOT denotational
    assert_eq!(equiv(&x, &spanset(&[sp(&[1], &[4])])), Ok(false));
    // Two internally-uniform sets in DIFFERENT length classes: Ok(false), not Err (§7).
    let other_class = spanset(&[sp(&[1, 0], &[1, 5])]);
    assert_eq!(equiv(&y, &other_class), Ok(false));
    // That is where `equiv` parts from the two sweeps, which refuse the SAME
    // pair outright — so a caller cannot reach the partition by dispatching on
    // `equiv`'s error, and asks `level_class` for the classes instead.
    assert_eq!(intersect_sets(&y, &other_class), Err(LevelMismatch));
    assert_eq!(difference_sets(&y, &other_class), Err(LevelMismatch));
    assert_eq!(y.level_class(), Ok(Some(1)));
    assert_eq!(other_class.level_class(), Ok(Some(2)));
    // An internally mixed set is still an error.
    let mixed = spanset(&[sp(&[1], &[3]), sp(&[1, 0], &[1, 5])]);
    assert_eq!(equiv(&mixed, &y), Err(LevelMismatch));
}

#[test]
fn canonical_key_is_the_denotational_dedup_identity() {
    let x = spanset(&[sp(&[3], &[5]), sp(&[1], &[3])]);
    let y = spanset(&[sp(&[1], &[5])]);
    let kx = canonical_key(&x).unwrap();
    let ky = canonical_key(&y).unwrap();
    assert_eq!(kx, ky); // S9: one canonical form per denotation
    assert!(kx.as_set().is_normalized()); // the read-only normalized view
    // Usable directly as an in-memory dedup/cache key (Hash + Eq).
    let mut m = HashMap::new();
    m.insert(kx, 1);
    assert_eq!(m.get(&ky), Some(&1));
    assert!(canonical_key(&SpanSet::empty()).is_ok()); // ⟨⟩ → the empty canonical form
    assert_eq!(canonical_key(&spanset(&[sp(&[1], &[3]), sp(&[1, 0], &[1, 5])])), Err(LevelMismatch));
}

#[test]
fn hull_is_the_tight_single_span_cover() {
    assert_eq!(hull(&[]), Ok(None)); // nothing to enclose — not a domain violation
    let p = [t(&[3]), t(&[1]), t(&[1, 5, 5])];
    let h = hull(&p).unwrap().unwrap();
    assert_eq!(h.start(), &t(&[1]));
    assert_eq!(h.reach(), t(&[4])); // the reach convention on max
    assert!(p.iter().all(|x| h.contains(x))); // covers the mixed-length interior point too
    // A STRADDLING P is the domain violation, and answers as one — distinct
    // from the empty set's Ok(None).
    assert_eq!(hull(&[t(&[0, 1]), t(&[5])]), Err(LevelMismatch)); // #min ≠ #max
    // Tight on a trailing-zero max: reach = [2,1], not inc(max,0) = [3,0].
    let h2 = hull(&[t(&[1, 0]), t(&[2, 0])]).unwrap().unwrap();
    assert_eq!(h2.reach(), t(&[2, 1]));
    assert!(h2.contains(&t(&[2, 0, 7])));
    assert!(!h2.contains(&t(&[2, 5])));
}

/// P is a walk, not a buffer: both point-set operations read each point once
/// through a borrow, so a caller hands over the iterator it already holds — a
/// deduplicating set, a filtered view, a borrowed sequence — instead of
/// materializing owned tumblers to have them compared.
#[test]
fn the_point_set_operations_take_any_walk_over_borrowed_points() {
    let owned = vec![t(&[3]), t(&[1]), t(&[7])];

    // A set — what a caller holding S7's set-cardinality reading has already
    // built. Nothing is copied to be compared, and nothing is collected first.
    let deduped: BTreeSet<Tumbler> = [t(&[3]), t(&[1]), t(&[7]), t(&[1])].into_iter().collect();
    assert_eq!(hull(&deduped), hull(&owned));
    assert_eq!(cover(&deduped).len(), 3); // |Σ| = the points yielded

    // A filtered view — a caller that selected before calling.
    let selected = owned.iter().filter(|x| **x > t(&[1]));
    assert_eq!(hull(selected), hull(&[t(&[3]), t(&[7])]));

    // A borrowed sequence still reads as one point set, by slice or by walk.
    assert_eq!(hull(&owned[..]), hull(&owned));
    assert_eq!(cover(owned.iter()), cover(&owned));
}

#[test]
fn cover_is_one_unit_span_per_point() {
    assert_eq!(cover(&[]), SpanSet::empty());
    let p = [t(&[1]), t(&[2]), t(&[1])]; // duplicates allowed: |Σ| = points yielded
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
