//! §F — span constructors (T12/WF with the documented error precedence), the
//! SC classifier, and the gated pairwise algebra (S1–S6, S11).

mod common;

use common::*;
use skep_address::*;

// ---- constructors -----------------------------------------------------------

#[test]
fn span_new_enforces_t12() {
    assert!(Span::new(t(&[1, 0, 2]), t(&[0, 0, 1])).is_ok());
    assert_eq!(
        Span::new(t(&[1]), t(&[0, 0])).unwrap_err(),
        T12Clause::ZeroWidth
    );
    assert_eq!(
        Span::new(t(&[1]), t(&[0, 1])).unwrap_err(),
        T12Clause::ActionPointTooDeep
    );
}

/// T12 IS `⊕`'s domain, and `Span::reach` unwraps `⊕` on the strength of it.
/// The two must admit exactly the same pairs: a `Span` that exists and a
/// `reach()` that panics is the failure this pins, and it would surface in
/// M5/M6/M7 rather than here.
#[test]
fn span_new_admits_exactly_what_add_accepts() {
    let starts = [t(&[1]), t(&[1, 0, 2]), t(&[0, 0]), t(&[7, 3, 1, 4])];
    let widths = [
        t(&[0]),          // zero displacement
        t(&[0, 0]),       // zero displacement, longer
        t(&[1]),          // acts at position 1
        t(&[0, 1]),       // acts at position 2
        t(&[0, 0, 5]),    // acts at position 3
        t(&[0, 0, 0, 2]), // acts at position 4
        t(&[2, 9, 9]),
    ];
    for s in &starts {
        for w in &widths {
            let span = Span::new(s.clone(), w.clone());
            assert_eq!(
                span.is_ok(),
                add(s, w).is_ok(),
                "T12 and ⊕ disagree on ({s:?}, {w:?})"
            );
            // Where T12 admits, reach() is total and lands where ⊕ says.
            if let Ok(span) = span {
                assert_eq!(span.reach(), add(s, w).unwrap());
                assert!(span.reach() > *span.start()); // T12's whole purpose
            }
        }
    }
}

#[test]
fn from_endpoints_derives_the_width_and_checks_the_level_clause_first() {
    let s = sp(&[1, 0, 2], &[1, 0, 5]);
    assert_eq!(s.start(), &t(&[1, 0, 2]));
    assert_eq!(s.width(), &t(&[0, 0, 3]));
    assert_eq!(s.reach(), t(&[1, 0, 5])); // start ⊕ width, recomputed
    assert_eq!(
        Span::from_endpoints(t(&[2]), &t(&[2])).unwrap_err(),
        WfError::NotIncreasing
    );
    assert_eq!(
        Span::from_endpoints(t(&[3]), &t(&[2])).unwrap_err(),
        WfError::NotIncreasing
    );
    assert_eq!(
        Span::from_endpoints(t(&[1]), &t(&[1, 5])).unwrap_err(),
        WfError::LevelMismatch
    );
    // The level clause runs FIRST: a pair failing BOTH yields LevelMismatch (§6).
    assert_eq!(
        Span::from_endpoints(t(&[2, 0]), &t(&[1])).unwrap_err(),
        WfError::LevelMismatch
    );
}

#[test]
fn contains_is_half_open() {
    let s = sp(&[1, 0, 2], &[1, 0, 5]);
    assert!(s.contains(&t(&[1, 0, 2]))); // start inclusive
    assert!(s.contains(&t(&[1, 0, 4, 9, 9]))); // deeper extensions inside
    assert!(!s.contains(&t(&[1, 0, 5]))); // reach exclusive
    assert!(!s.contains(&t(&[1, 0, 1])));
}

#[test]
fn zero_sentinel_is_a_legal_span_endpoint() {
    // TA6 quarantine: the all-zero tumbler is rejected as an address but the
    // span layer never consults the address validator.
    let s = sp(&[0, 0], &[1, 0]);
    assert!(s.contains(&t(&[0, 5])));
    assert_eq!(classify(&t(&[0, 0])), Class::Invalid);
}

#[test]
fn is_level_uniform_reads_start_and_width_lengths() {
    assert!(sp(&[1, 0, 2], &[1, 0, 5]).is_level_uniform());
    assert!(!Span::new(t(&[1, 0, 2]), t(&[0, 1])).unwrap().is_level_uniform());
}

// ---- subtree_of (T5 + S7 witness width) -------------------------------------

#[test]
fn subtree_of_captures_exactly_the_subtree() {
    let s = subtree_of(&t(&[1, 0, 2]));
    assert_eq!(s.start(), &t(&[1, 0, 2]));
    assert_eq!(s.width(), &t(&[0, 0, 1])); // δ(1, #p) — S7's witness width
    assert_eq!(s.reach(), t(&[1, 0, 3]));
    assert!(s.contains(&t(&[1, 0, 2])));
    assert!(s.contains(&t(&[1, 0, 2, 9, 9]))); // every extension of p
    assert!(!s.contains(&t(&[1, 0, 3])));
}

#[test]
fn subtree_of_a_trailing_zero_prefix_does_not_overcapture() {
    // The width advances position #p, not sig(p): reach is [2,1], so [2,1]
    // (not an extension of [2,0]) stays out — the inc(p,0) mis-width guarded
    // against by the design.
    let s = subtree_of(&t(&[2, 0]));
    assert_eq!(s.reach(), t(&[2, 1]));
    assert!(s.contains(&t(&[2, 0])));
    assert!(s.contains(&t(&[2, 0, 5])));
    assert!(!s.contains(&t(&[2, 1])));
}

/// T5 — `subtree_of(p)` denotes EXACTLY the extensions of `p`, in both
/// directions and for any carrier prefix. Asserted against a reading of
/// "extension" written from the promise, over every tumbler of length 1..=3
/// over `{0, 1, 2, 3}` plus each prefix's own near neighbours — so the lower
/// boundary (a proper prefix of `p`, which is NOT an extension) is visited as
/// well as the reach.
#[test]
fn subtree_of_denotes_exactly_the_extensions_of_the_prefix() {
    let prefixes = [
        t(&[1]),
        t(&[2, 0]),
        t(&[0, 0]), // a carrier sentinel is a legal prefix
        t(&[1, 0, 2]),
        t(&[1, 0, 2, 0, 5]),
        t(&[3, 7]),
    ];
    let mut probes = tumblers_upto(&[0, 1, 2, 3], 3);
    for p in &prefixes {
        probes.push(p.clone());
        for tail in [&[0u32][..], &[1][..], &[9][..], &[0, 1][..], &[7, 7][..]] {
            let mut comps: Vec<Nat> = p.iter().cloned().collect();
            comps.extend(tail.iter().map(|&c| n(c)));
            probes.push(tumbler(comps));
        }
    }
    for p in &prefixes {
        let s = subtree_of(p);
        for probe in &probes {
            let is_extension =
                p.len() <= probe.len() && p.iter().zip(probe.iter()).all(|(a, b)| a == b);
            assert_eq!(
                s.contains(probe),
                is_extension,
                "subtree_of({p}) disagrees at {probe}"
            );
        }
    }
}

// ---- SC classifier ----------------------------------------------------------

#[test]
fn classify_spans_decides_the_five_cases_by_endpoint_order() {
    assert_eq!(classify_spans(&sp(&[1], &[3]), &sp(&[5], &[9])), SpanRel::Separated);
    assert_eq!(classify_spans(&sp(&[1], &[3]), &sp(&[3], &[5])), SpanRel::Adjacent);
    assert_eq!(classify_spans(&sp(&[1], &[5]), &sp(&[1], &[5])), SpanRel::Equal);
    assert_eq!(classify_spans(&sp(&[1], &[9]), &sp(&[3], &[5])), SpanRel::Containment);
    assert_eq!(classify_spans(&sp(&[3], &[5]), &sp(&[1], &[9])), SpanRel::Containment);
    assert_eq!(classify_spans(&sp(&[1], &[5]), &sp(&[3], &[9])), SpanRel::ProperOverlap);
    assert_eq!(classify_spans(&sp(&[3], &[9]), &sp(&[1], &[5])), SpanRel::ProperOverlap);
}

#[test]
fn classify_spans_has_no_level_gate() {
    // Mixed-length operands still classify: the classifier constructs nothing.
    assert_eq!(
        classify_spans(&sp(&[1], &[2]), &sp(&[5, 0], &[6, 0])),
        SpanRel::Separated
    );
}

// ---- the unconditional level gate -------------------------------------------

#[test]
fn pairwise_ops_gate_unconditionally_before_dispatch() {
    // Separated but level-mismatched operands: Err, never Ok(None)/Ok({a}) (§6).
    let a = sp(&[1], &[2]);
    let b = sp(&[5, 0], &[6, 0]);
    assert_eq!(intersect(&a, &b), Err(LevelMismatch));
    assert_eq!(merge(&a, &b), Err(LevelMismatch));
    assert_eq!(difference(&a, &b), Err(LevelMismatch));
    // A non-level-uniform operand fails the per-span half of the gate — in
    // EITHER position, on each of the three ops. The partner is level-uniform
    // and shares its start length, so nothing but the per-span clause can
    // refuse these pairs, and each operand is therefore asked about on its own
    // rather than through a self-pairing that either side would answer for.
    let nu = Span::new(t(&[1, 0, 2]), t(&[0, 1])).unwrap();
    let uniform = sp(&[1, 0, 2], &[1, 0, 5]);
    assert_eq!(intersect(&nu, &nu), Err(LevelMismatch));
    for (x, y) in [(&nu, &uniform), (&uniform, &nu)] {
        assert_eq!(intersect(x, y), Err(LevelMismatch));
        assert_eq!(merge(x, y), Err(LevelMismatch));
        assert_eq!(difference(x, y), Err(LevelMismatch));
    }
}

/// `intersect` and `merge` each decide one boundary question inline instead
/// of classifying, so their verdicts and `classify_spans`'s are reached by
/// different code and could drift apart in silence. They may not: `merge`
/// yields nothing exactly on Separated, `intersect` exactly on Separated or
/// Adjacent. Every SC case appears here, in both orders.
#[test]
fn inline_boundary_tests_agree_with_the_classifier() {
    let battery = [
        sp(&[1], &[9]),   // the reference interval
        sp(&[3], &[5]),   // strictly inside it
        sp(&[5], &[12]),  // overlapping past its reach
        sp(&[1], &[5]),   // sharing its start
        sp(&[5], &[9]),   // sharing its reach
        sp(&[9], &[12]),  // adjacent to it
        sp(&[20], &[30]), // separated from it
    ];
    for a in &battery {
        for b in &battery {
            let rel = classify_spans(a, b);
            assert_eq!(
                merge(a, b).unwrap().is_none(),
                rel == SpanRel::Separated,
                "merge disagrees with SC on ({a:?}, {b:?})"
            );
            assert_eq!(
                intersect(a, b).unwrap().is_none(),
                matches!(rel, SpanRel::Separated | SpanRel::Adjacent),
                "intersect disagrees with SC on ({a:?}, {b:?})"
            );
        }
    }
}

// ---- intersect / merge / split ----------------------------------------------

#[test]
fn intersect_yields_the_shared_region_and_nothing_when_disjoint() {
    assert_eq!(
        intersect(&sp(&[1], &[5]), &sp(&[3], &[9])).unwrap(),
        Some(sp(&[3], &[5]))
    );
    assert_eq!(intersect(&sp(&[1], &[3]), &sp(&[3], &[5])).unwrap(), None); // adjacent share nothing
    assert_eq!(intersect(&sp(&[1], &[3]), &sp(&[7], &[9])).unwrap(), None);
    assert_eq!(
        intersect(&sp(&[1], &[9]), &sp(&[3], &[5])).unwrap(),
        Some(sp(&[3], &[5]))
    );
}

#[test]
fn merge_joins_overlapping_and_adjacent_spans_and_refuses_separated() {
    assert_eq!(
        merge(&sp(&[1], &[5]), &sp(&[3], &[9])).unwrap(),
        Some(sp(&[1], &[9]))
    );
    assert_eq!(
        merge(&sp(&[1], &[3]), &sp(&[3], &[5])).unwrap(),
        Some(sp(&[1], &[5]))
    ); // adjacency merges (S3a)
    assert_eq!(merge(&sp(&[1], &[3]), &sp(&[7], &[9])).unwrap(), None); // separated
}

#[test]
fn split_cuts_at_an_interior_point_and_checks_the_level_clause_first() {
    let s = sp(&[1], &[9]);
    let (l, r) = split(&s, &t(&[4])).unwrap();
    assert_eq!(l, sp(&[1], &[4]));
    assert_eq!(r, sp(&[4], &[9]));
    assert_eq!(classify_spans(&l, &r), SpanRel::Adjacent); // adjacent by construction
    assert_eq!(split(&s, &t(&[1])), Err(SplitError::NotInterior)); // p = start
    assert_eq!(split(&s, &t(&[9])), Err(SplitError::NotInterior)); // p = reach
    // Level conditions run FIRST: a point of the wrong length is LevelMismatch
    // even when it is order-interior, and also when it is not interior at all.
    assert_eq!(split(&s, &t(&[5, 0])), Err(SplitError::LevelMismatch));
    assert_eq!(split(&s, &t(&[9, 5])), Err(SplitError::LevelMismatch));
    // σ itself must be level-uniform (S4).
    let nu = Span::new(t(&[1, 0, 2]), t(&[0, 1])).unwrap();
    assert_eq!(split(&nu, &t(&[1, 0, 3])), Err(SplitError::LevelMismatch));
}

// ---- difference (S11d) ------------------------------------------------------

#[test]
fn difference_yields_one_or_two_complements_by_sc_case() {
    let a = sp(&[1], &[9]);
    // separated / adjacent: ⟦a⟧ unchanged
    assert_eq!(difference(&a, &sp(&[20], &[30])).unwrap(), spanset(&[a.clone()]));
    assert_eq!(difference(&a, &sp(&[9], &[12])).unwrap(), spanset(&[a.clone()]));
    // proper overlap, a first: the left complement
    assert_eq!(difference(&a, &sp(&[5], &[12])).unwrap(), spanset(&[sp(&[1], &[5])]));
    // proper overlap, b first: the right complement
    assert_eq!(
        difference(&sp(&[5], &[12]), &sp(&[1], &[9])).unwrap(),
        spanset(&[sp(&[9], &[12])])
    );
    // strict containment: two complements in N1 order, normalized by construction
    let two = difference(&a, &sp(&[3], &[5])).unwrap();
    assert_eq!(two, spanset(&[sp(&[1], &[3]), sp(&[5], &[9])]));
    assert!(two.is_normalized());
    // a shared boundary drops the zero-width complement (S11d's "1 or 2"; S2)
    assert_eq!(difference(&a, &sp(&[1], &[5])).unwrap(), spanset(&[sp(&[5], &[9])]));
    assert_eq!(difference(&a, &sp(&[5], &[9])).unwrap(), spanset(&[sp(&[1], &[5])]));
    // a ⊆ b, including equal: empty
    assert_eq!(difference(&sp(&[3], &[5]), &a).unwrap(), SpanSet::empty());
    assert_eq!(difference(&a, &a).unwrap(), SpanSet::empty());
}

/// `classify_spans` and `difference` read ONE classification, so the
/// orientation cannot drift between them: whichever way a pair is ordered,
/// the result denotes exactly the part of `a` outside `b` — never `b`'s
/// complement, and never anything outside `a`. Every SC case appears in the
/// battery, each in both orders.
#[test]
fn difference_carves_a_not_b_in_every_orientation() {
    let battery = [
        sp(&[1], &[9]),   // the reference interval
        sp(&[3], &[5]),   // strictly inside it
        sp(&[5], &[12]),  // overlapping past its reach
        sp(&[1], &[5]),   // sharing its start
        sp(&[5], &[9]),   // sharing its reach
        sp(&[9], &[12]),  // adjacent to it
        sp(&[20], &[30]), // separated from it
    ];
    let probes: Vec<Tumbler> = [1u32, 3, 4, 5, 8, 9, 11, 12, 20, 25, 30]
        .iter()
        .map(|&x| t(&[x]))
        .collect();
    for a in &battery {
        for b in &battery {
            let only_a = difference(a, b).unwrap();
            for probe in &probes {
                assert_eq!(
                    only_a.denotes(probe),
                    a.contains(probe) && !b.contains(probe),
                    "difference({a:?}, {b:?}) disagrees at {probe:?}"
                );
            }
            // The published bounds on the result, in every case: ≤ 2 spans
            // (S11d/S1), and normalized by construction — the N1 ordering of
            // the two complements included.
            assert!(only_a.len() <= 2, "S11d fan-out on ({a:?}, {b:?})");
            assert!(
                only_a.is_normalized(),
                "difference({a:?}, {b:?}) is not normalized by construction"
            );
            // The two non-constructing cases return ⟦a⟧ itself, whole.
            if matches!(
                classify_spans(a, b),
                SpanRel::Separated | SpanRel::Adjacent
            ) {
                assert_eq!(only_a, spanset(std::slice::from_ref(a)));
            }
        }
    }
}
