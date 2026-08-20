//! The design's "by property test" obligations — the algebraic laws from the
//! source notes, named one test apiece: S4a, S3b, S5, S3a/S10, TS1–TS5,
//! TA-LC vs TA-MTO/TA-RC, and the D1/D2 displacement round-trip.

mod common;

use common::*;
use skep_address::*;

/// S4a — merging the two parts of `split(σ, p)` recovers σ exactly, for any
/// level-uniform σ and interior p.
#[test]
fn s4a_split_then_merge_recovers_sigma() {
    let cases = [
        (sp(&[1], &[9]), t(&[5])),
        (sp(&[1, 0], &[9, 0]), t(&[4, 2])),
        (sp(&[2, 5], &[2, 9]), t(&[2, 7])),
    ];
    for (sigma, p) in cases {
        let (l, r) = split(&sigma, &p).unwrap();
        assert_eq!(merge(&l, &r).unwrap(), Some(sigma));
    }
}

/// S3b — on adjacent pairs, `split(merge(α, β), boundary)` recovers `{α, β}`
/// with the left/right orientation preserved.
#[test]
fn s3b_merge_then_split_recovers_the_adjacent_pair() {
    let alpha = sp(&[1, 0], &[4, 2]);
    let beta = sp(&[4, 2], &[9, 0]);
    let merged = merge(&alpha, &beta).unwrap().unwrap();
    let (l, r) = split(&merged, &t(&[4, 2])).unwrap();
    assert_eq!((l, r), (alpha, beta));
}

/// S5 — the two part-widths of any split satisfy `d ⊕ d′ = ℓ`.
#[test]
fn s5_split_widths_compose_to_the_whole() {
    let cases = [
        (sp(&[1], &[9]), t(&[5])),
        (sp(&[1, 2], &[2, 0]), t(&[1, 5])),
        (sp(&[1, 0], &[9, 0]), t(&[4, 2])),
    ];
    for (sigma, p) in cases {
        let (l, r) = split(&sigma, &p).unwrap();
        assert_eq!(add(l.width(), r.width()).unwrap(), sigma.width().clone());
    }
}

/// S3a/S10 — union is order- and grouping-independent up to the canonical
/// form, with idempotence as a derived corollary.
#[test]
fn s10_union_laws_up_to_canonical_form() {
    let a = spanset(&[sp(&[1], &[4])]);
    let b = spanset(&[sp(&[3], &[6]), sp(&[9], &[12])]);
    // `c` carries a nested pair, so the canonical form these laws are stated
    // up to is one that coalescing actually had to decide.
    let c = spanset(&[sp(&[6], &[9]), sp(&[7], &[8])]);
    let key = |s: &SpanSet| canonical_key(s).unwrap();
    assert_eq!(key(&union(&a, &b)), key(&union(&b, &a))); // commutative
    assert_eq!(
        key(&union(&union(&a, &b), &c)),
        key(&union(&a, &union(&b, &c)))
    ); // associative
    assert_eq!(key(&union(&a, &a)), key(&a)); // idempotence (derived corollary)
}

/// TS1/TS3/TS4/TS5 — the ordinal-shift laws that quantify over one operand.
/// The last two operands carry components past 2⁶⁴, where TS4's strict
/// increase is exactly what a wrapping component add would break (T0(a)).
#[test]
fn ts_ordinal_shift_is_strictly_increasing_length_preserving_and_additive() {
    let vs = [
        t(&[1]),
        t(&[1, 0]),
        t(&[2, 5]),
        t(&[1, 0, 2, 0, 5, 0, 1, 9]),
        tumbler([Nat::from(u64::MAX)]),
        tumbler([n(2), Nat::from(u64::MAX)]),
    ];
    for v in &vs {
        for amount in [n(1), n(2), n(7)] {
            let s = shift(v, &amount);
            assert!(s > *v); // TS4: strict increase
            assert_eq!(s.len(), v.len()); // length-preserving
        }
        assert!(shift(v, &n(1)) < shift(v, &n(2))); // TS5: amount-monotone
        assert_ne!(shift(v, &n(1)), shift(v, &n(2))); // distinctness, TS5's corollary
        assert_eq!(shift(&shift(v, &n(2)), &n(3)), shift(v, &n(5))); // TS3: composes
    }
    // TS1: order preservation on same-length operands.
    let (v, w) = (t(&[1, 5]), t(&[2, 0]));
    assert!(v < w);
    assert!(shift(&v, &n(4)) < shift(&w, &n(4)));
}

/// TS2 (ShiftInjectivity) — `#v₁ = #v₂ ∧ shift(v₁, n) = shift(v₂, n) ⟹
/// v₁ = v₂`: injectivity in the OPERAND, which is what lets the I-stream stay
/// distinct under shift. Asserted over every same-length pair drawn from all
/// tumblers of length 1..=3 over `{0, 1, 2}`, so operands sharing a prefix —
/// the ones a shift that assigned rather than added would collapse — are
/// visited rather than chosen.
#[test]
fn ts2_shift_is_injective_in_the_operand() {
    let family = tumblers_upto(&[0, 1, 2], 3);
    for amount in [n(1), n(4)] {
        for v1 in &family {
            for v2 in &family {
                if v1.len() != v2.len() || v1 == v2 {
                    continue;
                }
                assert_ne!(
                    shift(v1, &amount),
                    shift(v2, &amount),
                    "TS2: shift collapsed {v1:?} and {v2:?}"
                );
            }
        }
    }
}

/// TA-LC — left cancellation holds: distinct displacements from one start
/// give distinct results (under the ⊕ preconditions).
#[test]
fn ta_lc_left_cancellation_holds() {
    let a = t(&[1, 2, 3]);
    let pool = [t(&[1]), t(&[2]), t(&[0, 1]), t(&[0, 0, 5]), t(&[1, 0]), t(&[0, 2, 1, 4])];
    let results: Vec<Tumbler> = pool.iter().map(|x| add(&a, x).unwrap()).collect();
    for i in 0..results.len() {
        for j in (i + 1)..results.len() {
            assert_ne!(
                results[i], results[j],
                "distinct displacements must give distinct results"
            );
        }
    }
}

/// TA-MTO/TA-RC — right cancellation FAILS: a witness pair `a ≠ b` with
/// `a ⊕ w = b ⊕ w` exists (the tail below the action point is discarded).
/// The test asserts the failure, not a law.
#[test]
fn ta_rc_right_cancellation_fails_witness() {
    let (a, b, w) = (t(&[1, 7]), t(&[1, 9]), t(&[2]));
    assert_ne!(a, b);
    assert_eq!(add(&a, &w).unwrap(), add(&b, &w).unwrap());
}

/// D1/D2 — whenever `displacement(a, b) = Some(w)`: `a ⊕ w = b`, and nearby
/// admissible displacements do not also reach `b`.
#[test]
fn displacement_round_trips_and_nearby_displacements_do_not() {
    let pairs = [
        (t(&[1, 2]), t(&[1, 5, 3])),
        (t(&[1]), t(&[4])),
        (t(&[2, 0, 1]), t(&[2, 0, 9, 9])),
        (t(&[1, 5]), t(&[2, 0])),
    ];
    for (a, b) in &pairs {
        let w = displacement(a, b).expect("witness pairs satisfy D0–D2");
        assert_eq!(&add(a, &w).unwrap(), b); // D1: the round-trip
        for alt in [shift(&w, &n(1)), t(&[1]), t(&[0, 1])] {
            if alt == w {
                continue;
            }
            if let Ok(r) = add(a, &alt) {
                assert_ne!(&r, b); // no other admissible displacement reaches b
            }
        }
    }
}

/// D0–D2 as a law rather than as four shapes: `displacement` answers `Some`
/// EXACTLY when `b ⊖ a` round-trips through `⊕`, and the witness it answers
/// with is the only displacement that reaches `b` from `a`. Asserted over
/// every ordered pair of every tumbler over `{0, 1, 2}` of length 1..=3.
///
/// `None` does NOT mean no displacement exists — for `a = [1,0]`, `b = [2]`
/// the gate refuses while `w = [1]` reaches `b` — so the promise is written
/// against `b ⊖ a` round-tripping, which is what D0–D2 guarantees, and not
/// against a witness existing. The uniqueness sweep is exhaustive because a
/// witness has length `#b ≤ 3` with components bounded by `b`'s, so it cannot
/// escape the family.
#[test]
fn displacement_is_exactly_the_round_trippable_window() {
    let family = tumblers_upto(&[0, 1, 2], 3);
    for a in &family {
        for b in &family {
            let d = displacement(a, b);
            let round_trips = sub(b, a)
                .ok()
                .and_then(|w| add(a, &w).ok())
                .is_some_and(|r| &r == b);
            assert_eq!(d.is_some(), round_trips, "displacement({a:?}, {b:?})");
            if let Some(w) = &d {
                assert_eq!(&add(a, w).unwrap(), b, "D1 round-trip for {a:?} → {b:?}");
                let k = action_point(w).expect("a displacement is Pos");
                assert!(k <= a.len(), "⊕ admits {w:?} from {a:?}");
            }
            let witnesses: Vec<&Tumbler> = family
                .iter()
                .filter(|x| add(a, x).is_ok_and(|r| &r == b))
                .collect();
            assert!(witnesses.len() <= 1, "two displacements reach {b:?} from {a:?}");
            if let (Some(w), Some(only)) = (&d, witnesses.first()) {
                assert_eq!(&w, only, "the answered witness is the only one");
            }
        }
    }
}
