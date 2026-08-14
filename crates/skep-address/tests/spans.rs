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

#[test]
fn from_endpoints_wf_and_error_precedence() {
    let s = sp(&[1, 0, 2], &[1, 0, 5]);
    assert_eq!(s.start(), &t(&[1, 0, 2]));
    assert_eq!(s.width(), &t(&[0, 0, 3]));
    assert_eq!(s.reach(), t(&[1, 0, 5])); // start ⊕ width, recomputed
    assert_eq!(
        Span::from_endpoints(t(&[2]), t(&[2])).unwrap_err(),
        WfError::NotIncreasing
    );
    assert_eq!(
        Span::from_endpoints(t(&[3]), t(&[2])).unwrap_err(),
        WfError::NotIncreasing
    );
    assert_eq!(
        Span::from_endpoints(t(&[1]), t(&[1, 5])).unwrap_err(),
        WfError::LevelMismatch
    );
    // The level clause runs FIRST: a pair failing BOTH yields LevelMismatch (§6).
    assert_eq!(
        Span::from_endpoints(t(&[2, 0]), t(&[1])).unwrap_err(),
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

// ---- SC classifier ----------------------------------------------------------

#[test]
fn classify_spans_five_cases() {
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
    // A non-level-uniform operand fails the per-span half of the gate.
    let nu = Span::new(t(&[1, 0, 2]), t(&[0, 1])).unwrap();
    assert_eq!(intersect(&nu, &nu), Err(LevelMismatch));
}

// ---- intersect / merge / split ----------------------------------------------

#[test]
fn intersect_cases() {
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
fn merge_cases() {
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
fn split_cases_and_error_precedence() {
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
fn difference_by_sc_case() {
    let a = sp(&[1], &[9]);
    // separated / adjacent: ⟦a⟧ unchanged
    assert_eq!(difference(&a, &sp(&[20], &[30])).unwrap(), set(&[a.clone()]));
    assert_eq!(difference(&a, &sp(&[9], &[12])).unwrap(), set(&[a.clone()]));
    // proper overlap, a first: the left complement
    assert_eq!(difference(&a, &sp(&[5], &[12])).unwrap(), set(&[sp(&[1], &[5])]));
    // proper overlap, b first: the right complement
    assert_eq!(
        difference(&sp(&[5], &[12]), &sp(&[1], &[9])).unwrap(),
        set(&[sp(&[9], &[12])])
    );
    // strict containment: two complements in N1 order, normalized by construction
    let two = difference(&a, &sp(&[3], &[5])).unwrap();
    assert_eq!(two, set(&[sp(&[1], &[3]), sp(&[5], &[9])]));
    assert!(two.is_normalized());
    // a shared boundary drops the zero-width complement (S11d's "1 or 2"; S2)
    assert_eq!(difference(&a, &sp(&[1], &[5])).unwrap(), set(&[sp(&[5], &[9])]));
    assert_eq!(difference(&a, &sp(&[5], &[9])).unwrap(), set(&[sp(&[1], &[5])]));
    // a ⊆ b, including equal: empty
    assert_eq!(difference(&sp(&[3], &[5]), &a).unwrap(), SpanSet::empty());
    assert_eq!(difference(&a, &a).unwrap(), SpanSet::empty());
}
