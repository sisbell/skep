//! §D/§E — position arithmetic (⊕/⊖/inc/sig, TA5a, D0–D2) and the ordinal
//! shift with its subspace-safe packaging (TS/TA7a).

mod common;

use common::*;
use skep_address::*;

// ---- action_point / sig -----------------------------------------------------

#[test]
fn action_point_is_first_nonzero_none_iff_zero() {
    assert_eq!(action_point(&t(&[0, 0, 3, 0])), Some(3));
    assert_eq!(action_point(&t(&[1, 0])), Some(1));
    assert_eq!(action_point(&t(&[0, 0])), None); // Zero(w)
}

#[test]
fn sig_is_last_nonzero_else_len() {
    assert_eq!(sig(&t(&[1, 0, 2, 0, 5])), 5); // T4-valid ⇒ sig = #t (TA5-SigValid)
    assert_eq!(sig(&t(&[1, 2, 0])), 2);
    assert_eq!(sig(&t(&[0, 0, 0])), 3); // all-zero: #t
}

// ---- ⊕ ---------------------------------------------------------------------

#[test]
fn add_three_region_semantics() {
    assert_eq!(add(&t(&[1, 0, 2]), &t(&[0, 0, 1])).unwrap(), t(&[1, 0, 3]));
    // prefix from a, sum at the action point, tail from w — result length #w
    assert_eq!(
        add(&t(&[1, 2, 3]), &t(&[0, 5, 7, 9])).unwrap(),
        t(&[1, 7, 7, 9])
    );
    // a's structure below the action point is discarded (TA-MTO/TA-RC)
    assert_eq!(add(&t(&[1, 7]), &t(&[2])).unwrap(), t(&[3]));
}

#[test]
fn add_requires_pos_w_and_an_action_point_within_start() {
    assert_eq!(add(&t(&[1]), &t(&[0, 0])), Err(AddPrecond)); // ¬Pos(w)
    assert_eq!(add(&t(&[1]), &t(&[0, 1])), Err(AddPrecond)); // actionPoint(w) = 2 > #a
}

// ---- ⊖ ---------------------------------------------------------------------

#[test]
fn sub_subtracts_at_the_zero_padded_divergence() {
    assert_eq!(sub(&t(&[1, 0, 3]), &t(&[1, 0, 2])).unwrap(), t(&[0, 0, 1]));
    // padded-equal: the all-zero tumbler of length L (a legal non-address result)
    assert_eq!(sub(&t(&[1, 0]), &t(&[1])).unwrap(), t(&[0, 0]));
    // difference at the padded divergence, then a's padded tail
    assert_eq!(sub(&t(&[2]), &t(&[1, 5])).unwrap(), t(&[1, 0]));
}

#[test]
fn sub_requires_a_at_least_w() {
    assert_eq!(sub(&t(&[1, 2]), &t(&[1, 3])), Err(SubPrecond));
    assert_eq!(sub(&t(&[1]), &t(&[1, 0, 1])), Err(SubPrecond)); // a is a proper prefix ⇒ a < w
}

// ---- inc + TA5a gate --------------------------------------------------------

#[test]
fn inc_zero_advances_sig() {
    assert_eq!(inc(&t(&[1, 0, 5]), 0), t(&[1, 0, 6]));
    assert_eq!(inc(&t(&[2, 0]), 0), t(&[3, 0])); // sig = 1 on a trailing-zero tumbler
}

#[test]
fn inc_positive_k_extends_by_k_positions() {
    assert_eq!(inc(&t(&[1]), 1), t(&[1, 1]));
    assert_eq!(inc(&t(&[1]), 2), t(&[1, 0, 1]));
    assert_eq!(inc(&t(&[1]), 3), t(&[1, 0, 0, 1])); // pure form; the TA5a gate rejects k ≥ 3
}

#[test]
fn ta5a_gate_admits_the_descent_only_for_a_non_element_address() {
    let node = addr(&[1]);
    assert!(inc_preserves_t4(&node, 0));
    assert!(inc_preserves_t4(&node, 1));
    assert!(inc_preserves_t4(&node, 2)); // zeros = 0 ≤ 2
    assert!(!inc_preserves_t4(&node, 3)); // k ≥ 3 never
    let elem = addr(&[1, 0, 2, 0, 5, 0, 1]);
    assert!(inc_preserves_t4(&elem, 1));
    assert!(!inc_preserves_t4(&elem, 2)); // zeros = 3: one more separator breaks T4
}

/// TA5a as a law rather than as six points. The gate predicate reads a level;
/// `inc` appends; `checked_inc` applies the validator unguarded on the
/// strength of the two agreeing, on M3's every mint. So the agreement is
/// asserted over EVERY T4-valid address in the zero/nonzero family of length
/// 1..=7 — exhaustive in what T4 reads — against `k` on both sides of the
/// gate's cut.
#[test]
fn the_ta5a_gate_admits_exactly_what_inc_leaves_t4_valid() {
    for len in 1..=7usize {
        for bits in 0..(1u32 << len) {
            let comps: Vec<u32> = (0..len).map(|i| (bits >> i) & 1).collect();
            let Ok(a) = validate(t(&comps)) else { continue };
            for k in 0..=4usize {
                assert_eq!(
                    inc_preserves_t4(&a, k),
                    is_t4_valid(&inc(a.tumbler(), k)),
                    "TA5a gate disagrees with inc on ({a}, k = {k})"
                );
                // Wherever the gate opens, the constructor's mint opens with
                // it — which is what stops `checked_inc` faulting on a mint.
                assert_eq!(
                    checked_inc(&a, k).is_ok(),
                    inc_preserves_t4(&a, k),
                    "checked_inc disagrees with the gate on ({a}, k = {k})"
                );
            }
        }
    }
}

#[test]
fn checked_inc_gates_and_reclassifies() {
    let doc = addr(&[1, 0, 2, 0, 5]);
    let elem = checked_inc(&doc, 2).unwrap();
    assert_eq!(elem.tumbler(), &t(&[1, 0, 2, 0, 5, 0, 1]));
    assert_eq!(elem.level(), Level::Element); // reclassified across the descent
    assert_eq!(checked_inc(&elem, 2), Err(GateViolation));
    let next = checked_inc(&doc, 0).unwrap(); // next sibling stays a Document
    assert_eq!(next.tumbler(), &t(&[1, 0, 2, 0, 6]));
    assert_eq!(next.level(), Level::Document);
}

/// T0(a) — component magnitude is unbounded, and the arithmetic is exact at
/// magnitudes no fixed-width component holds. This is the clause that deletes
/// the reference design's silent digit-overflow wrap in `tumbleradd`: a
/// wrapping component would make two distinct positions equal, which is the
/// alias class T3 exists to keep empty, reopened at the top end.
#[test]
fn arithmetic_is_exact_above_any_fixed_width() {
    let a = tumbler([n(1), beyond_u64()]);
    let w = tumbler([n(0), beyond_u64()]);
    let b = add(&a, &w).unwrap();
    assert_eq!(b.get(2), Some(&(beyond_u64() + beyond_u64()))); // 2⁶⁵ at one position, no wrap
    assert_eq!(displacement(&a, &b), Some(w)); // ⊖ recovers the wide width exactly

    // The two advances cross the 2⁶⁴ boundary rather than wrapping to zero.
    assert_eq!(
        inc(&tumbler([Nat::from(u64::MAX)]), 0),
        tumbler([beyond_u64()])
    );
    assert_eq!(
        shift(&tumbler([Nat::from(u64::MAX)]), &n(1)),
        tumbler([beyond_u64()])
    );
}

// ---- displacement (D0–D2) ---------------------------------------------------

#[test]
fn displacement_returns_the_round_trippable_witness() {
    let a = t(&[1, 2]);
    let b = t(&[1, 5, 3]);
    let w = displacement(&a, &b).unwrap();
    assert_eq!(w, t(&[0, 3, 3]));
    assert_eq!(add(&a, &w).unwrap(), b); // a ⊕ (b ⊖ a) = b
}

#[test]
fn displacement_refuses_outside_d0_d2() {
    assert_eq!(displacement(&t(&[1, 2]), &t(&[1, 2])), None); // ¬(a < b)
    assert_eq!(displacement(&t(&[1, 5]), &t(&[1, 2])), None); // a > b
    assert_eq!(displacement(&t(&[1, 2]), &t(&[1, 2, 5])), None); // proper prefix: D1 refuses
    assert_eq!(displacement(&t(&[1, 2, 3]), &t(&[2, 4])), None); // #a > #b
}

// ---- shift / ElemPos (TS, TA7a) --------------------------------------------

#[test]
fn shift_advances_the_last_component_only() {
    assert_eq!(shift(&t(&[1, 0, 2]), &n(5)), t(&[1, 0, 7]));
    assert_eq!(shift(&t(&[1, 0, 2]), &n(0)), t(&[1, 0, 2])); // total extension: identity
}

#[test]
fn raw_shift_on_a_subspace_base_advances_the_subspace_id() {
    // The documented TA7a hazard: on `doc·0·subspace` the last component IS
    // the subspace id — a raw shift advances content (1) → link (2). This is
    // shift's specified primitive behavior; `shift_ordinal` is the safe form.
    let base = t(&[1, 0, 2, 0, 5, 0, 1]);
    assert_eq!(ordinal(&base), &content_subspace()); // the "ordinal" here is s_C
    assert_eq!(shift(&base, &n(1)), t(&[1, 0, 2, 0, 5, 0, 2]));
}

#[test]
fn elem_addr_mints_the_guarded_element() {
    let p = ElemPos {
        doc: addr(&[1, 0, 2, 0, 5]),
        subspace: n(1),
        ordinal: n(9),
    };
    let a = elem_addr(p).unwrap();
    assert_eq!(a.tumbler(), &t(&[1, 0, 2, 0, 5, 0, 1, 9]));
    assert_eq!(a.level(), Level::Element);
}

#[test]
fn elem_addr_guards_each_condition() {
    let doc = addr(&[1, 0, 2, 0, 5]);
    let not_doc = ElemPos {
        doc: addr(&[1, 0, 2]),
        subspace: n(1),
        ordinal: n(1),
    };
    assert_eq!(elem_addr(not_doc), Err(ElemError::DocNotDocument));
    let sub0 = ElemPos {
        doc: doc.clone(),
        subspace: n(0),
        ordinal: n(1),
    };
    assert_eq!(elem_addr(sub0), Err(ElemError::SubspaceZero));
    let ord0 = ElemPos {
        doc,
        subspace: n(2),
        ordinal: n(0),
    };
    assert_eq!(elem_addr(ord0), Err(ElemError::OrdinalZero));
}

/// A position is its content, so the shift is asserted as a whole position —
/// which pins the document and the subspace as surviving the advance, not
/// just the ordinal that moved.
#[test]
fn shift_ordinal_leaves_the_subspace_untouched() {
    let p = ElemPos {
        doc: addr(&[1, 0, 2, 0, 5]),
        subspace: content_subspace(),
        ordinal: n(9),
    };
    let q = shift_ordinal(p.clone(), &n(3));
    assert_eq!(
        q,
        ElemPos {
            doc: addr(&[1, 0, 2, 0, 5]),
            subspace: content_subspace(),
            ordinal: n(12),
        }
    );
    assert_eq!(shift_ordinal(p.clone(), &n(0)), p); // the identity displacement
    assert_eq!(
        elem_addr(q).unwrap().tumbler(),
        &t(&[1, 0, 2, 0, 5, 0, 1, 12])
    );
}
