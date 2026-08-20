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
fn add_preconditions() {
    assert_eq!(add(&t(&[1]), &t(&[0, 0])), Err(AddPrecond)); // ¬Pos(w)
    assert_eq!(add(&t(&[1]), &t(&[0, 1])), Err(AddPrecond)); // actionPoint(w) = 2 > #a
}

// ---- ⊖ ---------------------------------------------------------------------

#[test]
fn sub_zero_padded_divergence() {
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
fn ta5a_gate_predicate() {
    let node = addr(&[1]);
    assert!(inc_preserves_t4(&node, 0));
    assert!(inc_preserves_t4(&node, 1));
    assert!(inc_preserves_t4(&node, 2)); // zeros = 0 ≤ 2
    assert!(!inc_preserves_t4(&node, 3)); // k ≥ 3 never
    let elem = addr(&[1, 0, 2, 0, 5, 0, 1]);
    assert!(inc_preserves_t4(&elem, 1));
    assert!(!inc_preserves_t4(&elem, 2)); // zeros = 3: one more separator breaks T4
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
    assert_eq!(displacement(&t(&[1, 2]), &t(&[1, 2, 5])), None); // proper prefix: divergence > #a
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
