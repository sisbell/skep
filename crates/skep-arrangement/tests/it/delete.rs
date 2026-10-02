//! DELETE (§B; ASN-0117): the gap it closes, the content store and R it leaves
//! alone, and its refusals in order.

use skep_address::Span;
use skep_arrangement::{DeleteError, Deposit, HasM5, Vstream};
use skep_content::{HasContent, Val};

use crate::common::*;

#[test]
fn delete_contracts_the_arrangement_and_touches_neither_content_nor_r() {
    // ASN-0117: gap closes (suffix reseats), content store untouched
    // (NonDestruction P0), R keeps the pair (P2) — which SHOWDELETIONS reads.
    let k = mem_kernel();
    let vs = Vstream::new(&k);
    vs.insert(
        P1,
        &doc1(),
        vp(1, 1),
        vec![val(b"a"), val(b"b"), val(b"c"), val(b"d"), val(b"e")],
        Deposit::Undeclared,
    )
    .expect("insert commits");
    vs.delete(P1, &doc1(), vp(1, 2), n(2)).expect("delete commits");
    let s = k.snapshot();
    let m5 = s.world().m5();
    assert_eq!(m5.content_count(&doc1()), n(3));
    assert_eq!(read_v(&s, &doc1(), 1), b"a".to_vec());
    assert_eq!(read_v(&s, &doc1(), 2), b"d".to_vec()); // suffix shifted left
    assert_eq!(read_v(&s, &doc1(), 3), b"e".to_vec());
    // The deleted bytes are still in the permascroll.
    assert_eq!(
        s.world()
            .content()
            .value_at(ca(2).tumbler())
            .map(Val::as_bytes),
        Some(&b"b"[..])
    );
    // SHOWDELETIONS: ever-placed minus current image = [ca2, ca4).
    let d = m5.deletions(&doc1());
    let spans: Vec<Span> = d.iter().cloned().collect();
    assert_eq!(spans.len(), 1);
    assert_eq!(spans[0].start(), ca(2).tumbler());
    assert_eq!(spans[0].reach(), *ca(4).tumbler());
}

#[test]
fn delete_rejects_in_documented_order() {
    let k = mem_kernel();
    let vs = insert_abc(&k);
    let unregistered_doc = a(&[1, 0, 1, 0, 9]);
    assert!(matches!(
        rejected(vs.delete(P1, &unregistered_doc, vp(1, 1), n(1))),
        DeleteError::DocNotRegistered
    ));
    assert!(matches!(
        rejected(vs.delete(P1, &doc1(), vp(2, 1), n(1))),
        DeleteError::NotContentSubspace
    ));
    assert!(matches!(
        rejected(vs.delete(P1, &doc1(), vp(1, 4), n(1))),
        DeleteError::NotArranged
    ));
    // Ordinal 0 is arranged nowhere, and it is the case the arranged check
    // exists for: containment alone admits it (0 + 1 ≤ n_C + 1), and the
    // fold would then remove position 1.
    assert!(matches!(
        rejected(vs.delete(P1, &doc1(), vp(1, 0), n(1))),
        DeleteError::NotArranged
    ));
    assert!(matches!(
        rejected(vs.delete(P1, &doc1(), vp(1, 2), n(3))),
        DeleteError::OutOfBounds
    ));
    assert!(matches!(
        rejected(vs.delete(P1, &doc1(), vp(1, 1), n(0))),
        DeleteError::EmptyWidth
    ));
    // Which wins when both the position and the width are bad: the position
    // check runs first, so an unarranged ordinal is reported as such even
    // when the width is zero.
    assert!(matches!(
        rejected(vs.delete(P1, &doc1(), vp(1, 9), n(0))),
        DeleteError::NotArranged
    ));
    // Subspace before position: the link subspace AND an ordinal no content
    // position holds — the subspace check runs first.
    assert!(matches!(
        rejected(vs.delete(P1, &doc1(), vp(2, 9), n(1))),
        DeleteError::NotContentSubspace
    ));
}
