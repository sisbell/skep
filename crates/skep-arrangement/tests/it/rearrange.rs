//! REARRANGE (§B; ASN-0119): the pivot and the swap, the cut counts it admits,
//! and its refusals in order.

use skep_arrangement::{Deposit, HasM5, RearrangeError, VPos, Vstream};
use skep_kernel::TxnError;

use crate::common::*;

#[test]
fn rearrange_pivot_exchanges_the_two_adjacent_regions() {
    // ASN-0119: 3 cuts [2,4,6] over a..e — α = {2,3}, β = {4,5} — tile to
    // a, d, e, b, c. Content, links, R untouched (pure permutation).
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
    vs.rearrange(P1, &doc1(), &[vp(1, 2), vp(1, 4), vp(1, 6)])
        .expect("pivot commits");
    let s = k.snapshot();
    let got: Vec<Vec<u8>> = (1..=5).map(|i| read_v(&s, &doc1(), i)).collect();
    assert_eq!(got, vec![b"a".to_vec(), b"d".to_vec(), b"e".to_vec(), b"b".to_vec(), b"c".to_vec()]);
    assert_eq!(s.world().m5().content_count(&doc1()), n(5));
    assert!(s.world().m5().deletions(&doc1()).is_empty()); // range unchanged (RA1)
}

#[test]
fn rearrange_swap_exchanges_the_outer_regions_around_the_middle() {
    // ASN-0119: 4 cuts [1,2,3,4] — α = {1}, μ = {2}, β = {3} — tile to
    // c, b, a, d, e.
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
    vs.rearrange(P1, &doc1(), &[vp(1, 1), vp(1, 2), vp(1, 3), vp(1, 4)])
        .expect("swap commits");
    let s = k.snapshot();
    let got: Vec<Vec<u8>> = (1..=5).map(|i| read_v(&s, &doc1(), i)).collect();
    assert_eq!(got, vec![b"c".to_vec(), b"b".to_vec(), b"a".to_vec(), b"d".to_vec(), b"e".to_vec()]);
}

#[test]
fn rearrange_rejects_in_documented_order() {
    let k = mem_kernel();
    let vs = insert_abc(&k);
    let unregistered_doc = a(&[1, 0, 1, 0, 9]);
    assert!(matches!(
        rejected(vs.rearrange(P1, &unregistered_doc, &[vp(1, 1), vp(1, 2), vp(1, 3)])),
        RearrangeError::DocNotRegistered
    ));
    assert!(matches!(
        rejected(vs.rearrange(P1, &doc1(), &[vp(1, 1), vp(1, 2)])),
        RearrangeError::BadCutCount
    ));
    assert!(matches!(
        rejected(vs.rearrange(P1, &doc1(), &[vp(1, 2), vp(1, 2), vp(1, 3)])),
        RearrangeError::NotAscending
    ));
    assert!(matches!(
        rejected(vs.rearrange(P1, &doc1(), &[vp(2, 1), vp(1, 2), vp(1, 3)])),
        RearrangeError::NotContentSubspace
    ));
    // n_C = 3 ⇒ upper bound is 4.
    assert!(matches!(
        rejected(vs.rearrange(P1, &doc1(), &[vp(1, 1), vp(1, 2), vp(1, 5)])),
        RearrangeError::OutOfBounds
    ));
    // …and the lower bound, which the upper bound's check cannot stand in
    // for: a first cut at ordinal 0, the rest ascending and in bounds.
    // Admitted, the fold's clamp would read it as 1 and exchange a with b c.
    assert!(matches!(
        rejected(vs.rearrange(P1, &doc1(), &[vp(1, 0), vp(1, 2), vp(1, 4)])),
        RearrangeError::OutOfBounds
    ));
    // Which wins, in each documented pair. Count before ascent: two cuts,
    // descending.
    assert!(matches!(
        rejected(vs.rearrange(P1, &doc1(), &[vp(1, 2), vp(1, 1)])),
        RearrangeError::BadCutCount
    ));
    // Ascent before subspace: three cuts, out of order, with the middle one
    // in the link subspace.
    assert!(matches!(
        rejected(vs.rearrange(P1, &doc1(), &[vp(1, 2), vp(2, 1), vp(1, 3)])),
        RearrangeError::NotAscending
    ));
    // Subspace before bounds: ascending cuts, the first in the link
    // subspace, the last past doc1's upper bound of n_C + 1 = 4.
    assert!(matches!(
        rejected(vs.rearrange(P1, &doc1(), &[vp(2, 1), vp(1, 2), vp(1, 9)])),
        RearrangeError::NotContentSubspace
    ));
    // Bounds before emptiness, which is what makes `EmptyContentSubspace`
    // the defensive-completeness verdict its own doc says it is: doc2 is
    // registered and content-empty, so n_C + 1 = 1 admits only ordinal 1 and
    // the third cut trips OutOfBounds first. Transposing the two checks
    // would make an unreachable verdict reachable, and M10 would then have
    // to handle it.
    assert!(matches!(
        rejected(vs.rearrange(P1, &doc2(), &[vp(1, 1), vp(1, 2), vp(1, 3)])),
        RearrangeError::OutOfBounds
    ));
}

#[test]
fn rearrange_admits_three_or_four_cuts_and_refuses_every_other_count() {
    // R-PRE: exactly three cuts or four. Each count is asked of a cut vector
    // that passes every OTHER guard — strictly ascending content-subspace
    // cuts inside [1, n_C + 1] — so BadCutCount is the only verdict it can
    // earn. The count is M5's alone to judge: the wire reads `cuts` as a
    // plain list under its generic cap, and the fold tiles any vector it is
    // handed, so a count admitted here commits a permutation R-PRE does not
    // define.
    let k = mem_kernel();
    let vs = Vstream::new(&k);
    vs.insert(
        P1,
        &doc1(),
        vp(1, 1),
        vec![val(b"a"), val(b"b"), val(b"c"), val(b"d"), val(b"e")],
        Deposit::Undeclared,
    )
    .expect("insert commits"); // n_C = 5: boundaries 1..=6 are admissible
    let cuts: Vec<VPos> = (1..=6).map(|o| vp(1, o)).collect();
    let before = k.current_seq();
    for count in [0usize, 1, 2, 5, 6] {
        match vs.rearrange(P1, &doc1(), &cuts[..count]) {
            Err(TxnError::Rejected(RearrangeError::BadCutCount)) => {}
            other => panic!("{count} cuts: expected BadCutCount, got {other:?}"),
        }
    }
    assert_eq!(k.current_seq(), before, "no refused count commits");
    for count in [3usize, 4] {
        vs.rearrange(P1, &doc1(), &cuts[..count])
            .unwrap_or_else(|e| panic!("{count} cuts: expected a commit, got {e:?}"));
    }
}
