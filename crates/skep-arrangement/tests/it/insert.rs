//! INSERT (§B; ASN-0116): what it mints, writes and places, the run start it
//! returns, and the order of its refusals.

use skep_arrangement::{Deposit, HasM5, InsertError, Run, Vstream};

use crate::common::*;

#[test]
fn insert_mints_writes_places_and_returns_the_run_start() {
    // ASN-0116/§3: one composite; returns the run START (M9's predicate-def
    // identity) + the commit Seq; reads compose off one snapshot.
    let k = mem_kernel();
    let vs = Vstream::new(&k);
    let (start, seq) = vs
        .insert(P1, &doc1(), vp(1, 1), vec![val(b"a"), val(b"b"), val(b"c")], Deposit::Undeclared)
        .expect("insert commits");
    assert_eq!(start, ca(1));
    assert_eq!(k.current_seq(), seq);
    let s = k.snapshot();
    let m5 = s.world().m5();
    assert_eq!(m5.content_count(&doc1()), n(3));
    // Held-lock mints are contiguous ⇒ exactly ONE placed run.
    let runs: Vec<&Run> = m5.content_runs(&doc1()).collect();
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].i_start(), &ca(1));
    assert_eq!(runs[0].width(), &n(3));
    assert_eq!(m5.point(&doc1(), &vp(1, 2)), Some(ca(2)));
    assert_eq!(read_v(&s, &doc1(), 2), b"b".to_vec());
    // image is the centralized iextent lift.
    let cov = m5.image(&doc1(), &vspan(1, 1, 3));
    assert!(cov.denotes(ca(1).tumbler()));
    assert!(cov.denotes(ca(3).tumbler()));
    assert!(!cov.denotes(ca(4).tumbler()));
    // J1★ off the same snapshot: the placement is already in R.
    assert_eq!(m5.docs_ever_containing(&cov), vec![doc1()]);
}

#[test]
fn insert_appends_coalesce_and_interior_inserts_shift_the_suffix() {
    let k = mem_kernel();
    let vs = insert_abc(&k);
    // Tail append continues the frontier ⇒ I-adjacent ⇒ still one run (M12).
    let (start, _) = vs
        .insert(P1, &doc1(), vp(1, 4), vec![val(b"d")], Deposit::Undeclared)
        .expect("append commits");
    assert_eq!(start, ca(4));
    {
        let s = k.snapshot();
        assert_eq!(s.world().m5().content_runs(&doc1()).len(), 1);
    }
    // Interior insert splits the run; the suffix shifts for free (§1).
    let (start, _) = vs
        .insert(P1, &doc1(), vp(1, 2), vec![val(b"x")], Deposit::Undeclared)
        .expect("interior insert commits");
    assert_eq!(start, ca(5));
    let s = k.snapshot();
    let m5 = s.world().m5();
    assert_eq!(m5.content_count(&doc1()), n(5));
    assert_eq!(m5.content_runs(&doc1()).len(), 3);
    assert_eq!(read_v(&s, &doc1(), 1), b"a".to_vec());
    assert_eq!(read_v(&s, &doc1(), 2), b"x".to_vec());
    assert_eq!(read_v(&s, &doc1(), 3), b"b".to_vec());
    assert_eq!(read_v(&s, &doc1(), 5), b"d".to_vec());
}

#[test]
fn insert_rejects_in_documented_order_and_commits_nothing() {
    // §3's shape half: DocNotRegistered → EmptyContent → NotContentSubspace →
    // OutOfBounds, each case also defective in the verdicts after it, and
    // every rejection a clean no-op. The NotOwner and PublishedTarget slots
    // between the first two are pinned with ownership and publication
    // (`an_unregistered_document_never_yields_an_ownership_verdict`,
    // `edit_ops_reject_a_sibling_principal_and_commit_nothing`,
    // `ownership_stands_ahead_of_the_published_target_refusal`,
    // `in_place_edits_refuse_a_published_target_and_commit_nothing`).
    let k = mem_kernel();
    let vs = Vstream::new(&k);
    let before = k.current_seq();
    let unregistered_doc = a(&[1, 0, 1, 0, 9]); // never registered
    assert!(matches!(
        rejected(vs.insert(P1, &unregistered_doc, vp(2, 0), vec![], Deposit::Undeclared)),
        InsertError::DocNotRegistered
    ));
    assert!(matches!(
        rejected(vs.insert(P1, &doc1(), vp(2, 0), vec![], Deposit::Undeclared)),
        InsertError::EmptyContent
    ));
    assert!(matches!(
        rejected(vs.insert(P1, &doc1(), vp(2, 99), vec![val(b"x")], Deposit::Undeclared)),
        InsertError::NotContentSubspace
    ));
    assert!(matches!(
        rejected(vs.insert(P1, &doc1(), vp(1, 0), vec![val(b"x")], Deposit::Undeclared)),
        InsertError::OutOfBounds
    ));
    // n_C = 0: the only valid insertion ordinal is 1 (FirstInsertionPosition).
    assert!(matches!(
        rejected(vs.insert(P1, &doc1(), vp(1, 2), vec![val(b"x")], Deposit::Undeclared)),
        InsertError::OutOfBounds
    ));
    assert_eq!(k.current_seq(), before);
}
