//! REINSTATE (the write by identity; the replacement act's record, E2 (a)):
//! a delete undone at the SAME I-addresses leaves the arrangement as it was
//! — the content list byte for byte, `point` answering the old addresses,
//! nothing minted — so every link on them returns; the wide reach, a removed
//! run placed into another document by identity; the duplicate edge; and
//! each guard the real state can reach, in its documented order.

use skep_address::{Address, SpanSet};
use skep_arrangement::{Caller, HasM5, ReinstateError, Run, ShotRun};
use skep_content::HasContent;
use skep_namespace::PrincipalId;

use crate::common::*;

/// T1e — the act the owner's ruling asks for: a delete, then a reinstate of
/// the same I-run at the same position, and the document is what it was
/// before the delete — the same content list run for run, the same address
/// at every ordinal, the same bytes, and nothing minted or written on the
/// way. An insert in its place (the editor's old undo) would answer fresh
/// addresses at ordinal 2 and grow the content store.
#[test]
fn a_delete_then_a_reinstate_of_the_same_run_restores_the_arrangement_byte_for_byte() {
    let k = mem_kernel();
    let vs = insert_abc(&k);
    let before = k.snapshot();
    let runs_before: Vec<Run> = before.world().m5().content_runs(&doc1()).cloned().collect();
    let addrs_before: Vec<Address> = (1..=3)
        .map(|o| before.world().m5().point(&doc1(), &vp(1, o)).expect("arranged"))
        .collect();
    assert_eq!(addrs_before, vec![ca(1), ca(2), ca(3)], "premise: a, b, c at their mints");
    let stored_before = before.world().content().len();

    vs.delete(P1, &doc1(), vp(1, 2), n(1)).expect("delete commits");
    let s = k.snapshot();
    assert_eq!(s.world().m5().content_count(&doc1()), n(2));
    assert_eq!(s.world().m5().point(&doc1(), &vp(1, 2)), Some(ca(3)), "the suffix shifted left");

    // THE ACT: the removed run, by its permanent address, back at its
    // position — `copy` cannot name it, no arrangement holding it now.
    let seq = vs
        .reinstate(P1, &doc1(), vp(1, 2), &[shot_run(&doc1(), &ca(2), 1)])
        .expect("reinstate commits");
    let s = k.snapshot();
    assert_eq!(s.seq(), seq);
    let m5 = s.world().m5();
    assert_eq!(m5.content_count(&doc1()), n(3));
    assert!(
        m5.content_runs(&doc1()).eq(runs_before.iter()),
        "the content list is the pre-delete list, run for run"
    );
    for (o, addr) in (1..=3).zip(&addrs_before) {
        assert_eq!(m5.point(&doc1(), &vp(1, o)).as_ref(), Some(addr), "ordinal {o}");
    }
    assert_eq!(read_v(&s, &doc1(), 2), b"b".to_vec());
    assert_eq!(
        s.world().content().len(),
        stored_before,
        "nothing minted, nothing written: the same bytes under the same addresses"
    );
}

/// THE WIDE REACH and the duplicate edge. A run no arrangement holds any
/// more is placed by identity into ANOTHER document of the owner's — the
/// window `copy` could make only while the origin still arranged the span —
/// and a run its document still arranges is placed AGAIN, a duplicate as a
/// self-copy's (S5), with no `already_arranged` refusal. Both documents are
/// R-candidates for the address afterwards.
#[test]
fn a_removed_run_is_placed_into_another_document_by_identity_and_a_duplicate_is_admitted() {
    let k = mem_kernel();
    let vs = insert_abc(&k);
    vs.delete(P1, &doc1(), vp(1, 2), n(1)).expect("delete commits");
    vs.reinstate(P1, &doc2(), vp(1, 1), &[shot_run(&doc1(), &ca(2), 1)])
        .expect("a run of another document's I-space is placed by identity");
    let s = k.snapshot();
    assert_eq!(s.world().m5().point(&doc2(), &vp(1, 1)), Some(ca(2)));
    assert_eq!(read_v(&s, &doc2(), 1), b"b".to_vec());

    // Edge 1: `ca(1)` is arranged at doc1's ordinal 1 and placed again at
    // its end — the arrangement keeps the multiplicity.
    vs.reinstate(P1, &doc1(), vp(1, 3), &[shot_run(&doc1(), &ca(1), 1)])
        .expect("a run already arranged is placed again");
    let s = k.snapshot();
    let m5 = s.world().m5();
    assert_eq!(m5.content_count(&doc1()), n(3));
    assert_eq!(m5.point(&doc1(), &vp(1, 1)), Some(ca(1)));
    assert_eq!(m5.point(&doc1(), &vp(1, 3)), Some(ca(1)));
    assert_eq!(m5.content_runs(&doc1()).len(), 3, "[ca1][ca3][ca1] — no merge across the seam");
    let cov = SpanSet::singleton(Run::new(ca(2), n(1)).expect("a content run").iextent());
    assert_eq!(m5.docs_ever_containing(&cov), vec![doc1(), doc2()]);
}

/// Each guard the real state reaches, in the order `Vstream::reinstate`
/// states: the destination's registration, ownership, publication, subspace
/// and bounds ahead of every run; then, per run in order, the shape, the
/// origin's registration and the bytes — EVERY address of the run — the
/// first defective run deciding; and the empty list last. A refusal commits
/// nothing. `TooManyRuns` is `ops::reinstate::tests`' alone: a claim about
/// the accumulator, not about this assembly.
#[test]
fn reinstate_rejects_each_documented_guard() {
    let k = mem_kernel();
    let vs = insert_abc(&k);
    let before = k.current_seq();
    let unregistered_doc = a(&[1, 0, 1, 0, 9]);
    let sound = shot_run(&doc1(), &ca(1), 1);
    // A run defective in its SHAPE: a link element is no content run.
    let link_start = ShotRun {
        origin: doc1(),
        run: Run::new(a(&[1, 0, 1, 0, 1, 0, 2, 1]), n(1)).expect("a link run"),
    };
    // …and one whose stated origin does not project to its start's document.
    let mis_stated = shot_run(&doc2(), &ca(1), 1);
    // …and one naming an address doc1 never minted.
    let never_minted = shot_run(&doc1(), &ca(9), 1);
    // …and one under a document M3 never registered.
    let ghost = shot_run(&unregistered_doc, &a(&[1, 0, 1, 0, 9, 0, 1, 1]), 1);

    // Destination first, as COPY.
    assert!(matches!(
        rejected(vs.reinstate(P1, &unregistered_doc, vp(1, 1), &[sound.clone()])),
        ReinstateError::DocNotRegistered
    ));
    let not_owner = rejected(vs.reinstate(
        Caller::Principal(PrincipalId(2)),
        &doc1(),
        vp(1, 1),
        &[sound.clone()],
    ));
    assert_eq!(not_owner, ReinstateError::NotOwner(doc1()), "the destination rides the verdict");
    assert!(matches!(
        rejected(vs.reinstate(P1, &pdoc(), vp(1, 1), &[link_start.clone()])),
        ReinstateError::PublishedTarget
    ));
    assert!(matches!(
        rejected(vs.reinstate(P1, &doc2(), vp(2, 1), &[link_start.clone()])),
        ReinstateError::NotContentSubspace
    ));
    assert!(matches!(
        rejected(vs.reinstate(P1, &doc2(), vp(1, 2), &[link_start.clone()])),
        ReinstateError::OutOfBounds
    ));
    assert!(matches!(
        rejected(vs.reinstate(P1, &doc2(), vp(1, 0), &[sound.clone()])),
        ReinstateError::OutOfBounds
    ));
    // Subspace before bounds: both wrong at once.
    assert!(matches!(
        rejected(vs.reinstate(P1, &doc2(), vp(2, 99), &[sound.clone()])),
        ReinstateError::NotContentSubspace
    ));
    // Per run: the shape.
    assert!(matches!(
        rejected(vs.reinstate(P1, &doc2(), vp(1, 1), &[link_start.clone()])),
        ReinstateError::BadRun
    ));
    assert!(matches!(
        rejected(vs.reinstate(P1, &doc2(), vp(1, 1), &[mis_stated.clone()])),
        ReinstateError::BadRun
    ));
    // The origin's registration.
    assert!(matches!(
        rejected(vs.reinstate(P1, &doc2(), vp(1, 1), &[ghost.clone()])),
        ReinstateError::SourceNotRegistered
    ));
    // The bytes — at every address: ca(2) and ca(3) are present, ca(4) is
    // not, and the run's start alone would have admitted it.
    assert!(matches!(
        rejected(vs.reinstate(P1, &doc2(), vp(1, 1), &[never_minted.clone()])),
        ReinstateError::DanglingSource
    ));
    assert!(matches!(
        rejected(vs.reinstate(P1, &doc2(), vp(1, 1), &[shot_run(&doc1(), &ca(2), 3)])),
        ReinstateError::DanglingSource
    ));
    // WHICH RUN SPEAKS: the first defective one, in order.
    assert!(matches!(
        rejected(vs.reinstate(P1, &doc2(), vp(1, 1), &[sound.clone(), mis_stated.clone()])),
        ReinstateError::BadRun
    ));
    assert!(matches!(
        rejected(vs.reinstate(P1, &doc2(), vp(1, 1), &[mis_stated.clone(), ghost.clone()])),
        ReinstateError::BadRun
    ));
    assert!(matches!(
        rejected(vs.reinstate(P1, &doc2(), vp(1, 1), &[ghost, mis_stated.clone()])),
        ReinstateError::SourceNotRegistered
    ));
    assert!(matches!(
        rejected(vs.reinstate(P1, &doc2(), vp(1, 1), &[never_minted, mis_stated])),
        ReinstateError::DanglingSource
    ));
    // The empty list.
    assert!(matches!(
        rejected(vs.reinstate(P1, &doc2(), vp(1, 1), &[])),
        ReinstateError::EmptyResult
    ));
    assert_eq!(k.current_seq(), before, "every refusal commits nothing");
    assert_eq!(k.snapshot().world().m5().content_count(&doc2()), n(0));
}
