//! Nullify, the sole retraction path, over a real kernel (InMemory): the
//! tombstone it leaves and the address it may target, its target precedence,
//! a second home's distinct retraction, and its irreversibility.

use crate::common;

use common::*;
use skep_kernel::TxnError;
use skep_links::{HasLinks, NullifyError, View};

#[test]
fn nullify_tombstones_its_target_and_accepts_its_own_fresh_address() {
    let k = kernel();
    let w = writer(&k);
    // P-tgt rejects a non-resident, non-self target.
    assert!(matches!(
        w.nullify(P1, &doc1(), &ca(9)),
        Err(TxnError::Rejected(NullifyError::BadTarget))
    ));
    // P0.
    assert!(matches!(
        w.nullify(P1, &a(&[1, 0, 1, 0, 7]), &la(1)),
        Err(TxnError::Rejected(NullifyError::HomeNotRegistered))
    ));
    // Happy path: the [R] tuple nullifies exactly the target root.
    let (target, _) = w.emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[]).expect("emit");
    let (r1, _) = w.nullify(P1, &doc1(), &target).expect("nullify");
    {
        let snap = k.snapshot();
        let links = snap.world().links();
        assert!(links.is_nullified(&target));
        assert!(!links.is_active(&target));
        assert!(links.is_active(&r1)); // the retraction tuple itself is active
        // Active slices exclude the nullified tuple; audit keeps it (R3).
        assert!(!links.type_slice(&pred_def_ty(), View::Active).contains(&target));
        assert!(links.type_slice(&pred_def_ty(), View::Audit).contains(&target));
    }
    // idem⊤: re-retracting the same target from the same home dedups.
    let (r2, _) = w.nullify(P1, &doc1(), &target).expect("re-nullify dedups");
    assert_eq!(r2, r1);
    // Born-nullified self-target: the target may be the address this call's
    // own retraction tuple would occupy (P-tgt's second disjunct) — doc2's
    // first link is la2(1).
    let (born_nullified, _) = w.nullify(P1, &doc2(), &la2(1)).expect("self-targeting retraction");
    assert_eq!(born_nullified, la2(1));
    {
        let snap = k.snapshot();
        assert!(snap.world().links().is_nullified(&la2(1)));
    }
    // The predicted address tracks the home's own link count, so the second
    // disjunct names a moving address, not a fixed one: doc1 holds two links
    // (target, r1 — the dedup hit staged nothing), so its next mint is exactly
    // la(3); la(4) is neither resident nor `a_emit`.
    assert!(matches!(
        w.nullify(P1, &doc1(), &la(4)),
        Err(TxnError::Rejected(NullifyError::BadTarget))
    ));
    let (born_on_used_chain, _) = w
        .nullify(P1, &doc1(), &la(3))
        .expect("self-targeting on a used chain");
    assert_eq!(born_on_used_chain, la(3));
    let snap = k.snapshot();
    assert!(snap.world().links().is_nullified(&la(3)));
}

#[test]
fn nullify_reports_a_foreign_target_before_a_bad_one() {
    // The two checks are ordered — ω on the target precedes P-tgt — so the
    // auth verdict never depends on residence timing. This is the one input
    // that satisfies both: P2 owns the home, owns neither the target nor its
    // account, and the target is neither resident nor this call's `a_emit`.
    let k = kernel();
    let w = writer(&k);
    assert!(matches!(
        w.nullify(P2, &sib_doc(), &ca(9)),
        Err(TxnError::Rejected(NullifyError::NotOwner(d))) if d == ca(9)
    ));
    // ...and each verdict is separately reachable, so the above is the
    // precedence and not the only answer either input can get: P2's own
    // ghost target is BadTarget, and P1's foreign target is NotOwner.
    assert!(matches!(
        w.nullify(P2, &sib_doc(), &a(&[1, 0, 2, 0, 1, 0, 1, 9])),
        Err(TxnError::Rejected(NullifyError::BadTarget))
    ));
}

#[test]
fn nullify_from_a_second_home_deposits_a_distinct_retraction() {
    // The [R] dedup key carries d_retr in its canonical from-fill, so the
    // same target retracted from another home is a FRESH retraction tuple —
    // the exact opposite of assert_sup's home-excluded key, where a duplicate
    // (old, new) from another home dedups to the first claim.
    let k = kernel();
    let w = writer(&k);
    let (target, _) = w
        .emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[])
        .expect("target");
    let (r1, _) = w.nullify(P1, &doc1(), &target).expect("retract from doc1");
    let (r2, _) = w.nullify(P1, &doc2(), &target).expect("retract from doc2");
    assert_ne!(r1, r2, "a second home's retraction is its own tuple");
    assert_eq!(r2, la2(1)); // doc2's own link chain
    let snap = k.snapshot();
    let links = snap.world().links();
    assert!(links.is_active(&r1) && links.is_active(&r2));
    assert!(links.is_nullified(&target)); // one target, monotone
}

#[test]
fn nullifying_a_retraction_restores_nothing() {
    // The tombstone set is monotone (R3/R6a) and the fold re-derives it from
    // the [R] link at every replay, whether or not that link is itself
    // nullified. This is where the module's two suppression mechanisms part
    // company: retiring reads the ACTIVE retired slice and is undoable
    // (is_filtered_reads_the_active_retired_slice), nullifying is not.
    let k = kernel();
    let w = writer(&k);
    let (target, _) = w
        .emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[])
        .expect("target");
    let (r1, _) = w.nullify(P1, &doc1(), &target).expect("retract it");
    let (r2, _) = w
        .nullify(P1, &doc1(), &r1)
        .expect("retract the retraction — an ordinary resident, owned target");
    assert_ne!(r2, r1, "a distinct I0 class, so the retraction lands fresh");
    let snap = k.snapshot();
    let links = snap.world().links();
    assert!(links.is_nullified(&r1), "the retraction is itself retracted");
    assert!(
        links.is_nullified(&target),
        "and its target stays nullified — the set is monotone"
    );
    assert!(!links.type_slice(&pred_def_ty(), View::Active).contains(&target));
    // The replay half: the fold re-derives the tombstone from a nullified
    // [R] link, so recovery restores nothing either.
    let bytes = bincode::serialize(snap.world()).expect("world serializes");
    let recovered: World = bincode::deserialize(&bytes).expect("world deserializes");
    let recovered =
        skep_kernel::WorldState::rebuild_derived(recovered).expect("this world's seed never refuses");
    assert!(recovered.links().is_nullified(&target));
    assert!(recovered.links().is_nullified(&r1));
}
