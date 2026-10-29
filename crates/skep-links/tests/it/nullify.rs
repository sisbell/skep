//! Nullify, the sole retraction path, over a real kernel (InMemory): the
//! tombstone it leaves and the address it may target, its target precedence,
//! a second home's distinct retraction, and its irreversibility — and the
//! record beside the tombstone, `retractions_of`, which names the `[R]`
//! records that retracted a root (the link-sets design §7, lane 7): one per
//! distinct retraction, in address order, a retraction of a retraction filed
//! under the retraction alone, and read off the hint at the price of its
//! addresses' lifts and nothing else.

use crate::common;
use crate::heap::settled_heap_bytes;

use common::*;
use skep_address::Address;
use skep_kernel::TxnError;
use skep_links::{retraction_tuple, HasLinks, LinkState, NullifyError, View};

/// The records that retracted `root`, as the store answers them.
fn retractions(links: &LinkState, root: &Address) -> Vec<Address> {
    links.retractions_of(root).collect()
}

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
        // The retraction is the tuple the published builder makes — the one
        // the daemon's entry-frame composer signs over.
        assert_eq!(*links.readlink(&r1).expect("resident"), retraction_tuple(&doc1(), &target));
        // The record beside the tombstone: the one `[R]` record, and none
        // under a root never retracted — the retraction itself included.
        assert_eq!(retractions(links, &target), vec![r1.clone()]);
        assert_eq!(retractions(links, &r1), vec![]);
        assert_eq!(retractions(links, &ca(9)), vec![], "a non-link names no record");
    }
    // idem⊤: re-retracting the same target from the same home dedups — and
    // deposits nothing, so the record beside the tombstone is still the one.
    let (r2, _) = w.nullify(P1, &doc1(), &target).expect("re-nullify dedups");
    assert_eq!(r2, r1);
    assert_eq!(retractions(k.snapshot().world().links(), &target), vec![r1.clone()]);
    // Born-nullified self-target: the target may be the address this call's
    // own retraction tuple would occupy (P-tgt's second disjunct) — doc2's
    // first link is la2(1).
    let (born_nullified, _) = w.nullify(P1, &doc2(), &la2(1)).expect("self-targeting retraction");
    assert_eq!(born_nullified, la2(1));
    {
        let snap = k.snapshot();
        assert!(snap.world().links().is_nullified(&la2(1)));
        // A born-nullified record is its own retraction: the one record
        // under its root is itself.
        assert_eq!(retractions(snap.world().links(), &la2(1)), vec![la2(1)]);
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
    // …and the record beside the tombstone names both, in address order:
    // which came first is the position map's to say, not this slice's.
    assert_eq!(retractions(links, &target), vec![r1, r2]);
}

/// The record beside the tombstone is a point lookup off the hint, counted
/// in bytes (the link-sets design §7, lane 7): a root never retracted asks
/// the heap for nothing; a root retracted once costs its set's one walk and
/// the lift of its record's address; a second retraction costs exactly one
/// lift more — one address clone — and no walk of any home, however many
/// links the homes hold. A flood of a thousand links beside the root, every
/// one of them on the same position, moves no figure.
#[test]
fn retractions_of_costs_its_records_lifts_and_nothing_of_the_homes() {
    let cost = |flood: u32| -> (u64, u64, u64, u64) {
        let k = kernel();
        let w = writer(&k);
        let (target, _) = w.emit(P1, &doc1(), &pred_def_ty(), &ca(1), &[]).expect("target");
        for i in 0..flood {
            deposit_in(&k, &doc1(), &[ca(1)], &[ca(100 + i)], &unregistered_ta(1));
            deposit_in(&k, &doc2(), &[ca(1)], &[ca(100 + i)], &unregistered_ta(1));
        }
        let never = ca(9);
        let bytes_of = |root: &Address, expected: usize| -> u64 {
            let snap = k.snapshot();
            let links = snap.world().links();
            let (records, bytes) = settled_heap_bytes(|| links.retractions_of(root).count());
            assert_eq!(records, expected);
            bytes
        };
        let none_bytes = bytes_of(&never, 0);
        let (r1, _) = w.nullify(P1, &doc1(), &target).expect("retract from doc1");
        let one_bytes = bytes_of(&target, 1);
        w.nullify(P1, &doc2(), &target).expect("retract from doc2");
        let two_bytes = bytes_of(&target, 2);
        let lift = settled_heap_bytes(|| r1.clone()).1;
        assert!(lift > 0, "an address lifted is an allocation");
        (none_bytes, one_bytes, two_bytes, lift)
    };
    let (none_bytes, one_bytes, two_bytes, lift) = cost(0);
    eprintln!("retractions_of: never retracted {none_bytes} B; one record {one_bytes} B; two records {two_bytes} B; one lift {lift} B");
    assert_eq!(none_bytes, 0, "a root never retracted asks the heap for nothing");
    assert!(one_bytes >= lift, "one record: its lift is in the figure");
    assert_eq!(two_bytes - one_bytes, lift, "a second record costs one lift more and nothing else");
    assert_eq!(cost(1_000), (none_bytes, one_bytes, two_bytes, lift), "a flood beside the root moves no figure");
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
    // The record beside the tombstone files the second retraction under the
    // RETRACTION it retracts, and adds nothing under the target: a
    // retracted retraction is still the one record of its target.
    assert_eq!(retractions(links, &target), vec![r1.clone()]);
    assert_eq!(retractions(links, &r1), vec![r2.clone()]);
    // The replay half: the fold re-derives the tombstone from a nullified
    // [R] link, so recovery restores nothing either — and the records
    // beside the tombstones come back as they stood.
    let bytes = bincode::serialize(snap.world()).expect("world serializes");
    let recovered: World = bincode::deserialize(&bytes).expect("world deserializes");
    let recovered =
        skep_kernel::WorldState::rebuild_derived(recovered).expect("this world's seed never refuses");
    assert!(recovered.links().is_nullified(&target));
    assert!(recovered.links().is_nullified(&r1));
    assert_eq!(retractions(recovered.links(), &target), vec![r1.clone()]);
    assert_eq!(retractions(recovered.links(), &r1), vec![r2]);
}
