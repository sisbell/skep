//! The fold's totality domain, the journaled types' serde round trips and
//! decode doors, and durable recovery by checkpoint and replay.

use crate::common::*;

use serde::Serialize;
use skep_address::{Level, Tumbler};
use skep_kernel::Kernel;
use skep_namespace::{
    HasM3, M3Rec, M3State, MintError, Namespace, PrincipalId, BOOTSTRAP_PRINCIPAL,
};
use tempfile::tempdir;

/// Outside `apply_m3`'s totality domain (§Core data model): the count
/// representation cannot hold a gap, so a jumped ordinal would make
/// [1,0,1]..[1,0,4] phantom entities (B1/B3). The guard is a `debug_assert`,
/// so this states the fail-stop only where debug assertions are compiled in.
#[test]
#[cfg(debug_assertions)]
#[should_panic(expected = "Allocate ordinal must equal its namespace's effective frontier + 1")]
fn a_jumped_allocate_ordinal_fail_stops_the_fold() {
    let _ = M3State::genesis().apply_m3(&alloc(&[1, 0, 5]));
}

/// The same guard in the other direction: a re-staged Allocate would
/// silently regress the frontier and re-hand an address already minted.
#[test]
#[cfg(debug_assertions)]
#[should_panic(expected = "Allocate ordinal must equal its namespace's effective frontier + 1")]
fn a_regressed_allocate_ordinal_fail_stops_the_fold() {
    let s = M3State::genesis()
        .apply_m3(&alloc(&[1, 0, 1]))
        .apply_m3(&alloc(&[1, 0, 2]));
    let _ = s.apply_m3(&alloc(&[1, 0, 1]));
}

// ---- serde / recovery ----

#[test]
fn journaled_types_survive_serde_round_trips() {
    // M3Rec — the journal delta — through M2's actual wire format (bincode).
    let recs = [
        M3Rec::Allocate {
            addr: a(&[1, 0, 1]),
            published: false,
        },
        // A document's Allocate carries its resolved bit, and the bit rides
        // the round trip with it (PUB-7.8/7.10).
        M3Rec::Allocate {
            addr: a(&[1, 0, 1, 0, 1]),
            published: true,
        },
        M3Rec::RegisterNode { addr: a(&[1, 7]) },
        M3Rec::RegisterPrincipal {
            prefix: a(&[1, 0, 1]),
            id: ID1,
        },
    ];
    for rec in &recs {
        let bytes = bincode::serialize(rec).expect("serialize M3Rec");
        let back: M3Rec = bincode::deserialize(&bytes).expect("deserialize M3Rec");
        assert_eq!(*rec, back); // whole value: variant AND payload
    }

    // The Address payloads journal as bare, flat tumblers — the data model's
    // form, not the in-memory type's. A raw record carrying Tumblers encodes
    // byte-identically, variant for variant.
    #[derive(Serialize)]
    enum RawM3Rec {
        Allocate { addr: Tumbler, published: bool },
        RegisterNode { addr: Tumbler },
        RegisterPrincipal { prefix: Tumbler, id: PrincipalId },
    }
    let raw_recs = [
        RawM3Rec::Allocate {
            addr: t(&[1, 0, 1]),
            published: false,
        },
        RawM3Rec::Allocate {
            addr: t(&[1, 0, 1, 0, 1]),
            published: true,
        },
        RawM3Rec::RegisterNode { addr: t(&[1, 7]) },
        RawM3Rec::RegisterPrincipal {
            prefix: t(&[1, 0, 1]),
            id: ID1,
        },
    ];
    for (rec, raw) in recs.iter().zip(&raw_recs) {
        assert_eq!(
            bincode::serialize(rec).expect("serialize M3Rec"),
            bincode::serialize(raw).expect("serialize the raw shape"),
        );
    }

    // A tumbler that is not T4-valid cannot arrive as a record: the payload
    // re-validates on the way off the journal (M1's validating Deserialize),
    // so the fold is never handed a malformed address.
    let malformed = bincode::serialize(&RawM3Rec::RegisterNode { addr: t(&[1, 0]) })
        .expect("serialize the raw shape");
    assert!(bincode::deserialize::<M3Rec>(&malformed).is_err());

    // Nor can a PARENTLESS Allocate. [7] is T4-valid, so M1's door passes it
    // — and `apply_m3` derives its namespace from the parent, which a
    // one-component node has none of, so folding one would panic the applier
    // at every replay from then on. M3's own door is what refuses it, before
    // the record is ever a value.
    for parentless in [t(&[7]), t(&[1])] {
        let frame = bincode::serialize(&RawM3Rec::Allocate {
            addr: parentless,
            published: false,
        })
        .expect("serialize the raw shape");
        assert!(
            bincode::deserialize::<M3Rec>(&frame).is_err(),
            "a parentless Allocate decoded into a record"
        );
    }
    // The refusal is exactly the parentless case, not a length rule: the
    // shortest address that DOES extend a parent still decodes.
    let shortest = bincode::serialize(&RawM3Rec::Allocate {
        addr: t(&[1, 1]),
        published: false,
    })
    .expect("serialize the raw shape");
    assert_eq!(
        bincode::deserialize::<M3Rec>(&shortest).expect("a two-component Allocate decodes"),
        M3Rec::Allocate {
            addr: a(&[1, 1]),
            published: false,
        }
    );
    // …and RegisterNode is untouched by it: a one-component node is exactly
    // what that variant carries.
    let bare_node_frame = bincode::serialize(&RawM3Rec::RegisterNode { addr: t(&[7]) })
        .expect("serialize the raw shape");
    assert_eq!(
        bincode::deserialize::<M3Rec>(&bare_node_frame).expect("a bare node registers"),
        M3Rec::RegisterNode { addr: a(&[7]) }
    );

    // A principal seats at an ACCOUNT prefix and nowhere else. `delegate` is
    // the sole producer of this record and its hoisted `NotAccountTier` gate
    // makes every one it stages account-tier — genesis's node-tier π₀ seat is
    // world state, not a record — so the door refuses nothing M3 has written.
    // Node tier is the shape that matters: ω's O1a filter ADMITS it, so its
    // carrier would be the effective owner of everything under that node no
    // deeper account principal covers, and could seat that node's first
    // account. Below-tier seats every reader of Π refuses already.
    for off_tier in [
        t(&[1]),
        t(&[1, 7]),
        t(&[1, 0, 1, 0, 1]),
        t(&[1, 0, 1, 0, 1, 0, 1, 1]),
    ] {
        let frame = bincode::serialize(&RawM3Rec::RegisterPrincipal {
            prefix: off_tier.clone(),
            id: ID1,
        })
        .expect("serialize the raw shape");
        assert!(
            bincode::deserialize::<M3Rec>(&frame).is_err(),
            "a {off_tier:?} principal seat decoded into a record"
        );
    }
    // …and the account tier decodes at both of its forms — under a node, and
    // the sub-account chain `delegate` also stages.
    let sub_account_frame = bincode::serialize(&RawM3Rec::RegisterPrincipal {
        prefix: t(&[1, 0, 1, 1]),
        id: ID2,
    })
    .expect("serialize the raw shape");
    assert_eq!(
        bincode::deserialize::<M3Rec>(&sub_account_frame).expect("a sub-account seat decodes"),
        M3Rec::RegisterPrincipal {
            prefix: a(&[1, 0, 1, 1]),
            id: ID2
        }
    );

    // M3State — the checkpointed slice: every field is ordinary serde (none
    // skip-serialized; default rebuild_derived), so a round-tripped state
    // answers identically.
    let (k, acct, doc) = kernel_with_account_and_doc();
    let keys = [M3State::content_lock_key(&doc)];
    k.transact::<_, MintError>(&keys, |stg| {
        let (_, r) = stg.working().m3().mint_content(&doc)?;
        stg.push(r.into());
        Ok(())
    })
    .expect("content commit");
    let state = k.snapshot().world().m3().clone();
    let bytes = bincode::serialize(&state).expect("serialize M3State");
    let back: M3State = bincode::deserialize(&bytes).expect("deserialize M3State");
    // Whole-value: the decoded slice IS the encoded one, entry for entry
    // across the three registries and the publication map — which the
    // per-question probes below then name, so a failure says which claim
    // broke.
    assert_eq!(back, state);
    assert!(back.is_allocated(&a(&[1, 0, 1, 0, 1, 0, 1, 1])));
    assert!(back.is_registered_document(&doc));
    // The publication map rides inside the slice too: the fixture's doc is
    // the account's doc 1, born published by the flagless create.
    assert!(back.published(&doc));
    assert_eq!(back.entity_level(&acct), Some(Level::Account));
    assert_eq!(back.next_account_prefix(&a(&[1])), Some(a(&[1, 0, 2])));
    // The whole principal registry rides inside the slice — both its
    // entries, both directions (id → prefix, address → ω).
    assert_eq!(back.principal_prefix(ID1), Some(&acct));
    assert_eq!(back.effective_owner(&doc), Some(ID1));
    assert_eq!(back.principal_prefix(BOOTSTRAP_PRINCIPAL), Some(&a(&[1])));
    assert_eq!(back.effective_owner(&a(&[1])), Some(BOOTSTRAP_PRINCIPAL));
}

#[test]
fn durable_kernel_recovers_the_whole_slice_by_checkpoint_and_replay() {
    // M3 rides M2 (§8): its slice — the three registries and the publication
    // map — is restored verbatim from the loaded checkpoint, then advanced by
    // replaying post-checkpoint M3Recs (default rebuild_derived — nothing to
    // re-seed). The publication map's own recovery, bit by bit, is pinned in
    // `the_bit_is_immutable_and_recovers_by_checkpoint_and_replay`.
    let dir = tempdir().expect("tempdir");
    let acct;
    let doc;
    let before;
    {
        let k = Kernel::open(fsync_config(dir.path()), genesis_world()).expect("open");
        let ns = Namespace::new(&k);
        let (acc, _) = ns
            .delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1]), ID1)
            .expect("delegate");
        acct = acc;
        // Checkpoint here: the delegation is restored FROM the checkpoint;
        // everything after rides post-checkpoint replay.
        k.checkpoint().expect("checkpoint");
        let (d, _) = ns.create_new_document(ID1, &acct, None).expect("create");
        doc = d;
        ns.register_node(t(&[1, 7])).expect("register node");
        before = k.snapshot().world().m3().clone();
    }
    let k2 = Kernel::open(fsync_config(dir.path()), genesis_world()).expect("reopen");
    let snap = k2.snapshot();
    let m3 = snap.world().m3();
    // What recovery claims, whole: the restored slice IS the pre-crash slice
    // — checkpoint-loaded registries plus post-checkpoint replay landing
    // exactly where the live one stood. The named answers below say which
    // parts of that a reader cares about.
    assert_eq!(m3, &before);
    assert_eq!(m3.principal_prefix(ID1), Some(&acct));
    assert!(m3.is_registered_document(&doc));
    assert_eq!(m3.entity_level(&a(&[1, 7])), Some(Level::Node));
    assert_eq!(m3.effective_owner(&doc), Some(ID1));
    // The frontiers recovered too: the chains continue where they left off.
    assert_eq!(m3.next_account_prefix(&a(&[1])), Some(a(&[1, 0, 2])));
    let (d2, _) = m3.mint_document(&acct, false).expect("mint after recovery");
    assert_eq!(d2, a(&[1, 0, 1, 0, 2]));
}
