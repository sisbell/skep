//! The fold's totality domain, the journaled types' serde round trips, decode
//! doors and canonical bytes, and durable recovery by checkpoint and replay.

use crate::common::*;

use serde::Serialize;
use skep_address::{Level, Tumbler};
use skep_kernel::Kernel;
use skep_namespace::{
    ghost_position, head_document, system_account, HasM3, M3Rec, M3State, MintError, Namespace,
    PrincipalId, BOOTSTRAP_PRINCIPAL, SYSTEM_PRINCIPAL,
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

/// A `RegisterNode` naming an address BELOW the node tier: inside the fold's
/// totality domain, outside `register_node`'s admission conditions, and past
/// the record door, which deliberately carries no tier check. `apply_m3`
/// states what that costs — "a non-node-level entry is unreachable, since
/// `is_allocated` consults `nodes` only on the `Node` arm" — and that sentence
/// is the door's whole justification. An `is_allocated` spelled
/// `nodes.contains(a) || is_chain_member(a)` passes every other test, and then
/// one frame registers an account no one is seated at, a document with no
/// publication entry (which a by-miss index reads as PUBLISHED), or a ghost
/// tumbler, which must answer unallocated on every board forever.
#[test]
fn a_non_node_entry_in_the_node_registry_is_unreachable() {
    let acct = a(&[1, 0, 9]);
    let doc = a(&[1, 0, 1, 0, 9]);
    let ghost = ghost_position(1);
    let s = [&acct, &doc, &ghost]
        .into_iter()
        .fold(M3State::genesis(), |s, addr| {
            s.apply_m3(&M3Rec::RegisterNode { addr: addr.clone() })
        });
    for addr in [&acct, &doc, &ghost] {
        assert!(
            !s.is_allocated(addr),
            "{addr:?} reads allocated off the node registry"
        );
        assert_eq!(
            s.entity_level(addr),
            None,
            "{addr:?} reads as an entity off the node registry"
        );
    }
    // …so every gate that reads them refuses exactly as if the record were
    // absent.
    assert_eq!(
        s.mint_document(&acct, false).unwrap_err(),
        MintError::NotAnAccount
    );
    assert!(s.next_account_prefix(&acct).is_none());
    assert_eq!(
        s.mint_content(&doc).unwrap_err(),
        MintError::HomeNotRegistered
    );
}

/// O12/O13: a seat is written ONCE. A second `RegisterPrincipal` naming a
/// seated prefix is a transition no op makes — `delegate` seats only a fresh
/// prefix — and no record door can refuse it, since whether a prefix is
/// seated is a claim about the registry and not about the frame. So the fold
/// answers it: the first seat stands, and `principal_prefix` stays the
/// value-stable read its doc promises. The system account is the case worth
/// naming: its seat makes `SYSTEM_PRINCIPAL` ω of the head document `H`, so a
/// frame that replaced it would hand every published head to another
/// principal. There is no `debug_assert` in this arm, so the fold reaches the
/// guard on both build profiles.
#[test]
fn a_replayed_seat_never_replaces_a_seated_principal() {
    let s = M3State::genesis().apply_m3(&M3Rec::RegisterPrincipal {
        prefix: system_account(),
        id: ID1,
    });
    assert_eq!(s.effective_owner(&head_document()), Some(SYSTEM_PRINCIPAL));
    assert_eq!(
        s.principal_prefix(SYSTEM_PRINCIPAL),
        Some(&system_account())
    );
    assert!(
        s.principal_prefix(ID1).is_none(),
        "the replacing id is seated nowhere"
    );
    assert_eq!(s, M3State::genesis(), "the frame changed nothing");

    // …and an account `delegate` seated, the same.
    let acct = a(&[1, 0, 1]);
    let seat = |id| M3Rec::RegisterPrincipal {
        prefix: acct.clone(),
        id,
    };
    let seated = M3State::genesis()
        .apply_m3(&alloc(&[1, 0, 1]))
        .apply_m3(&seat(ID1));
    let replayed = seated.apply_m3(&seat(ID2));
    assert_eq!(replayed.effective_owner(&acct), Some(ID1));
    assert_eq!(replayed.principal_prefix(ID1), Some(&acct));
    assert!(replayed.principal_prefix(ID2).is_none());
    assert_eq!(replayed, seated);
}

// ---- serde / recovery ----

/// `M3Rec`'s journal shape with each `Address` payload written as the bare
/// tumbler it journals as — the data model's form, not the in-memory type's —
/// so a test can pin the encoding byte for byte and hand the decoder frames
/// the in-memory type could never build.
#[derive(Serialize)]
enum RawM3Rec {
    Allocate { addr: Tumbler, published: bool },
    RegisterNode { addr: Tumbler },
    RegisterPrincipal { prefix: Tumbler, id: PrincipalId },
}

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

/// A record comes back off the journal through its fields' doors and no other
/// way: M1's validating decode refuses a non-T4 address in any payload,
/// `Allocate`'s address door refuses a parentless one, and
/// `RegisterPrincipal`'s prefix door refuses every seat off the account tier —
/// each a decode failure, never a value the fold could be handed — while the
/// shapes just inside each door still decode.
#[test]
fn a_journal_frame_re_enters_only_through_its_field_doors() {
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
}

/// `M3State`'s bytes are CANONICAL — "two slices holding the same entries
/// encode to one byte string on any process and any machine" — which is what
/// lets M2's checkpoint header commit to its body by hash, and a published
/// head name a checkpoint by hash. The crate's only other pin on the slice's
/// bytes is genesis's, at two entries per field, where a hash-ordered field
/// would still match half the time, and it does not reach the frontier map,
/// the field whose order its own doc calls WRITTEN. So: eight or more entries
/// in EVERY field, reached along two different histories off two SEPARATELY
/// built geneses — not one cloned, so a hash-ordered field would carry two
/// hashers — and the bytes compared whole.
#[test]
fn two_slices_holding_the_same_entries_encode_to_one_byte_string() {
    let accounts: Vec<Vec<u32>> = (1..=6).map(|i| vec![1, 0, i]).collect();
    let docs: Vec<Vec<u32>> = (1..=6).map(|i| vec![1, 0, i, 0, 1]).collect();
    let seat = |i: usize| M3Rec::RegisterPrincipal {
        prefix: a(&accounts[i]),
        id: PrincipalId(10 + i as u64),
    };
    let document = |i: usize| M3Rec::Allocate {
        addr: a(&docs[i]),
        published: i % 2 == 0,
    };
    let node = |n: u32| M3Rec::RegisterNode { addr: a(&[1, n]) };

    // History X: account by account — its baptism, its seat, its document —
    // then the nodes 1.2..1.7 ascending.
    let mut x = M3State::genesis();
    for (i, acct) in accounts.iter().enumerate() {
        x = x
            .apply_m3(&alloc(acct))
            .apply_m3(&seat(i))
            .apply_m3(&document(i));
    }
    for n in 2..=7 {
        x = x.apply_m3(&node(n));
    }
    // History Y, off a SECOND genesis: the nodes first and descending, the
    // accounts (one chain, so in order), the documents in reverse — each is c₁
    // of its own chain — and the seats in reverse.
    let mut y = M3State::genesis();
    for n in (2..=7).rev() {
        y = y.apply_m3(&node(n));
    }
    for acct in &accounts {
        y = y.apply_m3(&alloc(acct));
    }
    for i in (0..accounts.len()).rev() {
        y = y.apply_m3(&document(i));
    }
    for i in (0..accounts.len()).rev() {
        y = y.apply_m3(&seat(i));
    }

    // One set of entries — nine frontiers, eight nodes, eight seats, eight
    // documents — reached two ways…
    assert_eq!(x, y);
    assert_eq!(x.documents().len(), 8);
    // …is one byte string.
    assert_eq!(
        bincode::serialize(&x).expect("serialize history X"),
        bincode::serialize(&y).expect("serialize history Y"),
        "two slices holding the same entries encode differently"
    );
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
