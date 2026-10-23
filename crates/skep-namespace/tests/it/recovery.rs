//! The fold's totality domain and what it leaves to its producers, the
//! journaled types' serde round trips, decode doors, canonical bytes and the
//! slice's rendering, and durable recovery by checkpoint and replay.

use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::common::*;

use serde::Serialize;
use skep_address::{shift, validate, Level, Nat, Tumbler};
use skep_kernel::{Kernel, Seq};
use skep_namespace::{
    ghost_position, head_document, system_account, HasM3, M3Rec, M3State, MintError, Namespace,
    PrincipalId, BOOTSTRAP_PRINCIPAL, MAX_NODE_COMPONENTS, MAX_PRINCIPAL_COMPONENTS,
    SYSTEM_PRINCIPAL,
};
use tempfile::tempdir;

/// `AllocateRange(RangeAllocation { first, count })` through the `test-hooks`
/// constructor, for the fold's totality tests.
fn alloc_range(first: &[u32], count: u32) -> M3Rec {
    M3Rec::allocate_range(a(first), Nat::from(count))
}

/// Outside `apply_m3`'s totality domain (§Core data model): the count
/// representation cannot hold a gap, so a jumped ordinal would make
/// [1,0,1]..[1,0,4] phantom entities (B1/B3). The fold fail-stops on it, on
/// every build.
#[test]
#[should_panic(expected = "Allocate ordinal must equal its namespace's effective frontier + 1")]
fn a_jumped_allocate_ordinal_fail_stops_the_fold() {
    let _ = M3State::genesis().apply_m3(Seq(0), &alloc(&[1, 0, 5]));
}

/// The same guard in the other direction: a re-staged Allocate would
/// silently regress the frontier and re-hand an address already minted.
#[test]
#[should_panic(expected = "Allocate ordinal must equal its namespace's effective frontier + 1")]
fn a_regressed_allocate_ordinal_fail_stops_the_fold() {
    let s = M3State::genesis()
        .apply_m3(Seq(0), &alloc(&[1, 0, 1]))
        .apply_m3(Seq(0), &alloc(&[1, 0, 2]));
    let _ = s.apply_m3(Seq(0), &alloc(&[1, 0, 1]));
}

/// The range mint's commit half under the same guard: a range whose first
/// ordinal jumps past the frontier would leave a gap no count can hold (B1),
/// so the fold fail-stops on it, on every build.
#[test]
#[should_panic(expected = "a range's first ordinal must equal its namespace's effective frontier + 1")]
fn a_jumped_range_first_ordinal_fail_stops_the_fold() {
    let _ = M3State::genesis().apply_m3(Seq(0), &alloc_range(&[1, 0, 1, 0, 1, 0, 1, 5], 3));
}

/// …and the other direction: a re-staged range would regress the frontier
/// past addresses already minted and re-hand them.
#[test]
#[should_panic(expected = "a range's first ordinal must equal its namespace's effective frontier + 1")]
fn a_regressed_range_first_ordinal_fail_stops_the_fold() {
    let s = M3State::genesis().apply_m3(Seq(0), &alloc_range(&[1, 0, 1, 0, 1, 0, 1, 1], 3));
    let _ = s.apply_m3(Seq(0), &alloc_range(&[1, 0, 1, 0, 1, 0, 1, 2], 2));
}

/// A jumped `Allocate` is refused at the fold, on every build, and nowhere
/// earlier: no field door can see contiguity — a claim about the frontier the
/// record would advance — so the frame decodes, as a producer that decodes a
/// record and pushes it would hold it, and the push is where it stops. The
/// refusal is clean: nothing is journaled, the kernel is not poisoned and
/// still commits, no document the record names or would have skipped reads
/// registered, the account's next document is the one it was, and the panic
/// names the record. Folded, the record would register docs 2–4 with no
/// publication entry, each read published by the engine's exception set.
#[test]
fn a_jumped_allocate_decodes_and_fail_stops_at_the_push() {
    let (k, acct, _doc) = kernel_with_account_and_doc();
    let frame = bincode::serialize(&RawM3Rec::Allocate {
        addr: t(&[1, 0, 1, 0, 5]),
        published: false,
    })
    .expect("serialize the raw shape");
    let jumped: M3Rec = bincode::deserialize(&frame).expect("no field door sees contiguity");
    let before = k.current_seq();
    let refused = catch_unwind(AssertUnwindSafe(|| {
        k.transact::<_, MintError>(&[M3State::document_lock_key(&acct)], |stg| {
            stg.push(jumped.into());
            Ok(())
        })
    }));
    let payload = refused.expect_err("the jumped Allocate folded and committed");
    let message = payload
        .downcast_ref::<String>()
        .cloned()
        .unwrap_or_default();
    assert!(
        message.contains("1.0.1.0.5 is not its chain's next"),
        "the refusal names the record: {message:?}"
    );
    assert_eq!(k.current_seq(), before, "the refusal committed something");
    assert!(!k.is_poisoned(), "the refusal poisoned the kernel");
    let m3 = k.snapshot().world().m3().clone();
    for skipped in 2..=5 {
        assert!(
            !m3.is_registered_document(&a(&[1, 0, 1, 0, skipped])),
            "doc {skipped} reads registered"
        );
    }
    // …and the kernel still commits: the account's next document is doc 2.
    let d2 = commit_mint(&k, M3State::document_lock_key(&acct), |m3| {
        m3.mint_document(&acct, false)
    });
    assert_eq!(d2, a(&[1, 0, 1, 0, 2]));
}

/// The range mint's precondition, held on every build: a range of nothing
/// moves no frontier and its record is refused at decode, so the mint refuses
/// a zero `count` before any record exists — a caller's bug answered as one,
/// rather than a first address handed out that the chain's next mint issues
/// again, under a frame no replay of the journal could decode.
#[test]
#[should_panic(expected = "a content range mints at least one address")]
fn a_range_of_nothing_fail_stops_at_its_mint() {
    let (k, _acct, doc) = kernel_with_account_and_doc();
    let m3 = k.snapshot().world().m3().clone();
    let _ = m3.mint_content_range(&doc, &Nat::from(0u32));
}

/// RANGE ≡ SINGLES (B2: a mint is a pure function of the frontier): after
/// `mint_content_range(home, N)` the chain's frontier stands at `first ⊕ (N −
/// 1)`, the next `mint_content(home)` issues `first ⊕ N`, every address of
/// the range reads allocated, and the N addresses are byte for byte the N
/// that N successive single mints off the same state would have issued — so
/// a stretch's k-th byte sits at the address the k-th per-byte value would
/// have had. The range mint keeps `mint_content`'s gate too: an unregistered
/// home is `HomeNotRegistered`.
#[test]
fn a_range_mint_issues_the_addresses_n_single_mints_would_and_moves_the_frontier_by_n() {
    let (k, _acct, doc) = kernel_with_account_and_doc();
    let base = k.snapshot().world().m3().clone();
    let n = 5u32;
    let (first, range) = base.mint_content_range(&doc, &Nat::from(n)).expect("doc is registered");
    assert_eq!(first, a(&[1, 0, 1, 0, 1, 0, 1, 1]), "the chain's first slot");
    let M3Rec::AllocateRange(allocation) = &range else { panic!("a range mint returns its record") };
    assert_eq!((allocation.first(), allocation.count()), (&first, &Nat::from(n)));
    let after_range = base.apply_m3(Seq(0), &range);
    // The singles, folded one after another off the same base.
    let mut after_singles = base.clone();
    let mut singles = Vec::new();
    for _ in 0..n {
        let (addr, rec) = after_singles.mint_content(&doc).expect("doc is registered");
        after_singles = after_singles.apply_m3(Seq(0), &rec);
        singles.push(addr);
    }
    for (k, single) in singles.iter().enumerate() {
        let in_range = validate(shift(first.tumbler(), &Nat::from(k))).expect("T4-valid");
        assert_eq!(single, &in_range, "address {k} of the range is the {k}th single mint's");
        assert!(after_range.is_allocated(&in_range), "address {k} of the range reads allocated");
    }
    assert_eq!(after_range, after_singles, "one range and N singles leave one slice");
    let (next, _) = after_range.mint_content(&doc).expect("doc is registered");
    assert_eq!(next, validate(shift(first.tumbler(), &Nat::from(n))).expect("T4-valid"));
    assert_eq!(after_range.next_content_address(&doc), Some(next.clone()));
    assert!(!after_range.is_allocated(&next), "the address past the range is not yet minted");
    // A second range continues the chain where the first reached.
    let (second, _) = after_range.mint_content_range(&doc, &Nat::from(2u32)).expect("registered");
    assert_eq!(second, next);
    assert_eq!(
        base.mint_content_range(&a(&[1, 0, 1, 0, 9]), &Nat::from(1u32)).unwrap_err(),
        MintError::HomeNotRegistered
    );
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
            s.apply_m3(Seq(0), &M3Rec::register_node(addr.clone()))
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
    let s = M3State::genesis().apply_m3(Seq(0), &M3Rec::register_principal(system_account(), ID1));
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
    let seat = |id| M3Rec::register_principal(acct.clone(), id);
    let seated = M3State::genesis()
        .apply_m3(Seq(0), &alloc(&[1, 0, 1]))
        .apply_m3(Seq(0), &seat(ID1));
    let replayed = seated.apply_m3(Seq(0), &seat(ID2));
    assert_eq!(replayed.effective_owner(&acct), Some(ID1));
    assert_eq!(replayed.principal_prefix(ID1), Some(&acct));
    assert!(replayed.principal_prefix(ID2).is_none());
    assert_eq!(replayed, seated);
}

/// The seat–allocation coupling (O17b; ASN-0042's PrefixBaptismCoupling) is
/// its PRODUCERS' and not the fold's — `M3Rec::RegisterPrincipal` states
/// what a producer owes, and the `principals` field lists the coupling among
/// Π's producer invariants: `apply_m3` folds an account's `Allocate` with no
/// seat, and a `RegisterPrincipal` at an account no chain holds, each as it
/// arrives, and re-establishes neither half. On every state the ops produce
/// the halves agree
/// (`an_account_is_allocated_iff_a_principal_is_seated_at_it`); this is the
/// state a producer that broke the coupling leaves, and what each half's
/// breach costs the owner-of-address read (AUTH-6.37), which reads
/// `prefix == a` as an account's allocation test. The other clause the fold
/// leaves unchecked, a seat under a carried id, is
/// `omega_names_the_seat_it_matched_when_two_principals_carry_one_id`'s.
#[test]
fn the_fold_leaves_the_seat_allocation_coupling_to_its_producers() {
    let (allocated, seated) = (a(&[1, 0, 1]), a(&[1, 0, 2]));
    let s = M3State::genesis()
        .apply_m3(Seq(0), &alloc(&[1, 0, 1]))
        .apply_m3(Seq(0), &M3Rec::register_principal(seated.clone(), ID2));

    // Allocated and seated nowhere: ω climbs to π₀'s node seat, so the
    // owner-of-address read calls the account free, an owner above it owns
    // its documents, and the owner-account read answers nobody.
    assert!(s.is_registered_account(&allocated));
    assert_eq!(s.effective_owner_prefix(&allocated), Some(&a(&[1])));
    assert_eq!(s.account_seat(&allocated), None);
    // Seated and allocated nowhere: ω answers the seat itself, so the
    // owner-of-address read calls allocated an account no chain holds.
    assert!(!s.is_allocated(&seated));
    assert_eq!(s.effective_owner_prefix(&seated), Some(&seated));
    assert_eq!(s.principal_prefix(ID2), Some(&seated));
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
    AllocateRange { first: Tumbler, count: Nat },
}

#[test]
fn journaled_types_survive_serde_round_trips() {
    // M3Rec — the journal delta — through M2's actual wire format (bincode).
    let recs = [
        M3Rec::allocate(a(&[1, 0, 1]), false),
        // A document's Allocate carries its resolved bit, and the bit rides
        // the round trip with it (PUB-7.8/7.10).
        M3Rec::allocate(a(&[1, 0, 1, 0, 1]), true),
        M3Rec::register_node(a(&[1, 7])),
        M3Rec::register_principal(a(&[1, 0, 1]), ID1),
        // The range mint: its first address and its count, no bit.
        M3Rec::allocate_range(a(&[1, 0, 1, 0, 1, 0, 1, 1]), Nat::from(3u32)),
    ];
    for rec in &recs {
        let bytes = bincode::serialize(rec).expect("serialize M3Rec");
        let restored: M3Rec = bincode::deserialize(&bytes).expect("deserialize M3Rec");
        assert_eq!(*rec, restored); // whole value: variant AND payload
    }

    // The Address payloads journal as bare, flat tumblers — the data model's
    // form, not the in-memory type's. A raw record carrying Tumblers encodes
    // byte-identically, variant for variant — the range mint at index 3,
    // appended after the three.
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
        RawM3Rec::AllocateRange {
            first: t(&[1, 0, 1, 0, 1, 0, 1, 1]),
            count: Nat::from(3u32),
        },
    ];
    let range_bytes = bincode::serialize(&recs[4]).expect("serialize the range mint");
    assert_eq!(&range_bytes[..4], &3u32.to_le_bytes(), "AllocateRange is variant 3");
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
    let live = k.snapshot().world().m3().clone();
    let bytes = bincode::serialize(&live).expect("serialize M3State");
    let restored: M3State = bincode::deserialize(&bytes).expect("deserialize M3State");
    // Whole-value: the decoded slice IS the encoded one, entry for entry
    // across the three registries and the publication map — which the
    // per-question probes below then name, so a failure says which claim
    // broke.
    assert_eq!(restored, live);
    assert!(restored.is_allocated(&a(&[1, 0, 1, 0, 1, 0, 1, 1])));
    assert!(restored.is_registered_document(&doc));
    // The publication map rides inside the slice too: the fixture's doc is
    // the account's doc 1, born published by the flagless create.
    assert!(restored.published(&doc));
    assert_eq!(restored.entity_level(&acct), Some(Level::Account));
    assert_eq!(restored.next_account_prefix(&a(&[1])), Some(a(&[1, 0, 2])));
    // The whole principal registry rides inside the slice — both its
    // entries, both directions (id → prefix, address → ω).
    assert_eq!(restored.principal_prefix(ID1), Some(&acct));
    assert_eq!(restored.effective_owner(&doc), Some(ID1));
    assert_eq!(
        restored.principal_prefix(BOOTSTRAP_PRINCIPAL),
        Some(&a(&[1]))
    );
    assert_eq!(
        restored.effective_owner(&a(&[1])),
        Some(BOOTSTRAP_PRINCIPAL)
    );
}

/// A record comes back off the journal through its fields' doors and no other
/// way: M1's validating decode refuses a non-T4 address in any payload,
/// `Allocate`'s address door refuses a parentless one, and
/// `RegisterPrincipal`'s prefix door refuses every seat off the account tier —
/// each a decode failure, never a value the fold could be handed — while the
/// shapes just inside each door still decode, and so does every shape past an
/// op's depth cap, which no door carries.
#[test]
fn a_journal_frame_re_enters_only_through_its_field_doors() {
    // A tumbler that is not T4-valid cannot arrive as a record: the payload
    // re-validates on the way off the journal (M1's validating Deserialize),
    // so the fold is never handed a malformed address.
    let malformed_frame = bincode::serialize(&RawM3Rec::RegisterNode { addr: t(&[1, 0]) })
        .expect("serialize the raw shape");
    assert!(bincode::deserialize::<M3Rec>(&malformed_frame).is_err());

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
    let shortest_parented_frame = bincode::serialize(&RawM3Rec::Allocate {
        addr: t(&[1, 1]),
        published: false,
    })
    .expect("serialize the raw shape");
    assert_eq!(
        bincode::deserialize::<M3Rec>(&shortest_parented_frame)
            .expect("a two-component Allocate decodes"),
        M3Rec::allocate(a(&[1, 1]), false)
    );
    // …and RegisterNode is untouched by it: a one-component node is exactly
    // what that variant carries.
    let bare_node_frame = bincode::serialize(&RawM3Rec::RegisterNode { addr: t(&[7]) })
        .expect("serialize the raw shape");
    assert_eq!(
        bincode::deserialize::<M3Rec>(&bare_node_frame).expect("a bare node registers"),
        M3Rec::register_node(a(&[7]))
    );

    // A range mint's FIRST address re-enters through `Allocate`'s door and
    // the element-tier check this kind alone needs: a parentless first is
    // refused as `Allocate`'s is, and a T4-valid first at any level but the
    // element's — a range is minted on a content chain only — is refused
    // too; its COUNT is refused at zero, a range of nothing. The shapes just
    // inside each door decode: an element first with a count of one.
    for (what, first) in [
        ("a parentless first", t(&[7])),
        ("a node-tier first", t(&[1, 7])),
        ("an account-tier first", t(&[1, 0, 1])),
        ("a document-tier first", t(&[1, 0, 1, 0, 1])),
    ] {
        let frame = bincode::serialize(&RawM3Rec::AllocateRange {
            first,
            count: Nat::from(1u32),
        })
        .expect("serialize the raw shape");
        assert!(
            bincode::deserialize::<M3Rec>(&frame).is_err(),
            "{what} decoded into a range mint"
        );
    }
    let zero_count = bincode::serialize(&RawM3Rec::AllocateRange {
        first: t(&[1, 0, 1, 0, 1, 0, 1, 1]),
        count: Nat::from(0u32),
    })
    .expect("serialize the raw shape");
    assert!(
        bincode::deserialize::<M3Rec>(&zero_count).is_err(),
        "a range of nothing decoded into a record"
    );
    let one_element = bincode::serialize(&RawM3Rec::AllocateRange {
        first: t(&[1, 0, 1, 0, 1, 0, 1, 1]),
        count: Nat::from(1u32),
    })
    .expect("serialize the raw shape");
    assert_eq!(
        bincode::deserialize::<M3Rec>(&one_element).expect("an element first with a count of one decodes"),
        M3Rec::allocate_range(a(&[1, 0, 1, 0, 1, 0, 1, 1]), Nat::from(1u32))
    );
    // A link-chain element passes the element-tier check — the door asks the
    // tier, not the subspace, which M3's own mint never crosses.
    let link_element = bincode::serialize(&RawM3Rec::AllocateRange {
        first: t(&[1, 0, 1, 0, 1, 0, 2, 1]),
        count: Nat::from(2u32),
    })
    .expect("serialize the raw shape");
    assert!(bincode::deserialize::<M3Rec>(&link_element).is_ok());

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
        M3Rec::register_principal(a(&[1, 0, 1, 1]), ID2)
    );
    // A crate holding a decoded seat reads it through its payload's accessors
    // and has no way to write it: `Principal`'s fields are private, so the
    // account tier this door just checked stands for as long as the record
    // does, and a record pushed from here is one its own replay decodes (the
    // E0616 pair on `M3Rec` pins the write's refusal).
    let M3Rec::RegisterPrincipal(principal) =
        bincode::deserialize::<M3Rec>(&sub_account_frame).expect("a sub-account seat decodes")
    else {
        panic!("a RegisterPrincipal frame decodes into a RegisterPrincipal");
    };
    assert_eq!(
        (principal.prefix(), principal.id()),
        (&a(&[1, 0, 1, 1]), ID2)
    );

    // …and no door carries an op's CAP. `register_node` refuses a node past
    // MAX_NODE_COMPONENTS and `delegate` a prefix past
    // MAX_PRINCIPAL_COMPONENTS, at their gates and never off the journal: a
    // cap at a door would refuse a record M3 wrote before the cap existed,
    // and M2 halts on a frame that will not decode, so a board whose journal
    // held one could never open again — a resource charge turned into an
    // unreplayable journal. Each over-cap shape a door could be tempted to
    // refuse decodes.
    let over_cap_node: Vec<u32> = std::iter::repeat_n(1u32, MAX_NODE_COMPONENTS + 1).collect();
    let mut over_cap_acct = vec![1u32, 0];
    over_cap_acct.extend(std::iter::repeat_n(1u32, MAX_PRINCIPAL_COMPONENTS));
    for (raw, rec) in [
        (
            RawM3Rec::RegisterNode {
                addr: t(&over_cap_node),
            },
            M3Rec::register_node(a(&over_cap_node)),
        ),
        (
            RawM3Rec::Allocate {
                addr: t(&over_cap_acct),
                published: false,
            },
            M3Rec::allocate(a(&over_cap_acct), false),
        ),
        (
            RawM3Rec::RegisterPrincipal {
                prefix: t(&over_cap_acct),
                id: ID2,
            },
            M3Rec::register_principal(a(&over_cap_acct), ID2),
        ),
    ] {
        let frame = bincode::serialize(&raw).expect("serialize the raw shape");
        assert_eq!(
            bincode::deserialize::<M3Rec>(&frame).expect("an over-cap record decodes"),
            rec
        );
    }
}

/// `M3State`'s bytes are CANONICAL — "two slices holding the same entries
/// encode to one byte string on any process and any machine" — which is what
/// lets M2's checkpoint header commit to its body by hash, and a published
/// head name a checkpoint by hash. The crate's other pins on the slice's bytes
/// are genesis's (`genesis.rs`, and the publication suite's suffix), at two
/// entries per field, where a hash-ordered field would still match half the
/// time. So: eight or more entries in EVERY field, reached along two different
/// histories off two SEPARATELY built geneses — not one cloned, so a
/// hash-ordered field would carry two hashers — and the bytes compared whole.
#[test]
fn two_slices_holding_the_same_entries_encode_to_one_byte_string() {
    let accounts: Vec<Vec<u32>> = (1..=6).map(|i| vec![1, 0, i]).collect();
    let docs: Vec<Vec<u32>> = (1..=6).map(|i| vec![1, 0, i, 0, 1]).collect();
    let seat = |i: usize| M3Rec::register_principal(a(&accounts[i]), PrincipalId(10 + i as u64));
    let document = |i: usize| M3Rec::allocate(a(&docs[i]), i.is_multiple_of(2));
    let node = |n: u32| M3Rec::register_node(a(&[1, n]));

    // History X: account by account — its baptism, its seat, its document —
    // then the nodes 1.2..1.7 ascending.
    let mut x = M3State::genesis();
    for (i, acct) in accounts.iter().enumerate() {
        x = x
            .apply_m3(Seq(0), &alloc(acct))
            .apply_m3(Seq(0), &seat(i))
            .apply_m3(Seq(0), &document(i));
    }
    for n in 2..=7 {
        x = x.apply_m3(Seq(0), &node(n));
    }
    // History Y, off a SECOND genesis: the nodes first and descending, the
    // accounts (one chain, so in order), the documents in reverse — each is c₁
    // of its own chain — and the seats in reverse.
    let mut y = M3State::genesis();
    for n in (2..=7).rev() {
        y = y.apply_m3(Seq(0), &node(n));
    }
    for acct in &accounts {
        y = y.apply_m3(Seq(0), &alloc(acct));
    }
    for i in (0..accounts.len()).rev() {
        y = y.apply_m3(Seq(0), &document(i));
    }
    for i in (0..accounts.len()).rev() {
        y = y.apply_m3(Seq(0), &seat(i));
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
fn the_slice_prints_its_four_fields_and_their_contents() {
    // The slice a world embeds is reportable, so a test failure or a `dbg!` in
    // any engine can print it — the impl has to live here, since no downstream
    // crate may add it. Rendered from a POPULATED slice, so all four fields —
    // the three registries and the publication map — have contents to print
    // and not just names.
    let (k, _acct, _doc) = kernel_with_account_and_doc();
    let snap = k.snapshot();
    let rendered = format!("{:?}", snap.world().m3());
    for field in ["frontiers", "nodes", "principals", "publication"] {
        assert!(
            rendered.contains(field),
            "the rendering omits {field}: {rendered}"
        );
    }
    // The contents ride along: the bootstrap principal and the delegate.
    assert!(rendered.contains("PrincipalId(0)"), "{rendered}");
    assert!(rendered.contains("PrincipalId(1)"), "{rendered}");
    // NOT: comparing two renderings as an equality oracle. Every field
    // is an ORDERED collection since 2026-09-23 (`frontiers` moved off the
    // `im::HashMap` whose per-process `RandomState` once printed equal slices
    // in differing orders), so two equal slices now render alike — but the
    // rendering is a report, and `M3State`'s own `PartialEq` is the one that
    // compares by entries; it is what `journaled_types_survive_serde_round_trips`
    // asserts on.
}

#[test]
fn durable_kernel_recovers_the_whole_slice_by_checkpoint_and_replay() {
    // M3 rides M2 (§8): its slice — the three registries and the publication
    // map — is restored verbatim from the loaded checkpoint, then advanced by
    // replaying post-checkpoint M3Recs (default rebuild_derived — nothing to
    // re-seed). The publication map's own recovery, bit by bit, is pinned in
    // `the_bit_is_immutable_and_recovers_by_checkpoint_and_replay`.
    let dir = tempdir().expect("tempdir");
    let (acct, doc, live) = {
        let k = Kernel::open(fsync_config(dir.path()), genesis_world()).expect("open");
        let ns = Namespace::new(&k);
        let (acct, _) = ns
            .delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1]), ID1)
            .expect("delegate");
        // Checkpoint here: the delegation is restored FROM the checkpoint;
        // everything after rides post-checkpoint replay.
        k.checkpoint().expect("checkpoint");
        let (doc, _) = ns.create_new_document(ID1, &acct, None).expect("create");
        ns.register_node(t(&[1, 7])).expect("register node");
        let live = k.snapshot().world().m3().clone();
        (acct, doc, live)
    };
    let k2 = Kernel::open(fsync_config(dir.path()), genesis_world()).expect("reopen");
    let snap = k2.snapshot();
    let m3 = snap.world().m3();
    // What recovery claims, whole: the recovered slice IS the live one —
    // checkpoint-loaded registries plus post-checkpoint replay landing
    // exactly where it stood. The named answers below say which parts of
    // that a reader cares about.
    assert_eq!(m3, &live);
    assert_eq!(m3.principal_prefix(ID1), Some(&acct));
    assert!(m3.is_registered_document(&doc));
    assert_eq!(m3.entity_level(&a(&[1, 7])), Some(Level::Node));
    assert_eq!(m3.effective_owner(&doc), Some(ID1));
    // The frontiers recovered too: the chains continue where they left off.
    assert_eq!(m3.next_account_prefix(&a(&[1])), Some(a(&[1, 0, 2])));
    let (d2, _) = m3.mint_document(&acct, false).expect("mint after recovery");
    assert_eq!(d2, a(&[1, 0, 1, 0, 2]));
}
