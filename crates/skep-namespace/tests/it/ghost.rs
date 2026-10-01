//! The ghost region (owner ruling, 2026-08-26): it has exactly five names, and
//! the one chain that could issue a ghost tumbler never does.

use crate::common::*;

use skep_namespace::{
    ghost_home_document, ghost_position, system_account, HasM3, M3State, Namespace,
    GHOST_POSITIONS, SYSTEM_PRINCIPAL,
};

/// The region has exactly [`GHOST_POSITIONS`] names, and this assert is what
/// says so: one ordinal past it is an ORDINARILY MINTABLE content address of
/// a real document — the allocator floors five and no more — so a caller
/// holding a sixth "reserved" address would dispatch on a number the mint can
/// also issue. The `# Panics` clause, made executable.
#[test]
#[should_panic(expected = "the ghost region is content addresses")]
fn ghost_position_refuses_the_ordinal_past_the_region() {
    let _ = ghost_position(GHOST_POSITIONS + 1);
}

/// The other end: a chain opens at ordinal 1, so there is no ordinal 0 to
/// reserve. Without the assert this still panics — but inside M1's element
/// lift, naming the wrong contract to the crate that reads these five.
#[test]
#[should_panic(expected = "the ghost region is content addresses")]
fn ghost_position_refuses_the_ordinal_below_the_region() {
    let _ = ghost_position(0);
}

/// The non-reissue guarantee, driven through the real ops — the load-bearing
/// clause of the ghost-tumbler ruling: dispatch is by number, so the
/// allocator must provably never issue any of the five reserved values. The
/// ghost region IS reachable territory — the ghost home document is REAL:
/// genesis seeds the system node 1.1, the system account 1.1.0.1 and its
/// doc 1 (PUB-6.65) at exactly the addresses a claim ceremony at that node
/// would reach — admitting the node, delegating its operator's account,
/// minting that account's doc 1 — which is exactly why the floor exists; this
/// drives the one chain that could issue a ghost tumbler from genesis to well
/// past the region and watches every answer.
#[test]
fn the_content_chain_of_the_ghost_home_document_never_issues_a_ghost_tumbler() {
    let k = mem_kernel(genesis_world());
    let ns = Namespace::new(&k);

    // The lineage is seeded and its document is EMPTY: nothing exists at a
    // ghost tumbler at genesis.
    let d1 = ghost_home_document();
    {
        let snap = k.snapshot();
        let m3 = snap.world().m3();
        assert!(
            m3.is_registered_account(&system_account()),
            "the seed seats the system account"
        );
        assert!(
            m3.is_registered_document(&d1),
            "the seed registers the ghost home document at its ordinary ordinal"
        );
        for ordinal in 1..=GHOST_POSITIONS {
            assert!(
                !m3.is_allocated(&ghost_position(ordinal)),
                "ghost {ordinal} allocated at genesis"
            );
        }
    }

    // Drive the one namespace whose chain contains the five ghost tumblers:
    // every mint lands PAST the region, contiguously from GHOST_POSITIONS + 1.
    for ordinal in GHOST_POSITIONS + 1..=GHOST_POSITIONS + 7 {
        let minted = commit_mint(&k, M3State::content_lock_key(&d1), |m3| {
            m3.mint_content(&d1)
        });
        assert_eq!(
            minted,
            a(&[1, 1, 0, 1, 0, 1, 0, 1, ordinal]),
            "the ghost home document's content chain must start past the region and stay contiguous"
        );
    }

    // The exclusion is permanent, not merely initial: with the stored
    // frontier far past the region, the five still answer unallocated, while
    // the content address at GHOST_POSITIONS + 1 is an ordinary member.
    let snap = k.snapshot();
    let m3 = snap.world().m3();
    for ordinal in 1..=GHOST_POSITIONS {
        assert!(
            !m3.is_allocated(&ghost_position(ordinal)),
            "ghost {ordinal} became a chain member"
        );
    }
    assert!(m3.is_allocated(&a(&[1, 1, 0, 1, 0, 1, 0, 1, GHOST_POSITIONS + 1])));

    // The sibling chains under the same lineage produce their own members,
    // never a ghost tumbler — the T4b unique-parse half of the argument, at
    // the chains an attacker would actually drive: the link chain differs in
    // subspace, the version chain in tier shape.
    let link = commit_mint(&k, M3State::link_lock_key(&d1), |m3| m3.mint_link(&d1));
    assert_eq!(link, a(&[1, 1, 0, 1, 0, 1, 0, 2, 1]));
    let version = commit_mint(&k, M3State::version_lock_key(&d1), |m3| {
        m3.mint_version(&d1, false)
    });
    assert_eq!(version, a(&[1, 1, 0, 1, 0, 1, 1]));

    // ANOTHER document under the account carries no floor: its content chain
    // starts at 1 like any other — the region is five content addresses of
    // one document, not a rule about the prefix. Doc 2 is the seeded `H`, so
    // the account's next mint (as its own principal, the system's) is doc 3.
    let (d3, _) = ns
        .create_new_document(SYSTEM_PRINCIPAL, &system_account(), None)
        .expect("doc 3");
    assert_eq!(d3, a(&[1, 1, 0, 1, 0, 3]));
    let first = commit_mint(&k, M3State::content_lock_key(&d3), |m3| {
        m3.mint_content(&d3)
    });
    assert_eq!(first, a(&[1, 1, 0, 1, 0, 3, 0, 1, 1]));
}

/// The floored frontier is ordinary recoverable state: a slice that minted
/// past the ghost region round-trips M2's checkpoint encoding, and the
/// restored slice keeps both halves — members stay members, ghosts stay
/// excluded. The frontier key's anchor is the ghost home document's content
/// base, which must pass `NsKey`'s T4 anchor door like any other key.
#[test]
fn a_floored_frontier_survives_the_checkpoint_round_trip() {
    let k = mem_kernel(genesis_world());
    // The ghost home document is genesis's (PUB-6.65's seed), born empty: the
    // first mint on its chain is what floors the frontier.
    let d1 = ghost_home_document();
    commit_mint(&k, M3State::content_lock_key(&d1), |m3| {
        m3.mint_content(&d1)
    });

    let live = k.snapshot().world().m3().clone();
    let bytes = bincode::serialize(&live).expect("checkpoint-encode the slice");
    let restored: M3State = bincode::deserialize(&bytes).expect("the slice re-enters");
    assert_eq!(restored, live);
    for ordinal in 1..=GHOST_POSITIONS {
        assert!(!restored.is_allocated(&ghost_position(ordinal)));
    }
    assert!(restored.is_allocated(&a(&[1, 1, 0, 1, 0, 1, 0, 1, GHOST_POSITIONS + 1])));
    let (next, _) = restored.mint_content(&d1).expect("the chain continues");
    assert_eq!(next, a(&[1, 1, 0, 1, 0, 1, 0, 1, GHOST_POSITIONS + 2]));
}

/// A ghost-ordinal `Allocate` is OUTSIDE the fold's totality domain — the
/// contiguity fail-stop reads the effective frontier, so a record claiming a
/// ghost tumbler is corruption caught at the fold, not an ordinal silently
/// absorbed into membership.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "effective frontier")]
fn the_fold_fail_stops_on_an_allocate_inside_the_ghost_region() {
    M3State::genesis().apply_m3(&alloc(&[1, 1, 0, 1, 0, 1, 0, 1, 1]));
}
