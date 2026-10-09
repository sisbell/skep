//! §B create_new_document and fork: creation authorized by ω, the slot an
//! account's document chain opens at, and fork's reduction to a creation in
//! the caller's own account.

use crate::common::*;

use skep_namespace::{
    first_document_address, ghost_home_document, prefix_contains, system_account,
    CreateDocumentError, HasM3, MintError, Namespace, BOOTSTRAP_PRINCIPAL,
};

#[test]
fn create_new_document_authorizes_by_omega() {
    let k = mem_kernel(genesis_world());
    let ns = Namespace::new(&k);
    let (acct, _) = ns
        .delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1]), ID1)
        .expect("delegate");

    // Ordinary: the effective owner baptizes documents in chain order.
    let (d1, seq1) = ns.create_new_document(ID1, &acct, None).expect("create 1");
    let (d2, seq2) = ns.create_new_document(ID1, &acct, None).expect("create 2");
    assert_eq!(d1, a(&[1, 0, 1, 0, 1]));
    assert_eq!(d2, a(&[1, 0, 1, 0, 2]));
    assert!(seq2 > seq1);
    assert!(k.snapshot().world().m3().is_registered_document(&d1));

    // The ownership-divergence trap (O5): π₀'s prefix CONTAINS the account,
    // yet ω names ID1 — bare containment must not authorize.
    let before = k.current_seq();
    assert!(prefix_contains(&a(&[1]), &acct));
    assert_eq!(
        rejected(ns.create_new_document(BOOTSTRAP_PRINCIPAL, &acct, None)),
        CreateDocumentError::NotOwner
    );
    // An unknown caller is the effective owner of nothing.
    assert_eq!(
        rejected(ns.create_new_document(UNKNOWN_ID, &acct, None)),
        CreateDocumentError::NotOwner
    );
    // ω-auth is evaluated FIRST (§7): a non-owner of an unregistered
    // account gets NotOwner, while the owner (π₀ is ω of [1,0,2], which no
    // deeper seat covers) reaches the structural mint gate — NotAnAccount
    // covers unregistered and node-tier targets alike.
    assert_eq!(
        rejected(ns.create_new_document(ID1, &a(&[1, 0, 2]), None)),
        CreateDocumentError::NotOwner
    );
    assert_eq!(
        rejected(ns.create_new_document(BOOTSTRAP_PRINCIPAL, &a(&[1, 0, 2]), None)),
        CreateDocumentError::Mint(MintError::NotAnAccount)
    );
    assert_eq!(
        rejected(ns.create_new_document(BOOTSTRAP_PRINCIPAL, &a(&[1]), None)),
        CreateDocumentError::Mint(MintError::NotAnAccount)
    );
    // A refused creation baptizes nothing: no commit, and the account's
    // document chain still stands where d1 and d2 left it — the next
    // creation takes ordinal 3, so no refusal spent a slot.
    assert_eq!(k.current_seq(), before);
    let (d3, _) = ns.create_new_document(ID1, &acct, None).expect("create 3");
    assert_eq!(d3, a(&[1, 0, 1, 0, 3]));
}

#[test]
fn the_first_document_address_is_the_slot_the_document_chain_opens_at() {
    // §1: the chain's opening ordinal is M3's, so M3 names the address rather
    // than leaving callers to rebuild `A·0·1`. The slot is nameable before
    // anything occupies it, and the account's FIRST creation lands on it.
    let k = mem_kernel(genesis_world());
    let ns = Namespace::new(&k);
    let (acct, _) = ns
        .delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1]), ID1)
        .expect("delegate");
    let slot = first_document_address(&acct).expect("an account anchors a document chain");
    assert_eq!(slot, a(&[1, 0, 1, 0, 1]));
    let before_create = k.snapshot().world().m3().clone();
    assert!(!before_create.is_allocated(&slot)); // the slot, not a claim
    assert!(!before_create.has_documents(&acct)); // …and the chain it opens is empty
    let (d1, _) = ns.create_new_document(ID1, &acct, None).expect("create 1");
    assert_eq!(d1, slot);
    // The slot against the registry, and the chain against its frontier —
    // two reads, one question, answered in both directions: the slot was
    // unallocated above and is a registered document now, and the chain that
    // was empty holds one.
    let m3 = k.snapshot().world().m3().clone();
    assert!(m3.is_registered_document(&slot));
    assert!(m3.has_documents(&acct));
    let (d2, _) = ns.create_new_document(ID1, &acct, None).expect("create 2");
    assert_ne!(d2, slot);
    // The ghost home document is that rule applied to the system account
    // genesis seeds — so the compiled literal and the chain rule agree.
    assert_eq!(
        first_document_address(&system_account()),
        Some(ghost_home_document())
    );
    // Only an account anchors a document chain, so off the account tier
    // there is no slot and no documents; an unregistered account's chain is
    // empty too.
    let m3 = k.snapshot().world().m3().clone();
    for no_chain in [&a(&[1]), &d1, &a(&[1, 0, 1, 0, 1, 0, 1, 1])] {
        assert!(first_document_address(no_chain).is_none(), "{no_chain:?}");
        assert!(!m3.has_documents(no_chain), "{no_chain:?}");
    }
    assert!(!m3.has_documents(&a(&[1, 0, 9])));
}

// ---- §B fork ----

#[test]
fn fork_mints_in_the_callers_own_account_at_its_own_commit() {
    let k = mem_kernel(genesis_world());
    let ns = Namespace::new(&k);
    let (acct, _) = ns
        .delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1]), ID1)
        .expect("delegate");

    // O10, account-tier: reduces to create_new_document(caller,
    // pfx(caller)) — a fresh self-owned document one tier below the prefix…
    let before = k.current_seq();
    let (d1, seq) = ns.fork(ID1, None).expect("fork");
    assert_eq!(d1, a(&[1, 0, 1, 0, 1]));
    // …acknowledged at its OWN commit (commit-before-acknowledge): the
    // coordinate `fork` answers is the one create_new_document committed it
    // at, never the snapshot it read the caller's account off — the
    // coordinate before it.
    assert!(seq > before, "fork answered {seq:?}, not past {before:?}");
    assert_eq!(k.current_seq(), seq);
    assert!(prefix_contains(&acct, &d1));
    let snap = k.snapshot();
    assert!(snap.world().m3().is_registered_document(&d1));
    assert!(snap.world().m3().is_effective_owner(ID1, &d1));
    // Shares the (account, 2) chain with create_new_document.
    let (d2, _) = ns.create_new_document(ID1, &acct, None).expect("create");
    assert_eq!(d2, a(&[1, 0, 1, 0, 2]));
}

#[test]
fn fork_resolves_its_flag_as_create_new_document_does() {
    let k = mem_kernel(genesis_world());
    let ns = Namespace::new(&k);
    let (acct, _) = ns
        .delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1]), ID1)
        .expect("delegate");

    // The flag rides the reduction to create_new_document (PUB-8.16; owner
    // 2026-09-05, one rule in one place): a flagless fork into the EMPTY
    // account is the born-published doc 1 (PUB-8.21)…
    let (d1, _) = ns.fork(ID1, None).expect("fork");
    assert!(
        k.snapshot().world().m3().published(&d1),
        "the flagless first fork is doc 1, born published"
    );
    // The account's second document, created on the chain fork mints on.
    ns.create_new_document(ID1, &acct, None).expect("create");
    // …a flagless fork into the NON-empty account is private, and an
    // explicit flag is honored as sent.
    let (d3, _) = ns.fork(ID1, None).expect("a later fork");
    assert_eq!(d3, a(&[1, 0, 1, 0, 3]));
    let (d4, _) = ns.fork(ID1, Some(true)).expect("an explicit-true fork");
    let (d5, _) = ns.fork(ID1, Some(false)).expect("an explicit-false fork");
    let m3 = k.snapshot().world().m3().clone();
    assert!(
        !m3.published(&d3),
        "a flagless non-first fork is private (PUB-1.1)"
    );
    assert!(m3.published(&d4));
    assert!(!m3.published(&d5));
}

#[test]
fn fork_refuses_an_unknown_id_and_a_node_tier_caller() {
    // Bare genesis holds both shapes: no principal carries UNKNOWN_ID, and
    // π₀'s own prefix is the node [1].
    let k = mem_kernel(genesis_world());
    let ns = Namespace::new(&k);

    // Unknown id: typed NotOwner (an unregistered caller owns nothing).
    assert_eq!(
        rejected(ns.fork(UNKNOWN_ID, None)),
        CreateDocumentError::NotOwner
    );
    // Node-tier caller (π₀ at [1]): the node-tier O10 case is DROPPED —
    // typed Mint(NotAnAccount), never a silent skip (Conflicts §6).
    assert_eq!(
        rejected(ns.fork(BOOTSTRAP_PRINCIPAL, None)),
        CreateDocumentError::Mint(MintError::NotAnAccount)
    );
}
