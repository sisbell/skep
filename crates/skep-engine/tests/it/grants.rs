//! The grant fold and the read predicate (PUB round 2, lane 3.3, §1), through
//! the assembled engine: a grant is an ordinary link the fold recognizes as a
//! VALUE, seeded at load and folded on every deposit; `World::readable` is the
//! one predicate every read surface answers through. Store semantics are not
//! re-tested here — what is tested is the ASSEMBLY: the fold, its admission,
//! its supersession, its re-seed across a restart, and the three clauses of
//! the predicate.

use crate::common;

use common::*;
use skep_arrangement::Caller;
use skep_engine::{Engine, World};
use skep_links::{HasLinks, ShippedType, SlotArg};
use skep_namespace::{HasM3, PrincipalId, BOOTSTRAP_PRINCIPAL};
use tempfile::tempdir;

/// The GRANTS class type address (COMMONS DECISION 5 — 1.1.0.1.0.1.0.3.90).
/// Hardcoded here as a client would name it; the engine constant is crate
/// private.
fn t_grant() -> skep_address::Address {
    addr(&[1, 1, 0, 1, 0, 1, 0, 3, 90])
}

struct Board {
    acct_a: skep_address::Address,
    home_a: skep_address::Address,
    draft_a: skep_address::Address,
    acct_b: skep_address::Address,
    b: PrincipalId,
}

/// Two accounts under the genesis node: A (principal 1) with a published home
/// (its flagless first mint, PUB-8.21) and a private draft (its second), and B
/// (principal 2), a stranger to A's subtree.
fn two_accounts(engine: &Engine) -> Board {
    let ns = engine.namespace();
    let node = node1();
    let pa = engine
        .kernel()
        .snapshot()
        .world()
        .m3()
        .next_account_prefix(&node)
        .expect("prefix A");
    let (acct_a, _) = ns
        .delegate(BOOTSTRAP_PRINCIPAL, pa.tumbler().clone(), PrincipalId(1))
        .expect("delegate A");
    let (home_a, _) =
        ns.create_new_document(PrincipalId(1), &acct_a, None).expect("A's published home");
    let (draft_a, _) =
        ns.create_new_document(PrincipalId(1), &acct_a, None).expect("A's private draft");
    let pb = engine
        .kernel()
        .snapshot()
        .world()
        .m3()
        .next_account_prefix(&node)
        .expect("prefix B");
    let (acct_b, _) = ns
        .delegate(BOOTSTRAP_PRINCIPAL, pb.tumbler().clone(), PrincipalId(2))
        .expect("delegate B");
    Board { acct_a, home_a, draft_a, acct_b, b: PrincipalId(2) }
}

/// Deposit a grant-typed link, as A, in one of A's documents: `ty` = T_grant,
/// `from` = the content-prefix, `to` = the grantee (empty ⟹ ANY-PRINCIPAL).
/// Returns the link's address. Whether the record is ADMITTED is the fold's
/// verdict, not the deposit's — the residence test below leans on that.
fn grant(
    engine: &Engine,
    home: &skep_address::Address,
    from: &skep_address::Address,
    to: Vec<skep_address::Address>,
) -> skep_address::Address {
    let issuer = Caller::Principal(PrincipalId(1));
    match engine.linkstore(&World::visible_to(issuer)).makelink(
        issuer,
        home,
        SlotArg::Addrs(vec![from.clone()]),
        SlotArg::Addrs(to),
        SlotArg::Addrs(vec![t_grant()]),
    ) {
        Ok((addr, _)) => addr,
        Err(_) => panic!("the grant link deposits into A's own document"),
    }
}

fn world(engine: &Engine) -> World {
    engine.kernel().snapshot().world().clone()
}

/// A specific grant makes A's private draft readable to the grantee B and to
/// nobody else: not the guest, not a stranger — while A itself reads it by the
/// subtree clause and its published home is readable by all.
#[test]
fn a_specific_grant_opens_a_draft_to_its_grantee_alone() {
    let engine = mem_engine();
    let b = two_accounts(&engine);

    // Before the grant: only A (subtree) reads the draft.
    let w = world(&engine);
    assert!(w.readable(Some(PrincipalId(1)), &b.draft_a), "A reads its own draft (subtree)");
    assert!(!w.readable(Some(b.b), &b.draft_a), "B cannot read it yet");
    assert!(!w.readable(None, &b.draft_a), "the guest cannot");
    assert!(w.readable(None, &b.home_a), "the published home is readable by all");

    // Grant the draft to B's account.
    grant(&engine, &b.home_a, &b.draft_a, vec![b.acct_b.clone()]);
    let w = world(&engine);
    assert!(w.readable(Some(b.b), &b.draft_a), "B now reads the granted draft");
    assert!(!w.readable(None, &b.draft_a), "the guest still cannot — a grant is to a principal");
    assert!(
        !w.readable(Some(PrincipalId(3)), &b.draft_a),
        "an ungranted principal cannot (grantee is PRINCIPAL-EXACT)"
    );
}

/// The ANY-PRINCIPAL form (empty `to`, PUB-5.8): readable by every bound
/// principal, still not by the guest.
#[test]
fn an_any_principal_grant_opens_a_draft_to_every_principal_but_not_the_guest() {
    let engine = mem_engine();
    let b = two_accounts(&engine);
    grant(&engine, &b.home_a, &b.draft_a, vec![]); // empty `to` ⟹ ANY-PRINCIPAL
    let w = world(&engine);
    assert!(w.readable(Some(b.b), &b.draft_a), "B, a principal, reads it");
    assert!(w.readable(Some(PrincipalId(9)), &b.draft_a), "any principal reads it");
    assert!(!w.readable(None, &b.draft_a), "the guest does not — ANY-PRINCIPAL excludes the guest");
}

/// The ACCOUNT rung (PUB-5.9, PUB-1.100): a grant whose content-prefix is A's
/// account covers every document under it by containment — the draft that
/// exists and the one A mints afterwards (forward-inclusive) — for the grantee
/// alone; the guest and an ungranted principal read neither.
#[test]
fn an_account_rung_grant_covers_the_account_s_documents_forward_inclusively() {
    let engine = mem_engine();
    let b = two_accounts(&engine);
    grant(&engine, &b.home_a, &b.acct_a, vec![b.acct_b.clone()]);
    let (later, _) = engine
        .namespace()
        .create_new_document(PrincipalId(1), &b.acct_a, None)
        .expect("A's later draft");

    let w = world(&engine);
    assert!(w.readable(Some(b.b), &b.draft_a), "B reads the draft under the granted account");
    assert!(w.readable(Some(b.b), &later), "…and the draft minted after the grant");
    assert!(!w.readable(None, &later), "the guest still cannot");
    assert!(!w.readable(Some(PrincipalId(3)), &later), "nor an ungranted principal");
}

/// The SUBTREE clause runs DOWNWARD only (H1, PUB-1.32): a sub-account
/// delegated under A reads A's draft (its prefix lies inside A's account);
/// the org root — principal 0, seated at node [1], ABOVE every account —
/// reads no draft by subtree; and the org's members are siblings, so B reads
/// nothing of A's.
#[test]
fn the_subtree_clause_runs_downward_only() {
    let engine = mem_engine();
    let b = two_accounts(&engine);
    // A sub-account of A, delegated by A (the owner of A's prefix).
    let sub_prefix = engine
        .kernel()
        .snapshot()
        .world()
        .m3()
        .next_account_prefix(&b.acct_a)
        .expect("A's next sub-account prefix");
    let (sub, _) = engine
        .namespace()
        .delegate(PrincipalId(1), sub_prefix.tumbler().clone(), PrincipalId(11))
        .expect("A delegates a sub-account");
    let (sub_draft, _) = engine
        .namespace()
        .create_new_document(PrincipalId(11), &sub, Some(false))
        .expect("the sub-account's own private draft");

    let w = world(&engine);
    assert!(w.readable(Some(PrincipalId(11)), &b.draft_a), "A's sub-account reads A's draft");
    assert!(
        !w.readable(Some(PrincipalId(1)), &sub_draft),
        "A does NOT read its sub-account's draft — the subtree runs downward, never up"
    );
    assert!(
        !w.readable(Some(BOOTSTRAP_PRINCIPAL), &b.draft_a),
        "the org root (principal 0 at node [1]) reads no draft by subtree"
    );
    assert!(!w.readable(Some(b.b), &b.draft_a), "a sibling account reads nothing of A's");
    assert!(w.readable(Some(BOOTSTRAP_PRINCIPAL), &b.home_a), "…but everyone reads the published home");
}

/// The grantee is PRINCIPAL-EXACT (H1, PUB-5.8): a grant to B's account
/// opens the draft to B and not to a sub-account B delegates — the grant does
/// not run down B's subtree the way ownership does.
#[test]
fn a_grant_to_an_account_excludes_its_sub_accounts() {
    let engine = mem_engine();
    let b = two_accounts(&engine);
    let sub_prefix = engine
        .kernel()
        .snapshot()
        .world()
        .m3()
        .next_account_prefix(&b.acct_b)
        .expect("B's next sub-account prefix");
    engine
        .namespace()
        .delegate(b.b, sub_prefix.tumbler().clone(), PrincipalId(12))
        .expect("B delegates a sub-account");
    grant(&engine, &b.home_a, &b.draft_a, vec![b.acct_b.clone()]);
    let w = world(&engine);
    assert!(w.readable(Some(b.b), &b.draft_a), "the grantee reads");
    assert!(
        !w.readable(Some(PrincipalId(12)), &b.draft_a),
        "the grantee's sub-account does not — grantee-exact"
    );
}

/// The residence pin (PUB-5.17) and the class law (PUB-5.2): a grant record is
/// a fold input only when homed in the issuer's OWN doc 1, published. The same
/// record deposited in A's draft (a private home) or in a published edition of
/// A's that is not doc 1 opens nothing; deposited in doc 1 it admits.
#[test]
fn a_grant_homed_anywhere_but_the_issuer_s_published_doc_1_is_inert() {
    let engine = mem_engine();
    let b = two_accounts(&engine);

    // In the draft itself — a private home entitles nowhere.
    grant(&engine, &b.draft_a, &b.draft_a, vec![b.acct_b.clone()]);
    assert!(!world(&engine).readable(Some(b.b), &b.draft_a), "a draft-homed grant is inert");

    // In a published edition of A's that is not the account's doc 1.
    let (edition, _) = engine
        .namespace()
        .create_new_document(PrincipalId(1), &b.acct_a, Some(true))
        .expect("A's published edition");
    grant(&engine, &edition, &b.draft_a, vec![b.acct_b.clone()]);
    assert!(
        !world(&engine).readable(Some(b.b), &b.draft_a),
        "a grant homed outside doc 1 is inert to the fold"
    );

    // In doc 1: the one home the class law names.
    grant(&engine, &b.home_a, &b.draft_a, vec![b.acct_b.clone()]);
    assert!(world(&engine).readable(Some(b.b), &b.draft_a), "the doc-1 record admits");
}

/// A grant issued by an account that is NOT the draft's owner cannot open it
/// (coverage's issuer clause, PUB-5.19): B, granting A's draft to itself from
/// B's own home, opens nothing.
#[test]
fn a_grant_from_a_non_owner_opens_nothing() {
    let engine = mem_engine();
    let b = two_accounts(&engine);
    // B's own published home.
    let (home_b, _) = engine
        .namespace()
        .create_new_document(b.b, &b.acct_b, None)
        .expect("B's published home");
    // B tries to grant A's draft to itself, from B's home.
    match engine.linkstore(&World::visible_to(Caller::Principal(b.b))).makelink(
        Caller::Principal(b.b),
        &home_b,
        SlotArg::Addrs(vec![b.draft_a.clone()]),
        SlotArg::Addrs(vec![b.acct_b.clone()]),
        SlotArg::Addrs(vec![t_grant()]),
    ) {
        Ok(_) => {}
        Err(_) => panic!("the deposit itself succeeds — coverage is a READ-time verdict"),
    }
    let w = world(&engine);
    assert!(
        !w.readable(Some(b.b), &b.draft_a),
        "the grant's issuer (B) is not the draft's ω owner (A), so it opens nothing"
    );
}

/// Revocation by supersession (PUB-5.13): a later admitted grant naming the
/// earlier grant's own link address in `from` removes it.
#[test]
fn a_superseding_record_revokes_the_grant_it_names() {
    let engine = mem_engine();
    let b = two_accounts(&engine);
    let g = grant(&engine, &b.home_a, &b.draft_a, vec![b.acct_b.clone()]);
    assert!(world(&engine).readable(Some(b.b), &b.draft_a), "granted");

    // A revoking record: `from` names the grant link itself.
    grant(&engine, &b.home_a, &g, vec![b.acct_b.clone()]);
    assert!(
        !world(&engine).readable(Some(b.b), &b.draft_a),
        "the superseding record revoked the grant"
    );
}

/// RETRACTION IS NOT REVOCATION (PUB-5.13): the fold has no nullification
/// arm, so a grant whose link a later `nullify` retracted still opens what it
/// granted, and only a superseding grant record takes it back. That is the
/// premise the seed's AUDIT view rests on — an active-view walk would drop
/// exactly this grant, and the recovered fold would differ from the live one
/// — so the check is the fold's own agreement with its seed, through the
/// dump's grant section.
#[test]
fn a_nullified_grant_still_opens_its_draft_and_the_audit_view_seed_agrees() {
    let engine = mem_engine();
    let b = two_accounts(&engine);
    let g = grant(&engine, &b.home_a, &b.draft_a, vec![b.acct_b.clone()]);
    assert!(world(&engine).readable(Some(b.b), &b.draft_a), "granted");

    let issuer = Caller::Principal(PrincipalId(1));
    engine
        .linkstore(&World::visible_to(issuer))
        .nullify(issuer, &b.home_a, &g)
        .unwrap_or_else(|_| panic!("the issuer retracts its own grant link"));

    let w = world(&engine);
    assert!(w.links().is_nullified(&g), "the fixture must retract the grant link");
    assert!(
        w.readable(Some(b.b), &b.draft_a),
        "a retracted grant link is still an admitted grant — revocation is by supersession"
    );
    engine
        .check_hints()
        .expect("the audit-view seed reproduces the fold over a nullified grant");
}

/// A supersession CLAIM over a grant is lineage display, never a fold input:
/// revocation is a later admitted `t_grant` record naming the earlier one,
/// and nothing else. It is also where the two halves see different RECORDS —
/// the fold sees every link deposit, the seed walks the grants class alone —
/// so a fold that honoured the claim would part from its seed at the next
/// restart rather than at the deposit.
#[test]
fn a_supersession_claim_over_a_grant_revokes_nothing_and_the_seed_agrees() {
    let engine = mem_engine();
    let b = two_accounts(&engine);
    let old = grant(&engine, &b.home_a, &b.draft_a, vec![b.acct_b.clone()]);
    let new = grant(&engine, &b.home_a, &b.acct_a, vec![b.acct_b.clone()]);

    let issuer = Caller::Principal(PrincipalId(1));
    engine
        .linkstore(&World::visible_to(issuer))
        .assert_sup(issuer, &b.home_a, &old, &new)
        .unwrap_or_else(|_| panic!("the issuer claims its second grant supersedes its first"));

    let w = world(&engine);
    let sup = w.links().reserved_type(ShippedType::Supersedes);
    assert_eq!(
        w.links().succs(sup, &old),
        vec![new.clone()],
        "the fixture must deposit an operative supersession claim over the grant"
    );
    assert_eq!(
        w.issuers_for(&b.acct_b),
        vec![(b.acct_a.clone(), vec![b.acct_a.clone(), b.draft_a.clone()])],
        "both grants stand: a [K_sup] claim is not the fold's revocation"
    );
    engine.check_hints().expect("the seed, which never sees the claim, reproduces the fold");
}

/// The fold re-seeds across a restart (PUB-7.7 seed half): a checkpoint holding
/// a grant, reopened, still opens the draft to the grantee — and the empty-map
/// world grants nothing (PUB-7.68).
#[test]
fn the_fold_re_seeds_across_a_restart_and_an_empty_map_grants_nothing() {
    let dir = tempdir().expect("tempdir");
    let (draft_a, b_id, acct_b) = {
        let engine = Engine::open(fsync_cfg(dir.path())).expect("fsync open");
        // Empty-map witness: genesis holds no grants, so no private document is
        // readable by anyone but its owner subtree (there are none yet).
        let board = two_accounts(&engine);
        grant(&engine, &board.home_a, &board.draft_a, vec![board.acct_b.clone()]);
        engine.kernel().checkpoint().expect("checkpoint at head");
        assert!(world(&engine).readable(Some(board.b), &board.draft_a), "live: B reads it");
        (board.draft_a, board.b, board.acct_b)
    };

    // Reopen: the seed re-derives the fold from the link map.
    let engine = Engine::open(fsync_cfg(dir.path())).expect("reopen over the checkpoint");
    let w = world(&engine);
    assert!(w.readable(Some(b_id), &draft_a), "the recovered fold still opens the draft to B");
    let _ = acct_b;

    // Empty-map: a fresh engine's fold is empty — a private draft is readable
    // only by its owner subtree, never by a grant that does not exist.
    let fresh = mem_engine();
    let board = two_accounts(&fresh);
    assert!(
        !world(&fresh).readable(Some(board.b), &board.draft_a),
        "an empty fold grants nothing (PUB-7.68)"
    );
}

/// The fold's two enumerations for the feed (lane 3.6 §3; PUB-7.22,
/// PUB-7.28): the LIVE ANY-PRINCIPAL set and a grantee's issuers with the
/// union of covered prefixes — both read off the fold's own indexes, both
/// agreeing with the predicate they are the inside-out of, and both moving
/// with a superseding record at once (revocation is immediate, PUB-7.23).
#[test]
fn the_two_feed_enumerations_read_the_fold_s_live_state() {
    let engine = mem_engine();
    let b = two_accounts(&engine);
    let (draft_two, _) = engine
        .namespace()
        .create_new_document(PrincipalId(1), &b.acct_a, None)
        .expect("A's second draft");

    // Empty fold: nothing enumerates.
    let w = world(&engine);
    assert!(w.universal_grants().is_empty(), "no universal grant yet");
    assert!(w.issuers_for(&b.acct_b).is_empty(), "B holds no grant yet");

    // Two grants to B from A — the draft and the whole account — and one
    // ANY-PRINCIPAL grant of the second draft.
    grant(&engine, &b.home_a, &b.draft_a, vec![b.acct_b.clone()]);
    grant(&engine, &b.home_a, &b.acct_a, vec![b.acct_b.clone()]);
    let g_any = grant(&engine, &b.home_a, &draft_two, vec![]);

    let w = world(&engine);
    assert_eq!(
        w.issuers_for(&b.acct_b),
        vec![(b.acct_a.clone(), vec![b.acct_a.clone(), b.draft_a.clone()])],
        "B's one issuer is A, with the UNION of A's prefixes to B in address order"
    );
    assert!(
        w.issuers_for(&b.acct_a).is_empty(),
        "the grantee side is principal-exact: A itself holds no grant"
    );
    assert_eq!(
        w.universal_grants(),
        vec![(draft_two.clone(), vec![b.acct_a.clone()])],
        "the live any-principal set lists the second draft under its issuer"
    );
    // The enumerations are the predicate turned inside out.
    assert!(w.readable(Some(b.b), &b.draft_a));
    assert!(w.readable(Some(PrincipalId(9)), &draft_two), "any principal reads draft two");
    assert!(!w.readable(None, &draft_two), "the guest never does");

    // A superseding record leaves the enumeration at the commit that carries
    // it — no restart, no lag.
    grant(&engine, &b.home_a, &g_any, vec![]);
    let w = world(&engine);
    assert!(w.universal_grants().is_empty(), "the revoked universal grant is gone at once");
    assert!(!w.readable(Some(PrincipalId(9)), &draft_two), "and the predicate agrees");
    assert_eq!(w.issuers_for(&b.acct_b).len(), 1, "B's grants are untouched by it");
}
