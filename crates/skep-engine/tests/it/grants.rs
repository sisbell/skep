//! The grant fold and the read predicate (PUB round 2, lane 3.3, §1), through
//! the assembled engine: a grant is an ordinary link the fold recognizes as a
//! VALUE, seeded at load and folded on every deposit; `World::readable` is the
//! one predicate every read surface answers through. Store semantics are not
//! re-tested here — what is tested is the ASSEMBLY: the fold, its admission,
//! its supersession, its re-seed across a restart, and the three clauses of
//! the predicate.

use crate::common;

use common::*;
use skep_address::{validate, Level, Tumbler};
use skep_arrangement::{trunk_of, Caller};
use skep_engine::{Engine, IssuerGrant, UniversalGrant, World};
use skep_links::{HasLinks, ShippedType, SlotArg};
use skep_namespace::{first_document_address, HasM3, PrincipalId, BOOTSTRAP_PRINCIPAL};
use tempfile::tempdir;

/// The GRANTS class type address (COMMONS DECISION 5 — 1.1.0.1.0.1.0.3.90).
/// Hardcoded here as a client would name it; the engine constant is crate
/// private.
fn t_grant() -> skep_address::Address {
    addr(&[1, 1, 0, 1, 0, 1, 0, 3, 90])
}

/// The EDITION class — `1.1.0.1.0.1.0.3.14`, a commons type OUTSIDE the
/// grants class. For the record that names the grants class among others.
fn t_edition() -> skep_address::Address {
    addr(&[1, 1, 0, 1, 0, 1, 0, 3, 14])
}

/// A SUBTYPE beneath the grants class — `1.1.0.1.0.1.0.3.90.1`. The daemon's
/// write path recognizes a class's subtypes BY PREFIX; the fold recognizes
/// its class by the ADDRESS. The two rules differ on purpose, and this is the
/// address that tells them apart.
fn t_grant_subtype() -> skep_address::Address {
    addr(&[1, 1, 0, 1, 0, 1, 0, 3, 90, 1])
}

/// The ISSUER: owner of the published home every grant below is deposited
/// in, and of the private draft those grants open.
const A: PrincipalId = PrincipalId(1);

/// The GRANTEE: a stranger to A's subtree until A grants it something.
const B: PrincipalId = PrincipalId(2);

struct Board {
    acct_a: skep_address::Address,
    home_a: skep_address::Address,
    draft_a: skep_address::Address,
    acct_b: skep_address::Address,
}

/// Two accounts under the genesis node: [`A`] with a published home (its
/// flagless first mint, PUB-8.21) and a private draft (its second), and
/// [`B`], a stranger to A's subtree.
fn two_accounts(engine: &Engine) -> Board {
    let ns = engine.namespace();
    let node = node1();
    let prefix_a = engine
        .kernel()
        .snapshot()
        .world()
        .m3()
        .next_account_prefix(&node)
        .expect("prefix A");
    let (acct_a, _) = ns
        .delegate(BOOTSTRAP_PRINCIPAL, prefix_a.tumbler().clone(), A)
        .expect("delegate A");
    let (home_a, _) =
        ns.create_new_document(A, &acct_a, None).expect("A's published home");
    let (draft_a, _) =
        ns.create_new_document(A, &acct_a, None).expect("A's private draft");
    let prefix_b = engine
        .kernel()
        .snapshot()
        .world()
        .m3()
        .next_account_prefix(&node)
        .expect("prefix B");
    let (acct_b, _) = ns
        .delegate(BOOTSTRAP_PRINCIPAL, prefix_b.tumbler().clone(), B)
        .expect("delegate B");
    Board { acct_a, home_a, draft_a, acct_b }
}

/// The principal whose account's doc 1 is a DRAFT ([`draft_home_account`]).
const D: PrincipalId = PrincipalId(4);

/// A SECOND ISSUER, for the feed enumerations: an account that grants beside
/// [`A`] so each enumeration's row list carries more than one entry.
const C: PrincipalId = PrincipalId(5);

/// An account whose DOC 1 IS A DRAFT — the first mint with an explicit
/// `false`, which the daemon's door refuses (PUB-8.20) and the engine mints —
/// plus a later private document for a grant to name. Returns
/// `(the draft doc 1, that later document)`.
///
/// The ONE shape that isolates admission's PUBLISHED clause. Every other
/// draft-homed record fails the DOC-1 clause as well, so a fold that skipped
/// the publication test answers those the same way and only this one
/// differently.
fn draft_home_account(engine: &Engine) -> (skep_address::Address, skep_address::Address) {
    let ns = engine.namespace();
    let prefix = engine
        .kernel()
        .snapshot()
        .world()
        .m3()
        .next_account_prefix(&node1())
        .expect("prefix D");
    let (acct, _) =
        ns.delegate(BOOTSTRAP_PRINCIPAL, prefix.tumbler().clone(), D).expect("delegate D");
    let (home, _) =
        ns.create_new_document(D, &acct, Some(false)).expect("an explicit-false FIRST mint");
    let (secret, _) = ns.create_new_document(D, &acct, None).expect("a later mint, private");
    assert_eq!(
        first_document_address(&acct).as_ref(),
        Some(&home),
        "the home must BE doc 1, or the doc-1 clause refuses it and the tests below prove nothing"
    );
    (home, secret)
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
    grant_as(engine, A, home, from, to)
}

/// [`grant`] by any ISSUER — the principal that deposits, whose account is
/// the one admission reads as ω of the home.
fn grant_as(
    engine: &Engine,
    issuer: PrincipalId,
    home: &skep_address::Address,
    from: &skep_address::Address,
    to: Vec<skep_address::Address>,
) -> skep_address::Address {
    grant_slots(engine, issuer, home, vec![from.clone()], to)
}

/// [`grant_as`] with both caller-shaped slots as SEQUENCES. A well-formed
/// record denotes exactly one address in `from` and one or none in `to`;
/// anything else is the MALFORMED shape the fold ignores, and this is the one
/// way to build one.
fn grant_slots(
    engine: &Engine,
    issuer: PrincipalId,
    home: &skep_address::Address,
    from: Vec<skep_address::Address>,
    to: Vec<skep_address::Address>,
) -> skep_address::Address {
    grant_typed(engine, issuer, home, from, to, vec![t_grant()])
}

/// The deposit itself, all three slots as SEQUENCES — including the TYPE,
/// which is what the fold recognizes a grant record by. A well-formed record
/// names exactly the grants class there; anything else is a link the fold
/// must not read as a grant, and this is the one way to build one.
fn grant_typed(
    engine: &Engine,
    issuer: PrincipalId,
    home: &skep_address::Address,
    from: Vec<skep_address::Address>,
    to: Vec<skep_address::Address>,
    ty: Vec<skep_address::Address>,
) -> skep_address::Address {
    let caller = Caller::Principal(issuer);
    match engine.linkstore(&World::visible_to(caller)).makelink(
        caller,
        home,
        SlotArg::Addrs(from),
        SlotArg::Addrs(to),
        SlotArg::Addrs(ty),
    ) {
        Ok((addr, _)) => addr,
        Err(_) => panic!("the link deposits into the issuer's own document"),
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
    assert!(w.readable(Some(A), &b.draft_a), "A reads its own draft (subtree)");
    assert!(!w.readable(Some(B), &b.draft_a), "B cannot read it yet");
    assert!(!w.readable(None, &b.draft_a), "the guest cannot");
    assert!(w.readable(None, &b.home_a), "the published home is readable by all");

    // Grant the draft to B's account.
    grant(&engine, &b.home_a, &b.draft_a, vec![b.acct_b.clone()]);
    let w = world(&engine);
    assert!(w.readable(Some(B), &b.draft_a), "B now reads the granted draft");
    assert!(!w.readable(None, &b.draft_a), "the guest still cannot — a grant is to a principal");
    assert!(
        !w.readable(Some(PrincipalId(3)), &b.draft_a),
        "an ungranted principal cannot (grantee is PRINCIPAL-EXACT)"
    );
}

/// The ANY-PRINCIPAL form (empty `to`, PUB-5.8): readable by every bound
/// principal, still not by the guest — and the tier's membership test is
/// BEING a principal and nothing more, so an UNSEATED one reads it too. That
/// last case is what the predicate's grant bullet states and what a reader
/// would otherwise have to infer from a principal-exact index it never
/// probes: with no seat there is no account to compare in the subtree clause
/// and no key to probe in that index, and the universal probe runs anyway.
#[test]
fn an_any_principal_grant_opens_a_draft_to_every_principal_but_not_the_guest() {
    let engine = mem_engine();
    let b = two_accounts(&engine);
    grant(&engine, &b.home_a, &b.draft_a, vec![]); // empty `to` ⟹ ANY-PRINCIPAL
    let w = world(&engine);
    assert!(w.readable(Some(B), &b.draft_a), "B, a principal, reads it");
    // Never delegated, so M3 seats it nowhere — the premise of the next line.
    const UNSEATED: PrincipalId = PrincipalId(9);
    assert!(
        w.m3().principal_prefix(UNSEATED).is_none(),
        "the fixture must leave this principal unseated, or it proves nothing about the tier"
    );
    assert!(w.readable(Some(UNSEATED), &b.draft_a), "an unseated principal is still a principal");
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
        .create_new_document(A, &b.acct_a, None)
        .expect("A's later draft");

    let w = world(&engine);
    assert!(w.readable(Some(B), &b.draft_a), "B reads the draft under the granted account");
    assert!(w.readable(Some(B), &later), "…and the draft minted after the grant");
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
        .delegate(A, sub_prefix.tumbler().clone(), PrincipalId(11))
        .expect("A delegates a sub-account");
    let (sub_draft, _) = engine
        .namespace()
        .create_new_document(PrincipalId(11), &sub, Some(false))
        .expect("the sub-account's own private draft");

    let w = world(&engine);
    assert!(w.readable(Some(PrincipalId(11)), &b.draft_a), "A's sub-account reads A's draft");
    assert!(
        !w.readable(Some(A), &sub_draft),
        "A does NOT read its sub-account's draft — the subtree runs downward, never up"
    );
    assert!(
        !w.readable(Some(BOOTSTRAP_PRINCIPAL), &b.draft_a),
        "the org root (principal 0 at node [1]) reads no draft by subtree"
    );
    assert!(!w.readable(Some(B), &b.draft_a), "a sibling account reads nothing of A's");
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
        .delegate(B, sub_prefix.tumbler().clone(), PrincipalId(12))
        .expect("B delegates a sub-account");
    grant(&engine, &b.home_a, &b.draft_a, vec![b.acct_b.clone()]);
    let w = world(&engine);
    assert!(w.readable(Some(B), &b.draft_a), "the grantee reads");
    assert!(
        !w.readable(Some(PrincipalId(12)), &b.draft_a),
        "the grantee's sub-account does not — grantee-exact"
    );
}

/// The residence pin (PUB-5.17) and the class law (PUB-5.2): a grant record is
/// a fold input only when homed in the issuer's OWN doc 1, published. Both
/// homes below sit OUTSIDE doc 1 — A's second document, and a published
/// edition of A's — so each isolates the DOC-1 clause; deposited in doc 1 the
/// same record admits. The PUBLISHED clause is reached by one home shape
/// alone, a draft that IS doc 1, and its witness is
/// [`a_grant_homed_in_a_draft_doc_1_is_inert`].
#[test]
fn a_grant_homed_anywhere_but_the_issuer_s_published_doc_1_is_inert() {
    let engine = mem_engine();
    let b = two_accounts(&engine);

    // In A's second document, which is a draft — but it is the position in the
    // chain, not the bit, that refuses this one.
    grant(&engine, &b.draft_a, &b.draft_a, vec![b.acct_b.clone()]);
    assert!(
        !world(&engine).readable(Some(B), &b.draft_a),
        "A's second document is not its doc 1, so the record is inert"
    );

    // In a published edition of A's that is not the account's doc 1.
    let (edition, _) = engine
        .namespace()
        .create_new_document(A, &b.acct_a, Some(true))
        .expect("A's published edition");
    grant(&engine, &edition, &b.draft_a, vec![b.acct_b.clone()]);
    assert!(
        !world(&engine).readable(Some(B), &b.draft_a),
        "a grant homed outside doc 1 is inert to the fold"
    );

    // In doc 1: the one home the class law names.
    grant(&engine, &b.home_a, &b.draft_a, vec![b.acct_b.clone()]);
    assert!(world(&engine).readable(Some(B), &b.draft_a), "the doc-1 record admits");
}

/// Admission's PUBLISHED clause (I4, PUB-5.19), isolated: grants are born
/// published, so a record homed in an UNPUBLISHED doc 1 is no grant. The home
/// here satisfies every other clause — it is the issuer's own doc 1, and the
/// issuer is ω of the document granted — so the publication bit is the only
/// thing standing between this record and an entitlement.
#[test]
fn a_grant_homed_in_a_draft_doc_1_is_inert() {
    let engine = mem_engine();
    let b = two_accounts(&engine);
    let (draft_home, secret) = draft_home_account(&engine);

    grant_as(&engine, D, &draft_home, &secret, vec![b.acct_b.clone()]);

    let w = world(&engine);
    assert!(!w.readable(Some(B), &secret), "an unpublished home admits no grant");
    assert!(w.issuers_for(&b.acct_b).is_empty(), "…and the fold holds no record of it");
    engine.check_hints().expect("the seed refuses it for the reason the fold did");
}

/// The recovery ORDER, from the far end (PUB-7.7, `World::rebuild_derived`):
/// the exception set is seeded before the grant fold, so the seed asks
/// admission's published clause the question the fold asked. A grant the live
/// fold refused for an unpublished home must be refused again at load — a
/// grant seed handed an empty set would admit it, and the restart would open a
/// private document that was closed the moment before.
///
/// The checkpoint sits at HEAD, so the reopened base IS the checkpoint and
/// nothing replays onto it: what answers below is the seed alone.
#[test]
fn a_restart_does_not_admit_a_grant_the_live_fold_refused() {
    let dir = tempdir().expect("tempdir");
    let (secret, grantee) = {
        let engine = Engine::open(fsync_cfg(dir.path())).expect("fsync open");
        let b = two_accounts(&engine);
        let (draft_home, secret) = draft_home_account(&engine);
        grant_as(&engine, D, &draft_home, &secret, vec![b.acct_b.clone()]);
        assert!(!world(&engine).readable(Some(B), &secret), "live: the fold refuses it");
        engine.kernel().checkpoint().expect("checkpoint at head");
        (secret, B)
    };

    let engine = Engine::open(fsync_cfg(dir.path())).expect("reopen over the checkpoint");
    assert!(
        !world(&engine).readable(Some(grantee), &secret),
        "the seed admitted what the fold refused: a restart opened a private document"
    );
    engine.check_hints().expect("the recovered fold equals a from-authoritative rebuild");
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
        .create_new_document(B, &b.acct_b, None)
        .expect("B's published home");
    // B tries to grant A's draft to itself, from B's home.
    match engine.linkstore(&World::visible_to(Caller::Principal(B))).makelink(
        Caller::Principal(B),
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
        !w.readable(Some(B), &b.draft_a),
        "the grant's issuer (B) is not the draft's ω owner (A), so it opens nothing"
    );
}

/// Coverage's ISSUER clause on the ANY-PRINCIPAL index (PUB-5.19) — the arm
/// the test above cannot reach: that record names a grantee, so it lands in
/// the PRINCIPAL-EXACT index and leaves the universal one empty. A record has
/// a grantee or it has none, so the predicate's two probes take two tests.
/// Here B grants A's draft to EVERY principal, from B's own published doc 1.
#[test]
fn an_any_principal_grant_from_a_non_owner_opens_nothing() {
    let engine = mem_engine();
    let b = two_accounts(&engine);
    let (home_b, _) = engine
        .namespace()
        .create_new_document(B, &b.acct_b, None)
        .expect("B's published home");
    grant_as(&engine, B, &home_b, &b.draft_a, vec![]); // empty `to` ⟹ ANY-PRINCIPAL

    // The record IS admitted, so the probe reaches its issuer clause — without
    // this the assertions below would pass for want of a grant rather than for
    // want of an owner.
    let w = world(&engine);
    assert_eq!(
        w.universal_grants(),
        vec![UniversalGrant {
            content_prefix: b.draft_a.clone(),
            issuers: vec![b.acct_b.clone()],
        }],
        "the deposit must enter the universal index, or this test proves nothing"
    );
    assert!(
        !w.readable(Some(B), &b.draft_a),
        "the grant's issuer (B) is not the draft's ω owner (A), so it opens nothing"
    );
    assert!(
        !w.readable(Some(PrincipalId(3)), &b.draft_a),
        "…and no other principal reads it either, though the grant names them all"
    );
    engine.check_hints().expect("the seed refuses it for the reason the fold did");
}

/// The fold keys on the grants class by DENOTATION EQUALITY, so a type slot
/// naming that class AMONG OTHERS is no grant record. `single_denoted`
/// refuses a slot denoting several addresses; a fold reaching for a slot's
/// first denoted address, or asking whether ANY of them is the class, would
/// admit this one and share a draft on the strength of a link typed something
/// else as well.
#[test]
fn a_link_typed_the_grants_class_and_another_grants_nothing() {
    let engine = mem_engine();
    let b = two_accounts(&engine);
    let link = grant_typed(
        &engine,
        A,
        &b.home_a,
        vec![b.draft_a.clone()],
        vec![b.acct_b.clone()],
        vec![t_grant(), t_edition()],
    );

    let w = world(&engine);
    assert!(
        w.links().readlink(&link).is_some(),
        "the deposit itself succeeds — the open surface fences neither class"
    );
    assert!(!w.readable(Some(B), &b.draft_a), "a dual-typed link is no grant record");
    assert!(w.issuers_for(&b.acct_b).is_empty(), "…and nothing of it entered the fold");
    engine.check_hints().expect("the seed refuses it for the reason the fold did");
}

/// …and by the ADDRESS, never by prefix: a `3.90.k` SUBTYPE is the daemon's
/// write-path class (PUB-6.30 recognizes a class's subtypes by prefix) and is
/// not the fold's. The two rules differ on purpose — the engine's type ledger
/// states both — and this is the case that keeps them apart, so a later
/// reconciliation of the fold to the door's rule cannot land unnoticed.
#[test]
fn a_link_typed_a_grants_subtype_grants_nothing() {
    let engine = mem_engine();
    let b = two_accounts(&engine);
    let link = grant_typed(
        &engine,
        A,
        &b.home_a,
        vec![b.draft_a.clone()],
        vec![b.acct_b.clone()],
        vec![t_grant_subtype()],
    );

    let w = world(&engine);
    assert!(w.links().readlink(&link).is_some(), "the deposit itself succeeds");
    assert!(!w.readable(Some(B), &b.draft_a), "a subtype-typed link is no grant record");
    assert!(w.issuers_for(&b.acct_b).is_empty(), "…and nothing of it entered the fold");
    engine.check_hints().expect("the seed refuses it for the reason the fold did");
}

/// The fold IGNORES a malformed record: `from` must denote exactly one address
/// and `to` exactly one or none, so a record naming two grantees grants to
/// NEITHER and one naming two prefixes shares NEITHER. That is the fail-closed
/// direction, and it is the one a fold reaching for a slot's FIRST denoted
/// address would reverse — the weakening M7 names beside `single_denoted`
/// itself, and the natural shape of a later "several grantees" change.
#[test]
fn a_grant_record_with_a_multi_address_slot_grants_nothing() {
    let engine = mem_engine();
    let b = two_accounts(&engine);
    // A second grantee ACCOUNT, seated: the grant clause probes the
    // principal-exact index with the principal's own account, so a principal
    // with no account could not answer this question either way.
    let prefix_c = engine
        .kernel()
        .snapshot()
        .world()
        .m3()
        .next_account_prefix(&node1())
        .expect("prefix C");
    let (acct_c, _) = engine
        .namespace()
        .delegate(BOOTSTRAP_PRINCIPAL, prefix_c.tumbler().clone(), PrincipalId(3))
        .expect("delegate C");
    let (draft_two, _) = engine
        .namespace()
        .create_new_document(A, &b.acct_a, None)
        .expect("A's second draft");

    // Two grantees in `to`, then two content-prefixes in `from` — each record
    // well-formed in every other respect, homed in A's published doc 1.
    grant_slots(
        &engine,
        A,
        &b.home_a,
        vec![b.draft_a.clone()],
        vec![b.acct_b.clone(), acct_c.clone()],
    );
    grant_slots(
        &engine,
        A,
        &b.home_a,
        vec![b.draft_a.clone(), draft_two.clone()],
        vec![b.acct_b.clone()],
    );

    // Every entitlement either record would have carried had its slot been
    // read one address at a time: both grantees of the first, both prefixes
    // of the second.
    let w = world(&engine);
    let carried = [(B, &b.draft_a), (PrincipalId(3), &b.draft_a), (B, &draft_two)];
    for (principal, doc) in carried {
        assert!(!w.readable(Some(principal), doc), "a malformed record opened {doc} to {principal:?}");
    }
    assert!(
        w.issuers_for(&b.acct_b).is_empty() && w.issuers_for(&acct_c).is_empty(),
        "neither malformed record entered the fold"
    );
    engine.check_hints().expect("the seed ignores them for the reason the fold did");
}

/// Revocation by supersession (PUB-5.13): a later admitted grant naming the
/// earlier grant's own link address in `from` removes it.
#[test]
fn a_superseding_record_revokes_the_grant_it_names() {
    let engine = mem_engine();
    let b = two_accounts(&engine);
    let g = grant(&engine, &b.home_a, &b.draft_a, vec![b.acct_b.clone()]);
    assert!(world(&engine).readable(Some(B), &b.draft_a), "granted");

    // A revoking record: `from` names the grant link itself.
    grant(&engine, &b.home_a, &g, vec![b.acct_b.clone()]);
    assert!(
        !world(&engine).readable(Some(B), &b.draft_a),
        "the superseding record revoked the grant"
    );
}

/// …and revocation reads the grants class of ONE HOME (PUB-5.13): a record
/// naming an earlier grant's link address from a home of its own is a fresh
/// grant, never a revocation of what it names. Same home ⟹ same ω owner is
/// the whole of the issuer restriction, and without it any account could
/// retire any other account's grants by depositing one link in its own doc 1.
///
/// The predicate is the only witness. Both halves of the discipline drive one
/// classification, so a fold that dropped the home comparison and a seed that
/// dropped it agree with each other, and the faithfulness check stays green.
#[test]
fn a_record_homed_elsewhere_revokes_no_grant_it_names() {
    let engine = mem_engine();
    let b = two_accounts(&engine);
    let g = grant(&engine, &b.home_a, &b.draft_a, vec![b.acct_b.clone()]);
    assert!(world(&engine).readable(Some(B), &b.draft_a), "granted");

    // B's own published doc 1, and a record of B's naming A's grant.
    let (home_b, _) = engine
        .namespace()
        .create_new_document(B, &b.acct_b, None)
        .expect("B's published home");
    grant_as(&engine, B, &home_b, &g, vec![b.acct_b.clone()]);

    let w = world(&engine);
    assert!(
        w.readable(Some(B), &b.draft_a),
        "a record homed in B's doc 1 retired A's grant: any account could retire any other's"
    );
    assert_eq!(
        w.issuers_for(&b.acct_b).len(),
        2,
        "A's grant stands, and B's record is a fresh grant of B's own"
    );
    engine.check_hints().expect("both halves agree, which is why only the predicate sees this");
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
    assert!(world(&engine).readable(Some(B), &b.draft_a), "granted");

    let issuer = Caller::Principal(A);
    engine
        .linkstore(&World::visible_to(issuer))
        .nullify(issuer, &b.home_a, &g)
        .unwrap_or_else(|_| panic!("the issuer retracts its own grant link"));

    let w = world(&engine);
    assert!(w.links().is_nullified(&g), "the fixture must retract the grant link");
    assert!(
        w.readable(Some(B), &b.draft_a),
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

    let issuer = Caller::Principal(A);
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
        vec![IssuerGrant {
            issuer: b.acct_a.clone(),
            content_prefixes: vec![b.acct_a.clone(), b.draft_a.clone()],
        }],
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
    let (draft_a, acct_b) = {
        let engine = Engine::open(fsync_cfg(dir.path())).expect("fsync open");
        // Empty-map witness: genesis holds no grants, so no private document is
        // readable by anyone but its owner subtree (there are none yet).
        let board = two_accounts(&engine);
        grant(&engine, &board.home_a, &board.draft_a, vec![board.acct_b.clone()]);
        engine.kernel().checkpoint().expect("checkpoint at head");
        assert!(world(&engine).readable(Some(B), &board.draft_a), "live: B reads it");
        (board.draft_a, board.acct_b)
    };

    // Reopen: the seed re-derives the fold from the link map.
    let engine = Engine::open(fsync_cfg(dir.path())).expect("reopen over the checkpoint");
    let w = world(&engine);
    assert!(w.readable(Some(B), &draft_a), "the recovered fold still opens the draft to B");
    let _ = acct_b;

    // Empty-map: a fresh engine's fold is empty — a private draft is readable
    // only by its owner subtree, never by a grant that does not exist.
    let fresh = mem_engine();
    let board = two_accounts(&fresh);
    assert!(
        !world(&fresh).readable(Some(B), &board.draft_a),
        "an empty fold grants nothing (PUB-7.68)"
    );
}

/// The fold's two enumerations for the feed (lane 3.6 §3; PUB-7.22,
/// PUB-7.28): the LIVE ANY-PRINCIPAL set and a grantee's issuers with the
/// union of covered prefixes — both read off the fold's own indexes, both
/// agreeing with the predicate they are the inside-out of, and both moving
/// with a superseding record at once (revocation is immediate, PUB-7.23).
///
/// Each enumeration is ordered at TWO levels — the rows by their key, then
/// each row's own list — and this fixture carries at least two entries at
/// every one of the four, deposited in the REVERSE of the order asserted. A
/// build that iterated in deposit order, or off a hash-keyed structure, would
/// answer a different vector here; with one entry per level every order
/// coincides and no assertion can tell them apart.
#[test]
fn the_two_feed_enumerations_read_the_fold_s_live_state() {
    let engine = mem_engine();
    let b = two_accounts(&engine);
    let (draft_two, _) = engine
        .namespace()
        .create_new_document(A, &b.acct_a, None)
        .expect("A's second draft");
    // A SECOND ISSUER, seated after A and B, so its account address sorts
    // last: `acct_c` is the row every deposit below puts FIRST.
    let prefix_c = engine
        .kernel()
        .snapshot()
        .world()
        .m3()
        .next_account_prefix(&node1())
        .expect("prefix C");
    let (acct_c, _) = engine
        .namespace()
        .delegate(BOOTSTRAP_PRINCIPAL, prefix_c.tumbler().clone(), C)
        .expect("delegate C");
    let (home_c, _) =
        engine.namespace().create_new_document(C, &acct_c, None).expect("C's published home");
    assert!(b.acct_a < acct_c, "the fixture wants A's account to sort before C's");
    assert!(b.draft_a < draft_two, "…and A's first draft before its second");

    // Empty fold: nothing enumerates.
    let w = world(&engine);
    assert!(w.universal_grants().is_empty(), "no universal grant yet");
    assert!(w.issuers_for(&b.acct_b).is_empty(), "B holds no grant yet");

    // C's deposits first, and within them the later prefix first — so every
    // list below is asserted in the reverse of the order it was written in.
    // C owns neither draft, so none of these opens anything; they are index
    // entries, which is what the enumerations answer with.
    grant_as(&engine, C, &home_c, &draft_two, vec![]);
    grant_as(&engine, C, &home_c, &draft_two, vec![b.acct_b.clone()]);
    grant_as(&engine, C, &home_c, &b.draft_a, vec![b.acct_b.clone()]);
    // Then A's: two to B — the draft and the whole account — and two
    // ANY-PRINCIPAL, the second draft before the first.
    grant(&engine, &b.home_a, &b.draft_a, vec![b.acct_b.clone()]);
    grant(&engine, &b.home_a, &b.acct_a, vec![b.acct_b.clone()]);
    let g_any = grant(&engine, &b.home_a, &draft_two, vec![]);
    grant(&engine, &b.home_a, &b.draft_a, vec![]);

    let w = world(&engine);
    assert_eq!(
        w.issuers_for(&b.acct_b),
        vec![
            IssuerGrant {
                issuer: b.acct_a.clone(),
                content_prefixes: vec![b.acct_a.clone(), b.draft_a.clone()],
            },
            IssuerGrant {
                issuer: acct_c.clone(),
                content_prefixes: vec![b.draft_a.clone(), draft_two.clone()],
            },
        ],
        "B's issuers in address order, each with the UNION of its prefixes in address order"
    );
    assert!(
        w.issuers_for(&b.acct_a).is_empty(),
        "the grantee side is principal-exact: A itself holds no grant"
    );
    assert_eq!(
        w.universal_grants(),
        vec![
            UniversalGrant {
                content_prefix: b.draft_a.clone(),
                issuers: vec![b.acct_a.clone()],
            },
            UniversalGrant {
                content_prefix: draft_two.clone(),
                issuers: vec![b.acct_a.clone(), acct_c.clone()],
            },
        ],
        "the live any-principal set in prefix order, each issuer list in address order"
    );
    // The enumerations are the predicate turned inside out — and an entry
    // whose issuer is not the document's owner is listed and opens nothing.
    assert!(w.readable(Some(B), &b.draft_a));
    assert!(w.readable(Some(PrincipalId(9)), &draft_two), "any principal reads draft two");
    assert!(!w.readable(None, &draft_two), "the guest never does");

    // A superseding record leaves the enumeration at the commit that carries
    // it — no restart, no lag: A's entry leaves `draft_two`, C's stays.
    grant(&engine, &b.home_a, &g_any, vec![]);
    let w = world(&engine);
    assert_eq!(
        w.universal_grants(),
        vec![
            UniversalGrant {
                content_prefix: b.draft_a.clone(),
                issuers: vec![b.acct_a.clone()],
            },
            UniversalGrant { content_prefix: draft_two.clone(), issuers: vec![acct_c.clone()] },
        ],
        "the revoked entry is gone at once, and only that entry"
    );
    assert!(
        !w.readable(Some(PrincipalId(9)), &draft_two),
        "and the predicate agrees: C's surviving entry is not the owner's"
    );
    assert_eq!(w.issuers_for(&b.acct_b).len(), 2, "B's grants are untouched by it");
}

/// The fold's query indexes are keyed by a grant's ISSUER, CONTENT-PREFIX and
/// GRANTEE, and they are SETS: two admitted grants that agree on those three
/// contribute ONE index entry, and nothing counts how many named it. So where
/// an issuer grants the same prefix to the same grantee twice and then revokes
/// ONE of the two, the entry both contributed leaves — while the other record
/// stays in the operative set the dump's grant section renders.
///
/// Pinned here because the fold's own doc states it, and because it is the one
/// place `readable` and that section disagree: the second grant is rendered
/// and does not open its draft. Whether the index should carry a count is a
/// spec question and not this crate's; what this test holds is that the
/// behaviour cannot change unnoticed.
#[test]
fn two_grants_sharing_an_index_entry_are_withdrawn_together() {
    let engine = mem_engine();
    let b = two_accounts(&engine);
    // Two grants, same issuer, same content-prefix, same grantee.
    let first = grant(&engine, &b.home_a, &b.draft_a, vec![b.acct_b.clone()]);
    let second = grant(&engine, &b.home_a, &b.draft_a, vec![b.acct_b.clone()]);
    assert_ne!(first, second, "two deposits, two link addresses");
    assert!(world(&engine).readable(Some(B), &b.draft_a), "granted twice");

    // Revoke the FIRST: a later record naming its link address.
    grant(&engine, &b.home_a, &first, vec![b.acct_b.clone()]);

    let w = world(&engine);
    assert!(
        !w.readable(Some(B), &b.draft_a),
        "the entry both grants contributed left with the one that was revoked"
    );
    assert!(w.issuers_for(&b.acct_b).is_empty(), "…and so did the feed's own read of it");
    // The unrevoked record is still in the operative set: the dump's grant
    // section names its link address.
    let text = engine.world_dump().into_string();
    assert!(
        text.contains(&format!("{:?}", second.to_string())),
        "the second grant is still an operative record:\n{text}"
    );
    engine.check_hints().expect("the seed reproduces the fold over a shared index entry");
}

/// The reach the read predicate's PROJECTION cost term is paid over: the
/// projection runs AHEAD of every clause, so a caller pays it on an address
/// nothing can refuse — one M3 never registered, whose component count is the
/// caller's own choice — and the answer is then the fail-open `true` the
/// published clause gives an absent address (PUB-7.5).
///
/// A DEEP DOCUMENT FIELD is the shape, because that field's length is the
/// projection's iteration count and each iteration copies the whole address.
/// Every clause below the projection is bounded by something the store chose:
/// the exception set is a hash probe, and the grant clause's ancestor walk is
/// reached only past a set HIT, so it only ever runs over a document M3
/// registered. The projection is reached by everything.
///
/// Pinned as REACH rather than as a figure, exactly as
/// [`a_grant_names_an_address_the_client_invented`] pins the dump's magnitude
/// term: what bounds the count in the live system is the daemon's wire cap on
/// a tumbler's components, and nothing in this crate refuses the shape. A
/// corpus seed for the workspace's fuzzing tier, which is where a figure
/// would come from.
#[test]
fn the_read_predicate_projects_an_address_the_client_invented() {
    let engine = mem_engine();
    let b = two_accounts(&engine);

    // A DOCUMENT address under A's account whose document field is a long run
    // of version components — T4-valid, registered nowhere, and never
    // reachable by any mint.
    let deep: skep_address::Address = {
        let comps = b
            .acct_a
            .tumbler()
            .iter()
            .cloned()
            .chain([nat(0)])
            .chain((0..64u32).map(|_| nat(1)));
        validate(Tumbler::new(comps).expect("nonempty")).expect("a document tier address is T4-valid")
    };
    // The premises, stated where they can fail: this must be a DOCUMENT — the
    // level whose field the projection peels — with a field long enough that
    // the peel is not one step, and it must be unregistered, so no clause
    // below the projection can refuse it first.
    assert_eq!(deep.level(), Level::Document);
    assert_eq!(
        deep.document_field().map(|field| field.len()),
        Some(64),
        "the projection's iteration count IS this field's length"
    );
    assert!(
        !engine.kernel().snapshot().world().m3().is_registered_document(&deep),
        "the point is an address M3 never minted"
    );
    // …and the projection really does run over all of it, peeling to the
    // account's own doc 1 — which is not this address.
    assert_eq!(trunk_of(&deep), addr(&[1, 0, 1, 0, 1]));

    let w = world(&engine);
    // The work is spent, and then the address is fail-open readable: at every
    // class, for the guest that never authenticated as much as for the owner.
    assert!(w.readable(None, &deep), "an unregistered address is fail-open (PUB-7.5)");
    assert!(w.readable(Some(A), &deep));
    assert!(w.readable(Some(B), &deep));
    // The registration check the contract puts AHEAD of the read is the
    // caller's, and no caller of this predicate can run it for free: M3's own
    // read answers the other way, so the deferral is a second walk and not a
    // cheaper first one.
    assert!(!w.m3().is_registered_document(&deep));
}
