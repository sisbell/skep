//! The grant fold and the read predicate (PUB round 2, lane 3.3, §1), through
//! the assembled engine: a grant is an ordinary link the fold recognizes as a
//! VALUE, seeded at load and folded on every deposit; `World::readable` is the
//! one predicate every read surface answers through. Store semantics are not
//! re-tested here — what is tested is the ASSEMBLY: the fold, its admission,
//! its revocation, its re-seed across a restart and under a historical
//! reconstruction, the three clauses of the predicate, and the reader class
//! it is bound as.

use crate::common;

use common::*;
use skep_address::{validate, Level, Tumbler};
use skep_arrangement::{trunk_of, Caller, Deposit};
use skep_content::Val;
use skep_engine::{Engine, IssuerGrant, UniversalGrant, World};
use skep_links::{HasLinks, ShippedType, SlotArg};
use skep_namespace::{
    first_document_address, prefix_contains, HasM3, PrincipalId, BOOTSTRAP_PRINCIPAL,
};
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
    engine
        .linkstore(&World::visible_to(caller))
        .makelink(caller, home, SlotArg::Addrs(from), SlotArg::Addrs(to), SlotArg::Addrs(ty))
        .expect("the link deposits into the issuer's own document")
        .0
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
    let board = two_accounts(&engine);

    // Before the grant: only A (subtree) reads the draft.
    let w = world(&engine);
    assert!(w.readable(Some(A), &board.draft_a), "A reads its own draft (subtree)");
    assert!(!w.readable(Some(B), &board.draft_a), "B cannot read it yet");
    assert!(!w.readable(None, &board.draft_a), "the guest cannot");
    assert!(w.readable(None, &board.home_a), "the published home is readable by all");

    // Grant the draft to B's account.
    grant(&engine, &board.home_a, &board.draft_a, vec![board.acct_b.clone()]);
    let w = world(&engine);
    assert!(w.readable(Some(B), &board.draft_a), "B now reads the granted draft");
    assert!(
        !w.readable(None, &board.draft_a),
        "the guest still cannot — a grant is to a principal"
    );
    assert!(
        !w.readable(Some(PrincipalId(3)), &board.draft_a),
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
    let board = two_accounts(&engine);
    grant(&engine, &board.home_a, &board.draft_a, vec![]); // empty `to` ⟹ ANY-PRINCIPAL
    let w = world(&engine);
    assert!(w.readable(Some(B), &board.draft_a), "B, a principal, reads it");
    // Never delegated, so M3 seats it nowhere — the premise of the next line.
    const UNSEATED: PrincipalId = PrincipalId(9);
    assert!(
        w.m3().principal_prefix(UNSEATED).is_none(),
        "the fixture must leave this principal unseated, or it proves nothing about the tier"
    );
    assert!(
        w.readable(Some(UNSEATED), &board.draft_a),
        "an unseated principal is still a principal"
    );
    assert!(
        !w.readable(None, &board.draft_a),
        "the guest does not — ANY-PRINCIPAL excludes the guest"
    );
}

/// The ACCOUNT rung (PUB-5.9, PUB-1.100): a grant whose content-prefix is A's
/// account covers every document under it by containment — the draft that
/// exists and the one A mints afterwards (forward-inclusive) — for the grantee
/// alone; the guest and an ungranted principal read neither.
#[test]
fn an_account_rung_grant_covers_the_account_s_documents_forward_inclusively() {
    let engine = mem_engine();
    let board = two_accounts(&engine);
    grant(&engine, &board.home_a, &board.acct_a, vec![board.acct_b.clone()]);
    let (later, _) = engine
        .namespace()
        .create_new_document(A, &board.acct_a, None)
        .expect("A's later draft");

    let w = world(&engine);
    assert!(w.readable(Some(B), &board.draft_a), "B reads the draft under the granted account");
    assert!(w.readable(Some(B), &later), "…and the draft minted after the grant");
    assert!(!w.readable(None, &later), "the guest still cannot");
    assert!(!w.readable(Some(PrincipalId(3)), &later), "nor an ungranted principal");
}

/// …and the ANY-PRINCIPAL index is probed at EVERY ancestor, exactly as the
/// principal-exact one is: an ACCOUNT-rung grant to every principal covers
/// each document under the account, the one minted after it included. Every
/// other any-principal grant in this suite names its document directly, so a
/// walk that probed the universal index at `doc` alone would answer all of
/// them and close only this one.
#[test]
fn an_any_principal_account_rung_grant_covers_the_account_s_documents() {
    let engine = mem_engine();
    let board = two_accounts(&engine);
    grant(&engine, &board.home_a, &board.acct_a, vec![]); // empty `to` ⟹ ANY-PRINCIPAL
    let (later, _) = engine
        .namespace()
        .create_new_document(A, &board.acct_a, None)
        .expect("A's later draft");

    let w = world(&engine);
    for doc in [&board.draft_a, &later] {
        assert!(w.readable(Some(B), doc), "B reads {doc} under the granted account");
        assert!(w.readable(Some(PrincipalId(3)), doc), "…and so does any other principal");
        assert!(!w.readable(None, doc), "the guest never does");
    }
    engine.check_hints().expect("the seed admits the account-rung grant as the fold did");
}

/// A principal seated at A's FIRST sub-account ([`nested_accounts`]).
const CHILD: PrincipalId = PrincipalId(11);

/// A principal seated beneath [`CHILD`]'s account — A's grandchild.
const GRANDCHILD: PrincipalId = PrincipalId(13);

/// A principal seated at A's SECOND sub-account — [`CHILD`]'s nested sibling.
const SECOND_CHILD: PrincipalId = PrincipalId(14);

/// A board with NESTED accounts, each holding one private draft: [`A`] and
/// its sibling [`B`] under the genesis node, [`CHILD`] and [`SECOND_CHILD`]
/// beneath A, and [`GRANDCHILD`] beneath CHILD.
struct Nested {
    board: Board,
    child_draft: skep_address::Address,
    grandchild_draft: skep_address::Address,
    second_child_draft: skep_address::Address,
    b_draft: skep_address::Address,
}

/// A sub-account delegated beneath `parent` by the principal seated there,
/// seated with `id`, and its one private draft — an explicit-`false` first
/// mint, which the engine mints. Returns `(the account, the draft)`.
fn sub_account_with_a_draft(
    engine: &Engine,
    delegator: PrincipalId,
    parent: &skep_address::Address,
    id: PrincipalId,
) -> (skep_address::Address, skep_address::Address) {
    let prefix = engine
        .kernel()
        .snapshot()
        .world()
        .m3()
        .next_account_prefix(parent)
        .expect("the parent's next sub-account prefix");
    let (acct, _) = engine
        .namespace()
        .delegate(delegator, prefix.tumbler().clone(), id)
        .expect("the parent delegates a sub-account");
    assert!(prefix_contains(parent, &acct), "the fixture must NEST the two accounts");
    let (draft, _) = engine
        .namespace()
        .create_new_document(id, &acct, Some(false))
        .expect("the sub-account's own private draft");
    (acct, draft)
}

fn nested_accounts(engine: &Engine) -> Nested {
    let board = two_accounts(engine);
    let (child, child_draft) = sub_account_with_a_draft(engine, A, &board.acct_a, CHILD);
    let (_, grandchild_draft) = sub_account_with_a_draft(engine, CHILD, &child, GRANDCHILD);
    let (_, second_child_draft) =
        sub_account_with_a_draft(engine, A, &board.acct_a, SECOND_CHILD);
    // B's first mint is its published home; its second is the draft.
    engine.namespace().create_new_document(B, &board.acct_b, None).expect("B's published home");
    let (b_draft, _) =
        engine.namespace().create_new_document(B, &board.acct_b, None).expect("B's private draft");
    Nested { board, child_draft, grandchild_draft, second_child_draft, b_draft }
}

/// The SUBTREE clause runs BOTH WAYS (H1; PUB-1.32 as amended, PUB RES-215):
/// a sub-account reads the drafts of the accounts ABOVE it (its prefix lies
/// inside theirs), and a parent account reads the drafts of the accounts
/// BENEATH it (theirs lie inside its own) — each transitively, one vector per
/// direction and per depth. A read and never ω: the parent owns none of what
/// it reads there.
#[test]
fn the_subtree_clause_runs_both_ways() {
    let engine = mem_engine();
    let n = nested_accounts(&engine);
    let w = world(&engine);

    // The first compare — the principal at or beneath the owner.
    assert!(w.readable(Some(CHILD), &n.board.draft_a), "A's sub-account reads A's draft");
    assert!(w.readable(Some(GRANDCHILD), &n.board.draft_a), "…and so does its grandchild");
    assert!(w.readable(Some(GRANDCHILD), &n.child_draft), "…which reads its own parent's too");

    // The second compare — the principal at or above the owner.
    assert!(w.readable(Some(A), &n.child_draft), "A reads its sub-account's draft");
    assert!(w.readable(Some(A), &n.grandchild_draft), "…and its grandchild's, transitively");
    assert!(w.readable(Some(CHILD), &n.grandchild_draft), "a sub-account reads its own sub-account's");

    // Reading is not owning: ω stays exact-match on what the parent reads.
    assert_eq!(
        w.m3().effective_owner(&n.child_draft),
        Some(CHILD),
        "the sub-account's draft is the sub-account's, never the parent's that reads it"
    );
}

/// A SIBLING reads nothing of its sibling's under either compare — neither
/// account's prefix contains the other's — at the top of the account tier
/// (the org's members, A and B) and NESTED (two sub-accounts of one parent);
/// and the relation does not run sideways through a shared ancestor: B reads
/// nothing beneath A, and nothing beneath A reads B's.
#[test]
fn a_sibling_account_reads_nothing_of_its_sibling_s() {
    let engine = mem_engine();
    let n = nested_accounts(&engine);
    let w = world(&engine);

    assert!(!w.readable(Some(B), &n.board.draft_a), "a sibling account reads nothing of A's");
    assert!(!w.readable(Some(A), &n.b_draft), "…nor A of its sibling's");
    assert!(
        !w.readable(Some(CHILD), &n.second_child_draft),
        "two sub-accounts of one parent are siblings: the first reads nothing of the second's"
    );
    assert!(!w.readable(Some(SECOND_CHILD), &n.child_draft), "…nor the second of the first's");
    assert!(
        !w.readable(Some(SECOND_CHILD), &n.grandchild_draft),
        "…nor of what lies beneath the first"
    );
    assert!(
        !w.readable(Some(GRANDCHILD), &n.second_child_draft),
        "…nor the first's sub-account of the second's"
    );
    assert!(!w.readable(Some(B), &n.child_draft), "A's sibling reads nothing beneath A");
    assert!(!w.readable(Some(CHILD), &n.b_draft), "…and nothing beneath A reads A's sibling's");
    // The parent they share reads both: the clause is ancestry, not kinship.
    assert!(w.readable(Some(A), &n.child_draft) && w.readable(Some(A), &n.second_child_draft));
}

/// The GUEST holds no account and satisfies neither compare: on the nested
/// board it reads the published homes and no draft at any depth.
#[test]
fn the_guest_reads_published_documents_alone_on_a_nested_board() {
    let engine = mem_engine();
    let n = nested_accounts(&engine);
    let w = world(&engine);

    assert!(w.readable(None, &n.board.home_a), "the published home is readable by all");
    for draft in
        [&n.board.draft_a, &n.child_draft, &n.grandchild_draft, &n.second_child_draft, &n.b_draft]
    {
        assert!(!w.readable(None, draft), "the guest reads no draft: {draft}");
        assert!(!w.readable_guest(draft), "…and `readable_guest` is that answer: {draft}");
    }
}

/// THE PRINCIPAL-0 VECTOR (PUB-1.32: the node-tier principal 0 is EXCLUDED BY
/// NAME; PUB-7.2): the node's own principal is seated at node `[1]`, whose
/// prefix contains EVERY account on the board, so the second compare taken
/// bare — `account(p) ⊑ owner_account(doc)` — would admit it to every draft
/// there is. A seat that is no ACCOUNT is no account's ancestor for the
/// clause: on a board with nested accounts principal 0 reads no draft at any
/// depth by subtree, and one by GRANT alone.
#[test]
fn the_node_tier_principal_reads_no_draft_by_subtree() {
    let engine = mem_engine();
    let n = nested_accounts(&engine);
    let w = world(&engine);

    // The premise: principal 0's seat is the node, and the node contains
    // every owner account below — the second compare's bare answer is YES.
    let seat = w.m3().principal_prefix(BOOTSTRAP_PRINCIPAL).expect("genesis seats principal 0");
    assert_eq!(seat.level(), Level::Node, "principal 0 is seated at a node, never an account");
    let drafts =
        [&n.board.draft_a, &n.child_draft, &n.grandchild_draft, &n.second_child_draft, &n.b_draft];
    for draft in drafts {
        let owner = w.owner_account(draft).expect("a draft has a memoized owner");
        assert!(
            prefix_contains(seat, owner),
            "the fixture must put {owner} under the node, or the vector proves nothing"
        );
        assert!(
            !w.readable(Some(BOOTSTRAP_PRINCIPAL), draft),
            "principal 0 (at node [1]) reads no draft by subtree: {draft}"
        );
    }
    assert!(
        w.readable(Some(BOOTSTRAP_PRINCIPAL), &n.board.home_a),
        "…but everyone reads the published home"
    );

    // By grant alone: an ANY-PRINCIPAL grant reaches principal 0 as it
    // reaches every principal, and opens exactly the draft it names.
    grant(&engine, &n.board.home_a, &n.board.draft_a, vec![]); // empty `to` ⟹ ANY-PRINCIPAL
    let w = world(&engine);
    assert!(
        w.readable(Some(BOOTSTRAP_PRINCIPAL), &n.board.draft_a),
        "the node's principal reads a draft a grant opens to it"
    );
    assert!(
        !w.readable(Some(BOOTSTRAP_PRINCIPAL), &n.child_draft),
        "…and still none the grant does not name"
    );
}

/// The grantee is PRINCIPAL-EXACT (H1, PUB-5.8): a grant to B's account
/// opens the draft to B and not to a sub-account B delegates — the grant does
/// not run down B's subtree the way ownership does.
#[test]
fn a_grant_to_an_account_excludes_its_sub_accounts() {
    let engine = mem_engine();
    let board = two_accounts(&engine);
    let sub_prefix = engine
        .kernel()
        .snapshot()
        .world()
        .m3()
        .next_account_prefix(&board.acct_b)
        .expect("B's next sub-account prefix");
    engine
        .namespace()
        .delegate(B, sub_prefix.tumbler().clone(), PrincipalId(12))
        .expect("B delegates a sub-account");
    grant(&engine, &board.home_a, &board.draft_a, vec![board.acct_b.clone()]);
    let w = world(&engine);
    assert!(w.readable(Some(B), &board.draft_a), "the grantee reads");
    assert!(
        !w.readable(Some(PrincipalId(12)), &board.draft_a),
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
    let board = two_accounts(&engine);

    // In A's second document, which is a draft — but it is the position in the
    // chain, not the bit, that refuses this one.
    grant(&engine, &board.draft_a, &board.draft_a, vec![board.acct_b.clone()]);
    assert!(
        !world(&engine).readable(Some(B), &board.draft_a),
        "A's second document is not its doc 1, so the record is inert"
    );

    // In a published edition of A's that is not the account's doc 1.
    let (edition, _) = engine
        .namespace()
        .create_new_document(A, &board.acct_a, Some(true))
        .expect("A's published edition");
    grant(&engine, &edition, &board.draft_a, vec![board.acct_b.clone()]);
    assert!(
        !world(&engine).readable(Some(B), &board.draft_a),
        "a grant homed outside doc 1 is inert to the fold"
    );

    // In doc 1: the one home the class law names.
    grant(&engine, &board.home_a, &board.draft_a, vec![board.acct_b.clone()]);
    assert!(world(&engine).readable(Some(B), &board.draft_a), "the doc-1 record admits");
}

/// Admission's PUBLISHED clause (I4, PUB-5.19), isolated: grants are born
/// published, so a record homed in an UNPUBLISHED doc 1 is no grant. The home
/// here satisfies every other clause — it is the issuer's own doc 1, and the
/// issuer is ω of the document granted — so the publication bit is the only
/// thing standing between this record and an entitlement.
#[test]
fn a_grant_homed_in_a_draft_doc_1_is_inert() {
    let engine = mem_engine();
    let board = two_accounts(&engine);
    let (draft_home, secret) = draft_home_account(&engine);

    grant_as(&engine, D, &draft_home, &secret, vec![board.acct_b.clone()]);

    let w = world(&engine);
    assert!(!w.readable(Some(B), &secret), "an unpublished home admits no grant");
    assert!(w.issuers_for(&board.acct_b).is_empty(), "…and the fold holds no record of it");
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
        let board = two_accounts(&engine);
        let (draft_home, secret) = draft_home_account(&engine);
        grant_as(&engine, D, &draft_home, &secret, vec![board.acct_b.clone()]);
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
    let board = two_accounts(&engine);
    // B's own published home.
    let (home_b, _) = engine
        .namespace()
        .create_new_document(B, &board.acct_b, None)
        .expect("B's published home");
    // B tries to grant A's draft to itself, from B's home.
    engine
        .linkstore(&World::visible_to(Caller::Principal(B)))
        .makelink(
            Caller::Principal(B),
            &home_b,
            SlotArg::Addrs(vec![board.draft_a.clone()]),
            SlotArg::Addrs(vec![board.acct_b.clone()]),
            SlotArg::Addrs(vec![t_grant()]),
        )
        .expect("the deposit itself succeeds — coverage is a READ-time verdict");
    let w = world(&engine);
    assert!(
        !w.readable(Some(B), &board.draft_a),
        "the grant's issuer (B) is not the draft's ω owner (A), so it opens nothing"
    );
}

/// Coverage's ISSUER clause on the ANY-PRINCIPAL index (PUB-5.19) — the arm
/// the test above cannot reach: that record names a grantee, so it lands in
/// the PRINCIPAL-EXACT index and leaves the universal one empty. A record has
/// a grantee or it has none, so the predicate's two probes take two tests.
/// Here B grants A's draft to EVERY principal, from B's own published doc 1.
///
/// It is also the row `World::universal_grants` names as proof that its rows
/// are STORED and a superset of entitlement: the record is admitted on its
/// home alone, so its row is listed, and it entitles nobody.
#[test]
fn an_any_principal_grant_from_a_non_owner_opens_nothing() {
    let engine = mem_engine();
    let board = two_accounts(&engine);
    let (home_b, _) = engine
        .namespace()
        .create_new_document(B, &board.acct_b, None)
        .expect("B's published home");
    grant_as(&engine, B, &home_b, &board.draft_a, vec![]); // empty `to` ⟹ ANY-PRINCIPAL

    // The record IS admitted, so the probe reaches its issuer clause — without
    // this the assertions below would pass for want of a grant rather than for
    // want of an owner.
    let w = world(&engine);
    assert_eq!(
        w.universal_grants(),
        vec![UniversalGrant { content_prefix: &board.draft_a, issuers: vec![&board.acct_b] }],
        "the deposit must enter the universal index, or this test proves nothing"
    );
    assert!(
        !w.readable(Some(B), &board.draft_a),
        "the grant's issuer (B) is not the draft's ω owner (A), so it opens nothing"
    );
    assert!(
        !w.readable(Some(PrincipalId(3)), &board.draft_a),
        "…and no other principal reads it either, though the grant names them all"
    );
    engine.check_hints().expect("the seed refuses it for the reason the fold did");
}

/// A principal seated at a SUB-ACCOUNT of [`A`]'s ([`a_sub_account_of_a`]).
const S: PrincipalId = PrincipalId(6);

/// A sub-account of [`A`]'s, and the two documents its principal [`S`] mints.
struct SubAccount {
    acct: skep_address::Address,
    /// S's published doc 1 — the one home S's grants admit from.
    home: skep_address::Address,
    /// S's private draft.
    draft: skep_address::Address,
}

/// A sub-account of A's, delegated to [`S`], with its published doc 1 and a
/// private draft. Its documents lie under A's prefix and are not A's — ω keeps
/// the LONGEST covering seat — which is the premise both tests below turn on,
/// so it is asserted here, where it is built.
fn a_sub_account_of_a(engine: &Engine, board: &Board) -> SubAccount {
    let prefix = engine
        .kernel()
        .snapshot()
        .world()
        .m3()
        .next_account_prefix(&board.acct_a)
        .expect("A's next sub-account prefix");
    let (acct, _) =
        engine.namespace().delegate(A, prefix.tumbler().clone(), S).expect("A delegates");
    let (home, _) =
        engine.namespace().create_new_document(S, &acct, None).expect("S's published doc 1");
    let (draft, _) =
        engine.namespace().create_new_document(S, &acct, None).expect("S's private draft");
    let w = world(engine);
    assert!(prefix_contains(&board.acct_a, &acct), "the fixture must NEST the two accounts");
    assert!(w.readable(None, &home), "S's doc 1 is born published");
    assert!(!w.readable(None, &draft), "S's later mint is a draft");
    // The parent READS its sub-account's draft — the subtree clause runs both
    // ways (PUB-1.32 as amended) — and owns none of it, which is the premise.
    assert!(w.readable(Some(A), &draft), "the parent reads its sub-account's draft by subtree");
    assert_eq!(w.owner_account(&draft), Some(&acct), "…and ω keeps it the sub-account's");
    SubAccount { acct, home, draft }
}

/// Coverage's ISSUER clause (PUB-5.19) is EQUALITY with the document's ω
/// owner, never containment — and a SUB-ACCOUNT is where the two part, since
/// A's account contains S's. A's account-rung grant covers S's draft by
/// containment, so a clause read as "the issuer's account contains the
/// owner's" would open S's draft to whoever A names, though A only READS that
/// draft — by the subtree clause, which runs both ways (PUB-1.32 as amended) —
/// and owns none of it: reading is not owning, the same boundary the test
/// below crosses the other way. The non-owner tests above use a SIBLING
/// account, which contains nothing, so neither can tell the two readings
/// apart. Asked of both indexes.
#[test]
fn a_parent_account_s_grant_opens_none_of_its_sub_account_s_drafts() {
    let engine = mem_engine();
    let board = two_accounts(&engine);
    let sub_account = a_sub_account_of_a(&engine, &board);
    grant(&engine, &board.home_a, &board.acct_a, vec![board.acct_b.clone()]);
    grant(&engine, &board.home_a, &board.acct_a, vec![]); // empty `to` ⟹ ANY-PRINCIPAL

    let w = world(&engine);
    // Both grants ARE admitted, so each probe reaches its issuer clause.
    assert!(w.readable(Some(B), &board.draft_a), "the named grant covers A's own draft");
    assert!(
        w.readable(Some(PrincipalId(9)), &board.draft_a),
        "…and the ANY-PRINCIPAL one covers it for every principal"
    );
    assert!(
        !w.readable(Some(B), &sub_account.draft),
        "the named grantee does not read the sub-account's draft"
    );
    assert!(
        !w.readable(Some(PrincipalId(9)), &sub_account.draft),
        "…nor does every principal, through the ANY-PRINCIPAL grant"
    );
    assert!(w.readable(Some(S), &sub_account.draft), "while its own owner does");
    engine.check_hints().expect("the seed admits both grants as the fold did");
}

/// …and across the same boundary the other way: S READS A's draft, by the
/// subtree clause, but reading is not owning, so S's admitted grants of it —
/// from S's own published doc 1 — open it to nobody. A clause read as "the
/// owner's account contains the issuer's" would admit both. Asked of both
/// indexes — and so it holds, for `World::issuers_for` as for
/// `World::universal_grants`, a STORED row that entitles nobody.
#[test]
fn a_sub_account_s_grant_opens_none_of_its_parent_s_drafts() {
    let engine = mem_engine();
    let board = two_accounts(&engine);
    let sub_account = a_sub_account_of_a(&engine, &board);
    grant_as(&engine, S, &sub_account.home, &board.draft_a, vec![board.acct_b.clone()]);
    grant_as(&engine, S, &sub_account.home, &board.draft_a, vec![]); // empty `to` ⟹ ANY-PRINCIPAL

    let w = world(&engine);
    assert!(w.readable(Some(S), &board.draft_a), "S reads A's draft by subtree — the premise");
    // Both records ARE admitted, so each probe reaches its issuer clause.
    assert_eq!(
        w.issuers_for(&board.acct_b),
        vec![IssuerGrant { issuer: &sub_account.acct, content_prefixes: vec![&board.draft_a] }],
        "S's named grant must enter the principal-exact index, or this proves nothing"
    );
    assert_eq!(
        w.universal_grants(),
        vec![UniversalGrant { content_prefix: &board.draft_a, issuers: vec![&sub_account.acct] }],
        "…and its ANY-PRINCIPAL grant the universal one"
    );
    assert!(
        !w.readable(Some(B), &board.draft_a),
        "the issuer (S) is not the draft's ω owner (A), so the named grant opens nothing"
    );
    assert!(
        !w.readable(Some(PrincipalId(9)), &board.draft_a),
        "…and neither does the ANY-PRINCIPAL one"
    );
    engine.check_hints().expect("the seed admits S's records as the fold did");
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
    let board = two_accounts(&engine);
    let link = grant_typed(
        &engine,
        A,
        &board.home_a,
        vec![board.draft_a.clone()],
        vec![board.acct_b.clone()],
        vec![t_grant(), t_edition()],
    );

    let w = world(&engine);
    assert!(
        w.links().readlink(&link).is_some(),
        "the deposit itself succeeds — the open surface fences neither class"
    );
    assert!(!w.readable(Some(B), &board.draft_a), "a dual-typed link is no grant record");
    assert!(w.issuers_for(&board.acct_b).is_empty(), "…and nothing of it entered the fold");
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
    let board = two_accounts(&engine);
    let link = grant_typed(
        &engine,
        A,
        &board.home_a,
        vec![board.draft_a.clone()],
        vec![board.acct_b.clone()],
        vec![t_grant_subtype()],
    );

    let w = world(&engine);
    assert!(w.links().readlink(&link).is_some(), "the deposit itself succeeds");
    assert!(!w.readable(Some(B), &board.draft_a), "a subtype-typed link is no grant record");
    assert!(w.issuers_for(&board.acct_b).is_empty(), "…and nothing of it entered the fold");
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
    let board = two_accounts(&engine);
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
        .create_new_document(A, &board.acct_a, None)
        .expect("A's second draft");

    // Two grantees in `to`, then two content-prefixes in `from` — each record
    // well-formed in every other respect, homed in A's published doc 1.
    grant_slots(
        &engine,
        A,
        &board.home_a,
        vec![board.draft_a.clone()],
        vec![board.acct_b.clone(), acct_c.clone()],
    );
    grant_slots(
        &engine,
        A,
        &board.home_a,
        vec![board.draft_a.clone(), draft_two.clone()],
        vec![board.acct_b.clone()],
    );

    // Every entitlement either record would have carried had its slot been
    // read one address at a time: both grantees of the first, both prefixes
    // of the second.
    let w = world(&engine);
    let carried = [(B, &board.draft_a), (PrincipalId(3), &board.draft_a), (B, &draft_two)];
    for (principal, doc) in carried {
        assert!(!w.readable(Some(principal), doc), "a malformed record opened {doc} to {principal:?}");
    }
    assert!(
        w.issuers_for(&board.acct_b).is_empty() && w.issuers_for(&acct_c).is_empty(),
        "neither malformed record entered the fold"
    );
    engine.check_hints().expect("the seed ignores them for the reason the fold did");
}

/// A `to` slot that is NOT EMPTY but denotes NO address is MALFORMED, never
/// the ANY-PRINCIPAL form: "empty" is the endset holding no span, not its
/// denoting none, and the two part on a resolved content RANGE — one span two
/// positions wide, which `Endset::addrs` skips. Read the other way, this
/// record grants the draft to every principal. Every other `to` slot in this
/// file is address-form, where the two readings agree.
#[test]
fn a_to_slot_that_is_not_empty_but_denotes_nothing_grants_to_nobody() {
    let engine = mem_engine();
    let board = two_accounts(&engine);
    let caller = Caller::Principal(A);
    engine
        .vstream()
        .insert(
            caller,
            &board.draft_a,
            vp(1, 1),
            vec![Val::new(vec![b'a']), Val::new(vec![b'b'])],
            Deposit::Undeclared,
        )
        .expect("the owner writes two values into its draft");
    let (link, _) = engine
        .linkstore(&World::visible_to(caller))
        .makelink(
            caller,
            &board.home_a,
            SlotArg::Addrs(vec![board.draft_a.clone()]),
            // TWO positions wide, so the resolved span is not unit-depth.
            SlotArg::Resolve(vec![vspec(&board.draft_a, 1, 2)]),
            SlotArg::Addrs(vec![t_grant()]),
        )
        .expect("a grant-typed record with a resolved `to` deposits");

    let w = world(&engine);
    let to = w.links().readlink(&link).expect("the record is resident").to_slot();
    // The premise, stated where it can fail: a `to` that denotes an address,
    // or holds no span, makes the two readings agree here.
    assert!(
        !to.is_empty() && to.addrs().next().is_none(),
        "the fixture must deposit a `to` that holds a span and denotes nothing: {to:?}"
    );
    assert!(w.universal_grants().is_empty(), "the record is no ANY-PRINCIPAL grant");
    assert!(w.issuers_for(&board.acct_b).is_empty(), "…nor a grant to anyone it names");
    assert!(
        !w.readable(Some(PrincipalId(9)), &board.draft_a),
        "so no principal reads the draft through it"
    );
    engine.check_hints().expect("the seed refuses it for the reason the fold did");
}

/// An address that stands OFF the ladder, built on a fresh board — one of the
/// vectors of [`a_grant_whose_from_stands_on_neither_rung_is_of_neither_kind`].
type OffTheLadder = fn(&Engine, &Board) -> skep_address::Address;

/// THE FROM's RUNG (PUB-5.15 as RES-252 leaves it; PUB-5.10's ladder): a
/// grant's `from` is a DOCUMENT or an ACCOUNT, and a record whose `from` is an
/// address of neither rung is of NEITHER KIND — it enters no index, so no row
/// of the universal set names a prefix the coverage test cannot cover, and no
/// board-wide face announces a share nobody holds. One vector per way of
/// standing off the ladder, each on its own board, each deposited in BOTH
/// forms — a named grantee, and the empty `to` that would have made it
/// universal — well-formed in every other respect and homed in A's published
/// doc 1:
///
/// * a VERSION MEMBER of the draft: a document-LEVEL address, which the read
///   predicate projects to its trunk before the grant clause walks up from
///   it, so no walk ever probes it;
/// * the NODE: an address that walk DOES reach. Until the rung was read, a
///   node-rung record from A opened every draft A owns — containment ∩ A's
///   own ω — though the ladder never held that rung; it opens nothing now;
/// * a LINK ADDRESS in A's own doc 1 that NO record occupies — RES-252's own
///   vector, an address-form slot taking no occupancy;
/// * a link address in A's own doc 1 that an ORDINARY link occupies: resident,
///   and no record of the class.
///
/// A link address that IS a record of the class from this home is the
/// earlier-record test's, and those vectors sit beside the revocation tests
/// below; one that is ANOTHER home's grant is
/// [`a_record_homed_elsewhere_revokes_no_grant_it_names`].
///
/// A standing universal grant of a SECOND draft is on every board, so what is
/// asserted of the universal set is that it is UNCHANGED, which an empty set
/// cannot tell from unread.
#[test]
fn a_grant_whose_from_stands_on_neither_rung_is_of_neither_kind() {
    let vectors: [(&str, OffTheLadder); 4] = [
        ("a version member", |_, board| {
            let member = validate(
                Tumbler::new(board.draft_a.tumbler().iter().cloned().chain([nat(1)]))
                    .expect("nonempty"),
            )
            .expect("a version member of a document is T4-valid");
            // The premise: a document-LEVEL address that is not its own trunk.
            assert_eq!(member.level(), Level::Document);
            assert_eq!(trunk_of(&member), board.draft_a, "the projection names the draft");
            member
        }),
        ("the node", |engine, board| {
            let node = node1();
            // The premise: the grant clause's ancestor walk reaches it.
            assert!(prefix_contains(&node, &board.draft_a), "the node contains A's draft");
            assert_eq!(
                world(engine).owner_account(&board.draft_a),
                Some(&board.acct_a),
                "…and A, the issuer, is that draft's ω owner"
            );
            node
        }),
        ("a link address no record occupies", |engine, board| {
            let vacant = element(&board.home_a, 2, 99);
            assert!(world(engine).links().readlink(&vacant).is_none(), "nothing was deposited there");
            vacant
        }),
        ("a link address an ordinary link occupies", |engine, board| {
            let ordinary = grant_typed(
                engine,
                A,
                &board.home_a,
                vec![board.draft_a.clone()],
                vec![board.acct_b.clone()],
                vec![t_edition()],
            );
            assert!(world(engine).links().readlink(&ordinary).is_some(), "the link is resident");
            ordinary
        }),
    ];

    for (what, off_the_ladder) in vectors {
        let engine = mem_engine();
        let board = two_accounts(&engine);
        let (draft_two, _) = engine
            .namespace()
            .create_new_document(A, &board.acct_a, None)
            .expect("A's second draft");
        grant(&engine, &board.home_a, &draft_two, vec![]); // the standing universal grant
        let from = off_the_ladder(&engine, &board);

        grant(&engine, &board.home_a, &from, vec![board.acct_b.clone()]);
        grant(&engine, &board.home_a, &from, vec![]); // empty `to` ⟹ ANY-PRINCIPAL

        let w = world(&engine);
        assert_eq!(
            w.universal_grants(),
            vec![UniversalGrant { content_prefix: &draft_two, issuers: vec![&board.acct_a] }],
            "{what}: the universal set is unchanged — no row names {from}"
        );
        assert!(
            w.issuers_for(&board.acct_b).is_empty(),
            "{what}: …and the named form entered the principal-exact index no more than that"
        );
        for principal in [B, PrincipalId(9)] {
            assert!(
                !w.readable(Some(principal), &board.draft_a),
                "{what}: a record of neither kind opened A's draft to {principal:?}"
            );
        }
        engine.check_hints().unwrap_or_else(|divergence| {
            panic!("{what}: the seed must refuse it for the reason the fold did: {divergence:?}")
        });
    }
}

/// …and the two rungs the ladder DOES hold admit as they always have: a `from`
/// at a DOCUMENT and a `from` at an ACCOUNT are GRANTS, each entering the
/// index its `to` names. The rung is read off the ADDRESS — arithmetic, no
/// registration read — so a sub-account prefix nobody delegated stands on the
/// account rung as a delegated one does
/// (`a_grant_names_an_address_the_client_invented` holds the same of a
/// document no mint produced).
#[test]
fn a_grant_at_a_document_and_at_an_account_stands_on_the_ladder() {
    let engine = mem_engine();
    let board = two_accounts(&engine);
    let undelegated = validate(
        Tumbler::new(board.acct_a.tumbler().iter().cloned().chain([nat(7)])).expect("nonempty"),
    )
    .expect("a sub-account prefix is T4-valid");
    assert_eq!(undelegated.level(), Level::Account, "an account-LEVEL address");
    assert!(!world(&engine).m3().is_allocated(&undelegated), "…that M3 never delegated");

    grant(&engine, &board.home_a, &board.draft_a, vec![]); // the DOCUMENT rung
    grant(&engine, &board.home_a, &board.acct_a, vec![board.acct_b.clone()]); // the ACCOUNT rung
    grant(&engine, &board.home_a, &undelegated, vec![]); // …by arithmetic alone

    let w = world(&engine);
    assert_eq!(
        w.universal_grants(),
        vec![
            UniversalGrant { content_prefix: &board.draft_a, issuers: vec![&board.acct_a] },
            UniversalGrant { content_prefix: &undelegated, issuers: vec![&board.acct_a] },
        ],
        "the document-rung grant, and the account-rung one over an undelegated prefix"
    );
    assert_eq!(
        w.issuers_for(&board.acct_b),
        vec![IssuerGrant { issuer: &board.acct_a, content_prefixes: vec![&board.acct_a] }],
        "the account-rung grant, held by the grantee it names"
    );
    assert!(w.readable(Some(PrincipalId(9)), &board.draft_a), "the document rung opens the draft");
    assert!(w.readable(Some(B), &board.draft_a), "…and so does the account rung, to its grantee");
    engine.check_hints().expect("the seed admits all three as the fold did");
}

/// Revocation by supersession (PUB-5.13): a later admitted grant naming the
/// earlier grant's own link address in `from` removes it.
#[test]
fn a_later_record_naming_a_grant_revokes_it() {
    let engine = mem_engine();
    let board = two_accounts(&engine);
    let g = grant(&engine, &board.home_a, &board.draft_a, vec![board.acct_b.clone()]);
    assert!(world(&engine).readable(Some(B), &board.draft_a), "granted");

    // A revoking record: `from` names the grant link itself.
    grant(&engine, &board.home_a, &g, vec![board.acct_b.clone()]);
    assert!(
        !world(&engine).readable(Some(B), &board.draft_a),
        "the later record naming the grant revoked it"
    );
}

/// …and a record naming a grant ALREADY WITHDRAWN is of NEITHER KIND (PUB-5.15,
/// RES-226): the revocation was the first one, and a second names the grant to
/// no effect. The shape is a blind retry of the revoke after a lost ack, and
/// its `to` is what made it dangerous. Read off the operative set — which the
/// withdrawn grant has LEFT — the retry names nothing the fold knows and falls
/// through to a FRESH GRANT over the grant's own link address: to the old
/// grantee where its `to` names one, to ANY-PRINCIPAL where its `to` is empty.
/// A universal share the issuer never made, permanent, and a row on every
/// board-wide face. Both forms of the retry are deposited here, and neither
/// enters an index: A RECORD THAT WITHDRAWS A SHARE NEVER BECOMES ONE.
///
/// Held TWICE, as
/// [`a_record_naming_a_revocation_is_of_neither_kind_and_lifts_no_withdrawal`]
/// and [`a_restart_keeps_the_earlier_records_a_later_record_is_classified_against`]
/// are: the earlier-record test decides each record, and the ladder would
/// refuse the link address in its `from` besides. No answer of the predicate
/// can part the two, so the fold's own unit tests pin the first on its own —
/// the key it keeps, and its turn ahead of the ladder.
#[test]
fn a_record_naming_a_withdrawn_grant_is_of_neither_kind() {
    let engine = mem_engine();
    let board = two_accounts(&engine);
    let g = grant(&engine, &board.home_a, &board.draft_a, vec![board.acct_b.clone()]);
    grant(&engine, &board.home_a, &g, vec![board.acct_b.clone()]); // the revocation
    assert!(!world(&engine).readable(Some(B), &board.draft_a), "revoked");

    // The retry, in both forms: `from` names the grant the first one withdrew.
    grant(&engine, &board.home_a, &g, vec![board.acct_b.clone()]);
    grant(&engine, &board.home_a, &g, vec![]); // empty `to` ⟹ ANY-PRINCIPAL, were it a grant

    let w = world(&engine);
    assert!(
        w.universal_grants().is_empty(),
        "the retry with an empty `to` became a universal grant over a link address: {:?}",
        w.universal_grants()
    );
    assert!(
        w.issuers_for(&board.acct_b).is_empty(),
        "the retry naming the old grantee became a grant to it: {:?}",
        w.issuers_for(&board.acct_b)
    );
    assert!(!w.readable(Some(B), &board.draft_a), "`grant_exists` stays false for the grantee");
    assert!(!w.readable(Some(PrincipalId(9)), &board.draft_a), "…and for every other principal");
    engine.check_hints().expect("the seed classifies both retries exactly as the fold did");
}

/// …and the REVOCATION test speaks before the `to` slot is read (the fold's
/// stated precedence): a revoking record whose `to` names TWO addresses still
/// revokes, though the same `to` on a FRESH grant makes it malformed and
/// grants to neither — which is
/// `a_grant_record_with_a_multi_address_slot_grants_nothing` above.
///
/// Both wrong readings land here, and the faithfulness check sees neither,
/// since one classification serves both halves of the discipline. A depositor
/// who takes the malformed rule to cover every slot believes this revocation
/// failed and the grantee still reads; the access was in fact withdrawn. A
/// maintainer who parses `to` ahead of the revocation branch turns the
/// deposit into a silent no-op and leaves a draft open to a grantee its owner
/// revoked.
#[test]
fn a_revoking_record_revokes_whatever_its_to_slot_holds() {
    let engine = mem_engine();
    let board = two_accounts(&engine);
    let g = grant(&engine, &board.home_a, &board.draft_a, vec![board.acct_b.clone()]);
    assert!(world(&engine).readable(Some(B), &board.draft_a), "granted");

    // The revoking record: `from` names the grant link, and `to` names two
    // addresses — the shape that makes a fresh grant malformed.
    grant_slots(
        &engine,
        A,
        &board.home_a,
        vec![g],
        vec![board.acct_b.clone(), board.acct_a.clone()],
    );

    let w = world(&engine);
    assert!(
        !w.readable(Some(B), &board.draft_a),
        "the `to` slot is unread on the revoking arm: a wide one revokes as any other does"
    );
    assert!(w.issuers_for(&board.acct_b).is_empty(), "…and the fold holds no record of the grant");
    engine.check_hints().expect("the seed classifies it exactly as the fold did");
}

/// THE S2-NAMES-S1 CELL (PUB-5.15, RES-226): a record whose `from` names a
/// REVOCATION is of NEITHER KIND. Read as "that record's supersession" it
/// would unseat S1 — superseded by a later admitted record from its own home —
/// and the grant S1 withdrew would stand again: `grant_exists` TRUE over a
/// share its issuer took back. Read off the operative set, where no revocation
/// ever sat, it lifts nothing and falls through to a fresh grant over S1's
/// link address instead. It is neither: S2 moves no honored state and enters
/// no index — and nor does S3, whose `from` names S2, a record ITSELF of
/// neither kind. A WITHDRAWAL, ONCE HONORED, IS LIFTED BY NOTHING; what the
/// issuer does to share again is grant again, which the last lines hold.
#[test]
fn a_record_naming_a_revocation_is_of_neither_kind_and_lifts_no_withdrawal() {
    let engine = mem_engine();
    let board = two_accounts(&engine);
    let g = grant(&engine, &board.home_a, &board.draft_a, vec![board.acct_b.clone()]);
    let s1 = grant(&engine, &board.home_a, &g, vec![board.acct_b.clone()]);
    assert!(!world(&engine).readable(Some(B), &board.draft_a), "S1 withdrew the grant");

    // S2 names S1 — in both forms, the empty `to` being the one that would
    // have made it universal — and S3 names S2.
    let s2 = grant(&engine, &board.home_a, &s1, vec![board.acct_b.clone()]);
    grant(&engine, &board.home_a, &s1, vec![]);
    grant(&engine, &board.home_a, &s2, vec![]);

    let w = world(&engine);
    assert!(
        !w.readable(Some(B), &board.draft_a),
        "a record naming the revocation lifted it: the withdrawn grant stands again"
    );
    assert!(
        w.universal_grants().is_empty() && w.issuers_for(&board.acct_b).is_empty(),
        "…and neither S2 nor S3 is a grant over the address it names: {:?} {:?}",
        w.universal_grants(),
        w.issuers_for(&board.acct_b)
    );
    engine.check_hints().expect("the seed classifies S2 and S3 exactly as the fold did");

    // Sharing again is a FRESH grant, and nothing above stands in its way.
    grant(&engine, &board.home_a, &board.draft_a, vec![board.acct_b.clone()]);
    assert!(world(&engine).readable(Some(B), &board.draft_a), "a later grant admits again");
}

/// …and what both vectors above are decided on is FOLD STATE, journaled
/// nowhere: a restart re-derives it off the grants class (PUB-7.7's seed
/// half), so a record deposited AFTER the restart that names a grant
/// withdrawn, or a revocation deposited, BEFORE it is of neither kind still.
/// The checkpoint sits at HEAD, so the reopened base IS the checkpoint and
/// nothing replays onto it: what the later deposits are classified against is
/// what the seed alone rebuilt.
#[test]
fn a_restart_keeps_the_earlier_records_a_later_record_is_classified_against() {
    let dir = tempdir().expect("tempdir");
    let (board, g, s1) = {
        let engine = Engine::open(fsync_cfg(dir.path())).expect("fsync open");
        let board = two_accounts(&engine);
        let g = grant(&engine, &board.home_a, &board.draft_a, vec![board.acct_b.clone()]);
        let s1 = grant(&engine, &board.home_a, &g, vec![board.acct_b.clone()]);
        assert!(!world(&engine).readable(Some(B), &board.draft_a), "live: S1 withdrew the grant");
        engine.kernel().checkpoint().expect("checkpoint at head");
        (board, g, s1)
    };

    let engine = Engine::open(fsync_cfg(dir.path())).expect("reopen over the checkpoint");
    assert!(!world(&engine).readable(Some(B), &board.draft_a), "recovered: still withdrawn");
    grant(&engine, &board.home_a, &g, vec![]); // names the withdrawn grant
    grant(&engine, &board.home_a, &s1, vec![]); // names the revocation

    let w = world(&engine);
    assert!(
        w.universal_grants().is_empty(),
        "a record the live fold would have refused became a universal grant after a restart: {:?}",
        w.universal_grants()
    );
    assert!(!w.readable(Some(B), &board.draft_a), "…and the withdrawal is lifted by neither");
    engine.check_hints().expect("the recovered fold equals a from-authoritative rebuild");
}

/// …and revocation reads the grants class of ONE HOME (PUB-5.13): a record
/// naming an earlier grant's link address from a home of its own is never a
/// revocation of what it names. Same home ⟹ same ω owner is the whole of the
/// issuer restriction, and without it any account could retire any other
/// account's grants by depositing one link in its own doc 1. Nor is it a
/// GRANT: the earlier-record test passes it by — what it names is no record of
/// ITS home — and the ladder then refuses it, a link address standing on
/// neither rung (PUB-5.15, RES-252). It is of NEITHER KIND, where it was once
/// a fresh grant of B's own over A's link address.
///
/// The predicate is the only witness. Both halves of the discipline drive one
/// classification, so a fold that dropped the home comparison and a seed that
/// dropped it agree with each other, and the faithfulness check stays green.
#[test]
fn a_record_homed_elsewhere_revokes_no_grant_it_names() {
    let engine = mem_engine();
    let board = two_accounts(&engine);
    let g = grant(&engine, &board.home_a, &board.draft_a, vec![board.acct_b.clone()]);
    assert!(world(&engine).readable(Some(B), &board.draft_a), "granted");

    // B's own published doc 1, and a record of B's naming A's grant.
    let (home_b, _) = engine
        .namespace()
        .create_new_document(B, &board.acct_b, None)
        .expect("B's published home");
    grant_as(&engine, B, &home_b, &g, vec![board.acct_b.clone()]);

    let w = world(&engine);
    assert!(
        w.readable(Some(B), &board.draft_a),
        "a record homed in B's doc 1 retired A's grant: any account could retire any other's"
    );
    assert_eq!(
        w.issuers_for(&board.acct_b),
        vec![IssuerGrant { issuer: &board.acct_a, content_prefixes: vec![&board.draft_a] }],
        "A's grant stands, and B's record — a link address in its `from` — is no grant of B's"
    );
    engine.check_hints().expect("both halves agree, which is why only the predicate sees this");
}

/// RETRACTION IS NOT REVOCATION (PUB-5.13): the fold has no nullification
/// arm, so a grant whose link a later `nullify` retracted still opens what it
/// granted, and only a revoking grant record takes it back. That is the
/// premise the seed's AUDIT view rests on — an active-view walk would drop
/// exactly this grant, and the recovered fold would differ from the live one
/// — so the check is the fold's own agreement with its seed, through the
/// dump's grant section.
#[test]
fn a_nullified_grant_still_opens_its_draft_and_the_audit_view_seed_agrees() {
    let engine = mem_engine();
    let board = two_accounts(&engine);
    let g = grant(&engine, &board.home_a, &board.draft_a, vec![board.acct_b.clone()]);
    assert!(world(&engine).readable(Some(B), &board.draft_a), "granted");

    let issuer = Caller::Principal(A);
    engine
        .linkstore(&World::visible_to(issuer))
        .nullify(issuer, &board.home_a, &g)
        .expect("the issuer retracts its own grant link");

    let w = world(&engine);
    assert!(w.links().is_nullified(&g), "the fixture must retract the grant link");
    assert!(
        w.readable(Some(B), &board.draft_a),
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
    let board = two_accounts(&engine);
    let old = grant(&engine, &board.home_a, &board.draft_a, vec![board.acct_b.clone()]);
    let new = grant(&engine, &board.home_a, &board.acct_a, vec![board.acct_b.clone()]);

    let issuer = Caller::Principal(A);
    engine
        .linkstore(&World::visible_to(issuer))
        .assert_sup(issuer, &board.home_a, &old, &new)
        .expect("the issuer claims its second grant supersedes its first");

    let w = world(&engine);
    let sup = w.links().reserved_type(ShippedType::Supersedes);
    assert_eq!(
        w.links().succs(sup, &old),
        vec![new.clone()],
        "the fixture must deposit an operative supersession claim over the grant"
    );
    assert_eq!(
        w.issuers_for(&board.acct_b),
        vec![IssuerGrant {
            issuer: &board.acct_a,
            content_prefixes: vec![&board.acct_a, &board.draft_a],
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
    let (draft_a, _acct_b) = {
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

    // Empty-map: a fresh engine's fold is empty — a private draft is readable
    // only by its owner subtree, never by a grant that does not exist.
    let fresh = mem_engine();
    let board = two_accounts(&fresh);
    assert!(
        !world(&fresh).readable(Some(B), &board.draft_a),
        "an empty fold grants nothing (PUB-7.68)"
    );
}

/// `Engine::world_at`'s POSTCONDITION — the returned world has been through
/// `rebuild_derived` — over the one base that gives it teeth: a CHECKPOINT,
/// which M2 decodes with the exception set and both grant indexes empty.
/// Every other reconstruction in this suite starts from genesis, whose derived
/// state is empty whether or not a rebuild ran, so a base selection that
/// skipped the rebuild on a checkpoint would pass all of them — and every
/// historical read would take the checkpoint's drafts for published and its
/// grants for ungiven.
#[test]
fn a_reconstruction_over_a_checkpoint_base_answers_its_drafts_and_grants() {
    let dir = tempdir().expect("tempdir");
    let engine = Engine::open(fsync_cfg(dir.path())).expect("fsync open");
    let board = two_accounts(&engine);
    grant(&engine, &board.home_a, &board.draft_a, vec![board.acct_b.clone()]);
    let base = engine.kernel().checkpoint().expect("the base the reconstruction starts from");
    // A commit above the base, so the reconstruction FOLDS onto it…
    let (later, past) =
        engine.namespace().create_new_document(A, &board.acct_a, None).expect("A's later draft");
    assert!(past > base, "the boundary sits above the checkpoint");
    // …and one above `past`, so the answer is the past and not the head.
    grant(&engine, &board.home_a, &later, vec![board.acct_b.clone()]);

    let w = engine.world_at(past).expect("a committed boundary answers");
    assert!(
        !w.readable(None, &board.draft_a),
        "the seeded exception set holds the checkpoint's draft"
    );
    assert!(!w.readable(None, &later), "…and the fold adds the one minted above it");
    assert_eq!(
        w.issuers_for(&board.acct_b),
        vec![IssuerGrant { issuer: &board.acct_a, content_prefixes: vec![&board.draft_a] }],
        "the grant fold is seeded from the checkpoint, and the grant above `past` is not in it"
    );
    assert!(w.readable(Some(B), &board.draft_a), "so the checkpoint's grant still opens its draft");
    engine.check_hints_of(&w).expect("the reconstruction's rendered hints match a rebuild");
}

/// The fold's two enumerations for the feed (lane 3.6 §3; PUB-7.22,
/// PUB-7.28): the LIVE ANY-PRINCIPAL set and a grantee's issuers with the
/// union of the prefixes their grants name — both read off the fold's own
/// indexes, both agreeing with the predicate they are the inside-out of, and
/// both moving with a revoking record at once (revocation is immediate,
/// PUB-7.23).
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
    let board = two_accounts(&engine);
    let (draft_two, _) = engine
        .namespace()
        .create_new_document(A, &board.acct_a, None)
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
    assert!(board.acct_a < acct_c, "the fixture wants A's account to sort before C's");
    assert!(board.draft_a < draft_two, "…and A's first draft before its second");

    // Empty fold: nothing enumerates.
    let w = world(&engine);
    assert!(w.universal_grants().is_empty(), "no universal grant yet");
    assert!(w.issuers_for(&board.acct_b).is_empty(), "B holds no grant yet");

    // C's deposits first, and within them the later prefix first — so every
    // list below is asserted in the reverse of the order it was written in.
    // C owns neither draft, so none of these opens anything; they are index
    // entries, which is what the enumerations answer with.
    grant_as(&engine, C, &home_c, &draft_two, vec![]);
    grant_as(&engine, C, &home_c, &draft_two, vec![board.acct_b.clone()]);
    grant_as(&engine, C, &home_c, &board.draft_a, vec![board.acct_b.clone()]);
    // Then A's: two to B — the draft and the whole account — and two
    // ANY-PRINCIPAL, the second draft before the first.
    grant(&engine, &board.home_a, &board.draft_a, vec![board.acct_b.clone()]);
    grant(&engine, &board.home_a, &board.acct_a, vec![board.acct_b.clone()]);
    let g_any = grant(&engine, &board.home_a, &draft_two, vec![]);
    grant(&engine, &board.home_a, &board.draft_a, vec![]);

    let w = world(&engine);
    assert_eq!(
        w.issuers_for(&board.acct_b),
        vec![
            IssuerGrant {
                issuer: &board.acct_a,
                content_prefixes: vec![&board.acct_a, &board.draft_a],
            },
            IssuerGrant { issuer: &acct_c, content_prefixes: vec![&board.draft_a, &draft_two] },
        ],
        "B's issuers in address order, each with the UNION of its prefixes in address order"
    );
    assert!(
        w.issuers_for(&board.acct_a).is_empty(),
        "the grantee side is principal-exact: A itself holds no grant"
    );
    assert_eq!(
        w.universal_grants(),
        vec![
            UniversalGrant { content_prefix: &board.draft_a, issuers: vec![&board.acct_a] },
            UniversalGrant { content_prefix: &draft_two, issuers: vec![&board.acct_a, &acct_c] },
        ],
        "the live any-principal set in prefix order, each issuer list in address order"
    );
    // …and each read's order IS its rows' own `Ord`: a row orders by the key
    // it is the one row for, so a caller that merges or re-sorts rows keeps
    // the order the read handed them back in.
    assert!(w.issuers_for(&board.acct_b).is_sorted(), "issuer rows order by issuer");
    assert!(w.universal_grants().is_sorted(), "any-principal rows order by prefix");
    // The enumerations are the predicate turned inside out — and an entry
    // whose issuer is not the document's owner is listed and opens nothing.
    assert!(w.readable(Some(B), &board.draft_a));
    assert!(w.readable(Some(PrincipalId(9)), &draft_two), "any principal reads draft two");
    assert!(!w.readable(None, &draft_two), "the guest never does");

    // A revoking record withdraws its grant from the enumeration at the commit
    // that carries it — no restart, no lag: A's entry leaves `draft_two`, C's
    // stays.
    grant(&engine, &board.home_a, &g_any, vec![]);
    let w = world(&engine);
    assert_eq!(
        w.universal_grants(),
        vec![
            UniversalGrant { content_prefix: &board.draft_a, issuers: vec![&board.acct_a] },
            UniversalGrant { content_prefix: &draft_two, issuers: vec![&acct_c] },
        ],
        "the revoked entry is gone at once, and only that entry"
    );
    assert!(
        !w.readable(Some(PrincipalId(9)), &draft_two),
        "and the predicate agrees: C's surviving entry is not the owner's"
    );
    assert_eq!(w.issuers_for(&board.acct_b).len(), 2, "B's grants are untouched by it");
}

/// Revoking the LAST issuer of an ANY-PRINCIPAL prefix removes the prefix's
/// ROW: the enumeration is the set of prefixes currently granted, and an empty
/// index means nothing granted. The feed test's revocation leaves a second
/// issuer behind, so it cannot see a row that outlived its issuers — and
/// neither can the predicate, since an empty issuer set opens nothing. The
/// daemon's feed can: it merges one term per listed prefix, per request.
#[test]
fn revoking_an_any_principal_prefix_s_last_issuer_removes_its_row() {
    let engine = mem_engine();
    let board = two_accounts(&engine);
    let g = grant(&engine, &board.home_a, &board.draft_a, vec![]); // empty `to` ⟹ ANY-PRINCIPAL
    let w = world(&engine);
    assert_eq!(
        w.universal_grants(),
        vec![UniversalGrant { content_prefix: &board.draft_a, issuers: vec![&board.acct_a] }],
        "the fixture must enter the universal index"
    );

    grant(&engine, &board.home_a, &g, vec![]); // the revoking record
    let w = world(&engine);
    assert!(
        w.universal_grants().is_empty(),
        "no live grant covers the prefix, so no row names it: {:?}",
        w.universal_grants()
    );
    assert!(!w.readable(Some(PrincipalId(9)), &board.draft_a), "and the predicate agrees");
    engine.check_hints().expect("the seed agrees over the revocation");
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
    let board = two_accounts(&engine);
    // Two grants, same issuer, same content-prefix, same grantee.
    let first = grant(&engine, &board.home_a, &board.draft_a, vec![board.acct_b.clone()]);
    let second = grant(&engine, &board.home_a, &board.draft_a, vec![board.acct_b.clone()]);
    assert_ne!(first, second, "two deposits, two link addresses");
    assert!(world(&engine).readable(Some(B), &board.draft_a), "granted twice");

    // Revoke the FIRST: a later record naming its link address.
    grant(&engine, &board.home_a, &first, vec![board.acct_b.clone()]);

    let w = world(&engine);
    assert!(
        !w.readable(Some(B), &board.draft_a),
        "the entry both grants contributed left with the one that was revoked"
    );
    assert!(w.issuers_for(&board.acct_b).is_empty(), "…and so did the feed's own read of it");
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
/// caller's own choice — before any clause has answered.
///
/// A deep VERSION MEMBER is the shape, because the projection is the one
/// step whose work follows the argument itself: `trunk_of` cuts the version
/// components off in one truncation, linear in the address's component count
/// (`World::readable`'s COST states the figure).
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
    let board = two_accounts(&engine);

    // A DOCUMENT address under A's account whose document field is a long run
    // of version components — T4-valid, registered nowhere, and never
    // reachable by any mint.
    let deep: skep_address::Address = {
        let comps = board
            .acct_a
            .tumbler()
            .iter()
            .cloned()
            .chain([nat(0)])
            .chain((0..64u32).map(|_| nat(1)));
        validate(Tumbler::new(comps).expect("nonempty")).expect("a document tier address is T4-valid")
    };
    // The premises, stated where they can fail: this must be a DOCUMENT — the
    // level whose version components the projection cuts off — carrying 63 of
    // them, so the cut is real work and not the identity; and it must be
    // unregistered, so no clause below the projection can refuse it first.
    assert_eq!(deep.level(), Level::Document);
    assert_eq!(
        deep.document_field().map(|field| field.len()),
        Some(64),
        "the document field is one ordinal and 63 version components"
    );
    assert!(
        !engine.kernel().snapshot().world().m3().is_registered_document(&deep),
        "the point is an address M3 never minted"
    );
    // …and the projection really does cut all of them off, answering the
    // account's own doc 1 — which is not this address.
    assert_eq!(trunk_of(&deep), addr(&[1, 0, 1, 0, 1]));

    let w = world(&engine);
    // The work is spent, and the address then reads as its trunk, A's
    // published home: at every class, for the guest that never authenticated
    // as much as for the owner. That answer is no witness to the projection —
    // the deep address is absent from the exception set too, and would read
    // readable without it — which is what
    // `a_version_member_shaped_address_under_a_draft_reads_as_the_draft` is for.
    assert!(w.readable(None, &deep), "its trunk is the published home, so every class reads it");
    assert!(w.readable(Some(A), &deep));
    assert!(w.readable(Some(B), &deep));
    // The registration check the contract puts AHEAD of the read is the
    // caller's, and no caller of this predicate can run it for free: M3's own
    // read answers the other way, so the deferral is a second walk and not a
    // cheaper first one.
    assert!(!w.m3().is_registered_document(&deep));
}

/// The PROJECTION, over the one shape where it moves an answer: an address
/// shaped as a VERSION MEMBER of a DRAFT reads as that draft — the guest and a
/// stranger refused, the owner admitted — though M3 never registered it.
/// Every registered version member carries its trunk's bit (PUB-8.17) and a
/// private document is versionless (PUB-2.9), so on a registered address the
/// projection never changes an answer; and the deep address of
/// `the_read_predicate_projects_an_address_the_client_invented` has a
/// PUBLISHED trunk, which reads readable either way. Without the projection
/// this address is absent from the exception set, and so fail-open to every
/// class.
#[test]
fn a_version_member_shaped_address_under_a_draft_reads_as_the_draft() {
    let engine = mem_engine();
    let board = two_accounts(&engine);
    let version_member = validate(
        Tumbler::new(board.draft_a.tumbler().iter().cloned().chain([nat(1)])).expect("nonempty"),
    )
    .expect("a version member of a document is T4-valid");
    assert_eq!(
        version_member.level(),
        Level::Document,
        "a version member is a document-tier address"
    );
    assert_eq!(trunk_of(&version_member), board.draft_a, "the projection names the draft");
    let w = world(&engine);
    assert!(!w.m3().is_registered_document(&version_member), "a private document is versionless");
    assert!(!w.readable(None, &version_member), "the guest reads it as the draft");
    assert!(!w.readable(Some(B), &version_member), "…and so does a stranger");
    assert!(w.readable(Some(A), &version_member), "while the owner reads it by the subtree clause");
}

/// `World::published`'s POSTCONDITION, held through the predicate M10's door
/// consults: an address NO MINT PRODUCED reads READABLE at every reader class
/// and at every tier, so a read arm's own `*NotRegistered` speaks and a
/// WITHHELD answer never names an address that does not exist (PUB-6.12 —
/// the obligation M10's `ReadableWorld` places on this implementer). M10's
/// own suite drives its door over a test world of its own, so the engine's
/// predicate is held here. The answer rides on the exception set answering
/// `true` for an address it never held — the postcondition a build answering
/// off M3's bit (PUB-7.69) must keep, since M3's own read answers `false`.
#[test]
fn an_address_no_mint_produced_reads_readable_at_every_class_and_tier() {
    let engine = mem_engine();
    let board = two_accounts(&engine);
    let never_minted = validate(
        Tumbler::new(board.acct_a.tumbler().iter().cloned().chain([nat(0), nat(99)]))
            .expect("nonempty"),
    )
    .expect("a document tier address is T4-valid");
    let w = world(&engine);
    for unregistered in [
        addr(&[9]),                   // a node no one registered
        addr(&[1, 0, 99]),            // an account no one delegated
        element(&never_minted, 1, 1), // an element of a document no one minted
        never_minted,                 // …and that document
    ] {
        assert!(!w.m3().is_allocated(&unregistered), "{unregistered}: no mint produced it");
        for principal in [None, Some(A), Some(B), Some(PrincipalId(9))] {
            assert!(
                w.readable(principal, &unregistered),
                "{unregistered} at {principal:?}: an unregistered address reads READABLE"
            );
        }
    }
}

/// ONE reader class, reused across documents of different owners, judges each
/// by that document's OWN owner: what `World::reader_class` binds is the
/// reader's SEAT, looked up once, and never a verdict. Asked of a seated
/// reader and of an unseated one, whose seat resolves to none and must still
/// reach the ANY-PRINCIPAL tier — an unseated principal is not the guest.
#[test]
fn one_reader_class_answers_each_document_by_its_own_owner() {
    let engine = mem_engine();
    let board = two_accounts(&engine);
    engine.namespace().create_new_document(B, &board.acct_b, None).expect("B's published home");
    let (draft_b, _) =
        engine.namespace().create_new_document(B, &board.acct_b, None).expect("B's private draft");

    let w = world(&engine);
    let reader = w.reader_class(Some(B));
    assert!(reader.readable(&board.home_a), "a published document, before any seat is looked up");
    assert!(reader.readable(&draft_b), "B's own draft, by the subtree clause");
    assert!(!reader.readable(&board.draft_a), "A's ungranted draft, through the SAME reader class");
    assert!(reader.readable(&draft_b), "B's draft again: the class held a seat, not a verdict");
    for doc in [&board.home_a, &draft_b, &board.draft_a] {
        assert_eq!(reader.readable(doc), w.readable(Some(B), doc), "{doc}: one predicate");
    }

    grant(&engine, &board.home_a, &board.draft_a, vec![]); // empty `to` ⟹ ANY-PRINCIPAL
    let w = world(&engine);
    const UNSEATED: PrincipalId = PrincipalId(9);
    assert!(
        w.m3().principal_prefix(UNSEATED).is_none(),
        "the fixture must leave this principal unseated, or it proves nothing about the tier"
    );
    let reader = w.reader_class(Some(UNSEATED));
    assert!(!reader.readable(&draft_b), "no seat and no grant: B's draft stays closed");
    assert!(
        reader.readable(&board.draft_a),
        "a seat of none still reaches A's ANY-PRINCIPAL grant"
    );
}
