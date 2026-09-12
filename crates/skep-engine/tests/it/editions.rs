//! The audit-view edition-claim lookup (PUB-8.46; PUB round 2, lane 3.4 §2)
//! through the assembled engine: `World::edition_claims` composes M7's audit
//! reads over the pinned edition class — a `to`-range lookup over ADMITTED,
//! UNSUPERSEDED claims WHETHER OR NOT RETRACTED, each row naming its home
//! (the edition) and stating its retraction. The home rule is M10's and the
//! wire shapes are the daemon's (their suites); what is tested here is the
//! CLASS the world answers, and that it is the class and nothing narrower.

use crate::common;

use common::*;
use skep_address::{document_of, parent, Address};
use skep_arrangement::{Caller, Deposit};
use skep_content::Val;
use skep_engine::{Engine, World};
use skep_febe::EditionClaim;
use skep_links::{enc, Endset, HasLinks, SlotArg, View};
use skep_namespace::{HasM3, PrincipalId, BOOTSTRAP_PRINCIPAL};

/// The EDITION class type address (commons-seeding.md row `3.14 | edition`
/// — OWNER CONFIRM OWED), as a client names it: `1.1.0.1.0.1.0.3.14`.
fn t_edition() -> Address {
    addr(&[1, 1, 0, 1, 0, 1, 0, 3, 14])
}

/// The `.2 expanded` descriptive subtype beneath it — a member by PREFIX.
fn t_edition_expanded() -> Address {
    addr(&[1, 1, 0, 1, 0, 1, 0, 3, 14, 2])
}

/// The GRANTS class — a foreign type, outside the edition class.
fn t_grant() -> Address {
    addr(&[1, 1, 0, 1, 0, 1, 0, 3, 90])
}

const A: PrincipalId = PrincipalId(1);

struct Board {
    /// A's published target document.
    target: Address,
    /// `target.1` — the target's first VERSION MEMBER, which is a version of
    /// the document and never a member of a class.
    version_member: Address,
    /// Two published editions — alike in every respect a test turns on.
    e1: Address,
    e2: Address,
    /// A third edition, PRIVATE: the one home a guest cannot read.
    draft_edition: Address,
    /// A second published TARGET, outside `target`'s subtree — so a claim
    /// denoting it is the `to`-range miss.
    other_target: Address,
}

fn board(engine: &Engine) -> Board {
    let ns = engine.namespace();
    let prefix =
        engine.kernel().snapshot().world().m3().next_account_prefix(&node1()).expect("prefix A");
    let (acct, _) = ns.delegate(BOOTSTRAP_PRINCIPAL, prefix.tumbler().clone(), A).expect("A");
    let mint = |flag: Option<bool>| ns.create_new_document(A, &acct, flag).expect("A mints").0;
    let _home = mint(None); // doc 1, born published
    let target = mint(Some(true));
    let e1 = mint(Some(true));
    let e2 = mint(Some(true));
    let draft_edition = mint(Some(false));
    let other_target = mint(Some(true));
    let (version_member, _) = engine
        .vstream()
        .version(A, &target, None)
        .unwrap_or_else(|_| panic!("a version of the published target mints"));
    Board { target, version_member, e1, e2, draft_edition, other_target }
}

/// Deposit a claim in `home`: `from` = the home (the edition), `to` = the
/// claimed target, `ty` = the type — address-form slots, MAKELINK's open
/// surface, exactly as a client deposits one.
fn claim(engine: &Engine, home: &Address, to: &Address, ty: &Address) -> Address {
    let caller = Caller::Principal(A);
    engine
        .linkstore(&World::visible_to(caller))
        .makelink(
            caller,
            home,
            SlotArg::Addrs(vec![home.clone()]),
            SlotArg::Addrs(vec![to.clone()]),
            SlotArg::Addrs(vec![ty.clone()]),
        )
        .map(|(addr, _)| addr)
        .unwrap_or_else(|_| panic!("the claim deposits into A's own edition"))
}

fn nullify(engine: &Engine, home: &Address, target: &Address) {
    let caller = Caller::Principal(A);
    engine
        .linkstore(&World::visible_to(caller))
        .nullify(caller, home, target)
        .unwrap_or_else(|_| panic!("the owner retracts its own claim"));
}

fn supersede(engine: &Engine, home: &Address, old: &Address, new: &Address) {
    let caller = Caller::Principal(A);
    engine
        .linkstore(&World::visible_to(caller))
        .assert_sup(caller, home, old, new)
        .unwrap_or_else(|_| panic!("the owner supersedes its own claim"));
}

fn world(engine: &Engine) -> World {
    engine.kernel().snapshot().world().clone()
}

fn row(claim: &Address, home: &Address, to: &Address, active: bool) -> EditionClaim {
    row_to(claim, home, enc([to]), active)
}

/// [`row`] where the `to` slot is not one address: the row carries the endset
/// AS DEPOSITED, so the wide-slot test states its whole expectation.
fn row_to(claim: &Address, home: &Address, to: Endset, active: bool) -> EditionClaim {
    EditionClaim { claim: claim.clone(), home: home.clone(), to, active }
}

/// Two editions claim the target, one through a subtype; the second is then
/// RETRACTED. The audit-view lookup lists BOTH, in link-address order, each
/// with its home and its retraction stated — where M7's active view holds
/// one. The subtype's claim is in the class by prefix.
#[test]
fn the_lookup_lists_the_class_s_claims_retracted_or_not_with_their_homes() {
    let engine = mem_engine();
    let b = board(&engine);
    let c1 = claim(&engine, &b.e1, &b.target, &t_edition());
    let c2 = claim(&engine, &b.e2, &b.target, &t_edition_expanded());
    nullify(&engine, &b.e2, &c2);

    let w = world(&engine);
    assert_eq!(
        w.edition_claims(&b.target),
        vec![row(&c1, &b.e1, &b.target, true), row(&c2, &b.e2, &b.target, false)],
        "both claims, homes named, the retraction stated"
    );
    // The active view — what a result-set read answers — holds one.
    let links = w.links();
    assert!(links.is_active(&c1) && !links.is_active(&c2));
    let active = links.type_slice(&enc([&t_edition()]), View::Active);
    assert!(active.contains(&c1) && !active.contains(&c2), "M7's active view lists one: {active:?}");
}

/// The class and nothing narrower or wider: a claim SUPERSEDED through the
/// managed class (D4, PUB-6.32) leaves the answer; a claim of a FOREIGN type
/// on the same target never enters it.
#[test]
fn a_superseded_claim_and_a_foreign_type_leave_the_class() {
    let engine = mem_engine();
    let b = board(&engine);
    let old = claim(&engine, &b.e1, &b.target, &t_edition());
    let new = claim(&engine, &b.e1, &b.target, &t_edition());
    let foreign = claim(&engine, &b.e1, &b.target, &t_grant());
    supersede(&engine, &b.e1, &old, &new);

    let w = world(&engine);
    let rows = w.edition_claims(&b.target);
    assert_eq!(rows, vec![row(&new, &b.e1, &b.target, true)], "{rows:?}");
    assert!(w.links().is_active(&old), "the superseded claim is still active — it is D4 that retires it");
    assert!(w.links().readlink(&foreign).is_some(), "the foreign-typed link is resident, and not in the class");
}

/// Class MEMBERSHIP is over EVERY denoted address: a type slot naming the
/// edition class AND a foreign class is no member, though it OVERLAPS the
/// class range and the `to`-range lookup does return it for judgement. The
/// wholly foreign type above never reaches the membership test at all — it
/// sits outside the range, so the lookup never hands it over — which is why
/// the quantifier takes a claim of its own.
#[test]
fn a_type_slot_denoting_the_class_and_a_foreign_class_is_no_member() {
    let engine = mem_engine();
    let b = board(&engine);
    let good = claim(&engine, &b.e1, &b.target, &t_edition());
    let caller = Caller::Principal(A);
    let (dual, _) = engine
        .linkstore(&World::visible_to(caller))
        .makelink(
            caller,
            &b.e2,
            SlotArg::Addrs(vec![b.e2.clone()]),
            SlotArg::Addrs(vec![b.target.clone()]),
            SlotArg::Addrs(vec![t_edition(), t_grant()]),
        )
        .unwrap_or_else(|_| panic!("a dual-typed link deposits through the open surface"));

    let w = world(&engine);
    assert_eq!(
        w.edition_claims(&b.target),
        vec![row(&good, &b.e1, &b.target, true)],
        "a slot that merely overlaps the class range is no member of it"
    );
    assert!(
        w.links().readlink(&dual).is_some(),
        "the dual-typed link is resident, and not in the class"
    );
}

/// A DRAFT edition's claim is in the class the world answers — the world
/// answers the class, unfiltered — and its home is unreadable to the guest,
/// which is the row M10's home rule drops for a stranger and keeps for the
/// owner (the daemon's suite drives that over the wire).
#[test]
fn a_draft_edition_s_claim_is_in_the_class_the_world_answers() {
    let engine = mem_engine();
    let b = board(&engine);
    let c3 = claim(&engine, &b.draft_edition, &b.target, &t_edition());
    let w = world(&engine);
    assert_eq!(w.edition_claims(&b.target), vec![row(&c3, &b.draft_edition, &b.target, true)]);
    assert!(
        !w.readable(None, &b.draft_edition),
        "the draft edition is the home the guest cannot read"
    );
    assert!(w.readable(Some(A), &b.draft_edition), "…and the owner can");
}

/// The `to`-RANGE is the target's subtree: a claim denoting the target's
/// VERSION answers for the document (containment) and for the version member;
/// a claim on the document answers for its version member too (the document's
/// subtree contains the member's); a claim on another document never answers
/// for this one, and answers for its own.
#[test]
fn the_to_range_is_the_target_s_subtree() {
    let engine = mem_engine();
    let b = board(&engine);
    let on_doc = claim(&engine, &b.e1, &b.target, &t_edition());
    let on_member = claim(&engine, &b.e2, &b.version_member, &t_edition());
    let on_other = claim(&engine, &b.e1, &b.other_target, &t_edition());

    let w = world(&engine);
    assert_eq!(
        w.edition_claims(&b.target),
        vec![row(&on_doc, &b.e1, &b.target, true), row(&on_member, &b.e2, &b.version_member, true)],
        "the document names every claim denoting it or a version of it"
    );
    assert_eq!(
        w.edition_claims(&b.version_member),
        vec![row(&on_doc, &b.e1, &b.target, true), row(&on_member, &b.e2, &b.version_member, true)],
        "a version member names the claims denoting it and those denoting its document"
    );
    assert_eq!(w.edition_claims(&b.other_target), vec![row(&on_other, &b.e1, &b.other_target, true)]);
    assert!(w.edition_claims(&b.e1).is_empty(), "an edition is claimed by nothing");
}

/// The `to` test is M7's OVERLAP regime and NOT denotation — and this is the
/// one shape where the two readings part. A slot resolved over a RANGE of the
/// target's content is a single non-unit span: it lies inside the target's
/// subtree, so it overlaps, and it denotes NO address at all, so a denotation
/// reading returns nothing. Every other claim in this file carries
/// address-form slots, where the two readings agree on every row.
///
/// The distinction is the containment the lookup exists for, and it is what
/// M10's `PublicationWorld::edition_claims` describes the other way round. A
/// narrowing of this side to match that text drops a whole class of claim
/// from every reader's answer, and this is the row that would go with it.
#[test]
fn a_to_slot_that_denotes_nothing_under_the_target_is_still_a_row() {
    let engine = mem_engine();
    let b = board(&engine);
    let caller = Caller::Principal(A);
    // Claimed here is `other_target`, the published document with NO version:
    // a declared deposit into a published document lands in its HEAD member's
    // arrangement (PUB-2.66), and this one is its own head, so the content it
    // takes is content the resolve below can name in its own V-space.
    engine
        .vstream()
        .insert(
            caller,
            &b.other_target,
            vp(1, 1),
            vec![Val::new(vec![b'a']), Val::new(vec![b'b'])],
            Deposit::Declared,
        )
        .unwrap_or_else(|_| panic!("a declared deposit at fresh positions (PUB-2.59)"));
    let (ranged, _) = engine
        .linkstore(&World::visible_to(caller))
        .makelink(
            caller,
            &b.e1,
            SlotArg::Addrs(vec![b.e1.clone()]),
            // TWO positions wide, so the resolved span is not unit-depth.
            SlotArg::Resolve(vec![vspec(&b.other_target, 1, 2)]),
            SlotArg::Addrs(vec![t_edition()]),
        )
        .unwrap_or_else(|_| panic!("a claim over a RANGE of the target's content deposits"));

    let w = world(&engine);
    let rows = w.edition_claims(&b.other_target);
    assert_eq!(rows.len(), 1, "the ranged claim is a row of the target's class: {rows:?}");
    assert_eq!(rows[0].claim, ranged);
    assert_eq!(rows[0].home, b.e1);
    // The premise, stated where it can fail: this slot must DENOTE nothing,
    // or the two readings agree here and the test says nothing about either.
    assert!(
        rows[0].to.addrs().next().is_none(),
        "the fixture must deposit a `to` slot that denotes no address: {:?}",
        rows[0].to
    );
    assert!(!rows[0].to.is_empty(), "…while still covering the target's own subtree");
}

/// The COST paragraph's BREADTH term, pinned: the lookup ranges over
/// `target`'s whole subtree and restricts `target`'s LEVEL nowhere, so a NODE
/// address — three components, the genesis node — answers with every edition
/// claim under it, across accounts and documents alike. What bounds this read
/// is the store's size and not the request's.
#[test]
fn the_lookup_ranges_over_whatever_tier_the_caller_names() {
    let engine = mem_engine();
    let b = board(&engine);
    let on_doc = claim(&engine, &b.e1, &b.target, &t_edition());
    let on_member = claim(&engine, &b.e2, &b.version_member, &t_edition());
    let on_other = claim(&engine, &b.e1, &b.other_target, &t_edition());

    let w = world(&engine);
    // The account tier: every claim on any document A owns.
    let account = document_of(&b.target).and_then(|d| parent(&d)).expect("the target's account");
    // …in LINK-address order, so e1's two claims precede e2's one whatever
    // the documents they name.
    assert_eq!(
        w.edition_claims(&account),
        vec![
            row(&on_doc, &b.e1, &b.target, true),
            row(&on_other, &b.e1, &b.other_target, true),
            row(&on_member, &b.e2, &b.version_member, true),
        ],
        "an account address ranges over every document under it"
    );
    // …and the NODE tier answers the same set, from an address of three
    // components that names no document at all.
    assert_eq!(
        w.edition_claims(&node1()),
        w.edition_claims(&account),
        "the genesis node ranges over every account under it: the whole store"
    );
    assert!(document_of(&node1()).is_none(), "the node names no document, and is not refused");
}

/// …and the ANSWER's size is the DEPOSITOR's, not the request's: a row
/// matched on one address carries its `to` endset AS DEPOSITED, so a claim
/// naming the target among many addresses hands the whole slot back to a
/// caller that asked after one. The cost paragraph's third term.
#[test]
fn a_row_carries_the_to_slot_as_deposited_however_wide() {
    let engine = mem_engine();
    let b = board(&engine);
    let caller = Caller::Principal(A);
    // A `to` slot naming the target and 63 ghost addresses of the edition's
    // own never-minted subspace 3 — one address of the request, 64 of the
    // answer.
    let mut to: Vec<Address> = vec![b.target.clone()];
    to.extend((1..64u32).map(|n| element(&b.e1, 3, n)));
    let (wide, _) = engine
        .linkstore(&World::visible_to(caller))
        .makelink(
            caller,
            &b.e1,
            SlotArg::Addrs(vec![b.e1.clone()]),
            SlotArg::Addrs(to.clone()),
            SlotArg::Addrs(vec![t_edition()]),
        )
        .unwrap_or_else(|_| panic!("a wide-slotted claim deposits through the open surface"));

    let w = world(&engine);
    let rows = w.edition_claims(&b.target);
    assert_eq!(rows, vec![row_to(&wide, &b.e1, enc(to.iter()), true)], "{rows:?}");
    assert_eq!(
        rows[0].to.len(),
        64,
        "the row carries every span deposited, for a request that named one address"
    );
}
