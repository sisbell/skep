//! The three publication reads — the reads M10 composes rather than forwards
//! (PUB-8.12, PUB-8.46, PUB-8.47) — over the public surface: the doc-metadata
//! read answers what a client admits an edition by, its birth version checked
//! against the address `Op::Version` minted; the two reads that take a
//! document demand a registered DOCUMENT and refuse every other tier, ahead of
//! the edition-claim lookup; the three-valued publication flag reaches the
//! store unresolved, each explicit arm as sent; and the any-principal read
//! hands a client the answer set and never the index — every served row
//! carrying the one issuer ω answers for its prefix, the guest answered empty
//! without the index being walked, which a principal's answer walks once.

use std::collections::BTreeSet;

use crate::common;

use common::*;
use skep_febe::{Op, RejectCode, SessionId, UniversalGrant, UniversalIndexRow};
use skep_namespace::{PrincipalId, BOOTSTRAP_PRINCIPAL};

/// The two publication reads that take a document (PUB-8.12, PUB-8.46),
/// payload and all.
///
/// The birth version is ONE value, and both halves of it are load-bearing.
/// Its address is a RECONSTRUCTION of M3's version-chain encoding, which
/// fails SILENTLY if that encoding moves — a wrong `D.1` is a well-formed
/// address whose content count is `0` — so the answer is checked against the
/// address `Op::Version` actually minted, and its extent against the content
/// that version shares. A document whose chain has no member reports no
/// birth at all: absent, never zero, which is why the two travel together.
#[test]
fn the_publication_reads_answer_the_metadata_a_client_admits_an_edition_by() {
    let fx = setup();

    // A draft with no chain member: private, owned, and unborn.
    let draft = create_doc(&fx);
    let (doc, published, owner, birth) =
        doc_metadata(ex(&fx.febe, fx.user, Op::DocMetadata { doc: draft.clone() }));
    assert_eq!(doc, draft);
    assert!(!published, "an explicit-`false` mint is a draft");
    assert_eq!(owner.expect("ω is total over the registered space"), fx.account);
    assert!(birth.is_none(), "no member, so no extent is read: absent, not zero");

    // A published edition with three deposited positions, versioned once.
    let edition = create_edition(&fx);
    deposit3(&fx, &edition);
    let (member, _) =
        ack_addr(ex(&fx.febe, fx.user, Op::Version { d_src: edition.clone(), published: None }));

    let (doc, published, _, birth) =
        doc_metadata(ex(&fx.febe, fx.user, Op::DocMetadata { doc: edition.clone() }));
    assert_eq!(doc, edition);
    assert!(published);
    let birth = birth.expect("a document whose chain has a member reports its birth version");
    assert_eq!(
        birth.addr, member,
        "the reported `D.1` is the address the first `version` minted — the one check that \
         catches a reconstruction which has fallen out of step with M3's encoding"
    );
    assert_eq!(birth.extent, nat(3), "the birth extent PUB-3.19's edition test images over");

    // A VERSION MEMBER answers its DOCUMENT's state (PUB-2.15), birth included.
    let (doc, published, _, birth) =
        doc_metadata(ex(&fx.febe, fx.user, Op::DocMetadata { doc: member.clone() }));
    assert_eq!(doc, edition, "the argument projects to its trunk document");
    assert!(published);
    assert_eq!(birth.expect("the document's own birth").addr, member);

    // The audit-view lookup answers the class its world composes — this
    // miniature world carries no edition type, so the class is empty — and
    // both reads refuse an unregistered argument rather than inventing one.
    assert!(
        edition_claims(ex(&fx.febe, fx.user, Op::EditionClaims { target: edition })).is_empty()
    );
    let ghost = addr(&[1, 0, 1, 0, 91]);
    for op in [Op::DocMetadata { doc: ghost.clone() }, Op::EditionClaims { target: ghost }] {
        let kind = op.kind();
        let rej = rejected(ex(&fx.febe, fx.user, op));
        assert_eq!(rej.code, RejectCode::DocNotRegistered, "{kind:?}");
    }
}

/// PUB-8.46 and the registration refusal M10 ORIGINATES: the two publication
/// reads that take a document — the only reads whose registration refusal
/// comes from no store — demand a registered DOCUMENT, and the TIER half of
/// that demand is what bounds the edition-claim seam, since the world narrows
/// its `to` range by no level: an account-tier target would ask after every
/// document under it and a node-tier one after the whole store. A registered
/// account, the genesis node and a content element are refused exactly as an
/// unregistered document is, and the registered document beside them is
/// answered. And the refusal comes BEFORE the lookup: the test world's
/// `edition_claims` refuses to answer a target that is not a registered
/// document — the precondition the seam lets an implementer assume — so a
/// front door that asked first and refused after fails here, in the double.
#[test]
fn doc_metadata_and_edition_claims_demand_a_registered_document_not_merely_an_entity() {
    let fx = setup();
    let d = create_doc(&fx);
    let (element, _) = insert3(&fx, &d);
    let ghost = ghost_doc(&fx.account, 91);

    for named in [&fx.account, &node1(), &element, &ghost] {
        for op in [
            Op::DocMetadata { doc: named.clone() },
            Op::EditionClaims { target: named.clone() },
        ] {
            let kind = op.kind();
            let rej = rejected(ex(&fx.febe, fx.user, op));
            assert_eq!(rej.op, kind);
            assert_eq!(rej.code, RejectCode::DocNotRegistered, "{kind:?} on {named:?}");
        }
    }
    // The registered document beside them is answered, so the eight refusals
    // are about the ARGUMENT and not about the reads being broken.
    assert_eq!(doc_metadata(ex(&fx.febe, fx.user, Op::DocMetadata { doc: d.clone() })).0, d);
    assert!(edition_claims(ex(&fx.febe, fx.user, Op::EditionClaims { target: d })).is_empty());
}

/// PUB-8.16 / PUB-8.21: the three-valued flag rides through UNRESOLVED — M10
/// decides nothing about it, and M3's create path resolves the absent arm. A
/// fresh account's FIRST flagless mint is born PUBLISHED and the next is
/// private, which an M10 that collapsed absent to the wire default could not
/// produce. FORK reduces to a create in the caller's OWN account and resolves
/// the same flag at the same path.
#[test]
fn the_absent_publication_flag_reaches_the_store_unresolved() {
    let fx = setup();
    let published_of = |doc: skep_address::Address| {
        doc_metadata(ex(&fx.febe, fx.user, Op::DocMetadata { doc })).1
    };
    let flagless = || Op::CreateNewDocument { account: fx.account.clone(), published: None };

    let (first, _) = ack_addr(ex(&fx.febe, fx.user, flagless()));
    assert!(
        published_of(first),
        "the account's first flagless mint is born published (PUB-8.21)"
    );
    let (second, _) = ack_addr(ex(&fx.febe, fx.user, flagless()));
    assert!(!published_of(second), "every later flagless mint is private (PUB-1.1)");

    // A principal whose account is empty forks that account's published home.
    let (prefix, _) = maybe_addr(ex(&fx.febe, fx.boot, Op::NextAccountPrefix { parent: node1() }));
    ack_addr(ex(
        &fx.febe,
        fx.boot,
        Op::Delegate {
            new_prefix: prefix.expect("a second delegable prefix").tumbler().clone(),
            new_id: PrincipalId(21),
        },
    ));
    let fresh = fx.febe.open_session(PrincipalId(21));
    let (home, _) = ack_addr(ex(&fx.febe, fresh, Op::Fork { published: None }));
    assert!(
        doc_metadata(ex(&fx.febe, fresh, Op::DocMetadata { doc: home })).1,
        "a fork into an empty account mints that account's published home"
    );
}

/// PUB-8.16 on FORK's EXPLICIT arms: the flag rides through verbatim, and
/// M3's create path honors it as sent. Each cell is one where the explicit
/// flag and the ABSENT one disagree, so a fork that dropped or defaulted the
/// flag answers the other bit — `Some(true)` into an account that already
/// has a document mints a PUBLISHED one where absent mints a draft;
/// `Some(false)` as an empty account's first mint mints a DRAFT where absent
/// mints the published home. (The daemon refuses that explicit-false first
/// mint, PUB-8.20; below the daemon it mints, which is what makes the cell
/// observable here.)
#[test]
fn an_explicit_fork_flag_reaches_the_store_verbatim() {
    let fx = setup();
    let published_of = |session: SessionId, doc: skep_address::Address| {
        doc_metadata(ex(&fx.febe, session, Op::DocMetadata { doc })).1
    };
    let _ = create_doc(&fx); // the account is no longer empty
    let (fork, _) = ack_addr(ex(&fx.febe, fx.user, Op::Fork { published: Some(true) }));
    assert!(published_of(fx.user, fork), "Some(true) into a non-empty account: published");

    let (prefix, _) = maybe_addr(ex(&fx.febe, fx.boot, Op::NextAccountPrefix { parent: node1() }));
    ack_addr(ex(
        &fx.febe,
        fx.boot,
        Op::Delegate {
            new_prefix: prefix.expect("a second delegable prefix").tumbler().clone(),
            new_id: PrincipalId(22),
        },
    ));
    let fresh = fx.febe.open_session(PrincipalId(22));
    let (first, _) = ack_addr(ex(&fx.febe, fresh, Op::Fork { published: Some(false) }));
    assert!(!published_of(fresh, first), "Some(false) as the first mint: a draft, not the home");
}

/// The any-principal read's served guarantee (PUB-8.47; RES-231, RES-298),
/// asked of the registry through the surface's own owner-of-address read:
/// every served row carries ONE issuer, and it is the seat ω answers for the
/// row's prefix — the answer set, never the index. Vacuous over no rows.
fn assert_served_rows_are_omega_owned(fx: &Fixture, served: &[UniversalGrant]) {
    for r in served {
        let seat =
            effective_owner(ex(&fx.febe, fx.user, Op::EffectiveOwner { addr: r.prefix.clone() }))
                .map(|(seat, _)| seat);
        assert_eq!(r.issuers.len(), 1, "ω is a function: one issuer per served row, {r:?}");
        for issuer in &r.issuers {
            assert_eq!(
                seat.as_ref(),
                Some(issuer),
                "{issuer} does not ω-own {}: the row is the index, not the answer",
                r.prefix
            );
        }
    }
}

/// THE ANY-PRINCIPAL DISCOVERY READ (PUB-8.47) over the surface: the world
/// hands M10 the fold's live universal INDEX, raw, and M10 serves the ANSWER
/// SET — never the index (RES-258). Seeded RAW through the miniature world, so
/// what is exercised is the door's own narrowing (RES-231, RES-264, RES-273,
/// RES-298) and the ruled shape (RES-224), nothing of the engine's fold. THE
/// COMPARE IS ω's, so `X.1` and `Y` are REGISTERED — by the surface's own
/// `delegate` — for the registry to answer them: a stored prefix ω answers
/// the issuer for is served unchanged; one WIDER than the issuer's account
/// (an agent's share over its hirer's prefix) is served as the issuer's own
/// account; a hirer's share over its registered sub-account is NO row, the
/// issuer not the owner, and neither is a stranger's record over a
/// stranger's document — each dropped issuer by issuer, while the record
/// stands in the index; rows GROUP by the served prefix — two stored rows
/// narrowing to one — in prefix order, and every served row carries ONE
/// issuer, the seat ω answers for its prefix. The GUEST is answered EMPTY, an
/// answer and never a refusal (PUB-5.109); every bound principal, the same
/// rows; and nothing is consulted, there being no document argument.
#[test]
fn the_any_principal_discovery_read_hands_a_client_the_answer_set_never_the_index() {
    let fx = setup();
    let read = |session| universal_grants(ex(&fx.febe, session, Op::UniversalGrants));
    let sub = |a: &skep_address::Address, k: u32| -> skep_address::Address {
        let comps = a.tumbler().iter().cloned().chain([nat(k)]);
        skep_address::validate(skep_address::Tumbler::new(comps).expect("nonempty"))
            .unwrap_or_else(|_| panic!("a sub-account of a T4-valid account is T4-valid"))
    };

    // The empty index: zero rows, as_of the head — the shape, not a refusal.
    let r = ex(&fx.febe, fx.user, Op::UniversalGrants);
    assert_eq!(as_of(&r), fx.febe.log_position());
    assert!(universal_grants(r).is_empty(), "no universal grant stands");

    // X, the fixture's account; X.1 beneath it (the agent space); Y, a
    // stranger's account, disjoint from both; and documents under each. X.1
    // and Y are SEATED, each by a `delegate`, so ω answers them: the compare
    // is the registry's (RES-298), and an unseated X.1 would answer X.
    let x = fx.account.clone();
    let x1 = sub(&x, 1);
    ack_addr(ex(
        &fx.febe,
        fx.user,
        Op::Delegate { new_prefix: x1.tumbler().clone(), new_id: PrincipalId(31) },
    ));
    let (y, _) = maybe_addr(ex(&fx.febe, fx.boot, Op::NextAccountPrefix { parent: node1() }));
    let y = y.expect("a second top-level account is delegable");
    ack_addr(ex(
        &fx.febe,
        fx.boot,
        Op::Delegate { new_prefix: y.tumbler().clone(), new_id: PrincipalId(21) },
    ));
    assert!(!x.tumbler().to_string().starts_with(&y.tumbler().to_string()));
    let dx = ghost_doc(&x, 5); // X's document
    let dx1 = ghost_doc(&x1, 1); // X.1's document
    let dy = ghost_doc(&y, 1); // Y's document
    let dy2 = ghost_doc(&y, 2); // another of Y's

    // Two row types, one per side of the seam.
    let stored_row = |content_prefix: &skep_address::Address, issuers: &[&skep_address::Address]| {
        UniversalIndexRow {
            content_prefix: content_prefix.clone(),
            issuers: issuers.iter().map(|a| (*a).clone()).collect(),
        }
    };
    let served_row = |prefix: &skep_address::Address, issuers: &[&skep_address::Address]| {
        UniversalGrant {
            prefix: prefix.clone(),
            issuers: issuers.iter().map(|a| (*a).clone()).collect(),
        }
    };
    // The STORED index, deliberately out of prefix order: what each row
    // narrows to is stated beside it.
    seed_universal_grant_index(vec![
        stored_row(&x, &[&x1]),      // RES-264: X.1's share over X, wider ⇒ served at X.1
        stored_row(&dy, &[&x, &y]),  // RES-231: X's record over Y's document ⇒ X dropped; Y's stands
        stored_row(&dx1, &[&x1]),    // ω answers X.1 for its own document ⇒ unchanged
        stored_row(&x1, &[&x, &x1]), // RES-298: X's share over its SEATED X.1 ⇒ X dropped; X.1's own stands
        stored_row(&dy2, &[&x1]),    // X.1's record over Y's other document ⇒ no row at all
        stored_row(&dx, &[&x]),      // ω answers X for its own document ⇒ unchanged
    ]);

    let served = read(fx.user);
    assert_eq!(
        served,
        vec![
            served_row(&dx, &[&x]),
            served_row(&x1, &[&x1]),
            served_row(&dx1, &[&x1]),
            served_row(&dy, &[&y]),
        ],
        "the answer set: covered prefixes, grouped, in prefix order"
    );
    assert!(served.is_sorted_by_key(|r| r.prefix.clone()), "prefix order");
    assert!(served.iter().all(|r| r.prefix != dy2), "a disjoint pair contributes no row");
    // RES-231 and RES-298 in one sentence: the served set never names an
    // issuer who is not the owner, whatever the index holds.
    assert_served_rows_are_omega_owned(&fx, &served);

    // THE GUEST is answered EMPTY, never refused (PUB-5.109); a SECOND bound
    // principal is handed the same rows: the set is a board population, not
    // the requester's.
    let r = ex(&fx.febe, SessionId::GUEST, Op::UniversalGrants);
    assert_eq!(as_of(&r), fx.febe.log_position(), "an answer, stamped like any read");
    assert!(universal_grants(r).is_empty(), "the guest is outside every grant");
    let other = fx.febe.open_session(OTHER);
    assert_eq!(read(other), served, "every bound principal, the same rows");

    // Nothing is consulted: a document this world refuses to every principal
    // but USER changes no answer, the read naming no document.
    seed_unreadable_world(vec![dx.clone(), dx1.clone(), dy.clone()]);
    assert_eq!(read(other), served, "no document argument, so no consult and nothing withheld");
}

/// THE WIDER ARM's "AND IS NOT IT" (PUB-8.47; RES-298): the served prefix is
/// the issuer's own account where the stored prefix CONTAINS that account and
/// is not it — and the second half is what this pins, at the one cell it
/// bites: an issuer that is NO SEAT. The engine's fold cannot mint one (its
/// issuer is ω of the grant's home, a seat by construction), so the row is
/// seeded RAW, as the vector above seeds its own: `(Z, [Z])` over a top-level
/// `Z` no `delegate` has seated, which ω answers the NODE for. The exact arm
/// passes the pair by, ω not answering `Z`; containment ALONE would serve it
/// — `Z` contains `Z` — as `(Z, [Z])`, an issuer the registry seats nowhere
/// listed as the owner of what is the node's; "and is not it" makes the pair
/// NO row. The check is `assert_served_rows_are_omega_owned` — vacuous over
/// the empty answer and RED at `(Z, [Z])` the moment the clause goes. THE
/// CONTROL: seated by a `delegate`, `Z` answers itself and the SAME stored
/// row is served unchanged, by the exact arm — so what dropped it was the
/// missing seat, and the seeded row did reach the narrowing.
///
/// The seeded row's issuer is no seat, so it lies outside the obligation
/// [`UniversalIndexRow`] states for every row the world hands over —
/// deliberately: an unseated issuer is the only input at which the strict
/// reading of WIDER can be observed at all.
#[test]
fn an_unseated_issuer_over_its_own_prefix_is_no_row() {
    let fx = setup();
    let read = || universal_grants(ex(&fx.febe, fx.user, Op::UniversalGrants));
    let owner_of = |a: &skep_address::Address| {
        effective_owner(ex(&fx.febe, fx.user, Op::EffectiveOwner { addr: a.clone() }))
    };

    // Z: the node's next top-level account, peeked and NOT delegated — no
    // seat, so ω answers the NODE for it, the bootstrap principal's own.
    let (z, _) = maybe_addr(ex(&fx.febe, fx.boot, Op::NextAccountPrefix { parent: node1() }));
    let z = z.expect("a second top-level account is delegable");
    assert_eq!(owner_of(&z), Some((node1(), BOOTSTRAP_PRINCIPAL)), "no seat: ω(Z) is the node");

    // The ONE stored row, seeded RAW: Z's universal share over Z itself.
    seed_universal_grant_index(vec![UniversalIndexRow {
        content_prefix: z.clone(),
        issuers: vec![z.clone()],
    }]);

    // NO row: ω answers the node, so the exact arm passes the pair by, and Z
    // is not WIDER than Z. Without `prefix != issuer` the read serves
    // (Z, [Z]) and the served-row check is red at it.
    let served = read();
    assert_served_rows_are_omega_owned(&fx, &served);
    assert!(served.is_empty(), "an unseated issuer over its own prefix is no row: {served:?}");

    // THE CONTROL: seat Z and ω answers Z for Z — the same stored row is
    // served unchanged at the next read, and the check holds over a row.
    ack_addr(ex(
        &fx.febe,
        fx.boot,
        Op::Delegate { new_prefix: z.tumbler().clone(), new_id: PrincipalId(21) },
    ));
    assert_eq!(owner_of(&z), Some((z.clone(), PrincipalId(21))), "seated, Z answers itself");
    let served = read();
    assert_eq!(
        served,
        vec![UniversalGrant { prefix: z.clone(), issuers: BTreeSet::from([z.clone()]) }],
        "ω answers the issuer for the stored prefix: unchanged"
    );
    assert_served_rows_are_omega_owned(&fx, &served);
}

/// THE EXACT ARM's named residue (PUB-8.47; RES-298), as `Op::UniversalGrants`
/// states it: a stored prefix that is a sub-prefix of the issuer's account no
/// delegation has seated is served UNCHANGED — ω answers the issuer there —
/// and the row drops at the first read after a delegation seats it, ω then
/// answering the new seat while the issuer's account is no wider than the
/// stored prefix. Each read holds the served guarantee: the one issuer listed
/// is the seat ω answers for its prefix, asked through the surface's own
/// owner-of-address read.
#[test]
fn an_unseated_sub_prefix_is_served_until_a_delegation_seats_it() {
    let fx = setup();
    let read = || universal_grants(ex(&fx.febe, fx.user, Op::UniversalGrants));
    let seat_of = |a: &skep_address::Address| {
        effective_owner(ex(&fx.febe, fx.user, Op::EffectiveOwner { addr: a.clone() }))
            .map(|(seat, _)| seat)
    };

    // `inc(X, 1)`, peeked and NOT delegated: a sub-prefix of X, and no seat.
    let (child, _) =
        maybe_addr(ex(&fx.febe, fx.user, Op::NextAccountPrefix { parent: fx.account.clone() }));
    let child = child.expect("a fresh account's first child is delegable");
    assert_eq!(seat_of(&child), Some(fx.account.clone()), "no seat: ω answers X at the child");

    // X's universal share over its unseated child, seeded RAW.
    seed_universal_grant_index(vec![UniversalIndexRow {
        content_prefix: child.clone(),
        issuers: vec![fx.account.clone()],
    }]);
    let served = read();
    assert_eq!(
        served,
        vec![UniversalGrant {
            prefix: child.clone(),
            issuers: BTreeSet::from([fx.account.clone()]),
        }],
        "ω answers X at the unseated child: the stored prefix is served unchanged"
    );
    assert_served_rows_are_omega_owned(&fx, &served);

    // Seated by X's own `delegate`: ω answers the child itself, and X's
    // account is no wider than the child, so X's share over it is no row.
    ack_addr(ex(
        &fx.febe,
        fx.user,
        Op::Delegate { new_prefix: child.tumbler().clone(), new_id: PrincipalId(41) },
    ));
    assert_eq!(seat_of(&child), Some(child.clone()), "seated, the child answers itself");
    assert!(read().is_empty(), "the row drops at the first read after the delegation");
}

/// PUB-8.47 / PUB-5.109, at the seam's cost: the GUEST is answered before the
/// index is enumerated — grants reach principals alone, so a requester no
/// grant reaches never pays for the store-sized walk, and an unauthenticated
/// request cannot drive it — while a bound principal's answer is ONE
/// enumeration off its snapshot (`PublicationWorld::universal_grant_index`:
/// "enumerated once per request").
#[test]
fn the_universal_index_is_enumerated_once_for_a_principal_and_never_for_the_guest() {
    let fx = setup();
    seed_universal_grant_index(vec![UniversalIndexRow {
        content_prefix: fx.account.clone(),
        issuers: vec![fx.account.clone()],
    }]);

    let r = ex(&fx.febe, SessionId::GUEST, Op::UniversalGrants);
    assert!(universal_grants(r).is_empty(), "the guest is answered empty");
    assert_eq!(universal_grant_index_reads(), 0, "the guest's empty answer walked no index");

    let served = universal_grants(ex(&fx.febe, fx.user, Op::UniversalGrants));
    assert_eq!(served.len(), 1, "premise: a principal is served the seeded row");
    assert_eq!(universal_grant_index_reads(), 1, "one enumeration per request");
}
