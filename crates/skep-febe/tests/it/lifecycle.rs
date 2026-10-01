//! End-to-end lifecycle tests over the public surface only: bootstrap →
//! delegate → create → edit → link → query, all through
//! `OperationSurface::execute`. What they pin: the namespace reads and the
//! owner-of-address read, node admission under any bound session, the
//! document and link families end to end with the response shape each `Op`
//! answers, a link slot index answered at either extreme, the version-chain
//! refusals, and the typed, classified, localized rejections (§5). The
//! publication reads, the retry memo and EDITLINK's successor each have a file
//! of their own.

use crate::common;

use common::*;
use skep_address::{elem_addr, ElemPos, SpanSet};
use skep_discovery::{FourSet, SlotSpec};
use skep_febe::{
    Deposit, Disposition, Op, OpKind, RejectCode, SessionId, SlotArg, SuccessorSpec, FROM,
};
use skep_links::{enc, View};
use skep_namespace::{PrincipalId, BOOTSTRAP_PRINCIPAL};
use skep_retrieval::{RegionSpec, Spec};

/// A link-subspace element address under `doc` that no MAKELINK ever minted.
fn ghost_link(doc: &skep_address::Address, ordinal: u32) -> skep_address::Address {
    elem_addr(ElemPos { doc: doc.clone(), subspace: nat(2), ordinal: nat(ordinal) })
        .unwrap_or_else(|_| panic!("valid element position"))
}

/// Bootstrap provisioning and the two namespace-structure reads (§2/§6):
/// NextAccountPrefix feeds Delegate; PrincipalPrefix resolves any principal's
/// public prefix (None = absent); RegisterNode runs under the bootstrap
/// session with no principal semantics.
#[test]
fn the_namespace_reads_answer_the_registry_and_absence_is_not_a_refusal() {
    let fx = setup();

    // The delegated account is the prefix the read handed out (setup used it).
    let (mine, _) = maybe_addr(ex(&fx.febe, fx.user, Op::PrincipalPrefix { id: USER }));
    assert_eq!(mine.expect("registered principal has a prefix"), fx.account);

    // An unknown principal is None — absence, not a rejection.
    let (absent, _) = maybe_addr(ex(&fx.febe, fx.user, Op::PrincipalPrefix { id: PrincipalId(99) }));
    assert!(absent.is_none(), "an unregistered principal is answered absent, never refused");

    // The frontier advanced past the delegated prefix: the next peek differs.
    let (next, _) = maybe_addr(ex(&fx.febe, fx.boot, Op::NextAccountPrefix { parent: node1() }));
    assert_ne!(next.expect("node still delegable"), fx.account);

    // Node provisioning: supplied address, bootstrap session, AckAddr echo.
    let (node, _) = ack_addr(ex(&fx.febe, fx.boot, Op::RegisterNode { addr: tum(&[1, 2]) }));
    assert_eq!(node, addr(&[1, 2]));
}

/// THE OWNER-OF-ADDRESS READ (AUTH-6.37) over the surface: ω UNPROJECTED —
/// the longest registered prefix containing `addr` and the principal seated
/// at it, as ONE entry — and the four cells every caller of it stands on.
/// An ACCOUNT is ALLOCATED iff `prefix == addr`: a seat answers itself. An
/// UNALLOCATED `inc(X, 1)` answers `X`'s OWN seat — never none under the node
/// — so `Some` alone is not the allocation test (AUTH-5.87 op (1)'s resume
/// reads the equality and nothing else), and the SAME address answers itself
/// once a `delegate` seats it. At every other tier the equality says nothing
/// about allocation: a minted document and a node `register_node` admitted
/// are allocated and seated nowhere, so each answers the seat above it.
/// Under no registered prefix, both halves are absent TOGETHER. And the read
/// is SESSION-BLIND: the GUEST is answered exactly what the bound principal
/// is.
#[test]
fn the_owner_of_address_read_answers_omega_unprojected() {
    let fx = setup();
    let owner_of = |session, a: &skep_address::Address| {
        effective_owner(ex(&fx.febe, session, Op::EffectiveOwner { addr: a.clone() }))
    };

    // A seat of its own: the prefix IS the address asked, at both tiers.
    assert_eq!(owner_of(fx.user, &fx.account), Some((fx.account.clone(), USER)));
    assert_eq!(owner_of(fx.user, &node1()), Some((node1(), BOOTSTRAP_PRINCIPAL)));

    // `inc(X, 1)`, peeked and NOT delegated: X's own principal at X's own
    // prefix — the nearest seat above it — and so NOT allocated.
    let (first_child, _) =
        maybe_addr(ex(&fx.febe, fx.user, Op::NextAccountPrefix { parent: fx.account.clone() }));
    let first_child = first_child.expect("a fresh account's first child is delegable");
    let unallocated = owner_of(fx.user, &first_child).expect("never none under a seat");
    assert_eq!(unallocated, (fx.account.clone(), USER), "the unallocated child answers X");
    assert_ne!(unallocated.0, first_child, "prefix != addr: the address is not a seat");

    // A document-tier address asked about is a registry probe like any other:
    // no consult, no registration check, the owning seat — and a MINTED
    // document is allocated yet seated nowhere, so the equality is an
    // account's allocation test and no other tier's. A node `register_node`
    // admitted is the same: allocated, seating no one, answered the seat above.
    let doc = create_doc(&fx);
    assert_eq!(
        owner_of(fx.user, &doc),
        Some((fx.account.clone(), USER)),
        "a minted document is allocated yet no seat: it answers its account's"
    );
    let unminted = addr(&[1, 0, 1, 0, 99]);
    assert_eq!(owner_of(fx.user, &unminted), Some((fx.account.clone(), USER)));
    let (admitted, _) = ack_addr(ex(&fx.febe, fx.boot, Op::RegisterNode { addr: tum(&[1, 3]) }));
    assert_eq!(
        owner_of(fx.user, &admitted),
        Some((node1(), BOOTSTRAP_PRINCIPAL)),
        "an admitted node is allocated and seats no one: it answers the genesis node's seat"
    );

    // Seated by a `delegate`, the same address answers ITSELF and the
    // principal that delegate registered; beneath it the longest prefix wins.
    let child_principal = PrincipalId(31);
    ack_addr(ex(
        &fx.febe,
        fx.user,
        Op::Delegate { new_prefix: first_child.tumbler().clone(), new_id: child_principal },
    ));
    assert_eq!(owner_of(fx.user, &first_child), Some((first_child.clone(), child_principal)));
    let (grandchild, _) =
        maybe_addr(ex(&fx.febe, fx.user, Op::NextAccountPrefix { parent: first_child.clone() }));
    assert_eq!(
        owner_of(fx.user, &grandchild.expect("the new seat is delegable under")),
        Some((first_child.clone(), child_principal)),
        "an unallocated grandchild answers the NEAREST seat, not the account above it"
    );

    // Under no registered principal's prefix: both halves absent, TOGETHER.
    assert_eq!(owner_of(fx.user, &addr(&[2])), None);
    assert_eq!(owner_of(fx.user, &addr(&[2, 0, 7])), None);

    // SESSION-BLIND: the guest is answered what the bound principal is, at
    // every cell above — public, immutable registry data, nothing withheld.
    let guest = SessionId::GUEST;
    for probe in [fx.account.clone(), first_child.clone(), doc, admitted, addr(&[2, 0, 7])] {
        assert_eq!(
            owner_of(guest, &probe),
            owner_of(fx.user, &probe),
            "the guest and the bound principal are answered alike"
        );
    }
}

/// §6/`Op::RegisterNode`: a bound session is the ONLY gate on node admission
/// — `Namespace::register_node` takes no principal and `RegisterNodeError`
/// carries no authority variant — so an ordinary delegated principal
/// registers a node, and confining this to provisioning is policy nobody
/// enforces. Pinned so the claim is executable rather than a paragraph: a
/// check added anywhere on this path turns this red, which is the
/// conversation such a check owes.
#[test]
fn a_node_registers_under_any_bound_session_not_only_bootstrap() {
    let fx = setup();
    assert_ne!(USER, BOOTSTRAP_PRINCIPAL, "fx.user speaks for an ordinary delegated principal");
    let (node, at) = ack_addr(ex(&fx.febe, fx.user, Op::RegisterNode { addr: tum(&[1, 8]) }));
    assert_eq!(node, addr(&[1, 8]));
    assert_eq!(at, fx.febe.log_position(), "and it committed, like any other write");
}

/// The document family end-to-end: create/insert/retrieve with the V1
/// coordinates (§1/§3), Fork ≠ Version (§3), origin attribution, COMPARE,
/// FINDDOCSCONTAINING, COPY, DELETE + SHOWDELETIONS, REARRANGE.
///
/// Under the version-chain model a document is either edited in place (a
/// draft) or versioned (a published edition), never both (PUB-2.9,
/// PUB-2.11): the content lives in an EDITION it was deposited into
/// (PUB-2.59), the version is the edition's, and the in-place edits run in a
/// DRAFT that transcludes the edition's content (PUB-2.27's own staging
/// shape) — so SHOWDELETIONS still has an address the version holds.
#[test]
fn the_document_family_answers_end_to_end() {
    let fx = setup();
    let edition = create_edition(&fx);
    let (_start, at) = deposit3(&fx, &edition);

    // Read-your-writes for a sequential client (G0): the later snapshot's
    // as_of is ≥ the write's committed coordinate.
    let (items, as_of) = delivery(ex(
        &fx.febe,
        fx.user,
        Op::RetrieveV { specs: vec![Spec { doc: edition.clone(), span: vspan(1, 1, 3) }] },
    ));
    assert_eq!(items.0.len(), 3);
    assert!(as_of >= at, "a later read sees at least the coordinate the write committed at");

    let (bound, _) = spanset(ex(&fx.febe, fx.user, Op::RetrieveDocVSpan { doc: edition.clone() }));
    assert_ne!(bound, SpanSet::empty());
    let (exact, _) = spanset(ex(&fx.febe, fx.user, Op::RetrieveDocVSpanSet { doc: edition.clone() }));
    assert_ne!(exact, SpanSet::empty());

    // Fork mints an EMPTY document (shares no content); Version is the
    // content-sharing fork (§3) — the two must not be conflated.
    let (fork, _) = ack_addr(ex(&fx.febe, fx.user, Op::Fork { published: None }));
    let (fork_set, _) = spanset(ex(&fx.febe, fx.user, Op::RetrieveDocVSpanSet { doc: fork.clone() }));
    assert_eq!(fork_set, SpanSet::empty());
    let (version, _) = ack_addr(ex(&fx.febe, fx.user, Op::Version { d_src: edition.clone(), published: None }));
    let (version_set, _) = spanset(ex(&fx.febe, fx.user, Op::RetrieveDocVSpanSet { doc: version.clone() }));
    assert_ne!(version_set, SpanSet::empty());

    // The version's content originated in the edition (SHOWORIGIN reports
    // allocators).
    let origins = addrs(ex(&fx.febe, fx.user, Op::ShowOrigin { doc: version.clone(), span: vspan(1, 1, 1) }));
    assert_eq!(origins, vec![edition.clone()]);

    // COMPARE finds address-equal correspondences between the edition and its
    // version.
    let rep = compare(ex(
        &fx.febe,
        fx.user,
        Op::Compare {
            rho1: vec![RegionSpec { doc: edition.clone(), spans: vec![vspan(1, 1, 2)] }],
            rho2: vec![RegionSpec { doc: version.clone(), spans: vec![vspan(1, 1, 2)] }],
        },
    ));
    assert!(!rep.0.is_empty(), "the edition and its version share address-equal content");

    // Present-tense containers of the edition's first element: at least the
    // edition and its version.
    let holders = addrs(ex(
        &fx.febe,
        fx.user,
        Op::FindDocsContaining {
            regions: vec![RegionSpec { doc: edition.clone(), spans: vec![vspan(1, 1, 1)] }],
        },
    ));
    assert!(holders.contains(&edition), "the document that allocated the element contains it");
    assert!(holders.contains(&version), "the version that shares it contains it too");

    // COPY transcludes into the empty fork; its arrangement is now non-empty.
    ack(ex(&fx.febe, fx.user, Op::Copy { doc: fork.clone(), at: vp(1, 1), specs: vec![vspec(&edition, 1, 1)] }));
    let (fork_set, _) = spanset(ex(&fx.febe, fx.user, Op::RetrieveDocVSpanSet { doc: fork.clone() }));
    assert_ne!(fork_set, SpanSet::empty());

    // The in-place edits run in a DRAFT staged from the edition (PUB-2.27):
    // the edition itself refuses them (PUB-2.11).
    let rej = rejected(ex(&fx.febe, fx.user, Op::Delete { doc: edition.clone(), p: vp(1, 3), width: nat(1) }));
    assert_eq!(rej.code, RejectCode::PublishedTarget);
    let draft = create_doc(&fx);
    ack(ex(&fx.febe, fx.user, Op::Copy { doc: draft.clone(), at: vp(1, 1), specs: vec![vspec(&edition, 1, 3)] }));

    // DELETE closes the gap in the draft; the removed I-address is still current
    // in the version — exactly SHOWDELETIONS' a-with-b half.
    ack(ex(&fx.febe, fx.user, Op::Delete { doc: draft.clone(), p: vp(1, 3), width: nat(1) }));
    let rep = deletions(ex(&fx.febe, fx.user, Op::ShowDeletions { d_a: draft.clone(), d_b: version.clone() }));
    assert_eq!(rep.deleted_from_a_with_b.len(), 1);
    assert!(rep.deleted_from_b_with_a.is_empty(), "nothing was deleted from the version");

    // REARRANGE (pivot, 3 cuts) over the remaining two elements.
    ack(ex(
        &fx.febe,
        fx.user,
        Op::Rearrange { doc: draft.clone(), cuts: vec![vp(1, 1), vp(1, 2), vp(1, 3)] },
    ));

    assert!(fx.febe.log_position() >= at, "the log never regresses past a committed write (G0)");
}

/// The version-chain model's three refusals, as M10 surfaces them (owner
/// ruling D2b: the crates refuse, M10 lowers): each is its own permanent
/// code, none carries a site, and the declared deposit is the one insert a
/// published document admits (PUB-2.11, PUB-2.7, PUB-2.9, PUB-2.59).
#[test]
fn the_version_chain_refusals_surface_as_their_own_permanent_codes() {
    let fx = setup();
    let edition = create_edition(&fx);
    deposit3(&fx, &edition);
    let draft = create_doc(&fx);
    insert3(&fx, &draft);
    let before = fx.febe.log_position();

    // PUB-2.11: the four in-place edits on the edition.
    let undeclared = Op::Insert {
        doc: edition.clone(),
        at: vp(1, 4),
        values: vec![skep_content::Val::new(vec![b'x'])],
        deposit: Deposit::Undeclared,
    };
    let refusals = vec![
        (OpKind::Insert, ex(&fx.febe, fx.user, undeclared)),
        (
            OpKind::Copy,
            ex(
                &fx.febe,
                fx.user,
                Op::Copy { doc: edition.clone(), at: vp(1, 4), specs: vec![vspec(&draft, 1, 1)] },
            ),
        ),
        (
            OpKind::Delete,
            ex(&fx.febe, fx.user, Op::Delete { doc: edition.clone(), p: vp(1, 1), width: nat(1) }),
        ),
        (
            OpKind::Rearrange,
            ex(
                &fx.febe,
                fx.user,
                Op::Rearrange { doc: edition.clone(), cuts: vec![vp(1, 1), vp(1, 2), vp(1, 3)] },
            ),
        ),
        // PUB-2.7: an explicit private member of the owner's published edition.
        (
            OpKind::Version,
            ex(&fx.febe, fx.user, Op::Version { d_src: edition.clone(), published: Some(false) }),
        ),
        // PUB-2.9: any version of the owner's private draft.
        (
            OpKind::Version,
            ex(&fx.febe, fx.user, Op::Version { d_src: draft.clone(), published: None }),
        ),
    ];
    let expected = [
        RejectCode::PublishedTarget,
        RejectCode::PublishedTarget,
        RejectCode::PublishedTarget,
        RejectCode::PublishedTarget,
        RejectCode::PrivateVersionOfPublished,
        RejectCode::PrivateSourceVersionless,
    ];
    for ((kind, r), code) in refusals.into_iter().zip(expected) {
        let rej = rejected(r);
        assert_eq!(rej.op, kind);
        assert_eq!(rej.code, code, "{kind:?}");
        assert_eq!(rej.disposition, Disposition::Permanent, "{kind:?}: a permanent class");
        assert!(rej.site.is_none(), "{kind:?}: the face keys on the code alone");
    }
    assert_eq!(fx.febe.log_position(), before, "a refusal commits nothing");

    // The declared deposit at the edition's fresh position lands (PUB-2.59);
    // declared but touching an arranged position, it is refused the same way
    // (the declaration is not a bypass).
    ack_addr(ex(
        &fx.febe,
        fx.user,
        Op::Insert {
            doc: edition.clone(),
            at: vp(1, 4),
            values: vec![skep_content::Val::new(vec![b'r'])],
            deposit: declared(),
        },
    ));
    let rej = rejected(ex(
        &fx.febe,
        fx.user,
        Op::Insert {
            doc: edition.clone(),
            at: vp(1, 2),
            values: vec![skep_content::Val::new(vec![b'r'])],
            deposit: declared(),
        },
    ));
    assert_eq!(rej.code, RejectCode::PublishedTarget);
    // The declaration NAMES the class and M5 tests it (PUB-2.11, RES-249):
    // declared under a type the deposit class does not hold — the edition's
    // own address, no class type at all — the fresh position a member is
    // admitted at is refused the same way, and M10 lowers M5's verdict
    // unchanged.
    let rej = rejected(ex(
        &fx.febe,
        fx.user,
        Op::Insert {
            doc: edition.clone(),
            at: vp(1, 5),
            values: vec![skep_content::Val::new(vec![b'r'])],
            deposit: Deposit::Declared(edition.clone()),
        },
    ));
    assert_eq!(rej.code, RejectCode::PublishedTarget);
    // The inherited version of the edition is admitted (PUB-2.8).
    ack_addr(ex(&fx.febe, fx.user, Op::Version { d_src: edition, published: None }));
}

/// The link family end-to-end: MAKELINK (no dedup), raw reads with the
/// in-band ⟨⟩ ≠ ⊥ FOLLOWLINK contract (§2), the M8 region/descriptor/
/// pointwise/lineage reads, EDITLINK's read-assembled successor (§4),
/// idempotent zero-step EMIT (§3), and the active-view consequences of
/// NULLIFY.
#[test]
fn the_link_family_answers_end_to_end() {
    let fx = setup();
    let d = create_doc(&fx);
    let (start, _) = insert3(&fx, &d);
    let region = vec![vspan(1, 1, 3)];

    let make = || Op::MakeLink {
        home: d.clone(),
        from: SlotArg::Resolve(vec![vspec(&d, 1, 1)]),
        to: SlotArg::Resolve(vec![vspec(&d, 2, 1)]),
        ty: SlotArg::Resolve(vec![vspec(&d, 3, 1)]),
        replaces: None,
    };
    let (l1, _) = ack_addr(ex(&fx.febe, fx.user, make()));
    let (l2, _) = ack_addr(ex(&fx.febe, fx.user, make()));
    assert_ne!(l1, l2); // MAKELINK never dedups — distinct links always

    // Raw reads: value-or-None, and FOLLOWLINK's in-band Result — absence is
    // Err(Invalid) INSIDE Response::Follow, never a Rejection (§2).
    assert!(
        link_value(ex(&fx.febe, fx.user, Op::ReadLink { a: l1.clone() })).is_some(),
        "a resident link reads back as a value"
    );
    assert!(
        link_value(ex(&fx.febe, fx.user, Op::ReadLink { a: ghost_link(&d, 99) })).is_none(),
        "an address no MAKELINK minted reads back as ⊥"
    );
    let cov = follow(ex(&fx.febe, fx.user, Op::FollowLink { a: l1.clone(), slot: FROM }));
    assert_ne!(cov.expect("the FROM slot exists"), SpanSet::empty());
    assert!(
        follow(ex(&fx.febe, fx.user, Op::FollowLink { a: ghost_link(&d, 99), slot: FROM })).is_err(),
        "following a non-link answers Invalid in band"
    );
    assert!(
        follow(ex(&fx.febe, fx.user, Op::FollowLink { a: l1.clone(), slot: 9 })).is_err(),
        "following a slot past the arity answers Invalid in band"
    );

    // Region family (foundation ∩ active).
    assert!(
        !runs(ex(&fx.febe, fx.user, Op::Image { d: d.clone(), region: region.clone() })).is_empty(),
        "the region has a V→I image"
    );
    assert_eq!(count(ex(&fx.febe, fx.user, Op::CountV { d: d.clone(), region: region.clone() })), 2);
    let found = addrs(ex(&fx.febe, fx.user, Op::FindLinksV { d: d.clone(), region: region.clone() }));
    assert!(found.contains(&l1), "the first link is discovered from the region");
    assert!(found.contains(&l2), "the second link is discovered from the region");
    let w = page(ex(
        &fx.febe,
        fx.user,
        Op::WindowV { d: d.clone(), region: region.clone(), cur: None, n: 1 },
    ));
    assert_eq!(w.batch.len(), 1);
    assert!(!w.exhausted, "a window of one over two links has a next page");
    assert!(
        !endsets(ex(&fx.febe, fx.user, Op::RetrieveEndsets { d: d.clone(), region: region.clone() }))
            .is_empty(),
        "the region's links report their endsets"
    );

    // Descriptor family (address-keyed, home-projected, total).
    let home_q = || FourSet {
        home: SlotSpec::Spans(enc([&d])),
        from: SlotSpec::Any,
        to: SlotSpec::Any,
        ty: SlotSpec::Any,
    };
    let ftt = addrs(ex(&fx.febe, fx.user, Op::FindLinksFtt { q: home_q() }));
    assert!(ftt.contains(&l1), "the first link is homed in d");
    assert!(ftt.contains(&l2), "the second link is homed in d");
    assert!(
        count(ex(&fx.febe, fx.user, Op::CountFtt { q: home_q() })) >= 2,
        "the descriptor census counts at least the two links just made"
    );
    let w = page(ex(&fx.febe, fx.user, Op::WindowFtt { q: home_q(), cur: None, n: 1 }));
    assert_eq!(w.batch.len(), 1);

    // Pointwise projection & discoverability.
    let (proj, _) = spanset(ex(&fx.febe, fx.user, Op::Project { a: l1.clone(), slot: FROM, d: d.clone() }));
    assert_ne!(proj, SpanSet::empty());
    assert!(
        bool_val(ex(&fx.febe, fx.user, Op::DiscoverableFrom { a: l1.clone(), d: d.clone() })),
        "an active link over d's arrangement is discoverable from d"
    );

    // EDITLINK: content successor assembled by M10 off a prior snapshot (§4).
    let (succ, claim1, _) = ack_edit(ex(
        &fx.febe,
        fx.user,
        Op::EditLink {
            original: l1.clone(),
            successor: SuccessorSpec {
                from: vec![vspec(&d, 1, 1)],
                to: vec![vspec(&d, 2, 1)],
                ty: SlotArg::Resolve(vec![vspec(&d, 3, 1)]),
            },
            d_s: d.clone(),
            d_a: d.clone(),
        },
    ));
    assert_ne!(succ, l1);

    // AssertSup + archival lineage (flipped slot convention: old ⇐ FROM).
    let (claim2, _) =
        ack_addr(ex(&fx.febe, fx.user, Op::AssertSup { home: d.clone(), old: l1.clone(), new: l2.clone() }));
    let in_claims = claims(ex(&fx.febe, fx.user, Op::InClaims { y: l1.clone(), view: View::Active }));
    assert_eq!(in_claims.len(), 2); // editlink's claim + the explicit assert_sup claim
    assert!(
        in_claims.iter().any(|c| c.claim == claim1 && c.new == succ),
        "editlink's own claim names its successor as what supersedes l1"
    );
    assert!(
        in_claims.iter().any(|c| c.claim == claim2 && c.new == l2 && c.active),
        "the explicit assert_sup claim names l2, and is active"
    );
    let out_claims = claims(ex(&fx.febe, fx.user, Op::OutClaims { x: l2.clone(), view: View::Active }));
    assert_eq!(out_claims.len(), 1);
    assert_eq!(out_claims[0].claim, claim2);

    // Idempotent zero-step EMIT (§3): a dedup hit returns (incumbent,
    // base_seq) with no commit — marshaled identically to the miss.
    let emit = || Op::Emit { home: d.clone(), ty: pred_def_ty(), from: start.clone(), to: vec![] };
    let (e1, at1) = ack_addr(ex(&fx.febe, fx.user, emit()));
    let before = fx.febe.log_position();
    let (e2, at2) = ack_addr(ex(&fx.febe, fx.user, emit()));
    assert_eq!(e2, e1);
    assert_eq!(at2, at1);
    assert_eq!(fx.febe.log_position(), before);

    // Pre-edit survival preview (the last-witness condition over the active
    // view): l1/l2/succ keep witnesses at ordinals 2–3, but the pred-def
    // tuple's only content anchor IS the element being deleted — it alone
    // is reported dropped from d.
    let rep = orphans(ex(&fx.febe, fx.user, Op::DeleteOrphans { d: d.clone(), p: vp(1, 1), width: nat(1) }));
    assert_eq!(rep.orphaned, vec![e1.clone()]);

    // NULLIFY retracts l2: present-state reads are active-filtered
    // (foundation ∩ active — the region family stabs the link-store index,
    // so the unseated editlink successor and the pred-def tuple, whose
    // endsets cover these I-extents, still surface), and discoverable_from
    // is compound "reachable AND active". The retraction tuple itself
    // surfaces too: nullify deposits [enc({home}), enc({target}), [R]], and
    // enc is the subtree-span encoding (AD), so a document-homed FROM covers
    // every content I-extent under d — and the retraction is active.
    let (retraction, _) =
        ack_addr(ex(&fx.febe, fx.user, Op::Nullify { home: d.clone(), target: l2.clone() }));
    assert!(
        !bool_val(ex(&fx.febe, fx.user, Op::DiscoverableFrom { a: l2.clone(), d: d.clone() })),
        "a retracted link is no longer discoverable: the compound is reachable AND active"
    );
    let found = addrs(ex(&fx.febe, fx.user, Op::FindLinksV { d: d.clone(), region: region.clone() }));
    assert!(found.contains(&l1), "l1 survives its own supersession — a claim is not a retraction");
    assert!(found.contains(&succ), "the unseated editlink successor still stabs the index");
    assert!(found.contains(&e1), "the pred-def tuple's endsets still cover these I-extents");
    assert!(found.contains(&retraction), "the retraction tuple is itself an active link over d");
    assert!(!found.contains(&l2), "the nullified link is filtered out of the active view");
    assert_eq!(count(ex(&fx.febe, fx.user, Op::CountV { d: d.clone(), region })), 4);
}

/// The wire's slot index is a client-chosen `usize` that M10 hands straight to
/// a 1-based lookup — `Op::FollowLink` to M7's `followlink`, `Op::Project`
/// through M8's `project_on` to the same — and both are a GUEST's reads. At
/// either extreme, 0 and `usize::MAX`, each is ANSWERED exactly as a slot past
/// the arity is: FOLLOWLINK's in-band `Err(Invalid)`, PROJECT's `NotALink`. A
/// lookup rewritten to subtract before it range-checks makes slot 0 a remote
/// panic, and this is what turns red.
#[test]
fn a_slot_index_at_either_extreme_is_answered_never_faulted() {
    let fx = setup();
    let (d, l) = linked_doc(&fx);
    for slot in [0, usize::MAX] {
        assert!(
            follow(ex(&fx.febe, SessionId::GUEST, Op::FollowLink { a: l.clone(), slot })).is_err(),
            "slot {slot}: Invalid, in band"
        );
        let rej = rejected(ex(
            &fx.febe,
            SessionId::GUEST,
            Op::Project { a: l.clone(), slot, d: d.clone() },
        ));
        assert_eq!(rej.code, RejectCode::NotALink, "slot {slot}");
    }
}

/// §5/§6: every failure arrives as a typed, classified, localized rejection —
/// the session gate, the Reorder/Permanent disposition policy, M6's threaded
/// FaultSite vs the fieldless M5/M8 lowerings, the M10-side editlink guard,
/// and the as-built supersession fence.
#[test]
fn refusals_arrive_typed_classified_and_localized() {
    let fx = setup();
    let d = create_doc(&fx);
    let (start, _) = insert3(&fx, &d);

    // Write on an unbound (closed) session: Unauthenticated, pre-transaction.
    let retired = fx.febe.open_session(PrincipalId(9));
    fx.febe.close_session(retired);
    let rej = rejected(ex(
        &fx.febe,
        retired,
        Op::Insert {
            doc: d.clone(),
            at: vp(1, 1),
            values: vec![skep_content::Val::new(vec![1u8])],
            deposit: Deposit::Undeclared,
        },
    ));
    assert_eq!(rej.op, OpKind::Insert);
    assert_eq!(rej.code, RejectCode::Unauthenticated);
    assert_eq!(rej.disposition, Disposition::Permanent);

    // M6's DocNotRegistered carries the offending document into the site;
    // ambiguous registration codes are hinted Reorder (§5).
    let ghost = addr(&[1, 0, 1, 0, 77]);
    let rej = rejected(ex(
        &fx.febe,
        fx.user,
        Op::RetrieveV { specs: vec![Spec { doc: ghost.clone(), span: vspan(1, 1, 1) }] },
    ));
    assert_eq!(rej.code, RejectCode::DocNotRegistered);
    assert_eq!(rej.disposition, Disposition::Reorder);
    assert_eq!(rej.site.expect("M6 localizes").addr, Some(ghost.clone()));

    // M5's same-named code is fieldless — site None (§5).
    let rej = rejected(ex(
        &fx.febe,
        fx.user,
        Op::Delete { doc: ghost, p: vp(1, 1), width: nat(1) },
    ));
    assert_eq!(rej.code, RejectCode::DocNotRegistered);
    assert_eq!(rej.disposition, Disposition::Reorder);
    assert!(rej.site.is_none(), "M5's DocNotRegistered is fieldless, so nothing localizes it");

    // The canonical out-of-order retraction: BadTarget ⇒ Reorder (§5).
    let rej = rejected(ex(
        &fx.febe,
        fx.user,
        Op::Nullify { home: d.clone(), target: ghost_link(&d, 99) },
    ));
    assert_eq!(rej.code, RejectCode::BadTarget);
    assert_eq!(rej.disposition, Disposition::Reorder);

    // M10's own editlink guard: an ill-formed (link-subspace) content VSpec
    // is a typed IllFormedSpec, never M5's silent ⟨⟩ clip (§4). A good spec
    // rides ahead of it, so the reported `site.index` is the offender's
    // position and not the only position there was.
    let ill_formed = skep_arrangement::VSpec { source: d.clone(), span: vspan(2, 1, 1) };
    let rej = rejected(ex(
        &fx.febe,
        fx.user,
        Op::EditLink {
            original: ghost_link(&d, 99),
            successor: SuccessorSpec {
                from: vec![vspec(&d, 1, 1), ill_formed],
                to: vec![],
                ty: SlotArg::Addrs(vec![d.clone()]),
            },
            d_s: d.clone(),
            d_a: d.clone(),
        },
    ));
    assert_eq!(rej.op, OpKind::EditLink);
    assert_eq!(rej.code, RejectCode::IllFormedSpec);
    assert_eq!(rej.disposition, Disposition::Permanent);
    assert_eq!(
        rej.site.expect("M10 localizes its own successor faults").index,
        Some(1),
        "the second spec is the offender, and the rejection says which"
    );

    // The same guard on the other fault a successor spec can carry: a source
    // M3 does not know resolves to ⟨⟩, so it is refused instead of committed
    // as an empty slot — and hinted Reorder, since a client that arrives
    // ahead of its own CREATENEWDOCUMENT may reissue (§4).
    let unregistered =
        skep_arrangement::VSpec { source: addr(&[1, 0, 1, 0, 78]), span: vspan(1, 1, 1) };
    let rej = rejected(ex(
        &fx.febe,
        fx.user,
        Op::EditLink {
            original: ghost_link(&d, 99),
            successor: SuccessorSpec {
                from: vec![vspec(&d, 1, 1), unregistered],
                to: vec![],
                ty: SlotArg::Addrs(vec![d.clone()]),
            },
            d_s: d.clone(),
            d_a: d.clone(),
        },
    ));
    assert_eq!(rej.op, OpKind::EditLink);
    assert_eq!(rej.code, RejectCode::SourceNotRegistered);
    assert_eq!(rej.disposition, Disposition::Reorder);
    assert_eq!(rej.site.expect("M10 localizes its own successor faults").index, Some(1));

    // The as-built [K_sup] emit fence lowers to DcViolation (report: drift):
    // supersession claims write only via AssertSup/EditLink.
    let make = || Op::MakeLink {
        home: d.clone(),
        from: SlotArg::Resolve(vec![vspec(&d, 1, 1)]),
        to: SlotArg::Resolve(vec![vspec(&d, 2, 1)]),
        ty: SlotArg::Resolve(vec![vspec(&d, 3, 1)]),
        replaces: None,
    };
    let (l1, _) = ack_addr(ex(&fx.febe, fx.user, make()));
    let (l2, _) = ack_addr(ex(&fx.febe, fx.user, make()));
    let rej = rejected(ex(
        &fx.febe,
        fx.user,
        Op::Emit { home: d.clone(), ty: supersedes_ty(), from: l1.clone(), to: vec![l2] },
    ));
    assert_eq!(rej.code, RejectCode::DcViolation);
    assert_eq!(rej.disposition, Disposition::Permanent);

    // Contrast with FOLLOWLINK's in-band Invalid: Project's non-link IS a
    // precondition failure and IS lowered (§2).
    let rej = rejected(ex(&fx.febe, fx.user, Op::Project { a: start, slot: FROM, d: d.clone() }));
    assert_eq!(rej.code, RejectCode::NotALink);
    assert_eq!(rej.disposition, Disposition::Permanent);

    // A link-subspace region is BadRegion (M8 gates; M10 forwards verbatim).
    let rej = rejected(ex(
        &fx.febe,
        fx.user,
        Op::WindowV { d: d.clone(), region: vec![vspan(2, 1, 1)], cur: None, n: 1 },
    ));
    assert_eq!(rej.code, RejectCode::BadRegion);
    assert_eq!(rej.disposition, Disposition::Permanent);

    // Append-only allocations: a re-registered node is NotFresh — Permanent,
    // steering to re-derivation, never reissue-polling (§5).
    ack_addr(ex(&fx.febe, fx.boot, Op::RegisterNode { addr: tum(&[1, 7]) }));
    let rej = rejected(ex(&fx.febe, fx.boot, Op::RegisterNode { addr: tum(&[1, 7]) }));
    assert_eq!(rej.code, RejectCode::NotFresh);
    assert_eq!(rej.disposition, Disposition::Permanent);

    // Re-delegating an already-delegated prefix: ω(new_prefix) now names the
    // delegated principal, so M3's pinned gate order rejects NotAuthorized
    // (Permanent) before freshness is even checked.
    let rej = rejected(ex(
        &fx.febe,
        fx.boot,
        Op::Delegate { new_prefix: fx.account.tumbler().clone(), new_id: PrincipalId(8) },
    ));
    assert_eq!(rej.code, RejectCode::NotAuthorized);
    assert_eq!(rej.disposition, Disposition::Permanent);
}
