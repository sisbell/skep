//! End-to-end lifecycle tests over the public surface only: bootstrap →
//! delegate → create → edit → link → query, all through
//! `Operation::execute`, asserting exactly what the design/interface claim —
//! commit-before-ack coordinates, the response shape per `Op`, the
//! idempotency contract (§7), the session gate (§6), and the typed,
//! classified rejections (§5).

mod common;

use common::*;
use skep_address::{elem_addr, ElemPos, SpanSet};
use skep_discovery::{FourSet, SlotSpec};
use skep_febe::{
    Disposition, Op, OpKind, RejectCode, SlotArg, SuccessorSpec, FROM, MAX_REQ_ID_BYTES,
};
use skep_links::{enc, View, MAX_SLOT_SPANS};
use skep_namespace::{PrincipalId, BOOTSTRAP_PRINCIPAL};
use skep_retrieval::{Region, Spec};

/// A link-subspace element address under `doc` that no MAKELINK ever minted.
fn ghost_link(doc: &skep_address::Address, ordinal: u32) -> skep_address::Address {
    elem_addr(ElemPos { doc: doc.clone(), subspace: nat(2), ordinal: nat(ordinal) })
        .unwrap_or_else(|_| panic!("valid element position"))
}

/// A three-element document and one link over it — the starting point every
/// EDITLINK case below needs.
fn linked_doc(fx: &Fixture) -> (skep_address::Address, skep_address::Address) {
    let d = create_doc(fx);
    insert3(fx, &d);
    let (l, _) = ack_addr(ex(
        &fx.febe,
        fx.user,
        Op::MakeLink {
            home: d.clone(),
            from: SlotArg::Resolve(vec![vspec(&d, 1, 1)]),
            to: SlotArg::Resolve(vec![vspec(&d, 2, 1)]),
            ty: SlotArg::Resolve(vec![vspec(&d, 3, 1)]),
        },
    ));
    (d, l)
}

/// Bootstrap provisioning and the two namespace-structure reads (§2/§6):
/// NextAccountPrefix feeds Delegate; PrincipalPrefix resolves any principal's
/// public prefix (None = absent); RegisterNode runs under the bootstrap
/// session with no principal semantics.
#[test]
fn bootstrap_and_namespace_reads() {
    let fx = setup();

    // The delegated account is the prefix the read handed out (setup used it).
    let (mine, _) = maybe_addr(ex(&fx.febe, fx.user, Op::PrincipalPrefix { id: USER }));
    assert_eq!(mine.expect("registered principal has a prefix"), fx.account);

    // An unknown principal is None — absence, not a rejection.
    let (absent, _) = maybe_addr(ex(&fx.febe, fx.user, Op::PrincipalPrefix { id: PrincipalId(99) }));
    assert!(absent.is_none());

    // The frontier advanced past the delegated prefix: the next peek differs.
    let (next, _) = maybe_addr(ex(&fx.febe, fx.boot, Op::NextAccountPrefix { parent: node1() }));
    assert_ne!(next.expect("node still delegable"), fx.account);

    // Node provisioning: supplied address, bootstrap session, AckAddr echo.
    let (node, _) = ack_addr(ex(&fx.febe, fx.boot, Op::RegisterNode { addr: tum(&[1, 2]) }));
    assert_eq!(node, addr(&[1, 2]));
}

/// §6/`Op::RegisterNode`: a bound session is the ONLY gate on node admission
/// — `Namespace::register_node` takes no principal and `NodeError` carries no
/// authority variant — so an ordinary delegated principal registers a node,
/// and confining this to provisioning is policy nobody enforces. Pinned so
/// the claim is executable rather than a paragraph: a check added anywhere on
/// this path turns this red, which is the conversation such a check owes.
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
#[test]
fn document_lifecycle() {
    let fx = setup();
    let d = create_doc(&fx);
    let (_start, at) = insert3(&fx, &d);

    // Read-your-writes for a sequential client (G0): the later snapshot's
    // as_of is ≥ the write's committed coordinate.
    let (items, as_of) = delivery(ex(
        &fx.febe,
        fx.user,
        Op::RetrieveV { specs: vec![Spec { doc: d.clone(), span: vspan(1, 1, 3) }] },
    ));
    assert_eq!(items.0.len(), 3);
    assert!(as_of >= at, "a later read sees at least the coordinate the write committed at");

    let (bound, _) = spanset(ex(&fx.febe, fx.user, Op::RetrieveDocVSpan { doc: d.clone() }));
    assert_ne!(bound, SpanSet::empty());
    let (exact, _) = spanset(ex(&fx.febe, fx.user, Op::RetrieveDocVSpanSet { doc: d.clone() }));
    assert_ne!(exact, SpanSet::empty());

    // Fork mints an EMPTY document (shares no content); Version is the
    // content-sharing fork (§3) — the two must not be conflated.
    let (f, _) = ack_addr(ex(&fx.febe, fx.user, Op::Fork));
    let (f_set, _) = spanset(ex(&fx.febe, fx.user, Op::RetrieveDocVSpanSet { doc: f.clone() }));
    assert_eq!(f_set, SpanSet::empty());
    let (v, _) = ack_addr(ex(&fx.febe, fx.user, Op::Version { d_src: d.clone() }));
    let (v_set, _) = spanset(ex(&fx.febe, fx.user, Op::RetrieveDocVSpanSet { doc: v.clone() }));
    assert_ne!(v_set, SpanSet::empty());

    // The version's content originated in d (SHOWORIGIN reports allocators).
    let origins = addrs(ex(&fx.febe, fx.user, Op::ShowOrigin { doc: v.clone(), span: vspan(1, 1, 1) }));
    assert_eq!(origins, vec![d.clone()]);

    // COMPARE finds address-equal correspondences between d and its version.
    let rep = compare(ex(
        &fx.febe,
        fx.user,
        Op::Compare {
            rho1: vec![Region { doc: d.clone(), spans: vec![vspan(1, 1, 2)] }],
            rho2: vec![Region { doc: v.clone(), spans: vec![vspan(1, 1, 2)] }],
        },
    ));
    assert!(!rep.0.is_empty(), "d and its version share address-equal content");

    // Present-tense containers of d's first element: at least d and v.
    let holders = addrs(ex(
        &fx.febe,
        fx.user,
        Op::FindDocsContaining {
            regions: vec![Region { doc: d.clone(), spans: vec![vspan(1, 1, 1)] }],
        },
    ));
    assert!(holders.contains(&d), "the document that allocated the element contains it");
    assert!(holders.contains(&v), "the version that shares it contains it too");

    // COPY transcludes into the empty fork; its arrangement is now non-empty.
    ack(ex(&fx.febe, fx.user, Op::Copy { doc: f.clone(), at: vp(1, 1), specs: vec![vspec(&d, 1, 1)] }));
    let (f_set, _) = spanset(ex(&fx.febe, fx.user, Op::RetrieveDocVSpanSet { doc: f.clone() }));
    assert_ne!(f_set, SpanSet::empty());

    // DELETE closes the gap in d; the removed I-address is still current in
    // the version — exactly SHOWDELETIONS' a-with-b half.
    ack(ex(&fx.febe, fx.user, Op::Delete { doc: d.clone(), p: vp(1, 3), width: nat(1) }));
    let rep = deletions(ex(&fx.febe, fx.user, Op::ShowDeletions { d_a: d.clone(), d_b: v.clone() }));
    assert_eq!(rep.a_with_b.len(), 1);
    assert!(rep.b_with_a.is_empty(), "nothing was deleted from the version");

    // REARRANGE (pivot, 3 cuts) over the remaining two elements.
    ack(ex(
        &fx.febe,
        fx.user,
        Op::Rearrange { doc: d.clone(), cuts: vec![vp(1, 1), vp(1, 2), vp(1, 3)] },
    ));

    assert!(fx.febe.log_position() >= at, "the log never regresses past a committed write (G0)");
}

/// §7: sequential lost-ack retries replay the committed ack without
/// re-executing; the key is per-session and op-kind-matched; reads are never
/// memoized; a fresh session re-executes (best-effort, by design).
#[test]
fn idempotent_retry() {
    let fx = setup();
    let d = create_doc(&fx);
    let ins = || Op::Insert {
        doc: d.clone(),
        at: vp(1, 1),
        values: vec![skep_content::Val::new(vec![b'x'])],
    };

    let (addr1, at1) = ack_addr(ex_id(&fx.febe, fx.user, b"ins-1", ins()));
    let log0 = fx.febe.log_position();

    // Sequential retry: the rebuilt cached ack, no re-execution.
    let (addr2, at2) = ack_addr(ex_id(&fx.febe, fx.user, b"ins-1", ins()));
    assert_eq!(addr2, addr1);
    assert_eq!(at2, at1);
    assert_eq!(fx.febe.log_position(), log0);

    // Same ReqId under a DIFFERENT op-kind: a miss — the read executes (and
    // is itself never cached), leaving the write memo intact.
    let (set, _) = spanset(ex_id(&fx.febe, fx.user, b"ins-1", Op::RetrieveDocVSpan { doc: d.clone() }));
    assert_ne!(set, SpanSet::empty());
    let (addr3, at3) = ack_addr(ex_id(&fx.febe, fx.user, b"ins-1", ins()));
    assert_eq!(addr3, addr1);
    assert_eq!(at3, at1);
    assert_eq!(fx.febe.log_position(), log0);

    // A replay under a fresh session misses and re-executes (per-session
    // confinement): new address, advanced log.
    let s2 = fx.febe.open_session(USER);
    let (addr4, at4) = ack_addr(ex_id(&fx.febe, s2, b"ins-1", ins()));
    assert_ne!(addr4, addr1);
    assert!(at4 > at1);
    assert!(fx.febe.log_position() > log0);

    // The original session's memo is still confined and intact…
    let (addr5, at5) = ack_addr(ex_id(&fx.febe, fx.user, b"ins-1", ins()));
    assert_eq!(addr5, addr1);
    assert_eq!(at5, at1);

    // …until close_session retires the binding (a later write on the retired
    // id is Unauthenticated — and its idem entries are purged, §6).
    fx.febe.close_session(fx.user);
    let rej = rejected(ex_id(&fx.febe, fx.user, b"ins-1", ins()));
    assert_eq!(rej.code, RejectCode::Unauthenticated);
    assert_eq!(rej.disposition, Disposition::Permanent);
}

/// §7/[`MAX_REQ_ID_BYTES`]: the memo's SECOND door, through `execute`. An id
/// past the bound is answered like any other — the never-silent contract is
/// about the operation, and the operation is answered — and simply not
/// memoized, so the retry re-executes and the client is never told. An id
/// exactly at the bound is an ordinary key.
#[test]
fn an_oversized_request_id_is_answered_and_its_retry_re_executes() {
    let fx = setup();
    let d = create_doc(&fx);
    let ins = || Op::Insert {
        doc: d.clone(),
        at: vp(1, 1),
        values: vec![skep_content::Val::new(vec![b'y'])],
    };

    let over = vec![b'k'; MAX_REQ_ID_BYTES + 1];
    let (first, at1) = ack_addr(ex_id(&fx.febe, fx.user, &over, ins()));
    let log0 = fx.febe.log_position();
    let (second, at2) = ack_addr(ex_id(&fx.febe, fx.user, &over, ins()));
    assert_ne!(second, first, "an unmemoized retry re-executes");
    assert!(at2 > at1);
    assert!(fx.febe.log_position() > log0, "…and commits");

    let at_cap = vec![b'k'; MAX_REQ_ID_BYTES];
    let (a, _) = ack_addr(ex_id(&fx.febe, fx.user, &at_cap, ins()));
    let log1 = fx.febe.log_position();
    let (b, _) = ack_addr(ex_id(&fx.febe, fx.user, &at_cap, ins()));
    assert_eq!(b, a, "a key at the bound is an ordinary key");
    assert_eq!(fx.febe.log_position(), log1, "so its retry commits nothing");
}

/// §7/§1(d): the memo replays the acknowledgment SHAPE the write produced,
/// not merely its coordinate. EDITLINK's ack carries two same-typed addresses
/// — the successor link, and the claim that says it supersedes the original —
/// and a retry that handed them back swapped would send a client to read,
/// nullify or supersede the wrong link on the engine's own word.
#[test]
fn a_retried_editlink_replays_both_addresses_unswapped() {
    let fx = setup();
    let (d, original) = linked_doc(&fx);
    let edit = || Op::EditLink {
        original: original.clone(),
        successor: SuccessorSpec {
            from: vec![vspec(&d, 1, 1)],
            to: vec![vspec(&d, 2, 1)],
            ty: SlotArg::Resolve(vec![vspec(&d, 3, 1)]),
        },
        d_s: d.clone(),
        d_a: d.clone(),
    };

    let (succ, claim, at) = ack_edit(ex_id(&fx.febe, fx.user, b"edit-1", edit()));
    assert_ne!(succ, claim, "the successor and its supersession claim are two distinct links");
    let log0 = fx.febe.log_position();

    let (succ2, claim2, at2) = ack_edit(ex_id(&fx.febe, fx.user, b"edit-1", edit()));
    assert_eq!(succ2, succ, "the replayed successor is the successor that committed");
    assert_eq!(claim2, claim, "the replayed claim is the claim, not the successor again");
    assert_eq!(at2, at, "the replayed coordinate is the one the edit committed at");
    assert_eq!(fx.febe.log_position(), log0, "a replayed ack commits nothing");
}

/// §7: the bare-`Seq` acknowledgment round-trips too. [`Response::Ack`] is the
/// one committed shape carrying no address, and a DELETE that re-executed on
/// a lost ack would remove a second element the client never asked to lose.
#[test]
fn a_retried_delete_replays_its_bare_ack() {
    let fx = setup();
    let d = create_doc(&fx);
    insert3(&fx, &d);
    let del = || Op::Delete { doc: d.clone(), p: vp(1, 1), width: nat(1) };

    let at = ack(ex_id(&fx.febe, fx.user, b"del-1", del()));
    let log0 = fx.febe.log_position();
    let (before, _) = spanset(ex(&fx.febe, fx.user, Op::RetrieveDocVSpanSet { doc: d.clone() }));

    let at2 = ack(ex_id(&fx.febe, fx.user, b"del-1", del()));
    assert_eq!(at2, at, "the replayed ack carries the coordinate the delete committed at");
    assert_eq!(fx.febe.log_position(), log0, "a replayed ack commits nothing");
    let (after, _) = spanset(ex(&fx.febe, fx.user, Op::RetrieveDocVSpanSet { doc: d }));
    assert_eq!(after, before, "the remaining elements survive: the delete did not re-execute");
}

/// §4: `SuccessorSpec.ty`'s other form. `SlotArg::Addrs` builds an
/// address-denoting (managed-relation) type slot through `enc`, and it is the
/// only way a FEBE client gives a successor one — the content-resolved form
/// every other case uses cannot reach it.
#[test]
fn an_address_denoting_successor_type_slot_is_deposited_verbatim() {
    let fx = setup();
    let (d, original) = linked_doc(&fx);
    let (succ, _, _) = ack_edit(ex(
        &fx.febe,
        fx.user,
        Op::EditLink {
            original,
            successor: SuccessorSpec {
                from: vec![vspec(&d, 1, 1)],
                to: vec![vspec(&d, 2, 1)],
                ty: SlotArg::Addrs(vec![d.clone()]),
            },
            d_s: d.clone(),
            d_a: d.clone(),
        },
    ));

    let link =
        link_value(ex(&fx.febe, fx.user, Op::ReadLink { a: succ })).expect("the successor is resident");
    assert_eq!(link.type_slot(), &enc([&d]), "the address names ride into TYPE verbatim");
    assert!(!link.from_slot().is_empty(), "the content-resolved FROM is still resolved");
}

/// §4: a successor slot is built from ALL of its specs. Two non-adjacent
/// ordinals cannot merge into one span, and `Endset::from_spans` stores what
/// it is given, so the count is exact — a slot that kept only the last spec
/// would name one region where the client named two, commit, and read back
/// wrong.
#[test]
fn a_multi_spec_successor_slot_accumulates_every_spec() {
    let fx = setup();
    let (d, original) = linked_doc(&fx);
    let (succ, _, _) = ack_edit(ex(
        &fx.febe,
        fx.user,
        Op::EditLink {
            original,
            successor: SuccessorSpec {
                from: vec![vspec(&d, 1, 1), vspec(&d, 3, 1)],
                to: vec![vspec(&d, 2, 1)],
                ty: SlotArg::Addrs(vec![d.clone()]),
            },
            d_s: d.clone(),
            d_a: d.clone(),
        },
    ));

    let link =
        link_value(ex(&fx.febe, fx.user, Op::ReadLink { a: succ })).expect("the successor is resident");
    assert_eq!(link.from_slot().len(), 2, "both specs contributed a span to the slot");
}

/// §4: the successor slot's span budget, and where it is charged. A spec's
/// expansion is the SOURCE document's fragmentation, not the request's size —
/// one spec over a two-run region is two spans — so a short list of specs
/// names spans without bound. The slot is counted as it is built, so a
/// request past [`MAX_SLOT_SPANS`] is refused having held one slot's worth of
/// spans rather than every spec's, and with no transaction opened.
#[test]
fn an_over_budget_successor_slot_is_refused_before_any_transaction() {
    let fx = setup();
    let (d, original) = linked_doc(&fx);
    // Delete the middle element: the V gap closes, and what is left is two
    // elements at non-adjacent I-addresses — a two-run arrangement.
    ack(ex(&fx.febe, fx.user, Op::Delete { doc: d.clone(), p: vp(1, 2), width: nat(1) }));
    let region = || vspan(1, 1, 2);
    assert_eq!(
        runs(ex(&fx.febe, fx.user, Op::Image { d: d.clone(), region: vec![region()] })).len(),
        2,
        "the fixture is fragmented: one spec over this region resolves to two spans"
    );
    let two_spans = || skep_arrangement::VSpec { source: d.clone(), span: region() };

    let before = fx.febe.log_position();
    let rej = rejected(ex(
        &fx.febe,
        fx.user,
        Op::EditLink {
            original,
            successor: SuccessorSpec {
                from: vec![two_spans(); MAX_SLOT_SPANS / 2 + 1],
                to: vec![],
                ty: SlotArg::Addrs(vec![d.clone()]),
            },
            d_s: d.clone(),
            d_a: d,
        },
    ));
    assert_eq!(rej.op, OpKind::EditLink);
    assert_eq!(rej.code, RejectCode::SlotTooLarge);
    assert_eq!(rej.disposition, Disposition::Permanent, "no retry shrinks the slot");
    assert_eq!(fx.febe.log_position(), before, "the refusal opened no transaction");
}

/// §4, the other side of that boundary: a slot of exactly [`MAX_SLOT_SPANS`]
/// spans is the largest M7 accepts, and it is still accepted here. What the
/// budget refuses is what M7 would refuse; the counting moves where the
/// refusal happens, never which requests it answers.
#[test]
fn a_successor_slot_at_the_budget_is_still_accepted() {
    let fx = setup();
    let (d, original) = linked_doc(&fx);
    let one_span = || skep_arrangement::VSpec { source: d.clone(), span: vspan(1, 1, 1) };

    let (succ, _, _) = ack_edit(ex(
        &fx.febe,
        fx.user,
        Op::EditLink {
            original,
            successor: SuccessorSpec {
                from: vec![one_span(); MAX_SLOT_SPANS],
                to: vec![],
                ty: SlotArg::Addrs(vec![d.clone()]),
            },
            d_s: d.clone(),
            d_a: d.clone(),
        },
    ));
    let link =
        link_value(ex(&fx.febe, fx.user, Op::ReadLink { a: succ })).expect("the successor is resident");
    assert_eq!(link.from_slot().len(), MAX_SLOT_SPANS, "every span at the budget was deposited");
}

/// §4: the request-level refusal precedence, and what makes a successor's
/// `site.index` readable. Every slot offends here — the slots are built
/// `from`, then `to`, then `ty`, and the first refusal is the only answer —
/// so an index is a position within the slot that order arrives at, and a
/// client reading it against another slot would be pointed at the wrong spec.
#[test]
fn the_first_offending_successor_slot_is_the_one_that_speaks() {
    let fx = setup();
    let (d, original) = linked_doc(&fx);
    let unregistered =
        skep_arrangement::VSpec { source: addr(&[1, 0, 1, 0, 78]), span: vspan(1, 1, 1) };
    let ill_formed = skep_arrangement::VSpec { source: d.clone(), span: vspan(2, 1, 1) };

    // FROM offends at index 1; TO and TYPE each offend at index 0.
    let rej = rejected(ex(
        &fx.febe,
        fx.user,
        Op::EditLink {
            original,
            successor: SuccessorSpec {
                from: vec![vspec(&d, 1, 1), unregistered],
                to: vec![ill_formed.clone()],
                ty: SlotArg::Resolve(vec![ill_formed]),
            },
            d_s: d.clone(),
            d_a: d,
        },
    ));
    assert_eq!(
        rej.code,
        RejectCode::SourceNotRegistered,
        "FROM is built first, so FROM's fault is the one surfaced"
    );
    let site = rej.site.expect("M10 localizes its own successor faults");
    assert_eq!(
        site.slot,
        Some(FROM),
        "the answer says which slot that index is in, rather than leaving it to be deduced"
    );
    assert_eq!(site.index, Some(1), "the index is the offender's position within FROM");
}

/// The link family end-to-end: MAKELINK (no dedup), raw reads with the
/// in-band ⟨⟩ ≠ ⊥ FOLLOWLINK contract (§2), the M8 region/descriptor/
/// pointwise/lineage reads, EDITLINK's read-assembled successor (§4),
/// idempotent zero-step EMIT (§3), and the active-view consequences of
/// NULLIFY.
#[test]
fn link_lifecycle() {
    let fx = setup();
    let d = create_doc(&fx);
    let (start, _) = insert3(&fx, &d);
    let region = vec![vspan(1, 1, 3)];

    let mk = || Op::MakeLink {
        home: d.clone(),
        from: SlotArg::Resolve(vec![vspec(&d, 1, 1)]),
        to: SlotArg::Resolve(vec![vspec(&d, 2, 1)]),
        ty: SlotArg::Resolve(vec![vspec(&d, 3, 1)]),
    };
    let (l1, _) = ack_addr(ex(&fx.febe, fx.user, mk()));
    let (l2, _) = ack_addr(ex(&fx.febe, fx.user, mk()));
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
    assert_ne!(cov.expect("slot 1 exists"), SpanSet::empty());
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
    let inc = claims(ex(&fx.febe, fx.user, Op::InClaims { y: l1.clone(), view: View::Active }));
    assert_eq!(inc.len(), 2); // editlink's claim + the explicit assert_sup claim
    assert!(
        inc.iter().any(|c| c.claim == claim1 && c.new == succ),
        "editlink's own claim names its successor as what supersedes l1"
    );
    assert!(
        inc.iter().any(|c| c.claim == claim2 && c.new == l2 && c.active),
        "the explicit assert_sup claim names l2, and is active"
    );
    let out = claims(ex(&fx.febe, fx.user, Op::OutClaims { x: l2.clone(), view: View::Active }));
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].claim, claim2);

    // Idempotent zero-step EMIT (§3): a dedup hit returns (incumbent,
    // base_seq) with no commit — marshaled identically to the miss.
    let emit = || Op::Emit { home: d.clone(), ty: pred_def_ty(), from: start.clone(), to: vec![] };
    let (e1, at1) = ack_addr(ex(&fx.febe, fx.user, emit()));
    let log0 = fx.febe.log_position();
    let (e2, at2) = ack_addr(ex(&fx.febe, fx.user, emit()));
    assert_eq!(e2, e1);
    assert_eq!(at2, at1);
    assert_eq!(fx.febe.log_position(), log0);

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

/// §4: what M10's successor guard does NOT type. A source M3 has registered
/// but M5 has not yet arranged passes both checks and resolves to ⟨⟩, so the
/// successor commits with an empty FROM under an ordinary `AckEdit` — the
/// same empty slot MAKELINK's `Resolve` form deposits off the same run list,
/// and the boundary of what a client may conclude from a successful edit.
#[test]
fn an_unarranged_source_commits_an_empty_successor_slot() {
    let fx = setup();
    let d = create_doc(&fx);
    insert3(&fx, &d);
    let (original, _) = ack_addr(ex(
        &fx.febe,
        fx.user,
        Op::MakeLink {
            home: d.clone(),
            from: SlotArg::Resolve(vec![vspec(&d, 1, 1)]),
            to: SlotArg::Resolve(vec![vspec(&d, 2, 1)]),
            ty: SlotArg::Resolve(vec![vspec(&d, 3, 1)]),
        },
    ));

    // Registered by CREATENEWDOCUMENT, arranged by nothing: M5 arranges a
    // document only when something is written into it.
    let fresh = create_doc(&fx);
    let (succ, _, _) = ack_edit(ex(
        &fx.febe,
        fx.user,
        Op::EditLink {
            original,
            successor: SuccessorSpec {
                from: vec![vspec(&fresh, 1, 1)],
                to: vec![vspec(&d, 2, 1)],
                ty: SlotArg::Resolve(vec![vspec(&d, 3, 1)]),
            },
            d_s: d.clone(),
            d_a: d.clone(),
        },
    ));
    let link = link_value(ex(&fx.febe, fx.user, Op::ReadLink { a: succ })).expect("successor is resident");
    assert!(link.from_slot().is_empty(), "the unarranged source contributed no spans");
    assert!(!link.to_slot().is_empty(), "the arranged source did");
}

/// §5/§6: the typed rejection surface — the session gate, the
/// Reorder/Permanent disposition policy, M6's threaded FaultSite vs the
/// fieldless M5/M8 lowerings, the M10-side editlink guard, and the as-built
/// supersession fence.
#[test]
fn rejection_surface() {
    let fx = setup();
    let d = create_doc(&fx);
    let (start, _) = insert3(&fx, &d);

    // Write on an unbound (closed) session: Unauthenticated, pre-transaction.
    let stray = fx.febe.open_session(PrincipalId(9));
    fx.febe.close_session(stray);
    let rej = rejected(ex(
        &fx.febe,
        stray,
        Op::Insert { doc: d.clone(), at: vp(1, 1), values: vec![skep_content::Val::new(vec![1u8])] },
    ));
    assert_eq!(rej.op, OpKind::Insert);
    assert_eq!(rej.code, RejectCode::Unauthenticated);
    assert_eq!(rej.disposition, Disposition::Permanent);

    // M6's DocNotRegistered carries the offending document into the site;
    // ambiguous registration codes are hinted Reorder (§5).
    let ghost_doc = addr(&[1, 0, 1, 0, 77]);
    let rej = rejected(ex(
        &fx.febe,
        fx.user,
        Op::RetrieveV { specs: vec![Spec { doc: ghost_doc.clone(), span: vspan(1, 1, 1) }] },
    ));
    assert_eq!(rej.code, RejectCode::DocNotRegistered);
    assert_eq!(rej.disposition, Disposition::Reorder);
    assert_eq!(rej.site.expect("M6 localizes").addr, Some(ghost_doc.clone()));

    // M5's same-named code is fieldless — site None (§5).
    let rej = rejected(ex(
        &fx.febe,
        fx.user,
        Op::Delete { doc: ghost_doc, p: vp(1, 1), width: nat(1) },
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
    let mk = || Op::MakeLink {
        home: d.clone(),
        from: SlotArg::Resolve(vec![vspec(&d, 1, 1)]),
        to: SlotArg::Resolve(vec![vspec(&d, 2, 1)]),
        ty: SlotArg::Resolve(vec![vspec(&d, 3, 1)]),
    };
    let (l1, _) = ack_addr(ex(&fx.febe, fx.user, mk()));
    let (l2, _) = ack_addr(ex(&fx.febe, fx.user, mk()));
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
    // (Permanent) before freshness is even consulted.
    let rej = rejected(ex(
        &fx.febe,
        fx.boot,
        Op::Delegate { new_prefix: fx.account.tumbler().clone(), new_id: PrincipalId(8) },
    ));
    assert_eq!(rej.code, RejectCode::NotAuthorized);
    assert_eq!(rej.disposition, Disposition::Permanent);
}
