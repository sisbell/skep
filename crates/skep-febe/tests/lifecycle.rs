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
use skep_febe::{Disposition, Op, OpKind, RejectCode, SlotArg, SuccessorSpec};
use skep_links::{enc, View};
use skep_namespace::PrincipalId;
use skep_retrieval::{Region, Spec};

/// A link-subspace element address under `doc` that no MAKELINK ever minted.
fn ghost_link(doc: &skep_address::Address, ordinal: u32) -> skep_address::Address {
    elem_addr(ElemPos { doc: doc.clone(), subspace: n(2), ordinal: n(ordinal) })
        .unwrap_or_else(|_| panic!("valid element position"))
}

/// Bootstrap provisioning and the two namespace-structure reads (§2/§6):
/// NextAccountPrefix feeds Delegate; PrincipalPrefix resolves any principal's
/// public prefix (None = absent); RegisterNode runs under the bootstrap
/// session with no principal semantics.
#[test]
fn bootstrap_and_namespace_reads() {
    let fx = setup();

    // The delegated account is the prefix the read handed out (setup used it).
    let (mine, _) = maybe_addr(ex(&fx.op, fx.s, Op::PrincipalPrefix { id: USER }));
    assert_eq!(mine.expect("registered principal has a prefix"), fx.acct);

    // An unknown principal is None — absence, not a rejection.
    let (absent, _) = maybe_addr(ex(&fx.op, fx.s, Op::PrincipalPrefix { id: PrincipalId(99) }));
    assert!(absent.is_none());

    // The frontier advanced past the delegated prefix: the next peek differs.
    let (next, _) = maybe_addr(ex(&fx.op, fx.boot, Op::NextAccountPrefix { parent: node1() }));
    assert_ne!(next.expect("node still delegable"), fx.acct);

    // Node provisioning: supplied address, bootstrap session, AckAddr echo.
    let (node, _) = ack_addr(ex(&fx.op, fx.boot, Op::RegisterNode { addr: t(&[1, 2]) }));
    assert_eq!(node, a(&[1, 2]));
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
        &fx.op,
        fx.s,
        Op::RetrieveV { specs: vec![Spec { doc: d.clone(), span: vspan(1, 1, 3) }] },
    ));
    assert_eq!(items.0.len(), 3);
    assert!(as_of >= at);

    let (bound, _) = spanset(ex(&fx.op, fx.s, Op::RetrieveDocVSpan { doc: d.clone() }));
    assert_ne!(bound, SpanSet::empty());
    let (exact, _) = spanset(ex(&fx.op, fx.s, Op::RetrieveDocVSpanSet { doc: d.clone() }));
    assert_ne!(exact, SpanSet::empty());

    // Fork mints an EMPTY document (shares no content); Version is the
    // content-sharing fork (§3) — the two must not be conflated.
    let (f, _) = ack_addr(ex(&fx.op, fx.s, Op::Fork));
    let (f_set, _) = spanset(ex(&fx.op, fx.s, Op::RetrieveDocVSpanSet { doc: f.clone() }));
    assert_eq!(f_set, SpanSet::empty());
    let (v, _) = ack_addr(ex(&fx.op, fx.s, Op::Version { d_src: d.clone() }));
    let (v_set, _) = spanset(ex(&fx.op, fx.s, Op::RetrieveDocVSpanSet { doc: v.clone() }));
    assert_ne!(v_set, SpanSet::empty());

    // The version's content originated in d (SHOWORIGIN reports allocators).
    let origins = addrs(ex(&fx.op, fx.s, Op::ShowOrigin { doc: v.clone(), span: vspan(1, 1, 1) }));
    assert_eq!(origins, vec![d.clone()]);

    // COMPARE finds address-equal correspondences between d and its version.
    let rep = compare_rep(ex(
        &fx.op,
        fx.s,
        Op::Compare {
            rho1: vec![Region { doc: d.clone(), spans: vec![vspan(1, 1, 2)] }],
            rho2: vec![Region { doc: v.clone(), spans: vec![vspan(1, 1, 2)] }],
        },
    ));
    assert!(!rep.0.is_empty());

    // Present-tense containers of d's first element: at least d and v.
    let holders = addrs(ex(
        &fx.op,
        fx.s,
        Op::FindDocsContaining {
            regions: vec![Region { doc: d.clone(), spans: vec![vspan(1, 1, 1)] }],
        },
    ));
    assert!(holders.contains(&d) && holders.contains(&v));

    // COPY transcludes into the empty fork; its arrangement is now non-empty.
    ack(ex(&fx.op, fx.s, Op::Copy { doc: f.clone(), at: vp(1, 1), specs: vec![vspec(&d, 1, 1)] }));
    let (f_set, _) = spanset(ex(&fx.op, fx.s, Op::RetrieveDocVSpanSet { doc: f.clone() }));
    assert_ne!(f_set, SpanSet::empty());

    // DELETE closes the gap in d; the removed I-address is still current in
    // the version — exactly SHOWDELETIONS' a-with-b half.
    ack(ex(&fx.op, fx.s, Op::Delete { doc: d.clone(), p: vp(1, 3), width: n(1) }));
    let rep = deletions_rep(ex(&fx.op, fx.s, Op::ShowDeletions { d_a: d.clone(), d_b: v.clone() }));
    assert_eq!(rep.a_with_b.len(), 1);
    assert!(rep.b_with_a.is_empty());

    // REARRANGE (pivot, 3 cuts) over the remaining two elements.
    ack(ex(
        &fx.op,
        fx.s,
        Op::Rearrange { doc: d.clone(), cuts: vec![vp(1, 1), vp(1, 2), vp(1, 3)] },
    ));

    assert!(fx.op.log_position() >= at);
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

    let (addr1, at1) = ack_addr(ex_id(&fx.op, fx.s, b"ins-1", ins()));
    let log0 = fx.op.log_position();

    // Sequential retry: the rebuilt cached ack, no re-execution.
    let (addr2, at2) = ack_addr(ex_id(&fx.op, fx.s, b"ins-1", ins()));
    assert_eq!(addr2, addr1);
    assert_eq!(at2, at1);
    assert_eq!(fx.op.log_position(), log0);

    // Same ReqId under a DIFFERENT op-kind: a miss — the read executes (and
    // is itself never cached), leaving the write memo intact.
    let (set, _) = spanset(ex_id(&fx.op, fx.s, b"ins-1", Op::RetrieveDocVSpan { doc: d.clone() }));
    assert_ne!(set, SpanSet::empty());
    let (addr3, at3) = ack_addr(ex_id(&fx.op, fx.s, b"ins-1", ins()));
    assert_eq!(addr3, addr1);
    assert_eq!(at3, at1);
    assert_eq!(fx.op.log_position(), log0);

    // A replay under a fresh session misses and re-executes (per-session
    // confinement): new address, advanced log.
    let s2 = fx.op.open_session(USER);
    let (addr4, at4) = ack_addr(ex_id(&fx.op, s2, b"ins-1", ins()));
    assert_ne!(addr4, addr1);
    assert!(at4 > at1);
    assert!(fx.op.log_position() > log0);

    // The original session's memo is still confined and intact…
    let (addr5, at5) = ack_addr(ex_id(&fx.op, fx.s, b"ins-1", ins()));
    assert_eq!(addr5, addr1);
    assert_eq!(at5, at1);

    // …until close_session retires the binding (a later write on the retired
    // id is Unauthenticated — and its idem entries are purged, §6).
    fx.op.close_session(fx.s);
    let rej = rejected(ex_id(&fx.op, fx.s, b"ins-1", ins()));
    assert_eq!(rej.code, RejectCode::Unauthenticated);
    assert_eq!(rej.disposition, Disposition::Permanent);
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
    let (l1, _) = ack_addr(ex(&fx.op, fx.s, mk()));
    let (l2, _) = ack_addr(ex(&fx.op, fx.s, mk()));
    assert_ne!(l1, l2); // MAKELINK never dedups — distinct links always

    // Raw reads: value-or-None, and FOLLOWLINK's in-band Result — absence is
    // Err(Invalid) INSIDE Response::Follow, never a Rejection (§2).
    assert!(link_value(ex(&fx.op, fx.s, Op::ReadLink { a: l1.clone() })).is_some());
    assert!(link_value(ex(&fx.op, fx.s, Op::ReadLink { a: ghost_link(&d, 99) })).is_none());
    let cov = follow(ex(&fx.op, fx.s, Op::FollowLink { a: l1.clone(), slot: 1 }));
    assert_ne!(cov.expect("slot 1 exists"), SpanSet::empty());
    assert!(follow(ex(&fx.op, fx.s, Op::FollowLink { a: ghost_link(&d, 99), slot: 1 })).is_err());
    assert!(follow(ex(&fx.op, fx.s, Op::FollowLink { a: l1.clone(), slot: 9 })).is_err());

    // Region family (foundation ∩ active).
    assert!(!runs(ex(&fx.op, fx.s, Op::Image { d: d.clone(), region: region.clone() })).is_empty());
    assert_eq!(count(ex(&fx.op, fx.s, Op::CountV { d: d.clone(), region: region.clone() })), 2);
    let found = addrs(ex(&fx.op, fx.s, Op::FindLinksV { d: d.clone(), region: region.clone() }));
    assert!(found.contains(&l1) && found.contains(&l2));
    let w = page(ex(
        &fx.op,
        fx.s,
        Op::WindowV { d: d.clone(), region: region.clone(), cur: None, n: 1 },
    ));
    assert_eq!(w.batch.len(), 1);
    assert!(!w.exhausted);
    assert!(!endsets(ex(&fx.op, fx.s, Op::RetrieveEndsets { d: d.clone(), region: region.clone() }))
        .is_empty());

    // Descriptor family (address-keyed, home-projected, total).
    let home_q = || FourSet {
        home: SlotSpec::Spans(enc([&d])),
        from: SlotSpec::Any,
        to: SlotSpec::Any,
        ty: SlotSpec::Any,
    };
    let ftt = addrs(ex(&fx.op, fx.s, Op::FindLinksFtt { q: home_q() }));
    assert!(ftt.contains(&l1) && ftt.contains(&l2));
    assert!(count(ex(&fx.op, fx.s, Op::CountFtt { q: home_q() })) >= 2);
    let w = page(ex(&fx.op, fx.s, Op::WindowFtt { q: home_q(), cur: None, n: 1 }));
    assert_eq!(w.batch.len(), 1);

    // Pointwise projection & discoverability.
    let (proj, _) = spanset(ex(&fx.op, fx.s, Op::Project { a: l1.clone(), slot: 1, d: d.clone() }));
    assert_ne!(proj, SpanSet::empty());
    assert!(boolv(ex(&fx.op, fx.s, Op::DiscoverableFrom { a: l1.clone(), d: d.clone() })));

    // EDITLINK: content successor assembled by M10 off a prior snapshot (§4).
    let (succ, claim1, _) = ack_edit(ex(
        &fx.op,
        fx.s,
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
        ack_addr(ex(&fx.op, fx.s, Op::AssertSup { home: d.clone(), old: l1.clone(), new: l2.clone() }));
    let inc = claims(ex(&fx.op, fx.s, Op::InClaims { y: l1.clone(), view: View::Active }));
    assert_eq!(inc.len(), 2); // editlink's claim + the explicit assert_sup claim
    assert!(inc.iter().any(|c| c.claim == claim1 && c.new == succ));
    assert!(inc.iter().any(|c| c.claim == claim2 && c.new == l2 && c.active));
    let out = claims(ex(&fx.op, fx.s, Op::OutClaims { x: l2.clone(), view: View::Active }));
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].claim, claim2);

    // Idempotent zero-step EMIT (§3): a dedup hit returns (incumbent,
    // base_seq) with no commit — marshaled identically to the miss.
    let emit = || Op::Emit { home: d.clone(), ty: pred_def_ty(), from: start.clone(), to: vec![] };
    let (e1, eat1) = ack_addr(ex(&fx.op, fx.s, emit()));
    let log0 = fx.op.log_position();
    let (e2, eat2) = ack_addr(ex(&fx.op, fx.s, emit()));
    assert_eq!(e2, e1);
    assert_eq!(eat2, eat1);
    assert_eq!(fx.op.log_position(), log0);

    // Pre-edit survival preview (the last-witness condition over the active
    // view): l1/l2/succ keep witnesses at ordinals 2–3, but the pred-def
    // tuple's only content anchor IS the element being deleted — it alone
    // is reported dropped from d.
    let rep = orphans(ex(&fx.op, fx.s, Op::DeleteOrphans { d: d.clone(), p: vp(1, 1), width: n(1) }));
    assert_eq!(rep.orphaned, vec![e1.clone()]);

    // NULLIFY retracts l2: present-state reads are active-filtered
    // (foundation ∩ active — the region family stabs the link-store index,
    // so the unseated editlink successor and the pred-def tuple, whose
    // endsets cover these I-extents, still surface), and discoverable_from
    // is compound "reachable AND active". The retraction tuple r itself
    // surfaces too: nullify deposits [enc({home}), enc({target}), [R]], and
    // enc is the subtree-span encoding (AD), so a document-homed FROM covers
    // every content I-extent under d — and r is active.
    let (r, _) = ack_addr(ex(&fx.op, fx.s, Op::Nullify { home: d.clone(), target: l2.clone() }));
    assert!(!boolv(ex(&fx.op, fx.s, Op::DiscoverableFrom { a: l2.clone(), d: d.clone() })));
    let found = addrs(ex(&fx.op, fx.s, Op::FindLinksV { d: d.clone(), region: region.clone() }));
    assert!(found.contains(&l1) && found.contains(&succ) && found.contains(&e1));
    assert!(found.contains(&r) && !found.contains(&l2));
    assert_eq!(count(ex(&fx.op, fx.s, Op::CountV { d: d.clone(), region })), 4);
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
    let stray = fx.op.open_session(PrincipalId(9));
    fx.op.close_session(stray);
    let rej = rejected(ex(
        &fx.op,
        stray,
        Op::Insert { doc: d.clone(), at: vp(1, 1), values: vec![skep_content::Val::new(vec![1u8])] },
    ));
    assert_eq!(rej.op, OpKind::Insert);
    assert_eq!(rej.code, RejectCode::Unauthenticated);
    assert_eq!(rej.disposition, Disposition::Permanent);

    // M6's DocNotRegistered carries the offending document into the site;
    // ambiguous registration codes are hinted Reorder (§5).
    let ghost_doc = a(&[1, 0, 1, 0, 77]);
    let rej = rejected(ex(
        &fx.op,
        fx.s,
        Op::RetrieveV { specs: vec![Spec { doc: ghost_doc.clone(), span: vspan(1, 1, 1) }] },
    ));
    assert_eq!(rej.code, RejectCode::DocNotRegistered);
    assert_eq!(rej.disposition, Disposition::Reorder);
    assert_eq!(rej.site.expect("M6 localizes").addr, Some(ghost_doc.clone()));

    // M5's same-named code is fieldless — site None (§5).
    let rej = rejected(ex(
        &fx.op,
        fx.s,
        Op::Delete { doc: ghost_doc, p: vp(1, 1), width: n(1) },
    ));
    assert_eq!(rej.code, RejectCode::DocNotRegistered);
    assert_eq!(rej.disposition, Disposition::Reorder);
    assert!(rej.site.is_none());

    // The canonical out-of-order retraction: BadTarget ⇒ Reorder (§5).
    let rej = rejected(ex(
        &fx.op,
        fx.s,
        Op::Nullify { home: d.clone(), target: ghost_link(&d, 99) },
    ));
    assert_eq!(rej.code, RejectCode::BadTarget);
    assert_eq!(rej.disposition, Disposition::Reorder);

    // M10's own editlink guard: an ill-formed (link-subspace) content VSpec
    // is a typed IllFormedSpec, never M5's silent ⟨⟩ clip (§4).
    let ill_formed = skep_arrangement::VSpec { source: d.clone(), span: vspan(2, 1, 1) };
    let rej = rejected(ex(
        &fx.op,
        fx.s,
        Op::EditLink {
            original: ghost_link(&d, 99),
            successor: SuccessorSpec {
                from: vec![ill_formed],
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

    // The same guard on the other fault a successor spec can carry: a source
    // M3 does not know resolves to ⟨⟩, so it is refused instead of committed
    // as an empty slot — and hinted Reorder, since a client that arrives
    // ahead of its own CREATENEWDOCUMENT may reissue (§4).
    let unregistered =
        skep_arrangement::VSpec { source: a(&[1, 0, 1, 0, 78]), span: vspan(1, 1, 1) };
    let rej = rejected(ex(
        &fx.op,
        fx.s,
        Op::EditLink {
            original: ghost_link(&d, 99),
            successor: SuccessorSpec {
                from: vec![unregistered],
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

    // The as-built [K_sup] emit fence lowers to DcViolation (report: drift):
    // supersession claims write only via AssertSup/EditLink.
    let mk = || Op::MakeLink {
        home: d.clone(),
        from: SlotArg::Resolve(vec![vspec(&d, 1, 1)]),
        to: SlotArg::Resolve(vec![vspec(&d, 2, 1)]),
        ty: SlotArg::Resolve(vec![vspec(&d, 3, 1)]),
    };
    let (l1, _) = ack_addr(ex(&fx.op, fx.s, mk()));
    let (l2, _) = ack_addr(ex(&fx.op, fx.s, mk()));
    let rej = rejected(ex(
        &fx.op,
        fx.s,
        Op::Emit { home: d.clone(), ty: supersedes_ty(), from: l1.clone(), to: vec![l2] },
    ));
    assert_eq!(rej.code, RejectCode::DcViolation);
    assert_eq!(rej.disposition, Disposition::Permanent);

    // Contrast with FOLLOWLINK's in-band Invalid: Project's non-link IS a
    // precondition failure and IS lowered (§2).
    let rej = rejected(ex(&fx.op, fx.s, Op::Project { a: start, slot: 1, d: d.clone() }));
    assert_eq!(rej.code, RejectCode::NotALink);
    assert_eq!(rej.disposition, Disposition::Permanent);

    // A link-subspace region is BadRegion (M8 gates; M10 forwards verbatim).
    let rej = rejected(ex(
        &fx.op,
        fx.s,
        Op::WindowV { d: d.clone(), region: vec![vspan(2, 1, 1)], cur: None, n: 1 },
    ));
    assert_eq!(rej.code, RejectCode::BadRegion);
    assert_eq!(rej.disposition, Disposition::Permanent);

    // Append-only allocations: a re-registered node is NotFresh — Permanent,
    // steering to re-derivation, never reissue-polling (§5).
    ack_addr(ex(&fx.op, fx.boot, Op::RegisterNode { addr: t(&[1, 7]) }));
    let rej = rejected(ex(&fx.op, fx.boot, Op::RegisterNode { addr: t(&[1, 7]) }));
    assert_eq!(rej.code, RejectCode::NotFresh);
    assert_eq!(rej.disposition, Disposition::Permanent);

    // Re-delegating an already-delegated prefix: ω(new_prefix) now names the
    // delegated principal, so M3's pinned gate order rejects NotAuthorized
    // (Permanent) before freshness is even consulted.
    let rej = rejected(ex(
        &fx.op,
        fx.boot,
        Op::Delegate { new_prefix: fx.acct.tumbler().clone(), new_id: PrincipalId(8) },
    ));
    assert_eq!(rej.code, RejectCode::NotAuthorized);
    assert_eq!(rej.disposition, Disposition::Permanent);
}
