//! The linearization coordinate, over the whole operation set: every write
//! acknowledges at the coordinate it committed (A1/A7/V1), and every read
//! reports the snapshot it answered from (A2/V1). One test per side, each a
//! law over its half of the partition rather than a sample of it — a wrong
//! coordinate is the failure a correct answer hides, because a client's
//! read-your-writes and its pagination both key off nothing else.

mod common;

use common::*;
use skep_content::Val;
use skep_discovery::{FourSet, SlotSpec};
use skep_febe::{Op, OpKind, Response, SlotArg, SuccessorSpec, FROM};
use skep_kernel::Seq;
use skep_links::{enc, View};
use skep_namespace::PrincipalId;
use skep_retrieval::{Region, Spec};

/// The committed coordinate an acknowledgment carries, whichever of the
/// three acknowledging shapes it is.
fn at_of(kind: OpKind, r: &Response) -> Seq {
    match r {
        Response::Ack { at } | Response::AckAddr { at, .. } | Response::AckEdit { at, .. } => *at,
        Response::Rejected(rej) => panic!("{kind:?} was rejected: {rej}"),
        _ => panic!("{kind:?} did not acknowledge a committed write"),
    }
}

/// One write's promise: the `at` it reported IS the log head it just moved
/// to. Exact, and safe to state exactly — M2 mints one `Seq` per record and
/// returns the last of the range, which is the installed root's coordinate,
/// and a zero-step transaction returns the base seq, which is that same head.
fn committed(fx: &Fx, kind: OpKind, r: &Response, seen: &mut Vec<OpKind>) {
    assert_eq!(
        at_of(kind, r),
        fx.op.log_position(),
        "{kind:?} acknowledged at a coordinate that is not the one it committed"
    );
    assert!(!seen.contains(&kind), "{kind:?} is covered twice");
    seen.push(kind);
}

/// A1/A7/V1: `committed_at` on EVERY write is the operation's own
/// linearization point. A sequential chain over all fourteen writes, each
/// checked against the log head the moment it returns — the coordinate is
/// what a client waits at, so a stale or invented one breaks read-your-writes
/// while every answer still looks right.
#[test]
fn every_write_acks_at_the_coordinate_it_committed() {
    let fx = setup();
    let mut seen: Vec<OpKind> = Vec::new();

    // ── the document family ──
    let r = ex(&fx.op, fx.s, Op::CreateNewDocument { account: fx.acct.clone() });
    committed(&fx, OpKind::CreateNewDocument, &r, &mut seen);
    let (d, _) = ack_addr(r);

    let r = ex(
        &fx.op,
        fx.s,
        Op::Insert {
            doc: d.clone(),
            at: vp(1, 1),
            values: vec![Val::new(vec![b'a']), Val::new(vec![b'b']), Val::new(vec![b'c'])],
        },
    );
    committed(&fx, OpKind::Insert, &r, &mut seen);

    let r = ex(&fx.op, fx.s, Op::Fork);
    committed(&fx, OpKind::Fork, &r, &mut seen);
    let (f, _) = ack_addr(r);

    let r = ex(&fx.op, fx.s, Op::Version { d_src: d.clone() });
    committed(&fx, OpKind::Version, &r, &mut seen);

    let r = ex(&fx.op, fx.s, Op::Copy { doc: f, at: vp(1, 1), specs: vec![vspec(&d, 1, 1)] });
    committed(&fx, OpKind::Copy, &r, &mut seen);

    let r = ex(&fx.op, fx.s, Op::Delete { doc: d.clone(), p: vp(1, 3), width: n(1) });
    committed(&fx, OpKind::Delete, &r, &mut seen);

    let r = ex(
        &fx.op,
        fx.s,
        Op::Rearrange { doc: d.clone(), cuts: vec![vp(1, 1), vp(1, 2), vp(1, 3)] },
    );
    committed(&fx, OpKind::Rearrange, &r, &mut seen);

    // ── the link family, on a document whose three ordinals are intact ──
    let e = create_doc(&fx);
    let (e_start, _) = insert3(&fx, &e);
    let mk = || Op::MakeLink {
        home: e.clone(),
        from: SlotArg::Resolve(vec![vspec(&e, 1, 1)]),
        to: SlotArg::Resolve(vec![vspec(&e, 2, 1)]),
        ty: SlotArg::Resolve(vec![vspec(&e, 3, 1)]),
    };

    let r = ex(&fx.op, fx.s, mk());
    committed(&fx, OpKind::MakeLink, &r, &mut seen);
    let (l1, _) = ack_addr(r);
    let (l2, _) = ack_addr(ex(&fx.op, fx.s, mk()));

    let r = ex(
        &fx.op,
        fx.s,
        Op::EditLink {
            original: l1.clone(),
            successor: SuccessorSpec {
                from: vec![vspec(&e, 1, 1)],
                to: vec![vspec(&e, 2, 1)],
                ty: SlotArg::Resolve(vec![vspec(&e, 3, 1)]),
            },
            d_s: e.clone(),
            d_a: e.clone(),
        },
    );
    committed(&fx, OpKind::EditLink, &r, &mut seen);

    let r =
        ex(&fx.op, fx.s, Op::AssertSup { home: e.clone(), old: l1, new: l2.clone() });
    committed(&fx, OpKind::AssertSup, &r, &mut seen);

    let r = ex(
        &fx.op,
        fx.s,
        Op::Emit { home: e.clone(), ty: pred_def_ty(), from: e_start, to: vec![] },
    );
    committed(&fx, OpKind::Emit, &r, &mut seen);

    let r = ex(&fx.op, fx.s, Op::Nullify { home: e, target: l2 });
    committed(&fx, OpKind::Nullify, &r, &mut seen);

    // ── provisioning, under the bootstrap session ──
    let (prefix, _) = maybe_addr(ex(&fx.op, fx.boot, Op::NextAccountPrefix { parent: node1() }));
    let prefix = prefix.expect("the genesis node is still delegable");
    let r = ex(
        &fx.op,
        fx.boot,
        Op::Delegate { new_prefix: prefix.tumbler().clone(), new_id: PrincipalId(11) },
    );
    committed(&fx, OpKind::Delegate, &r, &mut seen);

    let r = ex(&fx.op, fx.boot, Op::RegisterNode { addr: t(&[1, 4]) });
    committed(&fx, OpKind::RegisterNode, &r, &mut seen);

    assert_eq!(seen.len(), 14, "the write half of the partition is 14 operations: {seen:?}");
}

/// A2/V1: `as_of` on EVERY read is the coordinate of the snapshot the answer
/// came from. Nothing writes during the loop, so the log head taken once
/// ahead of it is that coordinate for all 24 — a read that reports anything
/// else is telling the client it has seen a position it has not.
///
/// This pins the coordinate M10 *reports*. That every constituent of one
/// answer came off one root (A3/V2) is structural — it belongs to the single
/// snapshot `dispatch_read` pins — and no single-threaded test can distinguish
/// it from two snapshots taken in a quiet moment.
#[test]
fn every_read_reports_the_log_head_as_its_as_of() {
    let fx = setup();
    let d = create_doc(&fx);
    insert3(&fx, &d);
    let (v, _) = ack_addr(ex(&fx.op, fx.s, Op::Version { d_src: d.clone() }));
    let mk = || Op::MakeLink {
        home: d.clone(),
        from: SlotArg::Resolve(vec![vspec(&d, 1, 1)]),
        to: SlotArg::Resolve(vec![vspec(&d, 2, 1)]),
        ty: SlotArg::Resolve(vec![vspec(&d, 3, 1)]),
    };
    let (l1, _) = ack_addr(ex(&fx.op, fx.s, mk()));
    let (l2, _) = ack_addr(ex(&fx.op, fx.s, mk()));
    ack_addr(ex(
        &fx.op,
        fx.s,
        Op::AssertSup { home: d.clone(), old: l1.clone(), new: l2.clone() },
    ));

    let region = || vec![vspan(1, 1, 3)];
    let q = || FourSet {
        home: SlotSpec::Spans(enc([&d])),
        from: SlotSpec::Any,
        to: SlotSpec::Any,
        ty: SlotSpec::Any,
    };
    let reads = vec![
        Op::NextAccountPrefix { parent: node1() },
        Op::PrincipalPrefix { id: USER },
        Op::ReadLink { a: l1.clone() },
        Op::FollowLink { a: l1.clone(), slot: FROM },
        Op::RetrieveV { specs: vec![Spec { doc: d.clone(), span: vspan(1, 1, 3) }] },
        Op::RetrieveDocVSpan { doc: d.clone() },
        Op::RetrieveDocVSpanSet { doc: d.clone() },
        Op::ShowOrigin { doc: v.clone(), span: vspan(1, 1, 1) },
        Op::ShowDeletions { d_a: d.clone(), d_b: v.clone() },
        Op::Compare {
            rho1: vec![Region { doc: d.clone(), spans: vec![vspan(1, 1, 2)] }],
            rho2: vec![Region { doc: v, spans: vec![vspan(1, 1, 2)] }],
        },
        Op::FindDocsContaining {
            regions: vec![Region { doc: d.clone(), spans: vec![vspan(1, 1, 1)] }],
        },
        Op::Image { d: d.clone(), region: region() },
        Op::FindLinksV { d: d.clone(), region: region() },
        Op::FindLinksFtt { q: q() },
        Op::CountV { d: d.clone(), region: region() },
        Op::CountFtt { q: q() },
        Op::WindowV { d: d.clone(), region: region(), cur: None, n: 1 },
        Op::WindowFtt { q: q(), cur: None, n: 1 },
        Op::RetrieveEndsets { d: d.clone(), region: region() },
        Op::Project { a: l1.clone(), slot: FROM, d: d.clone() },
        Op::DiscoverableFrom { a: l1.clone(), d: d.clone() },
        Op::DeleteOrphans { d: d.clone(), p: vp(1, 1), width: n(1) },
        Op::InClaims { y: l1, view: View::Active },
        Op::OutClaims { x: l2, view: View::Active },
    ];

    let kinds: Vec<OpKind> = reads.iter().map(Op::kind).collect();
    assert_eq!(kinds.len(), 24, "the read half of the partition is 24 operations");
    for (i, a) in kinds.iter().enumerate() {
        for b in &kinds[i + 1..] {
            assert_ne!(a, b, "{a:?} is covered twice");
        }
    }

    let head = fx.op.log_position();
    for op in reads {
        let kind = op.kind();
        let r = ex(&fx.op, fx.s, op);
        assert_eq!(as_of(&r), head, "{kind:?} reports the snapshot it answered from");
    }
    assert_eq!(fx.op.log_position(), head, "no read moves the log");
}
