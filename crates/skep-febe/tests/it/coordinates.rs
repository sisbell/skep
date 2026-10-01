//! The linearization coordinate, over the whole operation set: every write
//! acknowledges at the coordinate it committed (A1/A7/V1), and every read
//! reports the snapshot it answered from (A2/V1). One test per side, each a
//! law over its half of the partition rather than a sample of it — a wrong
//! coordinate is the failure a correct answer hides, because a client's
//! read-your-writes and its pagination both key off nothing else — and one
//! for the write that commits nothing: answered with an incumbent it
//! deduplicated against, it acknowledges at the base it found it in.

use crate::common;

use common::*;
use skep_discovery::{FourSet, SlotSpec};
use skep_febe::{Op, OpKind, Response, SlotArg, FROM};
use skep_links::{enc, View};
use skep_retrieval::{RegionSpec, Spec};

/// One write's promise: the `at` it reported IS the committed head it just
/// moved to. Exact, and safe to state exactly — M2 mints one `Seq` per record
/// and returns the last of the range, which is the installed root's
/// coordinate, and a zero-step transaction returns the base seq, which is
/// that same head. And it is no snapshot coordinate: [`Response::as_of`]
/// answers `None` for every acknowledging shape.
fn assert_committed(fx: &Fixture, kind: OpKind, r: &Response, seen: &mut Vec<OpKind>) {
    assert_eq!(
        at_of(kind, r),
        fx.febe.log_position(),
        "{kind:?} acknowledged at a coordinate that is not the one it committed"
    );
    assert_eq!(r.as_of(), None, "{kind:?}: an acknowledgment reports no snapshot");
    assert!(!seen.contains(&kind), "{kind:?} is covered twice");
    seen.push(kind);
}

/// A1/A7/V1: `committed_at` on EVERY write is the operation's own
/// linearization point. A sequential chain over all fifteen writes
/// ([`commit_every_write`]), each checked against the committed head the
/// moment it returns — the coordinate is what a client waits at, so a stale
/// or invented one breaks read-your-writes while every answer still looks
/// right.
#[test]
fn every_write_acks_at_the_coordinate_it_committed() {
    let fx = setup();
    let mut seen: Vec<OpKind> = Vec::new();
    commit_every_write(&fx, None, |kind, _, r| assert_committed(&fx, kind, r, &mut seen));
    assert_eq!(seen.len(), 15, "the write half of the partition is 15 operations: {seen:?}");
}

/// A1 on the zero-step write (`Response::AckAddr`): one answered with an
/// incumbent it deduplicated against commits nothing, and acknowledges at the
/// coordinate of the base it found that incumbent in — the committed head when
/// it ran, NOT the incumbent's own commit — so a read at or past `at` reflects
/// it. A write lands between the two emits, which is what tells those two
/// coordinates apart.
#[test]
fn a_deduplicated_write_acknowledges_at_the_base_it_found_its_incumbent_in() {
    let fx = setup();
    let d = create_doc(&fx);
    let (start, _) = insert3(&fx, &d);
    let emit = || Op::Emit { home: d.clone(), ty: pred_def_ty(), from: start.clone(), to: vec![] };
    let (incumbent, committed_at) = ack_addr(ex(&fx.febe, fx.user, emit()));
    let _ = create_doc(&fx); // a later write moves the head past the incumbent's commit
    let head = fx.febe.log_position();
    assert!(head > committed_at, "premise: the head has moved past the incumbent");
    let (again, at) = ack_addr(ex(&fx.febe, fx.user, emit()));
    assert_eq!(again, incumbent, "the incumbent answers");
    assert_eq!(at, head, "at the base it was found in, not the incumbent's commit");
    assert_eq!(fx.febe.log_position(), head, "and nothing committed");
}

/// A2/V1: `as_of` on EVERY read is the coordinate of the snapshot the answer
/// came from. Nothing writes during the loop, so the committed head taken
/// once ahead of it is that coordinate for all 28 — a read that reports
/// anything else is telling the client it has seen a position it has not.
///
/// The 28 answer in all nineteen read shapes, so the law is also the one
/// check on [`Response::as_of`] and [`Response::as_of_mut`]: each is asked of
/// every read shape and must answer the head, so a shape either accessor
/// moved into its `None` arm — a stamp a historical door would then skip —
/// fails here.
///
/// This pins the coordinate M10 *reports*. That every constituent of one
/// answer came off one root (A3/V2) is structural — it belongs to the single
/// snapshot `dispatch_read` pins — and no single-threaded test can distinguish
/// it from two snapshots taken in a quiet moment.
#[test]
fn every_read_reports_the_committed_head_as_its_as_of() {
    let fx = setup();
    let draft = create_doc(&fx);
    insert3(&fx, &draft);
    // The version's source is a PUBLISHED edition with content — the one
    // owned source `version` admits (PUB-2.9) — deposited into (PUB-2.59).
    let edition = create_edition(&fx);
    deposit3(&fx, &edition);
    let (version, _) = ack_addr(ex(&fx.febe, fx.user, Op::Version { d_src: edition, published: None }));
    let make = || Op::MakeLink {
        home: draft.clone(),
        from: SlotArg::Resolve(vec![vspec(&draft, 1, 1)]),
        to: SlotArg::Resolve(vec![vspec(&draft, 2, 1)]),
        ty: SlotArg::Resolve(vec![vspec(&draft, 3, 1)]),
        replaces: None,
    };
    let (l1, _) = ack_addr(ex(&fx.febe, fx.user, make()));
    let (l2, _) = ack_addr(ex(&fx.febe, fx.user, make()));
    ack_addr(ex(
        &fx.febe,
        fx.user,
        Op::AssertSup { home: draft.clone(), old: l1.clone(), new: l2.clone() },
    ));

    let region = || vec![vspan(1, 1, 3)];
    let q = || FourSet {
        home: SlotSpec::Spans(enc([&draft])),
        from: SlotSpec::Any,
        to: SlotSpec::Any,
        ty: SlotSpec::Any,
    };
    let reads = vec![
        Op::NextAccountPrefix { parent: node1() },
        Op::PrincipalPrefix { id: USER },
        Op::EffectiveOwner { addr: fx.account.clone() },
        Op::ReadLink { a: l1.clone() },
        Op::FollowLink { a: l1.clone(), slot: FROM },
        Op::RetrieveV { specs: vec![Spec { doc: draft.clone(), span: vspan(1, 1, 3) }] },
        Op::RetrieveDocVSpan { doc: draft.clone() },
        Op::RetrieveDocVSpanSet { doc: draft.clone() },
        Op::ShowOrigin { doc: version.clone(), span: vspan(1, 1, 1) },
        Op::ShowDeletions { d_a: draft.clone(), d_b: version.clone() },
        Op::Compare {
            rho1: vec![RegionSpec { doc: draft.clone(), spans: vec![vspan(1, 1, 2)] }],
            rho2: vec![RegionSpec { doc: version, spans: vec![vspan(1, 1, 2)] }],
        },
        Op::FindDocsContaining {
            regions: vec![RegionSpec { doc: draft.clone(), spans: vec![vspan(1, 1, 1)] }],
        },
        Op::Image { d: draft.clone(), region: region() },
        Op::FindLinksV { d: draft.clone(), region: region() },
        Op::FindLinksFtt { q: q() },
        Op::CountV { d: draft.clone(), region: region() },
        Op::CountFtt { q: q() },
        Op::WindowV { d: draft.clone(), region: region(), cur: None, n: 1 },
        Op::WindowFtt { q: q(), cur: None, n: 1 },
        Op::RetrieveEndsets { d: draft.clone(), region: region() },
        Op::Project { a: l1.clone(), slot: FROM, d: draft.clone() },
        Op::DiscoverableFrom { a: l1.clone(), d: draft.clone() },
        Op::DeleteOrphans { d: draft.clone(), p: vp(1, 1), width: nat(1) },
        Op::InClaims { y: l1, view: View::Active },
        Op::OutClaims { x: l2, view: View::Active },
        Op::DocMetadata { doc: draft.clone() },
        Op::EditionClaims { target: draft.clone() },
        Op::UniversalGrants,
    ];

    let kinds: Vec<OpKind> = reads.iter().map(Op::kind).collect();
    assert_eq!(kinds.len(), 28, "the read half of the partition is 28 operations");
    for (i, a) in kinds.iter().enumerate() {
        for b in &kinds[i + 1..] {
            assert_ne!(a, b, "{a:?} is covered twice");
        }
    }

    let head = fx.febe.log_position();
    let mut shapes = std::collections::HashSet::new();
    for op in reads {
        let kind = op.kind();
        let mut r = ex(&fx.febe, fx.user, op);
        assert_eq!(as_of(&r), head, "{kind:?} reports the snapshot it answered from");
        assert_eq!(
            r.as_of_mut().copied(),
            Some(head),
            "{kind:?}: the mutable accessor classifies the shape alike"
        );
        shapes.insert(std::mem::discriminant(&r));
    }
    assert_eq!(shapes.len(), 19, "the 28 reads answer in every one of the nineteen read shapes");
    assert_eq!(fx.febe.log_position(), head, "no read moves the log");
}
