//! REINSTATE's in-crate claims, in a world whose arrangement and content
//! store are seeded INDEPENDENTLY — a state no engine reaches: the guard
//! order the op states where the unit state can reach it (the destination's
//! publication ahead of every run, a run's shape ahead of its registration
//! and its bytes, the first defective run deciding), THE EVERY-ADDRESS PROBE
//! that COPY's start-alone gate does not make, the run budget measured as
//! each run lands, and the empty list.

use serde::{Deserialize, Serialize};
use skep_content::{stage_write, ContentStore, Val};
use skep_kernel::{Kernel, Seq};
use skep_namespace::PrincipalId;

use super::*;
use crate::state::M5State;
use crate::testutil::{
    a, ca, doc1, doc2, la, mem_kernel_of, n, pdoc, rejected, run, seeded_m3, vp,
};

/// A world carrying a content store beside the arrangement, as COPY's own
/// tests build one: the two halves of S3★ set apart, so a test can say which
/// addresses the op probes.
#[derive(Clone, Serialize, Deserialize)]
struct GateWorld {
    m3: M3State,
    content: ContentStore,
    m5: M5State,
}

impl WorldState for GateWorld {
    type Record = M5Rec;
    fn apply(&self, _at: Seq, r: &M5Rec) -> GateWorld {
        GateWorld {
            m3: self.m3.clone(),
            content: self.content.clone(),
            m5: self.m5.apply_m5(r),
        }
    }
}
impl HasM3 for GateWorld {
    fn m3(&self) -> &M3State {
        &self.m3
    }
}
impl HasContent for GateWorld {
    fn content(&self) -> &ContentStore {
        &self.content
    }
}
impl HasM5 for GateWorld {
    fn m5(&self) -> &M5State {
        &self.m5
    }
}

/// A world arranging NOTHING — no document holds any position — with the
/// content store holding the bytes of exactly doc1's addresses `present`.
/// What a reinstate places here, no arrangement vouches for: the probe
/// alone decides.
fn gate_kernel(present: &[u32]) -> Kernel<GateWorld> {
    let mut content = ContentStore::default();
    for &k in present {
        let cw = stage_write(&content, ca(k), Val::new(&b"x"[..]))
            .expect("each seeded address is written once");
        content = content.apply_write(&cw);
    }
    mem_kernel_of(GateWorld {
        m3: seeded_m3(),
        content,
        m5: M5State::genesis(),
    })
}

/// A run of doc1's I-space, `width` positions from `ca(start)`, stated
/// under doc1 — the client's statement as the wire carries it.
fn of_doc1(start: u32, width: u32) -> ShotRun {
    ShotRun { origin: doc1(), run: run(&ca(start), width) }
}

fn content_count(k: &Kernel<GateWorld>, doc: &Address) -> skep_address::Nat {
    k.snapshot().world().m5().content_count(doc)
}

/// T1a — PUB-2.11 on REINSTATE's destination: the refusal fires ahead of
/// every per-run check and ahead of the destination's own shape checks, so a
/// run defective in every later way never speaks; into a draft the same run
/// is judged, and refused for what it is.
#[test]
fn reinstate_into_a_published_destination_refuses_before_any_run_is_judged() {
    let p1 = Caller::Principal(PrincipalId(1));
    let k = gate_kernel(&[]);
    let vs = Vstream::new(&k);
    // A link-element start: no content run of any origin, over a store
    // holding nothing at all.
    let defective = [ShotRun { origin: doc1(), run: run(&la(1), 1) }];
    assert!(matches!(
        rejected(vs.reinstate(p1, &pdoc(), vp(1, 1), &defective)),
        ReinstateError::PublishedTarget
    ));
    // Ahead of the destination's own shape checks as well: a link-subspace
    // position past every boundary, with nothing to place.
    assert!(matches!(
        rejected(vs.reinstate(p1, &pdoc(), vp(2, 99), &[])),
        ReinstateError::PublishedTarget
    ));
    assert_eq!(content_count(&k, &pdoc()), n(0));
    // The control: into the draft, the run is read — and refused for its
    // own defect.
    assert!(matches!(
        rejected(vs.reinstate(p1, &doc2(), vp(1, 1), &defective)),
        ReinstateError::BadRun
    ));
    assert_eq!(content_count(&k, &doc2()), n(0), "a refusal places nothing");
}

/// T1b — the per-run order, and WHICH RUN SPEAKS. A run is judged by its
/// SHAPE (`BadRun`: the client's stated origin must project to the trunk of
/// the document its start settles) before its origin's REGISTRATION
/// (`SourceNotRegistered`) before its BYTES (`DanglingSource`) — each pinned
/// against the next by a run defective in both ways — and the destination's
/// own checks stand ahead of every run. The runs are walked in order and the
/// FIRST defective one decides, whatever defect a later one carries.
#[test]
fn a_run_is_judged_by_its_shape_then_its_origin_then_its_bytes_and_the_first_defective_run_decides(
) {
    let p1 = Caller::Principal(PrincipalId(1));
    let k = gate_kernel(&[1, 2]);
    let vs = Vstream::new(&k);
    // Shape before bytes: an address the store does not hold, stated under
    // the wrong document — `BadRun`, never `DanglingSource`…
    let mis_stated = ShotRun { origin: doc2(), run: run(&ca(9), 1) };
    assert!(matches!(
        rejected(vs.reinstate(p1, &doc2(), vp(1, 1), &[mis_stated.clone()])),
        ReinstateError::BadRun
    ));
    // …and rightly stated, the same address is probed and refused for its
    // absence.
    assert!(matches!(
        rejected(vs.reinstate(p1, &doc2(), vp(1, 1), &[of_doc1(9, 1)])),
        ReinstateError::DanglingSource
    ));
    // Registration before bytes: an unregistered document's own address,
    // rightly stated, is refused for the document — the address is never
    // probed.
    let ghost = a(&[1, 0, 1, 0, 9]);
    let ghost_run = ShotRun { origin: ghost.clone(), run: run(&a(&[1, 0, 1, 0, 9, 0, 1, 1]), 1) };
    assert!(matches!(
        rejected(vs.reinstate(p1, &doc2(), vp(1, 1), &[ghost_run.clone()])),
        ReinstateError::SourceNotRegistered
    ));
    // Shape before registration: that same address stated under doc1 is
    // `BadRun` — its start does not settle doc1.
    assert!(matches!(
        rejected(vs.reinstate(
            p1,
            &doc2(),
            vp(1, 1),
            &[ShotRun { origin: doc1(), run: run(&a(&[1, 0, 1, 0, 9, 0, 1, 1]), 1) }]
        )),
        ReinstateError::BadRun
    ));
    // The destination's own checks stand ahead of every run.
    assert!(matches!(
        rejected(vs.reinstate(p1, &doc2(), vp(2, 1), &[mis_stated.clone()])),
        ReinstateError::NotContentSubspace
    ));
    assert!(matches!(
        rejected(vs.reinstate(p1, &doc2(), vp(1, 2), &[mis_stated.clone()])),
        ReinstateError::OutOfBounds
    ));
    assert_eq!(content_count(&k, &doc2()), n(0), "every refusal places nothing");
    // A stated origin that is a MEMBER of the minting document's chain
    // projects to it (PUB-2.15) and is admitted: doc1's first version
    // address names doc1's I-space.
    vs.reinstate(
        p1,
        &doc2(),
        vp(1, 1),
        &[ShotRun { origin: a(&[1, 0, 1, 0, 1, 1]), run: run(&ca(1), 1) }],
    )
    .expect("a member names its document's own I-space");
    assert_eq!(content_count(&k, &doc2()), n(1));
    // WHICH RUN SPEAKS: the list is walked and the first defective run
    // decides. A sound run, then a mis-stated one: the second's verdict.
    assert!(matches!(
        rejected(vs.reinstate(p1, &doc2(), vp(1, 2), &[of_doc1(2, 1), mis_stated.clone()])),
        ReinstateError::BadRun
    ));
    // A dangling run, then a mis-stated one: the FIRST's verdict — read the
    // other way (guards outermost, runs within) `BadRun` would win.
    assert!(matches!(
        rejected(vs.reinstate(p1, &doc2(), vp(1, 2), &[of_doc1(9, 1), mis_stated.clone()])),
        ReinstateError::DanglingSource
    ));
    // An unregistered origin, then a mis-stated run: the first's again.
    assert!(matches!(
        rejected(vs.reinstate(p1, &doc2(), vp(1, 2), &[ghost_run, mis_stated])),
        ReinstateError::SourceNotRegistered
    ));
    assert_eq!(content_count(&k, &doc2()), n(1), "the one admitted run alone was placed");
}

/// T1c — THE EVERY-ADDRESS PROBE. A client-named run was resolved from no
/// arrangement, so S3★'s induction does not cover its interior: every
/// address is asked, not the start alone. A run whose FIRST address holds a
/// value and whose THIRD does not is `DanglingSource` — the run COPY's
/// start-alone gate admits (`copy::tests`, Open decision #5's default) —
/// while the same start over the two present addresses commits, and a hole
/// AT the start is refused as any other.
#[test]
fn every_address_of_a_run_is_probed_not_its_start_alone() {
    let p1 = Caller::Principal(PrincipalId(1));
    let k = gate_kernel(&[1, 2]);
    let vs = Vstream::new(&k);
    assert!(matches!(
        rejected(vs.reinstate(p1, &doc2(), vp(1, 1), &[of_doc1(1, 3)])),
        ReinstateError::DanglingSource
    ));
    assert_eq!(content_count(&k, &doc2()), n(0), "a refusal places nothing");
    vs.reinstate(p1, &doc2(), vp(1, 1), &[of_doc1(1, 2)])
        .expect("a run whose every address holds a value is admitted");
    assert_eq!(content_count(&k, &doc2()), n(2));
    assert!(matches!(
        rejected(vs.reinstate(p1, &doc2(), vp(1, 3), &[of_doc1(3, 1)])),
        ReinstateError::DanglingSource
    ));
    assert_eq!(content_count(&k, &doc2()), n(2));
}

/// T1e — the staging form keeps REINSTATE's own bound and reads the working
/// world. In `GateWorld` — `Record = M5Rec`, no mint and no byte write —
/// placements staged under one transaction each judge the boundary the
/// placement before them left: a second past it is refused, and the refusal
/// discards the first with it, nothing committed; three in order commit as
/// one, the arrangement what their order made.
#[test]
fn a_staged_reinstate_reads_the_working_world_and_a_refusal_discards_the_whole_transaction() {
    let p1 = Caller::Principal(PrincipalId(1));
    let k = gate_kernel(&[1, 2, 3]);
    let key = [M3State::content_lock_key(&doc2())];
    let before = k.current_seq();
    // Ordinal 3 lies past the boundary the first placement leaves (one
    // position arranged, so 2 is the append boundary): refused, and the
    // first placement goes with it.
    let refused = rejected(k.transact(&key, |stg| {
        stage_reinstate_at(stg, p1, &doc2(), vp(1, 1), &[of_doc1(1, 1)])?;
        stage_reinstate_at(stg, p1, &doc2(), vp(1, 3), &[of_doc1(2, 1)])
    }));
    assert_eq!(refused, ReinstateError::OutOfBounds);
    assert_eq!(k.current_seq(), before, "the refusal commits nothing of the transaction");
    assert_eq!(content_count(&k, &doc2()), n(0));
    // In order: ca(1) at 1; ca(3) at the boundary the first left; ca(2)
    // between them — one run, the run-list's own merge.
    k.transact(&key, |stg| {
        stage_reinstate_at(stg, p1, &doc2(), vp(1, 1), &[of_doc1(1, 1)])?;
        stage_reinstate_at(stg, p1, &doc2(), vp(1, 2), &[of_doc1(3, 1)])?;
        stage_reinstate_at(stg, p1, &doc2(), vp(1, 2), &[of_doc1(2, 1)])
    })
    .expect("three placements commit as one");
    let s = k.snapshot();
    let m5 = s.world().m5();
    assert_eq!(m5.content_count(&doc2()), n(3));
    for (ord, addr) in [(1, ca(1)), (2, ca(2)), (3, ca(3))] {
        assert_eq!(m5.point(&doc2(), &vp(1, ord)), Some(addr), "ordinal {ord}");
    }
    assert_eq!(m5.content_run_count(&doc2()), 1);
}

/// T1d — the run budget and the empty list. The cap binds the ACCUMULATOR,
/// measured as each run lands, so an over-budget list is refused at the cap
/// with nothing placed; a list of exactly the budget is placed whole — and
/// since it names ONE address every time, it is also the duplicate edge
/// pinned: a run already arranged is placed again, as a self-copy's is. Two
/// I-adjacent runs of one origin coalesce into one run of the accumulator.
/// An empty list is `EmptyResult`, behind the destination's own checks.
#[test]
fn the_budget_is_measured_as_each_run_lands_duplicates_are_admitted_and_an_empty_list_is_refused(
) {
    let p1 = Caller::Principal(PrincipalId(1));
    let k = gate_kernel(&[1, 2, 3]);
    let vs = Vstream::new(&k);
    // `ca(1)` named MAX_PLACED_RUNS + 1 times: `shift(ca(1), 1) = ca(2) ≠
    // ca(1)`, so no two coalesce and every one pushes.
    let same: Vec<ShotRun> =
        std::iter::repeat_with(|| of_doc1(1, 1)).take(MAX_PLACED_RUNS + 1).collect();
    assert!(matches!(
        rejected(vs.reinstate(p1, &doc2(), vp(1, 1), &same)),
        ReinstateError::TooManyRuns
    ));
    assert_eq!(content_count(&k, &doc2()), n(0), "refused inside the closure: nothing staged");
    // Exactly the budget: placed whole, one address MAX_PLACED_RUNS times.
    vs.reinstate(p1, &doc2(), vp(1, 1), &same[..MAX_PLACED_RUNS])
        .expect("a placement of exactly the budget commits, duplicates and all");
    let s = k.snapshot();
    assert_eq!(s.world().m5().content_run_count(&doc2()), MAX_PLACED_RUNS);
    assert_eq!(s.world().m5().content_count(&doc2()), n(MAX_PLACED_RUNS as u32));
    assert_eq!(s.world().m5().point(&doc2(), &vp(1, 2)), Some(ca(1)), "the same address again");
    // I-adjacent runs of one origin are one run of the accumulator.
    vs.reinstate(p1, &doc1(), vp(1, 1), &[of_doc1(1, 1), of_doc1(2, 2)])
        .expect("adjacent runs commit");
    assert_eq!(k.snapshot().world().m5().content_run_count(&doc1()), 1);
    assert_eq!(k.snapshot().world().m5().content_count(&doc1()), n(3));
    // The empty list — and the destination's checks ahead of it.
    assert!(matches!(
        rejected(vs.reinstate(p1, &doc1(), vp(1, 4), &[])),
        ReinstateError::EmptyResult
    ));
    assert!(matches!(
        rejected(vs.reinstate(p1, &doc1(), vp(2, 1), &[])),
        ReinstateError::NotContentSubspace
    ));
    assert!(matches!(
        rejected(vs.reinstate(p1, &doc1(), vp(1, 0), &[])),
        ReinstateError::OutOfBounds
    ));
    assert_eq!(k.snapshot().world().m5().content_count(&doc1()), n(3));
}
