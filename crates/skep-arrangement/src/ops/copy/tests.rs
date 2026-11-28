//! COPY's in-crate claims, in a world whose arrangement and content store are
//! seeded INDEPENDENTLY — a state no engine reaches: its content-side
//! referential gate (S3★), its run budget over many specs and over one,
//! what its specs cost, and the published-target refusal ahead of every
//! source read.

use serde::{Deserialize, Serialize};
use skep_content::{stage_write, ContentStore, Val};
use skep_kernel::{Kernel, Seq};
use skep_namespace::PrincipalId;

use super::*;
use crate::run_list::RunList;
use crate::state::M5State;
use crate::testutil::{
    ca, doc1, doc2, mem_kernel_of, n, pdoc, rejected, run, seeded_m3, vp, vspan,
};

/// A world carrying a content store beside the arrangement — the one
/// slice `ops/tests.rs`'s `MiniWorld` deliberately lacks, kept a separate
/// type so the per-op-bound claim `MiniWorld` witnesses stays witnessed.
#[derive(Clone, Serialize, Deserialize)]
struct GateWorld {
    m3: M3State,
    content: ContentStore,
    m5: M5State,
}

impl WorldState for GateWorld {
    type Record = M5Rec;
    fn apply(&self, at: Seq, r: &M5Rec) -> GateWorld {
        GateWorld {
            m3: self.m3.clone(),
            content: self.content.clone(),
            m5: self.m5.apply_m5(at, r),
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

/// doc1 arranged as `run(ca(1), 3)`, with the content store holding the
/// bytes of exactly `present`. The two halves of S3★ are set apart from
/// each other, which is what lets one test say which of them COPY reads.
fn gate_kernel(present: &[u32]) -> Kernel<GateWorld> {
    gate_kernel_arranging(vec![run(&ca(1), 3)], present)
}

/// The same world arranging the runs a caller chooses — for the tests
/// whose subject is the source's RUN COUNT rather than its bytes.
fn gate_kernel_arranging(runs: Vec<Run>, present: &[u32]) -> Kernel<GateWorld> {
    let m5 = M5State::genesis().apply_m5(Seq(0), &M5Rec::ContentPlace {
        doc: doc1(),
        at: n(1),
        runs,
    });
    let mut content = ContentStore::default();
    for &k in present {
        let cw = stage_write(&content, ca(k), Val::new(&b"x"[..]))
            .expect("each seeded address is written once");
        content = content.apply_write(&cw);
    }
    mem_kernel_of(GateWorld {
        m3: seeded_m3(),
        content,
        m5,
    })
}

#[test]
fn copy_rejects_a_source_run_whose_start_is_absent_from_the_content_store() {
    // §5/S3★: COPY asserts each resolved run start ∈ dom(C) before
    // placing it, so a transclusion cannot manufacture a reference to
    // bytes that were never written — a reference R would then keep
    // permanently (P2) and every later RETRIEVEV would fail to resolve.
    let p1 = Caller::Principal(PrincipalId(1));
    // `count` positions from doc1's first content ordinal.
    let from_doc1 = |count: u32| {
        vec![VSpec {
            source: doc1(),
            span: vspan(1, 1, count),
        }]
    };

    // Nothing written: the resolved run's start, ca(1), is absent.
    let k = gate_kernel(&[]);
    assert!(matches!(
        rejected(Vstream::new(&k).copy(p1, &doc2(), vp(1, 1), &from_doc1(2), AsOf::Typed(k.current_seq()))),
        CopyError::DanglingSource
    ));

    // The identical COPY against a store that holds the bytes commits —
    // without this, the rejection above could be earned by anything.
    let k = gate_kernel(&[1, 2, 3]);
    Vstream::new(&k)
        .copy(p1, &doc2(), vp(1, 1), &from_doc1(2), AsOf::Typed(k.current_seq()))
        .expect("a resolved run whose start is present is admitted");
    assert_eq!(k.snapshot().world().m5().content_count(&doc2()), n(2));

    // Open decision #5's default, pinned: the gate reads run STARTS and
    // relies on the source's own S3★ for the interior. ca(3) is absent,
    // yet the width-3 run starting at the present ca(1) is admitted —
    // widening the gate to every address of a run turns this red, which
    // is how such a change announces itself.
    let k = gate_kernel(&[1, 2]);
    Vstream::new(&k)
        .copy(p1, &doc2(), vp(1, 1), &from_doc1(3), AsOf::Typed(k.current_seq()))
        .expect("the run start is present, so the run is admitted");
}

#[test]
fn copy_refuses_a_placement_past_the_run_budget_before_building_it() {
    // §5: the runs one COPY places are bounded, and the bound binds the
    // ACCUMULATOR rather than the request — a spec list is a multiplier,
    // so a small request can name an unbounded placement. Here 65_537
    // single-position specs against a one-address source: each resolves
    // to `run(ca(1), 1)`, which is never I-adjacent to the run before it
    // (`shift(ca(1), 1) = ca(2)`), so every one of them pushes.
    let p1 = Caller::Principal(PrincipalId(1));
    let k = gate_kernel(&[1, 2, 3]);
    let one = VSpec {
        source: doc1(),
        span: vspan(1, 1, 1),
    };
    let over_budget_specs: Vec<VSpec> = std::iter::repeat_with(|| one.clone())
        .take(MAX_PLACED_RUNS + 1)
        .collect();
    assert!(matches!(
        rejected(Vstream::new(&k).copy(p1, &doc2(), vp(1, 1), &over_budget_specs, AsOf::Typed(k.current_seq()))),
        CopyError::TooManyRuns
    ));
    // Nothing was placed: the refusal happens inside the closure, before
    // a record is staged, so the destination is untouched.
    assert_eq!(k.snapshot().world().m5().content_count(&doc2()), n(0));
    // And the cap refuses only what is past it — an ordinary copy still
    // commits, so the assertion above is not earned by refusing COPY.
    Vstream::new(&k)
        .copy(p1, &doc2(), vp(1, 1), &over_budget_specs[..3], AsOf::Typed(k.current_seq()))
        .expect("a placement inside the budget commits");
    assert_eq!(k.snapshot().world().m5().content_count(&doc2()), n(3));
}

#[test]
fn one_spec_over_a_fragmented_source_is_refused_at_the_cap_not_after_it() {
    // §5: a spec list is one multiplier of the source's fragmentation and
    // the SPAN is the other — a single spec over a heavily fragmented
    // source names as many runs as the source holds in range. The cap
    // therefore has to bind one spec, and it is measured as each run is
    // accumulated, so the refusal arrives AT the cap: the walk stops there,
    // whatever the source's run count, and never reaches a run past it.
    let p1 = Caller::Principal(PrincipalId(1));
    // Non-adjacent starts (`shift(ca(2k), 1) = ca(2k + 1) ≠ ca(2k + 2)`), so
    // nothing coalesces: the budget's runs, the one past it, and one more
    // whose start the store does not hold — a hole only a walk past the cap
    // reaches.
    let source_run_count = MAX_PLACED_RUNS + 2;
    let runs: Vec<Run> = (1..=source_run_count as u32)
        .map(|k| run(&ca(2 * k), 1))
        .collect();
    let present: Vec<u32> = (1..source_run_count as u32).map(|k| 2 * k).collect();
    let k = gate_kernel_arranging(runs, &present);
    assert_eq!(
        k.snapshot().world().m5().content_runs(&doc1()).len(),
        source_run_count,
        "the source arranges one run per placed address"
    );
    // ONE spec over the whole source: refused at run MAX_PLACED_RUNS + 1, so
    // never walked to the hole after it — a cap measured after the spec, or
    // after the spec list, would reach it and answer `DanglingSource`.
    let whole = [VSpec {
        source: doc1(),
        span: vspan(1, 1, source_run_count as u32),
    }];
    assert!(matches!(
        rejected(Vstream::new(&k).copy(p1, &doc2(), vp(1, 1), &whole, AsOf::Typed(k.current_seq()))),
        CopyError::TooManyRuns
    ));
    assert_eq!(k.snapshot().world().m5().content_count(&doc2()), n(0));
    // The hole is real: a spec over the last run alone is walked to it.
    assert!(matches!(
        rejected(Vstream::new(&k).copy(
            p1,
            &doc2(),
            vp(1, 1),
            &[VSpec {
                source: doc1(),
                span: vspan(1, source_run_count as u32, 1),
            }]
        , AsOf::Typed(k.current_seq()))),
        CopyError::DanglingSource
    ));
    // A span inside the budget over the same source still commits, so the
    // refusal above is about the count and not about the source.
    Vstream::new(&k)
        .copy(
            p1,
            &doc2(),
            vp(1, 1),
            &[VSpec {
                source: doc1(),
                span: vspan(1, 1, 4),
            }],
            AsOf::Typed(k.current_seq()),
        )
        .expect("a span inside the budget commits");
    assert_eq!(k.snapshot().world().m5().content_count(&doc2()), n(4));
    // The equal case: a span naming exactly the budget's runs is placed
    // whole — the cap refuses what is past it and nothing at it — and it
    // counts what THIS copy places, not what the destination holds:
    // doc2's four runs stay beside the budget's own, none of them
    // I-adjacent to the placement's first (`shift(ca(8), 1) ≠ ca(2)`).
    Vstream::new(&k)
        .copy(
            p1,
            &doc2(),
            vp(1, 5),
            &[VSpec {
                source: doc1(),
                span: vspan(1, 1, MAX_PLACED_RUNS as u32),
            }],
            AsOf::Typed(k.current_seq()),
        )
        .expect("a placement of exactly the budget commits");
    assert_eq!(
        k.snapshot().world().m5().content_run_count(&doc2()),
        4 + MAX_PLACED_RUNS
    );
}

#[test]
fn a_copys_specs_cost_a_descent_each_and_are_refused_for_what_they_place_alone() {
    // §5: a spec's resolution descends its source's run-list to the span —
    // a node a level, whatever the source holds left of it — and reads from
    // there the runs it yields, so what a copy's specs command under the
    // applier lock is what they place, and the placement budget is the one
    // budget of the copy. A copy of many specs over a fragmented source,
    // each keeping one run, is walked and placed whatever the product of
    // its spec count and the source's run count; a spec aimed past the
    // source's end reads no node and keeps nothing; and every spec is
    // resolved, which the source's one absent start makes visible, a spec
    // reaching it answering `DanglingSource`.
    let p1 = Caller::Principal(PrincipalId(1));
    let source_run_count: usize = 1024;
    // Non-adjacent starts, so nothing coalesces and the source really holds
    // this many runs.
    let runs: Vec<Run> = (1..=source_run_count as u32)
        .map(|k| run(&ca(2 * k), 1))
        .collect();
    // The store holds every start but the LAST: a spec reaching that run is
    // refused `DanglingSource`.
    let present: Vec<u32> = (1..source_run_count as u32).map(|k| 2 * k).collect();
    let k = gate_kernel_arranging(runs, &present);
    assert_eq!(
        k.snapshot().world().m5().content_run_count(&doc1()),
        source_run_count
    );
    let height = k.snapshot().world().m5().content_list(&doc1()).height() as u64;
    // As many specs as the source has runs, and one more: the product of
    // the two passes a million, and each spec costs one descent.
    let many = source_run_count + 1;
    assert!(many * source_run_count > 1 << 20, "premise: the specs' count times the source's runs");
    let first = VSpec {
        source: doc1(),
        span: vspan(1, 1, 1),
    };
    let past_the_end = VSpec {
        source: doc1(),
        span: vspan(1, source_run_count as u32 + 1, 1),
    };
    let last = VSpec {
        source: doc1(),
        span: vspan(1, source_run_count as u32, 1),
    };
    let specs = |spec: &VSpec, count: usize| -> Vec<VSpec> {
        std::iter::repeat_with(|| spec.clone())
            .take(count)
            .collect()
    };
    let before = k.current_seq();
    // A spec that reaches the absent start is resolved, and refused for
    // the hole — the last of many as the only one.
    let mut onto_the_hole = specs(&first, many);
    onto_the_hole.push(last.clone());
    for specs in [&onto_the_hole, &specs(&last, 1)] {
        assert!(matches!(
            rejected(Vstream::new(&k).copy(p1, &doc2(), vp(1, 1), specs, AsOf::Typed(k.current_seq()))),
            CopyError::DanglingSource
        ));
    }
    // A spec past the end keeps nothing, alone and after many — and reads
    // no node of the source.
    let entered = RunList::nodes_entered();
    assert!(matches!(
        rejected(Vstream::new(&k).copy(p1, &doc2(), vp(1, 1), &specs(&past_the_end, many), AsOf::Typed(k.current_seq()))),
        CopyError::EmptyResult
    ));
    assert_eq!(RunList::nodes_entered(), entered, "a span past the end is found past it by the root's sum");
    assert_eq!(k.current_seq(), before, "every refusal commits nothing");
    // The many specs, and one more past the end, are walked and placed:
    // one descent a spec that keeps a run, none for the one that keeps
    // nothing.
    let mut placing = specs(&first, many);
    placing.push(past_the_end.clone());
    let entered = RunList::nodes_entered();
    Vstream::new(&k)
        .copy(p1, &doc2(), vp(1, 1), &placing, AsOf::Typed(k.current_seq()))
        .expect("a copy of many specs over a fragmented source is walked and placed");
    let descents = RunList::nodes_entered() - entered;
    assert!(descents <= many as u64 * (height + 1), "{descents} nodes entered by {many} specs over a tree of height {height}");
    assert_eq!(
        k.snapshot().world().m5().content_count(&doc2()),
        n(many as u32)
    );
}

#[test]
fn copy_into_a_published_destination_refuses_before_reading_its_sources() {
    // PUB-2.11 on COPY's destination, in the content-store world: the
    // refusal fires ahead of every per-spec check, so a spec that would
    // otherwise be refused for its own reasons never speaks. Nothing is
    // stored here, so the spec below names a run whose start is absent —
    // `DanglingSource` wherever the spec is read, as the draft beside the
    // edition shows.
    let p1 = Caller::Principal(PrincipalId(1));
    let k = gate_kernel(&[]);
    let vs = Vstream::new(&k);
    let dangling = [VSpec {
        source: doc1(),
        span: vspan(1, 1, 2),
    }];
    assert!(matches!(
        rejected(vs.copy(p1, &pdoc(), vp(1, 1), &dangling, AsOf::Typed(k.current_seq()))),
        CopyError::PublishedTarget
    ));
    // Ahead of the destination's own shape checks as well: a
    // link-subspace position past every boundary.
    assert!(matches!(
        rejected(vs.copy(p1, &pdoc(), vp(2, 99), &[], AsOf::Typed(k.current_seq()))),
        CopyError::PublishedTarget
    ));
    assert_eq!(k.snapshot().world().m5().content_count(&pdoc()), n(0));
    // The control: into the draft, the same spec is read — and refused
    // for what it is.
    assert!(matches!(
        rejected(vs.copy(p1, &doc2(), vp(1, 1), &dangling, AsOf::Typed(k.current_seq()))),
        CopyError::DanglingSource
    ));
}
