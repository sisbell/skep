//! COPY's in-crate claims, in a world whose arrangement and content store are
//! seeded INDEPENDENTLY — a state no engine reaches: its content-side
//! referential gate (S3★), its run budget over many specs and over one, and
//! the published-target refusal ahead of every source read.

use serde::{Deserialize, Serialize};
use skep_content::{stage_write, ContentStore, Val};
use skep_kernel::Kernel;
use skep_namespace::PrincipalId;

use super::*;
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
    fn apply(&self, r: &M5Rec) -> GateWorld {
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

/// doc1 arranged as `run(ca(1), 3)`, with the content store holding the
/// bytes of exactly `present`. The two halves of S3★ are set apart from
/// each other, which is what lets one test say which of them COPY reads.
fn gate_kernel(present: &[u32]) -> Kernel<GateWorld> {
    gate_kernel_arranging(vec![run(&ca(1), 3)], present)
}

/// The same world arranging the runs a caller chooses — for the tests
/// whose subject is the source's RUN COUNT rather than its bytes.
fn gate_kernel_arranging(runs: Vec<Run>, present: &[u32]) -> Kernel<GateWorld> {
    let m5 = M5State::genesis().apply_m5(&M5Rec::ContentPlace {
        doc: doc1(),
        at: n(1),
        runs,
    });
    let mut content = ContentStore::default();
    for &k in present {
        let cw = stage_write(&content, &ca(k), Val::new(&b"x"[..]))
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
        rejected(Vstream::new(&k).copy(p1, &doc2(), vp(1, 1), &from_doc1(2))),
        CopyError::DanglingSource
    ));

    // The identical COPY against a store that holds the bytes commits —
    // without this, the rejection above could be earned by anything.
    let k = gate_kernel(&[1, 2, 3]);
    Vstream::new(&k)
        .copy(p1, &doc2(), vp(1, 1), &from_doc1(2))
        .expect("a resolved run whose start is present is admitted");
    assert_eq!(k.snapshot().world().m5().content_count(&doc2()), n(2));

    // Open decision #5's default, pinned: the gate reads run STARTS and
    // relies on the source's own S3★ for the interior. ca(3) is absent,
    // yet the width-3 run starting at the present ca(1) is admitted —
    // widening the gate to every address of a run turns this red, which
    // is how such a change announces itself.
    let k = gate_kernel(&[1, 2]);
    Vstream::new(&k)
        .copy(p1, &doc2(), vp(1, 1), &from_doc1(3))
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
        rejected(Vstream::new(&k).copy(p1, &doc2(), vp(1, 1), &over_budget_specs)),
        CopyError::TooManyRuns
    ));
    // Nothing was placed: the refusal happens inside the closure, before
    // a record is staged, so the destination is untouched.
    assert_eq!(k.snapshot().world().m5().content_count(&doc2()), n(0));
    // And the cap refuses only what is past it — an ordinary copy still
    // commits, so the assertion above is not earned by refusing COPY.
    Vstream::new(&k)
        .copy(p1, &doc2(), vp(1, 1), &over_budget_specs[..3])
        .expect("a placement inside the budget commits");
    assert_eq!(k.snapshot().world().m5().content_count(&doc2()), n(3));
}

#[test]
fn one_spec_over_a_fragmented_source_is_refused_at_the_cap_not_after_it() {
    // §5: a spec list is one multiplier of the source's fragmentation and
    // the SPAN is the other — a single spec over a heavily fragmented
    // source names as many runs as the source holds in range. The cap
    // therefore has to bind one spec, and because the resolution is pulled
    // lazily the refusal arrives AT the cap: the accumulator never holds
    // more than the budget, whatever the source's run count.
    let p1 = Caller::Principal(PrincipalId(1));
    // Non-adjacent starts (`shift(ca(2k), 1) = ca(2k + 1) ≠ ca(2k + 2)`),
    // so nothing coalesces and the source really holds this many runs.
    let over_budget_run_count = MAX_PLACED_RUNS + 1;
    let present: Vec<u32> = (1..=over_budget_run_count as u32).map(|k| 2 * k).collect();
    let runs: Vec<Run> = present.iter().map(|&k| run(&ca(k), 1)).collect();
    let k = gate_kernel_arranging(runs, &present);
    assert_eq!(
        k.snapshot().world().m5().content_runs(&doc1()).len(),
        over_budget_run_count,
        "the source arranges one run per placed address"
    );
    // ONE spec, whose span covers the whole source.
    let whole = [VSpec {
        source: doc1(),
        span: vspan(1, 1, over_budget_run_count as u32),
    }];
    assert!(matches!(
        rejected(Vstream::new(&k).copy(p1, &doc2(), vp(1, 1), &whole)),
        CopyError::TooManyRuns
    ));
    assert_eq!(k.snapshot().world().m5().content_count(&doc2()), n(0));
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
        )
        .expect("a placement of exactly the budget commits");
    assert_eq!(
        k.snapshot().world().m5().content_run_count(&doc2()),
        4 + MAX_PLACED_RUNS
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
        rejected(vs.copy(p1, &pdoc(), vp(1, 1), &dangling)),
        CopyError::PublishedTarget
    ));
    // Ahead of the destination's own shape checks as well: a
    // link-subspace position past every boundary.
    assert!(matches!(
        rejected(vs.copy(p1, &pdoc(), vp(2, 99), &[])),
        CopyError::PublishedTarget
    ));
    assert_eq!(k.snapshot().world().m5().content_count(&pdoc()), n(0));
    // The control: into the draft, the same spec is read — and refused
    // for what it is.
    assert!(matches!(
        rejected(vs.copy(p1, &doc2(), vp(1, 1), &dangling)),
        CopyError::DanglingSource
    ));
}
