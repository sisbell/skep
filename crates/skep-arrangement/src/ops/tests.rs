//! The design's per-op-bound claim, verified literally: a MINIMAL test
//! world — `HasM5 + HasM3`, `Record = M5Rec` (the identity `From`) —
//! drives `delete` and `rearrange`; no content store, no `From<M3Rec>`.
//!
//! And COPY's content-side referential gate (S3★), which needs a world
//! whose arrangement and content store can be seeded INDEPENDENTLY — a
//! state no engine reaches, every arranged address there having been
//! written by INSERT in the same composite. And J0's allocation step,
//! driven directly in a world of M3 and M4 alone, which is all it reads.
//! And the publish shot's placement claims — its run budget at both sites,
//! its re-insert budget, and its empty member — in a world whose three
//! slices are seeded apart, so a head can arrange more runs than a test
//! could build by transactions, and a draft can name values that were
//! never stored.

use serde::{Deserialize, Serialize};
use skep_content::ContentStore;
use skep_kernel::{CheckpointPolicy, Durability, Kernel, KernelConfig, SaltSource, TxnError};
use skep_namespace::{M3State, PrincipalId};

use super::*;
use crate::error::{CopyError, DeleteError, InsertError, PublishError, RearrangeError};
use crate::ownership::Caller;
use crate::shot::{Base, Shot, ShotRun};
use crate::state::{M5Rec, M5State, ShotTerms};
use crate::testutil::{a, ca, doc1, doc2, n, pca, pdoc, run, seeded_m3, vp, vspan};
use crate::vspace::VSpec;
use crate::HasM5;

/// Unwrap an op's typed rejection (`TxnError::Rejected(E)` — surfaced
/// verbatim, per M2's transact contract).
fn rejected<T, E: fmt::Debug>(r: Result<T, TxnError<E>>) -> E {
    match r {
        Err(TxnError::Rejected(e)) => e,
        Err(other) => panic!("expected TxnError::Rejected, got {other:?}"),
        Ok(_) => panic!("expected TxnError::Rejected, got Ok"),
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct MiniWorld {
    m3: M3State,
    m5: M5State,
}

impl WorldState for MiniWorld {
    type Record = M5Rec;
    fn apply(&self, r: &M5Rec) -> MiniWorld {
        MiniWorld {
            m3: self.m3.clone(),
            m5: self.m5.apply_m5(r),
        }
    }
}
impl HasM3 for MiniWorld {
    fn m3(&self) -> &M3State {
        &self.m3
    }
}
impl HasM5 for MiniWorld {
    fn m5(&self) -> &M5State {
        &self.m5
    }
}

fn mini_kernel() -> Kernel<MiniWorld> {
    let m5 = M5State::genesis().apply_m5(&M5Rec::ContentPlace {
        doc: doc1(),
        at: n(1),
        runs: vec![run(&ca(1), 5)],
    });
    let cfg = KernelConfig {
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(0),
    };
    Kernel::open(cfg, MiniWorld { m3: seeded_m3(), m5 }).expect("in-memory open")
}

#[test]
fn the_handle_prints_without_its_world_being_printable() {
    // `MiniWorld` is not `Debug`, and the handle is — which is the whole
    // reason the impl is written out rather than derived.
    let k = mini_kernel();
    assert_eq!(format!("{:?}", Vstream::new(&k)), "Vstream");
}

/// A world carrying a content store beside the arrangement — the one
/// slice `MiniWorld` deliberately lacks, kept a separate type so the
/// per-op-bound claim `MiniWorld` witnesses stays witnessed.
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
    let cfg = KernelConfig {
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(0),
    };
    Kernel::open(
        cfg,
        GateWorld {
            m3: seeded_m3(),
            content,
            m5,
        },
    )
    .expect("in-memory open")
}

/// The two slices J0's allocation step touches — M3's frontier and M4's
/// store — with a record for each, and nothing else: no arrangement, no
/// `M5Rec`. So the step's bounds are witnessed as `MiniWorld` witnesses
/// the per-op ones: it needs M3 and M4 and stages their records alone.
#[derive(Clone, Serialize, Deserialize)]
struct AllocWorld {
    m3: M3State,
    content: ContentStore,
}

#[derive(Clone, Serialize, Deserialize)]
enum AllocRec {
    M3(M3Rec),
    Content(ContentWrite),
}

impl From<M3Rec> for AllocRec {
    fn from(r: M3Rec) -> AllocRec {
        AllocRec::M3(r)
    }
}
impl From<ContentWrite> for AllocRec {
    fn from(r: ContentWrite) -> AllocRec {
        AllocRec::Content(r)
    }
}

impl WorldState for AllocWorld {
    type Record = AllocRec;
    fn apply(&self, r: &AllocRec) -> AllocWorld {
        match r {
            AllocRec::M3(x) => AllocWorld {
                m3: self.m3.apply_m3(x),
                content: self.content.clone(),
            },
            AllocRec::Content(x) => AllocWorld {
                m3: self.m3.clone(),
                content: self.content.apply_write(x),
            },
        }
    }
}
impl HasM3 for AllocWorld {
    fn m3(&self) -> &M3State {
        &self.m3
    }
}
impl HasContent for AllocWorld {
    fn content(&self) -> &ContentStore {
        &self.content
    }
}

#[test]
fn the_allocation_step_mints_writes_and_accumulates_through_the_merge_condition() {
    // J0's one enforcement site, which INSERT and the shot's re-insert
    // both call: each call mints under the home it is given, writes the
    // value there, and accumulates the address through the element that
    // owns the merge condition — so consecutive mints under one home
    // coalesce into one run, and a mint under another home, whose address
    // is not I-adjacent, opens a run of its own rather than widening the
    // first over addresses nobody allocated.
    let cfg = KernelConfig {
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(0),
    };
    let k = Kernel::open(
        cfg,
        AllocWorld {
            m3: seeded_m3(),
            content: ContentStore::default(),
        },
    )
    .expect("in-memory open");
    let keys = [M3State::content_lock_key(&doc1()), M3State::content_lock_key(&doc2())];
    let (runs, _) = k
        .transact(&keys, |stg| {
            let mut runs: Vec<Run> = Vec::new();
            for (home, byte) in [(doc1(), b"a"), (doc1(), b"b"), (doc2(), b"c")] {
                allocate_for_placement::<_, InsertError>(stg, &home, Val::new(&byte[..]), &mut runs)?;
            }
            Ok::<_, InsertError>(runs)
        })
        .expect("the allocations commit");
    let doc2_first = a(&[1, 0, 1, 0, 2, 0, 1, 1]);
    assert_eq!(runs, vec![run(&ca(1), 2), run(&doc2_first, 1)]);
    // Each address holds the value written at it, and each mint advanced
    // its home's frontier: the next mint under doc1 is ca(3).
    let s = k.snapshot();
    let content = s.world().content();
    for (addr, byte) in [(ca(1), b"a"), (ca(2), b"b"), (doc2_first, b"c")] {
        assert_eq!(content.value_at(addr.tumbler()).map(Val::as_bytes), Some(&byte[..]));
    }
    let (next, _) = s.world().m3().mint_content(&doc1()).expect("doc1 is registered");
    assert_eq!(next, ca(3));
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
fn the_placement_budget_stays_inside_the_transaction_budget() {
    // MAX_PLACED_RUNS is a number with an argument behind it, and the
    // argument is about M2's encoding — so it is measured against that
    // encoding rather than remembered. A full placement must still be a
    // transaction M2 could accept: a cap above the journal's own ceiling
    // would be no cap at all, since the work would be done and then
    // refused downstream, which is the cost the cap exists to refuse.
    const SAMPLE: usize = 64;
    let runs: Vec<Run> = (1..=SAMPLE as u32).map(|k| run(&ca(2 * k), 1)).collect();
    let rec = M5Rec::ContentPlace {
        doc: doc1(),
        at: n(1),
        runs,
    };
    let per_run = bincode::serialize(&rec).expect("the record encodes").len() / SAMPLE;
    let full = MAX_PLACED_RUNS as u64 * per_run as u64;
    assert!(
        full < skep_kernel::MAX_TXN_BYTES,
        "a full placement encodes to ~{full} bytes, past M2's {}",
        skep_kernel::MAX_TXN_BYTES
    );
}

#[test]
fn the_reinsert_budget_is_a_transaction_m2_accepts() {
    // MAX_REINSERTED_VALUES has an argument behind it as MAX_PLACED_RUNS
    // does, and the argument is M2's accounting — two records a value,
    // each charged its encoded bytes and its framing — so it is measured
    // against that accounting and not against a restatement of it. A
    // re-insert of exactly the budget, one byte a value at the shallowest
    // content address, staged through J0's own step — the one the shot's
    // re-insert calls — in one transaction, commits: the cap refuses no
    // shot M2 could have accepted at that depth, which is what keeps it a
    // bound on the staging rather than a second, tighter journal budget.
    let cfg = KernelConfig {
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(0),
    };
    let k = Kernel::open(
        cfg,
        AllocWorld {
            m3: seeded_m3(),
            content: ContentStore::default(),
        },
    )
    .expect("in-memory open");
    let (runs, _) = k
        .transact(&[M3State::content_lock_key(&doc1())], |stg| {
            let mut runs: Vec<Run> = Vec::new();
            for _ in 0..MAX_REINSERTED_VALUES {
                allocate_for_placement::<_, InsertError>(stg, &doc1(), Val::new(&b"x"[..]), &mut runs)?;
            }
            Ok::<_, InsertError>(runs)
        })
        .expect("a re-insert of exactly the budget is a transaction M2 accepts");
    // One run: the fresh addresses are I-adjacent, which is why the run
    // budget alone could never have seen this many values.
    assert_eq!(runs, vec![run(&ca(1), MAX_REINSERTED_VALUES as u32)]);
}

/// A world carrying all three slices the SHOT touches — M3 (its member's
/// mint), M4 (the existence check and the re-insert's writes) and M5 (the
/// base's tail and the member's placement) — seeded APART, as `GateWorld`'s
/// two are. The shot is the one op whose records span all three.
#[derive(Clone, Serialize, Deserialize)]
struct ShotWorld {
    m3: M3State,
    content: ContentStore,
    m5: M5State,
}

#[derive(Clone, Serialize, Deserialize)]
enum ShotRec {
    M3(M3Rec),
    Content(ContentWrite),
    M5(M5Rec),
}

impl From<M3Rec> for ShotRec {
    fn from(r: M3Rec) -> ShotRec {
        ShotRec::M3(r)
    }
}
impl From<ContentWrite> for ShotRec {
    fn from(r: ContentWrite) -> ShotRec {
        ShotRec::Content(r)
    }
}
impl From<M5Rec> for ShotRec {
    fn from(r: M5Rec) -> ShotRec {
        ShotRec::M5(r)
    }
}

impl WorldState for ShotWorld {
    type Record = ShotRec;
    fn apply(&self, r: &ShotRec) -> ShotWorld {
        match r {
            ShotRec::M3(x) => ShotWorld {
                m3: self.m3.apply_m3(x),
                content: self.content.clone(),
                m5: self.m5.clone(),
            },
            ShotRec::Content(x) => ShotWorld {
                m3: self.m3.clone(),
                content: self.content.apply_write(x),
                m5: self.m5.clone(),
            },
            ShotRec::M5(x) => ShotWorld {
                m3: self.m3.clone(),
                content: self.content.clone(),
                m5: self.m5.apply_m5(x),
            },
        }
    }
}
impl HasM3 for ShotWorld {
    fn m3(&self) -> &M3State {
        &self.m3
    }
}
impl HasContent for ShotWorld {
    fn content(&self) -> &ContentStore {
        &self.content
    }
}
impl HasM5 for ShotWorld {
    fn m5(&self) -> &M5State {
        &self.m5
    }
}

/// pdoc's first member, the head of its chain in `shot_kernel`'s world.
fn pdoc_member() -> Address {
    a(&[1, 0, 1, 0, 3, 1])
}

/// pdoc with `pdoc_member()` heading its chain and arranging
/// `member_runs` — nothing placed at all when they are empty, as no op
/// stages an empty placement — and pdoc's content elements stored at the
/// ordinals in `present`.
fn shot_kernel(member_runs: Vec<Run>, present: &[u32]) -> Kernel<ShotWorld> {
    let m3 = seeded_m3().apply_m3(&M3Rec::Allocate {
        addr: pdoc_member(),
        published: true,
    });
    let m5 = if member_runs.is_empty() {
        M5State::genesis()
    } else {
        M5State::genesis().apply_m5(&M5Rec::ContentPlace {
            doc: pdoc_member(),
            at: n(1),
            runs: member_runs,
        })
    };
    let mut content = ContentStore::default();
    for &k in present {
        let cw = stage_write(&content, &pca(k), Val::new(&b"x"[..]))
            .expect("each seeded address is written once");
        content = content.apply_write(&cw);
    }
    let cfg = KernelConfig {
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(0),
    };
    Kernel::open(cfg, ShotWorld { m3, content, m5 }).expect("in-memory open")
}

/// A shot staged off `pdoc_member()`, its copy having taken `extent` of
/// the head, supplying `runs` and naming no draft.
fn shot_off_the_head(extent: u32, runs: Vec<ShotRun>) -> Shot {
    Shot {
        base: Some(Base {
            member: pdoc_member(),
            extent: n(extent),
        }),
        draft: None,
        runs,
    }
}

#[test]
fn the_shot_refuses_a_client_arrangement_past_the_run_budget_and_places_one_at_it() {
    // MAX_PLACED_RUNS binds what one SHOT places, and a shot cannot be
    // split to meet it. Width-1 runs of the edition's own I-space at even
    // ordinals: none is I-adjacent to the one before it
    // (`shift(pca(2k), 1) = pca(2k + 1)`), so each pushes. Own I-space
    // takes no consult — and this consult admits everything — so the
    // source gate plays no part.
    let p1 = Caller::Principal(PrincipalId(1));
    let ordinals: Vec<u32> = (1..=MAX_PLACED_RUNS as u32 + 1).map(|o| 2 * o).collect();
    let k = shot_kernel(vec![], &ordinals);
    let runs = |count: usize| -> Vec<ShotRun> {
        ordinals[..count]
            .iter()
            .map(|&o| ShotRun {
                origin: pdoc(),
                run: run(&pca(o), 1),
            })
            .collect()
    };
    let anyone = |_: &ShotWorld, _: &Address| true;
    let before = k.current_seq();
    assert!(matches!(
        rejected(Vstream::new(&k).publish(
            p1,
            &pdoc(),
            shot_off_the_head(0, runs(MAX_PLACED_RUNS + 1)),
            &anyone
        )),
        PublishError::TooManyRuns
    ));
    assert_eq!(k.current_seq(), before, "the refusal commits nothing");
    // The equal case: a member of exactly the budget is placed, whole.
    let (member, _) = Vstream::new(&k)
        .publish(p1, &pdoc(), shot_off_the_head(0, runs(MAX_PLACED_RUNS)), &anyone)
        .expect("a placement at the budget commits");
    assert_eq!(
        k.snapshot().world().m5().content_runs(&member).len(),
        MAX_PLACED_RUNS
    );
}

#[test]
fn the_shot_refuses_a_carried_tail_past_the_run_budget() {
    // The base's post-render deposits count against the same budget,
    // measured as each is carried: a head arranging MAX_PLACED_RUNS + 1
    // non-adjacent runs cannot be shot from extent 0, though the client
    // supplies nothing. The head's bytes are stored as well, so the
    // budget is the only thing this world could refuse the shot for.
    let p1 = Caller::Principal(PrincipalId(1));
    let ordinals: Vec<u32> = (1..=MAX_PLACED_RUNS as u32 + 1).map(|o| 2 * o).collect();
    let head_runs: Vec<Run> = ordinals.iter().map(|&o| run(&pca(o), 1)).collect();
    let k = shot_kernel(head_runs.clone(), &ordinals);
    let anyone = |_: &ShotWorld, _: &Address| true;
    let before = k.current_seq();
    assert!(matches!(
        rejected(Vstream::new(&k).publish(p1, &pdoc(), shot_off_the_head(0, vec![]), &anyone)),
        PublishError::TooManyRuns
    ));
    assert_eq!(k.current_seq(), before, "the refusal commits nothing");
    // The equal case: from extent 1 the tail is exactly the budget, and it
    // is carried whole, in order.
    let (member, _) = Vstream::new(&k)
        .publish(p1, &pdoc(), shot_off_the_head(1, vec![]), &anyone)
        .expect("a tail of exactly the budget is carried");
    assert_eq!(
        k.snapshot().world().m5().content_runs(&member).cloned().collect::<Vec<_>>(),
        head_runs[1..].to_vec()
    );
}

#[test]
fn the_shot_refuses_a_reinsert_past_the_value_budget_before_probing_an_address() {
    // MAX_REINSERTED_VALUES binds how many values one SHOT re-inserts
    // from its draft, and the count is request arithmetic — the
    // draft-native runs' widths, summed — answered before any address is
    // probed. Nothing of doc1 is stored in this world, so every probe of
    // the draft answers `DanglingSource`: a shot refused `TooManyValues`
    // here was refused without one. What is bounded is the SUM, so two
    // runs over one I-extent, each inside the budget, are refused
    // together; a by-reference run is placed as one run and never
    // re-inserted, so its width is not counted; and the source gate still
    // speaks first.
    let p1 = Caller::Principal(PrincipalId(1));
    let k = shot_kernel(vec![], &[]);
    let vs = Vstream::new(&k);
    let anyone = |_: &ShotWorld, _: &Address| true;
    let no_one = |_: &ShotWorld, _: &Address| false;
    let shot_from = |runs: Vec<ShotRun>| Shot {
        base: Some(Base {
            member: pdoc_member(),
            extent: n(0),
        }),
        draft: Some(doc1()),
        runs,
    };
    let from_the_draft = |widths: &[usize]| {
        shot_from(
            widths
                .iter()
                .map(|&w| ShotRun {
                    origin: doc1(),
                    run: run(&ca(1), w as u32),
                })
                .collect(),
        )
    };
    let before = k.current_seq();
    assert!(matches!(
        rejected(vs.publish(p1, &pdoc(), from_the_draft(&[MAX_REINSERTED_VALUES + 1]), &anyone)),
        PublishError::TooManyValues
    ));
    let past_half = MAX_REINSERTED_VALUES / 2 + 1;
    assert!(matches!(
        rejected(vs.publish(p1, &pdoc(), from_the_draft(&[past_half, past_half]), &anyone)),
        PublishError::TooManyValues
    ));
    // Exactly the budget passes the count, and its first probe finds the
    // draft's first address holding nothing.
    assert!(matches!(
        rejected(vs.publish(p1, &pdoc(), from_the_draft(&[MAX_REINSERTED_VALUES]), &anyone)),
        PublishError::DanglingSource
    ));
    // A run of the edition's own I-space past the budget, beside the same
    // draft: not a re-insert, so it is refused for what it names.
    let own = ShotRun {
        origin: pdoc(),
        run: run(&pca(1), MAX_REINSERTED_VALUES as u32 + 1),
    };
    assert!(matches!(
        rejected(vs.publish(p1, &pdoc(), shot_from(vec![own]), &anyone)),
        PublishError::DanglingSource
    ));
    // A draft its shooter may not read is withheld, however much of it
    // the shot names.
    assert!(matches!(
        rejected(vs.publish(p1, &pdoc(), from_the_draft(&[MAX_REINSERTED_VALUES + 1]), &no_one)),
        PublishError::Withheld(d) if d == doc1()
    ));
    assert_eq!(k.current_seq(), before, "every refusal commits nothing");
}

#[test]
fn an_empty_shot_mints_its_member_places_nothing_and_journals_its_terms() {
    // An empty placement still pushes the shot's record (D25's (c′)): the
    // member's mint is M3's record, and M5's record carries the shot's
    // terms whatever the placement holds. With nothing to place, the
    // arrangement and R come out exactly as they went in — no arrangement
    // entry and nothing in R for the member, which reads as the lazy empty
    // arrangement, as an empty fork's does — while the member's terms are
    // noted (nothing placed, the base's extent as the shot named it) and
    // its birth extent at zero. (Until the record carried the terms an empty
    // placement pushed no record and the slice was untouched.)
    let p1 = Caller::Principal(PrincipalId(1));
    let k = shot_kernel(vec![], &[]);
    let before = k.snapshot().world().m5().clone();
    let anyone = |_: &ShotWorld, _: &Address| true;
    let shot = shot_off_the_head(0, vec![]);
    let extent = shot.base.as_ref().map(|base| base.extent.clone());
    let (member, _) = Vstream::new(&k)
        .publish(p1, &pdoc(), shot, &anyone)
        .expect("an empty shot commits");
    let s = k.snapshot();
    let m5 = s.world().m5();
    assert!(s.world().m3().is_registered_document(&member), "the member is minted");
    assert_eq!(m5.content_runs(&member).len(), 0, "nothing is placed for it");
    assert_eq!(m5.content_count(&member), n(0));
    assert_eq!(m5.provenance, before.provenance, "nothing in R for it");
    assert_eq!(m5.arrangements, before.arrangements, "no arrangement entry: the lazy empty one");
    assert_eq!(
        m5.shot_terms(&member),
        Some(&ShotTerms { placed: n(0), base_extent: extent }),
        "the terms are journaled all the same"
    );
    assert_eq!(m5.birth_extent(&member), n(0), "a birth version born empty, noted at zero");
}

#[test]
fn delete_and_rearrange_drive_a_minimal_world() {
    let k = mini_kernel();
    let vs = Vstream::new(&k);
    // The seeded owner of doc1 — the ω gate is exercised, not skipped.
    let p1 = Caller::Principal(PrincipalId(1));
    vs.delete(p1, &doc1(), vp(1, 2), n(1)).expect("delete commits");
    let seq = vs
        .rearrange(p1, &doc1(), &[vp(1, 1), vp(1, 2), vp(1, 3)])
        .expect("rearrange commits");
    let s = k.snapshot();
    assert_eq!(s.seq(), seq);
    let m5 = s.world().m5();
    // After deleting V2 (ca(2)): [ca1, ca3, ca4, ca5]; pivot at [1,2,3]
    // exchanges V1 and V2: [ca3, ca1, ca4, ca5].
    assert_eq!(m5.content_count(&doc1()), n(4));
    assert_eq!(m5.point(&doc1(), &vp(1, 1)), Some(ca(3)));
    assert_eq!(m5.point(&doc1(), &vp(1, 2)), Some(ca(1)));
    assert_eq!(m5.point(&doc1(), &vp(1, 3)), Some(ca(4)));
}

#[test]
fn the_in_place_refusal_needs_only_the_registry_and_the_arrangement() {
    // PUB-2.11 in the MINIMAL world: the published-target refusal reads
    // M3's bit and nothing else, so `delete`/`rearrange` refuse it under
    // `HasM5 + HasM3` alone — after ω, before every shape check (the
    // edition is empty, and the shape checks would have said so), and for
    // `Caller::System` as for the owner (PUB-6.28).
    let k = mini_kernel();
    let vs = Vstream::new(&k);
    let p1 = Caller::Principal(PrincipalId(1));
    let before = k.current_seq();
    assert!(matches!(
        rejected(vs.delete(p1, &pdoc(), vp(1, 1), n(1))),
        DeleteError::PublishedTarget
    ));
    assert!(matches!(
        rejected(vs.rearrange(p1, &pdoc(), &[vp(1, 1), vp(1, 2), vp(1, 3)])),
        RearrangeError::PublishedTarget
    ));
    assert!(matches!(
        rejected(vs.delete(Caller::System, &pdoc(), vp(1, 1), n(1))),
        DeleteError::PublishedTarget
    ));
    // ω stands ahead of it: a stranger learns nothing about publication.
    assert!(matches!(
        rejected(vs.delete(Caller::Principal(PrincipalId(2)), &pdoc(), vp(1, 1), n(1))),
        DeleteError::NotOwner(d) if d == pdoc()
    ));
    assert_eq!(k.current_seq(), before, "a refusal commits nothing");
    // And the draft beside it is edited as before.
    vs.delete(p1, &doc1(), vp(1, 1), n(1)).expect("a draft's delete commits");
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
