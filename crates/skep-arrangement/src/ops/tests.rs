//! The handle and what its operations share, tested. The per-op-bound claim,
//! verified literally: a MINIMAL world — `HasM5 + HasM3`, `Record = M5Rec`
//! (the identity `From`) — drives `delete` and `rearrange`, their in-place
//! refusal included, with no content store and no `From<M3Rec>`; and the
//! handle prints though that world does not. J0's allocation step, driven in
//! a world of M3 and M4 alone, which is all it reads. And the two budgets,
//! each measured against M2's own encoding and ceiling rather than restated.

use serde::{Deserialize, Serialize};
use skep_content::ContentStore;
use skep_kernel::{CheckpointPolicy, Durability, Kernel, KernelConfig, SaltSource};
use skep_namespace::{M3State, PrincipalId};

use super::*;
use crate::error::{DeleteError, InsertError, RearrangeError};
use crate::ownership::Caller;
use crate::state::{M5Rec, M5State};
use crate::testutil::{a, ca, doc1, doc2, n, pdoc, rejected, run, seeded_m3, vp};
use crate::HasM5;

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
