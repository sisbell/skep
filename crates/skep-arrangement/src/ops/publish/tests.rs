//! The publish shot's in-crate claims — its run budget at both sites, its
//! re-insert budget, its empty member, and a refusal after its re-insert is
//! staged — in a world whose three slices are seeded apart, so a head can
//! arrange more runs than a test could build by transactions, and a draft can
//! name values that were never stored.

use serde::{Deserialize, Serialize};
use skep_content::{stage_write, ContentStore, Val};
use skep_kernel::Kernel;
use skep_namespace::PrincipalId;

use super::*;
use crate::deposit::Deposit;
use crate::shot::{Base, ShotRun};
use crate::state::M5State;
use crate::testutil::{a, ca, doc1, mem_kernel_of, n, pca, pdoc, rejected, run, seeded_m3, vp};

/// A world carrying all three slices the SHOT touches — M3 (its member's
/// mint), M4 (the existence check and the re-insert's writes) and M5 (the
/// base's tail and the member's placement) — seeded APART, as COPY's
/// `GateWorld` seeds its two (`ops/copy/tests.rs`). The shot is the one op
/// whose records span all three.
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
    let m3 = seeded_m3().apply_m3(&M3Rec::allocate(pdoc_member(), true));
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
        let cw = stage_write(&content, pca(k), Val::new(&b"x"[..]))
            .expect("each seeded address is written once");
        content = content.apply_write(&cw);
    }
    mem_kernel_of(ShotWorld { m3, content, m5 })
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
            &shot_off_the_head(0, runs(MAX_PLACED_RUNS + 1)),
            &anyone
        )),
        PublishError::TooManyRuns
    ));
    assert_eq!(k.current_seq(), before, "the refusal commits nothing");
    // The equal case: a member of exactly the budget is placed, whole.
    let (member, _) = Vstream::new(&k)
        .publish(p1, &pdoc(), &shot_off_the_head(0, runs(MAX_PLACED_RUNS)), &anyone)
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
        rejected(Vstream::new(&k).publish(p1, &pdoc(), &shot_off_the_head(0, vec![]), &anyone)),
        PublishError::TooManyRuns
    ));
    assert_eq!(k.current_seq(), before, "the refusal commits nothing");
    // The equal case: from extent 1 the tail is exactly the budget, and it
    // is carried whole, in order.
    let (member, _) = Vstream::new(&k)
        .publish(p1, &pdoc(), &shot_off_the_head(1, vec![]), &anyone)
        .expect("a tail of exactly the budget is carried");
    assert_eq!(
        k.snapshot().world().m5().content_runs(&member).cloned().collect::<Vec<_>>(),
        head_runs[1..].to_vec()
    );
}

#[test]
fn the_shot_refuses_a_reinsert_past_its_budget_before_probing_an_address() {
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
        rejected(vs.publish(p1, &pdoc(), &from_the_draft(&[MAX_REINSERTED_VALUES + 1]), &anyone)),
        PublishError::TooManyValues
    ));
    let past_half = MAX_REINSERTED_VALUES / 2 + 1;
    assert!(matches!(
        rejected(vs.publish(p1, &pdoc(), &from_the_draft(&[past_half, past_half]), &anyone)),
        PublishError::TooManyValues
    ));
    // Exactly the budget passes the count, and its first probe finds the
    // draft's first address holding nothing.
    assert!(matches!(
        rejected(vs.publish(p1, &pdoc(), &from_the_draft(&[MAX_REINSERTED_VALUES]), &anyone)),
        PublishError::DanglingSource
    ));
    // A run of the edition's own I-space past the budget, beside the same
    // draft: not a re-insert, so it is refused for what it names.
    let own = ShotRun {
        origin: pdoc(),
        run: run(&pca(1), MAX_REINSERTED_VALUES as u32 + 1),
    };
    assert!(matches!(
        rejected(vs.publish(p1, &pdoc(), &shot_from(vec![own]), &anyone)),
        PublishError::DanglingSource
    ));
    // A draft its shooter may not read is withheld, however much of it
    // the shot names.
    assert!(matches!(
        rejected(vs.publish(p1, &pdoc(), &from_the_draft(&[MAX_REINSERTED_VALUES + 1]), &no_one)),
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
    // noted (nothing placed, the base's extent as the shot named it) and,
    // the member being the chain's second, no birth extent.
    let p1 = Caller::Principal(PrincipalId(1));
    let k = shot_kernel(vec![], &[]);
    let before = k.snapshot().world().m5().clone();
    let anyone = |_: &ShotWorld, _: &Address| true;
    let shot = shot_off_the_head(0, vec![]);
    let (member, _) = Vstream::new(&k)
        .publish(p1, &pdoc(), &shot, &anyone)
        .expect("an empty shot commits");
    let s = k.snapshot();
    let m5 = s.world().m5();
    assert!(s.world().m3().is_registered_document(&member), "the member is minted");
    assert_eq!(m5.content_runs(&member).len(), 0, "nothing is placed for it");
    assert_eq!(m5.content_count(&member), n(0));
    assert_eq!(m5.provenance, before.provenance, "nothing in R for it");
    assert_eq!(
        m5.arrangement_map(),
        before.arrangement_map(),
        "no arrangement entry: the lazy empty one"
    );
    assert_eq!(
        m5.shot_terms(&member),
        Some(&ShotTerms { placed: n(0), base_extent: shot.base.map(|base| base.extent) }),
        "the terms are journaled all the same"
    );
    assert_eq!(m5.birth_extent(&member), None, "the chain's second member is no birth version");
}

#[test]
fn a_shot_refused_after_its_reinsert_is_staged_leaves_no_mint_no_write_and_no_member() {
    // "A rejection leaves no state change" where it is more than trivially
    // true: the draft's one value re-inserted — a mint and a write staged —
    // ahead of a carried tail of exactly the budget, which it pushes one run
    // past. The refusal leaves no `Seq`, no value, no move of the trunk's
    // content frontier and no member (PUB-2.33's ONE commit). One carried run
    // shorter, the same shot commits, its re-insert landing where the refused
    // one staged its mint.
    let p1 = Caller::Principal(PrincipalId(1));
    let ordinals: Vec<u32> = (1..=MAX_PLACED_RUNS as u32 + 1).map(|o| 2 * o).collect();
    let head_runs: Vec<Run> = ordinals.iter().map(|&o| run(&pca(o), 1)).collect();
    let k = shot_kernel(head_runs, &ordinals);
    let vs = Vstream::new(&k);
    let values = vec![Val::new(&b"d"[..])];
    vs.insert(p1, &doc1(), vp(1, 1), values, Deposit::Undeclared)
        .expect("the draft holds one value, at ca(1)");
    let anyone = |_: &ShotWorld, _: &Address| true;
    let carrying_past = |extent: u32| Shot {
        base: Some(Base {
            member: pdoc_member(),
            extent: n(extent),
        }),
        draft: Some(doc1()),
        runs: vec![ShotRun {
            origin: doc1(),
            run: run(&ca(1), 1),
        }],
    };
    let before = k.current_seq();
    let stored = k.snapshot().world().content().len();
    let frontier = k.snapshot().world().m3().next_content_address(&pdoc());
    assert!(matches!(
        rejected(vs.publish(p1, &pdoc(), &carrying_past(1), &anyone)),
        PublishError::TooManyRuns
    ));
    let s = k.snapshot();
    let (m3, content) = (s.world().m3(), s.world().content());
    assert_eq!(k.current_seq(), before, "no Seq drawn");
    assert_eq!(content.len(), stored, "the staged write is gone");
    assert_eq!(
        m3.next_content_address(&pdoc()),
        frontier,
        "the staged mint is gone"
    );
    assert!(
        !m3.is_registered_document(&a(&[1, 0, 1, 0, 3, 2])),
        "no member"
    );
    let (member, _) = vs
        .publish(p1, &pdoc(), &carrying_past(2), &anyone)
        .expect("the re-insert and a tail one run shorter place exactly the budget");
    let s = k.snapshot();
    assert_eq!(s.world().m5().content_run_count(&member), MAX_PLACED_RUNS);
    assert_eq!(
        s.world().m5().point(&member, &vp(1, 1)),
        frontier,
        "the re-insert lands where the refused one staged its mint"
    );
}
