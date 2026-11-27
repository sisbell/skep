//! The publish shot's in-crate claims — its run budget at both sites, its
//! re-insert's two budgets, the count of its units against what its commit
//! stages and against the stored pieces it walks, its empty member, and a
//! refusal after its re-insert is staged — in a world whose three slices are
//! seeded apart, so a head can arrange more runs than a test could build by
//! transactions, a draft can name values that were never stored, and a draft
//! can hold a million stored pieces no test could type; and whose records
//! are counted by kind as they are staged.

use std::cell::Cell;

use serde::{Deserialize, Serialize};
use skep_content::{stage_stretch, stage_write, ContentStore, ContentStretch, Piece, Val};
use skep_kernel::{Kernel, Seq};
use skep_namespace::PrincipalId;

use super::*;
use crate::deposit::Deposit;
use crate::ops::AsOf;
use crate::shot::{Base, ShotRun};
use crate::state::M5State;
use crate::testutil::{a, ca, doc1, doc2, mem_kernel_of, n, nth_doc, pca, pdoc, rejected, run, seeded_m3, vp};

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
    Stretch(ContentStretch),
}

/// The records this thread has staged since the last [`Staged::take`], by
/// kind.
///
/// A staging lifts each record into the world's own exactly once, as it
/// pushes it, so the lifts are the records staged — a refused transaction's
/// among them, which is how a refusal ahead of every record is told from
/// one after some. A thread's own, since each test runs on one.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Staged {
    /// M3's records: each content mint, each range mint, the member's mint.
    mints: u64,
    /// M4's values: one per atom.
    writes: u64,
    /// M4's stretches: one per run of single-byte values.
    stretches: u64,
    /// M5's records: the shot's one placement.
    placements: u64,
}

thread_local! {
    static STAGED: Cell<Staged> = const { Cell::new(Staged { mints: 0, writes: 0, stretches: 0, placements: 0 }) };
}

impl Staged {
    /// Returns this thread's counts since the last call, and starts them
    /// again from nothing.
    fn take() -> Staged {
        STAGED.with(|staged| staged.replace(Staged::default()))
    }

    fn note(count: impl FnOnce(&mut Staged)) {
        STAGED.with(|staged| {
            let mut now = staged.get();
            count(&mut now);
            staged.set(now);
        });
    }
}

impl From<M3Rec> for ShotRec {
    fn from(r: M3Rec) -> ShotRec {
        Staged::note(|staged| staged.mints += 1);
        ShotRec::M3(r)
    }
}
impl From<ContentWrite> for ShotRec {
    fn from(r: ContentWrite) -> ShotRec {
        Staged::note(|staged| staged.writes += 1);
        ShotRec::Content(r)
    }
}
impl From<ContentStretch> for ShotRec {
    fn from(r: ContentStretch) -> ShotRec {
        Staged::note(|staged| staged.stretches += 1);
        ShotRec::Stretch(r)
    }
}
impl From<M5Rec> for ShotRec {
    fn from(r: M5Rec) -> ShotRec {
        Staged::note(|staged| staged.placements += 1);
        ShotRec::M5(r)
    }
}

impl WorldState for ShotWorld {
    type Record = ShotRec;
    fn apply(&self, at: Seq, r: &ShotRec) -> ShotWorld {
        match r {
            ShotRec::M3(x) => ShotWorld {
                m3: self.m3.apply_m3(at, x),
                content: self.content.clone(),
                m5: self.m5.clone(),
            },
            ShotRec::Content(x) => ShotWorld {
                m3: self.m3.clone(),
                content: self.content.apply_write(x),
                m5: self.m5.clone(),
            },
            ShotRec::Stretch(x) => ShotWorld {
                m3: self.m3.clone(),
                content: self.content.apply_stretch(x),
                m5: self.m5.clone(),
            },
            ShotRec::M5(x) => ShotWorld {
                m3: self.m3.clone(),
                content: self.content.clone(),
                m5: self.m5.apply_m5(at, x),
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
    a(&[1, 0, 1, 0, nth_doc(3), 1])
}

/// pdoc with `pdoc_member()` heading its chain and arranging
/// `member_runs` — nothing placed at all when they are empty, as no op
/// stages an empty placement — and pdoc's content elements stored at the
/// ordinals in `present`.
fn shot_kernel(member_runs: Vec<Run>, present: &[u32]) -> Kernel<ShotWorld> {
    let m3 = seeded_m3().apply_m3(Seq(0), &M3Rec::allocate(pdoc_member(), true));
    let m5 = if member_runs.is_empty() {
        M5State::genesis()
    } else {
        M5State::genesis().apply_m5(Seq(0), &M5Rec::ContentPlace {
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
        also: vec![],
        keep_base: false,
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
    // from its draft, and the count is request arithmetic — the DISTINCT
    // positions the draft-native runs name — answered before any address is
    // probed. Nothing of doc1 is stored in this world, so every probe of
    // the draft answers `DanglingSource`: a shot refused `TooManyValues`
    // here was refused without one. What is bounded is the distinct count,
    // each draft identity being minted once per shot: two runs over ONE
    // I-extent, each past half the budget, pass the count together and
    // meet the existence walk, while two over DISJOINT extents, each past
    // half, are refused together; a by-reference run is placed as one run
    // and never re-inserted, so its width is not counted; and the source
    // gate still speaks first.
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
        also: vec![],
        keep_base: false,
        runs,
    };
    // Runs of the draft, each `(first ordinal, width)`.
    let from_the_draft = |runs: &[(u32, usize)]| {
        shot_from(
            runs.iter()
                .map(|&(first, w)| ShotRun {
                    origin: doc1(),
                    run: run(&ca(first), w as u32),
                })
                .collect(),
        )
    };
    let before = k.current_seq();
    assert!(matches!(
        rejected(vs.publish(p1, &pdoc(), &from_the_draft(&[(1, MAX_REINSERTED_VALUES + 1)]), &anyone)),
        PublishError::TooManyValues
    ));
    let past_half = MAX_REINSERTED_VALUES / 2 + 1;
    assert!(matches!(
        rejected(vs.publish(
            p1,
            &pdoc(),
            &from_the_draft(&[(1, past_half), (past_half as u32 + 1, past_half)]),
            &anyone
        )),
        PublishError::TooManyValues
    ));
    assert!(
        matches!(
            rejected(vs.publish(p1, &pdoc(), &from_the_draft(&[(1, past_half), (1, past_half)]), &anyone)),
            PublishError::DanglingSource
        ),
        "one I-extent named twice is counted once: inside the budget, so the walk is reached"
    );
    // Exactly the budget passes the count, and its first probe finds the
    // draft's first address holding nothing.
    assert!(matches!(
        rejected(vs.publish(p1, &pdoc(), &from_the_draft(&[(1, MAX_REINSERTED_VALUES)]), &anyone)),
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
        rejected(vs.publish(p1, &pdoc(), &from_the_draft(&[(1, MAX_REINSERTED_VALUES + 1)]), &no_one)),
        PublishError::Withheld(d) if d == doc1()
    ));
    assert_eq!(k.current_seq(), before, "every refusal commits nothing");
}

#[test]
fn a_shot_reinserts_a_drafts_one_byte_values_as_one_stretch() {
    // THE LENGTH TEST: a draft a board written before stretches holds spells
    // its text as one-byte VALUES — seeded here through `stage_write` apiece,
    // the per-value form, and arranged as one run by M5's record. The
    // re-insert takes each one-byte `Piece::Value` into its pending byte-run
    // as it takes a `Piece::Bytes`, so the member holds ONE stretch for the
    // run — one entry, the bytes in order at the trunk's three fresh
    // addresses, each answering as a byte of a stretch — where re-minting
    // each as a one-byte value would carry the old form into every edition.
    let p1 = Caller::Principal(PrincipalId(1));
    let mut content = ContentStore::default();
    for (k, byte) in (1..=3u32).zip(b"abc") {
        let cw = stage_write(&content, ca(k), Val::new([*byte])).expect("fresh");
        content = content.apply_write(&cw);
    }
    let m5 = M5State::genesis().apply_m5(Seq(0), &M5Rec::ContentPlace {
        doc: doc1(),
        at: n(1),
        runs: vec![run(&ca(1), 3)],
    });
    let k = mem_kernel_of(ShotWorld { m3: seeded_m3(), content, m5 });
    let stored = k.snapshot().world().content().len();
    let anyone = |_: &ShotWorld, _: &Address| true;
    let shot = Shot {
        base: None,
        draft: Some(doc1()),
        also: vec![],
        keep_base: false,
        runs: vec![ShotRun { origin: doc1(), run: run(&ca(1), 3) }],
    };
    let (member, _) = Vstream::new(&k)
        .publish(p1, &pdoc(), &shot, &anyone)
        .expect("the birth shot commits");
    let s = k.snapshot();
    let (m5, content) = (s.world().m5(), s.world().content());
    assert_eq!(m5.content_count(&member), n(3), "three positions re-inserted");
    assert_eq!(content.len() - stored, 1, "one stretch, not three one-byte values");
    for (ordinal, byte) in (1..=3u32).zip(b"abc") {
        match content.value_at(pca(ordinal).tumbler()) {
            Some(Piece::Bytes(b)) => assert_eq!(b, &[*byte][..], "the byte at pca({ordinal})"),
            other => panic!("pca({ordinal}) holds {other:?}, not a byte of the member's stretch"),
        }
    }
}

#[test]
fn an_empty_shot_mints_its_member_places_nothing_and_journals_its_terms() {
    // An empty placement still pushes the shot's record (D25's (c′)): the
    // member's mint is M3's record, and M5's record carries the shot's
    // terms whatever the placement holds. With nothing to place, the
    // arrangement and R come out exactly as they went in — no arrangement
    // entry and nothing in R for the member, which reads as the lazy empty
    // arrangement, as an empty fork's does — while the member's terms are
    // noted (nothing placed, the base and its extent as the shot named
    // them) and, the member being the chain's second, no birth extent.
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
        Some(&ShotTerms {
            placed: n(0),
            base_extent: shot.base.as_ref().map(|base| base.extent.clone()),
            base: shot.base.as_ref().map(|base| base.member.clone()),
        }),
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
    vs.insert(p1, &doc1(), vp(1, 1), values, Deposit::Undeclared, AsOf::Typed(k.current_seq()))
        .expect("the draft holds one value, at ca(1)");
    let anyone = |_: &ShotWorld, _: &Address| true;
    let carrying_past = |extent: u32| Shot {
        base: Some(Base {
            member: pdoc_member(),
            extent: n(extent),
        }),
        draft: Some(doc1()),
        also: vec![],
        keep_base: false,
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
        !m3.is_registered_document(&a(&[1, 0, 1, 0, 65, 2])),
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

/// doc2's content element at `ordinal`.
fn d2(ordinal: u32) -> Address {
    a(&[1, 0, 1, 0, nth_doc(2), 0, 1, ordinal])
}

/// `content` with `bytes` stored from `first` as one stretch.
fn with_stretch(content: ContentStore, first: Address, bytes: &[u8]) -> ContentStore {
    let stretch = stage_stretch(&content, first, Arc::from(bytes)).expect("a fresh stretch");
    content.apply_stretch(&stretch)
}

/// `content` with `bytes` stored at `at` as one value.
fn with_value(content: ContentStore, at: Address, bytes: &[u8]) -> ContentStore {
    let write = stage_write(&content, at, Val::new(bytes)).expect("a fresh value");
    content.apply_write(&write)
}

/// A kernel over `content`, pdoc published and memberless, no document
/// arranging anything: a shot reads a draft's values at their addresses and
/// never its arrangement.
fn kernel_holding(content: ContentStore) -> Kernel<ShotWorld> {
    mem_kernel_of(ShotWorld { m3: seeded_m3(), content, m5: M5State::genesis() })
}

/// The birth shot of pdoc from `runs`, each `(origin, start, width)`, the
/// rendering draft doc1 and `also` beside it.
fn birth_shot(also: Vec<Address>, runs: &[(Address, Address, u32)]) -> Shot {
    Shot {
        base: None,
        draft: Some(doc1()),
        also,
        keep_base: false,
        runs: runs.iter().map(|(origin, start, width)| ShotRun { origin: origin.clone(), run: run(start, *width) }).collect(),
    }
}

/// Stages `shot` into pdoc in one transaction, its walk of the drafts'
/// stored pieces counted: the staging's answer, and the pieces walked.
fn staged_counting(k: &Kernel<ShotWorld>, shot: &Shot) -> (Result<(Address, Pairing), PublishError>, u64) {
    let p1 = Caller::Principal(PrincipalId(1));
    let anyone = |_: &ShotWorld, _: &Address| true;
    let keys = [head_lock_key(&pdoc()), M3State::content_lock_key(&pdoc())];
    let mut walked = 0u64;
    let staged = k.transact(&keys, |stg| stage_publish_stepped(stg, p1, &pdoc(), shot, &anyone, &mut |pieces| walked += pieces));
    let staged = match staged {
        Ok((answer, _)) => Ok(answer),
        Err(TxnError::Rejected(refused)) => Err(refused),
        Err(other) => panic!("the kernel refused the transaction: {other:?}"),
    };
    (staged, walked)
}

/// The count of `shot`'s units over `k`'s world, with the pieces it walked.
fn counted(k: &Kernel<ShotWorld>, shot: &Shot) -> (ReinsertedUnits, u64) {
    let mut walked = 0u64;
    let snapshot = k.snapshot();
    let units = shot.reinserted_units(snapshot.world(), &mut |pieces| walked += pieces);
    (units, walked)
}

/// EACH DRAFT IDENTITY ONCE PER SHOT, told position by position and
/// knowing nothing of portions or units: in `runs`' order a position met
/// for the first time takes the next fresh address of pdoc's content chain,
/// from `pca(1)`, and a position met again the address it took. Each entry
/// is the draft's position, the fresh one, whether this run minted it, and
/// the run's index.
fn position_by_position(shot: &Shot) -> Vec<(Address, Address, bool, usize)> {
    let mut fresh: std::collections::BTreeMap<Address, Address> = std::collections::BTreeMap::new();
    let mut out = Vec::new();
    for (index, entry) in shot.runs.iter().enumerate() {
        for from in entry.run.addrs() {
            let next = pca(fresh.len() as u32 + 1);
            let minted = !fresh.contains_key(&from);
            let to = fresh.entry(from.clone()).or_insert(next).clone();
            out.push((from, to, minted, index));
        }
    }
    out
}

/// The pairing, position by position, in its own order.
fn pairing_positions(pairing: &Pairing) -> Vec<(Address, Address, bool, usize)> {
    pairing
        .iter()
        .flat_map(|piece| piece.from.addrs().zip(piece.to.addrs()).map(|(from, to)| (from, to, piece.minted, piece.index)))
        .collect()
}

#[test]
fn the_units_a_shot_counts_are_the_units_its_commit_stages() {
    // THE COUNT IS THE STAGING's OWN SPLIT. Two named drafts, their runs
    // interleaved: doc1 holds `abcd`, the atom `XY`, `ef`, an empty value,
    // then `g` as a one-byte value, `h` as a one-byte stretch and `ij`;
    // doc2 holds `xyz` and the atom `PQ`. The shot names doc1's [3, 6]
    // (two byte-runs around an atom: three units), doc2's [1, 2] (one),
    // doc1's [7] — I-adjacent to the first run's end, and a portion of its
    // own: the byte `f` never joins the `e` before it (one) — then doc1
    // whole, [1, 12], which an earlier run minted the middle of: its
    // unminted portions are `ab` (one) and the empty value with `ghij`, a
    // one-byte value and two stretches in one byte-run (two); doc1's
    // [3, 6] again, minted whole already (none); and doc2's [2, 4], its
    // first position minted, `z` and the atom left (two). Ten units: three
    // atoms and seven byte-runs.
    let mut content = ContentStore::default();
    content = with_stretch(content, ca(1), b"abcd");
    content = with_value(content, ca(5), b"XY");
    content = with_stretch(content, ca(6), b"ef");
    content = with_value(content, ca(8), b"");
    content = with_value(content, ca(9), b"g");
    content = with_stretch(content, ca(10), b"h");
    content = with_stretch(content, ca(11), b"ij");
    content = with_stretch(content, d2(1), b"xyz");
    content = with_value(content, d2(4), b"PQ");
    let k = kernel_holding(content);
    let shot = birth_shot(
        vec![doc2()],
        &[(doc1(), ca(3), 4), (doc2(), d2(1), 2), (doc1(), ca(7), 1), (doc1(), ca(1), 12), (doc1(), ca(3), 4), (doc2(), d2(2), 3)],
    );
    // The count, over the snapshot the commit opens on: ten units holding
    // seventeen bytes, read off the twelve stored pieces the six runs'
    // unminted portions cut the drafts into — `cd`, `XY`, `e`; `xy`; `f`;
    // `ab`; the empty value, `g`, `h`, `ij`; `z`, `PQ` — each read once.
    let (units, walked) = counted(&k, &shot);
    let ReinsertedUnits::Counted(parts) = units else { panic!("within both budgets, every value stored: {units:?}") };
    assert_eq!(parts.tally(), UnitTally { units: 10, bytes: 17 });
    assert_eq!(walked, 12, "one step a stored piece of an unminted portion");
    assert_eq!(parts.atoms().map(Val::as_bytes).collect::<Vec<_>>(), [&b"XY"[..], b"", b"PQ"], "the atoms, in placement order");
    // The commit: two records a unit — a mint and a write an atom, a range
    // mint and a stretch a byte-run — beside the member's mint and its one
    // placement; and it walks the pieces the count walked, no more.
    Staged::take();
    let (staged, walked) = staged_counting(&k, &shot);
    let (member, pairing) = staged.expect("the shot commits");
    let records = Staged::take();
    assert_eq!(records, Staged { mints: 10 + 1, writes: 3, stretches: 7, placements: 1 }, "two records a unit, by kind");
    assert_eq!(records.writes + records.stretches, parts.tally().units, "the units counted are the units staged");
    assert_eq!(walked, 12, "the commit reads each stored piece once: the count's walk, and no second one");
    // The fresh runs and the pairing: each draft identity minted once, in
    // the order the runs meet it, every later occurrence the fresh address
    // the first took — told position by position, with no portion in it.
    assert_eq!(pairing_positions(&pairing), position_by_position(&shot));
    for piece in &pairing {
        let home = if piece.from.i_start() < &d2(1) { doc1() } else { doc2() };
        assert_eq!(piece.home, home, "each piece homed in the draft its identity was: {piece:?}");
    }
    // A portion is one pairing entry, however many units it held.
    let minted: Vec<(Run, Run)> = pairing.iter().filter(|piece| piece.minted).map(|piece| (piece.from.clone(), piece.to.clone())).collect();
    assert_eq!(
        minted,
        vec![
            (run(&ca(3), 4), run(&pca(1), 4)),
            (run(&d2(1), 2), run(&pca(5), 2)),
            (run(&ca(7), 1), run(&pca(7), 1)),
            (run(&ca(1), 2), run(&pca(8), 2)),
            (run(&ca(8), 5), run(&pca(10), 5)),
            (run(&d2(3), 2), run(&pca(15), 2)),
        ]
    );
    // And the member holds, at every position, the value its draft held.
    let s = k.snapshot();
    let (m5, content) = (s.world().m5(), s.world().content());
    assert_eq!(m5.content_count(&member), n(4 + 2 + 1 + 12 + 4 + 3));
    for (from, to, _, _) in pairing_positions(&pairing) {
        let (drafted, published) = (content.value_at(from.tumbler()), content.value_at(to.tumbler()));
        assert_eq!(drafted.map(|piece| piece.as_bytes()), published.map(|piece| piece.as_bytes()), "{from:?} became {to:?}");
    }
    assert_eq!(s.world().m3().next_content_address(&pdoc()), Some(pca(17)), "sixteen positions minted, each draft identity once");
}

#[test]
fn positions_named_one_by_one_and_then_together_are_counted_portion_by_portion() {
    // WHERE THE UNION COMES SHORT. One stretch of seven bytes; the shot
    // names its second, fourth and sixth positions, one run each, and then
    // all seven. To the union of the runs' extents that is one stretch, one
    // unit; the commit places each run apart, and the last run's unminted
    // portions are the four positions between and around the three — so
    // seven units, seven range mints and seven stretches, are what the shot
    // stages, and seven are what the count answers.
    let k = kernel_holding(with_stretch(ContentStore::default(), ca(1), b"abcdefg"));
    let shot = birth_shot(vec![], &[(doc1(), ca(2), 1), (doc1(), ca(4), 1), (doc1(), ca(6), 1), (doc1(), ca(1), 7)]);
    let (units, _) = counted(&k, &shot);
    assert_eq!(units.tally(), UnitTally { units: 7, bytes: 7 }, "a unit a portion, never one for the union: {units:?}");
    Staged::take();
    let (staged, _) = staged_counting(&k, &shot);
    staged.expect("the shot commits");
    assert_eq!(Staged::take(), Staged { mints: 7 + 1, writes: 0, stretches: 7, placements: 1 });
}

#[test]
fn a_portion_of_single_byte_pieces_is_one_unit_staged_as_two_records_and_walked_once() {
    // THE UNIT IS THE BYTE-RUN, NOT THE PIECE. A draft written a byte an
    // insert holds a stored piece a position: here the positions' budget of
    // them, 2^20, alternately a one-byte stretch and a one-byte value. The
    // shot naming them all re-inserts ONE unit — one range mint and one
    // stretch of 2^20 bytes — after a walk of every piece, which the commit
    // makes once: the count reads them, and the placement stages from what
    // the count read.
    let positions = MAX_REINSERTED_VALUES as u32;
    let mut content = ContentStore::default();
    for k in 1..=positions {
        let byte = [b'a' + (k % 26) as u8];
        content = if k % 2 == 1 { with_stretch(content, ca(k), &byte) } else { with_value(content, ca(k), &byte) };
    }
    let k = kernel_holding(content);
    let stored = k.snapshot().world().content().len();
    assert_eq!(stored, positions as usize, "premise: a stored piece a position");
    let shot = birth_shot(vec![], &[(doc1(), ca(1), positions)]);
    let (units, walked) = counted(&k, &shot);
    assert_eq!(units.tally(), UnitTally { units: 1, bytes: u64::from(positions) }, "{units:?}");
    assert_eq!(walked, u64::from(positions), "the count walks every piece: the budget on the units stops no walk");
    Staged::take();
    let (staged, walked) = staged_counting(&k, &shot);
    let (member, pairing) = staged.expect("one unit is inside the units' budget");
    assert_eq!(Staged::take(), Staged { mints: 1 + 1, writes: 0, stretches: 1, placements: 1 }, "two records for the unit");
    assert_eq!(walked, u64::from(positions), "each stored piece read once in the commit");
    assert_eq!(pairing.len(), 1, "one portion, one fresh run");
    let s = k.snapshot();
    assert_eq!(s.world().content().len() - stored, 1, "one stretch in the member");
    assert_eq!(s.world().m5().content_count(&member), n(positions));
    for at in [1, 2, positions / 2, positions] {
        let (drafted, published) = (s.world().content().value_at(ca(at).tumbler()), s.world().content().value_at(pca(at).tumbler()));
        assert_eq!(drafted.map(|piece| piece.as_bytes()), published.map(|piece| piece.as_bytes()), "position {at}");
    }
}

#[test]
fn a_shot_past_the_positions_is_refused_with_no_piece_walked_and_one_past_the_units_stages_nothing() {
    // ARITHMETIC FIRST. doc1 holds one more position than the positions'
    // budget, all of it stored: a shot naming them all is refused
    // `TooManyValues` by the count's arithmetic, and neither the count nor
    // the commit reads a stored piece to learn it; a shot naming exactly the
    // budget is counted, one unit, off the one stored piece.
    let positions = MAX_REINSERTED_VALUES as u32;
    let k = kernel_holding(with_stretch(ContentStore::default(), ca(1), &vec![b'x'; positions as usize + 1]));
    let before = k.current_seq();
    let past = birth_shot(vec![], &[(doc1(), ca(1), positions + 1)]);
    let (units, walked) = counted(&k, &past);
    assert!(matches!(units, ReinsertedUnits::PastPositions), "{units:?}");
    assert_eq!((units.tally(), walked), (UnitTally::default(), 0), "nothing counted, no piece walked");
    Staged::take();
    let (staged, walked) = staged_counting(&k, &past);
    assert_eq!(staged.expect_err("past the positions' budget"), PublishError::TooManyValues);
    assert_eq!((walked, Staged::take(), k.current_seq()), (0, Staged::default(), before), "no piece walked, no record staged");
    let (units, walked) = counted(&k, &birth_shot(vec![], &[(doc1(), ca(1), positions)]));
    assert_eq!((units.tally(), walked), (UnitTally { units: 1, bytes: u64::from(positions) }, 1), "{units:?}");
    // THE UNITS, BEFORE ANY RECORD. doc2 holds one more atom than the
    // units' budget — well inside the positions' — and a shot naming them
    // all is refused `TooManyUnits`: the count stops at the atom that opens
    // the unit past the budget, the commit stages no record, and nothing of
    // the transaction stands. Naming exactly the budget, the count answers
    // it whole.
    let units_budget = MAX_REINSERTED_UNITS as u32;
    let mut content = ContentStore::default();
    for at in 1..=units_budget + 1 {
        content = with_value(content, d2(at), b"at");
    }
    let k = kernel_holding(content);
    let (before, stored, frontier) = (k.current_seq(), k.snapshot().world().content().len(), k.snapshot().world().m3().next_content_address(&pdoc()));
    let atoms = |count: u32| Shot { draft: Some(doc2()), ..birth_shot(vec![], &[(doc2(), d2(1), count)]) };
    let (units, walked) = counted(&k, &atoms(units_budget + 1));
    let over = UnitTally { units: u64::from(units_budget) + 1, bytes: 2 * u64::from(units_budget) };
    assert!(matches!(units, ReinsertedUnits::PastUnits(tally) if tally == over), "the budget plus one, a lower bound, and the bytes of the units inside it: {units:?}");
    assert_eq!(walked, u64::from(units_budget) + 1, "the count stops at the piece that passed the budget");
    Staged::take();
    let (staged, _) = staged_counting(&k, &atoms(units_budget + 1));
    assert_eq!(staged.expect_err("past the units' budget"), PublishError::TooManyUnits);
    assert_eq!(Staged::take(), Staged::default(), "no record staged ahead of the refusal");
    let s = k.snapshot();
    assert_eq!((k.current_seq(), s.world().content().len(), s.world().m3().next_content_address(&pdoc())), (before, stored, frontier));
    let (units, _) = counted(&k, &atoms(units_budget));
    assert!(matches!(&units, ReinsertedUnits::Counted(parts) if parts.tally().units == u64::from(units_budget)), "{units:?}");
    // A VALUE MISSING IS NO UNIT: past the atoms doc2 holds nothing, and a
    // shot reaching one position past them inside the units' budget is told
    // so, with what stands ahead of the hole — and refused as a dangling
    // source, nothing staged.
    let reaching = Shot { draft: Some(doc2()), ..birth_shot(vec![], &[(doc2(), d2(units_budget), 3)]) };
    let (units, walked) = counted(&k, &reaching);
    assert!(matches!(units, ReinsertedUnits::Missing(tally) if tally == UnitTally { units: 2, bytes: 4 }), "{units:?}");
    assert_eq!(walked, 2);
    Staged::take();
    let (staged, _) = staged_counting(&k, &reaching);
    assert_eq!(staged.expect_err("a position holding nothing"), PublishError::DanglingSource);
    assert_eq!(Staged::take(), Staged::default());
}
