//! The edit's in-crate claims, in the world the landing's suite assembles
//! (`ops/set_arrangement/tests.rs`: M3, M4 and M5 under the real kernel, its
//! fold counting itself): a call of many changes is one commit of a fixed
//! number of records, folding the draft's list twice and reading it at its
//! changes' cuts alone, whatever the draft holds; a refused change leaves
//! nothing of its call; the typed state and the record's own position; an
//! empty list beside a base; every address the call places entering R; the
//! refusal order and each change's shape verdict, naming the change.

use skep_address::SpanSet;
use skep_content::{stage_write, ContentStore, Val};
use skep_kernel::{Kernel, Seq};
use skep_namespace::PrincipalId;

use super::super::set_arrangement::tests::{seeded, staged, Folds, LandWorld, P1};
use super::*;
use crate::error::EditError as E;
use crate::ops::{SetMerge, MAX_PLACED_RUNS};
use crate::run_list::Splice;
use crate::state::M5State;
use crate::testutil::{a, doc1, doc2, mem_kernel_of, n, nth_doc, pca, pdoc, rejected, run, seeded_m3, vca, vp};

/// A world whose draft `doc1` holds `runs` runs of width 3 of the edition's
/// I-space, no two I-adjacent, built by one fold.
fn fragmented(runs: u32) -> Kernel<LandWorld> {
    let list: Vec<Run> = (0..runs).map(|j| run(&pca(1 + 4 * j), 3)).collect();
    let m5 = M5State::genesis().apply_m5(Seq(0), &M5Rec::ContentPlace { doc: doc1(), at: n(1), runs: list });
    assert_eq!(m5.content_run_count(&doc1()), runs as usize);
    mem_kernel_of(LandWorld { m3: seeded_m3(), content: ContentStore::default(), m5 })
}

/// A world whose draft `doc1` holds five positions, one run of its first
/// member's I-space — a chain no mint of the draft's own advances — and
/// whose edition holds `a b c`, each stored.
fn small() -> Kernel<LandWorld> {
    let mut content = ContentStore::default();
    for k in 1..=3 {
        let write = stage_write(&content, pca(k), Val::new(&b"a"[..])).expect("written once");
        content = content.apply_write(&write);
    }
    let m5 = M5State::genesis().apply_m5(Seq(0), &M5Rec::ContentPlace { doc: doc1(), at: n(1), runs: vec![run(&vca(1), 5)] });
    mem_kernel_of(LandWorld { m3: seeded_m3(), content, m5 })
}

fn now(k: &Kernel<LandWorld>) -> AsOf {
    AsOf::Typed(k.current_seq())
}

/// One byte of text a value.
fn text(bytes: &[u8]) -> Placed {
    Placed::Values(bytes.iter().map(|b| Val::new(&[*b][..])).collect())
}

fn change(at: u32, width: u32, placed: Placed) -> Change {
    Change { at: vp(1, at), width: n(width), placed }
}

fn plain(changes: Vec<Change>) -> Edit {
    Edit { changes, head: None, base: None, merge: None }
}

fn runs_of(k: &Kernel<LandWorld>, doc: &Address) -> Vec<Run> {
    k.snapshot().world().m5().content_runs(doc).cloned().collect()
}

/// `k` changes spread over a draft of `runs` runs of width 3: change `j`
/// replaces the middle position of run `⌊(2j + 1)·runs ÷ (2k)⌋` with two
/// bytes.
fn spread(runs: u32, k: u32) -> Vec<Change> {
    (0..u64::from(k))
        .map(|j| {
            let at_run = ((2 * j + 1) * u64::from(runs) / (2 * u64::from(k))) as u32;
            change(3 * at_run + 2, 1, text(b"xy"))
        })
        .collect()
}

/// The lock hold, counted. A call of `k` changes into a draft of 65,536
/// runs: its record builds the draft's list twice — at its push and at the
/// seal — whatever `k`; its own walks and those two builds together judge
/// each change, place each run and open the list's tree at each change's
/// cuts a bounded number of times, a bound the draft's 65,536 runs do not
/// enter; and it stages three records, the range mint, the stretch and the
/// one record of its changes, whatever `k`. The count is held to its budget
/// as it grows, so a walk of the list asked once a change stops the call at
/// once.
#[test]
fn a_call_of_many_changes_folds_the_list_twice_and_reads_it_at_its_cuts_alone() {
    const RUNS: u32 = 65_536;
    for changes in [1u32, 16, 256, 4_096] {
        let k = fragmented(RUNS);
        let before = k.snapshot().world().m5().content_list(&doc1()).clone();
        let (seq_before, _) = (k.current_seq(), Folds::take());
        // P: each change places the one run its two bytes are minted as, so
        // the call's own walks are a judgment a change and a run a change.
        let budget = u64::from(changes + changes);
        let mut own = 0u64;
        let edited = Vstream::new(&k)
            .edit_stepped(P1, &doc1(), plain(spread(RUNS, changes)), AsOf::Typed(seq_before), &mut |steps| {
                own += steps;
                assert!(own <= budget, "{changes} changes: the call's own walks passed {budget} steps");
            })
            .expect("the call lands");
        let (records_folded, list_folds) = Folds::take();
        // (a) The draft's list is built exactly twice.
        assert_eq!(list_folds, 2, "{changes} changes: the list built at the push and at the seal");
        // (c) One range mint, one stretch, one record of the changes.
        assert_eq!(k.current_seq().0 - seq_before.0, 3, "{changes} changes: three records staged");
        assert_eq!(records_folded, 6, "{changes} changes: each of the three folded twice");
        assert_eq!(edited.at, k.current_seq(), "one commit, acknowledged at its own position");
        // The record's splice, counted on the list and the changes the call
        // made: change `j` places the two addresses minted for it.
        let first = edited.minted.expect("the call minted");
        let splices: Vec<Splice> = spread(RUNS, changes)
            .into_iter()
            .enumerate()
            .map(|(j, c)| Splice { at: c.at.ordinal, width: c.width, runs: vec![part(&first, 2 * j as u32, 2)] })
            .collect();
        let mut walk = 0u64;
        let spliced = before.spliced(&splices, &mut |steps| walk += steps);
        assert_eq!(&spliced, k.snapshot().world().m5().content_list(&doc1()), "{changes} changes: the record's own splice");
        // (b) The call's own walks and its record's two folds, within the
        // bound: each change judged and each run placed by the call, and
        // by each fold the tree opened at each change's cuts.
        assert_eq!(own, budget, "{changes} changes: one judgment a change, one run placed a change, and no run of the draft read");
        let fold = (u64::from(changes) + 1) * before.cut_steps() + u64::from(changes);
        assert!(walk <= fold, "{changes} changes: {walk} steps a fold past the splice's {fold}");
        if changes <= 256 {
            assert!(own + 2 * walk < u64::from(RUNS), "{changes} changes: {} steps follow the draft's 65,536 runs", own + 2 * walk);
        }
        assert_eq!(k.snapshot().world().m5().content_run_count(&doc1()), (RUNS + 2 * changes) as usize);
    }
}

/// The `width` addresses from the offset `from` past `first`: the part of a
/// call's minted run one of its changes took.
fn part(first: &Address, from: u32, width: u32) -> Run {
    Run { i_start: run(first, from + width).addr_at(&n(from)), width: n(width) }
}

/// ONE COMMIT. Five changes land at one position; and where the third is
/// out of bounds the call is refused naming it, nothing of the call
/// standing: not the two changes before it, not a position drawn.
#[test]
fn a_call_is_one_commit_and_a_refused_change_leaves_nothing_of_it() {
    let k = small();
    let before = k.current_seq();
    let five = |third: Change| {
        plain(vec![change(1, 0, text(b"a")), change(2, 1, text(b"b")), third, change(4, 1, Placed::Runs(vec![])), change(6, 0, text(b"e"))])
    };
    assert_eq!(
        rejected(Vstream::new(&k).edit(P1, &doc1(), five(change(3, 9, text(b"c"))), now(&k))),
        E::OutOfBounds { change: 2 }
    );
    assert_eq!(k.current_seq(), before, "a refusal draws no position");
    assert_eq!(runs_of(&k, &doc1()), vec![run(&vca(1), 5)], "the changes before the refused one do not stand");
    let edited = Vstream::new(&k).edit(P1, &doc1(), five(change(3, 1, text(b"c"))), now(&k)).expect("the five land");
    assert_eq!(edited.at, k.current_seq(), "acknowledged at the commit's own position");
    assert_eq!(k.snapshot().world().m5().arranged_at(&doc1()), Some(edited.at));
    // a x b c e — the four minted bytes consecutive, in the request's order.
    let first = edited.minted.expect("minted");
    assert_eq!(
        runs_of(&k, &doc1()),
        vec![part(&first, 0, 1), run(&vca(1), 1), part(&first, 1, 2), run(&vca(5), 1), part(&first, 3, 1)],
        "a, then x, then b and c side by side, then v, then e"
    );
}

/// THE TYPED STATE. A call typed against an older state is refused with
/// both positions and writes nothing; a call's own commit moves the draft's
/// position, so each of the six edits typed before it is refused; an empty
/// list beside a base and a merge lands, writes the base record and moves
/// the position all the same; and an empty list beside neither is refused.
#[test]
fn the_typed_state_is_judged_and_every_call_moves_it_an_empty_one_included() {
    let k = seeded();
    let (member, draft) = staged(&k);
    let stale = AsOf::Typed(Seq(0));
    let moved = k.snapshot().world().m5().arranged_at(&draft).expect("the stage arranged it");
    // (a) Typed below the draft's last change: refused, nothing written.
    let before = k.current_seq();
    assert_eq!(
        rejected(Vstream::new(&k).edit(P1, &draft, plain(vec![change(1, 0, text(b"q"))]), stale)),
        E::ArrangementMoved { as_of: Seq(0), current: moved }
    );
    assert_eq!(k.current_seq(), before);
    // (c) No change, a base and a merge: the record moves the position and
    // the base record stamps the marker at the commit.
    let head = Base { member: member.clone(), extent: n(3) };
    let landing = Edit { changes: vec![], head: Some(head.clone()), base: Some(head), merge: Some(SetMerge { sides: vec![], at: None }) };
    let typed = now(&k);
    let words = runs_of(&k, &draft);
    let landed = Vstream::new(&k).edit(P1, &draft, landing, typed).expect("an empty list beside a base and a merge");
    assert_eq!(landed.minted, None);
    assert_eq!(runs_of(&k, &draft), words, "no position changed");
    let m5 = k.snapshot().world().m5().clone();
    assert_eq!(m5.arranged_at(&draft), Some(landed.at), "the position moved to the commit");
    assert_eq!(m5.draft_base(&draft).and_then(|b| b.merge.as_ref()).map(|m| m.at), Some(landed.at), "the marker stamped");
    // (b) Each of the six edits typed before that commit is refused.
    let vs = Vstream::new(&k);
    let refused = E::ArrangementMoved { as_of: before, current: landed.at };
    assert_eq!(rejected(vs.edit(P1, &draft, plain(vec![change(1, 1, Placed::Runs(vec![]))]), typed)), refused);
    assert!(matches!(rejected(vs.insert(P1, &draft, vp(1, 1), vec![Val::new(&b"q"[..])], crate::Deposit::Undeclared, typed)), crate::InsertError::ArrangementMoved { .. }));
    assert!(matches!(rejected(vs.delete(P1, &draft, vp(1, 1), n(1), typed)), crate::DeleteError::ArrangementMoved { .. }));
    assert!(matches!(rejected(vs.copy(P1, &draft, vp(1, 1), &[], typed)), crate::CopyError::ArrangementMoved { .. }));
    assert!(matches!(rejected(vs.reinstate(P1, &draft, vp(1, 1), &[], typed)), crate::ReinstateError::ArrangementMoved { .. }));
    assert!(matches!(rejected(vs.rearrange(P1, &draft, &[], typed)), crate::RearrangeError::ArrangementMoved { .. }));
    // (d) No change, no base and no merge: nothing to write.
    assert_eq!(rejected(vs.edit(P1, &draft, plain(vec![]), now(&k))), E::EmptyResult { change: None });
    assert_eq!(k.current_seq(), landed.at, "the refusals wrote nothing");
}

/// R. Every value a call mints and every run it places by identity enters
/// the draft's provenance in the call's own commit, so the documents ever
/// holding either include the draft.
#[test]
fn every_address_a_call_places_enters_the_drafts_provenance() {
    let k = small();
    let holds = |k: &Kernel<LandWorld>, placed: &Run| {
        let coverage: SpanSet = [placed.iextent()].into_iter().collect();
        k.snapshot().world().m5().docs_ever_containing(&coverage).contains(&doc2())
    };
    let edition = ShotRun { origin: pdoc(), run: run(&pca(1), 3) };
    assert!(!holds(&k, &edition.run));
    // Runs placed by identity, in two changes, the second at the end.
    let two = plain(vec![change(1, 0, Placed::Runs(vec![ShotRun { origin: pdoc(), run: run(&pca(1), 1) }])), change(1, 0, Placed::Runs(vec![ShotRun { origin: pdoc(), run: run(&pca(2), 2) }]))]);
    Vstream::new(&k).edit(P1, &doc2(), two, now(&k)).expect("placed by identity");
    assert_eq!(runs_of(&k, &doc2()), vec![run(&pca(1), 3)]);
    assert!(holds(&k, &edition.run), "each placed run is recorded");
    // Values minted, in two changes: the second's bytes stand past the first's.
    let edited = Vstream::new(&k)
        .edit(P1, &doc2(), plain(vec![change(1, 1, text(b"pq")), change(3, 0, text(b"r"))]), now(&k))
        .expect("minted");
    let first = edited.minted.expect("the first address minted");
    assert_eq!(runs_of(&k, &doc2()), vec![run(&first, 2), run(&pca(2), 1), part(&first, 2, 1), run(&pca(3), 1)]);
    assert!(holds(&k, &run(&first, 3)), "every minted address is recorded");
    // What the first change removed stays recorded (P2), and reads as deleted.
    assert!(holds(&k, &run(&pca(1), 1)));
    assert!(!k.snapshot().world().m5().deletions(&doc2()).is_empty());
}

/// THE REFUSAL ORDER, one cell a pair of adjacent verdicts, each refusal
/// writing nothing: the destination's four, the typed state ahead of the
/// terms and of every shape, the empty call, then each change's shape in
/// the order stated, the first defective change deciding and named, then
/// the runs placed by identity.
#[test]
fn the_refusals_come_in_the_stated_order_each_naming_its_change() {
    let k = small();
    let before = k.current_seq();
    let vs = Vstream::new(&k);
    let ghost = a(&[1, 0, 1, 0, 71]);
    let p2 = Caller::Principal(PrincipalId(2));
    let bad = || vec![change(9, 9, text(b"q"))];
    assert_eq!(rejected(vs.edit(P1, &ghost, plain(bad()), now(&k))), E::DocNotRegistered);
    assert_eq!(rejected(vs.edit(p2, &doc1(), plain(bad()), now(&k))), E::NotOwner(doc1()));
    assert_eq!(rejected(vs.edit(P1, &pdoc(), plain(bad()), AsOf::Typed(Seq(0)))), E::PublishedTarget);
    // A second commit, so a state older than the draft's last change exists.
    let moved = vs.edit(P1, &doc1(), plain(vec![change(6, 0, text(b"!"))]), now(&k)).expect("an edit").at;
    let stale = AsOf::Typed(before);
    let unregistered = Base { member: ghost.clone(), extent: n(0) };
    assert_eq!(
        rejected(vs.edit(P1, &doc1(), Edit { head: Some(unregistered.clone()), ..plain(bad()) }, stale)),
        E::ArrangementMoved { as_of: before, current: moved },
        "the typed state ahead of the terms and the shapes"
    );
    assert_eq!(
        rejected(vs.edit(P1, &doc1(), Edit { head: Some(unregistered), ..plain(bad()) }, now(&k))),
        E::SourceNotRegistered { change: None },
        "the terms ahead of the shapes"
    );
    // Each shape, and the one before it winning where both hold.
    let shape = |changes: Vec<Change>| rejected(vs.edit(P1, &doc1(), plain(changes), now(&k)));
    let link = Change { at: vp(2, 1), width: n(9), placed: text(b"q") };
    assert_eq!(shape(vec![link]), E::NotContentSubspace { change: 0 });
    assert_eq!(shape(vec![change(3, 2, text(b"q")), change(4, 9, text(b"q"))]), E::NotAscending { change: 1 }, "below the reach of the change before, ahead of its bounds");
    assert_eq!(shape(vec![change(3, 2, text(b"q")), change(3, 0, text(b"q"))]), E::NotAscending { change: 1 }, "a site inside the removal before it");
    assert_eq!(shape(vec![change(0, 1, text(b"q"))]), E::NotArranged { change: 0 });
    assert_eq!(shape(vec![change(7, 1, text(b"q"))]), E::NotArranged { change: 0 }, "the append boundary holds nothing to remove");
    assert_eq!(shape(vec![change(6, 2, text(b"q"))]), E::OutOfBounds { change: 0 });
    assert_eq!(shape(vec![change(0, 0, text(b"q"))]), E::OutOfBounds { change: 0 });
    assert_eq!(shape(vec![change(8, 0, Placed::Runs(vec![]))]), E::OutOfBounds { change: 0 }, "the bounds ahead of the empty change");
    assert_eq!(shape(vec![change(2, 0, text(b""))]), E::EmptyResult { change: Some(0) });
    assert_eq!(shape(vec![change(2, 0, Placed::Runs(vec![]))]), E::EmptyResult { change: Some(0) });
    // Changes that touch are apart: the second begins where the first ends.
    let foreign = |start: u32| vec![ShotRun { origin: doc1(), run: run(&pca(start), 1) }];
    let dangling = || vec![ShotRun { origin: pdoc(), run: run(&pca(40), 1) }];
    let unminted = || vec![ShotRun { origin: a(&[1, 0, 1, 0, 71]), run: run(&a(&[1, 0, 1, 0, 71, 0, 1, 1]), 1) }];
    assert_eq!(shape(vec![change(1, 1, text(b"q")), change(2, 9, Placed::Runs(foreign(1)))]), E::OutOfBounds { change: 1 }, "every shape ahead of every run");
    assert_eq!(shape(vec![change(1, 1, Placed::Runs(foreign(1))), change(2, 1, Placed::Runs(dangling()))]), E::BadRun { change: 0 });
    assert_eq!(shape(vec![change(1, 1, text(b"q")), change(2, 1, Placed::Runs(unminted()))]), E::SourceNotRegistered { change: Some(1) });
    assert_eq!(shape(vec![change(1, 1, text(b"q")), change(2, 1, Placed::Runs(dangling()))]), E::DanglingSource { change: 1 });
    assert_eq!(k.current_seq(), moved, "no refusal wrote");
    // Touching changes land: a replacement, then a placement at its reach.
    let landed = vs.edit(P1, &doc1(), plain(vec![change(1, 2, text(b"q")), change(3, 0, text(b"r"))]), now(&k)).expect("touching changes are apart");
    let first = landed.minted.expect("minted");
    assert_eq!(runs_of(&k, &doc1())[0], run(&first, 2), "the two minted bytes side by side, in the request's order");
}

/// The run budget binds what one call places, counted over its changes.
#[test]
fn the_placed_runs_of_a_call_are_held_to_the_run_budget() {
    let k = small();
    // One run more than the budget, no two I-adjacent, in one change.
    let mut content = ContentStore::default();
    let runs: Vec<ShotRun> = (0..=MAX_PLACED_RUNS as u32)
        .map(|j| {
            let addr = a(&[1, 0, 1, 0, nth_doc(3), 0, 1, 1 + 2 * j]);
            let write = stage_write(&content, addr.clone(), Val::new(&b"a"[..])).expect("written once");
            content = content.apply_write(&write);
            ShotRun { origin: pdoc(), run: run(&addr, 1) }
        })
        .collect();
    let world = LandWorld { content, ..k.snapshot().world().clone() };
    let k = mem_kernel_of(world);
    let before = k.current_seq();
    assert_eq!(
        rejected(Vstream::new(&k).edit(P1, &doc1(), plain(vec![change(1, 0, Placed::Runs(runs))]), now(&k))),
        E::TooManyRuns
    );
    assert_eq!(k.current_seq(), before);
}
