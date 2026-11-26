//! The substitution's in-crate claims, in the world the landing's suite
//! assembles (`ops/set_arrangement/tests.rs`: M3, M4 and M5 under the real
//! kernel, its fold counting itself): the one pass leaves a draft exactly as
//! replacing its places one piece at a time does — the run-list, R↾doc span
//! for span, the arranged-at position — on every shape a publication hands
//! in, and refuses what that refuses, at the same entry; the entry that
//! answers is the earliest in the order given, never the lowest by place;
//! the gate answers ahead of every entry; a run put in is judged as
//! REINSTATE judges one; the places are one record whatever they hold; and
//! the check walks the draft's list once however many places it is asked.

use std::sync::Arc;

use skep_address::{shift, Span};
use skep_content::{stage_stretch, ContentStore};
use skep_kernel::{Kernel, Seq};
use skep_namespace::M3State;

use super::super::set_arrangement::tests::{Folds, LandWorld, P1};
use super::*;
use crate::error::{DeleteError, ReinstateError, SubstituteError as E};
use crate::ops::{stage_delete_at, stage_reinstate_at, AsOf};
use crate::run_list::RunList;
use crate::shot::ShotRun;
use crate::state::M5State;
use crate::testutil::{a, ca, doc1, doc2, la, mem_kernel_of, n, nth_doc, pca, pdoc, run, seeded_m3, vp};
use crate::vspace::ordinal_vspan;

/// The work the body may ask for each run of the draft, each piece and each
/// entry: the bound on its own steps.
const WORK_PER_UNIT: u64 = 2;

/// Returns doc2's content element at `ordinal`.
fn ca2(ordinal: u32) -> Address {
    a(&[1, 0, 1, 0, nth_doc(2), 0, 1, ordinal])
}

/// A world whose edition `pdoc` stores `stored` one-byte values at its
/// first addresses and arranges them, and whose other documents arrange the
/// runs given, each list built by one fold.
fn world(drafts: &[(Address, Vec<Run>)], stored: u32) -> Kernel<LandWorld> {
    let stretch = stage_stretch(&ContentStore::default(), pca(1), Arc::from(vec![b'p'; stored as usize])).expect("stored once");
    let content = ContentStore::default().apply_stretch(&stretch);
    let mut m5 = M5State::genesis().apply_m5(Seq(0), &M5Rec::ContentPlace { doc: pdoc(), at: n(1), runs: vec![run(&pca(1), stored)] });
    for (doc, runs) in drafts {
        m5 = m5.apply_m5(Seq(0), &M5Rec::ContentPlace { doc: doc.clone(), at: n(1), runs: runs.clone() });
    }
    mem_kernel_of(LandWorld { m3: seeded_m3(), content, m5 })
}

fn piece(from: Run, to: Run) -> Replacement {
    Replacement { from, to }
}

fn entry(index: usize, at: u32, pieces: Vec<Replacement>) -> Substitution {
    Substitution { index, at: vp(1, at), pieces: Some(pieces) }
}

/// Whether `doc` arranges exactly `pieces`, in sequence, over the positions
/// that open at `at`, each place resolved from the head of the list: the
/// check the re-window made before the one walk, kept here to judge it by.
fn arranged_at<'r>(m5: &M5State, doc: &Address, at: &VPos, pieces: impl IntoIterator<Item = &'r Run>) -> bool {
    let pieces: Vec<&Run> = pieces.into_iter().collect();
    let width: Nat = pieces.iter().map(|piece| piece.width().clone()).sum();
    let Some(span) = ordinal_vspan(at.clone(), width) else { return false };
    let zero = n(0);
    let (mut k, mut offset) = (0usize, zero.clone());
    for resolved in m5.iter_resolve(doc, &span) {
        let mut cursor = resolved.i_start().tumbler().clone();
        let mut left = resolved.width().clone();
        while left > zero {
            let Some(piece) = pieces.get(k) else { return false };
            if shift(piece.i_start().tumbler(), &offset) != cursor {
                return false;
            }
            let room = piece.width() - &offset;
            let step = if left < room { left.clone() } else { room };
            cursor = shift(&cursor, &step);
            offset += &step;
            left -= &step;
            if offset == *piece.width() {
                k += 1;
                offset = zero.clone();
            }
        }
    }
    k == pieces.len()
}

/// The places replaced one piece at a time, as the re-window staged them
/// before the one pass: per entry in the order given its place, its pieces
/// and the check against the working world; then per piece the `to` run
/// placed at its offset and the `from` run removed behind it, two records.
/// A refusal is spelled as the one pass spells that verdict.
fn piece_by_piece(stg: &mut Staging<LandWorld>, doc: &Address, entries: &[Substitution]) -> Result<(), E> {
    let placing = |e: ReinstateError, index: usize| match e {
        ReinstateError::DocNotRegistered => E::DocNotRegistered,
        ReinstateError::NotOwner(doc) => E::NotOwner(doc),
        ReinstateError::PublishedTarget => E::PublishedTarget,
        ReinstateError::BadRun => E::BadRun { index },
        ReinstateError::SourceNotRegistered => E::SourceNotRegistered { index },
        ReinstateError::DanglingSource => E::DanglingSource { index },
        other => panic!("the check rules out {other:?}"),
    };
    for entry in entries {
        let index = entry.index;
        if !entry.at.is_content() {
            return Err(E::NotContentSubspace { index });
        }
        let Some(pieces) = &entry.pieces else { return Err(E::Unrecorded { index }) };
        if !arranged_at(stg.working().m5(), doc, &entry.at, pieces.iter().map(|piece| &piece.from)) {
            return Err(E::Moved { index });
        }
        let mut offset = n(0);
        for piece in pieces {
            let at = VPos::content(&entry.at.ordinal + &offset);
            // The stated origin is the document the run's own start settles,
            // so the statement never disagrees with it.
            let origin = run_origin_document(&piece.to).unwrap_or_else(pdoc);
            let fresh = ShotRun { origin, run: piece.to.clone() };
            stage_reinstate_at(stg, P1, doc, at.clone(), &[fresh], AsOf::Unchecked).map_err(|e| placing(e, index))?;
            let moved = VPos::content(&at.ordinal + piece.to.width());
            if !arranged_at(stg.working().m5(), doc, &moved, [&piece.from]) {
                return Err(E::Moved { index });
            }
            stage_delete_at(stg, P1, doc, moved, piece.from.width().clone(), AsOf::Unchecked).map_err(|e: DeleteError| panic!("the placement rules out {e:?}"))?;
            offset += piece.from.width();
        }
    }
    Ok(())
}

/// What a path left of one document: its run-list, R↾doc span for span in
/// the order appended, and whether its arranged-at position is the commit's.
#[derive(Debug, Clone, PartialEq)]
struct Left {
    list: RunList,
    spans: Vec<Span>,
    moved_at_the_commit: bool,
}

fn spans_of(k: &Kernel<LandWorld>, doc: &Address) -> Vec<Span> {
    k.snapshot().world().m5().provenance.ever_contained(doc).iter().cloned().collect()
}

/// Runs `calls` — each a document and the entries substituted in it — in
/// one transaction, by the one pass where `one_pass` and one piece at a
/// time where not, over a fresh `world`: what each document was left as, or
/// the refusal, which has committed nothing.
fn landed(world: &dyn Fn() -> Kernel<LandWorld>, calls: &[(Address, Vec<Substitution>)], one_pass: bool) -> Result<Vec<Left>, E> {
    let k = world();
    let before = k.current_seq();
    let lists_before: Vec<RunList> = calls.iter().map(|(doc, _)| k.snapshot().world().m5().content_list(doc).clone()).collect();
    let keys: Vec<_> = {
        let mut keys: Vec<_> = calls.iter().map(|(doc, _)| M3State::content_lock_key(doc)).collect();
        keys.sort();
        keys.dedup();
        keys
    };
    let outcome = k.transact(&keys, |stg| {
        for (doc, entries) in calls {
            if one_pass {
                stage_substitute(stg, P1, doc, entries, &mut |_| {})?;
            } else {
                piece_by_piece(stg, doc, entries)?;
            }
        }
        Ok::<(), E>(())
    });
    match outcome {
        Ok(((), seq)) => Ok(calls
            .iter()
            .map(|(doc, _)| {
                let s = k.snapshot();
                let m5 = s.world().m5();
                Left { list: m5.content_list(doc).clone(), spans: spans_of(&k, doc), moved_at_the_commit: m5.arranged_at(doc) == Some(seq) }
            })
            .collect()),
        Err(refused) => {
            assert_eq!(k.current_seq(), before, "a refusal commits nothing");
            for ((doc, _), list) in calls.iter().zip(&lists_before) {
                assert_eq!(k.snapshot().world().m5().content_list(doc), list, "a refusal leaves the draft as it stood");
            }
            Err(crate::testutil::rejected(Err::<(), _>(refused)))
        }
    }
}

/// Whether two span lists hold the same spans, each as often, in any order.
fn same_spans(one: &[Span], other: &[Span]) -> bool {
    let mut rest: Vec<&Span> = other.iter().collect();
    one.len() == other.len() && one.iter().all(|span| rest.iter().position(|held| *held == span).map(|at| rest.swap_remove(at)).is_some())
}

/// Lands `calls` both ways and holds the one pass to the other: the
/// run-list exactly, R↾doc the same spans — in the same order where
/// `in_place_order`, the entries standing in the order of their places —
/// and the arranged-at position the commit's own on both. Returns what the
/// one pass left, beside what the other left.
fn both(world: &dyn Fn() -> Kernel<LandWorld>, calls: &[(Address, Vec<Substitution>)], in_place_order: bool) -> (Vec<Left>, Vec<Left>) {
    let one = landed(world, calls, true).expect("the one pass lands");
    let other = landed(world, calls, false).expect("piece by piece lands");
    for (k, (one, other)) in one.iter().zip(&other).enumerate() {
        assert_eq!(one.list, other.list, "document {k}: the run-list, exactly");
        assert!(same_spans(&one.spans, &other.spans), "document {k}: R gains the same spans: {:?} against {:?}", one.spans, other.spans);
        if in_place_order {
            assert_eq!(one.spans, other.spans, "document {k}: and in the same order");
        }
        assert!(one.moved_at_the_commit && other.moved_at_the_commit, "document {k}: arranged-at is the commit's position");
    }
    (one, other)
}

/// Holds both ways to one refusal.
fn both_refuse(world: &dyn Fn() -> Kernel<LandWorld>, calls: &[(Address, Vec<Substitution>)], refusal: E) {
    assert_eq!(landed(world, calls, true), Err(refusal.clone()), "the one pass");
    assert_eq!(landed(world, calls, false), Err(refusal), "piece by piece");
}

fn list_of(left: &Left) -> Vec<Run> {
    left.list.iter().cloned().collect()
}

/// ONE PASS LEAVES WHAT PIECE BY PIECE LEAVES. On each shape a publication
/// hands in: a run the draft holds twice, re-windowed at the named place
/// and left standing at the other; a place inside a run; a run of several
/// pieces whose published runs are I-adjacent, which the list holds as one
/// run and R as a span a piece; a place holding another draft's words,
/// re-windowed through two records' pieces; two drafts, each re-windowed at
/// its own place by the same pieces; and two lists naming one document,
/// the one run at each of the two places the draft holds it.
#[test]
fn one_pass_leaves_the_draft_as_piece_by_piece_does() {
    // A run held twice, the second occurrence named.
    let twice = || world(&[(doc1(), vec![run(&ca(1), 2), run(&ca(5), 1), run(&ca(1), 2)])], 8);
    let (one, _) = both(&twice, &[(doc1(), vec![entry(0, 4, vec![piece(run(&ca(1), 2), run(&pca(1), 2))])])], true);
    assert_eq!(list_of(&one[0]), vec![run(&ca(1), 2), run(&ca(5), 1), run(&pca(1), 2)], "the named place alone");

    // A place inside a run.
    let inside = || world(&[(doc1(), vec![run(&ca(1), 5)])], 8);
    let (one, _) = both(&inside, &[(doc1(), vec![entry(0, 2, vec![piece(run(&ca(2), 2), run(&pca(1), 2))])])], true);
    assert_eq!(list_of(&one[0]), vec![run(&ca(1), 1), run(&pca(1), 2), run(&ca(4), 2)]);

    // A run of two pieces whose published runs are I-adjacent: one run of
    // the list, two spans of R.
    let pieces = || world(&[(doc1(), vec![run(&ca(1), 1), run(&ca(7), 2), run(&ca(3), 1)])], 8);
    let before = spans_of(&pieces(), &doc1()).len();
    let adjacent = vec![piece(run(&ca(7), 1), run(&pca(1), 1)), piece(run(&ca(8), 1), run(&pca(2), 1))];
    let (one, other) = both(&pieces, &[(doc1(), vec![entry(0, 2, adjacent)])], true);
    assert_eq!(list_of(&one[0]), vec![run(&ca(1), 1), run(&pca(1), 2), run(&ca(3), 1)], "the list holds the two as one run");
    assert_eq!(one[0].spans[before..], [run(&pca(1), 1).iextent(), run(&pca(2), 1).iextent()], "R gains a span a piece");
    assert_eq!(other[0].spans.len(), before + 2);

    // Another draft's words held by transclusion, through two records.
    let stray = || world(&[(doc1(), vec![run(&ca(1), 1), run(&ca2(1), 3)])], 8);
    let recorded = vec![piece(run(&ca2(1), 2), run(&pca(1), 2)), piece(run(&ca2(3), 1), run(&pca(5), 1))];
    let (one, _) = both(&stray, &[(doc1(), vec![entry(0, 2, recorded)])], true);
    assert_eq!(list_of(&one[0]), vec![run(&ca(1), 1), run(&pca(1), 2), run(&pca(5), 1)]);

    // Two drafts, each at its own place of the same pieces.
    let family = || world(&[(doc1(), vec![run(&ca(1), 1), run(&ca2(1), 2)]), (doc2(), vec![run(&ca2(1), 2), run(&ca2(9), 1)])], 8);
    let same = |at: u32| vec![entry(0, at, vec![piece(run(&ca2(1), 2), run(&pca(1), 2))])];
    let (one, _) = both(&family, &[(doc1(), same(2)), (doc2(), same(1))], true);
    assert_eq!(list_of(&one[0]), vec![run(&ca(1), 1), run(&pca(1), 2)]);
    assert_eq!(list_of(&one[1]), vec![run(&pca(1), 2), run(&ca2(9), 1)]);

    // Two lists naming one document: one entry at each place.
    let lists = vec![entry(0, 1, vec![piece(run(&ca(1), 2), run(&pca(1), 2))]), entry(0, 4, vec![piece(run(&ca(1), 2), run(&pca(1), 2))])];
    let (one, _) = both(&twice, &[(doc1(), lists)], true);
    assert_eq!(list_of(&one[0]), vec![run(&pca(1), 2), run(&ca(5), 1), run(&pca(1), 2)]);
}

/// THE ORDER OF R's SPANS. Where the entries do not stand in the order of
/// their places, both ways leave one run-list and R the same spans; the one
/// pass appends them by place, as its record lists its changes, and piece
/// by piece appends them in the order given.
#[test]
fn the_spans_are_appended_by_place_where_piece_by_piece_appends_them_in_the_order_given() {
    let draft = || world(&[(doc1(), vec![run(&ca(1), 2), run(&ca(5), 2)])], 8);
    let before = spans_of(&draft(), &doc1()).len();
    let entries = vec![entry(0, 3, vec![piece(run(&ca(5), 2), run(&pca(1), 2))]), entry(1, 1, vec![piece(run(&ca(1), 2), run(&pca(3), 2))])];
    let (one, other) = both(&draft, &[(doc1(), entries)], false);
    assert_eq!(list_of(&one[0]), vec![run(&pca(3), 2), run(&pca(1), 2)]);
    let (first, second) = (run(&pca(1), 2).iextent(), run(&pca(3), 2).iextent());
    assert_eq!(one[0].spans[before..], [second.clone(), first.clone()], "the one pass: by place");
    assert_eq!(other[0].spans[before..], [first, second], "piece by piece: in the order given");
}

/// REFUSED ALIKE. Two places that overlap refuse the later entry; a place
/// the draft does not hold its runs at, an entry with no pieces and a place
/// outside the content subspace each refuse their entry — by the one pass
/// as piece by piece, with nothing committed.
#[test]
fn a_refused_entry_is_refused_alike_by_one_pass_and_piece_by_piece() {
    let draft = || world(&[(doc1(), vec![run(&ca(1), 4)])], 8);
    let at = |index: usize, at: u32, from: u32, to: u32| entry(index, at, vec![piece(run(&ca(from), 2), run(&pca(to), 2))]);
    // Two places that overlap: positions 1–2 and 2–3.
    both_refuse(&draft, &[(doc1(), vec![at(0, 1, 1, 1), at(1, 2, 2, 5)])], E::Moved { index: 1 });
    // The draft holds other runs at the place; the place reaches past the
    // draft's end; the place is ordinal 0.
    both_refuse(&draft, &[(doc1(), vec![at(4, 2, 1, 1)])], E::Moved { index: 4 });
    both_refuse(&draft, &[(doc1(), vec![at(4, 4, 4, 1)])], E::Moved { index: 4 });
    both_refuse(&draft, &[(doc1(), vec![at(4, 0, 1, 1)])], E::Moved { index: 4 });
    // No piece is no arrangement.
    both_refuse(&draft, &[(doc1(), vec![entry(2, 1, vec![])])], E::Moved { index: 2 });
    both_refuse(&draft, &[(doc1(), vec![Substitution { index: 3, at: vp(1, 1), pieces: None }])], E::Unrecorded { index: 3 });
    both_refuse(&draft, &[(doc1(), vec![Substitution { index: 5, at: vp(2, 1), pieces: None }])], E::NotContentSubspace { index: 5 });
}

/// THE EARLIEST ENTRY ANSWERS. A first entry the draft does not hold at its
/// place answers `Moved` naming it, whatever stands after it and wherever:
/// an entry with no pieces at a lower place, an entry overlapping its
/// place, and a second moved entry at a lower place, which the walk meets
/// first.
#[test]
fn the_earliest_entry_in_the_order_given_answers_never_the_lowest_place() {
    let draft = || world(&[(doc1(), vec![run(&ca(1), 8)])], 8);
    // The first entry asks position 5 for a run the draft holds at 1.
    let moved_first = || entry(0, 5, vec![piece(run(&ca(1), 2), run(&pca(1), 2))]);
    let unrecorded = Substitution { index: 1, at: vp(1, 1), pieces: None };
    both_refuse(&draft, &[(doc1(), vec![moved_first(), unrecorded])], E::Moved { index: 0 });
    let overlapping = entry(1, 6, vec![piece(run(&ca(6), 2), run(&pca(3), 2))]);
    both_refuse(&draft, &[(doc1(), vec![moved_first(), overlapping])], E::Moved { index: 0 });
    let moved_lower = entry(1, 1, vec![piece(run(&ca(3), 2), run(&pca(3), 2))]);
    both_refuse(&draft, &[(doc1(), vec![moved_first(), moved_lower])], E::Moved { index: 0 });
    // And an entry that holds, ahead of one that does not, leaves the later
    // one to answer.
    let holds = entry(0, 7, vec![piece(run(&ca(7), 2), run(&pca(1), 2))]);
    let moved_later = entry(1, 1, vec![piece(run(&ca(3), 2), run(&pca(3), 2))]);
    both_refuse(&draft, &[(doc1(), vec![holds, moved_later])], E::Moved { index: 1 });
}

/// THE GATE FIRST. A published document answers `PublishedTarget` whatever
/// its entries hold, a moved one among them; a document the caller does not
/// own and one never registered answer theirs. Piece by piece met the gate
/// at its first placement, behind the first entry's check, and so answered
/// the moved entry: the one refusal the two ways tell apart.
#[test]
fn the_gate_answers_ahead_of_every_entry() {
    let editions = || world(&[], 8);
    let moved = vec![entry(0, 5, vec![piece(run(&pca(1), 2), run(&pca(3), 2))])];
    assert_eq!(landed(&editions, &[(pdoc(), moved.clone())], true), Err(E::PublishedTarget), "the gate, ahead of the entry");
    assert_eq!(landed(&editions, &[(pdoc(), moved.clone())], false), Err(E::Moved { index: 0 }), "piece by piece: the entry's check came first");
    let held = vec![entry(0, 1, vec![piece(run(&pca(1), 2), run(&pca(3), 2))])];
    both_refuse(&editions, &[(pdoc(), held)], E::PublishedTarget);
    // Another principal's draft, and an address no mint made.
    let foreign = a(&[1, 0, 2, 0, 1]);
    let k = world(&[], 8);
    let refused = k.transact(&[M3State::content_lock_key(&foreign)], |stg| stage_substitute(stg, P1, &foreign, &moved, &mut |_| {}));
    assert_eq!(crate::testutil::rejected(refused), E::DocNotRegistered);
    let k = mem_kernel_of(LandWorld {
        m3: seeded_m3().apply_m3(Seq(0), &skep_namespace::M3Rec::allocate(foreign.clone(), false)),
        content: ContentStore::default(),
        m5: M5State::genesis(),
    });
    let refused = k.transact(&[M3State::content_lock_key(&foreign)], |stg| stage_substitute(stg, P1, &foreign, &moved, &mut |_| {}));
    assert_eq!(crate::testutil::rejected(refused), E::NotOwner(foreign));
}

/// A RUN PUT IN IS JUDGED AS REINSTATE JUDGES ONE: a start that is no
/// content element, a document no mint made, an address holding no value —
/// each behind its own entry's check and ahead of every later entry's, by
/// the one pass as piece by piece.
#[test]
fn a_run_put_in_is_judged_behind_its_entrys_check_and_ahead_of_the_next_entry() {
    let draft = || world(&[(doc1(), vec![run(&ca(1), 8)])], 4);
    let putting = |index: usize, at: u32, to: Run| entry(index, at, vec![piece(run(&ca(at), 1), to)]);
    both_refuse(&draft, &[(doc1(), vec![putting(0, 1, run(&la(1), 1))])], E::BadRun { index: 0 });
    let unminted = a(&[1, 0, 1, 0, nth_doc(9), 0, 1, 1]);
    both_refuse(&draft, &[(doc1(), vec![putting(0, 1, run(&unminted, 1))])], E::SourceNotRegistered { index: 0 });
    both_refuse(&draft, &[(doc1(), vec![putting(0, 1, run(&pca(5), 1))])], E::DanglingSource { index: 0 });
    // A dangling run of the first entry, ahead of a moved second entry —
    // and behind a moved first one.
    let moved = |index: usize| entry(index, 3, vec![piece(run(&ca(7), 1), run(&pca(1), 1))]);
    both_refuse(&draft, &[(doc1(), vec![putting(0, 1, run(&pca(5), 1)), moved(1)])], E::DanglingSource { index: 0 });
    both_refuse(&draft, &[(doc1(), vec![moved(0), putting(1, 1, run(&pca(5), 1))])], E::Moved { index: 0 });
}

/// ONE RECORD, WHATEVER THE PLACES HOLD. `pieces` pieces over as many
/// places stage one record, where piece by piece stages two a piece; the
/// draft's list is rebuilt once for it, and once more at the seal where the
/// transaction holds a second record. No entry stages nothing.
#[test]
fn the_places_are_one_record_whatever_they_hold() {
    const RUNS: u32 = 4_167;
    let fragmented = || world(&[(doc1(), (0..RUNS).map(|j| run(&ca(1 + 4 * j), 3)).collect()), (doc2(), vec![run(&ca2(1), 3)])], 3 * RUNS);
    // Entry `j` replaces the whole of run `j`, three positions.
    let entries = |pieces: u32| -> Vec<Substitution> { (0..pieces).map(|j| entry(j as usize, 3 * j + 1, vec![piece(run(&ca(1 + 4 * j), 3), run(&pca(3 * j + 1), 3))])).collect() };
    for pieces in [1u32, 16, 1_613] {
        let k = fragmented();
        let (before, _) = (k.current_seq(), Folds::take());
        k.transact(&[M3State::content_lock_key(&doc1())], |stg| stage_substitute(stg, P1, &doc1(), &entries(pieces), &mut |_| {})).expect("the places land");
        assert_eq!(k.current_seq().0 - before.0, 1, "{pieces} pieces: one record");
        assert_eq!(Folds::take(), (1, 1), "{pieces} pieces: the list rebuilt once, at the push");
        // The published runs are I-adjacent place to place: one run.
        assert_eq!(k.snapshot().world().m5().content_run_count(&doc1()), (RUNS - pieces + 1) as usize);

        // Beside a second draft's record: two records, each folded again at
        // the seal, so each draft's list is rebuilt twice.
        let k = fragmented();
        let (before, _) = (k.current_seq(), Folds::take());
        let other = vec![entry(0, 1, vec![piece(run(&ca2(1), 3), run(&pca(1), 3))])];
        let mut keys = vec![M3State::content_lock_key(&doc1()), M3State::content_lock_key(&doc2())];
        keys.sort();
        k.transact(&keys, |stg| {
            stage_substitute(stg, P1, &doc1(), &entries(pieces), &mut |_| {})?;
            stage_substitute(stg, P1, &doc2(), &other, &mut |_| {})
        })
        .expect("both drafts land");
        assert_eq!(k.current_seq().0 - before.0, 2, "{pieces} pieces: a record a draft");
        assert_eq!(Folds::take(), (4, 4), "{pieces} pieces: each record folded at its push and at the seal");

        // Piece by piece: two records a piece.
        let k = fragmented();
        let before = k.current_seq();
        k.transact(&[M3State::content_lock_key(&doc1())], |stg| piece_by_piece(stg, &doc1(), &entries(pieces.min(16)))).expect("piece by piece lands");
        assert_eq!(k.current_seq().0 - before.0, 2 * u64::from(pieces.min(16)));
    }
    let k = fragmented();
    let before = k.current_seq();
    k.transact(&[M3State::content_lock_key(&doc1())], |stg| stage_substitute(stg, P1, &doc1(), &[], &mut |_| {})).expect("no entry is no refusal");
    assert_eq!(k.current_seq(), before, "no entry stages nothing");
}

/// ONE WALK, COUNTED. `entries` places spread over a draft of 65,536 runs,
/// two pieces each: the body's own steps are each run the walk reads, each
/// entry twice and each piece twice — within the bound whatever the places
/// number, held as the count grows, so a place checked from the head of
/// the list stops the call at once.
#[test]
fn the_check_walks_the_draft_once_however_many_places_it_is_asked() {
    const RUNS: u32 = 65_536;
    for entries in [1u32, 16, 256, 4_096] {
        let k = world(&[(doc1(), (0..RUNS).map(|j| run(&ca(1 + 4 * j), 3)).collect())], 3 * entries);
        // Entry `j` replaces the whole of run `at_run(j)`, as a piece of one
        // position and a piece of two.
        let at_run = |j: u32| ((2 * u64::from(j) + 1) * u64::from(RUNS) / (2 * u64::from(entries))) as u32;
        let asked: Vec<Substitution> = (0..entries)
            .map(|j| {
                let (from, to) = (1 + 4 * at_run(j), 1 + 3 * j);
                entry(j as usize, 3 * at_run(j) + 1, vec![piece(run(&ca(from), 1), run(&pca(to), 1)), piece(run(&ca(from + 1), 2), run(&pca(to + 1), 2))])
            })
            .collect();
        let pieces = 2 * entries;
        let budget = WORK_PER_UNIT * u64::from(RUNS + pieces + entries);
        let mut own = 0u64;
        k.transact(&[M3State::content_lock_key(&doc1())], |stg| {
            stage_substitute(stg, P1, &doc1(), &asked, &mut |steps| {
                own += steps;
                assert!(own <= budget, "{entries} entries: the body's own steps passed {budget}");
            })
        })
        .expect("the places land");
        // The walk stops with the last place: it reads the runs up to it.
        let read = u64::from(at_run(entries - 1) + 1);
        assert_eq!(own, read + 2 * u64::from(entries) + 2 * u64::from(pieces), "{entries} entries: each run read once, each entry judged and walked, each piece compared and probed");
        assert!(own >= u64::from(entries + pieces), "a walk that charges nothing proves nothing");
        assert_eq!(k.snapshot().world().m5().content_run_count(&doc1()), RUNS as usize, "a run replaced by one run");
    }
}

/// A PIECE OF TWO WIDTHS moves what stands after its place by the
/// difference, the places being positions of the draft as it stood: the
/// second place is found where it was, and its runs land behind the wider
/// run put in at the first.
#[test]
fn a_piece_whose_two_runs_differ_in_width_moves_the_positions_after_it() {
    let k = world(&[(doc1(), vec![run(&ca(1), 6)])], 8);
    let entries = vec![entry(0, 1, vec![piece(run(&ca(1), 2), run(&pca(1), 3))]), entry(1, 5, vec![piece(run(&ca(5), 2), run(&pca(6), 1))])];
    k.transact(&[M3State::content_lock_key(&doc1())], |stg| stage_substitute(stg, P1, &doc1(), &entries, &mut |_| {})).expect("the places land");
    let left: Vec<Run> = k.snapshot().world().m5().content_runs(&doc1()).cloned().collect();
    assert_eq!(left, vec![run(&pca(1), 3), run(&ca(3), 2), run(&pca(6), 1)]);
}

/// THE ONE INPUT THE TWO WAYS TELL APART. A later entry whose runs to find
/// are the runs an earlier entry puts in, at the same place: made one at a
/// time the second finds the first's replacement standing and replaces it
/// in turn; the one pass judges every place against the draft as it stood,
/// and refuses the later entry for overlapping the earlier.
#[test]
fn a_later_entry_asking_for_what_an_earlier_one_put_in_is_refused_where_piece_by_piece_chains() {
    let draft = || world(&[(doc1(), vec![run(&ca2(1), 2)])], 8);
    let chained = vec![entry(0, 1, vec![piece(run(&ca2(1), 2), run(&pca(1), 2))]), entry(1, 1, vec![piece(run(&pca(1), 2), run(&pca(3), 2))])];
    assert_eq!(landed(&draft, &[(doc1(), chained.clone())], true), Err(E::Moved { index: 1 }));
    let made = landed(&draft, &[(doc1(), chained)], false).expect("piece by piece lands both");
    assert_eq!(list_of(&made[0]), vec![run(&pca(3), 2)]);
}
