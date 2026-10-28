//! The shot's refusals and its source gate, in `publish`'s stated check
//! order.

use std::cell::RefCell;

use skep_address::{Address, Nat};
use skep_arrangement::{
    reading_surface, shot_admission, trunk_head, Base, Caller, Deposit, HasM5, PublishError, Run,
    Shot, ShotRun, Vstream, MAX_REINSERTED_VALUES,
};
use skep_content::{HasContent, Val};
use skep_kernel::{Kernel, TxnError};
use skep_namespace::{HasM3, Namespace, PrincipalId};

use crate::common::*;

/// A consult that reads `allowed` alone — the world it is handed plays no
/// part — and records every origin it is asked about, in order: what "each
/// origin once, in run order, and never before ω" is asserted over.
fn recording_consult<'a>(
    asked: &'a RefCell<Vec<Address>>,
    allowed: Vec<Address>,
) -> impl Fn(&World, &Address) -> bool + 'a {
    move |_world: &World, origin: &Address| {
        asked.borrow_mut().push(origin.clone());
        allowed.contains(origin)
    }
}

/// The refusal `shot_admission` and `publish` both give one shot at or before
/// the source gate, or `None` where both carry it past: the shot is asked of
/// `shot_admission`, on the world `publish` then opens on, and then of
/// `publish`, under one consult. Where `at_the_gate`, both refuse it alike and
/// that refusal is handed back; where not, the admission passes it and
/// `publish` commits it or refuses it past its gate. Any other pair is the two
/// disagreeing, and panics.
fn agreed_refusal(
    k: &Kernel<World>,
    caller: Caller,
    doc: &Address,
    shot: &Shot,
    consult: &dyn Fn(&World, &Address) -> bool,
    at_the_gate: bool,
) -> Option<PublishError> {
    let admission = shot_admission(k.snapshot().world(), caller, doc, shot, consult);
    let published = Vstream::new(k).publish(caller, doc, shot, consult);
    match (admission, published) {
        (Err(asked), Err(TxnError::Rejected(answered))) if at_the_gate => {
            assert_eq!(asked, answered, "{doc:?}");
            Some(asked)
        }
        (Ok(()), Ok(_)) if !at_the_gate => None,
        (
            Ok(()),
            Err(TxnError::Rejected(
                PublishError::TooManyValues
                | PublishError::DanglingSource
                | PublishError::TooManyRuns,
            )),
        ) if !at_the_gate => None,
        other => panic!("{doc:?}: the admission and `publish` disagree: {other:?}"),
    }
}

#[test]
fn the_source_gate_runs_after_ownership_and_before_any_existence_answer() {
    // PUB-8.1's second constraint, PUB-6.36's order, PUB-6.24's carried cell:
    // the consult is asked per DISTINCT origin, in run order, of exactly the
    // origins the base does not already arrange and the document does not
    // own; the FIRST unreadable one answers `Withheld` — ahead of a dangling
    // run's `DanglingSource` — and `NotOwner` stands ahead of the consult.
    let k = mem_kernel();
    let vs = deposit_abc(&k);
    // Two foreign private documents: doc2 (P1's draft) and the sub-account's
    // document, owned by principal 3.
    vs.insert(P1, &doc2(), vp(1, 1), vec![val(b"w"), val(b"x")], Deposit::Undeclared).expect("doc2");
    let sub = Caller::Principal(PrincipalId(3));
    let subdoc = a(&[1, 0, 1, 1, 0, 1]);
    vs.insert(sub, &subdoc, vp(1, 1), vec![val(b"s")], Deposit::Undeclared).expect("subdoc");
    let w = a(&[1, 0, 1, 0, 2, 0, 1, 1]);
    let sca = a(&[1, 0, 1, 1, 0, 1, 0, 1, 1]);
    // Every origin a consult is asked about, in the order asked.
    let asked: RefCell<Vec<Address>> = RefCell::new(Vec::new());
    // (1) not_owner first: principal 2 shooting P1's edition, with a run
    //     onto an origin it may not read — the consult is never asked.
    let refusing = recording_consult(&asked, vec![]);
    assert!(matches!(
        rejected(vs.publish(
            Caller::Principal(PrincipalId(2)),
            &pdoc(),
            &Shot { base: None, draft: None, runs: vec![shot_run(&subdoc, &sca, 1)] },
            &refusing
        )),
        PublishError::NotOwner(d) if d == pdoc()
    ));
    assert!(asked.borrow().is_empty(), "no consult before ω");
    // (2) the first unreadable origin speaks, in run order, and a DANGLING
    //     run onto an unreadable origin answers withheld, never dangling —
    //     even listed behind a readable window.
    let dangling = a(&[1, 0, 1, 1, 0, 1, 0, 1, 9]);
    let refusing_subdoc = recording_consult(&asked, vec![doc2()]);
    assert!(matches!(
        rejected(vs.publish(
            P1,
            &pdoc(),
            &Shot {
                base: None,
                draft: None,
                runs: vec![
                    shot_run(&pdoc(), &pca(1), 3),
                    shot_run(&doc2(), &w, 1),
                    shot_run(&subdoc, &dangling, 1),
                    shot_run(&doc2(), &w, 1),
                ],
            },
            &refusing_subdoc
        )),
        PublishError::Withheld(d) if d == subdoc
    ));
    assert_eq!(
        asked.borrow().as_slice(),
        &[doc2(), subdoc.clone()],
        "the document's own space is not consulted, and the unreadable origin is refused before its dangling run is probed"
    );
    // (3) readable origins are placed; and an origin the BASE already
    //     arranges is NOT consulted again on the next shot.
    asked.borrow_mut().clear();
    let admitting = recording_consult(&asked, vec![doc2(), subdoc.clone()]);
    let (member1, _) = vs
        .publish(
            P1,
            &pdoc(),
            &Shot {
                base: None,
                draft: None,
                runs: vec![shot_run(&pdoc(), &pca(1), 3), shot_run(&doc2(), &w, 2), shot_run(&subdoc, &sca, 1)],
            },
            &admitting,
        )
        .expect("readable windows are placed");
    assert_eq!(asked.borrow().as_slice(), &[doc2(), subdoc.clone()]);
    assert_eq!(k.snapshot().world().m5().content_count(&member1), n(6));
    asked.borrow_mut().clear();
    // The next shot re-supplies the doc2 window and the subdoc run exactly
    // as member1 arranges them: both are CARRIED (PUB-6.24), and a consult
    // that would now refuse doc2 is never asked.
    let refusing_doc2 = recording_consult(&asked, vec![subdoc.clone()]);
    let (member2, _) = vs
        .publish(
            P1,
            &pdoc(),
            &Shot {
                base: Some(base(&member1, 6)),
                draft: None,
                runs: vec![shot_run(&pdoc(), &pca(1), 3), shot_run(&doc2(), &w, 2), shot_run(&subdoc, &sca, 1)],
            },
            &refusing_doc2,
        )
        .expect("carried runs need no consult");
    assert_eq!(asked.borrow().as_slice(), &[] as &[Address], "every run was carried by the base");
    assert_eq!(member2, a(&[1, 0, 1, 0, 3, 2]));
    // (4) existence, behind the gate: a readable origin's non-existent
    //     address answers dangling.
    assert!(matches!(
        rejected(vs.publish(
            P1,
            &pdoc(),
            &Shot { base: Some(base(&member2, 6)), draft: None, runs: vec![shot_run(&pdoc(), &pca(9), 1)] },
            &refusing_doc2
        )),
        PublishError::DanglingSource
    ));
    // (5) the base's shape speaks ahead of the gate: an extent past what the
    //     pinned member1 holds, beside a run member1 does not carry onto an
    //     origin the consult would refuse. The run is not carried, so the
    //     gate would ask about it — and it is never asked.
    asked.borrow_mut().clear();
    assert!(matches!(
        rejected(vs.publish(
            P1,
            &pdoc(),
            &Shot { base: Some(base(&member1, 99)), draft: None, runs: vec![shot_run(&subdoc, &dangling, 1)] },
            &refusing
        )),
        PublishError::BaseExtentTooLarge
    ));
    assert!(asked.borrow().is_empty(), "no consult before the base's shape is settled");
}

#[test]
fn the_consult_is_asked_once_per_origin_in_run_order_and_stops_at_the_first_refusal() {
    // PUB-6.23 as `publish` states it: `readable` is asked PER DISTINCT
    // ORIGIN DOCUMENT, in RUN order, the FIRST refusal answering — and never
    // about the document's own I-space, whichever chain address names the
    // shot (PUB-2.15). Each clause is given an input on which its negation
    // answers differently: two origins listed against their address order,
    // both refused; one origin windowed three times around another; and a
    // shot named by a member whose runs are the edition's own.
    let k = mem_kernel();
    let vs = deposit_abc(&k);
    vs.insert(P1, &doc2(), vp(1, 1), vec![val(b"w"), val(b"x")], Deposit::Undeclared).expect("doc2");
    let sub = Caller::Principal(PrincipalId(3));
    let subdoc = a(&[1, 0, 1, 1, 0, 1]);
    vs.insert(sub, &subdoc, vp(1, 1), vec![val(b"s")], Deposit::Undeclared).expect("subdoc");
    let w = a(&[1, 0, 1, 0, 2, 0, 1, 1]);
    let sca = a(&[1, 0, 1, 1, 0, 1, 0, 1, 1]);
    assert!(doc2() < subdoc, "the address order the run orders below reverse");
    let asked: RefCell<Vec<Address>> = RefCell::new(Vec::new());
    // Run order, and the stop: subdoc is listed first and both are refused,
    // so subdoc speaks and doc2 is never asked about.
    let refusing = recording_consult(&asked, vec![]);
    let before = k.current_seq();
    assert!(matches!(
        rejected(vs.publish(
            P1,
            &pdoc(),
            &Shot {
                base: None,
                draft: None,
                runs: vec![
                    shot_run(&pdoc(), &pca(1), 3),
                    shot_run(&subdoc, &sca, 1),
                    shot_run(&doc2(), &w, 1),
                ],
            },
            &refusing
        )),
        PublishError::Withheld(d) if d == subdoc
    ));
    assert_eq!(
        asked.borrow().as_slice(),
        std::slice::from_ref(&subdoc),
        "the first listed origin refuses; the one behind it is never asked"
    );
    assert_eq!(k.current_seq(), before, "the refusal commits nothing");
    // Once per origin: doc2 windowed three times around subdoc, all
    // admitted, and each origin asked about once, in the order first listed.
    asked.borrow_mut().clear();
    let admitting = recording_consult(&asked, vec![doc2(), subdoc.clone()]);
    let (member1, _) = vs
        .publish(
            P1,
            &pdoc(),
            &Shot {
                base: None,
                draft: None,
                runs: vec![
                    shot_run(&doc2(), &w, 1),
                    shot_run(&doc2(), &w, 2),
                    shot_run(&subdoc, &sca, 1),
                    shot_run(&doc2(), &w, 1),
                ],
            },
            &admitting,
        )
        .expect("every window admitted");
    assert_eq!(asked.borrow().as_slice(), &[doc2(), subdoc.clone()], "each origin once, in run order");
    assert_eq!(member1, vdoc());
    assert_eq!(k.snapshot().world().m5().content_count(&member1), n(5));
    // The document's own I-space, named by the member: the edition's three
    // positions, which member1 does not arrange and so cannot carry, are
    // placed with the consult never asked — "own" is the trunk's, not the
    // named address's.
    asked.borrow_mut().clear();
    let (member2, _) = vs
        .publish(
            P1,
            &member1,
            &Shot { base: Some(base(&member1, 5)), draft: None, runs: vec![shot_run(&pdoc(), &pca(1), 3)] },
            &refusing,
        )
        .expect("the edition's own I-space takes no consult, whichever member names the shot");
    assert!(asked.borrow().is_empty(), "nothing was asked");
    assert_eq!(member2, a(&[1, 0, 1, 0, 3, 2]));
    assert_eq!(k.snapshot().world().m5().content_count(&member2), n(3));
}

#[test]
fn carried_ness_is_judged_per_supplied_run_over_its_whole_i_extent() {
    // PUB-6.24's carried cell: a supplied run the base already arranges takes
    // no consult, and "already arranges" is a claim about EVERY address of
    // ONE run. Per run: a carried run decides nothing about its origin, so a
    // later run from the same origin is still asked about. Per I-extent: a run
    // that opens on what the base holds and reaches past it is not carried.
    // Read either more loosely and a shot windows addresses of an origin its
    // shooter may not read without the gate ever being asked.
    let k = mem_kernel();
    let vs = deposit_abc(&k);
    vs.insert(P1, &doc2(), vp(1, 1), vec![val(b"w"), val(b"x")], Deposit::Undeclared)
        .expect("doc2 holds w, x");
    let w = a(&[1, 0, 1, 0, 2, 0, 1, 1]);
    let asked: RefCell<Vec<Address>> = RefCell::new(Vec::new());
    let admitting = recording_consult(&asked, vec![doc2()]);
    let (member1, _) = vs
        .publish(
            P1,
            &pdoc(),
            &Shot {
                base: Some(base(&pdoc(), 3)),
                draft: None,
                runs: vec![shot_run(&pdoc(), &pca(1), 3), shot_run(&doc2(), &w, 2)],
            },
            &admitting,
        )
        .expect("the head windows w..x");
    let (y, _) = vs
        .insert(P1, &doc2(), vp(1, 3), vec![val(b"y")], Deposit::Undeclared)
        .expect("doc2 grows y");
    assert_eq!(y, a(&[1, 0, 1, 0, 2, 0, 1, 3]), "y continues w..x's I-extent");
    let refusing = recording_consult(&asked, vec![]);
    let shot_off_member1 = |runs: Vec<ShotRun>| Shot { base: Some(base(&member1, 5)), draft: None, runs };
    let before = k.current_seq();
    // Per run: the carried w marks nothing about doc2, so the later y is asked
    // about — and refused.
    asked.borrow_mut().clear();
    assert!(matches!(
        rejected(vs.publish(
            P1,
            &pdoc(),
            &shot_off_member1(vec![shot_run(&pdoc(), &pca(1), 3), shot_run(&doc2(), &w, 1), shot_run(&doc2(), &y, 1)]),
            &refusing
        )),
        PublishError::Withheld(d) if d == doc2()
    ));
    assert_eq!(asked.borrow().as_slice(), &[doc2()], "asked once, about the run member1 does not carry");
    // Per I-extent: ONE run opening on w, x — which member1 arranges — and
    // reaching y, which it does not. Judged on its start it would be carried.
    asked.borrow_mut().clear();
    assert!(matches!(
        rejected(vs.publish(
            P1,
            &pdoc(),
            &shot_off_member1(vec![shot_run(&pdoc(), &pca(1), 3), shot_run(&doc2(), &w, 3)]),
            &refusing
        )),
        PublishError::Withheld(d) if d == doc2()
    ));
    assert_eq!(asked.borrow().as_slice(), &[doc2()], "a run carried only in part is asked about");
    assert_eq!(k.current_seq(), before, "both refusals commit nothing");
    // The control: the same run one position narrower is carried whole.
    asked.borrow_mut().clear();
    let (member2, _) = vs
        .publish(
            P1,
            &pdoc(),
            &shot_off_member1(vec![shot_run(&pdoc(), &pca(1), 3), shot_run(&doc2(), &w, 2)]),
            &refusing,
        )
        .expect("a run carried whole takes no consult");
    assert!(asked.borrow().is_empty(), "nothing was asked");
    assert_eq!(k.snapshot().world().m5().content_count(&member2), n(5));
}

#[test]
fn a_run_bridging_a_gap_in_what_the_base_arranges_is_not_carried() {
    // PUB-6.24: a supplied run is carried when the base arranges EVERY one
    // of its addresses. The head here windows doc2's w and y and never x, so
    // a run over w..y — opening on an address the base holds and ending on
    // one it holds — is not carried, and the gate is asked. A carried test
    // that judged a run by where it opens and where it reaches would let a
    // shooter who has lost the right to read doc2 window x, the one address
    // the base never answered for, with the consult never asked.
    let k = mem_kernel();
    let vs = deposit_abc(&k);
    vs.insert(P1, &doc2(), vp(1, 1), vec![val(b"w"), val(b"x"), val(b"y")], Deposit::Undeclared)
        .expect("doc2 holds w, x, y");
    let w = a(&[1, 0, 1, 0, 2, 0, 1, 1]);
    let y = a(&[1, 0, 1, 0, 2, 0, 1, 3]);
    let asked: RefCell<Vec<Address>> = RefCell::new(Vec::new());
    let admitting = recording_consult(&asked, vec![doc2()]);
    let (member1, _) = vs
        .publish(
            P1,
            &pdoc(),
            &Shot {
                base: Some(base(&pdoc(), 3)),
                draft: None,
                runs: vec![
                    shot_run(&pdoc(), &pca(1), 3),
                    shot_run(&doc2(), &w, 1),
                    shot_run(&doc2(), &y, 1),
                ],
            },
            &admitting,
        )
        .expect("the head windows w and y, never x");
    assert_eq!(k.snapshot().world().m5().content_count(&member1), n(5));
    let refusing = recording_consult(&asked, vec![]);
    let shot_off_member1 = |runs: Vec<ShotRun>| Shot { base: Some(base(&member1, 5)), draft: None, runs };
    let before = k.current_seq();
    asked.borrow_mut().clear();
    assert!(matches!(
        rejected(vs.publish(
            P1,
            &pdoc(),
            &shot_off_member1(vec![shot_run(&pdoc(), &pca(1), 3), shot_run(&doc2(), &w, 3)]),
            &refusing
        )),
        PublishError::Withheld(d) if d == doc2()
    ));
    assert_eq!(asked.borrow().as_slice(), &[doc2()], "the bridging run is asked about, and refused");
    assert_eq!(k.current_seq(), before, "the refusal commits nothing");
    // The control: the base's own two windows, re-supplied as it arranges
    // them, are carried, and the same consult is never asked.
    asked.borrow_mut().clear();
    let (member2, _) = vs
        .publish(
            P1,
            &pdoc(),
            &shot_off_member1(vec![
                shot_run(&pdoc(), &pca(1), 3),
                shot_run(&doc2(), &w, 1),
                shot_run(&doc2(), &y, 1),
            ]),
            &refusing,
        )
        .expect("runs carried whole take no consult");
    assert!(asked.borrow().is_empty(), "nothing was asked");
    assert_eq!(k.snapshot().world().m5().content_count(&member2), n(5));
}

#[test]
fn the_carried_test_answers_a_run_of_the_wires_largest_width_without_searching_it() {
    // PUB-6.24's carried test, asked of a run as wide as the wire can name —
    // a width of 4096 decimal digits — whose endpoint length is not the
    // base's: its start lies under a member of doc2, one component deeper
    // than the head's one run, which is of the edition's own I-space. A piece
    // of another content chain holds no address of the run, so the test asks
    // the run only of the base union's piece of its own content chain — none
    // here — and searches no width: a search of the client's width would
    // cost a fragmented head tens of thousands of bigint steps per resident,
    // under the applier lock, ahead of any existence answer. Not carried, the
    // run is asked about; then its first address holds no value. What a
    // regression costs here is time, which this suite does not measure: a
    // corpus seed for the fuzzing tier, with a wall-clock budget, against a
    // fragmented head.
    let k = mem_kernel();
    let vs = deposit_abc(&k);
    let (member1, _) = vs
        .publish(
            P1,
            &pdoc(),
            &Shot { base: Some(base(&pdoc(), 3)), draft: None, runs: vec![shot_run(&pdoc(), &pca(1), 3)] },
            &readable_by(PrincipalId(1)),
        )
        .expect("the head arranges the edition's three positions");
    let widest = Nat::from(10u32).pow(4096) - n(1);
    let never_minted = a(&[1, 0, 1, 0, 2, 1, 0, 1, 1]); // doc2's member's first element
    let asked: RefCell<Vec<Address>> = RefCell::new(Vec::new());
    let admitting = recording_consult(&asked, vec![doc2()]);
    let before = k.current_seq();
    assert!(matches!(
        rejected(vs.publish(
            P1,
            &pdoc(),
            &Shot {
                base: Some(base(&member1, 3)),
                draft: None,
                runs: vec![ShotRun {
                    origin: doc2(),
                    run: Run::new(never_minted, widest).expect("a content run"),
                }],
            },
            &admitting
        )),
        PublishError::DanglingSource
    ));
    assert_eq!(asked.borrow().as_slice(), &[doc2()], "not carried, so asked about");
    assert_eq!(k.current_seq(), before, "the refusal commits nothing");
}

#[test]
fn a_supplied_run_is_dangling_when_any_address_lacks_a_value_not_only_its_start() {
    // S3★ on the shot, which asks EVERY address of a supplied run where
    // COPY's gate asks only the start: a client's run was not resolved from
    // an arrangement, so no induction over what arrangements admit covers its
    // interior. Each run below opens on stored values and reaches one
    // position past them.
    let k = mem_kernel();
    let vs = deposit_abc(&k); // pdoc: pca(1..3)
    insert_abc(&k); // doc1: ca(1..3)
    let readable = readable_by(PrincipalId(1));
    let before = k.current_seq();
    // By reference: pca(2) and pca(3) are stored, pca(4) is not.
    assert!(matches!(
        rejected(vs.publish(
            P1,
            &pdoc(),
            &Shot { base: Some(base(&pdoc(), 3)), draft: None, runs: vec![shot_run(&pdoc(), &pca(2), 3)] },
            &readable
        )),
        PublishError::DanglingSource
    ));
    // Draft-native: ca(2) and ca(3) are stored, ca(4) is not. The re-insert
    // reads every value it re-inserts, so a start-only check would send it to
    // an address with nothing there.
    assert!(matches!(
        rejected(vs.publish(
            P1,
            &pdoc(),
            &Shot { base: Some(base(&pdoc(), 3)), draft: Some(doc1()), runs: vec![shot_run(&doc1(), &ca(2), 3)] },
            &readable
        )),
        PublishError::DanglingSource
    ));
    assert_eq!(k.current_seq(), before, "both refusals commit nothing");
    assert!(!k.snapshot().world().m3().is_registered_document(&vdoc()), "no member");
    // The control: both runs one position shorter commit.
    let (member1, _) = vs
        .publish(
            P1,
            &pdoc(),
            &Shot {
                base: Some(base(&pdoc(), 3)),
                draft: Some(doc1()),
                runs: vec![shot_run(&pdoc(), &pca(2), 2), shot_run(&doc1(), &ca(2), 2)],
            },
            &readable,
        )
        .expect("every address present");
    let s = k.snapshot();
    assert_eq!(s.world().m5().content_count(&member1), n(4));
    assert_eq!(read_v(&s, &member1, 4), b"c".to_vec(), "the draft's c, re-inserted");
}

#[test]
fn the_existence_walk_probes_the_union_of_the_runs_and_misses_no_address_of_any() {
    // S3★ over the UNION of the supplied runs' I-extents: an extent several
    // runs name is probed once, and the hole only the longest run reaches is
    // found whichever order the runs come in — the one way a merged walk can
    // go wrong is to keep the reach of the first run naming a start where it
    // must keep the furthest. Corpus seed for the fuzzing tier: thousands of
    // runs over one large stored extent and one dangling run, refused
    // `DanglingSource` inside a wall-clock budget.
    let k = mem_kernel();
    let vs = deposit_abc(&k); // pdoc, memberless
    vs.insert(
        P1,
        &doc2(),
        vp(1, 1),
        vec![val(b"w"), val(b"x")],
        Deposit::Undeclared,
    )
    .expect("doc2 holds w, x");
    let w = a(&[1, 0, 1, 0, 2, 0, 1, 1]);
    let readable = readable_by(PrincipalId(1));
    let shot = |widths: [u32; 3]| Shot {
        base: Some(base(&pdoc(), 3)),
        draft: None,
        runs: widths
            .iter()
            .map(|&width| shot_run(&doc2(), &w, width))
            .collect(),
    };
    let before = k.current_seq();
    for widths in [[2, 3, 1], [3, 1, 2], [1, 2, 3]] {
        assert!(
            matches!(
                rejected(vs.publish(P1, &pdoc(), &shot(widths), &readable)),
                PublishError::DanglingSource
            ),
            "{widths:?}: the third address holds no value"
        );
    }
    assert_eq!(k.current_seq(), before, "every refusal commits nothing");
    let (member, _) = vs
        .publish(P1, &pdoc(), &shot([2, 2, 1]), &readable)
        .expect("every address present");
    assert_eq!(
        k.snapshot().world().m5().content_count(&member),
        n(5),
        "each run placed as named"
    );
}

#[test]
fn a_shot_rendering_its_drafts_content_many_times_over_mints_each_identity_once() {
    // The re-insert's size is the DISTINCT draft-native positions a shot
    // renders, and a small request can render a draft's stored content many
    // times over: here 4096 runs, each naming the same forty stored values —
    // 163,840 positions placed, commanded by a request of a few hundred
    // kilobytes. Under the old sum that was a refusal; under EACH DRAFT
    // IDENTITY ONCE PER SHOT (the link-sets design §5.7) it is forty mints:
    // the first run re-inserts the forty, one stretch, and every later run
    // places the fresh run it became by reference, writing nothing — so the
    // count is forty, inside the budget, the commit stages two records for
    // the content however many times the request repeats it, and the member
    // holds 163,840 positions over 4096 runs. Rendered once after the
    // edition's own three, the fresh identities continue the edition's
    // content chain from where the deposits left it. The budget binds the
    // distinct count, which `ops/publish/tests.rs` pins without a world.
    let k = mem_kernel();
    let vs = deposit_abc(&k); // pdoc: pca(1..3), memberless
    let forty: Vec<Val> = (0..40u8).map(|b| val(&[b'a' + b % 26])).collect();
    vs.insert(P1, &doc1(), vp(1, 1), forty, Deposit::Undeclared)
        .expect("the draft holds forty values");
    let repeats = 4096;
    assert!(repeats * 40 > MAX_REINSERTED_VALUES, "the fixture renders past the old sum");
    let readable = readable_by(PrincipalId(1));
    let rendered = |runs: Vec<ShotRun>| Shot {
        base: Some(base(&pdoc(), 3)),
        draft: Some(doc1()),
        runs,
    };
    let repeated = rendered((0..repeats).map(|_| shot_run(&doc1(), &ca(1), 40)).collect());
    assert_eq!(repeated.reinserted_values(), n(40), "forty distinct positions, named 4096 times");
    let stored = k.snapshot().world().content().len();
    let (member, _) = vs
        .publish(P1, &pdoc(), &repeated, &readable)
        .expect("forty distinct positions are inside the budget");
    let s = k.snapshot();
    assert_eq!(s.world().content().len() - stored, 1, "one stretch: the forty, minted once");
    assert_eq!(s.world().m3().next_content_address(&pdoc()), Some(pca(44)));
    let runs: Vec<Run> = s.world().m5().content_runs(&member).cloned().collect();
    assert_eq!(runs.len(), repeats, "one run per repeat, each the fresh run by reference");
    assert!(
        runs.iter().all(|run| *run == Run::new(pca(4), n(40)).expect("a run")),
        "every repeat is the one fresh run"
    );
    assert_eq!(s.world().m5().content_count(&member), n(40 * repeats as u32));
    // The control: the draft rendered once, after the edition's own three,
    // into the next member — its forty already the edition's own, placed by
    // reference as the edition's I-space is, nothing minted.
    let (member2, _) = vs
        .publish(
            P1,
            &pdoc(),
            &Shot {
                base: Some(base(&member, 40 * repeats as u32)),
                draft: Some(doc1()),
                runs: vec![shot_run(&pdoc(), &pca(1), 3), shot_run(&doc1(), &ca(1), 40)],
            },
            &readable,
        )
        .expect("a re-insert inside the budget commits");
    let s = k.snapshot();
    assert_eq!(
        s.world().m5().content_runs(&member2).cloned().collect::<Vec<_>>(),
        vec![Run::new(pca(1), n(3)).expect("a content run"), Run::new(pca(44), n(40)).expect("a content run")],
        "the edition's own three, then forty fresh identities from pca(44): the draft is minted again at a later shot"
    );
}

#[test]
fn a_draft_the_caller_does_not_own_is_refused_at_the_shots_own_door() {
    // THE UNOWNED-DRAFT EDGE (the link-sets design §5.7): "the shot REFUSES
    // A DRAFT THE CALLER DOES NOT OWN WHENEVER `draft` IS NAMED — a
    // draft-native run present or not; a readable draft of a sub-account's
    // or a grantor's is refused too — answered `not_owner` with `site.addr`
    // the draft … asked in `admit` right after the draft's registration and
    // ahead of every readability question, so ω speaks and readability never
    // does". P1 shoots into its edition naming the sub-account's draft: (a)
    // under a consult admitting every origin — the draft readable — the shot
    // is refused `NotOwner` carrying the draft, where the source gate had
    // nothing to say; (b) under P1's own class, which cannot read the draft,
    // the same `NotOwner` — never `Withheld`; (c) with no draft-native run at
    // all, the same; (d) the slot sits right after the draft's registration:
    // an unregistered draft answers `SourceNotRegistered`, and a malformed run
    // beside an unowned draft answers the draft, the runs being settled after
    // it; (e) `shot_admission` answers the same, being the same checks; (f)
    // nothing is committed; and (g) `System` passes the slot as it passes
    // slot 1, so the system producers' staging draft is theirs to name.
    let k = mem_kernel();
    let vs = deposit_abc(&k); // pdoc: a b c at pca(1..3), memberless
    let sub = Caller::Principal(PrincipalId(3));
    let subdoc = a(&[1, 0, 1, 1, 0, 1]);
    let (start, _) = vs
        .insert(sub, &subdoc, vp(1, 1), vec![val(b"s")], Deposit::Undeclared)
        .expect("the sub-account's draft holds a byte");
    let anyone = |_: &World, _: &Address| true;
    let own_class = readable_by(PrincipalId(1));
    let from_subdoc = |runs: Vec<ShotRun>| Shot { base: Some(base(&pdoc(), 3)), draft: Some(subdoc.clone()), runs };
    let before = k.current_seq();
    // (a), (b): readable or not, the draft is not P1's.
    for (what, consult) in [("readable", &anyone as &dyn Fn(&World, &Address) -> bool), ("unreadable", &own_class)] {
        assert!(
            matches!(
                rejected(vs.publish(P1, &pdoc(), &from_subdoc(vec![shot_run(&subdoc, &start, 1)]), consult)),
                PublishError::NotOwner(d) if d == subdoc
            ),
            "{what}: the draft is not the caller's, whatever the consult says"
        );
    }
    // (c): no draft-native run present — the draft named is enough.
    assert!(matches!(
        rejected(vs.publish(P1, &pdoc(), &from_subdoc(vec![shot_run(&pdoc(), &pca(1), 3)]), &anyone)),
        PublishError::NotOwner(d) if d == subdoc
    ));
    // (d): right after the draft's registration, ahead of the runs.
    let unregistered = a(&[1, 0, 1, 1, 0, 9]);
    assert!(matches!(
        rejected(vs.publish(
            P1,
            &pdoc(),
            &Shot { base: Some(base(&pdoc(), 3)), draft: Some(unregistered), runs: vec![] },
            &anyone
        )),
        PublishError::SourceNotRegistered
    ));
    let malformed = ShotRun { origin: subdoc.clone(), run: Run::new(a(&[1, 0, 1, 1, 0, 1, 0, 2, 1]), n(1)).expect("a link run") };
    assert!(matches!(
        rejected(vs.publish(P1, &pdoc(), &from_subdoc(vec![malformed.clone()]), &anyone)),
        PublishError::NotOwner(d) if d == subdoc
    ));
    assert!(
        matches!(
            rejected(vs.publish(P1, &pdoc(), &Shot { draft: Some(doc1()), ..from_subdoc(vec![malformed]) }, &anyone)),
            PublishError::BadRun
        ),
        "the control: the caller's own draft beside the same run answers the run"
    );
    // (e): the admission is the same checks.
    assert_eq!(
        shot_admission(k.snapshot().world(), P1, &pdoc(), &from_subdoc(vec![shot_run(&subdoc, &start, 1)]), &anyone),
        Err(PublishError::NotOwner(subdoc.clone()))
    );
    // (f): nothing committed.
    assert_eq!(k.current_seq(), before, "every refusal commits nothing");
    assert_eq!(trunk_head(k.snapshot().world().m3(), &pdoc()), None, "no member");
    // (g): the system caller passes, and the shot lands.
    let (member, _) = vs
        .publish(Caller::System, &pdoc(), &from_subdoc(vec![shot_run(&subdoc, &start, 1)]), &anyone)
        .expect("System is exempt from ω at the draft as at the document");
    assert_eq!(bytes_of(&k.snapshot(), &member), vec![b"s".to_vec()]);
}

#[test]
fn the_source_gate_is_asked_about_the_world_it_found_the_origin_registered_in() {
    // PUB-6.37 on the shot's source gate: `publish` finds each origin
    // registered in its transaction's WORKING world and then asks the
    // predicate about it, so that is the world the predicate is handed. A
    // predicate answering from a world taken earlier is asked about an
    // address that world never registered — and the engine's read predicate
    // is fail-open there (PUB-7.5), so a draft minted in between would pass
    // the gate that exists to keep it private. The draft here is minted in
    // between.
    let k = mem_kernel();
    let vs = deposit_abc(&k);
    let earlier = k.snapshot();
    let sub = PrincipalId(3);
    let (draft, _) = Namespace::new(&k)
        .create_new_document(sub, &a(&[1, 0, 1, 1]), Some(false))
        .expect("the sub-account mints a second private draft");
    let (start, _) = vs
        .insert(Caller::Principal(sub), &draft, vp(1, 1), vec![val(b"s")], Deposit::Undeclared)
        .expect("the draft holds a byte");
    assert!(
        !earlier.world().m3().is_registered_document(&draft),
        "the earlier world never registered the draft"
    );
    // The engine's predicate in miniature: fail-open on an address the world
    // has not registered, else published or owned by P1. Asked of the
    // earlier world, it would admit the draft.
    let fail_open = |world: &World, origin: &Address| {
        let m3 = world.m3();
        !m3.is_registered_document(origin)
            || m3.published(&skep_arrangement::trunk_of(origin))
            || m3.is_effective_owner(PrincipalId(1), origin)
    };
    assert!(fail_open(earlier.world(), &draft), "the earlier world's answer admits the draft");
    // Each question is recorded with whether the world it arrived with
    // registers what it asks about.
    let registered_when_asked: RefCell<Vec<bool>> = RefCell::new(Vec::new());
    let consult = |world: &World, origin: &Address| {
        registered_when_asked.borrow_mut().push(world.m3().is_registered_document(origin));
        fail_open(world, origin)
    };
    assert!(matches!(
        rejected(vs.publish(
            P1,
            &pdoc(),
            &Shot { base: None, draft: None, runs: vec![shot_run(&draft, &start, 1)] },
            &consult
        )),
        PublishError::Withheld(d) if d == draft
    ));
    assert_eq!(
        registered_when_asked.borrow().as_slice(),
        &[true],
        "asked once, of a world that registers the origin it is asked about"
    );
}

#[test]
fn a_shot_refuses_a_private_document_and_a_malformed_request_and_commits_nothing() {
    // PUB-2.9's `true` face on the shot, the base's three shape refusals, a
    // run that is no content run of its stated origin, an unregistered
    // origin — each a clean no-op, and each behind registration and ω. Where
    // a request below is defective twice over, it is `publish`'s stated order
    // that picks the verdict, and the comment names what the other order
    // would answer.
    let k = mem_kernel();
    let vs = deposit_abc(&k);
    insert_abc(&k);
    let readable = readable_by(PrincipalId(1));
    let before = k.current_seq();
    let plain = |runs: Vec<ShotRun>| Shot { base: None, draft: None, runs };
    let unregistered_doc = a(&[1, 0, 1, 0, 9]);
    // A private document has no chain (PUB-2.9).
    assert!(matches!(
        rejected(vs.publish(P1, &doc1(), &plain(vec![shot_run(&doc1(), &ca(1), 1)]), &readable)),
        PublishError::PrivateSourceVersionless
    ));
    // …and that refusal speaks ahead of the base's shape: doc1 is private
    // AND the base names the edition, which is no member of doc1's chain.
    // Read the other way round — the base's shape first — the answer would
    // be `BaseNotInChain`.
    assert!(matches!(
        rejected(vs.publish(
            P1,
            &doc1(),
            &Shot { base: Some(base(&pdoc(), 1)), draft: None, runs: vec![] },
            &readable
        )),
        PublishError::PrivateSourceVersionless
    ));
    // …and registration and each run's shape speak ahead of it (PUB-6.37):
    // doc1 is private AND its base names no document, then private AND its
    // run is mis-stated. Read with the publication refusal first — where the
    // four edits put it, straight after the gate — both would answer
    // `PrivateSourceVersionless`.
    assert!(matches!(
        rejected(vs.publish(
            P1,
            &doc1(),
            &Shot { base: Some(base(&unregistered_doc, 1)), draft: None, runs: vec![] },
            &readable
        )),
        PublishError::SourceNotRegistered
    ));
    assert!(matches!(
        rejected(vs.publish(P1, &doc1(), &plain(vec![shot_run(&doc2(), &ca(1), 1)]), &readable)),
        PublishError::BadRun
    ));
    // Registration ahead of everything (PUB-6.37): the document, then the
    // base, then an origin.
    assert!(matches!(
        rejected(vs.publish(P1, &unregistered_doc, &plain(vec![]), &readable)),
        PublishError::DocNotRegistered
    ));
    assert!(matches!(
        rejected(vs.publish(
            P1,
            &pdoc(),
            &Shot { base: Some(base(&unregistered_doc, 1)), draft: None, runs: vec![] },
            &readable
        )),
        PublishError::SourceNotRegistered
    ));
    assert!(matches!(
        rejected(vs.publish(
            P1,
            &pdoc(),
            &plain(vec![shot_run(&unregistered_doc, &a(&[1, 0, 1, 0, 9, 0, 1, 1]), 1)]),
            &readable
        )),
        PublishError::SourceNotRegistered
    ));
    // ω stands ahead of registration: a stranger naming a base that names no
    // document learns about ownership. Registration first would answer
    // `SourceNotRegistered`.
    assert!(matches!(
        rejected(vs.publish(
            Caller::Principal(PrincipalId(2)),
            &pdoc(),
            &Shot { base: Some(base(&unregistered_doc, 1)), draft: None, runs: vec![] },
            &readable
        )),
        PublishError::NotOwner(d) if d == pdoc()
    ));
    // The base's registration before any run's shape: the base names no
    // document AND the run is mis-stated. The runs first would answer
    // `BadRun`.
    assert!(matches!(
        rejected(vs.publish(
            P1,
            &pdoc(),
            &Shot {
                base: Some(base(&unregistered_doc, 1)),
                draft: None,
                runs: vec![shot_run(&doc2(), &ca(1), 1)],
            },
            &readable
        )),
        PublishError::SourceNotRegistered
    ));
    // The draft's registration before any run's shape, likewise: the draft
    // names no document AND the run is mis-stated. The runs first would
    // answer `BadRun`.
    assert!(matches!(
        rejected(vs.publish(
            P1,
            &pdoc(),
            &Shot {
                base: None,
                draft: Some(unregistered_doc.clone()),
                runs: vec![shot_run(&doc2(), &ca(1), 1)],
            },
            &readable
        )),
        PublishError::SourceNotRegistered
    ));
    // A run whose stated origin is not the document that minted it, and a
    // run whose start is a LINK element: neither is a content run of its
    // origin — refused on the request's own arithmetic.
    assert!(matches!(
        rejected(vs.publish(P1, &pdoc(), &plain(vec![shot_run(&doc2(), &ca(1), 1)]), &readable)),
        PublishError::BadRun
    ));
    assert!(matches!(
        rejected(vs.publish(P1, &pdoc(), &plain(vec![shot_run(&doc1(), &a(&[1, 0, 1, 0, 1, 0, 2, 1]), 1)]), &readable)),
        PublishError::BadRun
    ));
    // One run defective twice: its stated origin names no document AND does
    // not project to the document its start settles. The stated origin is
    // COMPARED, never read — `BadRun` is address arithmetic on the request
    // alone — and the registration read is of the DERIVED origin document,
    // doc1, which is registered. Reading the stated origin's registration
    // first would answer `SourceNotRegistered`.
    assert!(matches!(
        rejected(vs.publish(P1, &pdoc(), &plain(vec![shot_run(&unregistered_doc, &ca(1), 1)]), &readable)),
        PublishError::BadRun
    ));
    // The runs are walked in order, each settled as its origin document is
    // derived: a mis-stated run listed ahead of a run onto an unregistered
    // origin answers for itself. Registration asked of every run before any
    // run's shape, or the runs walked from the back, would answer
    // `SourceNotRegistered`.
    assert!(matches!(
        rejected(vs.publish(
            P1,
            &pdoc(),
            &plain(vec![
                shot_run(&doc2(), &ca(1), 1),
                shot_run(&unregistered_doc, &a(&[1, 0, 1, 0, 9, 0, 1, 1]), 1),
            ]),
            &readable
        )),
        PublishError::BadRun
    ));
    // The base: another document is not in the chain — and that speaks
    // ahead of the extent, 99 being past anything doc1 holds. The extent
    // first would answer `BaseExtentTooLarge`.
    assert!(matches!(
        rejected(vs.publish(
            P1,
            &pdoc(),
            &Shot { base: Some(base(&doc1(), 99)), draft: None, runs: vec![] },
            &readable
        )),
        PublishError::BaseNotInChain
    ));
    assert_eq!(k.current_seq(), before, "every refusal is a clean no-op");
    // Once a member exists, the birth shape and the memberless base are both
    // superseded (PUB-2.34, PUB-2.66) — the member must be named. The
    // superseded base speaks ahead of its extent, 99 being past anything the
    // edition holds.
    let (member1, _) = vs.publish(P1, &pdoc(), &plain(vec![shot_run(&pdoc(), &pca(1), 3)]), &readable).expect("birth");
    let after = k.current_seq();
    assert!(matches!(
        rejected(vs.publish(P1, &pdoc(), &plain(vec![]), &readable)),
        PublishError::BaseSuperseded
    ));
    assert!(matches!(
        rejected(vs.publish(
            P1,
            &pdoc(),
            &Shot { base: Some(base(&pdoc(), 99)), draft: None, runs: vec![] },
            &readable
        )),
        PublishError::BaseSuperseded
    ));
    // Named by the member, the shot is still the document's (PUB-2.15): a
    // base naming the document itself is its superseded pre-chain
    // arrangement, whichever chain address names the shot. Judged against
    // the address named instead, the pre-chain arrangement would pass for a
    // base and a member would be minted off it.
    assert!(matches!(
        rejected(vs.publish(
            P1,
            &member1,
            &Shot { base: Some(base(&pdoc(), 3)), draft: None, runs: vec![] },
            &readable
        )),
        PublishError::BaseSuperseded
    ));
    assert_eq!(k.current_seq(), after);
    assert!(!k.snapshot().world().m3().is_registered_document(&a(&[1, 0, 1, 0, 3, 2])), "no member was minted");
    // Named, the member is a base — and a shot with no runs lands an EMPTY
    // member, read as the lazy empty arrangement.
    let (member2, _) = vs
        .publish(P1, &pdoc(), &Shot { base: Some(base(&member1, 3)), draft: None, runs: vec![] }, &readable)
        .expect("an empty member");
    assert_eq!(k.snapshot().world().m5().content_count(&member2), n(0));
    assert_eq!(reading_surface(k.snapshot().world().m3(), &pdoc()), member2);
}

#[test]
fn a_stated_origin_or_draft_that_is_no_document_is_refused_not_projected() {
    // `bad_run` and `source_not_registered` on the shot's two named
    // documents (PUB-2.15, PUB-6.37): a run's `origin` and the shot's `draft`
    // name DOCUMENTS — a member projecting to its document — and an element
    // of the right document is not one. The trunk projection answers an
    // element with itself, so an element stated as an origin never matches
    // the document its run's start settles, and an element named as the
    // draft is no registered document — whichever chain member minted it.
    let k = mem_kernel();
    let vs = deposit_abc(&k);
    let readable = readable_by(PrincipalId(1));
    let (member1, _) = vs.version(PrincipalId(1), &pdoc(), None).expect("the first member");
    let (member_start, _) = vs
        .insert(P1, &member1, vp(1, 4), vec![val(b"z")], declared())
        .expect("a deposit named by the member, minted under its content chain");
    assert_eq!(member_start, vca(1));
    let shoot = |runs: Vec<ShotRun>, draft: Option<Address>| {
        vs.publish(P1, &pdoc(), &Shot { base: Some(base(&member1, 4)), draft, runs }, &readable)
    };
    let before = k.current_seq();
    // An element minted under the trunk, and one minted under a member.
    for element in [pca(1), vca(1)] {
        assert!(
            matches!(rejected(shoot(vec![shot_run(&element, &element, 1)], None)), PublishError::BadRun),
            "{element:?} stated as its own run's origin"
        );
        assert!(
            matches!(rejected(shoot(vec![], Some(element.clone()))), PublishError::SourceNotRegistered),
            "{element:?} named as the draft"
        );
    }
    assert_eq!(k.current_seq(), before, "every refusal is a clean no-op");
    // Stated as the documents they are — the trunk, and the member that
    // projects to it — the same runs commit.
    let (member2, _) = shoot(vec![shot_run(&pdoc(), &pca(1), 1), shot_run(&member1, &vca(1), 1)], None)
        .expect("each run's origin is the document that minted it");
    assert_eq!(k.snapshot().world().m5().content_count(&member2), n(2));
}

#[test]
fn a_shot_named_by_a_member_is_gated_as_named_and_judged_as_its_document() {
    // PUB-2.15 on the shot's own `doc`, where the projection MOVES it:
    // registration and ω are the ADDRESS NAMED's (slot 1), publication the
    // DOCUMENT's (slot 5) — as the four edits and `version` are judged. The
    // fixture stamps each member with the bit its document does NOT carry,
    // and a member address the chain never minted names nothing, though its
    // trunk is registered and P1's.
    let k = mem_kernel_of(genesis_with_members());
    let vs = Vstream::new(&k);
    let readable = readable_by(PrincipalId(1));
    let shot = |base: Option<Base>| Shot {
        base,
        draft: None,
        runs: vec![],
    };
    let member_of_draft = a(&[1, 0, 1, 0, 1, 1]); // stamped published; doc1 is private
    let member_of_edition = a(&[1, 0, 1, 0, 3, 1]); // stamped private; pdoc is published
    let before = k.current_seq();
    // Gated on the trunk instead, this would pass slot 1 and answer
    // `BaseSuperseded`, pdoc's chain having a member.
    assert!(matches!(
        rejected(vs.publish(P1, &a(&[1, 0, 1, 0, 3, 7]), &shot(None), &readable)),
        PublishError::DocNotRegistered
    ));
    // The payload is the address named, not the document it projects to.
    assert!(matches!(
        rejected(vs.publish(
            Caller::Principal(PrincipalId(2)),
            &member_of_edition,
            &shot(None),
            &readable
        )),
        PublishError::NotOwner(d) if d == member_of_edition
    ));
    // Read off the member's own bit, this would answer `BaseSuperseded`.
    assert!(matches!(
        rejected(vs.publish(P1, &member_of_draft, &shot(None), &readable)),
        PublishError::PrivateSourceVersionless
    ));
    assert_eq!(k.current_seq(), before, "every refusal commits nothing");
    // Read off the member's own bit, this would be refused as private.
    let off_the_member = shot(Some(base(&member_of_edition, 0)));
    let (member, _) = vs
        .publish(P1, &member_of_edition, &off_the_member, &readable)
        .expect("a member of a published document is shot as its document");
    assert_eq!(member, a(&[1, 0, 1, 0, 3, 2]));
    assert!(
        k.snapshot().world().m3().published(&member),
        "born published"
    );
}

#[test]
fn a_shot_refused_for_a_dangling_run_leaves_no_member_no_mint_and_no_placement() {
    // PUB-2.33's ONE COMMIT, from the refusal side, over the whole assembly:
    // a shot refused for a dangling run listed behind a draft-native run
    // leaves the head, the chain, the content chain and the arrangement as
    // they were. The existence walk runs ahead of the re-insert, so this
    // refusal arrives before anything is staged; the refusal AFTER a staged
    // re-insert — the run budget's — is pinned in `ops::publish::tests`,
    // whose world can seed a head of the budget's runs.
    let k = mem_kernel();
    let vs = deposit_abc(&k);
    insert_abc(&k);
    let readable = readable_by(PrincipalId(1));
    let before = k.current_seq();
    assert!(matches!(
        rejected(vs.publish(
            P1,
            &pdoc(),
            &Shot {
                base: Some(base(&pdoc(), 3)),
                draft: Some(doc1()),
                runs: vec![
                    shot_run(&pdoc(), &pca(1), 3),
                    shot_run(&doc1(), &ca(1), 3),
                    shot_run(&pdoc(), &pca(9), 1),
                ],
            },
            &readable
        )),
        PublishError::DanglingSource
    ));
    assert_eq!(k.current_seq(), before, "nothing committed");
    let s = k.snapshot();
    assert!(!s.world().m3().is_registered_document(&vdoc()), "no member");
    assert_eq!(trunk_head(s.world().m3(), &pdoc()), None);
    // The content chain did not move: the next deposit lands at ordinal 4.
    let (start, _) = vs.insert(P1, &pdoc(), vp(1, 4), vec![val(b"z")], declared()).expect("deposit");
    assert_eq!(start, pca(4), "no content mint was committed by the refused shot");
    // And the ordinary shot still lands, so the refusal above is about the
    // dangling run and not about publishing being closed.
    let (member1, _) = vs
        .publish(
            P1,
            &pdoc(),
            &Shot {
                base: Some(base(&pdoc(), 4)),
                draft: Some(doc1()),
                runs: vec![shot_run(&pdoc(), &pca(1), 4), shot_run(&doc1(), &ca(1), 3)],
            },
            &readable,
        )
        .expect("the ordinary shot");
    assert_eq!(k.snapshot().world().m5().content_count(&member1), n(7));
}

#[test]
fn the_shots_admission_is_the_answer_publish_gives_through_its_source_gate() {
    // `shot_admission` is `publish`'s checks through its source gate, asked
    // with no transaction. Over one world it agrees with `publish` on every
    // shot: refused at or before the gate, the same refusal; past it, a
    // refusal of the composite's own — the existence walk's, the budgets' —
    // or a commit. Each shot is asked of the world `publish` then opens on:
    // one slot's verdict apiece, one refused past the gate, one that commits,
    // after which the birth shape is superseded — and then the gate's two
    // skips, under a consult refusing every origin.
    let k = mem_kernel();
    let vs = deposit_abc(&k); // pdoc: a b c, memberless
    insert_abc(&k); // doc1: a b c
    let subdoc = a(&[1, 0, 1, 1, 0, 1]);
    let (sca, _) = vs
        .insert(
            Caller::Principal(PrincipalId(3)),
            &subdoc,
            vp(1, 1),
            vec![val(b"s")],
            Deposit::Undeclared,
        )
        .expect("a private draft P1 may not read holds a byte");
    let unregistered = a(&[1, 0, 1, 0, 9]);
    let readable = readable_by(PrincipalId(1));
    let plain = |base: Option<Base>, runs: Vec<ShotRun>| Shot { base, draft: None, runs };
    let cases = [
        (P1, unregistered.clone(), plain(None, vec![]), true),
        (Caller::Principal(PrincipalId(2)), pdoc(), plain(None, vec![]), true),
        (P1, pdoc(), plain(Some(base(&unregistered, 1)), vec![]), true),
        (P1, pdoc(), plain(None, vec![shot_run(&doc2(), &ca(1), 1)]), true),
        (P1, doc1(), plain(None, vec![]), true),
        (P1, pdoc(), plain(Some(base(&doc1(), 0)), vec![]), true),
        (P1, pdoc(), plain(Some(base(&pdoc(), 9)), vec![]), true),
        (P1, pdoc(), plain(None, vec![shot_run(&subdoc, &sca, 1)]), true),
        (P1, pdoc(), plain(None, vec![shot_run(&pdoc(), &pca(9), 1)]), false),
        (P1, pdoc(), plain(Some(base(&pdoc(), 3)), vec![shot_run(&pdoc(), &pca(1), 3)]), false),
        (P1, pdoc(), plain(None, vec![]), true),
    ];
    let refused: Vec<PublishError> = cases
        .into_iter()
        .filter_map(|(caller, doc, shot, at_the_gate)| {
            agreed_refusal(&k, caller, &doc, &shot, &readable, at_the_gate)
        })
        .collect();
    // Every slot through the gate spoke once, in the order the cases ask.
    assert_eq!(
        refused,
        [
            PublishError::DocNotRegistered,
            PublishError::NotOwner(pdoc()),
            PublishError::SourceNotRegistered,
            PublishError::BadRun,
            PublishError::PrivateSourceVersionless,
            PublishError::BaseNotInChain,
            PublishError::BaseExtentTooLarge,
            PublishError::Withheld(subdoc.clone()),
            PublishError::BaseSuperseded,
        ]
    );
    // The gate's two SKIPS — the document's own I-space, and a run its base
    // already arranges (PUB-6.24) — are where the two answers would part: an
    // admission that consulted either would refuse a shot `publish` commits,
    // and the daemon's attestation check reads such a refusal as the store's
    // own at or before its gate and passes the shot through unattested — a
    // checked-set shot committed unsigned. So: a head windowing subdoc,
    // minted under a consult admitting it; then, under one refusing EVERY
    // origin, the window off that head's pinned predecessor, which does not
    // arrange it — withheld on both sides — and the edition's own run with
    // the window off the head, which holds both — each skipped, committed on
    // both sides.
    let anyone = |_: &World, _: &Address| true;
    let no_one = |_: &World, _: &Address| false;
    let (windowing, _) = vs
        .publish(
            P1,
            &pdoc(),
            &plain(
                Some(base(&vdoc(), 3)),
                vec![shot_run(&pdoc(), &pca(1), 3), shot_run(&subdoc, &sca, 1)],
            ),
            &anyone,
        )
        .expect("a head windowing subdoc, its consult admitting it");
    let off_the_predecessor = plain(Some(base(&vdoc(), 3)), vec![shot_run(&subdoc, &sca, 1)]);
    let off_the_head = plain(
        Some(base(&windowing, 4)),
        vec![shot_run(&pdoc(), &pca(1), 3), shot_run(&subdoc, &sca, 1)],
    );
    assert_eq!(
        agreed_refusal(&k, P1, &pdoc(), &off_the_predecessor, &no_one, true),
        Some(PublishError::Withheld(subdoc)),
        "not carried: consulted, and refused, on both sides"
    );
    assert_eq!(
        agreed_refusal(&k, P1, &pdoc(), &off_the_head, &no_one, false),
        None,
        "own and carried: consulted on neither side"
    );
}
