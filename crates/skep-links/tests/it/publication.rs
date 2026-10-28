//! THE PUBLICATION (the link-sets design §5.7): the publish shot's ONE
//! COMMIT — the member minted and, for every piece of draft identity the shot
//! minted, one correspondence record homed in the draft, `from` the piece's
//! draft-native span and `to` the fresh span it became, both of one width,
//! typed the correspondence class and seated in the draft; THE TWIN FENCE —
//! "a draft-native run of the request whose I-span OVERLAPS a span a
//! correspondence record homed in `D` already names as its `from` — any part
//! of it … is REFUSED `already_published`, `site.addr` the record's `to`'s
//! member", nothing staged; the unowned-draft edge ahead of the fence; the
//! records-less shot committing as the shot alone does; the composite as a
//! staging function under one transaction with a staging of the test's own
//! (PATTERNS SP-30); and the attested arm. The kernel's `Seq` counts
//! records, so "one commit" is read off a journaled kernel's boundaries.
//!
//! And THE RE-WINDOW OF THE DRAFT AT ITS KEPT PLACES, CHECKED BY IDENTITY
//! (§5.7; the S-gate's composite, now the publication's own): the request
//! carries, per draft-native run, the V-place it held in the draft when the
//! client composed it, and the one commit checks the draft still arranges
//! that run's identity there and replaces it there by the fresh run it
//! became — "a `reinstate` of the fresh I-run at the run's place and a
//! `delete` of the draft-native run, staged in the same commit and applied
//! in turn so positions stay true, a piece of a run by the same piece of the
//! fresh run at its offset" — refusing the whole publication, with the
//! entry, where it does not: "`D` moved the run, split it, deleted it or
//! arranged it elsewhere since P4 … never a guess". The check is by
//! MEMBERSHIP (the S-gate's ruling): the named place alone, a draft
//! arranging the identity twice re-windowed at the named place and left
//! standing at the other. A request with no place is today's shot: the S1
//! cells above pass unchanged, carrying none.

use skep_address::{Address, Span, SpanSet};
use skep_arrangement::{
    head_lock_key, trunk_head, Caller, Deposit, HasM5, PublishError, ReinstateError, Run, Shot,
    ShotRun, VPos, Vstream,
};
use skep_content::{HasContent, Val};
use skep_kernel::{Attestation, Kernel, Seq, TxnError};
use skep_links::{
    correspondence_type, enc, is_correspondence_class, stage_correspondence, stage_publication,
    Endset, HasLinks, Link, LinkWriter, PublicationError, PublishDeposits, PublishTarget, SlotArg,
    FROM, TO,
};
use skep_namespace::{HasM3, M3Rec, M3State};

use crate::common::*;

/// A run of `width` positions from `start`, windowing `origin`.
fn shot_run(origin: &Address, start: &Address, width: u32) -> ShotRun {
    ShotRun { origin: origin.clone(), run: Run::new(start.clone(), n(width)).expect("a content run") }
}

/// A shot into the edition from doc1, in the birth shape where `base` is
/// `None`, else off `(member, extent)`.
fn shot(base: Option<(&Address, u32)>, runs: Vec<ShotRun>) -> Shot {
    Shot {
        base: base.map(|(member, extent)| skep_arrangement::Base { member: member.clone(), extent: n(extent) }),
        draft: Some(doc1()),
        runs,
    }
}

/// doc1 holding `text`, one byte a position from `ca(1)`, as P1's insert.
fn draft_holding(k: &Kernel<World>, text: &str) {
    let vals: Vec<Val> = text.bytes().map(|b| Val::new([b])).collect();
    Vstream::new(k)
        .insert(P1, &doc1(), vp(1, 1), vals, Deposit::Undeclared)
        .expect("the draft's insert commits");
}

/// The bytes at `doc`'s content positions, in V-order, off one snapshot.
fn bytes_of(k: &Kernel<World>, doc: &Address) -> String {
    let s = k.snapshot();
    let (m5, content) = (s.world().m5(), s.world().content());
    (1u32..)
        .map_while(|ord| m5.point(doc, &vp(1, ord)))
        .map(|addr| content.value_at(addr.tumbler()).expect("arranged content is stored").as_bytes().to_vec())
        .map(|b| String::from_utf8(b).expect("ascii"))
        .collect()
}

/// The correspondence record `(from, to)`, as the publication deposits it.
fn record(from: &Run, to: &Run) -> Link {
    Link::triple(Endset::from_spans([from.iextent()]), Endset::from_spans([to.iextent()]), enc([correspondence_type()]))
}

/// The correspondence records homed in doc1, in address order, each as its
/// link — every link of the draft typed the class, exactly.
fn records_in_doc1(k: &Kernel<World>) -> Vec<Link> {
    let s = k.snapshot();
    let links = s.world().links();
    (1u32..)
        .map_while(|ordinal| links.readlink(&la(ordinal)).cloned())
        .filter(|link| is_correspondence_class(link.type_slot()))
        .collect()
}

/// The refusal a publication answered, unwrapped.
fn refused(r: Result<(Address, skep_kernel::Seq), TxnError<PublicationError>>) -> PublicationError {
    match r {
        Err(TxnError::Rejected(e)) => e,
        other => panic!("expected a rejection, got {other:?}"),
    }
}

/// THE ONE COMMIT: a shot from doc1 holding a b c, naming b c and then a b c
/// — two pieces minted (b c, then a), one occurrence placed by reference —
/// commits the member and TWO records in ONE transaction: exactly one
/// boundary above the position before it. Each record is homed in doc1,
/// typed the correspondence class, `from` the draft-native piece and `to`
/// the fresh run it became, the two of one width; they rise in minting order
/// and are seated in the draft's link subspace as one run; the member reads
/// every occurrence the client placed; and the draft reads as it did.
#[test]
fn a_publication_mints_one_correspondence_record_per_minted_piece_in_one_commit() {
    let k = journaled_over(edition_world());
    draft_holding(&k, "abc");
    let before = k.snapshot();
    let (member, seq) = writer(&k)
        .publication(P1, &PublishTarget::Document(pdoc()), &shot(None, vec![shot_run(&doc1(), &ca(2), 2), shot_run(&doc1(), &ca(1), 3)]), &[], &PublishDeposits::default())
        .expect("the publication commits");
    assert_eq!(member, pmember(1), "the edition's first member");
    assert_eq!(
        k.boundaries_above(before.seq()).expect("a journaled kernel answers its boundaries"),
        vec![(seq, None)],
        "ONE commit: the member, its placement and the records under one boundary"
    );
    let run = |start: &Address, width: u32| Run::new(start.clone(), n(width)).expect("a run");
    assert_eq!(
        records_in_doc1(&k),
        vec![record(&run(&ca(2), 2), &run(&pca(1), 2)), record(&run(&ca(1), 1), &run(&pca(3), 1))],
        "one record per minted piece, in minting order: b c, then a"
    );
    let s = k.snapshot();
    let (m3, m5) = (s.world().m3(), s.world().m5());
    assert_eq!(
        (m3.minted_at(&la(1)), m3.minted_at(&la(2)), m3.minted_at(&member)),
        (Some(seq), Some(seq), Some(seq)),
        "the records and the member are minted at the one commit's coordinate; the records' \
         addresses rise in minting order"
    );
    assert_eq!(
        m5.link_runs(&doc1()).cloned().collect::<Vec<_>>(),
        vec![run(&la(1), 2)],
        "both records seated in the draft's link subspace, as one run"
    );
    for (link, slot) in [(la(1), FROM), (la(1), TO), (la(2), FROM), (la(2), TO)] {
        let value = s.world().links().readlink(&link).expect("a record");
        let span: Vec<&Span> = value.slot(slot).expect("a slot").spans().collect();
        assert_eq!(span.len(), 1, "one span per slot: the permanent I-span");
    }
    assert_eq!(bytes_of(&k, &member), "bcabc", "every occurrence the client placed");
    assert_eq!(bytes_of(&k, &doc1()), "abc", "the draft is untouched");
}

/// THE TWIN FENCE: once `a b c` is published from doc1, a second shot naming
/// `b` alone — a sub-run of the record's `from` — is refused
/// `AlreadyPublished`, its `site` the member the record's `to` was minted
/// into, with nothing staged: no member, no record, the `Seq` unchanged. The
/// site is the record's OWN member, not the chain's head: after a second
/// member places the fresh span by reference, the fence still names the
/// first. A FRESH run of the draft lands, with a record of its own; and a
/// link typed the parent `counterpart` — an ordinary link the owner
/// deposits — fences nothing, the test being the stored type slot's exact
/// one.
#[test]
fn the_twin_fence_refuses_a_run_a_record_already_names_and_stages_nothing() {
    let k = kernel_over(edition_world());
    draft_holding(&k, "abc");
    let w = writer(&k);
    let (m1, _) = w.publication(P1, &PublishTarget::Document(pdoc()), &shot(None, vec![shot_run(&doc1(), &ca(1), 3)]), &[], &PublishDeposits::default()).expect("the first shot");
    // A second member, placing the published words by reference and a
    // fresh `d` from the draft: a record for `d` alone.
    Vstream::new(&k).insert(P1, &doc1(), vp(1, 4), vec![Val::new([b'd'])], Deposit::Undeclared).expect("d at ca(4)");
    let (m2, _) = w
        .publication(P1, &PublishTarget::Document(pdoc()), &shot(Some((&m1, 3)), vec![shot_run(&pdoc(), &pca(1), 3), shot_run(&doc1(), &ca(4), 1)]), &[], &PublishDeposits::default())
        .expect("a fresh run lands");
    assert_eq!((m1, m2.clone()), (pmember(1), pmember(2)));
    assert_eq!(records_in_doc1(&k).len(), 2, "one record per shot that re-inserted: a b c, then d");
    assert_eq!(bytes_of(&k, &m2), "abcd");

    let before = k.snapshot();
    // `b` alone: a sub-run of the first record's `from`, split from its run.
    let refusal = refused(w.publication(P1, &PublishTarget::Document(pdoc()), &shot(Some((&m2, 4)), vec![shot_run(&doc1(), &ca(2), 1)]), &[], &PublishDeposits::default()));
    assert_eq!(
        refusal,
        PublicationError::AlreadyPublished { site: pmember(1) },
        "the record's own member — the first, though the second arranges the span too"
    );
    // The whole run again, and a run straddling the record's reach.
    for run in [shot_run(&doc1(), &ca(1), 3), shot_run(&doc1(), &ca(3), 2)] {
        assert_eq!(
            refused(w.publication(P1, &PublishTarget::Document(pdoc()), &shot(Some((&m2, 4)), vec![run]), &[], &PublishDeposits::default())),
            PublicationError::AlreadyPublished { site: pmember(1) }
        );
    }
    let s = k.snapshot();
    assert_eq!(s.seq(), before.seq(), "nothing committed");
    assert!(!s.world().m3().is_registered_document(&pmember(3)), "no member minted");
    assert_eq!(records_in_doc1(&k).len(), 2, "no record minted");

    // The parent type is an ordinary link, admitted at the open surface:
    // one FROM `e`, never published, fences nothing.
    Vstream::new(&k).insert(P1, &doc1(), vp(1, 5), vec![Val::new([b'e'])], Deposit::Undeclared).expect("e at ca(5)");
    let parent = a(&[1, 1, 0, 1, 0, 1, 0, 3, 102]);
    w.makelink(
        P1,
        &doc1(),
        SlotArg::Spans(vec![Run::new(ca(5), n(1)).expect("a run").iextent()]),
        SlotArg::Addrs(vec![doc2()]),
        SlotArg::Addrs(vec![parent]),
    )
    .expect("a counterpart-typed link is an ordinary link");
    let (m3, _) = w
        .publication(P1, &PublishTarget::Document(pdoc()), &shot(Some((&m2, 4)), vec![shot_run(&pdoc(), &pca(1), 4), shot_run(&doc1(), &ca(5), 1)]), &[], &PublishDeposits::default())
        .expect("the parent-typed link is no record: the run lands");
    assert_eq!(bytes_of(&k, &m3), "abcde");
    assert_eq!(records_in_doc1(&k).len(), 3, "three records, the counterpart link beside them at la(3)");
    assert!(
        k.snapshot().world().links().readlink(&la(4)).is_some_and(|l| is_correspondence_class(l.type_slot())),
        "the third record follows the counterpart link in the draft's link subspace"
    );
}

/// THE UNOWNED-DRAFT EDGE, ahead of the fence: P2's shot into its own
/// edition naming doc1 — P1's draft, holding a record whose `from` the shot
/// names — is refused `NotOwner` carrying the draft, never
/// `AlreadyPublished`: ω speaks first, and a draft the caller does not own
/// discloses none of its records. `System` passes the edge, and the fence
/// then speaks for it too.
#[test]
fn a_draft_the_caller_does_not_own_is_refused_ahead_of_the_fence() {
    let k = kernel_over(edition_world());
    draft_holding(&k, "abc");
    let w = writer(&k);
    w.publication(P1, &PublishTarget::Document(pdoc()), &shot(None, vec![shot_run(&doc1(), &ca(1), 3)]), &[], &PublishDeposits::default()).expect("P1 publishes a b c");
    let before = k.snapshot();
    let theirs = Shot { base: None, draft: Some(doc1()), runs: vec![shot_run(&doc1(), &ca(2), 1)] };
    assert_eq!(
        refused(w.publication(P2, &PublishTarget::Document(sib_doc()), &theirs, &[], &PublishDeposits::default())),
        PublicationError::Publish(PublishError::NotOwner(doc1())),
        "the draft is P1's: ω, not the fence"
    );
    assert_eq!(
        refused(w.publication(Caller::System, &PublishTarget::Document(sib_doc()), &theirs, &[], &PublishDeposits::default())),
        PublicationError::AlreadyPublished { site: pmember(1) },
        "System passes the edge, and the fence reads the record"
    );
    assert_eq!(k.snapshot().seq(), before.seq(), "nothing committed");
}

/// A records-less shot: with no draft named, or a draft named and nothing
/// re-inserted, the publication stages no record and commits exactly what
/// the shot alone stages — the same `Seq` advance, no link in the draft, the
/// draft's link key untaken.
#[test]
fn a_shot_that_re_inserts_nothing_stages_no_record_and_commits_as_the_shot_alone_does() {
    let k = kernel_over(edition_world());
    draft_holding(&k, "abc");
    // The shot alone, for the record count: one member, no records.
    let own = |base: Option<(&Address, u32)>, draft: Option<Address>| Shot {
        base: base.map(|(m, e)| skep_arrangement::Base { member: m.clone(), extent: n(e) }),
        draft,
        runs: vec![],
    };
    let seq0 = k.current_seq();
    let (m1, s1) = Vstream::new(&k).publish(P1, &pdoc(), &own(None, None), &ALL_VISIBLE).expect("the shot alone");
    let shot_alone = s1.0 - seq0.0;
    let (m2, s2) = writer(&k).publication(P1, &PublishTarget::Document(pdoc()), &own(Some((&m1, 0)), None), &[], &PublishDeposits::default()).expect("no draft");
    assert_eq!(s2.0 - s1.0, shot_alone, "the same records as the shot alone");
    let (_, s3) = writer(&k).publication(P1, &PublishTarget::Document(pdoc()), &own(Some((&m2, 0)), Some(doc1())), &[], &PublishDeposits::default()).expect("a draft, nothing re-inserted");
    assert_eq!(s3.0 - s2.0, shot_alone, "a draft named and nothing re-inserted: no record either");
    assert!(records_in_doc1(&k).is_empty(), "no record in the draft");
    assert_eq!(k.snapshot().world().m5().link_count(&doc1()), n(0));
}

/// THE STAGING FORM (PATTERNS SP-30): the composite stages under a
/// transaction of the test's own, beside a staging of its own — a second
/// record, through the public `stage_correspondence` — and the whole stands
/// or falls together: a refusal past the publication's staging discards the
/// member and the records with it. And the record's own backstops, reached
/// through the staging function alone: a draft the caller does not own
/// (`NotOwner`), an unregistered one (`HomeNotRegistered`).
#[test]
fn the_composite_stages_under_a_callers_transaction_and_a_refusal_discards_it_whole() {
    let k = kernel_over(edition_world());
    draft_holding(&k, "abc");
    let keys = [head_lock_key(&pdoc()), M3State::content_lock_key(&pdoc()), M3State::link_lock_key(&doc1())];
    let the_shot = shot(None, vec![shot_run(&doc1(), &ca(1), 3)]);
    let before = k.current_seq();
    // A refusal after the publication staged: nothing of it stands.
    let r: Result<((), skep_kernel::Seq), TxnError<PublicationError>> = k.transact(&keys, |stg| {
        stage_publication(stg, P1, &PublishTarget::Document(pdoc()), &the_shot, &[], &PublishDeposits::default(), &ALL_VISIBLE)?;
        Err(PublicationError::HomeNotRegistered)
    });
    assert!(matches!(r, Err(TxnError::Rejected(PublicationError::HomeNotRegistered))));
    assert_eq!(k.current_seq(), before, "nothing committed");
    assert!(records_in_doc1(&k).is_empty());
    assert!(!k.snapshot().world().m3().is_registered_document(&pmember(1)), "no member");
    // The composite beside a staging of the caller's own, in one commit.
    let (member, _) = k
        .transact(&keys, |stg| {
            let (member, _) = stage_publication(stg, P1, &PublishTarget::Document(pdoc()), &the_shot, &[], &PublishDeposits::default(), &ALL_VISIBLE)?;
            let from = Run::new(ca(1), n(1)).expect("a run");
            let to = Run::new(pca(9), n(1)).expect("a run");
            stage_correspondence(stg, &ALL_VISIBLE, P1, &doc1(), &from, &to)?;
            Ok::<_, PublicationError>(member)
        })
        .expect("one commit");
    assert_eq!(member, pmember(1));
    assert_eq!(records_in_doc1(&k).len(), 2, "the publication's record and the caller's own");
    // The backstops.
    let from = Run::new(ca(2), n(1)).expect("a run");
    let to = Run::new(pca(8), n(1)).expect("a run");
    let staged = |caller: Caller, draft: Address| {
        k.transact(&[M3State::link_lock_key(&draft)], |stg| {
            stage_correspondence(stg, &ALL_VISIBLE, caller, &draft, &from, &to).map(|_| ())
        })
    };
    assert!(matches!(staged(P2, doc1()), Err(TxnError::Rejected(PublicationError::NotOwner(d))) if d == doc1()));
    assert!(matches!(
        staged(P1, a(&[1, 0, 1, 0, 9])),
        Err(TxnError::Rejected(PublicationError::HomeNotRegistered))
    ));
}

/// THE ATTESTED ARM (signed ops): a publication through an attested writer
/// fills its one transaction's marker slot — the records ride the shot's own
/// attestation, outside its preimage — and a plain writer's leaves it empty.
#[test]
fn an_attested_publication_fills_its_one_commits_slot() {
    let k = journaled_over(edition_world());
    draft_holding(&k, "abc");
    let tag1 = Attestation::new(1, vec![0x11; 3_373]).expect("tag 1");
    let attested = LinkWriter::attested(&k, &ALL_VISIBLE, Some(&tag1));
    let (m1, s1) = attested.publication(P1, &PublishTarget::Document(pdoc()), &shot(None, vec![shot_run(&doc1(), &ca(1), 2)]), &[], &PublishDeposits::default()).expect("attested");
    let (_, s2) = writer(&k)
        .publication(P1, &PublishTarget::Document(pdoc()), &shot(Some((&m1, 2)), vec![shot_run(&pdoc(), &pca(1), 2), shot_run(&doc1(), &ca(3), 1)]), &[], &PublishDeposits::default())
        .expect("plain");
    assert_eq!(k.attestation_at(s1).unwrap(), Some(tag1), "the attested publication's one slot");
    assert_eq!(k.attestation_at(s2).unwrap(), None, "the plain one's");
    assert_eq!(records_in_doc1(&k).len(), 2);
}

// ───────────────────────── the re-window at the kept places ─────────────────────────

/// The kept places of a shot: `None` at every entry but the named ones.
fn places(n: usize, named: &[(usize, u32)]) -> Vec<Option<VPos>> {
    let mut out = vec![None; n];
    for &(index, ordinal) in named {
        out[index] = Some(vp(1, ordinal));
    }
    out
}

/// `doc`'s content runs, V-ordered, off one snapshot.
fn runs_of(k: &Kernel<World>, doc: &Address) -> Vec<Run> {
    k.snapshot().world().m5().content_runs(doc).cloned().collect()
}

/// Where `doc` arranges `run`'s identity — M5's I→V projection.
fn footprint(k: &Kernel<World>, doc: &Address, run: &Run) -> SpanSet {
    k.snapshot().world().m5().project(doc, &SpanSet::singleton(run.iextent()))
}

/// A run of `width` positions from `start`.
fn run(start: &Address, width: u32) -> Run {
    Run::new(start.clone(), n(width)).expect("a run")
}

/// A test run's width, as the small number it is.
fn width_of(run: &Run) -> u32 {
    u32::try_from(run.width()).expect("a test run's width fits")
}

/// Every V-span of `doc` the draft's kept state is read against, as the
/// client reads it before composing: `(ordinal, width)` pairs.
fn spans(pairs: &[(u32, u32)]) -> SpanSet {
    pairs.iter().map(|&(ordinal, width)| vspan(1, ordinal, width)).collect()
}

/// SAME COMMIT, WHOLE RUN AND PIECE. The invariant, §5.7's: the member
/// minted and the draft re-windowed at its kept place are ONE transaction —
/// exactly one boundary above the position before it, on a journaled kernel
/// — and the fresh run is placed THERE, whether the named span is a whole
/// run of the draft or a strict piece of one, "a piece of a run by the same
/// piece of the fresh run at its offset". Two cells: doc1 built by three
/// inserts so `b` is a run of its own (a at `ca(1)`, c at `ca(2)`, b at
/// `ca(3)`), and the one-run draft of `abc`, `b c` a piece at offset 1. In
/// each the client's P4 reading is the run's place, and after the one
/// commit, on one snapshot: doc1 reads the same bytes at every position; its
/// run at the place IS the member's fresh run, the draft-native one arranged
/// nowhere in doc1 and the rest of the draft at its own addresses; the
/// member reads the shot's bytes; and the record names the piece.
#[test]
fn a_shots_fresh_run_replaces_the_drafts_run_at_its_kept_place_in_the_one_commit() {
    let whole = |k: &Kernel<World>| {
        let vs = Vstream::new(k);
        vs.insert(P1, &doc1(), vp(1, 1), vec![Val::new([b'a'])], Deposit::Undeclared).expect("a at ca(1)");
        vs.insert(P1, &doc1(), vp(1, 2), vec![Val::new([b'c'])], Deposit::Undeclared).expect("c at ca(2)");
        vs.insert(P1, &doc1(), vp(1, 2), vec![Val::new([b'b'])], Deposit::Undeclared).expect("b at ca(3), between");
    };
    let piece = |k: &Kernel<World>| draft_holding(k, "abc");
    let cells: [(&str, &dyn Fn(&Kernel<World>), Run, u32, Vec<Run>, Vec<Run>); 2] = [
        ("whole", &whole, run(&ca(3), 1), 2, vec![run(&ca(1), 1), run(&ca(3), 1), run(&ca(2), 1)], vec![run(&ca(1), 1), run(&pca(1), 1), run(&ca(2), 1)]),
        ("piece", &piece, run(&ca(2), 2), 2, vec![run(&ca(1), 3)], vec![run(&ca(1), 1), run(&pca(1), 2)]),
    ];
    for (what, build, named, place, before_runs, after_runs) in cells {
        let k = journaled_over(edition_world());
        build(&k);
        let before = k.snapshot();
        assert_eq!(runs_of(&k, &doc1()), before_runs, "{what}: the draft's shape");
        assert_eq!(bytes_of(&k, &doc1()), "abc");
        // The client's P4 reading: where doc1 arranges the named run.
        assert_eq!(footprint(&k, &doc1(), &named), spans(&[(place, width_of(&named))]), "{what}");

        let the_shot = Shot { base: None, draft: Some(doc1()), runs: vec![ShotRun { origin: doc1(), run: named.clone() }] };
        let (member, seq) = writer(&k)
            .publication(P1, &PublishTarget::Document(pdoc()), &the_shot, &places(1, &[(0, place)]), &PublishDeposits::default())
            .expect("the one commit stands whole");
        assert_eq!(member, pmember(1), "{what}");
        assert_eq!(
            k.boundaries_above(before.seq()).expect("a journaled kernel answers its boundaries"),
            vec![(seq, None)],
            "{what}: ONE commit — the member, its records and the re-window under one boundary"
        );
        let fresh = run(&pca(1), width_of(&named));
        assert_eq!(bytes_of(&k, &doc1()), "abc", "{what}: the draft reads the same bytes at every position");
        assert_eq!(runs_of(&k, &doc1()), after_runs, "{what}: the fresh run at the place, the rest at its own addresses");
        assert!(footprint(&k, &doc1(), &named).is_empty(), "{what}: the draft-native run is arranged nowhere in the draft");
        assert_eq!(footprint(&k, &doc1(), &fresh), spans(&[(place, width_of(&named))]), "{what}: the fresh run holds the place");
        assert_eq!(bytes_of(&k, &member), if what == "whole" { "b" } else { "bc" }, "{what}: the member reads the shot's bytes");
        assert_eq!(records_in_doc1(&k), vec![record(&named, &fresh)], "{what}: one record, naming the piece");
        assert_eq!(trunk_head(k.snapshot().world().m3(), &pdoc()), Some(member));
    }
}

/// What the draft did to a named run between the kept place's reading and
/// the commit, and what the check must find.
struct Since {
    what: &'static str,
    /// The edit doc1 takes after the places are read.
    disturb: fn(&Vstream<'_, World>),
    /// The bytes doc1 reads afterwards, which the refusal leaves standing.
    after: &'static str,
}

/// REFUSED WITH THE ENTRY, NOTHING WRITTEN. The invariant, §5.7's: "where
/// the check fails — `D` moved the run, split it, deleted it or arranged it
/// elsewhere since P4 — the request is REFUSED … never a guess", with
/// `site.index` the entry, and the one transaction "either stands whole or
/// not at all": the shot's mints, its records and every earlier entry's
/// re-window are staged before the check, and the refusal discards them
/// with it. The draft holds `a b c d` as one run; the shot names `a` with
/// its place and then `b c` with its own, so the refusal must name the
/// SECOND entry while the first's place still holds. Four cells, each an
/// edit of doc1 after the places were read: `b c` MOVED by a rearrangement
/// that swaps `b` and `c` inside the span — the draft arranges the run's
/// addresses at the place still, in another order, which M5's projection
/// cannot tell from the kept state and the check must (a replacement there
/// would silently undo the edit); MOVED elsewhere, `b c` after `d`; SPLIT by
/// an insert inside it; DELETED. Afterwards nothing is committed: no member,
/// no record, no fresh identity, doc1 what the disturbance left at every
/// position and in every run.
#[test]
fn a_run_moved_split_or_deleted_since_its_place_was_read_refuses_with_its_entry_and_writes_nothing() {
    let cells = [
        Since {
            what: "swapped within the span",
            disturb: |vs| {
                vs.rearrange(P1, &doc1(), &[vp(1, 2), vp(1, 3), vp(1, 4)]).expect("a c b d");
            },
            after: "acbd",
        },
        Since {
            what: "moved after d",
            disturb: |vs| {
                vs.rearrange(P1, &doc1(), &[vp(1, 2), vp(1, 4), vp(1, 5)]).expect("a d b c");
            },
            after: "adbc",
        },
        Since {
            what: "split",
            disturb: |vs| {
                vs.insert(P1, &doc1(), vp(1, 3), vec![Val::new([b'x'])], Deposit::Undeclared).expect("a b x c d");
            },
            after: "abxcd",
        },
        Since {
            what: "deleted",
            disturb: |vs| {
                vs.delete(P1, &doc1(), vp(1, 2), n(1)).expect("a c d");
            },
            after: "acd",
        },
    ];
    for cell in cells {
        let k = kernel_over(edition_world());
        draft_holding(&k, "abcd");
        let (a, bc) = (run(&ca(1), 1), run(&ca(2), 2));
        // The client's P4 reading: `a` at 1, `b c` at 2.
        assert_eq!(footprint(&k, &doc1(), &a), spans(&[(1, 1)]), "{}", cell.what);
        assert_eq!(footprint(&k, &doc1(), &bc), spans(&[(2, 2)]), "{}", cell.what);
        (cell.disturb)(&Vstream::new(&k));
        let disturbed = k.snapshot();
        assert_eq!(bytes_of(&k, &doc1()), cell.after, "{}", cell.what);
        let runs_before = runs_of(&k, &doc1());
        let stored_before = disturbed.world().content().len();

        let the_shot = Shot {
            base: None,
            draft: Some(doc1()),
            runs: vec![ShotRun { origin: doc1(), run: a.clone() }, ShotRun { origin: doc1(), run: bc.clone() }],
        };
        let refusal = refused(writer(&k).publication(P1, &PublishTarget::Document(pdoc()), &the_shot, &places(2, &[(0, 1), (1, 2)]), &PublishDeposits::default()));
        assert_eq!(
            refusal,
            PublicationError::KeptPlaceMoved { index: 1 },
            "{}: the second entry's place no longer holds; the first's does",
            cell.what
        );

        let s = k.snapshot();
        assert_eq!(s.seq(), disturbed.seq(), "{}: nothing committed", cell.what);
        assert_eq!(trunk_head(s.world().m3(), &pdoc()), None, "{}: no member minted", cell.what);
        assert!(!s.world().m3().is_registered_document(&pmember(1)), "{}", cell.what);
        assert!(records_in_doc1(&k).is_empty(), "{}: no record", cell.what);
        assert_eq!(s.world().content().len(), stored_before, "{}: no fresh identity written", cell.what);
        assert_eq!(runs_of(&k, &doc1()), runs_before, "{}: the draft's runs unchanged", cell.what);
        assert_eq!(bytes_of(&k, &doc1()), cell.after, "{}: the draft unchanged at every position", cell.what);
    }
}

/// MEMBERSHIP (the S-gate's ruling): a draft that arranges a run's identity
/// twice — `a b c b`, the second `b` a self-copy of the first — answers two
/// V-spans to the projection, and a place on ONE of them re-windows that
/// occurrence and leaves the other standing as the draft's own words, "an
/// occurrence of a run's identity the request did not name stays as it
/// stands, the twin fence meeting it at its own publication". Two cells: the
/// place on the second occurrence, then on the first. In each, the named
/// occurrence holds the fresh run afterwards, the other still the
/// draft-native run, and the bytes read the same.
#[test]
fn a_run_the_draft_arranges_twice_is_re_windowed_at_the_named_place_and_left_standing_at_the_other() {
    for (named, other) in [(4u32, 2u32), (2, 4)] {
        let k = kernel_over(edition_world());
        draft_holding(&k, "abc");
        Vstream::new(&k).copy(P1, &doc1(), vp(1, 4), &[spec(&doc1(), 1, 2, 1)]).expect("a b c b: b twice");
        let b = run(&ca(2), 1);
        assert_eq!(bytes_of(&k, &doc1()), "abcb");
        assert_eq!(footprint(&k, &doc1(), &b), spans(&[(2, 1), (4, 1)]), "the premise: the identity at two places");

        let the_shot = Shot { base: None, draft: Some(doc1()), runs: vec![ShotRun { origin: doc1(), run: b.clone() }] };
        let (member, _) = writer(&k).publication(P1, &PublishTarget::Document(pdoc()), &the_shot, &places(1, &[(0, named)]), &PublishDeposits::default()).expect("the named place holds");
        let fresh = run(&pca(1), 1);
        assert_eq!(bytes_of(&k, &doc1()), "abcb", "at {named}: the draft reads the same");
        assert_eq!(footprint(&k, &doc1(), &fresh), spans(&[(named, 1)]), "at {named}: the fresh run holds the named place");
        assert_eq!(footprint(&k, &doc1(), &b), spans(&[(other, 1)]), "at {named}: the other occurrence stands as the draft's own");
        assert_eq!(bytes_of(&k, &member), "b");
        assert_eq!(records_in_doc1(&k), vec![record(&b, &fresh)], "one record, the identity minted once");
    }
}

/// THE REFERENCED PIECE: a run named twice in `runs` — the draft arranging
/// its identity twice, `a b c b` — with a place on each: the first entry
/// mints the fresh run and the second places the identity by reference to
/// it, "a later occurrence of a minted identity with the first's fresh run",
/// and the re-window puts the first's fresh run at BOTH places, so the
/// draft-native run is arranged nowhere in the draft afterwards and the
/// member reads the identity twice; one record, the identity minted once.
#[test]
fn a_run_named_twice_with_a_place_on_each_re_windows_the_second_to_the_firsts_fresh_run() {
    let k = kernel_over(edition_world());
    draft_holding(&k, "abc");
    Vstream::new(&k).copy(P1, &doc1(), vp(1, 4), &[spec(&doc1(), 1, 2, 1)]).expect("a b c b");
    let b = run(&ca(2), 1);
    let the_shot = Shot {
        base: None,
        draft: Some(doc1()),
        runs: vec![ShotRun { origin: doc1(), run: b.clone() }, ShotRun { origin: doc1(), run: b.clone() }],
    };
    let (member, _) = writer(&k).publication(P1, &PublishTarget::Document(pdoc()), &the_shot, &places(2, &[(0, 2), (1, 4)]), &PublishDeposits::default()).expect("both places hold");
    let fresh = run(&pca(1), 1);
    assert_eq!(bytes_of(&k, &doc1()), "abcb", "the draft reads the same");
    assert!(footprint(&k, &doc1(), &b).is_empty(), "the draft-native run is arranged nowhere in the draft");
    assert_eq!(footprint(&k, &doc1(), &fresh), spans(&[(2, 1), (4, 1)]), "the one fresh run at both places");
    assert_eq!(runs_of(&k, &member), vec![fresh.clone(), fresh.clone()], "the member places the identity twice, the second time by reference");
    assert_eq!(bytes_of(&k, &member), "bb");
    assert_eq!(records_in_doc1(&k), vec![record(&b, &fresh)], "one record: the identity was minted once");
    assert_eq!(k.snapshot().world().m3().next_content_address(&pdoc()), Some(pca(2)), "one fresh position minted");
}

/// A draft the re-window cannot edit: a PUBLISHED document named as the
/// draft (the shot admits any registered document of the caller's outside
/// the chain) takes the shot and its record, and then the placement refuses
/// `published_target` — `reinstate`'s own verdict, lowered as `Reinstate` —
/// and the whole publication falls with it: no member, no record. With no
/// place the same shot lands, the published draft's words re-inserted and
/// the draft left as it stands.
#[test]
fn a_published_document_named_as_the_draft_is_refused_at_the_placement_and_lands_with_no_place() {
    let published_draft = a(&[1, 0, 1, 0, 4]);
    let world = edition_world();
    let k = kernel_over(World { m3: world.m3.apply_m3(Seq(0), &M3Rec::allocate(published_draft.clone(), true)), ..world });
    Vstream::new(&k)
        .insert(P1, &published_draft, vp(1, 1), vec![Val::new([b'q'])], Deposit::Declared(skep_arrangement::deposit_class_types()[0].clone()))
        .expect("a declared deposit at the published document's fresh position");
    let q = Run::new(a(&[1, 0, 1, 0, 4, 0, 1, 1]), n(1)).expect("a run");
    let the_shot = Shot { base: None, draft: Some(published_draft.clone()), runs: vec![ShotRun { origin: published_draft.clone(), run: q }] };
    let before = k.current_seq();
    assert_eq!(
        refused(writer(&k).publication(P1, &PublishTarget::Document(pdoc()), &the_shot, &places(1, &[(0, 1)]), &PublishDeposits::default())),
        PublicationError::Reinstate(ReinstateError::PublishedTarget)
    );
    assert_eq!(k.current_seq(), before, "nothing committed");
    assert!(!k.snapshot().world().m3().is_registered_document(&pmember(1)), "no member");
    let (member, _) = writer(&k).publication(P1, &PublishTarget::Document(pdoc()), &the_shot, &[], &PublishDeposits::default()).expect("with no place, today's shot");
    assert_eq!(bytes_of(&k, &member), "q");
    assert_eq!(bytes_of(&k, &published_draft), "q", "the published draft stands");
}

// ───────────────────────── the deposits in the one commit (S3) ─────────────────────────

use skep_links::{
    edition_type, plan_deposits, read_with_type, retraction_tuple, supersession_claim, EndArg,
    LinkEntry, MemberSpan, NamedAddress, OldCause, PlanFault, PlannedDeposit, ReadWithCause,
    RetractCause, TYPE,
};

/// The owner's second published document, the SET `S`: `[1,0,1,0,4]`,
/// registered published by [`deposits_world`] alone.
fn set_s() -> Address {
    a(&[1, 0, 1, 0, 4])
}

/// [`edition_world`] with the set `S` registered published: the world every
/// deposit cell opens over — doc1 the staging draft, doc2 the private notes
/// `N`, `pdoc` the edition `E`, `S` the set, the sibling's published
/// document beside them.
fn deposits_world() -> World {
    let world = edition_world();
    World { m3: world.m3.apply_m3(Seq(0), &M3Rec::allocate(set_s(), true)), ..world }
}

/// Link element `k` of `doc`.
fn link_of(doc: &Address, k: u32) -> Address {
    let comps: Vec<u32> = doc.tumbler().iter().map(|c| u32::try_from(c).expect("a small component")).chain([0, 2, k]).collect();
    a(&comps)
}

/// The citation type, a commons address named verbatim.
fn citation() -> Address {
    a(&[1, 1, 0, 1, 0, 1, 0, 3, 13])
}

/// The address form over addresses alone.
fn addrs(list: &[&Address]) -> EndArg {
    EndArg::Addrs(list.iter().map(|&a| NamedAddress::Address(a.clone())).collect())
}

/// The I-span form over one run.
fn ispans(start: &Address, width: u32) -> EndArg {
    EndArg::Spans(vec![run(start, width).iextent()])
}

/// The member-position form over one span.
fn member_spans(ordinal: u64, width: u64) -> EndArg {
    EndArg::Member(vec![MemberSpan { ordinal, width }])
}

/// A `links` entry.
fn entry(home: NamedAddress, from: EndArg, to: EndArg, ty: EndArg, old: Option<Address>) -> LinkEntry {
    LinkEntry { home, from, to, ty, old }
}

/// The shot off the edition's current head, re-supplying the head's
/// positions by reference and then `fresh`, the draft's runs.
fn shot_off_head(k: &Kernel<World>, fresh: Vec<ShotRun>) -> Shot {
    let s = k.snapshot();
    let (m3, m5) = (s.world().m3(), s.world().m5());
    let head = trunk_head(m3, &pdoc()).expect("a head");
    let extent = m5.content_count(&head);
    let mut runs: Vec<ShotRun> = m5.content_runs(&head).map(|r| ShotRun { origin: pdoc(), run: r.clone() }).collect();
    runs.extend(fresh);
    Shot { base: Some(skep_arrangement::Base { member: head, extent }), draft: Some(doc1()), runs }
}

/// Publishes `shot` with `deposits` into the edition, as the owner.
fn publish(k: &Kernel<World>, shot: &Shot, deposits: &PublishDeposits) -> Result<(Address, Seq), TxnError<PublicationError>> {
    writer(k).publication(P1, &PublishTarget::Document(pdoc()), shot, &[], deposits)
}

/// The refusal a publication with `deposits` answers, the world untouched.
fn refused_plan(k: &Kernel<World>, shot: &Shot, deposits: PublishDeposits) -> PlanFault {
    let before = k.current_seq();
    let fault = match refused(publish(k, shot, &deposits)) {
        PublicationError::Plan(fault) => fault,
        other => panic!("expected a plan fault, got {other:?}"),
    };
    assert_eq!(k.current_seq(), before, "nothing committed");
    fault
}

/// THE BOARD the deposit cells share: doc1 holding `a b c`, published once
/// as `E.1` (the fresh identity `pca(1..=3)`, one record in doc1); the
/// original `L` in the notes `N` (doc2), FROM the draft's words, TO `N`
/// itself, the citation type; the held removal's mark `M` in `E.1`, over
/// the published words, one-sided. Answers `(L, M)`.
fn board(k: &Kernel<World>) -> (Address, Address) {
    draft_holding(k, "abc");
    let w = writer(k);
    let l = w
        .makelink(P1, &doc2(), SlotArg::Spans(vec![run(&ca(1), 3).iextent()]), SlotArg::Addrs(vec![doc2()]), SlotArg::Addrs(vec![citation()]))
        .expect("the original in the notes")
        .0;
    assert_eq!(l, link_of(&doc2(), 1));
    let (e1, _) = publish(k, &shot(None, vec![shot_run(&doc1(), &ca(1), 3)]), &PublishDeposits::default()).expect("E.1");
    assert_eq!(e1, pmember(1));
    let m = w
        .makelink(P1, &e1, SlotArg::Spans(vec![run(&pca(1), 3).iextent()]), SlotArg::Addrs(vec![]), SlotArg::Addrs(vec![a(&[1, 1, 0, 1, 0, 1, 0, 3, 23, 2])]))
        .expect("the mark in E.1")
        .0;
    assert_eq!(m, link_of(&e1, 1));
    (l, m)
}

/// ONE COMMIT: a publication carrying a copy of `L` into the member with
/// its claim, the retraction of `M` and a read-with to `S` — one boundary
/// above the position before it, on a journaled kernel; the member minted,
/// the record of the new word `d` in doc1, the copy the member's first link
/// FROM the published words' I-span (the member-position form resolved) TO
/// `N`, typed the citation; the claim `L → copy` the notes' second link; the
/// retraction tuple `E.1`'s second link, `M` off the active view; the
/// read-with `S`'s first link `{from: E, to: S, ty: rw}`, seated.
#[test]
fn a_publication_lands_its_copy_claim_retraction_and_read_with_in_one_commit() {
    let k = journaled_over(deposits_world());
    let (l, m) = board(&k);
    Vstream::new(&k).insert(P1, &doc1(), vp(1, 4), vec![Val::new([b'd'])], Deposit::Undeclared).expect("d at ca(4)");
    let before = k.snapshot();
    let the_shot = shot_off_head(&k, vec![shot_run(&doc1(), &ca(4), 1)]);
    let deposits = PublishDeposits {
        links: vec![entry(NamedAddress::Member, member_spans(1, 3), addrs(&[&doc2()]), addrs(&[&citation()]), Some(l.clone()))],
        retract: vec![m.clone()],
        read_with: vec![set_s()],
    };
    let (member, seq) = publish(&k, &the_shot, &deposits).expect("the one commit");
    assert_eq!(member, pmember(2));
    assert_eq!(
        k.boundaries_above(before.seq()).expect("a journaled kernel answers its boundaries"),
        vec![(seq, None)],
        "ONE commit: the member, the record, the copy, the claim, the retraction and the read-with"
    );
    let s = k.snapshot();
    let links = s.world().links();
    assert_eq!(bytes_of(&k, &member), "abcd");
    assert_eq!(records_in_doc1(&k).len(), 2, "the second shot's record for `d`");
    let copy = link_of(&member, 1);
    assert_eq!(
        links.readlink(&copy),
        Some(&Link::triple(Endset::from_spans([run(&pca(1), 3).iextent()]), enc([&doc2()]), enc([&citation()]))),
        "the copy: the member-position end stored as the published I-span"
    );
    assert_eq!(s.world().m5().link_runs(&member).cloned().collect::<Vec<_>>(), vec![run(&copy, 1)], "seated in the member");
    assert_eq!(links.readlink(&link_of(&doc2(), 2)), Some(&supersession_claim(&l, &copy)), "the claim in the notes");
    assert!(links.is_active(&l), "the original stands, superseded");
    assert_eq!(links.readlink(&link_of(&pmember(1), 2)), Some(&retraction_tuple(&pmember(1), &m)), "the retraction at the mark's home");
    assert!(!links.is_active(&m), "the mark is off the active view");
    let rw = link_of(&set_s(), 1);
    assert_eq!(links.readlink(&rw), Some(&Link::triple(enc([&pdoc()]), enc([&set_s()]), enc([read_with_type()]))), "the read-with in S");
    assert_eq!(s.world().m5().link_runs(&set_s()).cloned().collect::<Vec<_>>(), vec![run(&rw, 1)], "seated in S");
    let m3 = s.world().m3();
    for addr in [&copy, &link_of(&doc2(), 2), &link_of(&pmember(1), 2), &rw, &member] {
        assert_eq!(m3.minted_at(addr), Some(seq), "{addr} minted at the one commit");
    }
}

/// THE ORDER (the pin: within one commit a home's link addresses rise in
/// the order the daemon mints them): three `links` entries into the member
/// and one into `S`, then a read-with to `S`, land at consecutive ordinals
/// in the plan's order — the member's `.1`, `.2`, `.3` in declared order,
/// `S`'s `.1` the entry and `.2` the read-with, the copies ahead of the
/// read-with inside the home.
#[test]
fn a_homes_link_addresses_rise_in_the_plans_order_within_one_commit() {
    let k = kernel_over(deposits_world());
    board(&k);
    let the_shot = shot_off_head(&k, vec![]);
    let ty = |n: u32| addrs(&[&a(&[1, 1, 0, 1, 0, 1, 0, 3, 23, n])]);
    let deposits = PublishDeposits {
        links: vec![
            entry(NamedAddress::Member, member_spans(1, 1), addrs(&[]), ty(1), None),
            entry(NamedAddress::Member, member_spans(2, 1), addrs(&[]), ty(2), None),
            entry(NamedAddress::Address(set_s()), ispans(&pca(1), 3), addrs(&[]), ty(3), None),
            entry(NamedAddress::Member, member_spans(3, 1), addrs(&[]), ty(4), None),
        ],
        retract: vec![],
        read_with: vec![set_s()],
    };
    let (member, _) = publish(&k, &the_shot, &deposits).expect("the commit");
    let s = k.snapshot();
    let links = s.world().links();
    let ty_of = |addr: &Address| links.readlink(addr).expect("a link").slot(TYPE).expect("a type").clone();
    assert_eq!(ty_of(&link_of(&member, 1)), enc([&a(&[1, 1, 0, 1, 0, 1, 0, 3, 23, 1])]), "the first entry at .1");
    assert_eq!(ty_of(&link_of(&member, 2)), enc([&a(&[1, 1, 0, 1, 0, 1, 0, 3, 23, 2])]), "the second at .2");
    assert_eq!(ty_of(&link_of(&member, 3)), enc([&a(&[1, 1, 0, 1, 0, 1, 0, 3, 23, 4])]), "the fourth at .3: declared order within the member");
    assert_eq!(links.readlink(&link_of(&member, 4)), None, "and nothing past them");
    assert_eq!(ty_of(&link_of(&set_s(), 1)), enc([&a(&[1, 1, 0, 1, 0, 1, 0, 3, 23, 3])]), "the third entry, S's first");
    assert_eq!(ty_of(&link_of(&set_s(), 2)), enc([read_with_type()]), "the read-with after the copies in S");
    assert_eq!(links.readlink(&link_of(&set_s(), 3)), None);
}

/// THE MINT: `mint: true` under the owner's account with `claim: true` —
/// the edition minted under the account, born published, the member its
/// first, the words re-inserted under the edition's own chain, and the
/// edition claim homed in the edition, typed the edition class, `from` the
/// edition and `to` the origin draft `D`, seated; a read-with's `from` the
/// minted edition; `not_owner` naming the account for another's.
#[test]
fn a_minting_publication_mints_the_edition_and_homes_the_claim_in_it() {
    let k = journaled_over(deposits_world());
    draft_holding(&k, "abc");
    let account = a(&[1, 0, 1]);
    let before = k.snapshot();
    let the_shot = Shot { base: None, draft: Some(doc1()), runs: vec![shot_run(&doc1(), &ca(1), 3)] };
    let target = PublishTarget::Mint { account: account.clone(), claim: true };
    let deposits = PublishDeposits { links: vec![], retract: vec![], read_with: vec![set_s()] };
    let (member, seq) = writer(&k).publication(P1, &target, &the_shot, &[], &deposits).expect("the mint");
    let edition = a(&[1, 0, 1, 0, 5]);
    assert_eq!(member, a(&[1, 0, 1, 0, 5, 1]), "the edition's first member");
    assert_eq!(k.boundaries_above(before.seq()).expect("boundaries"), vec![(seq, None)], "one commit");
    let s = k.snapshot();
    let (m3, links) = (s.world().m3(), s.world().links());
    assert!(m3.is_registered_document(&edition) && m3.published(&edition), "the edition, born published");
    assert_eq!(m3.minted_at(&edition), Some(seq));
    assert_eq!(trunk_head(m3, &edition), Some(member.clone()));
    assert_eq!(bytes_of(&k, &member), "abc");
    assert_eq!(records_in_doc1(&k).len(), 1, "the record in the draft");
    let claim = link_of(&edition, 1);
    assert_eq!(
        links.readlink(&claim),
        Some(&Link::triple(enc([&edition]), enc([&doc1()]), enc([edition_type()]))),
        "the edition claim: from the edition, to the origin D, typed edition"
    );
    assert_eq!(s.world().m5().link_runs(&edition).cloned().collect::<Vec<_>>(), vec![run(&claim, 1)], "seated in the edition");
    assert_eq!(
        links.readlink(&link_of(&set_s(), 1)),
        Some(&Link::triple(enc([&edition]), enc([&set_s()]), enc([read_with_type()]))),
        "the read-with's from is the minted edition"
    );
    // Another's account: `not_owner` naming it, nothing minted.
    let theirs = PublishTarget::Mint { account: a(&[1, 0, 2]), claim: false };
    let before = k.current_seq();
    assert_eq!(
        refused(writer(&k).publication(P1, &theirs, &Shot { base: None, draft: None, runs: vec![] }, &[], &PublishDeposits::default())),
        PublicationError::Publish(PublishError::NotOwner(a(&[1, 0, 2])))
    );
    assert_eq!(k.current_seq(), before);
    // A base at the mint form: no chain for it to lie in.
    let based = Shot { base: Some(skep_arrangement::Base { member: pmember(1), extent: n(0) }), draft: None, runs: vec![] };
    assert_eq!(
        refused(writer(&k).publication(P1, &target, &based, &[], &PublishDeposits::default())),
        PublicationError::Publish(PublishError::BaseNotInChain)
    );
    assert_eq!(k.current_seq(), before);
}

/// THE REFUSALS, each with its entry's index and nothing committed: a
/// `links` entry homed in a private document, in a member `E.j`, in
/// another's published document (`not_owner`, the home); a public `old`, a
/// retracted `old`, an `old` superseded by the caller's own claim over the
/// published spans, a second entry naming one `old` (the SECOND refused);
/// a read-with-typed entry; a retraction of another's link, of a link homed
/// in a private document, of an absent one; a read-with to a private `S`,
/// to a member, to another's document.
#[test]
fn each_refused_entry_names_its_index_and_commits_nothing() {
    let k = kernel_over(deposits_world());
    let (l, m) = board(&k);
    let w = writer(&k);
    // A second original, retracted; another's link in the sibling's document.
    let l2 = w.makelink(P1, &doc2(), SlotArg::Spans(vec![run(&ca(2), 1).iextent()]), SlotArg::Addrs(vec![]), SlotArg::Addrs(vec![citation()])).expect("L2").0;
    w.nullify(P1, &doc2(), &l2).expect("L2 retracted");
    let theirs = w.makelink(P2, &sib_doc(), SlotArg::Addrs(vec![sib_doc()]), SlotArg::Addrs(vec![]), SlotArg::Addrs(vec![citation()])).expect("their link").0;
    let the_shot = shot_off_head(&k, vec![]);
    let copy = |home: NamedAddress, old: Option<Address>| entry(home, ispans(&pca(1), 3), addrs(&[&doc2()]), addrs(&[&citation()]), old);
    let links_only = |links: Vec<LinkEntry>| PublishDeposits { links, retract: vec![], read_with: vec![] };
    assert_eq!(refused_plan(&k, &the_shot, links_only(vec![copy(NamedAddress::Address(doc2()), None)])), PlanFault::LinkHome { index: 0 }, "a private home");
    assert_eq!(refused_plan(&k, &the_shot, links_only(vec![copy(NamedAddress::Address(pmember(1)), None)])), PlanFault::LinkHome { index: 0 }, "a member");
    assert_eq!(refused_plan(&k, &the_shot, links_only(vec![copy(NamedAddress::Address(sib_doc()), None)])), PlanFault::NotOwner(sib_doc()), "another's");
    assert_eq!(refused_plan(&k, &the_shot, links_only(vec![copy(NamedAddress::Edition, None)])), PlanFault::LinkHome { index: 0 }, "the edition's tag with no mint");
    assert_eq!(refused_plan(&k, &the_shot, links_only(vec![copy(NamedAddress::Member, Some(m.clone()))])), PlanFault::Old { index: 0, cause: OldCause::Public }, "a public old");
    assert_eq!(refused_plan(&k, &the_shot, links_only(vec![copy(NamedAddress::Member, Some(l2.clone()))])), PlanFault::Old { index: 0, cause: OldCause::Retracted }, "a retracted old");
    assert_eq!(refused_plan(&k, &the_shot, links_only(vec![copy(NamedAddress::Member, Some(link_of(&doc2(), 9)))])), PlanFault::Old { index: 0, cause: OldCause::Absent }, "an absent old");
    assert_eq!(refused_plan(&k, &the_shot, links_only(vec![copy(NamedAddress::Member, Some(theirs.clone()))])), PlanFault::Old { index: 0, cause: OldCause::NotOwner }, "another's old");
    assert_eq!(
        refused_plan(&k, &the_shot, links_only(vec![copy(NamedAddress::Member, None), copy(NamedAddress::Member, Some(l.clone())), copy(NamedAddress::Member, Some(l.clone()))])),
        PlanFault::DuplicateOriginal { index: 2 },
        "the second entry naming one old"
    );
    assert_eq!(
        refused_plan(&k, &the_shot, links_only(vec![entry(NamedAddress::Member, ispans(&pca(1), 3), addrs(&[]), addrs(&[read_with_type()]), None)])),
        PlanFault::ReadWithInLinks { index: 0 }
    );
    assert_eq!(
        refused_plan(&k, &the_shot, links_only(vec![entry(NamedAddress::Member, ispans(&pca(1), 3), addrs(&[]), addrs(&[&a(&[1, 1, 0, 1, 0, 1, 0, 1, 5])]), None)])),
        PlanFault::RetractionClass { index: 0 },
        "the class fences as today"
    );
    assert_eq!(
        refused_plan(&k, &the_shot, links_only(vec![entry(NamedAddress::Member, ispans(&pca(1), 3), addrs(&[]), addrs(&[]), None)])),
        PlanFault::EmptyType { index: 0 }
    );
    assert_eq!(
        refused_plan(&k, &the_shot, links_only(vec![entry(NamedAddress::Member, member_spans(3, 2), addrs(&[]), addrs(&[&citation()]), None)])),
        PlanFault::MemberSpan { index: 0 },
        "past the member's placed positions"
    );
    let retract_only = |retract: Vec<Address>| PublishDeposits { links: vec![], retract, read_with: vec![] };
    assert_eq!(refused_plan(&k, &the_shot, retract_only(vec![theirs.clone()])), PlanFault::Retract { index: 0, cause: RetractCause::NotOwner });
    assert_eq!(refused_plan(&k, &the_shot, retract_only(vec![l.clone()])), PlanFault::Retract { index: 0, cause: RetractCause::NotPublished });
    assert_eq!(refused_plan(&k, &the_shot, retract_only(vec![m.clone(), link_of(&pmember(1), 7)])), PlanFault::Retract { index: 1, cause: RetractCause::Absent });
    let read_with_only = |read_with: Vec<Address>| PublishDeposits { links: vec![], retract: vec![], read_with };
    assert_eq!(refused_plan(&k, &the_shot, read_with_only(vec![doc2()])), PlanFault::ReadWith { index: 0, cause: ReadWithCause::NotPublished });
    assert_eq!(refused_plan(&k, &the_shot, read_with_only(vec![set_s(), pmember(1)])), PlanFault::ReadWith { index: 1, cause: ReadWithCause::NotDocument });
    assert_eq!(refused_plan(&k, &the_shot, read_with_only(vec![sib_doc()])), PlanFault::ReadWith { index: 0, cause: ReadWithCause::NotOwner });
    assert_eq!(refused_plan(&k, &the_shot, read_with_only(vec![a(&[1, 0, 1, 0, 9])])), PlanFault::ReadWith { index: 0, cause: ReadWithCause::NotRegistered });
    // The order: a links fault speaks ahead of a retract fault ahead of a
    // read-with fault.
    assert_eq!(
        refused_plan(&k, &the_shot, PublishDeposits { links: vec![copy(NamedAddress::Address(doc2()), None)], retract: vec![theirs.clone()], read_with: vec![doc2()] }),
        PlanFault::LinkHome { index: 0 }
    );
    assert_eq!(
        refused_plan(&k, &the_shot, PublishDeposits { links: vec![], retract: vec![theirs], read_with: vec![doc2()] }),
        PlanFault::Retract { index: 0, cause: RetractCause::NotOwner }
    );
    // THE SUPERSEDED OLD: once `L` is accepted — its copy in the member,
    // its claim in the notes — a second copy of `L` over the published
    // spans the copy covers is refused `superseded`, while one over the
    // shot's own new words is not (nothing standing covers fresh words).
    publish(&k, &the_shot, &links_only(vec![copy(NamedAddress::Member, Some(l.clone()))])).expect("L accepted");
    let the_shot = shot_off_head(&k, vec![]);
    assert_eq!(
        refused_plan(&k, &the_shot, links_only(vec![copy(NamedAddress::Member, Some(l.clone()))])),
        PlanFault::Old { index: 0, cause: OldCause::Superseded }
    );
    Vstream::new(&k).insert(P1, &doc1(), vp(1, 4), vec![Val::new([b'd'])], Deposit::Undeclared).expect("d at ca(4)");
    let the_shot = shot_off_head(&k, vec![shot_run(&doc1(), &ca(4), 1)]);
    let on_new_words = entry(NamedAddress::Member, member_spans(4, 1), addrs(&[&doc2()]), addrs(&[&citation()]), Some(l.clone()));
    publish(&k, &the_shot, &links_only(vec![on_new_words])).expect("an entry on fresh words is covered by nothing");
}

/// THE SKIPS: a `retract` target already retracted and a `read_with` set a
/// read-with of the maker's already stands in, in a PUBLISHED home, each
/// commit nothing for their entry while the rest lands; a read-with standing
/// only in a PRIVATE home of the maker's is not counted, and the public one
/// is written.
#[test]
fn a_retracted_target_and_a_standing_read_with_are_skipped_and_a_private_one_is_not() {
    let k = kernel_over(deposits_world());
    let (_, m) = board(&k);
    let w = writer(&k);
    w.nullify(P1, &pmember(1), &m).expect("the mark taken off on another device");
    let e1_links = k.snapshot().world().m5().link_count(&pmember(1));
    // A read-with in the PRIVATE notes alone: not counted.
    w.makelink(P1, &doc2(), SlotArg::Addrs(vec![pdoc()]), SlotArg::Addrs(vec![set_s()]), SlotArg::Addrs(vec![read_with_type().clone()])).expect("a private read-with");
    let the_shot = shot_off_head(&k, vec![]);
    let deposits = PublishDeposits { links: vec![], retract: vec![m.clone()], read_with: vec![set_s()] };
    let (m2, _) = publish(&k, &the_shot, &deposits).expect("the rest lands");
    assert_eq!(m2, pmember(2));
    let s = k.snapshot();
    assert_eq!(s.world().m5().link_count(&pmember(1)), e1_links, "the skipped retraction stages nothing at the mark's home");
    assert_eq!(s.world().links().readlink(&link_of(&pmember(1), 3)), None);
    assert_eq!(
        s.world().links().readlink(&link_of(&set_s(), 1)),
        Some(&Link::triple(enc([&pdoc()]), enc([&set_s()]), enc([read_with_type()]))),
        "the read-with written in S: the private one does not skip it"
    );
    // Now the public one stands: a third publication's read-with is skipped.
    let the_shot = shot_off_head(&k, vec![]);
    let (m3, _) = publish(&k, &the_shot, &PublishDeposits { links: vec![], retract: vec![], read_with: vec![set_s()] }).expect("the shot lands");
    assert_eq!(m3, pmember(3));
    assert_eq!(k.snapshot().world().links().readlink(&link_of(&set_s(), 2)), None, "the standing read-with skips the entry");
    // Retracted, the public read-with no longer stands, and the next is written.
    w.nullify(P1, &set_s(), &link_of(&set_s(), 1)).expect("retracted");
    let the_shot = shot_off_head(&k, vec![]);
    publish(&k, &the_shot, &PublishDeposits { links: vec![], retract: vec![], read_with: vec![set_s()] }).expect("the shot lands");
    assert_eq!(k.snapshot().world().links().readlink(&link_of(&set_s(), 3)).map(|l| l.type_slot().clone()), Some(enc([read_with_type()])));
}

/// PLAN EQUALITY, by purity: the plan is a function of the world and the
/// request alone — the same world, the same plan, twice, and over the
/// transaction's own base the plan the composite stages equals it, deposit
/// for deposit, the skipped entries absent from both.
/// THE PIN ACROSS COMMITS (the link-sets design §5.7, W7 (3); `state.rs`'s
/// `next_link_address`): a home's link ordinals rise with commit position.
/// Three commits deposit into `S` — two entries, then three, then one — and
/// each commit's deposits are one contiguous run of `S`'s ordinals, every
/// ordinal above the commit before it, `minted_at` equal within a commit and
/// rising across them; so the middle commit's deposits are exactly the
/// ordinals whose `minted_at` is its position, found by a binary search over
/// the ordinals that reads `O(log n)` of them.
#[test]
fn a_homes_link_ordinals_rise_with_commit_position_across_commits() {
    let k = kernel_over(deposits_world());
    board(&k);
    let ty = |n: u32| addrs(&[&a(&[1, 1, 0, 1, 0, 1, 0, 3, 23, n])]);
    let into_s = |n: u32| entry(NamedAddress::Address(set_s()), ispans(&pca(1), 3), addrs(&[]), ty(n), None);
    let mut seqs = Vec::new();
    for (commit, count) in [2u32, 3, 1].into_iter().enumerate() {
        let the_shot = shot_off_head(&k, vec![]);
        let base = 10 * commit as u32;
        let deposits = PublishDeposits { links: (1..=count).map(|n| into_s(base + n)).collect(), retract: vec![], read_with: vec![] };
        let (_, seq) = publish(&k, &the_shot, &deposits).expect("the commit");
        seqs.push(seq);
    }
    assert!(seqs[0] < seqs[1] && seqs[1] < seqs[2], "three commits in order: {seqs:?}");
    let s = k.snapshot();
    let (links, m3) = (s.world().links(), s.world().m3());
    // The ordinals, each at its commit: 1–2 the first's, 3–5 the second's, 6
    // the third's — contiguous runs rising with position.
    let at = |ordinal: u32| m3.minted_at(&link_of(&set_s(), ordinal)).expect("a minted link");
    assert_eq!([at(1), at(2)], [seqs[0], seqs[0]], "the first commit's run");
    assert_eq!([at(3), at(4), at(5)], [seqs[1], seqs[1], seqs[1]], "the second's, above the first's");
    assert_eq!(at(6), seqs[2], "the third's, above the second's");
    assert_eq!(links.readlink(&link_of(&set_s(), 7)), None, "the frontier");
    // The position-fenced read: the first ordinal at or past the middle
    // commit's position and the first past it, each by a binary search over
    // the ordinals' ages — the deposits of the commit, by reading its
    // position and the ordinals alone, never the plan.
    let frontier = 6u32;
    let lower_bound = |target: Seq, strict: bool| -> u32 {
        let (mut lo, mut hi) = (1u32, frontier + 1);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let past = if strict { at(mid) > target } else { at(mid) >= target };
            if past {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }
        lo
    };
    let first = lower_bound(seqs[1], false);
    let past = lower_bound(seqs[1], true);
    assert_eq!((first, past), (3, 6), "the middle commit's deposits are ordinals 3 through 5");
}

/// THE PRICE OF THE IN-LOCK READS (the link-sets design §5.7, W8 (1)): the
/// four terms read off one snapshot — the caller's link-holding homes by
/// `homes_under` of the account (doc1 holding the record of `E.1`'s shot,
/// `N` holding `L`, `E.1` holding `M`: three, whatever the caller may read of
/// them), the `links` and `read_with` entries summed, the draft's content
/// runs and the request's runs — and the one comparison against
/// `MAX_PUBLICATION_READS`: a request at the budget is inside it, one past
/// it is over, the system caller prices no homes, and a shot naming no draft
/// no runs of one.
#[test]
fn the_price_of_a_publications_reads_is_its_four_terms_against_the_one_budget() {
    use skep_links::{price_publication_reads, ReadPrice, MAX_PUBLICATION_READS};

    let k = kernel_over(deposits_world());
    let (l, m) = board(&k);
    let s = k.snapshot();
    let world = s.world();
    let the_shot = shot_off_head(&k, vec![shot_run(&doc1(), &ca(1), 3)]);
    let deposits = PublishDeposits {
        links: vec![entry(NamedAddress::Member, member_spans(1, 3), addrs(&[&doc2()]), addrs(&[&citation()]), Some(l))],
        retract: vec![m],
        read_with: vec![set_s(), set_s()],
    };
    let price = price_publication_reads(world, P1, &the_shot, &deposits);
    assert_eq!(
        price,
        ReadPrice { homes: 3, entries: 3, draft_runs: 1, runs: 2 },
        "three link-holding homes under the account; one links entry and two read-withs; one run in doc1; two runs in the shot"
    );
    assert_eq!(price.total(), 3 * 3 + 2, "homes × entries + draft runs × runs");
    assert!(!price.over_budget());
    assert_eq!(ReadPrice::BUDGET, MAX_PUBLICATION_READS);
    let at_budget = ReadPrice { homes: 1, entries: MAX_PUBLICATION_READS, draft_runs: 0, runs: 0 };
    assert!(!at_budget.over_budget(), "at the budget is inside it");
    let past = ReadPrice { homes: 1, entries: MAX_PUBLICATION_READS, draft_runs: 1, runs: 1 };
    assert!(past.over_budget(), "one past the budget is over");
    let huge = ReadPrice { homes: usize::MAX, entries: 2, draft_runs: usize::MAX, runs: 2 };
    assert_eq!(huge.total(), usize::MAX, "the price saturates");
    assert_eq!(price_publication_reads(world, Caller::System, &the_shot, &deposits).homes, 0, "no account, no homes");
    let draftless = Shot { draft: None, ..the_shot.clone() };
    assert_eq!(price_publication_reads(world, P1, &draftless, &deposits).draft_runs, 0, "no draft, no draft runs");
}

/// THE WORST-CASE TABLE, PINNED (the link-sets design §5.6, M6): each
/// constant of `sizes.rs` is the bytes the kernel prices the kind's records
/// at — measured here as the journal's growth across one commit staging the
/// kind, less the growth of the same commit without it, on a journaled
/// kernel at the shallow depth the table states. The commit marker is read
/// off two commits of one and two correspondence records; every other figure
/// is a difference of two commits of the same shape but the kind. A figure
/// that moves with an encoding fails here, and the table is re-pinned.
#[test]
fn the_worst_case_table_is_the_bytes_the_kernel_prices_each_kind_at() {
    use skep_links::{
        CLAIM_BYTES, COPY_BYTES, CORRESPONDENCE_RECORD_BYTES, EDITION_CLAIM_BYTES, EDITION_MINT_BYTES,
        KEPT_PLACE_BYTES, MAX_SLOT_SPANS, PLACED_RUN_BYTES, READ_WITH_BYTES, REINSERTED_VALUE_BYTES,
        RETRACTION_BYTES, SHOT_BYTES,
    };

    // The marker and the record, off a kernel of their own: one record,
    // then two — the marker is what one commit costs past its records.
    let records = journaled_over(deposits_world());
    let correspondence = |count: u32| {
        let before = records.journal_bytes();
        records
            .transact(&[M3State::link_lock_key(&doc1())], |stg| {
                for i in 0..count {
                    let (from, to) = (run(&ca(100 + 10 * i), 3), run(&pca(100 + 10 * i), 3));
                    stage_correspondence(stg, &ALL_VISIBLE, P1, &doc1(), &from, &to)?;
                }
                Ok::<(), PublicationError>(())
            })
            .expect("the records commit");
        records.journal_bytes() - before
    };
    let one = correspondence(1);
    let two = correspondence(2);
    let record = two - one;
    let marker = one - record;
    assert!(marker > 0 && record > marker, "one record outweighs the marker: {record} against {marker}");

    // The board, and the shots measured on it: each off the head with the
    // extent whole, so nothing is carried and the member holds `fresh` alone.
    let k = journaled_over(deposits_world());
    let (l, m) = board(&k);
    let base_shot = |fresh: Vec<ShotRun>| {
        let s = k.snapshot();
        let head = trunk_head(s.world().m3(), &pdoc()).expect("a head");
        let extent = s.world().m5().content_count(&head);
        let draft = (!fresh.is_empty()).then(doc1);
        Shot { base: Some(skep_arrangement::Base { member: head, extent }), draft, runs: fresh }
    };
    let measure = |f: &dyn Fn()| {
        let before = k.journal_bytes();
        f();
        k.journal_bytes() - before - marker
    };
    let commit = |target: &PublishTarget, the_shot: &Shot, places: &[Option<VPos>], deposits: &PublishDeposits| {
        writer(&k).publication(P1, target, the_shot, places, deposits).expect("the commit");
    };
    let into_e = PublishTarget::Document(pdoc());
    let none = PublishDeposits::default();
    let shot_bytes = measure(&|| commit(&into_e, &base_shot(vec![]), &[], &none));
    let window = measure(&|| commit(&into_e, &base_shot(vec![shot_run(&pdoc(), &pca(1), 3)]), &[], &none));
    let placed_run = window - shot_bytes;
    // The copy at every slot's budget: `from` and `to` at `MAX_SLOT_SPANS`
    // content I-spans of the shallow depth, the type at as many unit spans.
    let full = LinkEntry {
        home: NamedAddress::Member,
        from: EndArg::Spans((1..=MAX_SLOT_SPANS as u32).map(|i| run(&pca(i), 1).iextent()).collect()),
        to: EndArg::Spans((1..=MAX_SLOT_SPANS as u32).map(|i| run(&pca(i), 1).iextent()).collect()),
        ty: EndArg::Addrs((1..=MAX_SLOT_SPANS as u32).map(|i| NamedAddress::Address(a(&[1, 1, 0, 1, 0, 1, 0, 3, 23, i]))).collect()),
        old: None,
    };
    let with = |links: Vec<LinkEntry>, retract: Vec<Address>, read_with: Vec<Address>| PublishDeposits { links, retract, read_with };
    let copy = measure(&|| commit(&into_e, &base_shot(vec![]), &[], &with(vec![full.clone()], vec![], vec![]))) - shot_bytes;
    let small = |old: Option<Address>| entry(NamedAddress::Member, ispans(&pca(1), 3), addrs(&[&doc2()]), addrs(&[&citation()]), old);
    let small_alone = measure(&|| commit(&into_e, &base_shot(vec![]), &[], &with(vec![small(None)], vec![], vec![])));
    let small_claimed = measure(&|| commit(&into_e, &base_shot(vec![]), &[], &with(vec![small(Some(l.clone()))], vec![], vec![])));
    let claim = small_claimed - small_alone;
    let retraction = measure(&|| commit(&into_e, &base_shot(vec![]), &[], &with(vec![], vec![m.clone()], vec![]))) - shot_bytes;
    let read_with = measure(&|| commit(&into_e, &base_shot(vec![]), &[], &with(vec![], vec![], vec![set_s()]))) - shot_bytes;
    // The re-insert: an atom at ca(4), a byte at ca(5), a byte at ca(6)
    // re-windowed at its place — each shot placing its one fresh run, and
    // minting its one record.
    let vs = Vstream::new(&k);
    vs.insert(P1, &doc1(), vp(1, 4), vec![Val::new([b'x', b'y'])], Deposit::Undeclared).expect("an atom at ca(4)");
    vs.insert(P1, &doc1(), vp(1, 5), vec![Val::new([b'd'])], Deposit::Undeclared).expect("d at ca(5)");
    vs.insert(P1, &doc1(), vp(1, 6), vec![Val::new([b'e'])], Deposit::Undeclared).expect("e at ca(6)");
    let atom = measure(&|| commit(&into_e, &base_shot(vec![shot_run(&doc1(), &ca(4), 1)]), &[], &none)) - shot_bytes - placed_run - record;
    let byte = measure(&|| commit(&into_e, &base_shot(vec![shot_run(&doc1(), &ca(5), 1)]), &[], &none)) - shot_bytes - placed_run - record;
    let byte_placed = measure(&|| commit(&into_e, &base_shot(vec![shot_run(&doc1(), &ca(6), 1)]), &places(1, &[(0, 6)]), &none)) - shot_bytes - placed_run - record;
    let kept_place = byte_placed - byte;
    assert_eq!(bytes_of(&k, &doc1()), "abcxyde", "doc1 reads as it did, its last byte re-windowed");
    // The mint form: the edition's mint over a birth shot into `S`, the
    // claim over the mint form without one.
    let birth = Shot { base: None, draft: None, runs: vec![] };
    let birth_s = measure(&|| commit(&PublishTarget::Document(set_s()), &birth, &[], &none));
    let account = a(&[1, 0, 1]);
    let minted = measure(&|| commit(&PublishTarget::Mint { account: account.clone(), claim: false }, &birth, &[], &none));
    let edition_mint = minted - birth_s;
    let drafted = Shot { base: None, draft: Some(doc1()), runs: vec![] };
    let claimed = measure(&|| commit(&PublishTarget::Mint { account: account.clone(), claim: true }, &drafted, &[], &none));
    let edition_claim = claimed - minted;

    let table = [
        ("CORRESPONDENCE_RECORD_BYTES", record, CORRESPONDENCE_RECORD_BYTES),
        ("COPY_BYTES", copy, COPY_BYTES),
        ("CLAIM_BYTES", claim, CLAIM_BYTES),
        ("RETRACTION_BYTES", retraction, RETRACTION_BYTES),
        ("READ_WITH_BYTES", read_with, READ_WITH_BYTES),
        ("KEPT_PLACE_BYTES", kept_place, KEPT_PLACE_BYTES),
        ("PLACED_RUN_BYTES", placed_run, PLACED_RUN_BYTES),
        ("REINSERTED_VALUE_BYTES", atom, REINSERTED_VALUE_BYTES),
        ("SHOT_BYTES", shot_bytes, SHOT_BYTES),
        ("EDITION_MINT_BYTES", edition_mint, EDITION_MINT_BYTES),
        ("EDITION_CLAIM_BYTES", edition_claim, EDITION_CLAIM_BYTES),
    ];
    println!(
        "the marker: {marker}; a one-byte value's stretch and range mint: {byte}; a birth shot: {birth_s}; a copy at one span a slot: {}",
        small_alone - shot_bytes
    );
    for (name, measured, pinned) in table {
        println!("{name}: measured {measured}, pinned {pinned}");
    }
    for (name, measured, pinned) in table {
        assert_eq!(measured, pinned, "{name} moved: the kernel prices the kind at {measured} bytes, the table says {pinned}");
    }
    // The figures the module's cards quote beside the table: the marker the
    // kernel's own card states, the birth shape's shot, a byte run's stretch
    // and the one-span copy the arithmetic's second verdict reads.
    assert_eq!((marker, birth_s, byte, small_alone - shot_bytes), (109, 258, 301, 1_025), "the quoted figures");
}

#[test]
fn the_plan_is_a_pure_function_of_the_world_and_the_request() {
    let k = kernel_over(deposits_world());
    let (l, m) = board(&k);
    writer(&k).nullify(P1, &pmember(1), &m).expect("the mark taken off");
    let the_shot = shot_off_head(&k, vec![]);
    let deposits = PublishDeposits {
        links: vec![entry(NamedAddress::Member, member_spans(1, 3), addrs(&[&doc2()]), addrs(&[&citation()]), Some(l.clone()))],
        retract: vec![m.clone()],
        read_with: vec![set_s()],
    };
    let snap = k.snapshot();
    let target = PublishTarget::Document(pdoc());
    let once = plan_deposits(snap.world(), P1, &target, &the_shot, &deposits).expect("a plan");
    let twice = plan_deposits(snap.world(), P1, &target, &the_shot, &deposits).expect("a plan");
    assert_eq!(once, twice, "the same world, the same plan");
    let homes: Vec<&NamedAddress> = once.homes.iter().map(|h| &h.home).collect();
    assert_eq!(homes, vec![&NamedAddress::Member, &NamedAddress::Address(set_s())], "the member first, then S; the skipped retraction's home absent");
    assert!(matches!(once.homes[0].deposits[..], [PlannedDeposit::Copy { index: 0, .. }]));
    assert!(matches!(once.homes[1].deposits[..], [PlannedDeposit::ReadWith { index: 0, .. }]));
    // Over the base the transaction opens on — the same snapshot, nothing
    // between — the plan the composite reads is this one.
    let again = plan_deposits(k.snapshot().world(), P1, &target, &the_shot, &deposits).expect("a plan");
    assert_eq!(again, once);
}
