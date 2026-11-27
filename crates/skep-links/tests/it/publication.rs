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
//! arranged it elsewhere since P4 … never a guess". The commit stages that
//! pair as ONE record a re-windowed draft, every kept place of the draft
//! checked on one walk of its run-list (M5's `stage_substitute`), and the
//! price counts it as a sum: the draft's runs and the pieces placed. The
//! check is by
//! MEMBERSHIP (the S-gate's ruling): the named place alone, a draft
//! arranging the identity twice re-windowed at the named place and left
//! standing at the other. A request with no place is today's shot: the S1
//! cells above pass unchanged, carrying none.

use skep_address::{Address, Span, SpanSet};
use skep_arrangement::AsOf;
use skep_arrangement::{
    head_lock_key, trunk_head, Caller, Deposit, DraftBase, HasM5, PublishError, ReinstateError, Run,
    Shot, ShotRun, VPos, Vstream,
};
use skep_content::{HasContent, Val};
use skep_kernel::{Attestation, Kernel, Seq, TxnError};
use skep_links::{
    correspondence_type, enc, is_correspondence_class, stage_correspondence, stage_publication,
    AlsoPlaces, Endset, HasLinks, Link, LinkWriter, PublicationError, PublishDeposits,
    PublishTarget, SlotArg, Visibility, FROM, TO,
};
use skep_namespace::{first_version_address, HasM3, M3Rec, M3State, PrincipalId};

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
        also: vec![],
        keep_base: false,
        runs,
        stretches: Vec::new(),
    }
}

/// doc1 holding `text`, one byte a position from `ca(1)`, as P1's insert.
fn draft_holding(k: &Kernel<World>, text: &str) {
    let vals: Vec<Val> = text.bytes().map(|b| Val::new([b])).collect();
    Vstream::new(k)
        .insert(P1, &doc1(), vp(1, 1), vals, Deposit::Undeclared, AsOf::Typed(k.current_seq()))
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
        .publication(P1, &PublishTarget::Document(pdoc()), &shot(None, vec![shot_run(&doc1(), &ca(2), 2), shot_run(&doc1(), &ca(1), 3)]), &[], &[], &PublishDeposits::default())
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
    let (m1, _) = w.publication(P1, &PublishTarget::Document(pdoc()), &shot(None, vec![shot_run(&doc1(), &ca(1), 3)]), &[], &[], &PublishDeposits::default()).expect("the first shot");
    // A second member, placing the published words by reference and a
    // fresh `d` from the draft: a record for `d` alone.
    Vstream::new(&k).insert(P1, &doc1(), vp(1, 4), vec![Val::new([b'd'])], Deposit::Undeclared, AsOf::Typed(k.current_seq())).expect("d at ca(4)");
    let (m2, _) = w
        .publication(P1, &PublishTarget::Document(pdoc()), &shot(Some((&m1, 3)), vec![shot_run(&pdoc(), &pca(1), 3), shot_run(&doc1(), &ca(4), 1)]), &[], &[], &PublishDeposits::default())
        .expect("a fresh run lands");
    assert_eq!((m1, m2.clone()), (pmember(1), pmember(2)));
    assert_eq!(records_in_doc1(&k).len(), 2, "one record per shot that re-inserted: a b c, then d");
    assert_eq!(bytes_of(&k, &m2), "abcd");

    let before = k.snapshot();
    // `b` alone: a sub-run of the first record's `from`, split from its run.
    let refusal = refused(w.publication(P1, &PublishTarget::Document(pdoc()), &shot(Some((&m2, 4)), vec![shot_run(&doc1(), &ca(2), 1)]), &[], &[], &PublishDeposits::default()));
    assert_eq!(
        refusal,
        PublicationError::AlreadyPublished { site: pmember(1) },
        "the record's own member — the first, though the second arranges the span too"
    );
    // The whole run again, and a run straddling the record's reach.
    for run in [shot_run(&doc1(), &ca(1), 3), shot_run(&doc1(), &ca(3), 2)] {
        assert_eq!(
            refused(w.publication(P1, &PublishTarget::Document(pdoc()), &shot(Some((&m2, 4)), vec![run]), &[], &[], &PublishDeposits::default())),
            PublicationError::AlreadyPublished { site: pmember(1) }
        );
    }
    let s = k.snapshot();
    assert_eq!(s.seq(), before.seq(), "nothing committed");
    assert!(!s.world().m3().is_registered_document(&pmember(3)), "no member minted");
    assert_eq!(records_in_doc1(&k).len(), 2, "no record minted");

    // The parent type is an ordinary link, admitted at the open surface:
    // one FROM `e`, never published, fences nothing.
    Vstream::new(&k).insert(P1, &doc1(), vp(1, 5), vec![Val::new([b'e'])], Deposit::Undeclared, AsOf::Typed(k.current_seq())).expect("e at ca(5)");
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
        .publication(P1, &PublishTarget::Document(pdoc()), &shot(Some((&m2, 4)), vec![shot_run(&pdoc(), &pca(1), 4), shot_run(&doc1(), &ca(5), 1)]), &[], &[], &PublishDeposits::default())
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
    w.publication(P1, &PublishTarget::Document(pdoc()), &shot(None, vec![shot_run(&doc1(), &ca(1), 3)]), &[], &[], &PublishDeposits::default()).expect("P1 publishes a b c");
    let before = k.snapshot();
    let theirs = Shot { base: None, draft: Some(doc1()), also: vec![], keep_base: false, runs: vec![shot_run(&doc1(), &ca(2), 1)], stretches: Vec::new() };
    assert_eq!(
        refused(w.publication(P2, &PublishTarget::Document(sib_doc()), &theirs, &[], &[], &PublishDeposits::default())),
        PublicationError::Publish(PublishError::NotOwner(doc1())),
        "the draft is P1's: ω, not the fence"
    );
    assert_eq!(
        refused(w.publication(Caller::System, &PublishTarget::Document(sib_doc()), &theirs, &[], &[], &PublishDeposits::default())),
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
        also: vec![],
        keep_base: false,
        runs: vec![],
        stretches: Vec::new(),
    };
    let seq0 = k.current_seq();
    let (m1, s1) = Vstream::new(&k).publish(P1, &pdoc(), &own(None, None), &ALL_VISIBLE).expect("the shot alone");
    let shot_alone = s1.0 - seq0.0;
    let (m2, s2) = writer(&k).publication(P1, &PublishTarget::Document(pdoc()), &own(Some((&m1, 0)), None), &[], &[], &PublishDeposits::default()).expect("no draft");
    assert_eq!(s2.0 - s1.0, shot_alone, "the same records as the shot alone");
    let (_, s3) = writer(&k).publication(P1, &PublishTarget::Document(pdoc()), &own(Some((&m2, 0)), Some(doc1())), &[], &[], &PublishDeposits::default()).expect("a draft, nothing re-inserted");
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
        stage_publication(stg, P1, &PublishTarget::Document(pdoc()), &the_shot, &[], &[], &PublishDeposits::default(), &ALL_VISIBLE)?;
        Err(PublicationError::HomeNotRegistered)
    });
    assert!(matches!(r, Err(TxnError::Rejected(PublicationError::HomeNotRegistered))));
    assert_eq!(k.current_seq(), before, "nothing committed");
    assert!(records_in_doc1(&k).is_empty());
    assert!(!k.snapshot().world().m3().is_registered_document(&pmember(1)), "no member");
    // The composite beside a staging of the caller's own, in one commit.
    let (member, _) = k
        .transact(&keys, |stg| {
            let (member, _) = stage_publication(stg, P1, &PublishTarget::Document(pdoc()), &the_shot, &[], &[], &PublishDeposits::default(), &ALL_VISIBLE)?;
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
        staged(P1, a(&[1, 0, 1, 0, 71])),
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
    let (m1, s1) = attested.publication(P1, &PublishTarget::Document(pdoc()), &shot(None, vec![shot_run(&doc1(), &ca(1), 2)]), &[], &[], &PublishDeposits::default()).expect("attested");
    let (_, s2) = writer(&k)
        .publication(P1, &PublishTarget::Document(pdoc()), &shot(Some((&m1, 2)), vec![shot_run(&pdoc(), &pca(1), 2), shot_run(&doc1(), &ca(3), 1)]), &[], &[], &PublishDeposits::default())
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
        vs.insert(P1, &doc1(), vp(1, 1), vec![Val::new([b'a'])], Deposit::Undeclared, AsOf::Typed(k.current_seq())).expect("a at ca(1)");
        vs.insert(P1, &doc1(), vp(1, 2), vec![Val::new([b'c'])], Deposit::Undeclared, AsOf::Typed(k.current_seq())).expect("c at ca(2)");
        vs.insert(P1, &doc1(), vp(1, 2), vec![Val::new([b'b'])], Deposit::Undeclared, AsOf::Typed(k.current_seq())).expect("b at ca(3), between");
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

        let the_shot = Shot { base: None, draft: Some(doc1()), also: vec![], keep_base: false, runs: vec![ShotRun { origin: doc1(), run: named.clone() }], stretches: Vec::new() };
        let (member, seq) = writer(&k)
            .publication(P1, &PublishTarget::Document(pdoc()), &the_shot, &places(1, &[(0, place)]), &[], &PublishDeposits::default())
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

/// A shot keeping its draft's base (skep #944) is re-windowed as any shot.
///
/// The draft is staged from the memberless edition, so the board records a
/// base for it, and holds `a b` as its own run. The shot names it as the
/// rendering draft with its kept place: with `keep_base` the one commit
/// still homes the record in the draft and re-windows it at the place, and
/// the draft's recorded base stands as the stage wrote it; without the flag
/// the same commit moves the base to the member it minted.
#[test]
fn a_shot_keeping_its_drafts_base_re_windows_the_draft_and_leaves_its_base_standing() {
    for keep_base in [true, false] {
        let k = journaled_over(edition_world());
        let vs = Vstream::new(&k);
        let (d, _) = vs.stage(PrincipalId(1), &pdoc()).expect("a draft of the memberless edition");
        assert_eq!(d, minted(1), "the premise: the first document the account's counter hands out here");
        let (start, _) = vs
            .insert(P1, &d, vp(1, 1), vec![Val::new(*b"a"), Val::new(*b"b")], Deposit::Undeclared, AsOf::Typed(k.current_seq()))
            .expect("the draft's own words");
        let recorded = k.snapshot().world().m5().draft_base(&d).cloned().expect("the stage records a base");
        let named = run(&start, 2);
        let the_shot = Shot {
            base: Some(skep_arrangement::Base { member: pdoc(), extent: n(0) }),
            draft: Some(d.clone()),
            also: vec![],
            keep_base,
            runs: vec![ShotRun { origin: d.clone(), run: named.clone() }],
            stretches: Vec::new(),
        };
        let (member, _) = writer(&k)
            .publication(P1, &PublishTarget::Document(pdoc()), &the_shot, &places(1, &[(0, 1)]), &[], &PublishDeposits::default())
            .expect("the one commit stands whole");
        let fresh = run(&pca(1), 2);
        assert_eq!(runs_of(&k, &d), vec![fresh.clone()], "keep_base {keep_base}: re-windowed at its place");
        assert_eq!(bytes_of(&k, &d), "ab", "keep_base {keep_base}");
        let s = k.snapshot();
        let homed = s.world().links().readlink(&link_of(&minted(1), 1)).cloned();
        assert_eq!(homed, Some(record(&named, &fresh)), "keep_base {keep_base}: the record homed in the draft");
        let moved = DraftBase { base: member.clone(), extent: n(2), source: pdoc(), merge: None, stamped: vec![] };
        assert_eq!(
            s.world().m5().draft_base(&d),
            Some(if keep_base { &recorded } else { &moved }),
            "keep_base {keep_base}: the base stands where the shot keeps it, else moves to the member"
        );
    }
}

/// What the draft did to a named run between the kept place's reading and
/// the commit, and what the check must find.
struct Since {
    what: &'static str,
    /// The edit doc1 takes after the places are read.
    disturb: fn(&Kernel<World>, &Vstream<'_, World>),
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
            disturb: |k, vs| {
                vs.rearrange(P1, &doc1(), &[vp(1, 2), vp(1, 3), vp(1, 4)], AsOf::Typed(k.current_seq())).expect("a c b d");
            },
            after: "acbd",
        },
        Since {
            what: "moved after d",
            disturb: |k, vs| {
                vs.rearrange(P1, &doc1(), &[vp(1, 2), vp(1, 4), vp(1, 5)], AsOf::Typed(k.current_seq())).expect("a d b c");
            },
            after: "adbc",
        },
        Since {
            what: "split",
            disturb: |k, vs| {
                vs.insert(P1, &doc1(), vp(1, 3), vec![Val::new([b'x'])], Deposit::Undeclared, AsOf::Typed(k.current_seq())).expect("a b x c d");
            },
            after: "abxcd",
        },
        Since {
            what: "deleted",
            disturb: |k, vs| {
                vs.delete(P1, &doc1(), vp(1, 2), n(1), AsOf::Typed(k.current_seq())).expect("a c d");
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
        (cell.disturb)(&k, &Vstream::new(&k));
        let disturbed = k.snapshot();
        assert_eq!(bytes_of(&k, &doc1()), cell.after, "{}", cell.what);
        let runs_before = runs_of(&k, &doc1());
        let stored_before = disturbed.world().content().len();

        let the_shot = Shot {
            base: None,
            draft: Some(doc1()),
            also: vec![],
            keep_base: false,
            runs: vec![ShotRun { origin: doc1(), run: a.clone() }, ShotRun { origin: doc1(), run: bc.clone() }],
            stretches: Vec::new(),
        };
        let refusal = refused(writer(&k).publication(P1, &PublishTarget::Document(pdoc()), &the_shot, &places(2, &[(0, 1), (1, 2)]), &[], &PublishDeposits::default()));
        assert_eq!(
            refusal,
            PublicationError::KeptPlaceMoved { index: 1, draft: doc1() },
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
        Vstream::new(&k).copy(P1, &doc1(), vp(1, 4), &[spec(&doc1(), 1, 2, 1)], AsOf::Typed(k.current_seq())).expect("a b c b: b twice");
        let b = run(&ca(2), 1);
        assert_eq!(bytes_of(&k, &doc1()), "abcb");
        assert_eq!(footprint(&k, &doc1(), &b), spans(&[(2, 1), (4, 1)]), "the premise: the identity at two places");

        let the_shot = Shot { base: None, draft: Some(doc1()), also: vec![], keep_base: false, runs: vec![ShotRun { origin: doc1(), run: b.clone() }], stretches: Vec::new() };
        let (member, _) = writer(&k).publication(P1, &PublishTarget::Document(pdoc()), &the_shot, &places(1, &[(0, named)]), &[], &PublishDeposits::default()).expect("the named place holds");
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
    Vstream::new(&k).copy(P1, &doc1(), vp(1, 4), &[spec(&doc1(), 1, 2, 1)], AsOf::Typed(k.current_seq())).expect("a b c b");
    let b = run(&ca(2), 1);
    let the_shot = Shot {
        base: None,
        draft: Some(doc1()),
        also: vec![],
        keep_base: false,
        runs: vec![ShotRun { origin: doc1(), run: b.clone() }, ShotRun { origin: doc1(), run: b.clone() }],
        stretches: Vec::new(),
    };
    let (member, _) = writer(&k).publication(P1, &PublishTarget::Document(pdoc()), &the_shot, &places(2, &[(0, 2), (1, 4)]), &[], &PublishDeposits::default()).expect("both places hold");
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
/// the chain) takes the shot and its record, and then the re-window's gate
/// refuses `published_target` — the verdict `reinstate` answers a published
/// destination, lowered as `Reinstate` — and the whole publication falls
/// with it: no member, no record. The gate answers ahead of every entry's
/// check, so a place the draft does not hold the run at is refused
/// `published_target` too, never `kept_place_moved`. With no place the same
/// shot lands, the published draft's words re-inserted and the draft left
/// as it stands.
#[test]
fn a_published_document_named_as_the_draft_is_refused_at_its_gate_and_lands_with_no_place() {
    let published_draft = doc(4);
    let world = edition_world();
    let k = kernel_over(World { m3: world.m3.apply_m3(Seq(0), &M3Rec::allocate(published_draft.clone(), true)), ..world });
    Vstream::new(&k)
        .insert(P1, &published_draft, vp(1, 1), vec![Val::new([b'q'])], Deposit::Declared(skep_arrangement::deposit_class_types()[0].clone()), AsOf::Typed(k.current_seq()))
        .expect("a declared deposit at the published document's fresh position");
    let q = Run::new(a(&[1, 0, 1, 0, nth_doc(4), 0, 1, 1]), n(1)).expect("a run");
    let the_shot = Shot { base: None, draft: Some(published_draft.clone()), also: vec![], keep_base: false, runs: vec![ShotRun { origin: published_draft.clone(), run: q }], stretches: Vec::new() };
    let before = k.current_seq();
    assert_eq!(
        refused(writer(&k).publication(P1, &PublishTarget::Document(pdoc()), &the_shot, &places(1, &[(0, 1)]), &[], &PublishDeposits::default())),
        PublicationError::Reinstate(ReinstateError::PublishedTarget)
    );
    assert_eq!(
        refused(writer(&k).publication(P1, &PublishTarget::Document(pdoc()), &the_shot, &places(1, &[(0, 5)]), &[], &PublishDeposits::default())),
        PublicationError::Reinstate(ReinstateError::PublishedTarget),
        "a place the draft does not hold the run at: the gate answers before the entry is checked"
    );
    assert_eq!(k.current_seq(), before, "nothing committed");
    assert!(!k.snapshot().world().m3().is_registered_document(&pmember(1)), "no member");
    let (member, _) = writer(&k).publication(P1, &PublishTarget::Document(pdoc()), &the_shot, &[], &[], &PublishDeposits::default()).expect("with no place, today's shot");
    assert_eq!(bytes_of(&k, &member), "q");
    assert_eq!(bytes_of(&k, &published_draft), "q", "the published draft stands");
}

// ───────────────────────── the stray places (F4) ─────────────────────────

/// doc2's content element `k`: `[1,0,1,0,nth_doc(2),0,1,k]`.
fn ca2(k: u32) -> Address {
    a(&[1, 0, 1, 0, nth_doc(2), 0, 1, k])
}

/// The board every stray cell opens over: doc1 `a b c`, published once with
/// `b c` at its place — doc1 arranging its own `a` and then E.1's fresh
/// `b c` (`pca(1..=2)`), one record `(ca(2..=3) → pca(1..=2))` — and then
/// THE STRAY ACT: a raw `reinstate` of the draft's own `b c` after them, so
/// doc1 reads `a b c b c` and arranges the record's `from`, private text
/// again, at 4. Answers `E.1`.
fn stray_board(k: &Kernel<World>) -> Address {
    draft_holding(k, "abc");
    let the_shot = Shot { base: None, draft: Some(doc1()), also: vec![], keep_base: false, runs: vec![shot_run(&doc1(), &ca(2), 2)], stretches: Vec::new() };
    let (member, _) = writer(k).publication(P1, &PublishTarget::Document(pdoc()), &the_shot, &places(1, &[(0, 2)]), &[], &PublishDeposits::default()).expect("E.1");
    Vstream::new(k).reinstate(P1, &doc1(), vp(1, 4), &[ShotRun { origin: doc1(), run: run(&ca(2), 2) }], AsOf::Typed(k.current_seq())).expect("the stray act");
    assert_eq!(bytes_of(k, &doc1()), "abcbc");
    assert_eq!(runs_of(k, &doc1()), vec![run(&ca(1), 1), run(&pca(1), 2), run(&ca(2), 2)], "the premise: the record's from, back in the draft at 4");
    assert_eq!(records_in_doc1(k), vec![record(&run(&ca(2), 2), &run(&pca(1), 2))]);
    member
}

/// THE STRAY (the link-sets design §5.7, "AND THE STRAY PLACES WITH THEM"):
/// a second publication whose `runs` names the stray words BY REFERENCE to
/// the record's `to` — E's own identity, a run the pairing never holds —
/// with their kept place beside it: ONE commit (one boundary on a journaled
/// kernel) after which doc1 reads the same bytes and arranges E's identity
/// at the place, the draft-native words arranged nowhere in it; the member
/// holds the run by reference, twice, as any run of the document's own;
/// NO new record, the S1 record standing alone; no identity minted.
#[test]
fn a_stray_run_re_composed_by_reference_to_its_record_is_re_windowed_at_its_kept_place_in_one_commit() {
    let k = journaled_over(edition_world());
    stray_board(&k);
    let before = k.snapshot();
    // The head's `b c` by reference, then the stray run re-composed by
    // reference to the record's `to`, its place beside it.
    let the_shot = shot_off_head(&k, vec![shot_run(&pdoc(), &pca(1), 2)]);
    assert_eq!(the_shot.runs.len(), 2);
    let (member, seq) = writer(&k)
        .publication(P1, &PublishTarget::Document(pdoc()), &the_shot, &places(2, &[(1, 4)]), &[], &PublishDeposits::default())
        .expect("the stray re-window commits");
    assert_eq!(member, pmember(2));
    assert_eq!(k.boundaries_above(before.seq()).expect("a journaled kernel answers its boundaries"), vec![(seq, None)], "ONE commit");
    assert_eq!(bytes_of(&k, &doc1()), "abcbc", "the draft reads the same bytes at every position");
    assert_eq!(runs_of(&k, &doc1()), vec![run(&ca(1), 1), run(&pca(1), 2), run(&pca(1), 2)], "E's identity at the place");
    assert!(footprint(&k, &doc1(), &run(&ca(2), 2)).is_empty(), "the draft-native words arranged nowhere in the draft");
    assert_eq!(footprint(&k, &doc1(), &run(&pca(1), 2)), spans(&[(2, 4)]), "E's identity at 2 and at 4, one V-span to the projection");
    assert_eq!(runs_of(&k, &member), vec![run(&pca(1), 2), run(&pca(1), 2)], "the member holds the run by reference, twice");
    assert_eq!(bytes_of(&k, &member), "bcbc");
    assert_eq!(records_in_doc1(&k), vec![record(&run(&ca(2), 2), &run(&pca(1), 2))], "NO new record: the S1 record stands alone");
    assert_eq!(k.snapshot().world().m3().next_content_address(&pdoc()), Some(pca(3)), "no identity minted");
    assert_eq!(trunk_head(k.snapshot().world().m3(), &pdoc()), Some(member));
}

/// A DRAFT LEFT AS IT STANDS (§5.1's residue; "shot again, it meets the
/// twin fence at every run already published from it, and those runs are
/// re-composed by reference to the records' `to` … re-windowed onto them at
/// their kept places"): today's shot of `b c` with no place leaves doc1
/// arranging the record's `from`; the next shot re-supplies the whole draft
/// — `a` draft-native with its place, `b c` by reference to the record's
/// `to` with its — and the one commit re-windows both kinds: doc1 reads
/// `a b c`, arranges `a`'s fresh identity at 1 and E's `b c` at 2, its own
/// words nowhere; two records, `a`'s new beside `b c`'s standing.
#[test]
fn a_draft_left_arranging_published_words_is_re_windowed_by_the_next_shot_that_sends_their_place() {
    let k = kernel_over(edition_world());
    draft_holding(&k, "abc");
    let first = Shot { base: None, draft: Some(doc1()), also: vec![], keep_base: false, runs: vec![shot_run(&doc1(), &ca(2), 2)], stretches: Vec::new() };
    writer(&k).publication(P1, &PublishTarget::Document(pdoc()), &first, &[], &[], &PublishDeposits::default()).expect("today's shot");
    assert_eq!(runs_of(&k, &doc1()), vec![run(&ca(1), 3)], "the draft left as it stands");
    let the_shot = Shot {
        base: Some(skep_arrangement::Base { member: pmember(1), extent: n(2) }),
        draft: Some(doc1()),
        also: vec![],
        keep_base: false,
        runs: vec![shot_run(&doc1(), &ca(1), 1), shot_run(&pdoc(), &pca(1), 2)],
        stretches: Vec::new(),
    };
    let (member, _) = writer(&k)
        .publication(P1, &PublishTarget::Document(pdoc()), &the_shot, &places(2, &[(0, 1), (1, 2)]), &[], &PublishDeposits::default())
        .expect("both kinds of place hold");
    assert_eq!(member, pmember(2));
    assert_eq!(bytes_of(&k, &doc1()), "abc");
    assert_eq!(runs_of(&k, &doc1()), vec![run(&pca(3), 1), run(&pca(1), 2)], "a's fresh identity, then E's b c");
    assert!(footprint(&k, &doc1(), &run(&ca(1), 3)).is_empty(), "the draft's own words arranged nowhere");
    assert_eq!(bytes_of(&k, &member), "abc");
    assert_eq!(records_in_doc1(&k), vec![record(&run(&ca(2), 2), &run(&pca(1), 2)), record(&run(&ca(1), 1), &run(&pca(3), 1))], "b c's standing, a's new");
}

/// A PIECE, AND ACROSS TWO RECORDS: doc1 `a b c d e` published twice with
/// places — `b c` into E.1, `d e` into E.2, two records whose `to` spans
/// adjoin (`pca(1..=2)`, `pca(3..=4)`) — then two stray acts, `c` alone
/// (a piece of the first record's `from`, at offset 1) and `b c d e` (across
/// both records); the shot re-composes the first as `pca(2)` and the second
/// as `pca(1..=4)`, each with its place, and the one commit re-windows the
/// piece at its offset and the span piece by piece — the draft holding the
/// two records' words as one run, which the check walks as one — leaving
/// doc1 reading the same bytes with E's identity at both places, the
/// records as they were, no identity minted.
#[test]
fn a_stray_run_that_is_a_piece_of_a_record_or_spans_two_records_is_re_windowed_piece_by_piece() {
    let k = journaled_over(edition_world());
    draft_holding(&k, "abcde");
    let none = PublishDeposits::default();
    let into_e = PublishTarget::Document(pdoc());
    let first = Shot { base: None, draft: Some(doc1()), also: vec![], keep_base: false, runs: vec![shot_run(&doc1(), &ca(2), 2)], stretches: Vec::new() };
    writer(&k).publication(P1, &into_e, &first, &places(1, &[(0, 2)]), &[], &none).expect("E.1");
    let second = shot_off_head(&k, vec![shot_run(&doc1(), &ca(4), 2)]);
    writer(&k).publication(P1, &into_e, &second, &places(2, &[(1, 4)]), &[], &none).expect("E.2");
    assert_eq!(runs_of(&k, &doc1()), vec![run(&ca(1), 1), run(&pca(1), 4)], "the premise: the fresh identity adjoining, one run");
    assert_eq!(records_in_doc1(&k), vec![record(&run(&ca(2), 2), &run(&pca(1), 2)), record(&run(&ca(4), 2), &run(&pca(3), 2))]);
    let vs = Vstream::new(&k);
    vs.reinstate(P1, &doc1(), vp(1, 6), &[ShotRun { origin: doc1(), run: run(&ca(3), 1) }], AsOf::Typed(k.current_seq())).expect("c, the piece");
    vs.reinstate(P1, &doc1(), vp(1, 7), &[ShotRun { origin: doc1(), run: run(&ca(2), 4) }], AsOf::Typed(k.current_seq())).expect("b c d e, across both");
    assert_eq!(bytes_of(&k, &doc1()), "abcdecbcde");
    let before = k.snapshot();
    let the_shot = shot_off_head(&k, vec![shot_run(&pdoc(), &pca(2), 1), shot_run(&pdoc(), &pca(1), 4)]);
    assert_eq!(the_shot.runs.len(), 3, "the head's run, the piece, the span");
    let (member, seq) = writer(&k).publication(P1, &into_e, &the_shot, &places(3, &[(1, 6), (2, 7)]), &[], &none).expect("piece by piece");
    assert_eq!(member, pmember(3));
    assert_eq!(k.boundaries_above(before.seq()).expect("boundaries"), vec![(seq, None)], "ONE commit");
    assert_eq!(bytes_of(&k, &doc1()), "abcdecbcde", "the same bytes");
    assert_eq!(runs_of(&k, &doc1()), vec![run(&ca(1), 1), run(&pca(1), 4), run(&pca(2), 1), run(&pca(1), 4)], "E's identity at both places");
    assert!(footprint(&k, &doc1(), &run(&ca(2), 4)).is_empty(), "the draft-native words arranged nowhere");
    assert_eq!(bytes_of(&k, &member), "bcdecbcde");
    assert_eq!(records_in_doc1(&k).len(), 2, "no new record");
    assert_eq!(k.snapshot().world().m3().next_content_address(&pdoc()), Some(pca(5)), "no identity minted");
}

/// MOVED, OR ALREADY PUBLISHED THERE: the stray words edited after their
/// place was read — `b` of the stray `b c` deleted, doc1 `a b c c` — refuse
/// the publication `KeptPlaceMoved` with the entry, nothing committed; and
/// a place where doc1 already arranges E's identity (the re-windowed `b c`
/// at 2) names no draft words to re-window and is refused the same — the
/// check asks for the record's `from` at the place, never a guess.
#[test]
fn a_stray_run_whose_draft_words_moved_since_is_refused_with_its_entry_and_writes_nothing() {
    let k = kernel_over(edition_world());
    stray_board(&k);
    Vstream::new(&k).delete(P1, &doc1(), vp(1, 4), n(1), AsOf::Typed(k.current_seq())).expect("a b c c");
    assert_eq!(bytes_of(&k, &doc1()), "abcc");
    let disturbed = k.snapshot();
    let runs_before = runs_of(&k, &doc1());
    let the_shot = shot_off_head(&k, vec![shot_run(&pdoc(), &pca(1), 2)]);
    for (place, what) in [(4u32, "the stray words moved"), (2, "E's identity already there")] {
        let refusal = refused(writer(&k).publication(P1, &PublishTarget::Document(pdoc()), &the_shot, &places(2, &[(1, place)]), &[], &PublishDeposits::default()));
        assert_eq!(refusal, PublicationError::KeptPlaceMoved { index: 1, draft: doc1() }, "{what}");
        let s = k.snapshot();
        assert_eq!(s.seq(), disturbed.seq(), "{what}: nothing committed");
        assert!(!s.world().m3().is_registered_document(&pmember(2)), "{what}: no member");
        assert_eq!(runs_of(&k, &doc1()), runs_before, "{what}: the draft unchanged");
        assert_eq!(records_in_doc1(&k).len(), 1, "{what}: the one record");
    }
}

/// RECORDED ELSEWHERE, OR UNRECORDED: the stray read runs over every
/// correspondence record the caller may read whose `to` covers the run,
/// WHEREVER HOMED — so E's `x y`, minted from doc2's words and recorded in
/// doc2 alone, IS found from doc1's shot (the same caller's), and the check
/// then asks doc1 for doc2's words at the place, where doc1 arranges its
/// own `a`: `KeptPlaceMoved` with the entry; `b c x`, covered by doc1's
/// record and doc2's together, tiles whole and fails the check the same
/// way. `StrayPlaceUnrecorded` keeps two premises: a window onto doc2's
/// own words, which no record names — refused, never silently kept — and
/// `x y` at a visibility class that does not admit doc2, the record's home
/// unreadable to the caller: a record the caller may not read is never
/// used. Each commits nothing: the shot's mints and the re-window of an
/// earlier entry are discarded with it.
#[test]
fn a_stray_run_no_record_the_caller_may_read_covers_whole_is_refused_with_its_entry_and_writes_nothing() {
    let k = kernel_over(edition_world());
    stray_board(&k);
    let into_e = PublishTarget::Document(pdoc());
    let none = PublishDeposits::default();
    Vstream::new(&k)
        .insert(P1, &doc2(), vp(1, 1), "xy".bytes().map(|b| Val::new([b])).collect(), Deposit::Undeclared, AsOf::Typed(k.current_seq()))
        .expect("doc2 holding x y");
    let from_doc2 = Shot {
        base: Some(skep_arrangement::Base { member: pmember(1), extent: n(2) }),
        draft: Some(doc2()),
        also: vec![],
        keep_base: false,
        runs: vec![shot_run(&pdoc(), &pca(1), 2), shot_run(&doc2(), &ca2(1), 2)],
        stretches: Vec::new(),
    };
    writer(&k).publication(P1, &into_e, &from_doc2, &[], &[], &none).expect("E.2, x y minted from doc2");
    assert_eq!(bytes_of(&k, &pmember(2)), "bcxy");
    let before = k.snapshot();
    // The caller's visibility class that does not admit doc2: the record
    // homed there is the caller's own, and still never read.
    let all_but_doc2: &Visibility<'_, World> = &|_: &World, d: &Address| *d != doc2();
    let cells: [(&str, ShotRun, &Visibility<'_, World>, PublicationError); 4] = [
        ("x y, recorded in doc2 alone: found, and doc1 arranges `a` at the place", shot_run(&pdoc(), &pca(3), 2), &ALL_VISIBLE, PublicationError::KeptPlaceMoved { index: 2, draft: doc1() }),
        ("b c x, covered by doc1's record and doc2's: found whole, the check fails", shot_run(&pdoc(), &pca(1), 3), &ALL_VISIBLE, PublicationError::KeptPlaceMoved { index: 2, draft: doc1() }),
        ("a window onto doc2's own words: no record names them", shot_run(&doc2(), &ca2(1), 2), &ALL_VISIBLE, PublicationError::StrayPlaceUnrecorded { index: 2, draft: doc1() }),
        ("x y, its record homed in a draft the caller may not read", shot_run(&pdoc(), &pca(3), 2), all_but_doc2, PublicationError::StrayPlaceUnrecorded { index: 2, draft: doc1() }),
    ];
    for (what, stray, readable, expected) in cells {
        // The head's run by reference, the stray `b c` with its place (which
        // holds), then the entry under test with a place of its own.
        let mut the_shot = shot_off_head(&k, vec![shot_run(&pdoc(), &pca(1), 2), stray]);
        the_shot.draft = Some(doc1());
        assert_eq!(the_shot.runs.len(), 3, "{what}");
        let refusal = refused(writer_at(&k, readable).publication(P1, &into_e, &the_shot, &places(3, &[(1, 4), (2, 1)]), &[], &none));
        assert_eq!(refusal, expected, "{what}");
        let s = k.snapshot();
        assert_eq!(s.seq(), before.seq(), "{what}: nothing committed, the first entry's re-window with it");
        assert_eq!(bytes_of(&k, &doc1()), "abcbc", "{what}");
        assert_eq!(runs_of(&k, &doc1()), vec![run(&ca(1), 1), run(&pca(1), 2), run(&ca(2), 2)], "{what}: the draft unchanged");
        assert!(!s.world().m3().is_registered_document(&pmember(3)), "{what}: no member");
    }
}

/// #747 HEALED (the stray read widened): a family publication that sent NO
/// place beside doc2's run — none in `places`, no `also_places` entry: an
/// earlier client's request, or a raw op's — re-mints doc2's words with the
/// record homed in doc2 and leaves the rendering draft doc1, holding those
/// words by identity, arranging doc2's old identity for them, and doc2 as
/// it stands; at doc1's OWN next shot the run re-composed to the trunk's
/// identity is sent with doc1's place in `places` and — doc2 named `also`
/// beside it — with doc2's place in `also_places`, and the one commit finds
/// doc2's record by its `to`, wherever homed, and re-windows BOTH drafts
/// there by the stray path: the same bytes in each, E's identity where
/// doc2's stood, doc2's record standing alone, no identity minted, ONE
/// commit.
#[test]
fn a_rendering_draft_holding_an_also_drafts_published_words_heals_at_its_own_next_shot_through_that_drafts_record() {
    let k = journaled_over(edition_world());
    draft_holding(&k, "ab");
    other_draft_holding(&k, "xy");
    Vstream::new(&k).copy(P1, &doc1(), vp(1, 3), &[spec(&doc2(), 1, 1, 2)], AsOf::Typed(k.current_seq())).expect("doc1 a b x y, doc2's words by identity");
    assert_eq!(runs_of(&k, &doc1()), vec![run(&ca(1), 2), run(&ca2(1), 2)]);
    let into = PublishTarget::Document(pdoc());
    let none = PublishDeposits::default();
    let w = writer(&k);
    // The family shot: doc1's own run with its place; doc2's run, named
    // `also`, with no place in either list.
    let the_family = family(None, vec![shot_run(&doc1(), &ca(1), 2), shot_run(&doc2(), &ca2(1), 2)]);
    let (m1, _) = w.publication(P1, &into, &the_family, &places(2, &[(0, 1)]), &[], &none).expect("E.1");
    assert_eq!(bytes_of(&k, &m1), "abxy");
    assert_eq!(runs_of(&k, &doc1()), vec![run(&pca(1), 2), run(&ca2(1), 2)], "the premise: doc1 re-windowed for its own words, doc2's old identity standing — #747");
    assert_eq!(runs_of(&k, &doc2()), vec![run(&ca2(1), 2)], "and doc2 as it stands: no list placed its run");
    assert_eq!(records_in_doc2(&k), vec![record(&run(&ca2(1), 2), &run(&pca(3), 2))], "the record homed in doc2");
    assert_eq!(records_in_doc1(&k).len(), 1);
    let before = k.snapshot();
    // doc1's next shot: the head's runs by reference, the stale run
    // re-composed to the trunk's identity with doc1's place beside it in
    // `places` and doc2's place beside it in doc2's `also_places` entry.
    let healing = Shot {
        base: Some(skep_arrangement::Base { member: m1.clone(), extent: n(4) }),
        draft: Some(doc1()),
        also: vec![doc2()],
        keep_base: false,
        runs: vec![shot_run(&pdoc(), &pca(1), 2), shot_run(&pdoc(), &pca(3), 2)],
        stretches: Vec::new(),
    };
    let doc2_places = vec![AlsoPlaces { draft: doc2(), places: vec![None, Some(vp(1, 1))] }];
    let (m2, seq) = w.publication(P1, &into, &healing, &places(2, &[(1, 3)]), &doc2_places, &none).expect("healed through doc2's record");
    assert_eq!(m2, pmember(2));
    assert_eq!(k.boundaries_above(before.seq()).expect("boundaries"), vec![(seq, None)], "ONE commit");
    assert_eq!(bytes_of(&k, &doc1()), "abxy", "the same bytes");
    assert_eq!(runs_of(&k, &doc1()), vec![run(&pca(1), 4)], "E's identity throughout: doc2's words healed at doc1's place");
    assert!(footprint(&k, &doc1(), &run(&ca2(1), 2)).is_empty(), "doc2's identity arranged nowhere in doc1");
    assert_eq!(bytes_of(&k, &doc2()), "xy", "doc2 reads the same bytes");
    assert_eq!(runs_of(&k, &doc2()), vec![run(&pca(3), 2)], "doc2 healed at its own place in the same commit, through its own record");
    assert!(footprint(&k, &doc2(), &run(&ca2(1), 2)).is_empty(), "doc2's private copy arranged nowhere");
    assert_eq!((records_in_doc1(&k).len(), records_in_doc2(&k).len()), (1, 1), "no new record");
    assert_eq!(k.snapshot().world().m3().next_content_address(&pdoc()), Some(pca(5)), "no identity minted");
    assert_eq!(bytes_of(&k, &m2), "abxy");
}

/// H1 HEALED (the counterpart first, the link-sets design §5.5): doc1
/// transcluded doc2's words BEFORE doc2 published them; doc2's own shot
/// mints them with the record homed in doc2 and re-windows doc2, doc1
/// still arranging doc2's old identity; at doc1's own next shot — doc2 not
/// named — the window re-composed to the record's `to` is sent with doc1's
/// place beside doc1's own fresh run's, and the one commit re-windows both:
/// doc1 arranges its own fresh identity and E's for doc2's words, the
/// member holds the second by reference, no record but doc1's own new one,
/// nothing of doc2's minted again.
#[test]
fn a_draft_that_transcluded_another_drafts_words_before_they_were_published_heals_at_its_own_next_shot() {
    let k = kernel_over(edition_world());
    draft_holding(&k, "ab");
    other_draft_holding(&k, "xy");
    Vstream::new(&k).copy(P1, &doc1(), vp(1, 3), &[spec(&doc2(), 1, 1, 2)], AsOf::Typed(k.current_seq())).expect("doc1 a b x y, the transclusion");
    let into = PublishTarget::Document(pdoc());
    let none = PublishDeposits::default();
    let w = writer(&k);
    // doc2 publishes its words itself, re-windowed at its place.
    let doc2_shot = Shot { base: None, draft: Some(doc2()), also: vec![], keep_base: false, runs: vec![shot_run(&doc2(), &ca2(1), 2)], stretches: Vec::new() };
    let (m1, _) = w.publication(P1, &into, &doc2_shot, &places(1, &[(0, 1)]), &[], &none).expect("E.1 from doc2");
    assert_eq!(runs_of(&k, &doc2()), vec![run(&pca(1), 2)], "doc2 re-windowed");
    assert_eq!(runs_of(&k, &doc1()), vec![run(&ca(1), 2), run(&ca2(1), 2)], "the premise: doc1 holds doc2's old identity — H1");
    // doc1's next shot: its own `a b` with its place, then the window
    // re-composed by reference to doc2's record's `to` with its place.
    let healing = Shot {
        base: Some(skep_arrangement::Base { member: m1.clone(), extent: n(2) }),
        draft: Some(doc1()),
        also: vec![],
        keep_base: false,
        runs: vec![shot_run(&doc1(), &ca(1), 2), shot_run(&pdoc(), &pca(1), 2)],
        stretches: Vec::new(),
    };
    let (m2, _) = w.publication(P1, &into, &healing, &places(2, &[(0, 1), (1, 3)]), &[], &none).expect("both kinds of place hold");
    assert_eq!(m2, pmember(2));
    assert_eq!(bytes_of(&k, &doc1()), "abxy", "the same bytes");
    assert_eq!(runs_of(&k, &doc1()), vec![run(&pca(3), 2), run(&pca(1), 2)], "doc1's fresh identity, then E's for doc2's words");
    assert!(footprint(&k, &doc1(), &run(&ca2(1), 2)).is_empty(), "doc2's identity arranged nowhere in doc1");
    assert_eq!(bytes_of(&k, &m2), "abxy");
    assert_eq!(runs_of(&k, &m2), vec![run(&pca(3), 2), run(&pca(1), 2)], "the member holds doc2's published words by reference");
    assert_eq!(records_in_doc1(&k), vec![record(&run(&ca(1), 2), &run(&pca(3), 2))], "doc1's own record alone");
    assert_eq!(records_in_doc2(&k).len(), 1, "doc2's record stands, no new one");
    assert_eq!(k.snapshot().world().m3().next_content_address(&pdoc()), Some(pca(5)), "nothing of doc2's minted again");
}

/// The owner's second published document `F`, the account's fourth,
/// [`doc`]`(4)`: the chain's next after `E`, registered published by
/// [`two_editions_world`] alone — the document another draft's words were
/// published into.
fn fdoc() -> Address {
    doc(4)
}

/// `F`'s content element `k`.
fn fca(k: u32) -> Address {
    a(&[1, 0, 1, 0, nth_doc(4), 0, 1, k])
}

/// [`edition_world`] with `F` registered published beside `E`.
fn two_editions_world() -> World {
    let world = edition_world();
    World { m3: world.m3.apply_m3(Seq(0), &M3Rec::allocate(fdoc(), true)), ..world }
}

/// A COUNTERPART INTO ANOTHER DOCUMENT (the link-sets design §5.5: a window
/// onto a run of any draft the person reads that an earlier shot re-minted
/// is re-composed by reference to the record's `to`, in whichever document
/// it lies): doc2 is F's draft, its `x` and `y` published into F by two
/// shots — two records homed in doc2, `to` F's identity; doc1, E's
/// rendering draft, holds doc2's words by transclusion from before. At a
/// visibility class that does not admit doc2 the run re-composed to F's
/// identity with its place is refused `StrayPlaceUnrecorded`, nothing
/// committed. At the caller's own class the price counts the two records
/// the stab finds, and the commit re-windows doc1 onto F's identity
/// through them, a run a piece — each windowing F, the document whose shot
/// minted it — the member holding F's words by reference, no
/// record written, nothing minted in F.
#[test]
fn a_window_onto_words_published_into_another_document_is_re_windowed_through_that_drafts_record() {
    use skep_links::{
        price_staged_bytes, stored_tumbler_bytes, CORRESPONDENCE_RECORD_BYTES, KEPT_PLACE_BYTES, PLACED_RUN_BYTES, REINSERTED_UNIT_BYTES, REWINDOWED_DRAFT_BYTES,
        SHOT_BYTES,
    };
    let k = kernel_over(two_editions_world());
    draft_holding(&k, "ab");
    other_draft_holding(&k, "xy");
    Vstream::new(&k).copy(P1, &doc1(), vp(1, 3), &[spec(&doc2(), 1, 1, 2)], AsOf::Typed(k.current_seq())).expect("doc1 a b x y, the transclusion");
    let (into_e, into_f) = (PublishTarget::Document(pdoc()), PublishTarget::Document(fdoc()));
    let none = PublishDeposits::default();
    let w = writer(&k);
    // doc2 into F, twice: `x`, then `y` beside it — two records in doc2.
    let first = Shot { base: None, draft: Some(doc2()), also: vec![], keep_base: false, runs: vec![shot_run(&doc2(), &ca2(1), 1)], stretches: Vec::new() };
    let (f1, _) = w.publication(P1, &into_f, &first, &places(1, &[(0, 1)]), &[], &none).expect("F.1");
    let second = Shot {
        base: Some(skep_arrangement::Base { member: f1, extent: n(1) }),
        draft: Some(doc2()),
        also: vec![],
        keep_base: false,
        runs: vec![shot_run(&fdoc(), &fca(1), 1), shot_run(&doc2(), &ca2(2), 1)],
        stretches: Vec::new(),
    };
    w.publication(P1, &into_f, &second, &places(2, &[(1, 2)]), &[], &none).expect("F.2");
    assert_eq!(records_in_doc2(&k), vec![record(&run(&ca2(1), 1), &run(&fca(1), 1)), record(&run(&ca2(2), 1), &run(&fca(2), 1))], "two records homed in doc2, `to` F's identity");
    assert_eq!(runs_of(&k, &doc2()), vec![run(&fca(1), 2)], "doc2 re-windowed onto F");
    assert_eq!(runs_of(&k, &doc1()), vec![run(&ca(1), 2), run(&ca2(1), 2)], "the premise: doc1 holds doc2's old identity");
    // doc1's shot into E: its own `a b` with its place, the window
    // re-composed to F's identity with its place.
    let the_shot = Shot { base: None, draft: Some(doc1()), also: vec![], keep_base: false, runs: vec![shot_run(&doc1(), &ca(1), 2), shot_run(&fdoc(), &fca(1), 2)], stretches: Vec::new() };
    let the_places = places(2, &[(0, 1), (1, 3)]);
    let before = k.snapshot();
    let all_but_doc2: &Visibility<'_, World> = &|_: &World, d: &Address| *d != doc2();
    assert_eq!(
        refused(writer_at(&k, all_but_doc2).publication(P1, &into_e, &the_shot, &the_places, &[], &none)),
        PublicationError::StrayPlaceUnrecorded { index: 1, draft: doc1() },
        "the records' home unreadable to the caller: no readable record covers the run"
    );
    assert_eq!(k.snapshot().seq(), before.seq(), "nothing committed");
    assert_eq!(runs_of(&k, &doc1()), vec![run(&ca(1), 2), run(&ca2(1), 2)], "the draft unchanged");
    // The price: the all-homes stab finds doc2's two records for the placed
    // run of F's words — two pieces, not one.
    let drafted = SHOT_BYTES + stored_tumbler_bytes(doc1().tumbler());
    assert_eq!(
        price_staged_bytes(before.world(), &ALL_VISIBLE, &into_e, &the_shot, &the_places, &[], &none),
        drafted
            + (REWINDOWED_DRAFT_BYTES + stored_tumbler_bytes(doc1().tumbler()))
            + (PLACED_RUN_BYTES + CORRESPONDENCE_RECORD_BYTES + KEPT_PLACE_BYTES)
            + (PLACED_RUN_BYTES + 2 * KEPT_PLACE_BYTES)
            + (REINSERTED_UNIT_BYTES + 2),
        "doc1's one record of its kept places; the draft-native run as one piece, its two typed bytes one unit; the placed run of F's words at its two records"
    );
    // …and at the class the commit above was refused at, doc2 unreadable,
    // the same stab counts no record of doc2's: the run is priced as the
    // one piece every placed stray is at least, where it is two for a
    // caller who reads doc2.
    assert_eq!(
        price_staged_bytes(before.world(), all_but_doc2, &into_e, &the_shot, &the_places, &[], &none),
        drafted
            + (REWINDOWED_DRAFT_BYTES + stored_tumbler_bytes(doc1().tumbler()))
            + (PLACED_RUN_BYTES + CORRESPONDENCE_RECORD_BYTES + KEPT_PLACE_BYTES)
            + (PLACED_RUN_BYTES + KEPT_PLACE_BYTES)
            + (REINSERTED_UNIT_BYTES + 2),
        "a record homed in a draft the caller may not read is no piece of the price"
    );
    let (m1, _) = w.publication(P1, &into_e, &the_shot, &the_places, &[], &none).expect("re-windowed onto F's identity through doc2's records");
    assert_eq!(m1, pmember(1));
    assert_eq!(bytes_of(&k, &doc1()), "abxy", "the same bytes");
    assert_eq!(runs_of(&k, &doc1()), vec![run(&pca(1), 2), run(&fca(1), 2)], "doc1's fresh identity, then F's for doc2's words");
    assert!(footprint(&k, &doc1(), &run(&ca2(1), 2)).is_empty(), "doc2's identity arranged nowhere in doc1");
    assert_eq!(bytes_of(&k, &m1), "abxy");
    assert_eq!(runs_of(&k, &m1), vec![run(&pca(1), 2), run(&fca(1), 2)], "the member holds F's words by reference");
    assert_eq!(records_in_doc1(&k), vec![record(&run(&ca(1), 2), &run(&pca(1), 2))], "doc1's own record alone, none for the window");
    assert_eq!(records_in_doc2(&k).len(), 2, "doc2's records stand");
    let s = k.snapshot();
    assert_eq!(s.world().m3().next_content_address(&pdoc()), Some(pca(3)), "E minted doc1's words alone");
    assert_eq!(s.world().m3().next_content_address(&fdoc()), Some(fca(3)), "nothing minted in F");
}

// ───────────────────────── the deposits in the one commit (S3) ─────────────────────────

use skep_links::{
    base_runs, edition_type, plan_deposits, read_with_type, retraction_tuple, supersession_claim, EndArg,
    LinkEntry, MemberSpan, NamedAddress, OldCause, OriginalCause, OriginalEntry, PlanFault,
    PlannedDeposit, ReadWithCause, RetractCause, TYPE,
};

/// The owner's second published document, the SET `S`, the account's
/// fourth, [`doc`]`(4)`: registered published by [`deposits_world`] alone.
fn set_s() -> Address {
    doc(4)
}

/// The `k`-th document a mint hands out in the owner's account over
/// [`edition_world`], which holds the account's first three — doc1, doc2
/// and the edition `E` — so its first mint is the account's fourth,
/// [`doc`]`(4)`.
fn minted(k: u32) -> Address {
    doc(k + 3)
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
    Shot { base: Some(skep_arrangement::Base { member: head, extent }), draft: Some(doc1()), also: vec![], keep_base: false, runs, stretches: Vec::new() }
}

/// Publishes `shot` with `deposits` into the edition, as the owner.
fn publish(k: &Kernel<World>, shot: &Shot, deposits: &PublishDeposits) -> Result<(Address, Seq), TxnError<PublicationError>> {
    writer(k).publication(P1, &PublishTarget::Document(pdoc()), shot, &[], &[], deposits)
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
    Vstream::new(&k).insert(P1, &doc1(), vp(1, 4), vec![Val::new([b'd'])], Deposit::Undeclared, AsOf::Typed(k.current_seq())).expect("d at ca(4)");
    let before = k.snapshot();
    let the_shot = shot_off_head(&k, vec![shot_run(&doc1(), &ca(4), 1)]);
    let deposits = PublishDeposits {
        claim: false,
        links: vec![entry(NamedAddress::Member, member_spans(1, 3), addrs(&[&doc2()]), addrs(&[&citation()]), Some(l.clone()))],
        retract: vec![m.clone()],
        read_with: vec![set_s()],
        supersede: vec![],
        originals: vec![],
        base_runs: vec![],
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
    assert_eq!(
        links.retractions_of(&m).collect::<Vec<_>>(),
        vec![link_of(&pmember(1), 2)],
        "the record beside the tombstone is the shot's retraction, minted at the shot's position"
    );
    let rw = link_of(&set_s(), 1);
    assert_eq!(links.readlink(&rw), Some(&Link::triple(enc([&pdoc()]), enc([&set_s()]), enc([read_with_type()]))), "the read-with in S");
    assert_eq!(s.world().m5().link_runs(&set_s()).cloned().collect::<Vec<_>>(), vec![run(&rw, 1)], "seated in S");
    let m3 = s.world().m3();
    for addr in [&copy, &link_of(&doc2(), 2), &link_of(&pmember(1), 2), &rw, &member] {
        assert_eq!(m3.minted_at(addr), Some(seq), "{addr} minted at the one commit");
    }
}

/// THE BASE'S WORDS ON ONE KERNEL (§5.1's key (iii) as E4 2.1 re-says it):
/// `base_runs` answers the runs the shot's base arranges over its positions
/// `1 ..= extent` — `E.1`'s `pca(1..=3)`, cut where the extent stops inside
/// the run — and none for the bare document or the birth shape. Set on the
/// deposits, (3) leaves them out of what a copy must cover: `L`, accepted at
/// `E.2` with a copy over `pca(1..=2)` alone, is planned again over
/// `pca(1..=3)` where no base word is read, and refused `superseded` where
/// the words of `E.2`, which holds all three, are — by the composite as by
/// the plan, nothing committed.
#[test]
fn the_bases_runs_are_its_positions_to_the_extent_and_three_leaves_them_out_of_the_cover() {
    let k = kernel_over(deposits_world());
    let (l, _) = board(&k);
    let snap = k.snapshot();
    let base_of = |base: Option<(&Address, u32)>| base_runs(snap.world(), &shot(base, vec![]));
    assert_eq!(base_of(Some((&pmember(1), 3))), vec![run(&pca(1), 3)], "E.1's positions 1..3");
    assert_eq!(base_of(Some((&pmember(1), 2))), vec![run(&pca(1), 2)], "cut where the extent stops");
    assert!(base_of(Some((&pdoc(), 3))).is_empty(), "the bare document keys nothing");
    assert!(base_of(None).is_empty(), "nor the birth shape");
    let offer = |width: u32, base_runs: Vec<Run>| PublishDeposits { links: vec![entry(NamedAddress::Member, ispans(&pca(1), width), addrs(&[&doc2()]), addrs(&[&citation()]), Some(l.clone()))], base_runs, ..PublishDeposits::default() };
    let (e2, _) = publish(&k, &shot_off_head(&k, vec![]), &offer(2, vec![])).expect("E.2, the copy cut to pca(1..=2)");
    assert_eq!(e2, pmember(2));
    let the_shot = shot_off_head(&k, vec![]);
    let snap = k.snapshot();
    let held = base_runs(snap.world(), &the_shot);
    assert_eq!(held, vec![run(&pca(1), 3)], "E.2 holds all three");
    let target = PublishTarget::Document(pdoc());
    assert!(plan_deposits(snap.world(), P1, &target, &the_shot, &offer(3, vec![])).is_ok(), "no base word read: the copy covers pca(1..=2) of pca(1..=3)");
    let superseded = PlanFault::Old { index: 0, cause: OldCause::Superseded };
    assert_eq!(plan_deposits(snap.world(), P1, &target, &the_shot, &offer(3, held.clone())).expect_err("refused"), superseded, "the base holds every word: none left to cover");
    assert_eq!(refused_plan(&k, &the_shot, offer(3, held)), superseded, "the composite plans on the same deposits");
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
        claim: false,
        links: vec![
            entry(NamedAddress::Member, member_spans(1, 1), addrs(&[]), ty(1), None),
            entry(NamedAddress::Member, member_spans(2, 1), addrs(&[]), ty(2), None),
            entry(NamedAddress::Address(set_s()), ispans(&pca(1), 3), addrs(&[]), ty(3), None),
            entry(NamedAddress::Member, member_spans(3, 1), addrs(&[]), ty(4), None),
        ],
        retract: vec![],
        read_with: vec![set_s()],
        supersede: vec![],
        originals: vec![],
        base_runs: vec![],
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
    let the_shot = Shot { base: None, draft: Some(doc1()), also: vec![], keep_base: false, runs: vec![shot_run(&doc1(), &ca(1), 3)], stretches: Vec::new() };
    let target = PublishTarget::Mint { account: account.clone() };
    let deposits = PublishDeposits { claim: true, links: vec![], retract: vec![], read_with: vec![set_s()], supersede: vec![], originals: vec![], base_runs: vec![] };
    let (member, seq) = writer(&k).publication(P1, &target, &the_shot, &[], &[], &deposits).expect("the mint");
    // The deposits world holds the account's first four documents, `S` the
    // fourth, so the mint is its fifth.
    let edition = doc(5);
    assert_eq!(Some(member.clone()), first_version_address(&edition), "the edition's first member");
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
    let theirs = PublishTarget::Mint { account: a(&[1, 0, 2]) };
    let before = k.current_seq();
    assert_eq!(
        refused(writer(&k).publication(P1, &theirs, &Shot { base: None, draft: None, also: vec![], keep_base: false, runs: vec![], stretches: Vec::new() }, &[], &[], &PublishDeposits::default())),
        PublicationError::Publish(PublishError::NotOwner(a(&[1, 0, 2])))
    );
    assert_eq!(k.current_seq(), before);
    // A base at the mint form: no chain for it to lie in.
    let based = Shot { base: Some(skep_arrangement::Base { member: pmember(1), extent: n(0) }), draft: None, also: vec![], keep_base: false, runs: vec![], stretches: Vec::new() };
    assert_eq!(
        refused(writer(&k).publication(P1, &target, &based, &[], &[], &PublishDeposits::default())),
        PublicationError::Publish(PublishError::BaseNotInChain)
    );
    assert_eq!(k.current_seq(), before);
}

/// THE CLAIM AT THE DOCUMENT FORM (skep #692): a first version published
/// from a draft into an EMPTY edition with `claim: true` — `doc` the
/// edition, no mint — writes the edition claim homed in the edition's own
/// address in the same commit as the member, the record the mint form
/// writes (typed the edition class, `from` the edition, `to` the origin
/// draft, seated), the plan homing it by the trunk's address and the price
/// adding the claim's bytes at this form too; and a second publication
/// claiming into the same edition — a member now standing — is refused
/// `Publish(ClaimRefused)` naming the edition, nothing committed, the plan
/// still planning the row (the refusal is the composite's, not the plan's)
/// and the same shot without its claim landing.
#[test]
fn a_first_version_into_an_empty_edition_carries_its_claim_homed_in_it() {
    use skep_links::{price_staged_bytes, EDITION_CLAIM_BYTES};

    let k = journaled_over(deposits_world());
    draft_holding(&k, "abc");
    let before = k.snapshot();
    let the_shot = Shot { base: None, draft: Some(doc1()), also: vec![], keep_base: false, runs: vec![shot_run(&doc1(), &ca(1), 3)], stretches: Vec::new() };
    let claimed = PublishDeposits { claim: true, ..PublishDeposits::default() };
    let target = PublishTarget::Document(pdoc());
    // The plan homes the claim by the edition's address, first of that home.
    let plan = plan_deposits(before.world(), P1, &target, &the_shot, &claimed).expect("a plan");
    assert_eq!(plan.homes.len(), 1);
    assert_eq!(plan.homes[0].home, NamedAddress::Address(pdoc()), "the edition by address, never the tag");
    assert_eq!(plan.homes[0].deposits, vec![PlannedDeposit::EditionClaim { origin: doc1() }]);
    assert_eq!(
        price_staged_bytes(before.world(), &ALL_VISIBLE, &target, &the_shot, &[], &[], &claimed) - price_staged_bytes(before.world(), &ALL_VISIBLE, &target, &the_shot, &[], &[], &PublishDeposits::default()),
        EDITION_CLAIM_BYTES,
        "the claim's bytes priced at the document form"
    );
    let (member, seq) = writer(&k).publication(P1, &target, &the_shot, &[], &[], &claimed).expect("the first version with its claim");
    assert_eq!(member, pmember(1));
    assert_eq!(k.boundaries_above(before.seq()).expect("boundaries"), vec![(seq, None)], "one commit");
    let s = k.snapshot();
    let (m3, links) = (s.world().m3(), s.world().links());
    assert_eq!(trunk_head(m3, &pdoc()), Some(member.clone()));
    assert_eq!(bytes_of(&k, &member), "abc");
    let claim = link_of(&pdoc(), 1);
    assert_eq!(
        links.readlink(&claim),
        Some(&Link::triple(enc([&pdoc()]), enc([&doc1()]), enc([edition_type()]))),
        "the edition claim: from the edition, to the origin D, typed edition — the mint form's record"
    );
    assert_eq!(s.world().m5().link_runs(&pdoc()).cloned().collect::<Vec<_>>(), vec![run(&claim, 1)], "seated in the edition");
    assert_eq!(m3.minted_at(&claim), Some(seq), "minted at the one commit");
    // A member stands: a second claiming publication is refused naming the
    // edition, off the member so the shot's own table passes — the plan
    // planning the row all the same, the composite refusing it.
    let before = k.current_seq();
    let second = Shot { base: Some(skep_arrangement::Base { member: member.clone(), extent: n(3) }), draft: Some(doc1()), also: vec![], keep_base: false, runs: vec![], stretches: Vec::new() };
    let snap = k.snapshot();
    let plan = plan_deposits(snap.world(), P1, &target, &second, &claimed).expect("the plan plans the row; the composite refuses it");
    assert_eq!(plan.homes[0].home, NamedAddress::Address(pdoc()));
    assert_eq!(
        refused(writer(&k).publication(P1, &target, &second, &[], &[], &claimed)),
        PublicationError::Publish(PublishError::ClaimRefused(pdoc()))
    );
    assert_eq!(k.current_seq(), before, "nothing committed");
    assert_eq!(links.readlink(&link_of(&pdoc(), 2)), None, "no second claim");
    // The same shot without its claim lands.
    let (second_member, _) = writer(&k).publication(P1, &target, &second, &[], &[], &PublishDeposits::default()).expect("the shot without its claim");
    assert_eq!(second_member, pmember(2));
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
    let links_only = |links: Vec<LinkEntry>| PublishDeposits { claim: false, links, retract: vec![], read_with: vec![], supersede: vec![], originals: vec![], base_runs: vec![] };
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
    let retract_only = |retract: Vec<Address>| PublishDeposits { claim: false, links: vec![], retract, read_with: vec![], supersede: vec![], originals: vec![], base_runs: vec![] };
    assert_eq!(refused_plan(&k, &the_shot, retract_only(vec![theirs.clone()])), PlanFault::Retract { index: 0, cause: RetractCause::NotOwner });
    assert_eq!(refused_plan(&k, &the_shot, retract_only(vec![l.clone()])), PlanFault::Retract { index: 0, cause: RetractCause::NotPublished });
    assert_eq!(refused_plan(&k, &the_shot, retract_only(vec![m.clone(), link_of(&pmember(1), 7)])), PlanFault::Retract { index: 1, cause: RetractCause::Absent });
    let read_with_only = |read_with: Vec<Address>| PublishDeposits { claim: false, links: vec![], retract: vec![], read_with, supersede: vec![], originals: vec![], base_runs: vec![] };
    assert_eq!(refused_plan(&k, &the_shot, read_with_only(vec![doc2()])), PlanFault::ReadWith { index: 0, cause: ReadWithCause::NotPublished });
    assert_eq!(refused_plan(&k, &the_shot, read_with_only(vec![set_s(), pmember(1)])), PlanFault::ReadWith { index: 1, cause: ReadWithCause::NotDocument });
    assert_eq!(refused_plan(&k, &the_shot, read_with_only(vec![sib_doc()])), PlanFault::ReadWith { index: 0, cause: ReadWithCause::NotOwner });
    assert_eq!(refused_plan(&k, &the_shot, read_with_only(vec![a(&[1, 0, 1, 0, 71])])), PlanFault::ReadWith { index: 0, cause: ReadWithCause::NotRegistered });
    // The order: a links fault speaks ahead of a retract fault ahead of a
    // read-with fault.
    assert_eq!(
        refused_plan(&k, &the_shot, PublishDeposits { claim: false, links: vec![copy(NamedAddress::Address(doc2()), None)], retract: vec![theirs.clone()], read_with: vec![doc2()], supersede: vec![], originals: vec![], base_runs: vec![] }),
        PlanFault::LinkHome { index: 0 }
    );
    assert_eq!(
        refused_plan(&k, &the_shot, PublishDeposits { claim: false, links: vec![], retract: vec![theirs], read_with: vec![doc2()], supersede: vec![], originals: vec![], base_runs: vec![] }),
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
    Vstream::new(&k).insert(P1, &doc1(), vp(1, 4), vec![Val::new([b'd'])], Deposit::Undeclared, AsOf::Typed(k.current_seq())).expect("d at ca(4)");
    let the_shot = shot_off_head(&k, vec![shot_run(&doc1(), &ca(4), 1)]);
    let on_new_words = entry(NamedAddress::Member, member_spans(4, 1), addrs(&[&doc2()]), addrs(&[&citation()]), Some(l.clone()));
    publish(&k, &the_shot, &links_only(vec![on_new_words])).expect("an entry on fresh words is covered by nothing");
}

/// A cut run's rest lands beside its cut copy, its original offered again.
///
/// `B` runs over the draft's `a b c d`, and its copy in `E.2` is cut at a
/// selection leaving `d` out. A later shot holds `a b c` by reference and
/// publishes `d` as new; its copy of `B` over the whole run is covered by
/// no standing copy, `d` being fresh (§5.1's key (iii), PUB-3.9), so it
/// lands, stored as one I-span over the kept words and the fresh word, its
/// claim beside the cut copy's and both active. On a shot leaving `d` out
/// again, an entry whose far end names `d` by the draft's own I-span holds
/// no new word, and is refused `superseded`, the cut copy covering its kept
/// words.
#[test]
fn the_rest_of_a_cut_run_lands_beside_its_cut_copy() {
    let k = kernel_over(deposits_world());
    board(&k);
    Vstream::new(&k).insert(P1, &doc1(), vp(1, 4), vec![Val::new([b'd'])], Deposit::Undeclared, AsOf::Typed(k.current_seq())).expect("d at ca(4)");
    let b = writer(&k)
        .makelink(P1, &doc2(), SlotArg::Spans(vec![run(&ca(1), 4).iextent()]), SlotArg::Addrs(vec![doc2()]), SlotArg::Addrs(vec![citation()]))
        .expect("the original over the whole run")
        .0;
    assert_eq!(b, link_of(&doc2(), 2));
    let copy = |from: EndArg, to: EndArg| entry(NamedAddress::Member, from, to, addrs(&[&citation()]), Some(b.clone()));
    let links_only = |links: Vec<LinkEntry>| PublishDeposits { links, ..PublishDeposits::default() };
    let (cut, _) = publish(&k, &shot_off_head(&k, vec![]), &links_only(vec![copy(member_spans(1, 3), addrs(&[&doc2()]))])).expect("the copy cut at the selection");
    assert_eq!(cut, pmember(2));
    assert_eq!(
        refused_plan(&k, &shot_off_head(&k, vec![]), links_only(vec![copy(member_spans(1, 3), ispans(&ca(4), 1))])),
        PlanFault::Old { index: 0, cause: OldCause::Superseded },
        "an I-span on the draft's words is no new word: the kept words decide"
    );
    let (member, _) = publish(&k, &shot_off_head(&k, vec![shot_run(&doc1(), &ca(4), 1)]), &links_only(vec![copy(member_spans(1, 4), addrs(&[&doc2()]))]))
        .expect("the whole run, `d` new: no standing copy covers it");
    assert_eq!(member, pmember(3));
    assert_eq!(bytes_of(&k, &member), "abcd");
    let s = k.snapshot();
    let links = s.world().links();
    let remade = link_of(&member, 1);
    assert_eq!(
        links.readlink(&remade),
        Some(&Link::triple(Endset::from_spans([run(&pca(1), 4).iextent()]), enc([&doc2()]), enc([&citation()]))),
        "the copy re-made over the whole run, the kept words and the fresh word"
    );
    let (first, second) = (link_of(&doc2(), 3), link_of(&doc2(), 4));
    assert_eq!(links.readlink(&first), Some(&supersession_claim(&b, &link_of(&cut, 1))), "the cut copy's claim");
    assert_eq!(links.readlink(&second), Some(&supersession_claim(&b, &remade)), "the re-made copy's claim beside it");
    assert!(links.is_active(&first) && links.is_active(&second), "both claims active");
    assert!(links.is_active(&link_of(&cut, 1)), "the cut copy stands");
}

/// A revision whose original's public copy covers its kept words is refused.
///
/// `R` revises `L` after `L`'s accept, its `from` run on over the new word
/// `d`. An entry for `R` over the kept words and `d` is refused
/// `superseded`: the rule reads `L`'s claims over the entry's kept words
/// whatever new words it holds, the new-word exemption of §5.1's key (iii)
/// being for `R`'s own claims alone (PUB-3.9).
#[test]
fn a_revision_of_an_accepted_original_is_refused_beside_new_words() {
    let k = kernel_over(deposits_world());
    let (l, _) = board(&k);
    let copy = |from: EndArg, old: &Address| entry(NamedAddress::Member, from, addrs(&[&doc2()]), addrs(&[&citation()]), Some(old.clone()));
    let links_only = |links: Vec<LinkEntry>| PublishDeposits { links, ..PublishDeposits::default() };
    publish(&k, &shot_off_head(&k, vec![]), &links_only(vec![copy(member_spans(1, 3), &l)])).expect("L accepted");
    Vstream::new(&k).insert(P1, &doc1(), vp(1, 4), vec![Val::new([b'd'])], Deposit::Undeclared, AsOf::Typed(k.current_seq())).expect("d at ca(4)");
    let revised = Link::triple(Endset::from_spans([run(&ca(1), 4).iextent()]), enc([&doc2()]), enc([&citation()]));
    let r = writer(&k).editlink(P1, &l, revised, &doc2(), &doc2()).expect("R revises L").0.successor;
    let rest = shot_off_head(&k, vec![shot_run(&doc1(), &ca(4), 1)]);
    assert_eq!(refused_plan(&k, &rest, links_only(vec![copy(member_spans(1, 4), &r)])), PlanFault::Old { index: 0, cause: OldCause::Superseded });
}

/// THE WHOLE-WORK ORIGINAL (the link-sets design §5.1's stored-endset test at
/// the door; the owner's ruling, 2026-10-29): a `links` entry whose `old`
/// reaches the words the shot publishes through a whole-work end alone — `W`
/// in the notes, FROM the edition `E` whole (one unit subtree span at `E`'s
/// address, a prefix of every published position) TO the draft's own words,
/// a content span the shot does not publish — is refused `Old` with
/// `WholeWork` at its entry, second entry or first, nothing committed. The
/// same shape with a content end ON the published words beside the
/// whole-work end — FROM `E` whole TO the member's first word — is admitted
/// and lands as its copy with its claim: the test is the end the original
/// reaches the words by, never a whole-work end's presence.
#[test]
fn an_original_reaching_the_published_words_through_a_whole_work_end_alone_is_refused() {
    let k = kernel_over(deposits_world());
    board(&k);
    let w = writer(&k);
    let whole = w
        .makelink(P1, &doc2(), SlotArg::Addrs(vec![pdoc()]), SlotArg::Spans(vec![run(&ca(1), 3).iextent()]), SlotArg::Addrs(vec![citation()]))
        .expect("the whole-work link in the notes")
        .0;
    assert_eq!(whole, link_of(&doc2(), 2));
    let the_shot = shot_off_head(&k, vec![]);
    let copy = |old: &Address| entry(NamedAddress::Member, member_spans(1, 3), addrs(&[&doc2()]), addrs(&[&citation()]), Some(old.clone()));
    let links_only = |links: Vec<LinkEntry>| PublishDeposits { claim: false, links, retract: vec![], read_with: vec![], supersede: vec![], originals: vec![], base_runs: vec![] };
    assert_eq!(
        refused_plan(&k, &the_shot, links_only(vec![copy(&whole)])),
        PlanFault::Old { index: 0, cause: OldCause::WholeWork },
        "the corner's link: the published words reached through E's unit span alone"
    );
    let plain = entry(NamedAddress::Member, member_spans(1, 1), addrs(&[]), addrs(&[&citation()]), None);
    assert_eq!(
        refused_plan(&k, &the_shot, links_only(vec![plain, copy(&whole)])),
        PlanFault::Old { index: 1, cause: OldCause::WholeWork },
        "at its entry"
    );
    // A whole-work end beside a content end on the published words: the
    // original reaches the words through the content end, and is admitted.
    let on_words = w
        .makelink(P1, &doc2(), SlotArg::Addrs(vec![pdoc()]), SlotArg::Spans(vec![run(&pca(1), 1).iextent()]), SlotArg::Addrs(vec![citation()]))
        .expect("a link reaching the words by a content end too")
        .0;
    assert_eq!(on_words, link_of(&doc2(), 3));
    let (member, _) = publish(&k, &the_shot, &links_only(vec![copy(&on_words)])).expect("admitted: the words reached through a content span");
    assert_eq!(member, pmember(2));
    let s = k.snapshot();
    let links = s.world().links();
    assert_eq!(links.readlink(&link_of(&doc2(), 4)), Some(&supersession_claim(&on_words, &link_of(&member, 1))), "its claim in the notes");
    assert!(links.is_active(&whole), "the whole-work link stands, untouched");
    assert_eq!(links.readlink(&link_of(&doc2(), 5)), None, "and no claim on it");
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
    let deposits = PublishDeposits { claim: false, links: vec![], retract: vec![m.clone()], read_with: vec![set_s()], supersede: vec![], originals: vec![], base_runs: vec![] };
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
    let (m3, _) = publish(&k, &the_shot, &PublishDeposits { claim: false, links: vec![], retract: vec![], read_with: vec![set_s()], supersede: vec![], originals: vec![], base_runs: vec![] }).expect("the shot lands");
    assert_eq!(m3, pmember(3));
    assert_eq!(k.snapshot().world().links().readlink(&link_of(&set_s(), 2)), None, "the standing read-with skips the entry");
    // Retracted, the public read-with no longer stands, and the next is written.
    w.nullify(P1, &set_s(), &link_of(&set_s(), 1)).expect("retracted");
    let the_shot = shot_off_head(&k, vec![]);
    publish(&k, &the_shot, &PublishDeposits { claim: false, links: vec![], retract: vec![], read_with: vec![set_s()], supersede: vec![], originals: vec![], base_runs: vec![] }).expect("the shot lands");
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
        let deposits = PublishDeposits { claim: false, links: (1..=count).map(|n| into_s(base + n)).collect(), retract: vec![], read_with: vec![], supersede: vec![], originals: vec![], base_runs: vec![] };
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
/// `N` holding `L`, `E.1` holding `M`: three, each one the class the cell
/// prices at admits), the `links` and `read_with` entries summed, the re-window's steps
/// where a place is carried — doc1's one run and the one piece placed in
/// it; none where no place is — and the twin fence's stab per re-inserted run,
/// placed or not — and the one comparison against `MAX_PUBLICATION_READS`:
/// a request at the budget is inside it, one past it is over, the system
/// caller prices no homes, and a shot naming no draft re-windows nothing and
/// re-inserts nothing. THE FENCE's TERM decides at the edge: three homes ×
/// 21,845 read-with entries is one read short of the budget, so one
/// re-inserted run stands at the budget and a second is past it. AND THE
/// FIFTH TERM (lane F4): the staged bytes, priced
/// from the table off the request — the shot, a by-reference run's
/// placement, a draft-native run's placement and record, its values, the
/// copy at its own slots' spans (a member-position span at the fewer of its
/// width and the runs, an address as its unit span) with its claim, the
/// retraction and the two read-withs, and where a place is carried the
/// re-windowed draft's one record and the place's change in it — against
/// `MAX_TXN_BYTES`, the same
/// `over_budget`; one past the transaction budget is over with the reads
/// inside theirs.
#[test]
fn the_price_of_a_publications_reads_is_its_four_terms_against_the_one_budget() {
    use skep_links::{
        price_publication_reads, stored_span_bytes, ReadPrice, CLAIM_BYTES, COPY_FIXED_BYTES, CORRESPONDENCE_RECORD_BYTES,
        KEPT_PLACE_BYTES, MAX_PUBLICATION_READS, PLACED_RUN_BYTES, READ_WITH_BYTES, REINSERTED_UNIT_BYTES, RETRACTION_BYTES, REWINDOWED_DRAFT_BYTES,
        SHOT_BYTES,
    };

    let k = kernel_over(deposits_world());
    let (l, m) = board(&k);
    let s = k.snapshot();
    let world = s.world();
    let target = PublishTarget::Document(pdoc());
    let the_shot = shot_off_head(&k, vec![shot_run(&doc1(), &ca(1), 3)]);
    let deposits = PublishDeposits {
        claim: false,
        links: vec![entry(NamedAddress::Member, member_spans(1, 3), addrs(&[&doc2()]), addrs(&[&citation()]), Some(l))],
        retract: vec![m],
        read_with: vec![set_s(), set_s()],
        supersede: vec![],
        originals: vec![],
        base_runs: vec![],
    };
    // No place: nothing is re-windowed, and the re-window's term is nothing.
    let unplaced = price_publication_reads(world, P1, &ALL_VISIBLE, &target, &the_shot, &[], &[], &deposits, &mut |_| {});
    assert_eq!(unplaced.rewindow, 0, "no place carried: the re-window places no piece");
    assert_eq!(unplaced.fence, 1, "the draft-native run's fence stab, placed or not");
    // A place beside the draft-native run: the draft's one run, and one piece.
    let price = price_publication_reads(world, P1, &ALL_VISIBLE, &target, &the_shot, &places(2, &[(1, 1)]), &[], &deposits, &mut |_| {});
    // The fifth term, from the table: the member-position `from` of width 3
    // over a shot of two runs is at most two content spans of the edition's
    // chain; `to` and `ty` one unit span each.
    let content_span = stored_span_bytes(&run(&pca(1), 1).iextent());
    let unit = |a: &Address| stored_span_bytes(&skep_address::subtree_of(a.tumbler()));
    // The rendering draft's address rides the placing record's own slot, and
    // the base's — the head the shot is made off — the terms' own.
    let rendering_draft = skep_links::stored_tumbler_bytes(doc1().tumbler());
    let based = skep_links::stored_tumbler_bytes(
        the_shot.base.as_ref().expect("a shot off the head").member.tumbler(),
    );
    let staged = SHOT_BYTES
        + based
        + rendering_draft
        + PLACED_RUN_BYTES
        + (PLACED_RUN_BYTES + CORRESPONDENCE_RECORD_BYTES)
        + (REINSERTED_UNIT_BYTES + 3)
        + COPY_FIXED_BYTES
        + 2 * content_span
        + unit(&doc2())
        + unit(&citation())
        + CLAIM_BYTES
        + RETRACTION_BYTES
        + 2 * READ_WITH_BYTES;
    // The re-windowed draft's one record, its address in it, and the one
    // place's change.
    let rewindowed = REWINDOWED_DRAFT_BYTES + rendering_draft + KEPT_PLACE_BYTES;
    assert_eq!(
        price,
        ReadPrice { homes: 3, entries: 3, rewindow: 1 + 1, fence: 1, staged_bytes: staged + rewindowed, units: 1 },
        "three link-holding homes under the account; one links entry and two read-withs; doc1's one run and the one piece placed in it; one re-inserted run; the staged bytes from the table with the draft's one record and its one kept place; the draft's three typed bytes one unit"
    );
    assert_eq!(unplaced, ReadPrice { rewindow: 0, staged_bytes: staged, ..price }, "unplaced: no re-window term, no record of kept places staged");
    assert_eq!((staged, rewindowed), (6_741, 252), "the figures, at the shallow depth");
    assert_eq!(price.total(), 3 * 3 + 2 + 1, "homes × entries + the re-window's steps + the fence's stabs");
    assert!(!price.over_budget());
    assert_eq!(ReadPrice::BUDGET, MAX_PUBLICATION_READS);
    assert_eq!(ReadPrice::BYTE_BUDGET, skep_kernel::MAX_TXN_BYTES);
    assert_eq!((ReadPrice::UNIT_BUDGET, ReadPrice::POSITION_BUDGET), (skep_arrangement::MAX_REINSERTED_UNITS as u64, skep_arrangement::MAX_REINSERTED_VALUES as u64), "the store's own two");
    let at_budget = ReadPrice { homes: 1, entries: MAX_PUBLICATION_READS, rewindow: 0, fence: 0, staged_bytes: ReadPrice::BYTE_BUDGET, units: 0 };
    assert!(!at_budget.over_budget(), "at both budgets is inside them");
    let many_units = ReadPrice { units: ReadPrice::UNIT_BUDGET + 1, ..at_budget };
    assert!(!many_units.over_budget(), "the units are no term of this refusal: past their budget the store refuses the shot itself");
    let past = ReadPrice { homes: 1, entries: MAX_PUBLICATION_READS, rewindow: 1, fence: 0, staged_bytes: 0, units: 0 };
    assert!(past.over_budget() && past.reads_over_budget() && !past.bytes_over_budget(), "one read past the budget is over");
    let stabbed = ReadPrice { rewindow: 0, fence: 1, ..past };
    assert!(stabbed.reads_over_budget(), "one fence stab past the budget is over");
    let heavy = ReadPrice { homes: 0, entries: 0, rewindow: 0, fence: 0, staged_bytes: ReadPrice::BYTE_BUDGET + 1, units: 0 };
    assert!(heavy.over_budget() && heavy.bytes_over_budget() && !heavy.reads_over_budget(), "one byte past the transaction budget is over");
    let huge = ReadPrice { homes: usize::MAX, entries: 2, rewindow: usize::MAX, fence: 2, staged_bytes: 0, units: 0 };
    assert_eq!(huge.total(), usize::MAX, "the price saturates");
    assert_eq!(price_publication_reads(world, Caller::System, &ALL_VISIBLE, &target, &the_shot, &[], &[], &deposits, &mut |_| {}).homes, 0, "no account, no homes");
    let draftless = Shot { draft: None, ..the_shot.clone() };
    let undrafted = price_publication_reads(world, P1, &ALL_VISIBLE, &target, &draftless, &places(2, &[(1, 1)]), &[], &deposits, &mut |_| {});
    assert_eq!((undrafted.rewindow, undrafted.fence), (0, 0), "no draft: nothing re-windowed, no run re-inserted");
    // The fence's term at the edge: 3 × 21,845 read-with entries is 65,535.
    let read_withs = PublishDeposits { read_with: vec![set_s(); 21_845], ..PublishDeposits::default() };
    let one_run = price_publication_reads(world, P1, &ALL_VISIBLE, &target, &the_shot, &[], &[], &read_withs, &mut |_| {});
    assert_eq!((one_run.homes * one_run.entries, one_run.rewindow, one_run.fence), (MAX_PUBLICATION_READS - 1, 0, 1));
    assert!(!one_run.reads_over_budget(), "one re-inserted run: at the budget");
    let two_runs = shot_off_head(&k, vec![shot_run(&doc1(), &ca(1), 3), shot_run(&doc1(), &ca(2), 1)]);
    let over = price_publication_reads(world, P1, &ALL_VISIBLE, &target, &two_runs, &[], &[], &read_withs, &mut |_| {});
    assert_eq!((over.rewindow, over.fence, over.total()), (0, 2, MAX_PUBLICATION_READS + 1));
    assert!(over.reads_over_budget() && !over.bytes_over_budget(), "a second re-inserted run, placed nowhere, is past the budget on the fence's stab");
}

/// THE STAGED BYTES' SHAPES (lane F4): what the fifth term prices off the
/// request alone, each against the formula — a kept place on a
/// draft-native run (`KEPT_PLACE_BYTES` per piece, a run cut by another
/// run's endpoints inside it priced per piece, and the re-windowed draft's
/// one record once, its address beside it); a kept place on a stray
/// run (per record of the draft overlapping it, one here; one where none
/// does, the arm refusing it); the mint form's two; a copy's `spans` form at
/// its own spans; and the member-position form's amplification, which the
/// product of caps hid: a hundred `links` entries whose `from` names the
/// member's 4096 positions, over a shot of 4096 runs, price past
/// `MAX_TXN_BYTES` from a request of a few hundred kilobytes, where one
/// such entry is well inside it.
#[test]
fn the_staged_bytes_are_priced_per_piece_per_record_and_per_span_the_request_spells() {
    use skep_links::{
        price_staged_bytes, stored_span_bytes, ReadPrice, CLAIM_BYTES, COPY_FIXED_BYTES, CORRESPONDENCE_RECORD_BYTES, EDITION_CLAIM_BYTES,
        EDITION_MINT_BYTES, KEPT_PLACE_BYTES, PLACED_RUN_BYTES, REINSERTED_UNIT_BYTES, REWINDOWED_DRAFT_BYTES, SHOT_BYTES,
    };

    let k = kernel_over(deposits_world());
    board(&k);
    let s = k.snapshot();
    let world = s.world();
    let target = PublishTarget::Document(pdoc());
    let none = PublishDeposits::default();
    let birth = |runs: Vec<ShotRun>| Shot { base: None, draft: Some(doc1()), also: vec![], keep_base: false, runs, stretches: Vec::new() };
    // Every shot here names doc1 as its rendering draft, whose address the
    // placing record carries in its own slot.
    let drafted = SHOT_BYTES + skep_links::stored_tumbler_bytes(doc1().tumbler());
    // Where a list carries a place doc1 is re-windowed: its one record, the
    // draft's address in it, whatever the places number.
    let rewindowed = REWINDOWED_DRAFT_BYTES + skep_links::stored_tumbler_bytes(doc1().tumbler());
    // Draft-native: `a b c` whole and `b` inside it — the first cut at `b`'s
    // two endpoints into three pieces, the second one piece; both placed.
    let nested = birth(vec![shot_run(&doc1(), &ca(1), 3), shot_run(&doc1(), &ca(2), 1)]);
    let per_piece = PLACED_RUN_BYTES + CORRESPONDENCE_RECORD_BYTES;
    assert_eq!(
        price_staged_bytes(world, &ALL_VISIBLE, &target, &nested, &[], &[], &none),
        drafted + (3 + 1) * per_piece + (REINSERTED_UNIT_BYTES + 3),
        "three pieces and one; the re-insert one unit — the three typed bytes, the second run's position minted by the first — and its bytes"
    );
    assert_eq!(
        price_staged_bytes(world, &ALL_VISIBLE, &target, &nested, &places(2, &[(0, 1), (1, 2)]), &[], &none),
        drafted + rewindowed + (3 + 1) * (per_piece + KEPT_PLACE_BYTES) + (REINSERTED_UNIT_BYTES + 3),
        "a kept place per piece, and the draft's one record once"
    );
    // Stray: the head's identity, which the board's one record names, with
    // a place — one record; identity no record names — priced as one piece,
    // the arm refusing it.
    let stray = birth(vec![shot_run(&pdoc(), &pca(1), 3)]);
    assert_eq!(price_staged_bytes(world, &ALL_VISIBLE, &target, &stray, &places(1, &[(0, 1)]), &[], &none), drafted + rewindowed + PLACED_RUN_BYTES + KEPT_PLACE_BYTES);
    let unrecorded = birth(vec![shot_run(&pdoc(), &pca(9), 1)]);
    assert_eq!(price_staged_bytes(world, &ALL_VISIBLE, &target, &unrecorded, &places(1, &[(0, 1)]), &[], &none), drafted + rewindowed + PLACED_RUN_BYTES + KEPT_PLACE_BYTES);
    // The mint form's two, and a copy in the I-span form at its own spans.
    let mint = PublishTarget::Mint { account: a(&[1, 0, 1]) };
    let spans = EndArg::Spans(vec![run(&pca(1), 2).iextent(), run(&pca(5), 1).iextent()]);
    let copy = PublishDeposits { claim: true, links: vec![entry(NamedAddress::Edition, spans.clone(), spans, addrs(&[&citation()]), None)], ..PublishDeposits::default() };
    let span_bytes: u64 = [run(&pca(1), 2), run(&pca(5), 1)].iter().map(|r| stored_span_bytes(&r.iextent())).sum();
    assert_eq!(
        price_staged_bytes(world, &ALL_VISIBLE, &mint, &birth(vec![]), &[], &[], &copy),
        drafted + EDITION_MINT_BYTES + EDITION_CLAIM_BYTES + COPY_FIXED_BYTES + 2 * span_bytes + stored_span_bytes(&skep_address::subtree_of(citation().tumbler())),
        "the mint and the claim, the copy at its four spans and its type, no claim without an original"
    );
    // A shot naming no draft prices the fixed records alone, and one naming
    // a base beside them the base's address, at its own bytes.
    let undrafted = Shot { base: None, draft: None, also: vec![], keep_base: false, runs: vec![], stretches: Vec::new() };
    assert_eq!(price_staged_bytes(world, &ALL_VISIBLE, &target, &undrafted, &[], &[], &none), SHOT_BYTES, "no draft named, no address priced");
    let head = trunk_head(world.m3(), &pdoc()).expect("a head");
    let based = Shot {
        base: Some(skep_arrangement::Base { member: head.clone(), extent: n(0) }),
        ..undrafted.clone()
    };
    assert_eq!(
        price_staged_bytes(world, &ALL_VISIBLE, &target, &based, &[], &[], &none),
        SHOT_BYTES + skep_links::stored_tumbler_bytes(head.tumbler()),
        "the base named, its address priced in the terms' slot"
    );
    assert!(CLAIM_BYTES > 0);
    // The member-position form's amplification.
    let wide = |count: usize| PublishDeposits {
        links: (0..count).map(|_| entry(NamedAddress::Member, member_spans(1, 4096), addrs(&[]), addrs(&[&citation()]), None)).collect(),
        ..PublishDeposits::default()
    };
    let many = birth((0..4096).map(|_| shot_run(&doc1(), &ca(1), 1)).collect());
    let one = price_staged_bytes(world, &ALL_VISIBLE, &target, &many, &[], &[], &wide(1));
    let hundred = price_staged_bytes(world, &ALL_VISIBLE, &target, &many, &[], &[], &wide(100));
    let content_span = stored_span_bytes(&run(&pca(1), 1).iextent());
    assert_eq!(hundred - one, 99 * (COPY_FIXED_BYTES + 4096 * content_span + stored_span_bytes(&skep_address::subtree_of(citation().tumbler()))));
    assert!(one < ReadPrice::BYTE_BUDGET, "one wide entry over the many-run shot is inside the budget: {one}");
    assert!(hundred > ReadPrice::BYTE_BUDGET, "a hundred are past it: {hundred} against {}", ReadPrice::BYTE_BUDGET);
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
    use skep_address::subtree_of;
    use skep_links::{
        stored_span_bytes, CLAIM_BYTES, COPY_BYTES, COPY_FIXED_BYTES, CORRESPONDENCE_RECORD_BYTES, EDITION_CLAIM_BYTES,
        EDITION_MINT_BYTES, KEPT_PLACE_BYTES, MAX_SLOT_SPANS, PLACED_RUN_BYTES, READ_WITH_BYTES, REINSERTED_UNIT_BYTES,
        RETRACTION_BYTES, REWINDOWED_DRAFT_BYTES, SHOT_BYTES, STRETCH_BYTES,
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
        Shot { base: Some(skep_arrangement::Base { member: head, extent }), draft, also: vec![], keep_base: false, runs: fresh, stretches: Vec::new() }
    };
    let measure = |f: &dyn Fn()| {
        let before = k.journal_bytes();
        f();
        k.journal_bytes() - before - marker
    };
    let commit = |target: &PublishTarget, the_shot: &Shot, places: &[Option<VPos>], deposits: &PublishDeposits| {
        writer(&k).publication(P1, target, the_shot, places, &[], deposits).expect("the commit");
    };
    let into_e = PublishTarget::Document(pdoc());
    let none = PublishDeposits::default();
    // A shot with fresh runs names doc1 as its rendering draft, whose address
    // the placing record carries in its own slot — taken off every figure
    // measured against a shot that names none, as the price takes it. Every
    // shot here names the head as its base, whose address the terms carry
    // in their own slot — taken off the fixed figure the same way; the head
    // each shot names is a member of one depth, so of one stored size.
    let drafted = skep_links::stored_tumbler_bytes(doc1().tumbler());
    let based = skep_links::stored_tumbler_bytes(
        trunk_head(k.snapshot().world().m3(), &pdoc()).expect("a head").tumbler(),
    );
    let shot_bytes = measure(&|| commit(&into_e, &base_shot(vec![]), &[], &none));
    let window = measure(&|| commit(&into_e, &base_shot(vec![shot_run(&pdoc(), &pca(1), 3)]), &[], &none));
    let placed_run = window - shot_bytes - drafted;
    // The copy at every slot's budget: `from` and `to` at `MAX_SLOT_SPANS`
    // content I-spans of the shallow depth, the type at as many unit spans.
    let full = LinkEntry {
        home: NamedAddress::Member,
        from: EndArg::Spans((1..=MAX_SLOT_SPANS as u32).map(|i| run(&pca(i), 1).iextent()).collect()),
        to: EndArg::Spans((1..=MAX_SLOT_SPANS as u32).map(|i| run(&pca(i), 1).iextent()).collect()),
        ty: EndArg::Addrs((1..=MAX_SLOT_SPANS as u32).map(|i| NamedAddress::Address(a(&[1, 1, 0, 1, 0, 1, 0, 3, 23, i]))).collect()),
        old: None,
    };
    let with = |links: Vec<LinkEntry>, retract: Vec<Address>, read_with: Vec<Address>| PublishDeposits { claim: false, links, retract, read_with, supersede: vec![], originals: vec![], base_runs: vec![] };
    let copy = measure(&|| commit(&into_e, &base_shot(vec![]), &[], &with(vec![full.clone()], vec![], vec![]))) - shot_bytes;
    // THE SHOT AT AN EMPTY HEAD: the shots above left the head a member of
    // no positions, and a shot off it carries `base_extent` 0 — a zero
    // `Nat` is four bytes shorter than 3 — so every records-less shot from
    // here is measured against this shot of the same shape, not the first
    // (which S4 subtracted, leaving two of its figures four bytes low).
    let shot_bytes_at_an_empty_head = measure(&|| commit(&into_e, &base_shot(vec![]), &[], &none));
    assert_eq!(shot_bytes - shot_bytes_at_an_empty_head, 4, "a zero base extent is one 32-bit digit shorter");
    // The copy's fixed part and a span's own bytes, each at its depth (lane
    // F4): the copy with `from` and `to` empty and one type address; then
    // one content span in `from`; then a second type address — the two
    // differences the span function must price, and the fixed part what is
    // left of the first once its one span is taken off.
    let bare = |from: EndArg, ty: &[&Address]| with(vec![entry(NamedAddress::Member, from, addrs(&[]), addrs(ty), None)], vec![], vec![]);
    let other_type = a(&[1, 1, 0, 1, 0, 1, 0, 3, 23, 1]);
    let empty_copy = measure(&|| commit(&into_e, &base_shot(vec![]), &[], &bare(EndArg::Spans(vec![]), &[&citation()]))) - shot_bytes_at_an_empty_head;
    let one_content_span = measure(&|| commit(&into_e, &base_shot(vec![]), &[], &bare(ispans(&pca(1), 3), &[&citation()]))) - shot_bytes_at_an_empty_head;
    let two_types = measure(&|| commit(&into_e, &base_shot(vec![]), &[], &bare(EndArg::Spans(vec![]), &[&citation(), &other_type]))) - shot_bytes_at_an_empty_head;
    assert_eq!(one_content_span - empty_copy, stored_span_bytes(&run(&pca(1), 3).iextent()), "a content span's bytes, as the function prices them");
    assert_eq!(two_types - empty_copy, stored_span_bytes(&subtree_of(other_type.tumbler())), "a ten-component unit span's bytes");
    let copy_fixed = empty_copy - stored_span_bytes(&subtree_of(citation().tumbler()));
    let small = |old: Option<Address>| entry(NamedAddress::Member, ispans(&pca(1), 3), addrs(&[&doc2()]), addrs(&[&citation()]), old);
    let small_alone = measure(&|| commit(&into_e, &base_shot(vec![]), &[], &with(vec![small(None)], vec![], vec![])));
    let small_claimed = measure(&|| commit(&into_e, &base_shot(vec![]), &[], &with(vec![small(Some(l.clone()))], vec![], vec![])));
    let claim = small_claimed - small_alone;
    let retraction = measure(&|| commit(&into_e, &base_shot(vec![]), &[], &with(vec![], vec![m.clone()], vec![]))) - shot_bytes_at_an_empty_head;
    let read_with = measure(&|| commit(&into_e, &base_shot(vec![]), &[], &with(vec![], vec![], vec![set_s()]))) - shot_bytes_at_an_empty_head;
    // The re-insert: an atom at ca(4), a byte at ca(5), a byte at ca(6)
    // re-windowed at its place — each shot placing its one fresh run, and
    // minting its one record. The atom's shot is made off the empty head
    // the shots above left, and is measured against the shot of that shape
    // (against the first it reads four bytes low, a zero base extent being
    // one digit shorter); every shot after it is off a head holding a
    // position, as the first was.
    let vs = Vstream::new(&k);
    vs.insert(P1, &doc1(), vp(1, 4), vec![Val::new([b'x', b'y'])], Deposit::Undeclared, AsOf::Typed(k.current_seq())).expect("an atom at ca(4)");
    vs.insert(P1, &doc1(), vp(1, 5), vec![Val::new([b'd'])], Deposit::Undeclared, AsOf::Typed(k.current_seq())).expect("d at ca(5)");
    vs.insert(P1, &doc1(), vp(1, 6), vec![Val::new([b'e'])], Deposit::Undeclared, AsOf::Typed(k.current_seq())).expect("e at ca(6)");
    let atom = measure(&|| commit(&into_e, &base_shot(vec![shot_run(&doc1(), &ca(4), 1)]), &[], &none)) - shot_bytes_at_an_empty_head - drafted - placed_run - record;
    let byte = measure(&|| commit(&into_e, &base_shot(vec![shot_run(&doc1(), &ca(5), 1)]), &[], &none)) - shot_bytes - drafted - placed_run - record;
    let byte_placed = measure(&|| commit(&into_e, &base_shot(vec![shot_run(&doc1(), &ca(6), 1)]), &places(1, &[(0, 6)]), &none)) - shot_bytes - drafted - placed_run - record;
    assert_eq!(bytes_of(&k, &doc1()), "abcxyde", "doc1 reads as it did, its last byte re-windowed");
    // The re-window's one record, told apart into its two figures: what one
    // place costs is what a second place adds — two shots of one shape, two
    // bytes apart in the draft, the first with no place and the second with
    // both placed — and what the record costs past its places is the one
    // placed byte's cost less that place and the draft's own address.
    for (at, byte) in (7u32..).zip(*b"fghijkl") {
        vs.insert(P1, &doc1(), vp(1, at), vec![Val::new([byte])], Deposit::Undeclared, AsOf::Typed(k.current_seq())).expect("a byte more");
    }
    let apart = |first: u32, placed: bool| {
        let fresh = vec![shot_run(&doc1(), &ca(first), 1), shot_run(&doc1(), &ca(first + 2), 1)];
        let kept = if placed { places(2, &[(0, first), (1, first + 2)]) } else { vec![] };
        measure(&|| commit(&into_e, &base_shot(fresh.clone()), &kept, &none))
    };
    let (two_runs, two_placed) = (apart(7, false), apart(11, true));
    let rewindowed_once = byte_placed - byte;
    let kept_place = (two_placed - two_runs) - rewindowed_once;
    let rewindowed_draft = rewindowed_once - kept_place - drafted;
    assert_eq!(bytes_of(&k, &doc1()), "abcxydefghijkl", "doc1 reads as it did through both re-windows");
    // The unit's own bytes on top of its fixed part: four bytes typed
    // together, one stretch, re-inserted as one unit — and an atom of five
    // bytes beside the atom of two.
    let typed = b"mnop".iter().map(|byte| Val::new([*byte])).collect();
    vs.insert(P1, &doc1(), vp(1, 14), typed, Deposit::Undeclared, AsOf::Typed(k.current_seq())).expect("four bytes at ca(14..=17)");
    vs.insert(P1, &doc1(), vp(1, 18), vec![Val::new(&b"vwxyz"[..])], Deposit::Undeclared, AsOf::Typed(k.current_seq())).expect("an atom at ca(18)");
    let run_of_four = measure(&|| commit(&into_e, &base_shot(vec![shot_run(&doc1(), &ca(14), 4)]), &[], &none)) - shot_bytes - drafted - placed_run - record;
    let atom_of_five = measure(&|| commit(&into_e, &base_shot(vec![shot_run(&doc1(), &ca(18), 1)]), &[], &none)) - shot_bytes - drafted - placed_run - record;
    // The mint form: the edition's mint over a birth shot into `S`, the
    // claim over the mint form without one.
    let birth = Shot { base: None, draft: None, also: vec![], keep_base: false, runs: vec![], stretches: Vec::new() };
    let birth_s = measure(&|| commit(&PublishTarget::Document(set_s()), &birth, &[], &none));
    let account = a(&[1, 0, 1]);
    let minted = measure(&|| commit(&PublishTarget::Mint { account: account.clone() }, &birth, &[], &none));
    let edition_mint = minted - birth_s;
    let drafted_birth = Shot { base: None, draft: Some(doc1()), also: vec![], keep_base: false, runs: vec![], stretches: Vec::new() };
    let claimed_deposits = PublishDeposits { claim: true, ..PublishDeposits::default() };
    let claimed = measure(&|| commit(&PublishTarget::Mint { account: account.clone() }, &drafted_birth, &[], &claimed_deposits));
    let edition_claim = claimed - minted - drafted;
    // The claim at the document form (skep #692): a drafted birth claiming
    // into an empty edition `doc` names, against the plain birth into
    // another — two editions minted under the account for it, at the depth
    // of the one the mint form mints — so the table's one figure stands for
    // either form.
    let fresh_edition = || {
        k.transact(&[M3State::document_lock_key(&account)], |stg| {
            let (edition, rec) = stg.working().m3().mint_document(&account, true).map_err(PublicationError::Mint)?;
            stg.push(rec.into());
            Ok::<Address, PublicationError>(edition)
        })
        .expect("an empty edition under the account")
        .0
    };
    let (plain_edition, claimed_edition) = (fresh_edition(), fresh_edition());
    let birth_plain = measure(&|| commit(&PublishTarget::Document(plain_edition.clone()), &birth, &[], &none));
    let birth_claimed = measure(&|| commit(&PublishTarget::Document(claimed_edition.clone()), &drafted_birth, &[], &claimed_deposits));
    let document_claim = birth_claimed - birth_plain - drafted;
    // A stretch's entry: one window placed off a head of three positions,
    // first as the whole arrangement and then as the change that replaces
    // all three — one member either way, and two records that differ by the
    // one entry, its start, its width and its count of positions each a
    // 32-bit digit. The first shot leaves the head at three positions for
    // the two measured.
    let window_shot = || base_shot(vec![shot_run(&pdoc(), &pca(1), 3)]);
    commit(&into_e, &window_shot(), &[], &none);
    let whole_form = measure(&|| commit(&into_e, &window_shot(), &[], &none));
    let by_its_stretch = measure(&|| {
        let mut shot = window_shot();
        let extent = shot.base.as_ref().expect("a base").extent.clone();
        assert_eq!(extent, n(3), "the head the whole form left");
        shot.stretches = vec![skep_arrangement::ShotStretch { start: n(1), width: extent, count: 1 }];
        commit(&into_e, &shot, &[], &none);
    });
    let stretch = by_its_stretch - whole_form;

    let table = [
        ("CORRESPONDENCE_RECORD_BYTES", record, CORRESPONDENCE_RECORD_BYTES),
        ("COPY_BYTES", copy, COPY_BYTES),
        ("COPY_FIXED_BYTES", copy_fixed, COPY_FIXED_BYTES),
        ("CLAIM_BYTES", claim, CLAIM_BYTES),
        ("RETRACTION_BYTES", retraction, RETRACTION_BYTES),
        ("READ_WITH_BYTES", read_with, READ_WITH_BYTES),
        ("KEPT_PLACE_BYTES", kept_place, KEPT_PLACE_BYTES),
        ("REWINDOWED_DRAFT_BYTES", rewindowed_draft, REWINDOWED_DRAFT_BYTES),
        ("PLACED_RUN_BYTES", placed_run, PLACED_RUN_BYTES),
        ("STRETCH_BYTES", stretch, STRETCH_BYTES),
        ("REINSERTED_UNIT_BYTES, a run of one byte past its byte", byte - 1, REINSERTED_UNIT_BYTES),
        ("REINSERTED_UNIT_BYTES, a run of four bytes past its bytes", run_of_four - 4, REINSERTED_UNIT_BYTES),
        // The shot measured places nothing: its count is a zero, one 32-bit
        // digit under the figure, which is a shot's with a count and an
        // extent both.
        ("SHOT_BYTES", shot_bytes - based + 4, SHOT_BYTES),
        ("EDITION_MINT_BYTES", edition_mint, EDITION_MINT_BYTES),
        ("EDITION_CLAIM_BYTES", edition_claim, EDITION_CLAIM_BYTES),
        ("EDITION_CLAIM_BYTES at the document form", document_claim, EDITION_CLAIM_BYTES),
    ];
    println!(
        "the marker: {marker}; a one-byte value's stretch and range mint: {byte}; a birth shot: {birth_s}; a copy at one span a slot: {}",
        small_alone - shot_bytes_at_an_empty_head
    );
    for (name, measured, pinned) in table {
        println!("{name}: measured {measured}, pinned {pinned}");
    }
    for (name, measured, pinned) in table {
        assert_eq!(measured, pinned, "{name} moved: the kernel prices the kind at {measured} bytes, the table says {pinned}");
    }
    // An atom is a unit priced at the same figure and its own length: as a
    // shot's one unit its two records are eleven bytes under a byte-run's —
    // its mint carries no count — so the figure bounds it, whatever its
    // length. (Each unit after a shot's first stages four bytes fewer still;
    // `a_reinsert_of_atoms_or_of_long_byte_runs_is_priced_at_or_above_what_it_stages`
    // counts that.)
    println!("an atom of two bytes: {atom}; of five: {atom_of_five}");
    assert_eq!((atom - 2, atom_of_five - 5), (REINSERTED_UNIT_BYTES - 11, REINSERTED_UNIT_BYTES - 11), "an atom past its bytes, at either length");
    // The figures the module's cards quote beside the table: the marker the
    // kernel's own card states, the birth shape's shot, a byte run's stretch
    // and the one-span copy the arithmetic's second verdict reads — the
    // copy's fixed part and its three spans at their depths.
    let one_span_copy = small_alone - shot_bytes_at_an_empty_head;
    assert_eq!(
        (marker, birth_s, byte, one_span_copy),
        (109, 276, 301, 1_029),
        "the quoted figures"
    );
    // A kept place's change is its ordinal, its width and its run count
    // around the one run it places, which is the placement's own figure.
    assert_eq!(KEPT_PLACE_BYTES - PLACED_RUN_BYTES, 32, "a change past its run");
    assert_eq!(
        one_span_copy,
        COPY_FIXED_BYTES + stored_span_bytes(&run(&pca(1), 3).iextent()) + stored_span_bytes(&subtree_of(doc2().tumbler())) + stored_span_bytes(&subtree_of(citation().tumbler())),
        "the one-span copy is the fixed part and its three spans"
    );
}

#[test]
fn the_plan_is_a_pure_function_of_the_world_and_the_request() {
    let k = kernel_over(deposits_world());
    let (l, m) = board(&k);
    writer(&k).nullify(P1, &pmember(1), &m).expect("the mark taken off");
    let the_shot = shot_off_head(&k, vec![]);
    let deposits = PublishDeposits {
        claim: false,
        links: vec![entry(NamedAddress::Member, member_spans(1, 3), addrs(&[&doc2()]), addrs(&[&citation()]), Some(l.clone()))],
        retract: vec![m.clone()],
        read_with: vec![set_s()],
        supersede: vec![],
        originals: vec![],
        base_runs: vec![],
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

/// A records-less shot off `base`, re-supplying its positions by reference.
fn shot_off(k: &Kernel<World>, base: &Address) -> Shot {
    let s = k.snapshot();
    let m5 = s.world().m5();
    let runs = m5.content_runs(base).map(|r| ShotRun { origin: pdoc(), run: r.clone() }).collect();
    Shot { base: Some(skep_arrangement::Base { member: base.clone(), extent: m5.content_count(base) }), draft: None, also: vec![], keep_base: false, runs, stretches: Vec::new() }
}

/// THE PLAN AND THE SHOT AGREE WHERE THE MEMBER LANDS (skep #806): over a
/// kernel holding `E.1`, the head `E.2` and the daughter `E.1.1`, a shot off
/// each base the trunk moved past — the older member `E.1`, the bare
/// document, the daughter — naming `E.1.1` superseded is refused
/// `head_moved` naming the head, nothing committed, while the same shot
/// with no deposit lands where M5's destination puts it, a daughter and
/// never the trunk's next member (`E.1.2`, then `E.1.3`, then `E.1.1.1`);
/// off the head it lands the trunk's next member `E.3` and the claim naming
/// it. The plan's head check and M5's destination rule are two spellings of
/// one rule, and this holds them to each other.
#[test]
fn a_shot_naming_a_daughter_lands_on_the_trunk_or_is_refused_as_head_moved() {
    use skep_links::{supersession_claim_in, SupersedeCause};

    let k = kernel_over(deposits_world());
    draft_holding(&k, "abc");
    let none = PublishDeposits::default();
    assert_eq!(publish(&k, &shot(None, vec![shot_run(&doc1(), &ca(1), 3)]), &none).expect("E.1").0, pmember(1));
    assert_eq!(publish(&k, &shot_off(&k, &pmember(1)), &none).expect("E.2").0, pmember(2));
    let e11 = publish(&k, &shot_off(&k, &pmember(1)), &none).expect("E.1.1").0;
    assert_eq!(e11, a(&[1, 0, 1, 0, nth_doc(3), 1, 1]), "off the member the trunk moved past: its daughter");
    let merge = PublishDeposits { supersede: vec![e11.clone()], ..PublishDeposits::default() };
    let head_moved = PlanFault::Supersede { index: 0, cause: SupersedeCause::HeadMoved(pmember(2)) };
    for (base, lands) in [
        (pmember(1), a(&[1, 0, 1, 0, nth_doc(3), 1, 2])),
        (pdoc(), a(&[1, 0, 1, 0, nth_doc(3), 1, 3])),
        (e11.clone(), a(&[1, 0, 1, 0, nth_doc(3), 1, 1, 1])),
    ] {
        let off = shot_off(&k, &base);
        assert_eq!(refused_plan(&k, &off, merge.clone()), head_moved, "off {base}: refused, nothing committed");
        assert_eq!(publish(&k, &off, &none).expect("the shot alone lands").0, lands, "off {base}: M5 mints a daughter");
        assert_eq!(trunk_head(k.snapshot().world().m3(), &pdoc()), Some(pmember(2)), "off {base}: the head stands");
    }
    let (member, _) = publish(&k, &shot_off(&k, &pmember(2)), &merge).expect("off the head, the merge lands");
    assert_eq!(member, pmember(3), "the trunk's next member");
    let s = k.snapshot();
    assert!(supersession_claim_in(s.world().links(), &pdoc(), &e11, &member), "the claim names the trunk's next member");
}

// ───────────────── the originals the commit ends (the private rider) ─────────────────

/// The rider naming `old` with `rest`.
fn originals(entries: Vec<(Address, Vec<Span>)>) -> PublishDeposits {
    PublishDeposits {
        originals: entries.into_iter().map(|(old, rest)| OriginalEntry { old, rest }).collect(),
        ..PublishDeposits::default()
    }
}

/// THE BOARD after the accept: `board`, then `L`'s copy into `E.2` with its
/// claim in the notes. Answers `(L, M, the copy)`: the copy `E.2`'s first
/// link, the claim the notes' second.
fn accepted(k: &Kernel<World>) -> (Address, Address, Address) {
    let (l, m) = board(k);
    let copy = entry(NamedAddress::Member, member_spans(1, 3), addrs(&[&doc2()]), addrs(&[&citation()]), Some(l.clone()));
    let (e2, _) = publish(k, &shot_off_head(k, vec![]), &PublishDeposits { links: vec![copy], ..PublishDeposits::default() }).expect("L accepted");
    assert_eq!(e2, pmember(2));
    let copy = link_of(&e2, 1);
    assert_eq!(k.snapshot().world().links().readlink(&link_of(&doc2(), 2)), Some(&supersession_claim(&l, &copy)), "the premise: the accept's claim");
    (l, m, copy)
}

/// THE TAKE-OFF ENDS THE ORIGINAL IN THE ONE COMMIT (the link-sets design
/// §5.7 (vi′); THE VALIDATION's (4′)): a publication retracting `L`'s copy
/// with the rider naming `L` lands as ONE commit — one boundary above the
/// position before it, on a journaled kernel — after which the copy and the
/// original are both off the active view, the original's retraction tuple
/// is the notes' next link, minted at the commit's coordinate, unseated as
/// `nullify` leaves it, and the accept's claim stands active, provenance;
/// the plan holds the original in its own list and in no home, so the
/// signed rows name no private write; and the member alone, with no copy
/// to fold under, is drawn nowhere after.
#[test]
fn a_take_off_naming_its_original_ends_it_in_the_one_commit() {
    let k = journaled_over(deposits_world());
    let (l, _, copy) = accepted(&k);
    let the_shot = shot_off_head(&k, vec![]);
    let deposits = PublishDeposits { retract: vec![copy.clone()], ..originals(vec![(l.clone(), vec![])]) };
    let before = k.snapshot();
    // The plan: the original outside the homes, which build the signed body.
    let plan = plan_deposits(before.world(), P1, &PublishTarget::Document(pdoc()), &the_shot, &deposits).expect("planned");
    assert_eq!(plan.originals.len(), 1);
    assert_eq!((plan.originals[0].index, &plan.originals[0].old, &plan.originals[0].home, &plan.originals[0].rest), (0, &l, &doc2(), &None));
    assert_eq!(plan.homes.len(), 1, "the retraction's home alone: {plan:?}");
    assert_eq!(plan.homes[0].home, NamedAddress::Address(pmember(2)));
    assert!(plan.homes.iter().all(|h| h.home != NamedAddress::Address(doc2())), "the original's home is in no row");
    let (member, seq) = publish(&k, &the_shot, &deposits).expect("the take-off");
    assert_eq!(member, pmember(3));
    assert_eq!(k.boundaries_above(before.seq()).expect("boundaries"), vec![(seq, None)], "ONE commit: the member, the copy's retraction and the original's");
    let s = k.snapshot();
    let (links, m3) = (s.world().links(), s.world().m3());
    assert!(!links.is_active(&copy), "the copy is off the active view");
    assert!(!links.is_active(&l), "and so is its original");
    let retraction = link_of(&doc2(), 3);
    assert_eq!(links.readlink(&retraction), Some(&retraction_tuple(&doc2(), &l)), "the original's retraction tuple, the notes' next link");
    assert_eq!(links.retractions_of(&l).collect::<Vec<_>>(), vec![retraction.clone()]);
    assert_eq!(m3.minted_at(&retraction), Some(seq), "minted at the one commit");
    assert_eq!(links.readlink(&link_of(&doc2(), 4)), None, "and nothing past it");
    assert_eq!(s.world().m5().link_count(&doc2()), n(1), "unseated, as nullify leaves a retraction: L alone is seated");
    assert!(links.is_active(&link_of(&doc2(), 2)), "the accept's claim stands");
}

/// A CUT COPY's REST KEEPS A FRESH MARK (the link-sets design §2, D5 (a)):
/// the mark `B` in the notes over the draft's `a b c d`, its copy cut at the
/// member's `a b c`; the take-off names `B` with the rest `d` as its one
/// span, and the one commit writes, in the notes, FIRST a fresh mark of `B`'s
/// type over exactly `d` in the end `B` holds it in — seated, as any draft
/// formatting is — THEN `B`'s retraction, the addresses rising in that
/// order (THE PIN); the fresh mark active, `B` not, the copy not. The price
/// carries the mark: a copy's fixed part, the rest's span and `B`'s stored
/// type span, beside the retraction.
#[test]
fn a_cut_copys_rest_keeps_a_fresh_mark_written_ahead_of_the_originals_retraction() {
    use skep_links::{price_staged_bytes, stored_span_bytes, COPY_FIXED_BYTES, RETRACTION_BYTES};

    let k = kernel_over(deposits_world());
    board(&k);
    Vstream::new(&k).insert(P1, &doc1(), vp(1, 4), vec![Val::new([b'd'])], Deposit::Undeclared, AsOf::Typed(k.current_seq())).expect("d at ca(4)");
    let ty = a(&[1, 1, 0, 1, 0, 1, 0, 3, 23, 2]);
    let b = writer(&k)
        .makelink(P1, &doc2(), SlotArg::Spans(vec![run(&ca(1), 4).iextent()]), SlotArg::Addrs(vec![]), SlotArg::Addrs(vec![ty.clone()]))
        .expect("the mark over the whole run")
        .0;
    assert_eq!(b, link_of(&doc2(), 2));
    let copy_entry = entry(NamedAddress::Member, member_spans(1, 3), addrs(&[]), addrs(&[&ty]), Some(b.clone()));
    let (e2, _) = publish(&k, &shot_off_head(&k, vec![]), &PublishDeposits { links: vec![copy_entry], ..PublishDeposits::default() }).expect("the copy, cut at the selection");
    let copy = link_of(&e2, 1);
    let rest = run(&ca(4), 1).iextent();
    let the_shot = shot_off_head(&k, vec![]);
    let deposits = PublishDeposits { retract: vec![copy.clone()], ..originals(vec![(b.clone(), vec![rest.clone()])]) };
    let target = PublishTarget::Document(pdoc());
    let snap = k.snapshot();
    let plan = plan_deposits(snap.world(), P1, &target, &the_shot, &deposits).expect("planned");
    let fresh = Link::triple(Endset::from_spans([rest.clone()]), Endset::empty(), enc([&ty]));
    assert_eq!(plan.originals[0].rest, Some(fresh.clone()), "the fresh mark: B's type over exactly the rest, in the end B holds it in");
    let base = price_staged_bytes(snap.world(), &ALL_VISIBLE, &target, &the_shot, &[], &[], &PublishDeposits { retract: vec![copy.clone()], ..PublishDeposits::default() });
    assert_eq!(
        price_staged_bytes(snap.world(), &ALL_VISIBLE, &target, &the_shot, &[], &[], &deposits) - base,
        RETRACTION_BYTES + COPY_FIXED_BYTES + stored_span_bytes(&rest) + stored_span_bytes(&skep_address::subtree_of(ty.tumbler())),
        "the rider's price: the retraction, and the fresh mark at its spans"
    );
    assert_eq!(
        price_staged_bytes(snap.world(), &ALL_VISIBLE, &target, &the_shot, &[], &[], &PublishDeposits { retract: vec![copy.clone()], ..originals(vec![(b.clone(), vec![])]) }) - base,
        RETRACTION_BYTES,
        "no rest: the retraction alone"
    );
    let seated_before = snap.world().m5().link_count(&doc2());
    let (member, seq) = publish(&k, &the_shot, &deposits).expect("the take-off with its rest");
    assert_eq!(member, pmember(3));
    let s = k.snapshot();
    let (links, m3, m5) = (s.world().links(), s.world().m3(), s.world().m5());
    let (mark, retraction) = (link_of(&doc2(), 4), link_of(&doc2(), 5));
    assert_eq!(links.readlink(&mark), Some(&fresh), "the fresh mark first");
    assert_eq!(links.readlink(&retraction), Some(&retraction_tuple(&doc2(), &b)), "then B's retraction");
    assert_eq!(links.readlink(&link_of(&doc2(), 6)), None);
    assert_eq!((m3.minted_at(&mark), m3.minted_at(&retraction)), (Some(seq), Some(seq)));
    assert_eq!(m5.link_count(&doc2()), &seated_before + n(1), "the mark is seated, the retraction not");
    assert!(links.is_active(&mark), "the rest keeps its formatting as the draft's own");
    assert!(!links.is_active(&b) && !links.is_active(&copy), "the mark taken off is drawn nowhere");
    assert_eq!(bytes_of(&k, &member), "abc");
}

/// THE REFUSALS of the rider, each with its entry and nothing committed
/// (THE VALIDATION's (4′)), in the step's order: an absent address, another
/// account's link, the public mark in `E.1`, a second entry naming one
/// original (the SECOND), a rest span that is no content span, a rest past
/// the slot budget, a rest span outside the original, an original no claim
/// of the caller's names, one whose claim names a copy this request does
/// not retract, one whose claim is retracted; and the order among the
/// lists — (4) ahead of (4′) ahead of (5), (3) ahead of them all.
#[test]
fn each_refused_original_names_its_entry_and_commits_nothing() {
    let k = kernel_over(deposits_world());
    let (l, m) = board(&k);
    let w = writer(&k);
    let theirs = w.makelink(P2, &sib_doc(), SlotArg::Addrs(vec![sib_doc()]), SlotArg::Addrs(vec![]), SlotArg::Addrs(vec![citation()])).expect("their link").0;
    let the_shot = shot_off_head(&k, vec![]);
    let refused = |cause: OriginalCause, index: usize| PlanFault::Original { index, cause };
    let with_mark = |rider: PublishDeposits| PublishDeposits { retract: vec![m.clone()], ..rider };
    // Before any accept: no claim names L.
    assert_eq!(refused_plan(&k, &the_shot, with_mark(originals(vec![(link_of(&doc2(), 9), vec![])]))), refused(OriginalCause::Absent, 0));
    assert_eq!(refused_plan(&k, &the_shot, with_mark(originals(vec![(theirs.clone(), vec![])]))), refused(OriginalCause::NotOwner, 0), "another account's");
    assert_eq!(refused_plan(&k, &the_shot, with_mark(originals(vec![(m.clone(), vec![])]))), refused(OriginalCause::Public, 0), "the public mark");
    assert_eq!(refused_plan(&k, &the_shot, with_mark(originals(vec![(l.clone(), vec![])]))), refused(OriginalCause::Unclaimed, 0), "no claim names L");
    // The order among the lists.
    assert_eq!(
        refused_plan(&k, &the_shot, PublishDeposits { retract: vec![theirs.clone()], ..originals(vec![(link_of(&doc2(), 9), vec![])]) }),
        PlanFault::Retract { index: 0, cause: RetractCause::NotOwner },
        "(4) speaks ahead of (4′)"
    );
    assert_eq!(
        refused_plan(&k, &the_shot, PublishDeposits { read_with: vec![doc2()], ..with_mark(originals(vec![(link_of(&doc2(), 9), vec![])])) }),
        refused(OriginalCause::Absent, 0),
        "(4′) speaks ahead of (5)"
    );
    let private_home = entry(NamedAddress::Address(doc2()), ispans(&pca(1), 3), addrs(&[]), addrs(&[&citation()]), None);
    assert_eq!(
        refused_plan(&k, &the_shot, PublishDeposits { links: vec![private_home], ..with_mark(originals(vec![(link_of(&doc2(), 9), vec![])])) }),
        PlanFault::LinkHome { index: 0 },
        "(3) speaks ahead of (4′)"
    );
    // After the accept: L's copy in E.2, its claim in the notes.
    let copy_entry = entry(NamedAddress::Member, member_spans(1, 3), addrs(&[&doc2()]), addrs(&[&citation()]), Some(l.clone()));
    let (e2, _) = publish(&k, &the_shot, &PublishDeposits { links: vec![copy_entry], ..PublishDeposits::default() }).expect("L accepted");
    let copy = link_of(&e2, 1);
    let the_shot = shot_off_head(&k, vec![]);
    let with_copy = |rider: PublishDeposits| PublishDeposits { retract: vec![copy.clone()], ..rider };
    assert_eq!(refused_plan(&k, &the_shot, with_copy(originals(vec![(l.clone(), vec![]), (l.clone(), vec![])]))), refused(OriginalCause::Duplicate, 1), "the second entry naming L");
    assert_eq!(
        refused_plan(&k, &the_shot, with_copy(originals(vec![(l.clone(), vec![skep_address::subtree_of(doc1().tumbler())])]))),
        refused(OriginalCause::NotContentSpan, 0),
        "a rest span at a document's address"
    );
    let too_many: Vec<Span> = (0..=skep_links::MAX_SLOT_SPANS).map(|_| run(&ca(1), 1).iextent()).collect();
    assert_eq!(refused_plan(&k, &the_shot, with_copy(originals(vec![(l.clone(), too_many)]))), refused(OriginalCause::TooLarge, 0));
    assert_eq!(
        refused_plan(&k, &the_shot, with_copy(originals(vec![(l.clone(), vec![run(&ca(4), 1).iextent()])]))),
        refused(OriginalCause::RestOutside, 0),
        "a rest span outside L's words"
    );
    assert_eq!(refused_plan(&k, &the_shot, originals(vec![(l.clone(), vec![])])), refused(OriginalCause::Unclaimed, 0), "the claim's copy is not in this request's retract list");
    assert_eq!(refused_plan(&k, &the_shot, with_mark(originals(vec![(l.clone(), vec![])]))), refused(OriginalCause::Unclaimed, 0), "another mark retracted, not the copy");
    // The claim retracted: L is unclaimed again.
    w.nullify(P1, &doc2(), &link_of(&doc2(), 2)).expect("the claim retracted");
    assert_eq!(refused_plan(&k, &the_shot, with_copy(originals(vec![(l.clone(), vec![])]))), refused(OriginalCause::Unclaimed, 0), "a retracted claim admits nothing");
}

/// THE SKIP AND THE CONTROL: an original already retracted — taken off on
/// another device since the panel — is SKIPPED, the entry committing
/// nothing while the rest of the request lands; and a copy retracted
/// WITHOUT the rider leaves its original standing, active, which is the
/// state the rider exists to end.
#[test]
fn a_retracted_original_is_skipped_and_a_copy_retracted_without_the_rider_leaves_it_standing() {
    let k = kernel_over(deposits_world());
    let (l, _, copy) = accepted(&k);
    let w = writer(&k);
    // The control: the copy alone.
    let (e3, _) = publish(&k, &shot_off_head(&k, vec![]), &PublishDeposits { retract: vec![copy.clone()], ..PublishDeposits::default() }).expect("the copy retracted");
    assert_eq!(e3, pmember(3));
    let s = k.snapshot();
    assert!(!s.world().links().is_active(&copy) && s.world().links().is_active(&l), "no rider: the original stands");
    assert_eq!(s.world().links().readlink(&link_of(&doc2(), 3)), None, "nothing written in the notes");
    // The skip: L retracted on another device, then the request naming it
    // — the copy's entry skipped too, both already retracted — lands with
    // nothing written in the notes.
    let retraction = w.nullify(P1, &doc2(), &l).expect("L retracted elsewhere").fresh();
    assert_eq!(retraction, link_of(&doc2(), 3));
    let (e4, _) = publish(&k, &shot_off_head(&k, vec![]), &PublishDeposits { retract: vec![copy.clone()], ..originals(vec![(l.clone(), vec![])]) }).expect("the request lands");
    assert_eq!(e4, pmember(4));
    let s = k.snapshot();
    assert_eq!(s.world().links().readlink(&link_of(&doc2(), 4)), None, "the skipped entry writes nothing");
    assert_eq!(s.world().links().retractions_of(&l).collect::<Vec<_>>(), vec![retraction], "the one retraction, the other device's");
}

// ───────────────────────── the family (the Nelson way) ─────────────────────────

/// doc2 — P1's second private draft, the family's other draft — holding
/// `text`, one byte a position from `ca2(1)`, as P1's insert.
fn other_draft_holding(k: &Kernel<World>, text: &str) {
    let vals: Vec<Val> = text.bytes().map(|b| Val::new([b])).collect();
    Vstream::new(k)
        .insert(P1, &doc2(), vp(1, 1), vals, Deposit::Undeclared, AsOf::Typed(k.current_seq()))
        .expect("doc2's insert commits");
}

/// The correspondence records homed in doc2, in address order, each as its
/// link — every link of the draft typed the class, exactly.
fn records_in_doc2(k: &Kernel<World>) -> Vec<Link> {
    let s = k.snapshot();
    let links = s.world().links();
    (1u32..)
        .map_while(|ordinal| links.readlink(&la2(ordinal)).cloned())
        .filter(|link| is_correspondence_class(link.type_slot()))
        .collect()
}

/// A family shot: doc1 the rendering draft, doc2 named `also`, off `base`.
fn family(base: Option<(&Address, u32)>, runs: Vec<ShotRun>) -> Shot {
    Shot { also: vec![doc2()], ..shot(base, runs) }
}

/// THE FAMILY's ONE COMMIT (B3-S11 P4; A-328): a shot from doc1 naming doc2
/// `also`, rendering doc1's `a b c`, doc2's `x y` and doc1's `b` again,
/// commits the member and ONE record per minted piece, each homed in the
/// draft whose identity the piece was — doc1's in doc1, doc2's in doc2, the
/// `b` named again placed by reference and recorded once — in ONE
/// transaction: one boundary above the position before it, every record
/// and the member minted at the one commit's coordinate, each record seated
/// in its own draft's link subspace; the member reads every placed byte and
/// both drafts read as they did.
#[test]
fn a_family_publication_homes_each_record_in_the_draft_whose_identity_it_was_in_one_commit() {
    let k = journaled_over(edition_world());
    draft_holding(&k, "abc");
    other_draft_holding(&k, "xy");
    let before = k.snapshot();
    let the_shot = family(None, vec![shot_run(&doc1(), &ca(1), 3), shot_run(&doc2(), &ca2(1), 2), shot_run(&doc1(), &ca(2), 1)]);
    let (member, seq) = writer(&k)
        .publication(P1, &PublishTarget::Document(pdoc()), &the_shot, &[], &[], &PublishDeposits::default())
        .expect("the family shot commits");
    assert_eq!(member, pmember(1));
    assert_eq!(k.boundaries_above(before.seq()).expect("boundaries"), vec![(seq, None)], "ONE commit: the member and two homes' records");
    assert_eq!(records_in_doc1(&k), vec![record(&run(&ca(1), 3), &run(&pca(1), 3))], "doc1's record for its own identity; `b` named again is placed by reference and recorded once");
    assert_eq!(records_in_doc2(&k), vec![record(&run(&ca2(1), 2), &run(&pca(4), 2))], "doc2's record homed in doc2");
    let s = k.snapshot();
    let (m3, m5) = (s.world().m3(), s.world().m5());
    assert_eq!((m3.minted_at(&la(1)), m3.minted_at(&la2(1)), m3.minted_at(&member)), (Some(seq), Some(seq), Some(seq)), "the one commit's coordinate");
    assert_eq!(m5.link_runs(&doc1()).cloned().collect::<Vec<_>>(), vec![run(&la(1), 1)]);
    assert_eq!(m5.link_runs(&doc2()).cloned().collect::<Vec<_>>(), vec![run(&la2(1), 1)], "seated in doc2's own link subspace");
    assert_eq!(bytes_of(&k, &member), "abcxyb", "every occurrence the client placed");
    assert_eq!((bytes_of(&k, &doc1()), bytes_of(&k, &doc2())), ("abc".to_string(), "xy".to_string()), "both drafts untouched");
}

/// THE TWIN FENCE PER NAMED DRAFT: once `a b c` and `x y` are published by
/// the family shot, doc1's later shot of `b` is refused at doc1's record,
/// doc2's own later shot of `x` — doc2 the rendering draft now — at doc2's,
/// and a family shot of doc1's naming doc2 among `also` with doc2's `y` at
/// doc2's record, read for the run of its identity: each `AlreadyPublished`
/// naming the member, nothing staged.
#[test]
fn the_twin_fence_reads_each_named_drafts_own_records() {
    let k = kernel_over(edition_world());
    draft_holding(&k, "abc");
    other_draft_holding(&k, "xy");
    let w = writer(&k);
    let into = PublishTarget::Document(pdoc());
    let none = PublishDeposits::default();
    let (m1, _) = w.publication(P1, &into, &family(None, vec![shot_run(&doc1(), &ca(1), 3), shot_run(&doc2(), &ca2(1), 2)]), &[], &[], &none).expect("E.1");
    let before = k.snapshot();
    assert_eq!(
        refused(w.publication(P1, &into, &shot(Some((&m1, 5)), vec![shot_run(&doc1(), &ca(2), 1)]), &[], &[], &none)),
        PublicationError::AlreadyPublished { site: pmember(1) },
        "doc1's own later shot of `b`: doc1's record"
    );
    let doc2_shot = Shot { base: Some(skep_arrangement::Base { member: m1.clone(), extent: n(5) }), draft: Some(doc2()), also: vec![], keep_base: false, runs: vec![shot_run(&doc2(), &ca2(1), 1)], stretches: Vec::new() };
    assert_eq!(refused(w.publication(P1, &into, &doc2_shot, &[], &[], &none)), PublicationError::AlreadyPublished { site: pmember(1) }, "doc2's own later shot of `x`: doc2's record");
    assert_eq!(
        refused(w.publication(P1, &into, &family(Some((&m1, 5)), vec![shot_run(&doc2(), &ca2(2), 1)]), &[], &[], &none)),
        PublicationError::AlreadyPublished { site: pmember(1) },
        "doc2's `y` from a family shot of doc1's: doc2's record, read for the run of its identity"
    );
    assert_eq!(k.snapshot().seq(), before.seq(), "nothing committed");
    assert!(!k.snapshot().world().m3().is_registered_document(&pmember(2)), "no member minted");
    assert_eq!((records_in_doc1(&k).len(), records_in_doc2(&k).len()), (1, 1), "no record minted");
}

/// EVERY NAMED DRAFT RE-WINDOWED (the link-sets design §5.7 (viii), the
/// Nelson way; skep #739): the family shot carrying, in `places`, doc1's
/// place for its own run AND for doc2's run — which doc1 holds by identity
/// — and, in `also_places`, doc2's own place for its run re-windows BOTH
/// drafts in the ONE commit: doc1 arranges E's identity throughout, doc2
/// arranges E's identity where its own words were, each draft's private
/// copy arranged nowhere — one identity everywhere — doc2's record homed in
/// doc2, each identity minted once. Then doc2 goes on with `z`, its place
/// is read, and `x` is deleted so `z` stands elsewhere: the family shot
/// naming the stale place for `z` in doc2's list is refused `KeptPlaceMoved`
/// NAMING doc2, nothing committed — doc1's own re-window discarded with it
/// — and a place in doc2's list beside a stray run no record the caller may
/// read covers whole (doc1's record unreadable at a class that does not
/// admit doc1) is refused `StrayPlaceUnrecorded` naming doc2; the same shot
/// with doc2's place where `z` now stands commits, both drafts re-windowed
/// again.
#[test]
fn a_family_shot_re_windows_every_named_draft_at_its_own_places_in_one_commit_and_a_moved_also_place_names_its_draft() {
    let k = journaled_over(edition_world());
    draft_holding(&k, "abc");
    other_draft_holding(&k, "xy");
    let vs = Vstream::new(&k);
    vs.copy(P1, &doc1(), vp(1, 4), &[spec(&doc2(), 1, 1, 2)], AsOf::Typed(k.current_seq())).expect("doc1 a b c x y, doc2's words by identity");
    assert_eq!(runs_of(&k, &doc1()), vec![run(&ca(1), 3), run(&ca2(1), 2)]);
    let w = writer(&k);
    let into = PublishTarget::Document(pdoc());
    let none = PublishDeposits::default();
    let before = k.snapshot();
    // doc1's place beside each run (1 and 4); doc2's own place beside its
    // run (1), in its `also_places` entry.
    let the_family = family(None, vec![shot_run(&doc1(), &ca(1), 3), shot_run(&doc2(), &ca2(1), 2)]);
    let doc2_at = |ordinal: u32| vec![AlsoPlaces { draft: doc2(), places: vec![None, Some(vp(1, ordinal))] }];
    let (m1, seq) = w.publication(P1, &into, &the_family, &places(2, &[(0, 1), (1, 4)]), &doc2_at(1), &none).expect("E.1, both drafts re-windowed");
    assert_eq!(m1, pmember(1));
    assert_eq!(k.boundaries_above(before.seq()).expect("boundaries"), vec![(seq, None)], "ONE commit");
    assert_eq!(bytes_of(&k, &m1), "abcxy");
    assert_eq!(bytes_of(&k, &doc1()), "abcxy", "doc1 reads the same bytes");
    assert_eq!(runs_of(&k, &doc1()), vec![run(&pca(1), 5)], "doc1 arranges E's identity throughout — its own words and doc2's, one run");
    assert_eq!(bytes_of(&k, &doc2()), "xy", "doc2 reads the same bytes");
    assert_eq!(runs_of(&k, &doc2()), vec![run(&pca(4), 2)], "doc2 re-windowed at its own place: E's identity where its words were");
    assert!(footprint(&k, &doc1(), &run(&ca2(1), 2)).is_empty() && footprint(&k, &doc2(), &run(&ca2(1), 2)).is_empty(), "doc2's private copy arranged nowhere");
    assert_eq!(records_in_doc1(&k), vec![record(&run(&ca(1), 3), &run(&pca(1), 3))]);
    assert_eq!(records_in_doc2(&k), vec![record(&run(&ca2(1), 2), &run(&pca(4), 2))], "doc2's record homed in doc2");
    assert_eq!(k.snapshot().world().m3().next_content_address(&pdoc()), Some(pca(6)), "each identity minted once");
    // doc2 goes on with `z` at 3; its place is read; then `x` is deleted,
    // so `z` stands at 2. doc1 holds `z` by identity too, at 6.
    vs.insert(P1, &doc2(), vp(1, 3), vec![Val::new([b'z'])], Deposit::Undeclared, AsOf::Typed(k.current_seq())).expect("z at ca2(3)");
    vs.delete(P1, &doc2(), vp(1, 1), n(1), AsOf::Typed(k.current_seq())).expect("x deleted");
    assert_eq!(bytes_of(&k, &doc2()), "yz");
    vs.copy(P1, &doc1(), vp(1, 6), &[spec(&doc2(), 1, 2, 1)], AsOf::Typed(k.current_seq())).expect("doc1 a b c x y z");
    let disturbed = k.snapshot();
    let runs_before = (runs_of(&k, &doc1()), runs_of(&k, &doc2()));
    let next = Shot {
        base: Some(skep_arrangement::Base { member: m1.clone(), extent: n(5) }),
        draft: Some(doc1()),
        also: vec![doc2()],
        keep_base: false,
        runs: vec![shot_run(&pdoc(), &pca(1), 5), shot_run(&doc2(), &ca2(3), 1)],
        stretches: Vec::new(),
    };
    let refusal = refused(w.publication(P1, &into, &next, &places(2, &[(1, 6)]), &doc2_at(3), &none));
    assert_eq!(refusal, PublicationError::KeptPlaceMoved { index: 1, draft: doc2() }, "doc2 no longer arranges `z` at 3: the refusal names doc2");
    assert_eq!(k.snapshot().seq(), disturbed.seq(), "nothing committed: doc1's own re-window at 6 discarded with it");
    assert_eq!((runs_of(&k, &doc1()), runs_of(&k, &doc2())), runs_before, "both drafts unchanged");
    assert!(!k.snapshot().world().m3().is_registered_document(&pmember(2)), "no member");
    // A stray place in doc2's list: E's `a b c x y` by reference, covered by
    // doc1's record and doc2's together — at a class that does not admit
    // doc1 the run is not covered whole by any readable record.
    let all_but_doc1: &Visibility<'_, World> = &|_: &World, d: &Address| *d != doc1();
    let strayed = vec![AlsoPlaces { draft: doc2(), places: vec![Some(vp(1, 1)), None] }];
    let refusal = refused(writer_at(&k, all_but_doc1).publication(P1, &into, &next, &[], &strayed, &none));
    assert_eq!(refusal, PublicationError::StrayPlaceUnrecorded { index: 0, draft: doc2() }, "no readable record covers the run whole: the refusal names doc2");
    assert_eq!(k.snapshot().seq(), disturbed.seq(), "nothing committed");
    // doc2's place where `z` now stands: E.2, both drafts re-windowed.
    let (m2, _) = w.publication(P1, &into, &next, &places(2, &[(1, 6)]), &doc2_at(2), &none).expect("E.2");
    assert_eq!(m2, pmember(2));
    assert_eq!((bytes_of(&k, &m2), bytes_of(&k, &doc1()), bytes_of(&k, &doc2())), ("abcxyz".to_string(), "abcxyz".to_string(), "yz".to_string()));
    assert_eq!(runs_of(&k, &doc1()), vec![run(&pca(1), 6)], "doc1: E's identity throughout");
    assert_eq!(runs_of(&k, &doc2()), vec![run(&pca(5), 2)], "doc2: E's identity for `y` and `z`, its own `z` arranged nowhere");
    assert_eq!(records_in_doc2(&k).len(), 2, "doc2's record for `z` beside its first");
}

/// THE PRICE of a family publication: the re-window's term is the SUM over
/// every document a list places, each its own term — the rendering draft's
/// run count and its one placed piece where `places` carries a place, each
/// `also` draft's where its `also_places` entry does, none where no list
/// places anything — and the fence's one stab per re-inserted run counts
/// the runs of every named draft's identity. THE STAGED BYTES
/// price an `also` draft's run as any draft-native run's, its record beside
/// it (the gap the survey found closed), a kept place PER LIST that
/// places a run — the rendering draft's `places` and each `also` entry —
/// and one record a draft a list re-windows.
#[test]
fn the_price_of_a_family_publication_sums_the_draft_term_over_every_draft_a_list_places() {
    use skep_links::{
        price_publication_reads, price_staged_bytes, stored_tumbler_bytes, CORRESPONDENCE_RECORD_BYTES, KEPT_PLACE_BYTES, PLACED_RUN_BYTES, REINSERTED_UNIT_BYTES,
        REWINDOWED_DRAFT_BYTES, SHOT_BYTES,
    };
    let k = kernel_over(edition_world());
    draft_holding(&k, "abc");
    other_draft_holding(&k, "xy");
    // doc2 in two runs, so its count tells from doc1's.
    Vstream::new(&k).insert(P1, &doc2(), vp(1, 1), vec![Val::new([b'w'])], Deposit::Undeclared, AsOf::Typed(k.current_seq())).expect("w ahead of x y");
    let s = k.snapshot();
    let world = s.world();
    let (d1, d2) = (world.m5().content_run_count(&doc1()), world.m5().content_run_count(&doc2()));
    assert_eq!((d1, d2), (1, 2), "the premise: two counts that tell apart");
    let into = PublishTarget::Document(pdoc());
    let none = PublishDeposits::default();
    let with = family(None, vec![shot_run(&doc1(), &ca(1), 3), shot_run(&doc2(), &ca2(1), 2)]);
    let doc2_places = vec![AlsoPlaces { draft: doc2(), places: vec![None, Some(vp(1, 2))] }];
    let price = |places: &[Option<VPos>], also: &[AlsoPlaces]| price_publication_reads(world, P1, &ALL_VISIBLE, &into, &with, places, also, &none, &mut |_| {});
    let unplaced = price(&[], &[]);
    assert_eq!(unplaced.rewindow, 0, "no list places anything: nothing is re-windowed, no re-window term");
    assert_eq!(unplaced.fence, 2, "one stab per re-inserted run, of whichever named draft");
    assert_eq!(price(&places(2, &[(0, 1)]), &[]).rewindow, d1 + 1, "the rendering draft's run count and its one placed piece where `places` carries a place");
    assert_eq!(price(&[], &doc2_places).rewindow, d2 + 1, "the `also` draft's run count and its one placed piece where its entry carries a place");
    assert_eq!(price(&places(2, &[(0, 1)]), &doc2_places).rewindow, (d1 + 1) + (d2 + 1), "each draft its own term, summed");
    assert_eq!(price(&[], &[AlsoPlaces { draft: doc2(), places: vec![None, None] }]).rewindow, 0, "an entry with no place places nothing");
    let (homes, entries) = (unplaced.homes, unplaced.entries);
    assert_eq!((price(&places(2, &[(0, 1)]), &doc2_places).homes, price(&places(2, &[(0, 1)]), &doc2_places).entries), (homes, entries), "the other terms stand");
    // The staged bytes: each named draft's run with its record, the two
    // units re-inserted — each draft's typed bytes one run — with their five
    // bytes, and a kept place per list that places a run —
    // doc1's two (its own run and doc2's, which it holds by identity) and
    // doc2's one.
    let drafted = SHOT_BYTES + stored_tumbler_bytes(doc1().tumbler());
    let runs_and_records = 2 * (PLACED_RUN_BYTES + CORRESPONDENCE_RECORD_BYTES) + (2 * REINSERTED_UNIT_BYTES + 5);
    assert_eq!(unplaced.units, 2, "a unit a draft: a run of typed bytes each");
    assert_eq!(price_staged_bytes(world, &ALL_VISIBLE, &into, &with, &[], &[], &none), drafted + runs_and_records, "the `also` draft's run priced as any draft-native run's, its record beside it");
    let a_draft = REWINDOWED_DRAFT_BYTES + stored_tumbler_bytes(doc1().tumbler());
    assert_eq!(stored_tumbler_bytes(doc2().tumbler()), stored_tumbler_bytes(doc1().tumbler()), "the two drafts lie at one depth");
    assert_eq!(
        price_staged_bytes(world, &ALL_VISIBLE, &into, &with, &places(2, &[(0, 1), (1, 4)]), &doc2_places, &none),
        drafted + runs_and_records + 3 * KEPT_PLACE_BYTES + 2 * a_draft,
        "a kept place per list that places a run, and one record a draft re-windowed"
    );
    assert_eq!(unplaced.staged_bytes, drafted + runs_and_records, "the price carries the same figure");
}

// ───────────────────────── the re-window's term ─────────────────────────

/// doc1 fragmented by `count` inserts of one value at its first position —
/// each value's identity above the last's, so no two runs merge.
fn fragment(k: &Kernel<World>, count: usize) {
    for _ in 0..count {
        Vstream::new(k)
            .insert(P1, &doc1(), vp(1, 1), vec![Val::new([b'a'])], Deposit::Undeclared, AsOf::Typed(k.current_seq()))
            .expect("an insert at the front");
    }
}

/// doc1's whole image as a birth shot, run for run, beside each run's place:
/// the V-ordinal doc1 arranges it at.
fn whole_image(k: &Kernel<World>) -> (Shot, Vec<Option<VPos>>) {
    let mut at = 1u32;
    let mut places = Vec::new();
    let mut runs = Vec::new();
    for r in runs_of(k, &doc1()) {
        places.push(Some(vp(1, at)));
        at += width_of(&r);
        runs.push(shot_run(&doc1(), r.i_start(), width_of(&r)));
    }
    (shot(None, runs), places)
}

/// THE RE-WINDOW's TERM IS A SUM: per document the commit re-windows, its
/// content runs and the pieces its lists place, never their product and
/// never the request's every run. doc1 in 200 runs, published whole with
/// every run placed at its own place — a first publication — prices 200
/// runs + 200 pieces beside 200 fence stabs. At 300 runs, the whole image
/// with ONE place — a typed word — prices 300 runs + one piece; every run
/// placed prices 300 + 300 and is admitted, where the pieces × the runs
/// would be 90,000, past the budget; and no place at all prices nothing
/// for the re-window, the fence's stab per run standing either way.
#[test]
fn the_re_window_is_priced_at_its_drafts_runs_and_the_pieces_its_lists_place() {
    use skep_links::{price_publication_reads, MAX_PUBLICATION_READS};

    let k = kernel_over(edition_world());
    let into = PublishTarget::Document(pdoc());
    let none = PublishDeposits::default();
    fragment(&k, 200);
    let (first, every) = whole_image(&k);
    let s = k.snapshot();
    assert_eq!(s.world().m5().content_run_count(&doc1()), 200, "the premise: two hundred runs");
    let published = price_publication_reads(s.world(), P1, &ALL_VISIBLE, &into, &first, &every, &[], &none, &mut |_| {});
    assert_eq!((published.rewindow, published.fence), (200 + 200, 200), "200 runs and 200 pieces; one stab per run");
    assert!(!published.reads_over_budget(), "a first publication of 200 runs, placed run for run, is inside the budget");
    fragment(&k, 100);
    let (whole, every) = whole_image(&k);
    let s = k.snapshot();
    assert_eq!(s.world().m5().content_run_count(&doc1()), 300, "the premise: three hundred runs");
    let price = |places: &[Option<VPos>]| price_publication_reads(s.world(), P1, &ALL_VISIBLE, &into, &whole, places, &[], &none, &mut |_| {});
    let word = price(&places(300, &[(0, 1)]));
    assert_eq!((word.rewindow, word.fence), (300 + 1, 300), "300 runs and one piece; 300 fence stabs");
    let all = price(&every);
    assert_eq!(all.rewindow, 300 + 300, "every run placed: the runs once, and a piece a run");
    assert!(!all.reads_over_budget() && 300 * 300 > MAX_PUBLICATION_READS, "admitted, where its pieces × its runs would be past the budget");
    let unplaced = price(&[]);
    assert_eq!((unplaced.rewindow, unplaced.fence), (0, 300), "no place: an unplaced run adds nothing to the re-window's term");
}

/// THE PIECES ARE COUNTED, THE CUTS ARE NOT: a run the pairing cuts into
/// three pieces is priced a step a piece — over doc1's one run `a b c`, the
/// run re-supplied after `b` alone, so `b`'s endpoints cut it, prices one
/// run + three pieces; a run placed strictly inside a run of the draft
/// prices one run + one piece, the two runs its ends cut adding nothing.
/// THE ALTERNATING SHAPE: doc1's one run of 512 positions re-supplied as
/// 512 one-position runs, every other one placed — each place splitting
/// what is left of the run, 511 cuts in all — prices one run + 256 pieces,
/// and lands.
#[test]
fn the_re_window_is_priced_per_piece_and_nothing_for_the_runs_its_places_cut() {
    use skep_links::price_publication_reads;

    let into = PublishTarget::Document(pdoc());
    let none = PublishDeposits::default();
    let k = kernel_over(edition_world());
    draft_holding(&k, "abc");
    let s = k.snapshot();
    let after_b = shot(None, vec![shot_run(&doc1(), &ca(2), 1), shot_run(&doc1(), &ca(1), 3)]);
    let cut = price_publication_reads(s.world(), P1, &ALL_VISIBLE, &into, &after_b, &places(2, &[(1, 1)]), &[], &none, &mut |_| {});
    assert_eq!((cut.rewindow, cut.fence), (1 + 3, 2), "one run, three pieces");
    let inside = price_publication_reads(s.world(), P1, &ALL_VISIBLE, &into, &after_b, &places(2, &[(0, 2)]), &[], &none, &mut |_| {});
    assert_eq!(inside.rewindow, 1 + 1, "`b` placed inside `a b c`: one run, one piece, its two cuts uncounted");
    let k = kernel_over(edition_world());
    draft_holding(&k, &"x".repeat(512));
    assert_eq!(runs_of(&k, &doc1()).len(), 1, "the premise: one run");
    let runs: Vec<ShotRun> = (1..=512).map(|j| shot_run(&doc1(), &ca(j), 1)).collect();
    let placed: Vec<(usize, u32)> = (0..512).step_by(2).map(|index| (index, index as u32 + 1)).collect();
    let (alternating, kept) = (shot(None, runs), places(512, &placed));
    let wide = price_publication_reads(k.snapshot().world(), P1, &ALL_VISIBLE, &into, &alternating, &kept, &[], &none, &mut |_| {});
    assert_eq!((wide.rewindow, wide.fence), (1 + 256, 512), "one run and 256 pieces, whatever they cut");
    assert!(!wide.reads_over_budget(), "inside the budget: {wide:?}");
    writer(&k).publication(P1, &into, &alternating, &kept, &[], &none).expect("the alternating shape lands");
    assert_eq!(bytes_of(&k, &doc1()), "x".repeat(512), "the draft reads as it did");
    assert_eq!(runs_of(&k, &doc1()).len(), 512, "every other position the edition's, each its own run of the draft");
}

/// THE FENCE AND THE LOCK SET, ONE PASS EACH: a family shot naming 64 owned
/// drafts — doc1 rendering, 63 `also` — and 4,096 runs, every one of the
/// last draft's identity, whose last word an earlier shot published, is
/// refused `AlreadyPublished` at that word, naming the member it was minted
/// into: the fence read every run of the family, each in its own draft's
/// records, and nothing is committed. It answers inside the house's two
/// seconds, the lock set and the fence each grouping the runs by draft in
/// one pass over the request, where asking each draft for its runs would
/// test the named drafts once per run per draft — 64 × 4,096 × 32 tests,
/// twice.
#[test]
fn a_family_of_sixty_four_drafts_and_4096_runs_is_fenced_in_one_pass() {
    use skep_arrangement::M5State;
    use skep_content::ContentStore;
    use skep_links::LinkState;

    let edition = doc(65);
    let m3 = many_documents(64).apply_m3(Seq(0), &M3Rec::allocate(edition.clone(), true));
    let k = kernel_over(World { m3, content: ContentStore::default(), m5: M5State::genesis(), links: LinkState::genesis() });
    let last = doc(64);
    let word = |j: u32| a(&[1, 0, 1, 0, nth_doc(64), 0, 1, j]);
    let vals: Vec<Val> = (0..4096).map(|_| Val::new([b'w'])).collect();
    Vstream::new(&k).insert(P1, &last, vp(1, 1), vals, Deposit::Undeclared, AsOf::Typed(k.current_seq())).expect("the last draft's words");
    let w = writer(&k);
    let into = PublishTarget::Document(edition.clone());
    let none = PublishDeposits::default();
    let lone = Shot { base: None, draft: Some(last.clone()), also: vec![], keep_base: false, runs: vec![shot_run(&last, &word(4096), 1)], stretches: Vec::new() };
    let (e1, _) = w.publication(P1, &into, &lone, &[], &[], &none).expect("the last word published");
    let family = Shot {
        base: Some(skep_arrangement::Base { member: e1.clone(), extent: n(1) }),
        draft: Some(doc(1)),
        also: (2..=64).map(doc).collect(),
        keep_base: false,
        runs: (1..=4096).map(|j| shot_run(&last, &word(j), 1)).collect(),
        stretches: Vec::new(),
    };
    let before = k.current_seq();
    let started = std::time::Instant::now();
    let refusal = refused(w.publication(P1, &into, &family, &[], &[], &none));
    let elapsed = started.elapsed();
    assert_eq!(refusal, PublicationError::AlreadyPublished { site: e1 }, "the fence met the published word at the last run");
    assert_eq!(k.current_seq(), before, "nothing committed");
    assert!(elapsed < std::time::Duration::from_secs(2), "the lock set and the fence over 64 drafts and 4,096 runs: {elapsed:?}");
}

// ───────────────────────── the re-window in one pass ─────────────────────────

/// THE EARLIEST ENTRY ANSWERS. A first entry whose place the draft does not
/// hold its run at answers `kept_place_moved` naming it, whatever stands
/// after it and wherever: a stray no record names, at a lower place; an
/// entry whose place overlaps its own; and a second moved entry at a lower
/// place, which a walk of the draft meets first. An entry that holds leaves
/// the later one to answer. Each refusal commits nothing.
#[test]
fn a_moved_first_entry_answers_ahead_of_whatever_stands_after_it() {
    let k = kernel_over(edition_world());
    draft_holding(&k, "abcdef");
    other_draft_holding(&k, "xy");
    let into = PublishTarget::Document(pdoc());
    let none = PublishDeposits::default();
    let before = k.current_seq();
    let own = |start: u32| shot_run(&doc1(), &ca(start), 2);
    // doc1 holds `a b` at 1, `c d` at 3, `e f` at 5.
    let cells: [(&str, ShotRun, u32, ShotRun, u32, usize); 4] = [
        ("a stray no record names, at a lower place", own(1), 3, shot_run(&doc2(), &ca2(1), 2), 1, 0),
        ("an entry overlapping the first's place", own(1), 3, own(5), 4, 0),
        ("a second moved entry at a lower place", own(1), 5, own(5), 1, 0),
        ("a first entry that holds", own(1), 1, own(5), 3, 1),
    ];
    for (what, first, first_at, second, second_at, index) in cells {
        let the_shot = shot(None, vec![first, second]);
        assert_eq!(
            refused(writer(&k).publication(P1, &into, &the_shot, &places(2, &[(0, first_at), (1, second_at)]), &[], &none)),
            PublicationError::KeptPlaceMoved { index, draft: doc1() },
            "{what}"
        );
        assert_eq!(k.current_seq(), before, "{what}: nothing committed");
        assert_eq!(runs_of(&k, &doc1()), vec![run(&ca(1), 6)], "{what}: the draft unchanged");
    }
}

/// The suite's world, its fold noting each content-arrangement record it is
/// handed — a placement, a removal, an edit — with the document it names,
/// so a test reads what a commit asked of a draft's run-list: a record
/// folded at its push and again at the seal is noted twice.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct Counted(World);

thread_local! {
    static FOLDED: std::cell::RefCell<Vec<(&'static str, Address)>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Returns the records this thread's counted worlds have folded since the
/// last call, and starts again from none.
fn folded() -> Vec<(&'static str, Address)> {
    FOLDED.with(|log| std::mem::take(&mut *log.borrow_mut()))
}

impl skep_kernel::WorldState for Counted {
    type Record = Record;
    fn apply(&self, at: Seq, r: &Record) -> Counted {
        use skep_arrangement::M5Rec;
        let noted = match r {
            Record::M5(M5Rec::ContentPlace { doc, .. }) => Some(("place", doc)),
            Record::M5(M5Rec::ContentRemove { doc, .. }) => Some(("remove", doc)),
            Record::M5(M5Rec::ContentEdit { doc, .. }) => Some(("edit", doc)),
            _ => None,
        };
        if let Some((kind, doc)) = noted {
            FOLDED.with(|log| log.borrow_mut().push((kind, doc.clone())));
        }
        Counted(self.0.apply(at, r))
    }
}
impl HasM3 for Counted {
    fn m3(&self) -> &M3State {
        &self.0.m3
    }
}
impl HasContent for Counted {
    fn content(&self) -> &skep_content::ContentStore {
        &self.0.content
    }
}
impl HasM5 for Counted {
    fn m5(&self) -> &skep_arrangement::M5State {
        &self.0.m5
    }
}
impl HasLinks for Counted {
    fn links(&self) -> &skep_links::LinkState {
        &self.0.links
    }
}

fn counted_kernel(world: World) -> Kernel<Counted> {
    let cfg = skep_kernel::KernelConfig {
        durability: skep_kernel::Durability::InMemory,
        checkpoint: skep_kernel::CheckpointPolicy::Manual,
        salt: skep_kernel::SaltSource::Seeded(0),
    };
    Kernel::open(cfg, Counted(world)).expect("in-memory open cannot fail")
}

static EVERY_DOCUMENT: fn(&Counted, &Address) -> bool = |_, _| true;

/// A world whose doc2 holds `4 × runs` one-byte values as one run, and whose
/// doc1 holds the first three of every four of them by identity: `runs`
/// runs of doc2's words, three wide, no two I-adjacent.
fn fragmented_family(runs: u32) -> World {
    let k = kernel_over(edition_world());
    let vals: Vec<Val> = (0..4 * runs).map(|_| Val::new(*b"w")).collect();
    Vstream::new(&k).insert(P1, &doc2(), vp(1, 1), vals, Deposit::Undeclared, AsOf::Typed(k.current_seq())).expect("doc2's words");
    let held: Vec<ShotRun> = (0..runs).map(|j| shot_run(&doc2(), &ca2(1 + 4 * j), 3)).collect();
    Vstream::new(&k).reinstate(P1, &doc1(), vp(1, 1), &held, AsOf::Typed(k.current_seq())).expect("doc1 holding doc2's words by identity");
    let world = k.snapshot().world().clone();
    assert_eq!((world.m5.content_run_count(&doc1()), world.m5.content_run_count(&doc2())), (runs as usize, 1));
    world
}

/// A family shot of `pieces` runs of doc2's words over [`fragmented_family`]
/// — run `j` a part of doc1's run `j`: the whole of it, its middle position,
/// which cuts the run at both ends, or its first position, which cuts it at
/// one, in turn — beside each run's place in doc1 and its place in doc2.
fn parts_of_the_family(pieces: u32) -> (Shot, Vec<Option<VPos>>, Vec<AlsoPlaces>) {
    let part = |j: u32| match j % 3 {
        0 => (0, 3),
        1 => (1, 1),
        _ => (0, 1),
    };
    let runs: Vec<ShotRun> = (0..pieces).map(|j| shot_run(&doc2(), &ca2(1 + 4 * j + part(j).0), part(j).1)).collect();
    let in_doc1: Vec<Option<VPos>> = (0..pieces).map(|j| Some(vp(1, 3 * j + 1 + part(j).0))).collect();
    let in_doc2: Vec<Option<VPos>> = (0..pieces).map(|j| Some(vp(1, 4 * j + 1 + part(j).0))).collect();
    (family(None, runs), in_doc1, vec![AlsoPlaces { draft: doc2(), places: in_doc2 }])
}

/// THE TERM IS A SUM. A draft of 4,167 runs re-windowed at 1,613 places, a
/// piece each, places that cut a run at one end and at both among them, is
/// priced at exactly its runs and its pieces — 5,780 steps, where the
/// pieces × the runs are past the budget a hundred times over — and a
/// second draft re-windowed beside it adds its own runs and pieces. The
/// publication is inside both budgets, and lands.
#[test]
fn the_re_windows_term_is_exactly_the_drafts_runs_and_the_pieces_placed() {
    use skep_links::{price_publication_reads, MAX_PUBLICATION_READS};
    const RUNS: u32 = 4_167;
    const PIECES: u32 = 1_613;
    let k = kernel_over(fragmented_family(RUNS));
    let (the_shot, in_doc1, in_doc2) = parts_of_the_family(PIECES);
    let into = PublishTarget::Document(pdoc());
    let none = PublishDeposits::default();
    let s = k.snapshot();
    let price = price_publication_reads(s.world(), P1, &ALL_VISIBLE, &into, &the_shot, &in_doc1, &[], &none, &mut |_| {});
    assert_eq!(price.rewindow, (RUNS + PIECES) as usize, "the draft's runs and the pieces placed, summed");
    assert_eq!(price.fence, PIECES as usize);
    assert!(!price.over_budget() && (RUNS * PIECES) as usize > 100 * MAX_PUBLICATION_READS, "{price:?}");
    let both = price_publication_reads(s.world(), P1, &ALL_VISIBLE, &into, &the_shot, &in_doc1, &in_doc2, &none, &mut |_| {});
    assert_eq!(both.rewindow, (RUNS + PIECES) as usize + (1 + PIECES) as usize, "doc2's one run and its pieces beside doc1's");
    let counts = |k: &Kernel<World>| (k.snapshot().world().m5().content_count(&doc1()), k.snapshot().world().m5().content_count(&doc2()));
    let counts_before = counts(&k);
    writer(&k).publication(P1, &into, &the_shot, &in_doc1, &in_doc2, &none).expect("the publication lands");
    assert_eq!(counts(&k), counts_before, "both drafts hold as many positions as they did");
    let fresh = |r: &Run| skep_address::document_of(r.i_start()).is_some_and(|d| d == pdoc());
    let placed: u32 = runs_of(&k, &doc1()).iter().filter(|r| fresh(r)).map(width_of).sum();
    assert_eq!(placed, runs_of(&k, &doc2()).iter().filter(|r| fresh(r)).map(width_of).sum::<u32>(), "the same positions re-windowed in each draft");
    assert_eq!(placed, (0..PIECES).map(|j| if j % 3 == 0 { 3 } else { 1 }).sum::<u32>());
}

/// ONE RECORD A DRAFT. A publication re-windowing a draft of 4,167 runs at
/// 1, 16 and 1,613 pieces stages its kept places as one edit record of the
/// draft — folded at its push and at the seal, so the draft's run-list is
/// rebuilt twice whatever the pieces number — and no placement and no
/// removal: one record more than the same shot stages with no place. A
/// second draft re-windowed beside it takes a record of its own, and two
/// lists naming one document are one record of it.
#[test]
fn a_publications_kept_places_are_one_record_a_draft_whatever_the_pieces() {
    const RUNS: u32 = 4_167;
    let world = fragmented_family(RUNS);
    let into = PublishTarget::Document(pdoc());
    let none = PublishDeposits::default();
    let publish = |the_shot: &Shot, in_doc1: &[Option<VPos>], also: &[AlsoPlaces]| -> (u64, Vec<(&'static str, Address)>) {
        let k = counted_kernel(world.clone());
        let (before, _) = (k.current_seq(), folded());
        LinkWriter::new(&k, &EVERY_DOCUMENT).publication(P1, &into, the_shot, in_doc1, also, &none).expect("the publication lands");
        (k.current_seq().0 - before.0, folded())
    };
    let of = |log: &[(&'static str, Address)], kind: &str, doc: &Address| log.iter().filter(|(k, d)| *k == kind && d == doc).count();
    for pieces in [1u32, 16, 1_613] {
        let (the_shot, in_doc1, in_doc2) = parts_of_the_family(pieces);
        let (unplaced, log) = publish(&the_shot, &[], &[]);
        assert!(log.is_empty(), "{pieces} pieces, no place: no draft's arrangement is written");
        let (records, log) = publish(&the_shot, &in_doc1, &[]);
        assert_eq!(records - unplaced, 1, "{pieces} pieces: the kept places are one record");
        assert_eq!((of(&log, "edit", &doc1()), log.len()), (2, 2), "{pieces} pieces: one edit record of doc1, folded at its push and at the seal, and nothing else of any draft");
        let (records, log) = publish(&the_shot, &in_doc1, &in_doc2);
        assert_eq!(records - unplaced, 2, "{pieces} pieces: a record a draft");
        assert_eq!((of(&log, "edit", &doc1()), of(&log, "edit", &doc2()), log.len()), (2, 2, 4), "{pieces} pieces: each draft's list rebuilt twice");
    }
    // Two lists naming one document — doc1 as the rendering draft and among
    // `also`, its first list placing the even runs and its second the odd —
    // re-window it once, by one record.
    let (the_shot, in_doc1, _) = parts_of_the_family(16);
    let named_twice = Shot { also: vec![doc2(), doc1()], ..the_shot.clone() };
    let split = |keep: u32| -> Vec<Option<VPos>> { in_doc1.iter().enumerate().map(|(j, place)| place.clone().filter(|_| j as u32 % 2 == keep)).collect() };
    let second_list = vec![AlsoPlaces { draft: doc1(), places: split(1) }];
    let (unplaced, _) = publish(&named_twice, &[], &[]);
    let (records, log) = publish(&named_twice, &split(0), &second_list);
    assert_eq!(records - unplaced, 1, "two lists, one document: one record");
    assert_eq!((of(&log, "edit", &doc1()), log.len()), (2, 2));
    let k = kernel_over(world.clone());
    let price = skep_links::price_publication_reads(k.snapshot().world(), P1, &ALL_VISIBLE, &into, &named_twice, &split(0), &second_list, &none, &mut |_| {});
    assert_eq!(price.rewindow, (RUNS + 16) as usize, "and priced once: its runs, and the pieces of both lists");
}

/// THE RE-WINDOW's SHARE OF THE PRICE IS AT OR ABOVE WHAT IT STAGES. On a
/// journaled kernel, a publication with its kept places against the same
/// publication with none, over one world: the bytes the places add to the
/// journal are the bytes they add to the price where every place is one
/// piece — one place, a stray through its record, sixteen places, two
/// drafts each at its own list — and fewer where a place holds several
/// pieces, each piece past the first staging a run and priced a whole
/// change.
#[test]
fn the_re_windows_share_of_the_price_is_at_or_above_what_it_stages() {
    use skep_links::{price_staged_bytes, stored_tumbler_bytes, KEPT_PLACE_BYTES, PLACED_RUN_BYTES, REWINDOWED_DRAFT_BYTES};
    let into = PublishTarget::Document(pdoc());
    let none = PublishDeposits::default();
    // What `kept` and `also` add to the price and to the journal of the
    // one commit, over `world`.
    let share = |world: &World, the_shot: &Shot, kept: &[Option<VPos>], also: &[AlsoPlaces]| -> (u64, u64) {
        let staged = |kept: &[Option<VPos>], also: &[AlsoPlaces]| {
            let k = journaled_over(world.clone());
            let before = k.journal_bytes();
            writer(&k).publication(P1, &into, the_shot, kept, also, &none).expect("the publication lands");
            k.journal_bytes() - before
        };
        let priced = |kept: &[Option<VPos>], also: &[AlsoPlaces]| price_staged_bytes(world, &ALL_VISIBLE, &into, the_shot, kept, also, &none);
        (priced(kept, also) - priced(&[], &[]), staged(kept, also) - staged(&[], &[]))
    };
    let after = |build: &dyn Fn(&Kernel<World>)| -> World {
        let k = kernel_over(edition_world());
        build(&k);
        let world = k.snapshot().world().clone();
        world
    };
    let a_draft = REWINDOWED_DRAFT_BYTES + stored_tumbler_bytes(doc1().tumbler());

    // One place, one piece.
    let abc = after(&|k| draft_holding(k, "abc"));
    assert_eq!(share(&abc, &shot(None, vec![shot_run(&doc1(), &ca(2), 1)]), &places(1, &[(0, 2)]), &[]), (a_draft + KEPT_PLACE_BYTES, a_draft + KEPT_PLACE_BYTES));

    // Sixteen places, a piece each.
    let wide = after(&|k| draft_holding(k, &"x".repeat(32)));
    let every_other: Vec<ShotRun> = (1..=32).map(|j| shot_run(&doc1(), &ca(j), 1)).collect();
    let kept: Vec<(usize, u32)> = (0..32).step_by(2).map(|index| (index, index as u32 + 1)).collect();
    assert_eq!(share(&wide, &shot(None, every_other), &places(32, &kept), &[]), (a_draft + 16 * KEPT_PLACE_BYTES, a_draft + 16 * KEPT_PLACE_BYTES));

    // Two drafts, each at its own list.
    let two = after(&|k| {
        draft_holding(k, "abc");
        other_draft_holding(k, "xy");
    });
    let both = family(None, vec![shot_run(&doc1(), &ca(1), 3), shot_run(&doc2(), &ca2(1), 2)]);
    let in_doc2 = vec![AlsoPlaces { draft: doc2(), places: vec![None, Some(vp(1, 1))] }];
    assert_eq!(share(&two, &both, &places(2, &[(0, 1)]), &in_doc2), (2 * (a_draft + KEPT_PLACE_BYTES), 2 * (a_draft + KEPT_PLACE_BYTES)));

    // A stray, through its one record.
    let strayed = after(&|k| {
        stray_board(k);
    });
    let k = kernel_over(strayed.clone());
    let mut heal = shot_off_head(&k, vec![shot_run(&pdoc(), &pca(1), 2)]);
    heal.draft = Some(doc1());
    assert_eq!(share(&strayed, &heal, &places(2, &[(1, 4)]), &[]), (a_draft + KEPT_PLACE_BYTES, a_draft + KEPT_PLACE_BYTES));

    // One place of three pieces: `a b c` whole, cut at `b`'s two ends by the
    // run that names `b` first. The record holds one change of three runs.
    let cut = shot(None, vec![shot_run(&doc1(), &ca(2), 1), shot_run(&doc1(), &ca(1), 3)]);
    let (priced, staged) = share(&abc, &cut, &places(2, &[(1, 1)]), &[]);
    assert_eq!(priced, a_draft + 3 * KEPT_PLACE_BYTES);
    assert_eq!(staged, a_draft + KEPT_PLACE_BYTES + 2 * PLACED_RUN_BYTES, "the place's one change, a run a piece");
    assert!(priced >= staged);
}

// ─────────────────── the re-insert's units, and its price ───────────────────

/// A world built by `build` over the edition world, as one value.
fn world_after(build: &dyn Fn(&Kernel<World>)) -> World {
    let k = kernel_over(edition_world());
    build(&k);
    let world = k.snapshot().world().clone();
    world
}

/// One insert of `values` into `doc` at content ordinal `at`.
fn typed_at(k: &Kernel<World>, doc: &Address, at: u32, values: Vec<Val>) {
    Vstream::new(k).insert(P1, doc, vp(1, at), values, Deposit::Undeclared, AsOf::Typed(k.current_seq())).expect("the insert commits");
}

/// THE UNITS THE PRICE ANSWERS ARE THE UNITS THE COUNT COUNTS AND THE COMMIT
/// STAGES. doc1 holds `abc`, the atom `XY` and `de`, typed in one insert:
/// six positions, three stored pieces. The price of the shot naming them
/// all answers three units — never its six positions — off one walk of the
/// three pieces; M5's count over the same snapshot answers the same three
/// and their seven bytes; the staged bytes price each unit at the table's
/// figure and its own bytes; and the commit stages three content entries,
/// one a unit, the fresh run their six positions.
#[test]
fn the_price_answers_the_units_the_count_counts_and_the_commit_stages() {
    use skep_arrangement::{ReinsertedUnits, UnitTally};
    use skep_links::{price_publication_reads, stored_tumbler_bytes, CORRESPONDENCE_RECORD_BYTES, PLACED_RUN_BYTES, REINSERTED_UNIT_BYTES, SHOT_BYTES};
    let k = kernel_over(edition_world());
    let values: Vec<Val> = [&b"a"[..], b"b", b"c", b"XY", b"d", b"e"].into_iter().map(Val::new).collect();
    typed_at(&k, &doc1(), 1, values);
    let (into, none) = (PublishTarget::Document(pdoc()), PublishDeposits::default());
    let the_shot = shot(None, vec![shot_run(&doc1(), &ca(1), 6)]);
    assert_eq!(the_shot.reinserted_values(), n(6), "premise: six positions");
    let s = k.snapshot();
    let mut walked = 0u64;
    let price = price_publication_reads(s.world(), P1, &ALL_VISIBLE, &into, &the_shot, &[], &[], &none, &mut |pieces| walked += pieces);
    assert_eq!((price.units, walked), (3, 3), "three units, off one walk of the three stored pieces");
    let counted = the_shot.reinserted_units(s.world(), &mut |_| {});
    assert!(matches!(counted, ReinsertedUnits::Counted(_)), "{counted:?}");
    assert_eq!(counted.tally(), UnitTally { units: price.units, bytes: 7 }, "the price's figure is the count's");
    assert_eq!(
        price.staged_bytes,
        SHOT_BYTES + stored_tumbler_bytes(doc1().tumbler()) + (PLACED_RUN_BYTES + CORRESPONDENCE_RECORD_BYTES) + 3 * REINSERTED_UNIT_BYTES + 7,
        "each unit at the table's figure and its own bytes"
    );
    let stored = s.world().content().len();
    let (member, _) = writer(&k).publication(P1, &into, &the_shot, &[], &[], &none).expect("the publication lands");
    let after = k.snapshot();
    assert_eq!((after.world().content().len() - stored) as u64, price.units, "a stored entry a unit: the units priced are the units staged");
    assert_eq!(runs_of(&k, &member), vec![run(&pca(1), 6)]);
}

/// A RE-INSERT IS PRICED AT OR ABOVE WHAT IT STAGES, whatever its units
/// hold. doc1 holds a typed byte, fifty atoms of sixty-four bytes, and three
/// runs of a thousand typed bytes with a two-byte atom between each. Against
/// the shot of the one byte — one unit, one run, one record, the same shape —
/// the shot of the fifty atoms adds to the price fifty units at the table's
/// figure and their own sixty-four bytes each, and to the journal a little
/// less; a thousand typed bytes, one unit as the byte is, add to both
/// exactly the unit and its thousand; and the three runs around their two
/// atoms, five units, add to the price what they stage and a little more.
/// The little is counted: the table's figure is what a shot's FIRST unit
/// stages past its bytes where it is a run of single bytes — every unit
/// after a shot's first stages four bytes fewer, and an atom eleven fewer
/// than a run, its mint carrying no count — so the price is an upper bound,
/// tight to a few bytes a unit. A price read off the positions alone, a
/// byte a position, comes short at the atoms.
#[test]
fn a_reinsert_of_atoms_or_of_long_byte_runs_is_priced_at_or_above_what_it_stages() {
    use skep_links::{price_staged_bytes, REINSERTED_UNIT_BYTES};
    let (into, none) = (PublishTarget::Document(pdoc()), PublishDeposits::default());
    let world = world_after(&|k| {
        typed_at(k, &doc1(), 1, vec![Val::new(*b"z")]);
        typed_at(k, &doc1(), 2, vec![Val::new([b'A'; 64]); 50]);
        let run = || std::iter::repeat_n(Val::new(*b"r"), 1_000);
        let between = || [Val::new(&b"--"[..])];
        typed_at(k, &doc1(), 52, run().chain(between()).chain(run()).chain(between()).chain(run()).collect());
    });
    // What the shot of doc1's `width` positions from `first` is priced at,
    // and what its one commit adds to the journal, each over `world`.
    let of = |first: u32, width: u32| -> (u64, u64) {
        let the_shot = shot(None, vec![shot_run(&doc1(), &ca(first), width)]);
        let k = journaled_over(world.clone());
        let before = k.journal_bytes();
        writer(&k).publication(P1, &into, &the_shot, &[], &[], &none).expect("the publication lands");
        (price_staged_bytes(&world, &ALL_VISIBLE, &into, &the_shot, &[], &[], &none), k.journal_bytes() - before)
    };
    let (priced_byte, staged_byte) = of(1, 1);
    let share = |first: u32, width: u32| {
        let (priced, staged) = of(first, width);
        (priced - priced_byte, staged - staged_byte)
    };
    let one_byte = REINSERTED_UNIT_BYTES + 1;
    // What the price is over what is staged, for a re-insert of `units`
    // units, `atoms` of them atoms.
    let over = |units: u64, atoms: u64| 4 * (units - 1) + 11 * atoms;
    // Fifty atoms of sixty-four bytes.
    let (priced, staged) = share(2, 50);
    assert_eq!(priced, 50 * (REINSERTED_UNIT_BYTES + 64) - one_byte, "a unit an atom, each at its own length");
    assert!(priced >= staged, "the atoms are priced {priced} and stage {staged}");
    assert_eq!(priced - staged, over(50, 50), "over by a few bytes a unit, never under");
    // One run of a thousand typed bytes: priced exactly.
    assert_eq!(share(52, 1_000), (REINSERTED_UNIT_BYTES + 1_000 - one_byte, REINSERTED_UNIT_BYTES + 1_000 - one_byte));
    // The three runs around their two atoms: five units.
    let (priced, staged) = share(52, 3_002);
    assert_eq!(priced, 5 * REINSERTED_UNIT_BYTES + 3_004 - one_byte);
    assert!(priced >= staged, "the runs and their atoms are priced {priced} and stage {staged}");
    assert_eq!(priced - staged, over(5, 2));
}

/// A PORTION OF SINGLE-BYTE PIECES IS PRICED AS THE ONE UNIT IT IS. doc1
/// holds the positions' budget of typed bytes, a stored piece a byte — a
/// draft written a byte an insert. The price of the shot naming them all
/// walks every piece once, answers ONE unit, and prices the re-insert at the
/// table's figure and the bytes themselves: inside the transaction budget,
/// where a price of a position an atom was four times past it.
#[test]
fn a_portion_of_single_byte_pieces_is_priced_at_one_unit_and_its_bytes() {
    use std::sync::Arc;

    use skep_content::stage_stretch;
    use skep_links::{price_publication_reads, stored_tumbler_bytes, ReadPrice, CORRESPONDENCE_RECORD_BYTES, PLACED_RUN_BYTES, REINSERTED_UNIT_BYTES, SHOT_BYTES};
    let positions = ReadPrice::POSITION_BUDGET as u32;
    let mut world = edition_world();
    for at in 1..=positions {
        let stretch = stage_stretch(&world.content, ca(at), Arc::from(&[b'a' + (at % 26) as u8][..])).expect("a fresh one-byte stretch");
        world.content = world.content.apply_stretch(&stretch);
    }
    assert_eq!(world.content.len(), positions as usize, "premise: a stored piece a position");
    let (into, none) = (PublishTarget::Document(pdoc()), PublishDeposits::default());
    let the_shot = shot(None, vec![shot_run(&doc1(), &ca(1), positions)]);
    let mut walked = 0u64;
    let price = price_publication_reads(&world, P1, &ALL_VISIBLE, &into, &the_shot, &[], &[], &none, &mut |pieces| walked += pieces);
    assert_eq!((price.units, walked), (1, u64::from(positions)), "one unit, after one walk of every piece");
    assert_eq!(
        price.staged_bytes,
        SHOT_BYTES + stored_tumbler_bytes(doc1().tumbler()) + (PLACED_RUN_BYTES + CORRESPONDENCE_RECORD_BYTES) + REINSERTED_UNIT_BYTES + u64::from(positions),
        "the unit's fixed figure and a byte a position"
    );
    assert!(!price.over_budget(), "inside both budgets: {price:?}");
    assert!(u64::from(positions) * 287 > 4 * ReadPrice::BYTE_BUDGET, "priced a position an atom, the same shot was past the bytes' budget four times over");
}

/// THE POSITIONS' ARITHMETIC ANSWERS AHEAD OF EVERY STORED PIECE. doc1 holds
/// an atom and then the positions' budget of typed bytes, one position more
/// than the budget in all. The price of the shot naming them all reads NO
/// stored piece: its units figure is nothing and its bytes carry no
/// re-insert at all — the shot is the store's to refuse, and the positions
/// a caller counts itself against the budget the price states. The shot of
/// exactly the budget is counted off its two stored pieces, two units. And a
/// shot reaching past what the draft holds is priced at the units standing
/// ahead of the first position holding nothing: a missing value is no unit.
#[test]
fn a_shot_past_the_positions_is_priced_with_no_stored_piece_read() {
    use skep_links::{price_publication_reads, stored_tumbler_bytes, ReadPrice, CORRESPONDENCE_RECORD_BYTES, PLACED_RUN_BYTES, REINSERTED_UNIT_BYTES, SHOT_BYTES};
    let budget = ReadPrice::POSITION_BUDGET as u32;
    let world = world_after(&|k| {
        typed_at(k, &doc1(), 1, std::iter::once(Val::new(&b"XY"[..])).chain(std::iter::repeat_n(Val::new(*b"x"), budget as usize)).collect());
    });
    let (into, none) = (PublishTarget::Document(pdoc()), PublishDeposits::default());
    let priced = |width: u32| {
        let the_shot = shot(None, vec![shot_run(&doc1(), &ca(1), width)]);
        let mut walked = 0u64;
        let price = price_publication_reads(&world, P1, &ALL_VISIBLE, &into, &the_shot, &[], &[], &none, &mut |pieces| walked += pieces);
        (price, walked)
    };
    let fixed = SHOT_BYTES + stored_tumbler_bytes(doc1().tumbler()) + (PLACED_RUN_BYTES + CORRESPONDENCE_RECORD_BYTES);
    let (past, walked) = priced(budget + 1);
    assert_eq!((past.units, walked), (0, 0), "past the positions: nothing counted, no stored piece read");
    assert_eq!(past.staged_bytes, fixed, "and no re-insert priced: the store refuses the shot before it stages a record");
    let (at, walked) = priced(budget);
    assert_eq!((at.units, walked), (2, 2), "at the budget: the atom and the one run of typed bytes");
    assert_eq!(at.staged_bytes, fixed + 2 * REINSERTED_UNIT_BYTES + 2 + u64::from(budget - 1));
    // A draft of two stored values, and a shot of three positions from them.
    let short = world_after(&|k| typed_at(k, &doc1(), 1, vec![Val::new(&b"XY"[..]), Val::new(*b"x")]));
    let reaching = shot(None, vec![shot_run(&doc1(), &ca(1), 3)]);
    let price = price_publication_reads(&short, P1, &ALL_VISIBLE, &into, &reaching, &[], &[], &none, &mut |_| {});
    assert_eq!(price.units, 2, "the units ahead of the hole: the store refuses the shot `dangling_source`");
}

/// NO UNIT FROM A DRAFT THE CALLER CANNOT READ. doc1 holds the same three
/// positions three ways — one typed run of three bytes, three atoms, and
/// one byte with nothing after it — and a shot of its own re-inserts the
/// three. At a class that reads doc1 the three worlds answer three prices:
/// one unit and its bytes, three units and theirs, and the one unit ahead
/// of the hole. At a class that does NOT read doc1 they answer ONE, figure
/// for figure: no unit, no byte of a re-insert, and NO stored piece read —
/// the price is taken ahead of every judgment of who owns the draft, so it
/// says nothing of how a draft the caller may not read holds its content.
/// The staged-bytes price alone answers the same. And a second named draft
/// the class does not admit silences the count of the first, which it
/// does: the store refuses that shot before it counts anything.
#[test]
fn a_named_draft_the_class_does_not_admit_is_counted_no_unit_and_read_no_piece() {
    use skep_links::{price_publication_reads, price_staged_bytes, REINSERTED_UNIT_BYTES};
    let (into, none) = (PublishTarget::Document(pdoc()), PublishDeposits::default());
    let worlds = [
        world_after(&|k| typed_at(k, &doc1(), 1, vec![Val::new(*b"a"), Val::new(*b"b"), Val::new(*b"c")])),
        world_after(&|k| typed_at(k, &doc1(), 1, vec![Val::new(&b"AA"[..]), Val::new(&b"BBB"[..]), Val::new(&b"CCCC"[..])])),
        world_after(&|k| typed_at(k, &doc1(), 1, vec![Val::new(*b"a")])),
    ];
    let the_shot = shot(None, vec![shot_run(&doc1(), &ca(1), 3)]);
    let all_but_doc1: &Visibility<'_, World> = &|_: &World, d: &Address| *d != doc1();
    let priced = |world: &World, class: &Visibility<'_, World>| {
        let mut walked = 0u64;
        let price = price_publication_reads(world, P1, class, &into, &the_shot, &[], &[], &none, &mut |pieces| walked += pieces);
        (price, walked)
    };
    // The class that reads the draft: the count, as the store would make it.
    let read: Vec<_> = worlds.iter().map(|world| priced(world, &ALL_VISIBLE)).collect();
    assert_eq!(read.iter().map(|(price, walked)| (price.units, *walked)).collect::<Vec<_>>(), [(1, 1), (3, 3), (1, 1)], "premise: one stretch, three atoms, one byte ahead of a hole");
    assert_eq!(read[1].0.staged_bytes - read[0].0.staged_bytes, 2 * REINSERTED_UNIT_BYTES + (2 + 3 + 4) - 3, "premise: and the three are priced apart");
    assert_eq!(read[0].0.staged_bytes - read[2].0.staged_bytes, 2, "premise: the hole's two missing bytes too");
    // The class that does not: one answer, whatever the draft holds.
    let unread: Vec<_> = worlds.iter().map(|world| priced(world, all_but_doc1)).collect();
    for (price, walked) in &unread {
        assert_eq!((price.units, *walked), (0, 0), "no unit counted, no stored piece read: {price:?}");
        assert_eq!(*price, unread[0].0, "the one price, figure for figure, whatever the draft holds");
    }
    assert_eq!(read[0].0.staged_bytes - unread[0].0.staged_bytes, REINSERTED_UNIT_BYTES + 3, "the re-insert is the whole of what the class withholds");
    for world in &worlds {
        assert_eq!(price_staged_bytes(world, all_but_doc1, &into, &the_shot, &[], &[], &none), unread[0].0.staged_bytes, "the bytes' own price, the same");
    }
    // Two named drafts, one of them unread: nothing of either is counted.
    let both = Shot { base: None, draft: Some(doc2()), also: vec![doc1()], keep_base: false, runs: vec![shot_run(&doc2(), &ca2(1), 1), shot_run(&doc1(), &ca(1), 3)], stretches: Vec::new() };
    let two = world_after(&|k| {
        typed_at(k, &doc1(), 1, vec![Val::new(&b"AA"[..]), Val::new(&b"BBB"[..]), Val::new(&b"CCCC"[..])]);
        typed_at(k, &doc2(), 1, vec![Val::new(&b"ZZ"[..])]);
    });
    let count = |class: &Visibility<'_, World>| {
        let mut walked = 0u64;
        let price = price_publication_reads(&two, P1, class, &into, &both, &[], &[], &none, &mut |pieces| walked += pieces);
        (price.units, walked)
    };
    assert_eq!(count(&ALL_VISIBLE), (4, 4), "premise: both read, four atoms");
    assert_eq!(count(all_but_doc1), (0, 0), "one named draft unread: no unit of the other either, and no piece read");
}

/// NO COUNT FROM A DRAFT THE CALLER CANNOT READ. F's words `x y z` stand
/// published three ways: by M5's shot alone, no record naming them; by a
/// publication of doc2's one run, ONE record homed in doc2; and by a
/// publication of doc2's three positions as three runs, THREE records homed
/// in doc2, tiling the same three words. Principal 2, who may not read
/// doc2, prices a shot of its own that places a stray run of those words in
/// its draft: at its class the three worlds answer ONE price, figure for
/// figure — the stray is the one piece every placed stray is at least,
/// whatever doc2 holds. The owner, who reads doc2, is priced with the
/// records it may read: one piece where one record names the words or
/// none, three where three do — the pieces its own commit's stray read
/// would be handed.
#[test]
fn a_stray_place_is_priced_at_the_callers_class_and_counts_no_record_it_may_not_read() {
    use skep_links::{price_publication_reads, KEPT_PLACE_BYTES};
    let into_f = PublishTarget::Document(fdoc());
    let none = PublishDeposits::default();
    let from_doc2 = |runs: Vec<ShotRun>| Shot { base: None, draft: Some(doc2()), also: vec![], keep_base: false, runs, stretches: Vec::new() };
    // F.1 holding `x y z`, by a shot that leaves `records` records in doc2.
    let published = |records: usize| -> World {
        let k = kernel_over(two_editions_world());
        other_draft_holding(&k, "xyz");
        match records {
            0 => {
                let readable = |_: &World, _: &Address| true;
                Vstream::new(&k).publish(P1, &fdoc(), &from_doc2(vec![shot_run(&doc2(), &ca2(1), 3)]), &readable).expect("F.1, by the shot alone");
            }
            1 => {
                writer(&k).publication(P1, &into_f, &from_doc2(vec![shot_run(&doc2(), &ca2(1), 3)]), &[], &[], &none).expect("F.1, one record");
            }
            _ => {
                let apart = vec![shot_run(&doc2(), &ca2(1), 1), shot_run(&doc2(), &ca2(3), 1), shot_run(&doc2(), &ca2(2), 1)];
                writer(&k).publication(P1, &into_f, &from_doc2(apart), &[], &[], &none).expect("F.1, three records");
            }
        }
        assert_eq!(runs_of(&k, &a(&[1, 0, 1, 0, nth_doc(4), 1])), vec![run(&fca(1), 3)], "premise: F.1 holds three positions of F's own identity");
        assert_eq!(records_in_doc2(&k).len(), records, "premise: the records homed in doc2");
        let world = k.snapshot().world().clone();
        world
    };
    let worlds = [published(0), published(1), published(3)];
    // Principal 2's shot: a stray run of F's three words, placed in its own
    // document.
    let stray = Shot { base: None, draft: Some(sib_doc()), also: vec![], keep_base: false, runs: vec![shot_run(&fdoc(), &fca(1), 3)], stretches: Vec::new() };
    let into_theirs = PublishTarget::Document(sib_doc());
    let the_places = places(1, &[(0, 1)]);
    let all_but_doc2: &Visibility<'_, World> = &|_: &World, d: &Address| *d != doc2();
    let priced = |world: &World, caller: Caller, class: &Visibility<'_, World>| price_publication_reads(world, caller, class, &into_theirs, &stray, &the_places, &[], &none, &mut |_| {});
    let unread: Vec<_> = worlds.iter().map(|world| priced(world, P2, all_but_doc2)).collect();
    assert_eq!(unread[1], unread[0], "one record in a draft the caller may not read moves no figure");
    assert_eq!(unread[2], unread[0], "nor do three");
    assert_eq!(unread[0].rewindow, 1, "the stray's one piece, in a draft of no runs");
    // The owner's class reads doc2: its records are its pieces.
    let read: Vec<_> = worlds.iter().map(|world| priced(world, P2, &ALL_VISIBLE)).collect();
    assert_eq!(read.iter().map(|price| price.rewindow).collect::<Vec<_>>(), [1, 1, 3], "a piece a record the caller may read, one at least");
    assert_eq!(read[2].staged_bytes - read[0].staged_bytes, 2 * KEPT_PLACE_BYTES, "and a kept place's change a piece");
    assert_eq!((read[0], read[1]), (unread[0], unread[1]), "where at most one record names the words the two classes are priced alike");
}

/// NO RUN COUNT FROM A DRAFT THE CALLER CANNOT READ. doc1 holds one content
/// run, then sixteen — an insert at its first position each, no two
/// merging — and doc2 two. A shot naming doc1 as its draft places one run
/// in it: a stray run of the edition's identity that no record names, one
/// piece. At a class that reads doc1 the two worlds answer two prices, the
/// re-window's steps fifteen apart: the draft's runs and the piece. At a
/// class that does NOT read doc1 they answer ONE, figure for figure — the
/// piece and no run, for another account's principal and for the caller
/// that is no principal — since the price is taken ahead of every judgment
/// of who owns the draft. The same holds where doc1 is an `also` draft
/// re-windowed at its own list. And the count is taken draft by draft:
/// doc2, which the class reads, re-windowed beside doc1 by the same shot,
/// is still counted its two runs. What the price leaves out is never
/// walked: the store refuses the shot by the draft's ownership.
#[test]
fn a_re_windowed_draft_the_class_does_not_admit_is_counted_no_run() {
    use skep_links::price_publication_reads;
    let (into, none) = (PublishTarget::Document(sib_doc()), PublishDeposits::default());
    // doc1 in `runs` runs, doc2 in two.
    let holding = |runs: usize| {
        world_after(&|k| {
            fragment(k, runs);
            other_draft_holding(k, "xy");
            Vstream::new(k).insert(P1, &doc2(), vp(1, 1), vec![Val::new(*b"w")], Deposit::Undeclared, AsOf::Typed(k.current_seq())).expect("w ahead of x y");
        })
    };
    let worlds = [holding(1), holding(16)];
    for (world, runs) in worlds.iter().zip([1, 16]) {
        assert_eq!((world.m5.content_run_count(&doc1()), world.m5.content_run_count(&doc2())), (runs, 2), "premise: the drafts' runs");
    }
    // One stray run, placed at the first position of whichever draft a list
    // names it in.
    let stray = || vec![shot_run(&pdoc(), &pca(1), 1)];
    let rendering = Shot { base: None, draft: Some(doc1()), also: vec![], keep_base: false, runs: stray(), stretches: Vec::new() };
    let among_also = Shot { base: None, draft: Some(sib_doc()), also: vec![doc1()], keep_base: false, runs: stray(), stretches: Vec::new() };
    let beside_doc2 = Shot { base: None, draft: Some(doc2()), also: vec![doc1()], keep_base: false, runs: stray(), stretches: Vec::new() };
    let one_place = places(1, &[(0, 1)]);
    let in_doc1 = [AlsoPlaces { draft: doc1(), places: vec![Some(vp(1, 1))] }];
    let all_but_doc1: &Visibility<'_, World> = &|_: &World, d: &Address| *d != doc1();
    let priced = |world: &World, caller: Caller, class: &Visibility<'_, World>, the_shot: &Shot, in_draft: &[Option<VPos>], in_also: &[AlsoPlaces]| {
        price_publication_reads(world, caller, class, &into, the_shot, in_draft, in_also, &none, &mut |_| {})
    };
    // The class that reads doc1: its runs, and the one piece placed in it.
    let read: Vec<_> = worlds.iter().map(|world| priced(world, P2, &ALL_VISIBLE, &rendering, &one_place, &[])).collect();
    assert_eq!(read.iter().map(|price| price.rewindow).collect::<Vec<_>>(), [1 + 1, 16 + 1], "the draft's runs and the one piece");
    assert_eq!(read[1].staged_bytes, read[0].staged_bytes, "premise: the bytes do not turn on the draft's runs");
    // The class that does not: one answer, whatever the draft holds.
    for caller in [P2, Caller::System] {
        let unread: Vec<_> = worlds.iter().map(|world| priced(world, caller, all_but_doc1, &rendering, &one_place, &[])).collect();
        assert_eq!(unread[1], unread[0], "{caller:?}: fifteen more runs in a draft the class does not admit move no figure");
        assert_eq!((unread[0].rewindow, unread[0].staged_bytes), (1, read[0].staged_bytes), "{caller:?}: the one piece and no run, the bytes as any caller's");
    }
    // The same draft named among `also`, re-windowed at its own list.
    let read: Vec<_> = worlds.iter().map(|world| priced(world, P2, &ALL_VISIBLE, &among_also, &[], &in_doc1).rewindow).collect();
    assert_eq!(read, [1 + 1, 16 + 1], "an `also` draft's runs and its one piece");
    for caller in [P2, Caller::System] {
        let unread: Vec<_> = worlds.iter().map(|world| priced(world, caller, all_but_doc1, &among_also, &[], &in_doc1)).collect();
        assert_eq!(unread[1], unread[0], "{caller:?}: nor do an `also` draft's runs");
        assert_eq!(unread[0].rewindow, 1, "{caller:?}: its one piece and no run");
    }
    // Draft by draft: doc2, which the class admits, re-windowed beside doc1.
    let beside: Vec<_> = worlds.iter().map(|world| priced(world, P2, all_but_doc1, &beside_doc2, &one_place, &in_doc1).rewindow).collect();
    assert_eq!(beside, [(2 + 1) + 1, (2 + 1) + 1], "doc2's two runs and its piece, and doc1's piece alone");
    let read: Vec<_> = worlds.iter().map(|world| priced(world, P2, &ALL_VISIBLE, &beside_doc2, &one_place, &in_doc1).rewindow).collect();
    assert_eq!(read, [(2 + 1) + (1 + 1), (2 + 1) + (16 + 1)], "each draft its own runs where both are read");
    // What the price leaves out is never walked: ω refuses the shot.
    let k = kernel_over(worlds[1].clone());
    assert_eq!(
        refused(writer_at(&k, all_but_doc1).publication(P2, &into, &rendering, &one_place, &[], &none)),
        PublicationError::Publish(PublishError::NotOwner(doc1())),
        "the draft is not the caller's: refused at the shot's admission, no draft re-windowed"
    );
}

/// NO STORED TYPE OF A LINK THE CALLER CANNOT READ. An `originals` entry
/// naming a rest is priced a fresh mark of the original's type, and the
/// type is read off the link. doc2, a private draft, holds at one link
/// address nothing, a link typed one ten-component address — the shallow
/// span — a link typed a shorter address, or a link typed three addresses.
/// At a class that reads doc2 the four worlds are priced apart, each at
/// the spans its type slot stores: the first two alike, the shorter type
/// under them, the three spans over. At a class that does NOT read doc2
/// they answer ONE figure — the address's where no link stands — in the
/// bytes' own price and in the reads' price alike, for another account's
/// principal and for the caller that is no principal: the bytes do not
/// tell a link the caller may not read from no link at all. An address
/// deriving no document is priced the same at any class. No such entry is
/// staged: the plan refuses an original that is absent or not the
/// caller's own.
#[test]
fn an_originals_stored_type_is_priced_only_where_the_class_admits_its_home() {
    use skep_address::subtree_of;
    use skep_links::{price_publication_reads, price_staged_bytes, stored_span_bytes, COPY_FIXED_BYTES, RETRACTION_BYTES};
    let into = PublishTarget::Document(sib_doc());
    let the_shot = Shot { base: None, draft: None, also: vec![], keep_base: false, runs: vec![], stretches: Vec::new() };
    let old = link_of(&doc2(), 1);
    // doc2 holding at `old` a link over doc1's `a b c` typed `ty`, or no
    // link where `ty` is empty.
    let typed = |ty: Vec<Address>| {
        world_after(&|k| {
            draft_holding(k, "abc");
            if !ty.is_empty() {
                let link = writer(k)
                    .makelink(P1, &doc2(), SlotArg::Spans(vec![run(&ca(1), 3).iextent()]), SlotArg::Addrs(vec![]), SlotArg::Addrs(ty.clone()))
                    .expect("the original in the private draft")
                    .0;
                assert_eq!(link, old, "premise: the draft's first link");
            }
        })
    };
    let shallow_ty = a(&[1, 1, 0, 1, 0, 1, 0, 3, 23, 2]);
    let worlds = [typed(vec![]), typed(vec![shallow_ty.clone()]), typed(vec![citation()]), typed(vec![shallow_ty.clone(), citation(), a(&[1, 1, 0, 1, 0, 1, 0, 3, 13, 1, 1])])];
    let shallow = stored_span_bytes(&subtree_of(shallow_ty.tumbler()));
    let stored: Vec<Option<u64>> = worlds.iter().map(|world| world.links.readlink(&old).map(|link| link.type_slot().spans().map(stored_span_bytes).sum())).collect();
    assert_eq!(stored[..2], [None, Some(shallow)], "premise: no link, and a type of the one shallow span");
    assert!(stored[2].is_some_and(|ty| ty < shallow) && stored[3].is_some_and(|ty| ty > 2 * shallow), "premise: a narrower type and a wider one: {stored:?}");
    // The bytes a request is priced at, by both prices: one figure.
    let bytes = |world: &World, caller: Caller, class: &Visibility<'_, World>, deposits: &PublishDeposits| {
        let alone = price_staged_bytes(world, class, &into, &the_shot, &[], &[], deposits);
        let price = price_publication_reads(world, caller, class, &into, &the_shot, &[], &[], deposits, &mut |_| {});
        assert_eq!(price.staged_bytes, alone, "the reads' price carries the bytes' own figure");
        alone
    };
    let rest = run(&ca(3), 1).iextent();
    let rider = originals(vec![(old.clone(), vec![rest.clone()])]);
    // The rider past its type: the retraction, and the mark's fixed part
    // and rest span.
    let fixed = bytes(&worlds[0], P2, &ALL_VISIBLE, &PublishDeposits::default()) + RETRACTION_BYTES + COPY_FIXED_BYTES + stored_span_bytes(&rest);
    // The class that reads doc2: each world at its stored type's spans.
    for (world, ty) in worlds.iter().zip(&stored) {
        assert_eq!(bytes(world, P2, &ALL_VISIBLE, &rider), fixed + ty.unwrap_or(shallow), "the type slot as stored, the shallow span where no link stands: {ty:?}");
    }
    // The class that does not: one figure, the absent link's.
    let all_but_doc2: &Visibility<'_, World> = &|_: &World, d: &Address| *d != doc2();
    for caller in [P2, Caller::System] {
        for (world, ty) in worlds.iter().zip(&stored) {
            assert_eq!(bytes(world, caller, all_but_doc2, &rider), fixed + shallow, "{caller:?}: a link the class does not admit the home of is priced as no link, whatever its type stores: {ty:?}");
        }
    }
    // An address that derives no document names no link: the same figure.
    let no_element = originals(vec![(a(&[1, 0, 1]), vec![rest.clone()])]);
    assert_eq!(bytes(&worlds[3], P2, &ALL_VISIBLE, &no_element), fixed + shallow, "an account's address: no home, no link");
    // No such entry is staged: the plan refuses each.
    for (world, cause) in worlds.iter().zip([OriginalCause::Absent, OriginalCause::NotOwner, OriginalCause::NotOwner, OriginalCause::NotOwner]) {
        let k = kernel_over(world.clone());
        assert_eq!(
            refused(writer_at(&k, all_but_doc2).publication(P2, &into, &the_shot, &[], &[], &rider)),
            PublicationError::Plan(PlanFault::Original { index: 0, cause }),
            "an original that is absent or another account's: refused by the plan, nothing staged"
        );
    }
}

/// NO HOME THE CALLER CANNOT READ. A publication's price counts the
/// caller's link-holding homes, the documents under its seat that hold a
/// link, and the node's own principal is seated at the node, under which
/// every home on the board lies. An account holds sixteen private drafts
/// and one published document that holds a link, and on three boards none
/// of the drafts, two of them, and all sixteen hold a link. At a class that
/// admits no private draft — published documents alone, the guest's — the
/// node's principal is priced ONE home on every board, the published one,
/// figure for figure: its count says nothing of how many drafts it may not
/// read hold a link, or whether any does. At the class that admits every
/// document its homes are the published one and the drafts holding links:
/// none, two and sixteen more. The account's own principal, at a class that
/// admits what it owns, is priced every home under its account on each
/// board — `homes_under` of the account, as before the class was asked —
/// and at the class of published documents alone the published one, the
/// count following the class and never the seat. The caller that is no
/// principal holds no seat and is priced no home at any class. And the
/// count stays at or above the homes the plan reads, the homes ω answers
/// the caller: none for the node's principal on any board, and for the
/// account's principal homes its own class admits, every one.
#[test]
fn a_home_the_class_does_not_admit_is_counted_no_home() {
    use skep_arrangement::M5State;
    use skep_content::ContentStore;
    use skep_links::{price_publication_reads, LinkState};
    use skep_namespace::BOOTSTRAP_PRINCIPAL;

    const NODE: Caller = Caller::Principal(BOOTSTRAP_PRINCIPAL);
    let (account, published) = (a(&[1, 0, 1]), doc(17));
    // The account's sixteen private drafts and its published document, the
    // first `linked` drafts and the published one each holding a link.
    let board = |linked: u32| -> World {
        let mut m3 = M3State::genesis()
            .apply_m3(Seq(0), &M3Rec::allocate(account.clone(), false))
            .apply_m3(Seq(0), &M3Rec::register_principal(account.clone(), PrincipalId(1)));
        for d in 1..=16 {
            m3 = m3.apply_m3(Seq(0), &M3Rec::allocate(doc(d), false));
        }
        m3 = m3.apply_m3(Seq(0), &M3Rec::allocate(published.clone(), true));
        let k = kernel_over(World { m3, content: ContentStore::default(), m5: M5State::genesis(), links: LinkState::genesis() });
        deposit_in(&k, &published, &[], &[], &citation());
        for d in 1..=linked {
            deposit_in(&k, &doc(d), &[], &[], &citation());
        }
        let world = k.snapshot().world().clone();
        world
    };
    let boards = [board(0), board(2), board(16)];
    assert_eq!(boards[0].m3.principal_prefix(BOOTSTRAP_PRINCIPAL), Some(&a(&[1])), "premise: the node's principal is seated at the node");
    let under = |world: &World, seat: &Address| world.links.homes_under(&enc([seat])).len();
    for (world, linked) in boards.iter().zip([0, 2, 16]) {
        assert_eq!((under(world, &a(&[1])), under(world, &account)), (1 + linked, 1 + linked), "premise: the homes under the node are the account's, the published one and the drafts holding links");
    }
    let (into, the_shot) = (PublishTarget::Document(published.clone()), shot(None, vec![]));
    let one_entry = PublishDeposits { read_with: vec![published.clone()], ..PublishDeposits::default() };
    let priced = |caller: Caller, class: &Visibility<'_, World>| -> Vec<skep_links::ReadPrice> {
        boards.iter().map(|world| price_publication_reads(world, caller, class, &into, &the_shot, &[], &[], &one_entry, &mut |_| {})).collect()
    };
    let homes = |caller: Caller, class: &Visibility<'_, World>| -> Vec<usize> { priced(caller, class).iter().map(|price| price.homes).collect() };
    let published_alone: &Visibility<'_, World> = &|world: &World, d: &Address| world.m3.published(d);
    let owned_or_published: &Visibility<'_, World> = &|world: &World, d: &Address| world.m3.published(d) || P1.is_owner(&world.m3, d);
    // The node's principal, at a class admitting no private draft: one
    // answer, whatever the drafts hold.
    let unread = priced(NODE, published_alone);
    assert_eq!(unread[1], unread[0], "two private drafts holding a link move no figure");
    assert_eq!(unread[2], unread[0], "nor do sixteen");
    assert_eq!((unread[0].homes, unread[0].total()), (1, 1), "the published home, which every class admits, and its one entry");
    // At the class admitting every document: the drafts holding links too.
    assert_eq!(homes(NODE, &ALL_VISIBLE), [1, 3, 17], "a home a link-holding document the class admits");
    // The account's principal: every home under its account, as before.
    let own = homes(P1, owned_or_published);
    assert_eq!(own, [1, 3, 17], "its own class admits each of its homes");
    for (world, count) in boards.iter().zip(&own) {
        assert_eq!(*count, under(world, &account), "`homes_under` of the account, the figure before the class was asked");
    }
    assert_eq!(homes(P1, published_alone), [1, 1, 1], "the count follows the class, never the seat");
    // No principal, no seat, no home.
    for class in [published_alone, &ALL_VISIBLE] {
        assert_eq!(homes(Caller::System, class), [0, 0, 0], "the caller that is no principal");
    }
    // At or above the homes the plan reads: those ω answers the caller.
    let owned = |world: &World, caller: Caller, seat: &Address| world.links.homes_under(&enc([seat])).iter().filter(|home| caller.is_owner(&world.m3, home)).count();
    for (world, (theirs, mine)) in boards.iter().zip(unread.iter().zip(&own)) {
        assert_eq!(owned(world, NODE, &a(&[1])), 0, "a document's owner is its own account's seat: the node's principal owns no home");
        assert!(owned(world, NODE, &a(&[1])) <= theirs.homes && owned(world, P1, &account) <= *mine, "the price is a bound on the homes the plan reads");
    }
}

/// A journaled board whose edition's first member arranges `count` runs,
/// none I-adjacent to the next: windows onto doc2 at every second address,
/// placed by a birth shot. doc2 holds `2 × count + 400` values, so 200 more
/// windows past the member's stand apart from it and from one another.
fn fragmented_board(count: u32) -> (Journaled, Address) {
    let k = journaled_over(edition_world());
    let values: Vec<Val> = (0..2 * count + 400).map(|_| Val::new(*b"x")).collect();
    Vstream::new(&k)
        .insert(Caller::System, &doc2(), VPos::content(n(1)), values, Deposit::Undeclared, AsOf::Typed(k.current_seq()))
        .expect("doc2's values");
    let birth = Shot {
        base: None,
        draft: None,
        also: vec![],
        keep_base: false,
        runs: (1..=count).map(|i| shot_run(&doc2(), &ca2(2 * i), 1)).collect(),
        stretches: Vec::new(),
    };
    let (member, _) = publish(&k, &birth, &PublishDeposits::default()).expect("the birth shot");
    assert_eq!(k.snapshot().world().m5().content_run_count(&member), count as usize);
    (k, member)
}

/// A SHOT'S JOURNAL FOLLOWS ITS CHANGE, NEVER THE FILE. A shot that names
/// its change stages the runs of the change and the stretches that place
/// them: a one-run change into a file of 1,000 runs and into one of 5,000
/// journals the SAME bytes, at one position of both, where the whole form
/// of that change journals a run's bytes for every run of the file. Within
/// one stretch each changed run adds a run's bytes and no more; each further
/// stretch adds a stretch's entry beside its run. The figures are read off
/// the journal's growth across each commit, and the price bounds each.
#[test]
fn a_stretch_shots_journal_follows_its_change_and_never_the_file() {
    use skep_arrangement::ShotStretch;
    use skep_links::{price_staged_bytes, stored_tumbler_bytes, PLACED_RUN_BYTES, SHOT_BYTES, STRETCH_BYTES};

    let none = PublishDeposits::default();
    let into_e = PublishTarget::Document(pdoc());
    // A fresh window the files do not hold, the `k`-th: past every address
    // the birth shot placed, and apart from the one before it.
    let fresh = |count: u32, k: u32| shot_run(&doc2(), &ca2(2 * count + 2 * k), 1);
    // The journal's growth across one publication off `base`, and the
    // member it mints.
    let journaled = |board: &Journaled, shot: &Shot| -> (u64, Address) {
        let before = board.journal_bytes();
        let (member, _) = publish(board, shot, &none).expect("the shot commits");
        (board.journal_bytes() - before, member)
    };
    // A shot off `base` at `extent` whose stretches each replace one
    // position by `runs_each` fresh windows, the `j`-th stretch at position
    // `100 + 10 j`.
    let places = |count: u32, base: &Address, stretches: u32, runs_each: u32| Shot {
        base: Some(skep_arrangement::Base { member: base.clone(), extent: n(count) }),
        draft: None,
        also: vec![],
        keep_base: false,
        runs: (1..=stretches * runs_each).map(|k| fresh(count, k)).collect(),
        stretches: (0..stretches)
            .map(|j| ShotStretch { start: n(100 + 10 * j), width: n(1), count: runs_each as usize })
            .collect(),
    };
    let mut one_run_change = Vec::new();
    let mut whole_form = Vec::new();
    for count in [1_000u32, 5_000] {
        let (board, first) = fragmented_board(count);
        // The one-run change, by its stretch.
        let shot = places(count, &first, 1, 1);
        let world_before = board.snapshot();
        let priced = price_staged_bytes(world_before.world(), &ALL_VISIBLE, &into_e, &shot, &[], &[], &none);
        let (bytes, member) = journaled(&board, &shot);
        assert_eq!(board.snapshot().world().m5().content_run_count(&member), count as usize);
        assert_eq!(bytes - priced, 109, "{count}: the price is exactly the records', the commit's marker beside them");
        assert_eq!(
            priced,
            SHOT_BYTES + stored_tumbler_bytes(first.tumbler()) + PLACED_RUN_BYTES + STRETCH_BYTES,
            "{count}: the shot's fixed part, its base's address, one run and one stretch"
        );
        one_run_change.push((bytes, priced));
        // The same change with no stretch list: every run of the file.
        let s = board.snapshot();
        let mut runs: Vec<ShotRun> =
            s.world().m5().content_runs(&first).map(|r| ShotRun { origin: doc2(), run: r.clone() }).collect();
        runs[99] = fresh(count, 1);
        let whole = Shot { base: Some(skep_arrangement::Base { member: first.clone(), extent: n(count) }), draft: None, also: vec![], keep_base: false, runs, stretches: Vec::new() };
        let (whole_bytes, whole_member) = journaled(&board, &whole);
        assert_eq!(
            board.snapshot().world().m5().content_runs(&whole_member).collect::<Vec<_>>(),
            board.snapshot().world().m5().content_runs(&member).collect::<Vec<_>>(),
            "{count}: the two forms mint one member"
        );
        whole_form.push(whole_bytes);
        if count == 5_000 {
            // Within one stretch a changed run is a run's bytes; each
            // further stretch is its entry beside its run. Every shot from
            // here lands as a daughter of the first member, the trunk's
            // head having moved, so each is measured against a daughter:
            // its address is a component longer, in its mint and in its
            // placing record.
            let (one, _) = journaled(&board, &places(count, &first, 1, 1));
            assert_eq!(one - bytes, 2 * 12, "a daughter's address, one component longer, twice");
            for runs in [10u32, 100] {
                let (many, _) = journaled(&board, &places(count, &first, 1, runs));
                assert_eq!(many - one, u64::from(runs - 1) * PLACED_RUN_BYTES, "{runs} runs in one stretch");
            }
            for stretches in [10u32, 100] {
                let (many, _) = journaled(&board, &places(count, &first, stretches, 1));
                assert_eq!(
                    many - one,
                    u64::from(stretches - 1) * (PLACED_RUN_BYTES + STRETCH_BYTES),
                    "{stretches} stretches of one run each: a run and a stretch entry apiece"
                );
            }
        }
    }
    let ((small, priced_small), (large, priced_large)) = (one_run_change[0], one_run_change[1]);
    println!(
        "a one-run change by its stretch: {small} B into 1,000 runs, {large} B into 5,000 (priced {priced_small}, {priced_large}); \
         the same change in the whole form: {} B and {} B",
        whole_form[0], whole_form[1]
    );
    assert_eq!(small, large, "the journal follows the change: not one byte for a run of the file");
    assert_eq!(priced_small, priced_large);
    assert_eq!(
        whole_form[1] - whole_form[0],
        4_000 * PLACED_RUN_BYTES,
        "the whole form journals a run's bytes for every run of the file"
    );
}
