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

use skep_address::{Address, Span};
use skep_arrangement::{
    head_lock_key, Caller, Deposit, HasM5, PublishError, Run, Shot, ShotRun, Vstream,
};
use skep_content::{HasContent, Val};
use skep_kernel::{Attestation, Kernel, TxnError};
use skep_links::{
    correspondence_type, enc, is_correspondence_class, stage_correspondence, stage_publication,
    Endset, HasLinks, Link, LinkWriter, PublicationError, SlotArg, FROM, TO,
};
use skep_namespace::{HasM3, M3State};

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
        .publication(P1, &pdoc(), &shot(None, vec![shot_run(&doc1(), &ca(2), 2), shot_run(&doc1(), &ca(1), 3)]))
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
    let (m1, _) = w.publication(P1, &pdoc(), &shot(None, vec![shot_run(&doc1(), &ca(1), 3)])).expect("the first shot");
    // A second member, placing the published words by reference and a
    // fresh `d` from the draft: a record for `d` alone.
    Vstream::new(&k).insert(P1, &doc1(), vp(1, 4), vec![Val::new([b'd'])], Deposit::Undeclared).expect("d at ca(4)");
    let (m2, _) = w
        .publication(P1, &pdoc(), &shot(Some((&m1, 3)), vec![shot_run(&pdoc(), &pca(1), 3), shot_run(&doc1(), &ca(4), 1)]))
        .expect("a fresh run lands");
    assert_eq!((m1, m2.clone()), (pmember(1), pmember(2)));
    assert_eq!(records_in_doc1(&k).len(), 2, "one record per shot that re-inserted: a b c, then d");
    assert_eq!(bytes_of(&k, &m2), "abcd");

    let before = k.snapshot();
    // `b` alone: a sub-run of the first record's `from`, split from its run.
    let refusal = refused(w.publication(P1, &pdoc(), &shot(Some((&m2, 4)), vec![shot_run(&doc1(), &ca(2), 1)])));
    assert_eq!(
        refusal,
        PublicationError::AlreadyPublished { site: pmember(1) },
        "the record's own member — the first, though the second arranges the span too"
    );
    // The whole run again, and a run straddling the record's reach.
    for run in [shot_run(&doc1(), &ca(1), 3), shot_run(&doc1(), &ca(3), 2)] {
        assert_eq!(
            refused(w.publication(P1, &pdoc(), &shot(Some((&m2, 4)), vec![run]))),
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
        .publication(P1, &pdoc(), &shot(Some((&m2, 4)), vec![shot_run(&pdoc(), &pca(1), 4), shot_run(&doc1(), &ca(5), 1)]))
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
    w.publication(P1, &pdoc(), &shot(None, vec![shot_run(&doc1(), &ca(1), 3)])).expect("P1 publishes a b c");
    let before = k.snapshot();
    let theirs = Shot { base: None, draft: Some(doc1()), runs: vec![shot_run(&doc1(), &ca(2), 1)] };
    assert_eq!(
        refused(w.publication(P2, &sib_doc(), &theirs)),
        PublicationError::Publish(PublishError::NotOwner(doc1())),
        "the draft is P1's: ω, not the fence"
    );
    assert_eq!(
        refused(w.publication(Caller::System, &sib_doc(), &theirs)),
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
    let (m2, s2) = writer(&k).publication(P1, &pdoc(), &own(Some((&m1, 0)), None)).expect("no draft");
    assert_eq!(s2.0 - s1.0, shot_alone, "the same records as the shot alone");
    let (_, s3) = writer(&k).publication(P1, &pdoc(), &own(Some((&m2, 0)), Some(doc1()))).expect("a draft, nothing re-inserted");
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
        stage_publication(stg, P1, &pdoc(), &the_shot, &ALL_VISIBLE)?;
        Err(PublicationError::HomeNotRegistered)
    });
    assert!(matches!(r, Err(TxnError::Rejected(PublicationError::HomeNotRegistered))));
    assert_eq!(k.current_seq(), before, "nothing committed");
    assert!(records_in_doc1(&k).is_empty());
    assert!(!k.snapshot().world().m3().is_registered_document(&pmember(1)), "no member");
    // The composite beside a staging of the caller's own, in one commit.
    let (member, _) = k
        .transact(&keys, |stg| {
            let member = stage_publication(stg, P1, &pdoc(), &the_shot, &ALL_VISIBLE)?;
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
    let (m1, s1) = attested.publication(P1, &pdoc(), &shot(None, vec![shot_run(&doc1(), &ca(1), 2)])).expect("attested");
    let (_, s2) = writer(&k)
        .publication(P1, &pdoc(), &shot(Some((&m1, 2)), vec![shot_run(&pdoc(), &pca(1), 2), shot_run(&doc1(), &ca(3), 1)]))
        .expect("plain");
    assert_eq!(k.attestation_at(s1).unwrap(), Some(tag1), "the attested publication's one slot");
    assert_eq!(k.attestation_at(s2).unwrap(), None, "the plain one's");
    assert_eq!(records_in_doc1(&k).len(), 2);
}
