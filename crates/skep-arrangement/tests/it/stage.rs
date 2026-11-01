//! STAGE (the staging act, B3-S10): the one operation that mints a private
//! draft of a source, shares the source's whole surface into it and records
//! where it began — and the base's move at every shot the draft renders.

use skep_arrangement::{AsOf, Deposit, DraftBase, HasM5, InsertError, Shot, StageError, Vstream};
use skep_kernel::{Attestation, Kernel};
use skep_namespace::{HasM3, PrincipalId};
use tempfile::tempdir;

use crate::common::*;

/// The `k`-th document of principal 1's account — the fourth and on are
/// what a stage mints there, the first three being the seeded fixtures.
fn minted(k: u32) -> skep_address::Address {
    a(&[1, 0, 1, 0, k])
}

/// THE STAGING ACT IS ONE BOARD OPERATION (B3-S10; A-350): a stage off a
/// version member mints a PRIVATE document in the stager's own account that
/// shares the member's whole surface by identity — `version`'s snapshot,
/// the link subspace apart — and records the draft's base, the extent the
/// copy took and its source in the slice's own state, all in ONE commit,
/// the ack's position. A bare published document with members stages its
/// head, as `version` snapshots it. The draft's typed state starts at the
/// mint (skep #442): an edit typed at the ack lands, one typed before it is
/// refused. The source answers no base: the read answers the address named.
#[test]
fn a_stage_mints_a_private_draft_sharing_the_sources_whole_surface_and_records_its_base() {
    let k = mem_kernel();
    let vs = deposit_abc(&k);
    let (member, _) = vs.version(PrincipalId(1), &pdoc(), None).expect("the edition's first version");
    assert_eq!(member, vdoc());
    let before = k.current_seq();
    let (draft, at) = vs.stage(PrincipalId(1), &member).expect("the stage commits");
    assert_eq!(draft, minted(4), "the next document of the stager's account");
    assert_eq!(k.current_seq(), at, "the ack's position is the head");
    {
        let s = k.snapshot();
        let (m3, m5) = (s.world().m3(), s.world().m5());
        assert!(m3.is_registered_document(&draft));
        assert!(!m3.published(&draft), "born private, whatever the source's state");
        assert!(m3.is_effective_owner(PrincipalId(1), &draft), "in the stager's own account");
        assert_eq!(
            m5.content_runs(&draft).collect::<Vec<_>>(),
            m5.content_runs(&member).collect::<Vec<_>>(),
            "the member's whole surface, by identity"
        );
        assert_eq!(bytes_of(&s, &draft), [b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]);
        assert_eq!(m5.link_count(&draft), n(0), "the link subspace is not shared");
        assert_eq!(
            m5.draft_base(&draft),
            Some(&DraftBase { base: member.clone(), extent: n(3), source: member.clone() }),
            "the base, the count the copy took, the source"
        );
        assert_eq!(m5.fork_source(&draft), Some(&member), "the snapshot's source, as a version's");
        assert_eq!(m5.arranged_at(&draft), Some(at), "the typed state starts at the mint");
        assert_eq!(m5.birth_extent(&draft), None, "no birth version: a document, not a member");
        assert_eq!(m5.shot_terms(&draft), None, "no shot minted it");
        assert_eq!(m5.draft_base(&member), None, "the source answers none: the address named");
        assert_eq!(m5.draft_base(&pdoc()), None);
    }
    // The first edit, typed against the stage's ack, lands; typed before
    // it, the edit is refused as moved (skep #442's board half).
    assert!(matches!(
        rejected(vs.insert(P1, &draft, vp(1, 4), vec![val(b"z")], Deposit::Undeclared, AsOf::Typed(before))),
        InsertError::ArrangementMoved { .. }
    ));
    vs.insert(P1, &draft, vp(1, 4), vec![val(b"z")], Deposit::Undeclared, AsOf::Typed(at))
        .expect("typed at the ack, the draft's first edit lands");
    // The bare published document with a member stages its HEAD — the
    // reading surface — and records the head as the base.
    let (off_bare, _) = vs.stage(PrincipalId(1), &pdoc()).expect("off the bare document");
    assert_eq!(off_bare, minted(5));
    let s = k.snapshot();
    assert_eq!(
        s.world().m5().draft_base(&off_bare),
        Some(&DraftBase { base: member.clone(), extent: n(3), source: member.clone() }),
        "the head, not the document's own pre-chain arrangement"
    );
    assert_eq!(s.world().m5().fork_source(&off_bare), Some(&member));
    // The source's own state is untouched by either stage (V3).
    assert_eq!(bytes_of(&s, &member), [b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]);
    assert_eq!(s.world().m5().content_count(&draft), n(4), "the first draft diverged alone");
}

/// THE BARE DOCUMENT AS THE BASE: staged while its chain is empty, a
/// published document is its own base, the extent what the copy took of
/// it — zero for an empty edition, its count once content stands there (a
/// memberless home's genesis atom counted where it is there), measured and
/// never a constant.
#[test]
fn a_stage_of_the_memberless_document_records_it_as_the_base_with_the_count_the_copy_took() {
    let k = mem_kernel();
    let vs = Vstream::new(&k);
    let (empty, _) = vs.stage(PrincipalId(1), &pdoc()).expect("off the empty edition");
    {
        let s = k.snapshot();
        let m5 = s.world().m5();
        assert_eq!(m5.content_count(&empty), n(0), "nothing to share");
        assert_eq!(
            m5.draft_base(&empty),
            Some(&DraftBase { base: pdoc(), extent: n(0), source: pdoc() }),
            "the bare document, at zero"
        );
        assert_eq!(m5.fork_source(&empty), Some(&pdoc()), "noted, an empty surface included");
    }
    deposit_abc(&k);
    let (full, _) = vs.stage(PrincipalId(1), &pdoc()).expect("off the edition holding a b c");
    let s = k.snapshot();
    let m5 = s.world().m5();
    assert_eq!(bytes_of(&s, &full), [b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]);
    assert_eq!(
        m5.draft_base(&full),
        Some(&DraftBase { base: pdoc(), extent: n(3), source: pdoc() }),
        "the count the copy took"
    );
    assert_eq!(m5.draft_base(&empty), Some(&DraftBase { base: pdoc(), extent: n(0), source: pdoc() }), "the earlier record stands");
}

/// THE POOL SIBLING (B3-S10): an alternative staged from a draft inherits
/// the draft's recorded base and extent, by identity — the alternative holds
/// the draft's words — with the draft as its source, one hop; an alternative
/// of an alternative inherits the same base with its own source. A draft the
/// board holds no base for — a plain mint never staged — leaves the
/// alternative unrecorded, a free-standing draft of its own, its source
/// noted all the same; another principal's draft stages into the stager's
/// own account the same way.
#[test]
fn an_alternative_inherits_its_source_drafts_base_and_an_unrecorded_source_leaves_it_free_standing() {
    let k = mem_kernel();
    let vs = deposit_abc(&k);
    insert_abc(&k);
    let (member, _) = vs.version(PrincipalId(1), &pdoc(), None).expect("the first version");
    let (staged, _) = vs.stage(PrincipalId(1), &member).expect("the staging draft");
    vs.insert(P1, &staged, vp(1, 4), vec![val(b"z")], Deposit::Undeclared, now(&k))
        .expect("the staging draft grows");
    let (alternative, _) = vs.stage(PrincipalId(1), &staged).expect("an alternative of the staging draft");
    assert_eq!(alternative, minted(5));
    {
        let s = k.snapshot();
        let m5 = s.world().m5();
        assert_eq!(
            m5.draft_base(&alternative),
            Some(&DraftBase { base: member.clone(), extent: n(3), source: staged.clone() }),
            "the staging draft's base and extent, inherited; the draft its source"
        );
        assert_eq!(
            m5.content_runs(&alternative).collect::<Vec<_>>(),
            m5.content_runs(&staged).collect::<Vec<_>>(),
            "the draft's current words, the edit included"
        );
        assert_eq!(bytes_of(&s, &alternative), [b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"z".to_vec()]);
        assert_eq!(m5.fork_source(&alternative), Some(&staged));
    }
    let (nested, _) = vs.stage(PrincipalId(1), &alternative).expect("an alternative of the alternative");
    assert_eq!(
        k.snapshot().world().m5().draft_base(&nested),
        Some(&DraftBase { base: member.clone(), extent: n(3), source: alternative.clone() }),
        "the same base, its own source"
    );
    // A plain draft never staged: doc1 holds a b c and no record.
    let (free, _) = vs.stage(PrincipalId(1), &doc1()).expect("an alternative of an unrecorded draft");
    {
        let s = k.snapshot();
        let m5 = s.world().m5();
        assert_eq!(m5.draft_base(&free), None, "free-standing: no base to inherit");
        assert_eq!(m5.fork_source(&free), Some(&doc1()), "its source noted all the same");
        assert_eq!(bytes_of(&s, &free), [b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]);
        assert!(!s.world().m3().published(&free));
    }
    // Another principal stages the draft into ITS own account.
    let (theirs, _) = vs.stage(PrincipalId(2), &doc1()).expect("another's draft, staged");
    assert_eq!(theirs, a(&[1, 0, 2, 0, 1]));
    let s = k.snapshot();
    assert!(s.world().m3().is_effective_owner(PrincipalId(2), &theirs));
    assert!(!s.world().m3().published(&theirs));
    assert_eq!(s.world().m5().draft_base(&theirs), None);
    assert_eq!(s.world().m5().fork_source(&theirs), Some(&doc1()));
}

/// THE BASE MOVES ON PUBLISH (B3-S10): at each shot naming the draft as its
/// rendering draft, the board moves the draft's recorded base to the member
/// the shot minted and its extent to that member's whole count — the carried
/// tail and the re-minted words counted — keeping the source; so a draft
/// staged from version 1 that publishes version 2 publishes version 3 next,
/// never a daughter of version 1. A shot naming no draft moves no base, and
/// nothing checks the request's own `base` against the record.
#[test]
fn the_base_moves_to_the_member_the_draft_renders_and_the_next_shot_lands_after_it() {
    let k = mem_kernel();
    let vs = deposit_abc(&k);
    let (e1, _) = vs.version(PrincipalId(1), &pdoc(), None).expect("version 1");
    let (d, _) = vs.stage(PrincipalId(1), &e1).expect("the staging draft");
    let (z, _) = vs
        .insert(P1, &d, vp(1, 4), vec![val(b"z")], Deposit::Undeclared, now(&k))
        .expect("the draft's own word");
    let readable = readable_by(PrincipalId(1));
    let shot = Shot {
        base: Some(base(&e1, 3)),
        draft: Some(d.clone()),
        also: vec![],
        runs: vec![shot_run(&pdoc(), &pca(1), 3), shot_run(&d, &z, 1)],
    };
    let (e2, _) = vs.publish(P1, &pdoc(), &shot, &readable).expect("version 2");
    assert_eq!(e2, a(&[1, 0, 1, 0, 3, 2]), "the trunk's next member");
    {
        let s = k.snapshot();
        let m5 = s.world().m5();
        assert_eq!(
            m5.draft_base(&d),
            Some(&DraftBase { base: e2.clone(), extent: n(4), source: e1.clone() }),
            "the base moved to the member, the extent its whole count, the source kept"
        );
        assert_eq!(m5.content_count(&e2), n(4));
    }
    // The next shot from the draft, off the base the board now records,
    // lands as version 3 — not as a daughter of version 1.
    let next = Shot {
        base: Some(base(&e2, 4)),
        draft: Some(d.clone()),
        also: vec![],
        runs: vec![shot_run(&pdoc(), &pca(1), 4)],
    };
    let (e3, _) = vs.publish(P1, &pdoc(), &next, &readable).expect("version 3");
    assert_eq!(e3, a(&[1, 0, 1, 0, 3, 3]));
    assert_eq!(
        k.snapshot().world().m5().draft_base(&d),
        Some(&DraftBase { base: e3.clone(), extent: n(4), source: e1.clone() })
    );
    // A shot naming no draft moves nothing.
    let unnamed = Shot { base: Some(base(&e3, 4)), draft: None, also: vec![], runs: vec![shot_run(&pdoc(), &pca(1), 4)] };
    vs.publish(P1, &pdoc(), &unnamed, &readable).expect("version 4, no draft named");
    assert_eq!(
        k.snapshot().world().m5().draft_base(&d),
        Some(&DraftBase { base: e3.clone(), extent: n(4), source: e1.clone() }),
        "no draft named: the draft's base stands where it stood"
    );
    // The request's base is the client's statement, checked against the
    // chain and never against the record: a shot naming version 1 as its
    // base while the record says version 3 lands as version 1's daughter,
    // as PUB-2.39 has it, and moves the base there.
    let daughter = Shot { base: Some(base(&e1, 3)), draft: Some(d.clone()), also: vec![], runs: vec![shot_run(&pdoc(), &pca(1), 3)] };
    let (e1_1, _) = vs.publish(P1, &pdoc(), &daughter, &readable).expect("a daughter under version 1");
    assert_eq!(e1_1, a(&[1, 0, 1, 0, 3, 1, 1]));
    assert_eq!(
        k.snapshot().world().m5().draft_base(&d),
        Some(&DraftBase { base: e1_1, extent: n(3), source: e1 })
    );
}

/// A draft the board held no base for — a plain mint, never staged — gains
/// one at its own shot: the member it rendered as its base and its source,
/// so a draft whose first publication minted its edition stands on that
/// edition's first member and publishes its second next.
#[test]
fn a_draft_the_board_held_no_base_for_gains_one_at_its_own_shot() {
    let k = mem_kernel();
    let vs = insert_abc(&k);
    assert_eq!(k.snapshot().world().m5().draft_base(&doc1()), None, "a plain draft");
    let readable = readable_by(PrincipalId(1));
    let birth = Shot { base: None, draft: Some(doc1()), also: vec![], runs: vec![shot_run(&doc1(), &ca(1), 3)] };
    let (e1, _) = vs.publish(P1, &pdoc(), &birth, &readable).expect("the birth version, from the draft");
    assert_eq!(e1, vdoc());
    assert_eq!(
        k.snapshot().world().m5().draft_base(&doc1()),
        Some(&DraftBase { base: e1.clone(), extent: n(3), source: e1.clone() }),
        "the member rendered, its base and its source"
    );
    let next = Shot { base: Some(base(&e1, 3)), draft: Some(doc1()), also: vec![], runs: vec![shot_run(&pdoc(), &pca(1), 3)] };
    let (e2, _) = vs.publish(P1, &pdoc(), &next, &readable).expect("the second version");
    assert_eq!(e2, a(&[1, 0, 1, 0, 3, 2]));
    assert_eq!(
        k.snapshot().world().m5().draft_base(&doc1()),
        Some(&DraftBase { base: e2, extent: n(3), source: e1 }),
        "moved again, the source kept"
    );
}

/// A refused stage leaves nothing: the three pre-transaction refusals, in
/// the order `version`'s cross-owner arm states them — registration first,
/// so a stage aimed at an address naming no document discloses nothing
/// about the stager — commit nothing and mint nothing.
#[test]
fn stage_rejects_an_unregistered_source_an_unknown_principal_and_a_node_tier_stager() {
    let k = mem_kernel();
    let vs = insert_abc(&k);
    let before = k.current_seq();
    let unregistered_doc = a(&[1, 0, 1, 0, 9]);
    assert!(matches!(
        rejected(vs.stage(PrincipalId(1), &unregistered_doc)),
        StageError::SourceNotRegistered
    ));
    assert!(matches!(rejected(vs.stage(PrincipalId(99), &doc1())), StageError::NotAPrincipal));
    // Principal 0 is the bootstrap NODE-tier principal: its account is no
    // account, so it stages nothing — rejected explicitly, never as a
    // downstream Mint(NotAnAccount).
    assert!(matches!(
        rejected(vs.stage(PrincipalId(0), &doc1())),
        StageError::NodeTierCrossOwner
    ));
    // Which wins: registration, so nothing about the stager is disclosed.
    assert!(matches!(
        rejected(vs.stage(PrincipalId(99), &unregistered_doc)),
        StageError::SourceNotRegistered
    ));
    assert_eq!(k.current_seq(), before, "a refusal commits nothing");
    assert!(!k.snapshot().world().m3().is_registered_document(&minted(4)), "nothing minted");
}

/// A stage is ONE commit — the mint, the snapshot and the record take one
/// boundary, the ack's, so a stop leaves the draft whole or nothing — and it
/// takes the PLAIN arm whatever handle it is called on: it is never
/// publish-class, so an attested handle's stage leaves its marker's
/// signature slot empty, where the same handle's `version` fills it.
#[test]
fn a_stage_is_one_commit_and_takes_the_plain_arm_whatever_handle_it_is_called_on() {
    let dir = tempdir().expect("tempdir");
    let k = Kernel::<World>::open(cfg_fsync(dir.path()), genesis()).expect("open");
    let tag = Attestation::new(1, vec![0x11; 64]).expect("a tag over a blob");
    let attested = Vstream::attested(&k, Some(&tag));
    deposit_abc(&k);
    insert_abc(&k);
    let before = k.current_seq();
    let (draft, s_stage) = attested.stage(PrincipalId(1), &pdoc()).expect("the attested handle's stage");
    assert_eq!(
        k.boundaries_above(before).expect("a journaled kernel answers its boundaries"),
        vec![(s_stage, None)],
        "exactly one commit position was taken, its signature slot empty"
    );
    assert_eq!(k.current_seq(), s_stage);
    {
        let s = k.snapshot();
        assert!(s.world().m3().is_registered_document(&draft), "the mint");
        assert_eq!(bytes_of(&s, &draft), [b"a".to_vec(), b"b".to_vec(), b"c".to_vec()], "the copy");
        assert_eq!(
            s.world().m5().draft_base(&draft),
            Some(&DraftBase { base: pdoc(), extent: n(3), source: pdoc() }),
            "the record"
        );
    }
    let (_, s_version) = attested.version(PrincipalId(2), &doc1(), None).expect("the attested handle's version");
    assert_eq!(k.attestation_at(s_stage).unwrap(), None, "a stage is never publish-class: the slot stays empty");
    assert_eq!(k.attestation_at(s_version).unwrap(), Some(tag), "the same handle's version fills it");
}
