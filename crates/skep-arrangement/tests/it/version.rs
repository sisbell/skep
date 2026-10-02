//! VERSION (§B; ASN-0123): the owned and the cross-owner fork, what each
//! shares, and the version-chain refusals on the owned arm.

use skep_address::SpanSet;
use skep_arrangement::{seat_link, Caller, Deposit, HasM5, Shot, VersionError, Vstream};
use skep_namespace::{HasM3, PrincipalId};

use crate::common::*;

#[test]
fn owned_version_shares_the_map_and_diverges_copy_on_write() {
    // ASN-0123: mint_version on the (d_src, 1) chain; the fork carries the
    // same V→I map; later edits diverge the fork only (V3/V11); the fork's
    // shared runs are R-recorded (J1★). The source is the PUBLISHED edition,
    // the one owned source `version` admits (PUB-2.9), and the fork is a
    // published member of its chain, so what diverges it is a DECLARED
    // deposit at its fresh position — the head's own exempt act (PUB-2.66).
    let k = mem_kernel();
    let vs = deposit_abc(&k);
    seat_link(&k, &pdoc(), &a(&[1, 0, 1, 0, 3, 0, 2, 1])).expect("seat commits");
    let (fork, _) = vs
        .version(PrincipalId(1), &pdoc(), None)
        .expect("owned fork commits");
    assert_eq!(fork, vdoc());
    {
        let s = k.snapshot();
        let m5 = s.world().m5();
        assert_eq!(
            m5.content_runs(&fork).collect::<Vec<_>>(),
            m5.content_runs(&pdoc()).collect::<Vec<_>>()
        );
        let first = m5.content_runs(&pdoc()).next().expect("pdoc arranges a run");
        let cov = SpanSet::singleton(first.iextent());
        assert_eq!(m5.docs_ever_containing(&cov), vec![pdoc(), vdoc()]);
        // V2: the snapshot is of the CONTENT subspace. The source's seated
        // link stays the source's — carried over it would sit in the fork
        // under an origin that is not the fork, which CL-OWN forbids.
        assert_eq!(m5.link_count(&fork), n(0));
        assert_eq!(m5.link_count(&pdoc()), n(1));
        // The member inherits the edition's publication (PUB-2.8).
        assert!(s.world().m3().published(&fork));
    }
    // Deposit into the fork: its content chain mints LENGTH-9 elements; the
    // source is untouched.
    let (start, _) = vs
        .insert(P1, &fork, vp(1, 4), vec![val(b"z")], declared())
        .expect("a declared deposit at the fork's fresh position commits");
    assert_eq!(start, vca(1));
    let s = k.snapshot();
    let m5 = s.world().m5();
    assert_eq!(m5.content_count(&fork), n(4));
    assert_eq!(m5.content_count(&pdoc()), n(3));
    assert_eq!(read_v(&s, &fork, 4), b"z".to_vec());
}

#[test]
fn cross_owner_version_mints_under_the_forkers_account() {
    // ASN-0123 P-tier: principal 2 (account [1,0,2]) forks doc1 — a fresh
    // document identity under ITS account, sharing doc1's content. doc1 is
    // principal 1's PRIVATE draft: another's draft the caller can read is
    // versioned as before (PUB-2.18; the source gate is lane 3.3's).
    let k = mem_kernel();
    let vs = insert_abc(&k);
    let (fork, _) = vs
        .version(PrincipalId(2), &doc1(), None)
        .expect("cross-owner fork commits");
    assert_eq!(fork, a(&[1, 0, 2, 0, 1]));
    let s = k.snapshot();
    let m5 = s.world().m5();
    assert_eq!(
        m5.content_runs(&fork).collect::<Vec<_>>(),
        m5.content_runs(&doc1()).collect::<Vec<_>>()
    );
    // The copy inherits the draft's private bit (PUB-8.17).
    assert!(!s.world().m3().published(&fork));
}

#[test]
fn a_parent_accounts_principal_versions_its_sub_accounts_document_across_ownership() {
    // ω is EXACT on `version`'s arm as on the write gates (ASN-0042
    // O2/O3/O8): the parent account [1,0,1] contains the sub-account's
    // document by prefix, but its principal is not that document's effective
    // owner, so its fork takes the CROSS-OWNER arm — a fresh document in its
    // own account, inheriting the source's private bit — and never the owned
    // arm, where a private source is refused `PrivateSourceVersionless`. Read
    // by containment, the arm would give that refusal. (M5 knows no read
    // rights, and this suite drives M5 directly: the source gate M10 runs
    // ahead of the store plays no part here.)
    let k = mem_kernel();
    let vs = Vstream::new(&k);
    let subdoc = a(&[1, 0, 1, 1, 0, 1]);
    vs.insert(
        Caller::Principal(PrincipalId(3)),
        &subdoc,
        vp(1, 1),
        vec![val(b"s")],
        Deposit::Undeclared,
    )
    .expect("the sub-account's principal edits its own draft");
    let (fork, _) = vs
        .version(PrincipalId(1), &subdoc, None)
        .expect("the parent's principal forks across ownership");
    let s = k.snapshot();
    let m3 = s.world().m3();
    assert!(
        m3.is_effective_owner(PrincipalId(1), &fork),
        "minted in the forker's own account"
    );
    assert!(!m3.published(&fork), "inheriting the private source's bit");
    assert_eq!(
        s.world().m5().content_runs(&fork).collect::<Vec<_>>(),
        s.world().m5().content_runs(&subdoc).collect::<Vec<_>>()
    );
    // The sub-account's own principal is on the owned arm, and its private
    // draft is versionless, as any owner's is.
    assert!(matches!(
        rejected(vs.version(PrincipalId(3), &subdoc, None)),
        VersionError::PrivateSourceVersionless
    ));
}

#[test]
fn version_of_an_empty_source_has_a_zero_content_footprint() {
    // ASN-0123 V1: n = 0 — the fork exists (registered) with an empty
    // arrangement and no provenance. The empty source is the published
    // edition, since a private one is versionless (PUB-2.9).
    let k = mem_kernel();
    let vs = Vstream::new(&k);
    let (fork, _) = vs
        .version(PrincipalId(1), &pdoc(), None)
        .expect("empty-source fork commits");
    assert_eq!(fork, vdoc());
    let s = k.snapshot();
    assert!(s.world().m3().is_registered_document(&fork));
    assert_eq!(s.world().m5().content_count(&fork), n(0));
    assert_eq!(s.world().m5().content_runs(&fork).len(), 0);
}

#[test]
fn a_version_born_empty_keeps_a_birth_extent_of_zero_through_its_first_deposit() {
    // BIRTH★ through `version`: an owned fork of a memberless edition mints
    // the birth version by snapshot, which notes its extent — zero, for an
    // empty edition. A deposit landing in the head afterwards notes nothing,
    // as no placement does, so the zero stands as the count grows. Asked as
    // a noted zero, it fails if the snapshot is skipped for an empty surface:
    // the version would then hold no birth at all.
    let k = mem_kernel();
    let vs = Vstream::new(&k);
    let (member, _) = vs
        .version(PrincipalId(1), &pdoc(), None)
        .expect("the birth version, of an empty edition");
    assert_eq!(member, vdoc(), "the chain's first member");
    vs.insert(P1, &pdoc(), vp(1, 1), vec![val(b"z")], declared())
        .expect("a deposit landing in the head the version minted");
    let s = k.snapshot();
    assert_eq!(s.world().m5().content_count(&member), n(1), "the head took the deposit");
    assert_eq!(
        s.world().m5().birth_extent(&member),
        Some(&n(0)),
        "born empty, whatever it took since"
    );
}

#[test]
fn nothing_a_version_mints_carries_shot_terms() {
    // `shot_terms` answers `None` for what no shot's record names — a member
    // an owned `version` minted among them — and the doc-metadata read serves
    // that answer: terms there tell a verifier a shot's entry signature covers
    // the first `placed` positions. Asked of all three things `version`
    // mints: a birth version of an EMPTY edition, a later member holding
    // content, and a cross-owner fork's fresh document. A `version` record
    // carrying terms — as the snapshot's explicit-runs form (Open decision
    // #4) would, written in the shot record's shape — answers here.
    let k = mem_kernel();
    let vs = Vstream::new(&k);
    let (birth, _) = vs
        .version(PrincipalId(1), &pdoc(), None)
        .expect("the birth version, of an empty edition");
    vs.insert(P1, &pdoc(), vp(1, 1), vec![val(b"z")], declared())
        .expect("a deposit landing in the head");
    let (later, _) = vs
        .version(PrincipalId(1), &pdoc(), None)
        .expect("a member sharing the head's one position");
    let (fork, _) = vs
        .version(PrincipalId(2), &pdoc(), None)
        .expect("a cross-owner fork");
    let s = k.snapshot();
    let m5 = s.world().m5();
    assert_eq!(
        m5.content_count(&later),
        n(1),
        "the premise: the later member holds content"
    );
    assert_eq!(
        m5.birth_extent(&birth),
        Some(&n(0)),
        "the premise: a noted birth version"
    );
    for minted in [&birth, &later, &fork] {
        assert_eq!(m5.shot_terms(minted), None, "{minted:?}: no shot minted it");
    }
}

#[test]
fn a_fork_is_as_empty_as_the_reading_surface_it_snapshots_not_the_address_named() {
    // ASN-0123 V1 under head-float: the fork is empty exactly when the
    // arrangement it snapshots — its source's READING SURFACE — is, whatever
    // the address named arranges. A bare edition whose own pre-chain
    // arrangement is empty forks its head's content (the state COPY, reading
    // the address named, refuses as `EmptySource`); one whose head is empty
    // forks nothing, however much its pre-chain arrangement holds.
    let k = mem_kernel();
    let vs = Vstream::new(&k);
    let (member1, _) = vs
        .version(PrincipalId(1), &pdoc(), None)
        .expect("an empty-source member");
    vs.insert(P1, &pdoc(), vp(1, 1), vec![val(b"z")], declared())
        .expect("lands in the head member1");
    let (member2, _) = vs.version(PrincipalId(1), &pdoc(), None).expect("forks the head");
    assert_eq!(member2, a(&[1, 0, 1, 0, 3, 2]));
    {
        let s = k.snapshot();
        let m5 = s.world().m5();
        assert_eq!(m5.content_count(&pdoc()), n(0), "the address named arranges nothing");
        assert_eq!(m5.content_count(&member2), n(1), "the fork holds its surface's one position");
        assert_eq!(
            m5.content_runs(&member2).collect::<Vec<_>>(),
            m5.content_runs(&member1).collect::<Vec<_>>()
        );
    }
    // The converse: content in the pre-chain arrangement, an empty head.
    let k = mem_kernel();
    let vs = deposit_abc(&k); // pdoc: a b c, memberless
    let (head, _) = vs
        .publish(
            P1,
            &pdoc(),
            &Shot { base: None, draft: None, runs: vec![] },
            &readable_by(PrincipalId(1)),
        )
        .expect("an empty birth version");
    let (fork, _) = vs.version(PrincipalId(1), &pdoc(), None).expect("forks the empty head");
    let s = k.snapshot();
    let m5 = s.world().m5();
    assert_eq!(m5.content_count(&pdoc()), n(3), "the address named arranges three positions");
    assert_eq!(m5.content_count(&head), n(0));
    assert_eq!(m5.content_count(&fork), n(0), "the fork is as empty as the head it snapshots");
    assert_eq!(m5.recorded_span_count(&fork), 0, "and R records nothing for it");
}

#[test]
fn version_rejects_unregistered_unknown_and_node_tier_callers() {
    let k = mem_kernel();
    let vs = insert_abc(&k);
    let unregistered_doc = a(&[1, 0, 1, 0, 9]);
    assert!(matches!(
        rejected(vs.version(PrincipalId(1), &unregistered_doc, None)),
        VersionError::SourceNotRegistered
    ));
    assert!(matches!(
        rejected(vs.version(PrincipalId(99), &doc1(), None)),
        VersionError::NotAPrincipal
    ));
    // Principal 0 is the bootstrap NODE-tier principal ([1], zeros = 0): a
    // cross-owner fork by it is outside VERSION's domain — rejected
    // explicitly, never as a downstream Mint(NotAnAccount).
    assert!(matches!(
        rejected(vs.version(PrincipalId(0), &doc1(), None)),
        VersionError::NodeTierCrossOwner
    ));
    // Which wins when both are bad: registration first, so a fork aimed at
    // an address naming no document discloses nothing about the forker — the
    // caller here is a principal the registry does not know, and the verdict
    // is still about the source.
    assert!(matches!(
        rejected(vs.version(PrincipalId(99), &unregistered_doc, None)),
        VersionError::SourceNotRegistered
    ));
}

#[test]
fn version_refuses_the_owners_private_source_whatever_the_flag() {
    // PUB-2.9 (the versionless sibling): a `version` on a PRIVATE source the
    // caller OWNS refuses, ONE code for all three flag values — the face
    // splits on the flag the caller sent, and that split is the daemon's.
    // Nothing commits, and the pool stays the private side's instrument
    // (PUB-2.19, PUB-2.20).
    let k = mem_kernel();
    let vs = insert_abc(&k);
    let before = k.current_seq();
    for flag in [None, Some(false), Some(true)] {
        assert!(
            matches!(
                rejected(vs.version(PrincipalId(1), &doc1(), flag)),
                VersionError::PrivateSourceVersionless
            ),
            "flag {flag:?}: a private owned source is versionless"
        );
    }
    // An EMPTY private draft is versionless too: the refusal is about the
    // source's state, not its content.
    assert!(matches!(
        rejected(vs.version(PrincipalId(1), &doc2(), None)),
        VersionError::PrivateSourceVersionless
    ));
    assert_eq!(k.current_seq(), before, "the refusal commits nothing");
    // The registration check stands ahead (PUB-6.37): an unregistered slot of
    // the chain answers registration, never a publication code.
    assert!(matches!(
        rejected(vs.version(PrincipalId(1), &a(&[1, 0, 1, 0, 9]), Some(false))),
        VersionError::SourceNotRegistered
    ));
}

#[test]
fn version_refuses_an_explicit_private_member_of_the_owners_published_source() {
    // PUB-2.7 / PUB-2.8: on a PUBLISHED source the caller owns, only the
    // explicit-PRIVATE arm refuses — absent inherits published and is legal,
    // and an explicit `true` is the same act spelled out. Each admitted call
    // appends the chain's next member (PUB-2.17), born published.
    let k = mem_kernel();
    let vs = deposit_abc(&k);
    let before = k.current_seq();
    assert!(matches!(
        rejected(vs.version(PrincipalId(1), &pdoc(), Some(false))),
        VersionError::PrivateVersionOfPublished
    ));
    assert_eq!(k.current_seq(), before, "the refusal commits nothing");
    let (member1, _) = vs
        .version(PrincipalId(1), &pdoc(), None)
        .expect("absent inherits published (PUB-2.8)");
    assert_eq!(member1, vdoc());
    let (member2, _) = vs
        .version(PrincipalId(1), &pdoc(), Some(true))
        .expect("an explicit true is admitted");
    assert_eq!(member2, a(&[1, 0, 1, 0, 3, 2]));
    let s = k.snapshot();
    assert!(s.world().m3().published(&member1));
    assert!(s.world().m3().published(&member2));
    // Every version address that exists names a PUBLISHED state (PUB-2.10):
    // a member the owner mints appends its own daughter chain (PUB-2.17), and
    // its private arm refuses exactly as the trunk's does.
    assert!(matches!(
        rejected(vs.version(PrincipalId(1), &member1, Some(false))),
        VersionError::PrivateVersionOfPublished
    ));
    let (daughter, _) = vs
        .version(PrincipalId(1), &member1, None)
        .expect("a member's daughter chain opens");
    assert_eq!(daughter, a(&[1, 0, 1, 0, 3, 1, 1]));
}

#[test]
fn the_cross_owner_arm_is_refused_by_neither_version_chain_rule() {
    // PUB-2.14 / PUB-2.18: where the caller does NOT own the source,
    // `version` mints a fresh document in the caller's own account off the
    // source default plus the flag, and neither refusal reads on it — the
    // entitled reader's PRIVATE working copy of published material (an
    // explicit `false`), the inherited copy (absent), and the fork of
    // another's draft all stand.
    let k = mem_kernel();
    let vs = deposit_abc(&k);
    insert_abc(&k);
    let (private_copy, _) = vs
        .version(PrincipalId(2), &pdoc(), Some(false))
        .expect("a private working copy of a published document");
    assert_eq!(private_copy, a(&[1, 0, 2, 0, 1]));
    let (inherited, _) = vs
        .version(PrincipalId(2), &pdoc(), None)
        .expect("the inherited copy");
    assert_eq!(inherited, a(&[1, 0, 2, 0, 2]));
    let (of_draft, _) = vs
        .version(PrincipalId(2), &doc1(), None)
        .expect("a fork of another's draft");
    assert_eq!(of_draft, a(&[1, 0, 2, 0, 3]));
    let s = k.snapshot();
    let m3 = s.world().m3();
    assert!(!m3.published(&private_copy), "the explicit false is the copy's bit");
    assert!(m3.published(&inherited), "absent inherits the source's published state");
    assert!(!m3.published(&of_draft), "absent inherits the draft's private state");
    // Each is a DOCUMENT of the forker's account, never a member of the
    // source's chain: the source's own chain is still empty.
    assert!(!m3.is_registered_document(&vdoc()));
    let m5 = s.world().m5();
    assert_eq!(
        m5.content_runs(&private_copy).collect::<Vec<_>>(),
        m5.content_runs(&pdoc()).collect::<Vec<_>>()
    );
    assert_eq!(
        m5.content_runs(&of_draft).collect::<Vec<_>>(),
        m5.content_runs(&doc1()).collect::<Vec<_>>()
    );
}

#[test]
fn version_judges_a_member_source_as_its_document() {
    // PUB-2.15 on `version`'s source: a member projects to its DOCUMENT
    // before the read. The fixture stamps each member with the bit its
    // document does NOT carry, so a read of the member's own bit would
    // answer the opposite of what these assert.
    let k = mem_kernel_of(genesis_with_members());
    let vs = Vstream::new(&k);
    // A member of the PUBLISHED pdoc, journaled private: versionable, and
    // the daughter it opens is published-born.
    let member_of_edition = a(&[1, 0, 1, 0, 3, 1]);
    let (daughter, _) = vs
        .version(PrincipalId(1), &member_of_edition, None)
        .expect("a member of a published document is versioned as its document");
    assert_eq!(daughter, a(&[1, 0, 1, 0, 3, 1, 1]));
    assert!(k.snapshot().world().m3().published(&daughter));
    // A member of the PRIVATE doc1, journaled published: versionless, as its
    // document is.
    assert!(matches!(
        rejected(vs.version(PrincipalId(1), &a(&[1, 0, 1, 0, 1, 1]), None)),
        VersionError::PrivateSourceVersionless
    ));
}
