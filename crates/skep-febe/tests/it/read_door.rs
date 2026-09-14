//! THE READ PATH'S use of the one predicate, pinned at the engine-free seam
//! `common`'s readability fixture gives it (PUB round 2, lane 3.3; PUB-6.1,
//! PUB-6.4, PUB-6.6, PUB-6.8, PUB-6.12, PUB-6.13, PUB-8.46).
//!
//! Six claims, all of them disclosure claims, and each a separate rule:
//!
//! 1. the DOC-ARGUMENT CONSULT — the first unreadable NAMED document of a
//!    read answers WITHHELD naming itself, ahead of every other validation;
//! 2. the LINK-ADDRESS ABSENCE RULE — a link homed in an unreadable document
//!    reads as `⊥`, exactly as a never-deposited address, never as ⟨⟩ and
//!    never as a refusal that would confirm the link exists;
//! 3. the RESULT-SET FILTER — a read whose arguments are all readable still
//!    drops each RESULT the caller may not read, at its identity;
//! 4. the WITHHELD ITEM — a delivery masks per RUN, in place, so an
//!    unreadable origin costs its positions and not its neighbours';
//! 5. the GUEST — a session resolving to no principal is MASKED, not gated;
//! 6. beneath all five, WHICH PREDICATE ANSWERS — the world's own where a
//!    front door supplies none, the supplied one OVERRIDING it where it does.
//!
//! The write path's use of the same predicate is `write_door.rs`.
//!
//! Three words, three concepts, each the corpus's: a DOCUMENT is unreadable
//! (PUB-6.1), a REQUEST is refused, an ANSWER is withheld.

use crate::common;

use common::*;
use skep_febe::{
    enc, Address, DeliveryItem, EditionClaim, FourSet, Op, OpKind, RegionSpec, RejectCode,
    Response, SlotArg, SlotSpec, Span, SpanSet, Spec, Tumbler, View, FROM, TO,
};

/// One link whose endsets cover `covered`'s content, homed in `home` — the
/// shape both the absence rule and the result-set filter turn on, since the
/// coverage decides which region index it stabs and the HOME decides who may
/// see it.
fn link_over(fx: &Fixture, home: &Address, covered: &Address) -> Address {
    ack_addr(ex(
        &fx.febe,
        fx.user,
        Op::MakeLink {
            home: home.clone(),
            from: SlotArg::Resolve(vec![vspec(covered, 1, 1)]), // populated
            to: SlotArg::Addrs(vec![]),                         // ⟨⟩
            ty: SlotArg::Resolve(vec![vspec(covered, 3, 1)]),
        },
    ))
    .0
}

/// The readability fixture's link pair. Four same-typed addresses, NAMED
/// rather than positional: a tuple of four `Address`es is the swap this file
/// would not notice.
struct LinkPair {
    /// The readable document both links' endsets cover, and `readable_l`'s home.
    readable_doc: Address,
    /// The home the stranger may not read — `unreadable_l`'s.
    unreadable_doc: Address,
    /// Homed in `unreadable_doc`: the link only the home rule removes.
    unreadable_l: Address,
    /// Homed in `readable_doc`: the link that survives every filter.
    readable_l: Address,
}

/// Two links over ONE readable document's content, distinguished by nothing
/// but their HOME, so only the result-set filter (PUB-6.13) can tell them
/// apart — the query, the census, the window, the lineage probe and the
/// orphan preview all reach both.
///
/// The unreadable home is created FIRST, so `unreadable_l` sorts BEFORE
/// `readable_l`: a link is minted in its home's link subspace, so the homes'
/// address order is the links'. That is what lets a window of one distinguish
/// a rule applied before the slice from one applied after (PUB-6.14) — and
/// the fixture asserts its own premise rather than depending on it silently.
fn two_links_over_one_document(fx: &Fixture, unreadable: &Unreadable) -> LinkPair {
    let unreadable_doc = create_doc(fx);
    let readable_doc = create_doc(fx);
    insert3(fx, &readable_doc);
    let unreadable_l = link_over(fx, &unreadable_doc, &readable_doc);
    let readable_l = link_over(fx, &readable_doc, &readable_doc);
    assert!(unreadable_l < readable_l, "the unreadable home's link must sort first");
    unreadable.lock().expect("no poisoning").push(unreadable_doc.clone());
    LinkPair { readable_doc, unreadable_doc, unreadable_l, readable_l }
}

// ────────────────────── 1. the doc-argument consult ─────────────────────────

/// PUB-6.12 / PUB-6.4: the FIRST unreadable NAMED document of a read, in
/// declaration order, answers WITHHELD naming itself — `reorder`, `site.addr`
/// that document, no `detail` — and the OWNER, for whom the same documents
/// are readable, is answered. Across an op's lists in declaration order, and
/// within a list by index.
#[test]
fn a_read_is_withheld_naming_its_first_unreadable_document() {
    let (fx, unreadable) = setup_with_unreadable();
    let d1 = create_doc(&fx);
    insert3(&fx, &d1);
    let d2 = create_doc(&fx);
    insert3(&fx, &d2);
    unreadable.lock().expect("no poisoning").extend([d1.clone(), d2.clone()]);
    let other = fx.febe.open_session(OTHER);
    let first_span = || vspan(1, 1, 1);

    // (op, the document the answer must name)
    let cases: Vec<(Op, &Address)> = vec![
        (Op::RetrieveDocVSpan { doc: d1.clone() }, &d1),
        (Op::RetrieveDocVSpanSet { doc: d1.clone() }, &d1),
        (Op::ShowOrigin { doc: d1.clone(), span: first_span() }, &d1),
        // Two named documents: the first DECLARED one speaks, either way round.
        (Op::ShowDeletions { d_a: d1.clone(), d_b: d2.clone() }, &d1),
        (Op::ShowDeletions { d_a: d2.clone(), d_b: d1.clone() }, &d2),
        // Across an op's lists: rho1's regions before rho2's.
        (
            Op::Compare {
                rho1: vec![RegionSpec { doc: d2.clone(), spans: vec![first_span()] }],
                rho2: vec![RegionSpec { doc: d1.clone(), spans: vec![first_span()] }],
            },
            &d2,
        ),
        // Within a list, by index.
        (
            Op::RetrieveV {
                specs: vec![
                    Spec { doc: d2.clone(), span: first_span() },
                    Spec { doc: d1.clone(), span: first_span() },
                ],
            },
            &d2,
        ),
        (
            Op::FindDocsContaining {
                regions: vec![
                    RegionSpec { doc: d2.clone(), spans: vec![first_span()] },
                    RegionSpec { doc: d1.clone(), spans: vec![first_span()] },
                ],
            },
            &d2,
        ),
        // The region family's `d`.
        (Op::Image { d: d1.clone(), region: vec![first_span()] }, &d1),
        (Op::FindLinksV { d: d1.clone(), region: vec![first_span()] }, &d1),
        (Op::CountV { d: d1.clone(), region: vec![first_span()] }, &d1),
        (Op::WindowV { d: d1.clone(), region: vec![first_span()], cur: None, n: 1 }, &d1),
        (Op::RetrieveEndsets { d: d1.clone(), region: vec![first_span()] }, &d1),
        (Op::DeleteOrphans { d: d1.clone(), p: vp(1, 1), width: nat(1) }, &d1),
        // The two publication reads: the H1 row (PUB-8.12, PUB-8.46).
        (Op::DocMetadata { doc: d1.clone() }, &d1),
        (Op::EditionClaims { target: d2.clone() }, &d2),
    ];
    for (op, named) in cases {
        let kind = op.kind();
        assert_withheld(ex(&fx.febe, other, op), kind, named);
    }

    // The consult is per principal: the owner reads its own documents.
    let (set, _) = spanset(ex(&fx.febe, fx.user, Op::RetrieveDocVSpan { doc: d1 }));
    assert_ne!(set, SpanSet::empty());
}

/// PUB-6.12's ORDER: the consult runs before any other validation, so a
/// private document never reaches a refusal that would describe it. The OWNER
/// meets the span fault — which is what proves the fixture's span really is
/// faulty — and the stranger meets the consult instead.
#[test]
fn the_doc_argument_consult_speaks_before_any_other_validation() {
    let (fx, unreadable) = setup_with_unreadable();
    let d = create_doc(&fx);
    insert3(&fx, &d);
    unreadable.lock().expect("no poisoning").push(d.clone());
    let other = fx.febe.open_session(OTHER);
    // Too shallow to be a V-span (#start ≥ 2): M6 faults it.
    let shallow = || {
        Span::new(
            Tumbler::new([nat(5)]).expect("nonempty"),
            Tumbler::new([nat(1)]).expect("nonempty"),
        )
        .expect("a well-formed span")
    };

    let rej = rejected(ex(
        &fx.febe,
        fx.user,
        Op::RetrieveV { specs: vec![Spec { doc: d.clone(), span: shallow() }] },
    ));
    assert_eq!(rej.code, RejectCode::MalformedSpan, "the fixture's span is genuinely faulty");

    assert_withheld(
        ex(
            &fx.febe,
            other,
            Op::RetrieveV { specs: vec![Spec { doc: d.clone(), span: shallow() }] },
        ),
        OpKind::RetrieveV,
        &d,
    );
}

/// PUB-6.8, the dual row: `project` and `discoverable_from` name the DOCUMENT
/// `d`, never the link `a`. An unreadable `d` is withheld naming `d`; a link
/// homed in an unreadable document takes M8's own ABSENCE answer — `NotALink`
/// and `false`, exactly as an address naming no link — and never a withheld,
/// which would confirm the link exists.
#[test]
fn the_dual_row_consults_the_document_and_never_the_link() {
    let (fx, unreadable) = setup_with_unreadable();
    let home = create_doc(&fx);
    insert3(&fx, &home);
    let link = link_over(&fx, &home, &home);
    let target = create_doc(&fx);
    insert3(&fx, &target);
    unreadable.lock().expect("no poisoning").push(target.clone());
    let other = fx.febe.open_session(OTHER);

    assert_withheld(
        ex(&fx.febe, other, Op::Project { a: link.clone(), slot: FROM, d: target.clone() }),
        OpKind::Project,
        &target,
    );
    assert_withheld(
        ex(&fx.febe, other, Op::DiscoverableFrom { a: link.clone(), d: target.clone() }),
        OpKind::DiscoverableFrom,
        &target,
    );

    // The LINK's home unreadable, `d` readable: the link is ABSENT to this
    // caller (PUB-6.6) — `project` answers `NotALink`, exactly as an address
    // naming no link, and `discoverable_from` answers `false`, the retracted
    // link's answer. Never a WITHHELD, which would confirm the link is there.
    // The link covers `d`'s OWN content, so a door that stopped threading the
    // predicate would hand this caller the very positions of a document it may
    // read that a link it may not see points at.
    let d = create_doc(&fx);
    insert3(&fx, &d);
    let over_d = link_over(&fx, &home, &d);
    // The owner's answers first, so the stranger's below are the absence rule
    // and not an empty world.
    let (mine, _) =
        spanset(ex(&fx.febe, fx.user, Op::Project { a: over_d.clone(), slot: FROM, d: d.clone() }));
    assert_ne!(mine, SpanSet::empty(), "the link really does project into `d`");
    assert!(bool_val(ex(&fx.febe, fx.user, Op::DiscoverableFrom { a: over_d.clone(), d: d.clone() })));

    unreadable.lock().expect("no poisoning").push(home);

    let rej =
        rejected(ex(&fx.febe, other, Op::Project { a: over_d.clone(), slot: FROM, d: d.clone() }));
    assert_eq!(
        rej.code,
        RejectCode::NotALink,
        "absent, exactly as an address naming no link: {rej}"
    );
    assert!(!bool_val(ex(&fx.febe, other, Op::DiscoverableFrom { a: over_d, d })));
}

/// PUB-6.12: a read that names no DOCUMENT has nothing to withhold — the FTT
/// descriptor family (a `home` constraint is not a named document), the raw
/// link reads (link-address ABSENCE, PUB-6.6), the lineage probes (probe keys)
/// and the two namespace reads. Every document in this world is unreadable to
/// this caller and each of the nine is still answered.
#[test]
fn a_read_naming_no_document_is_never_withheld() {
    let (fx, unreadable) = setup_with_unreadable();
    let d = create_doc(&fx);
    insert3(&fx, &d);
    let link = link_over(&fx, &d, &d);
    unreadable.lock().expect("no poisoning").push(d.clone());
    let other = fx.febe.open_session(OTHER);
    let q = || FourSet {
        home: SlotSpec::Spans(enc([&d])),
        from: SlotSpec::Any,
        to: SlotSpec::Any,
        ty: SlotSpec::Any,
    };

    for op in vec![
        Op::FindLinksFtt { q: q() },
        Op::CountFtt { q: q() },
        Op::WindowFtt { q: q(), cur: None, n: 1 },
        Op::ReadLink { a: link.clone() },
        Op::FollowLink { a: link.clone(), slot: FROM },
        Op::InClaims { y: link.clone(), view: View::Active },
        Op::OutClaims { x: link, view: View::Active },
        Op::NextAccountPrefix { parent: node1() },
        Op::PrincipalPrefix { id: USER },
    ] {
        let kind = op.kind();
        if let Response::Rejected(rej) = ex(&fx.febe, other, op) {
            assert_ne!(rej.code, RejectCode::Withheld, "{kind:?} names no document to withhold");
        }
    }
}

// ───────────────────── 2. the link-address absence rule ─────────────────────

/// PUB-6.6 on the READ side, the twin of the write door's rule: a link homed
/// in a document the caller may not read reads as `⊥` — `None` from READLINK,
/// `Err(Invalid)` from FOLLOWLINK — exactly as a never-deposited address, and
/// never ⟨⟩, which is a PRESENT link's empty slot and an ANSWER. The absence
/// is an answer too, never a rejection that would confirm the link exists.
#[test]
fn a_link_homed_in_an_unreadable_document_reads_as_absent() {
    let (fx, unreadable) = setup_with_unreadable();
    let home = create_doc(&fx);
    insert3(&fx, &home);
    let link = link_over(&fx, &home, &home);
    let other = fx.febe.open_session(OTHER);

    // Readable home: a value, a populated slot, and an EMPTY slot that is an
    // answer rather than an absence.
    assert!(link_value(ex(&fx.febe, other, Op::ReadLink { a: link.clone() })).is_some());
    assert_ne!(
        follow(ex(&fx.febe, other, Op::FollowLink { a: link.clone(), slot: FROM }))
            .expect("a present link's populated slot"),
        SpanSet::empty()
    );
    assert_eq!(
        follow(ex(&fx.febe, other, Op::FollowLink { a: link.clone(), slot: TO }))
            .expect("⟨⟩ is an ANSWER: a present link's empty slot"),
        SpanSet::empty()
    );

    unreadable.lock().expect("no poisoning").push(home);

    assert!(
        link_value(ex(&fx.febe, other, Op::ReadLink { a: link.clone() })).is_none(),
        "a link homed in an unreadable document reads as ⊥, never as its value"
    );
    assert!(
        follow(ex(&fx.febe, other, Op::FollowLink { a: link.clone(), slot: TO })).is_err(),
        "⊥, never ⟨⟩: an unreadable home is an absence, not an empty slot"
    );
    assert!(
        follow(ex(&fx.febe, other, Op::FollowLink { a: link.clone(), slot: FROM })).is_err(),
        "the populated slot is absent too — the whole link is ⊥"
    );
    assert!(
        matches!(
            ex(&fx.febe, other, Op::ReadLink { a: link.clone() }),
            Response::LinkValue { .. }
        ),
        "absence is an ANSWER, not a rejection"
    );

    // The owner still reads it: the rule is per principal.
    assert!(link_value(ex(&fx.febe, fx.user, Op::ReadLink { a: link })).is_some());
}

// ────────────────────────── 3. the result-set filter ────────────────────────

/// PUB-6.13, the RESULT-SET rule — which is not the consult: a read whose
/// named arguments are all readable still drops each RESULT whose HOME the
/// caller cannot read. A link homed in an unreadable draft covers the readable
/// document's content, so it stabs the region index either way; only the filter
/// removes it.
#[test]
fn link_discovery_drops_links_homed_where_the_caller_cannot_read() {
    let (fx, unreadable) = setup_with_unreadable();
    let LinkPair { readable_doc, unreadable_l, readable_l, .. } =
        two_links_over_one_document(&fx, &unreadable);
    let other = fx.febe.open_session(OTHER);
    let region = || vec![vspan(1, 1, 3)];

    let mine = addrs(ex(&fx.febe, fx.user, Op::FindLinksV { d: readable_doc.clone(), region: region() }));
    assert!(mine.contains(&unreadable_l) && mine.contains(&readable_l), "the owner reads both homes");
    let theirs = addrs(ex(&fx.febe, other, Op::FindLinksV { d: readable_doc.clone(), region: region() }));
    assert!(theirs.contains(&readable_l), "a link homed where the caller reads survives");
    assert!(!theirs.contains(&unreadable_l), "a link homed in an unreadable document is dropped");

    // The census counts what the caller may see, by the same rule.
    assert_eq!(count(ex(&fx.febe, fx.user, Op::CountV { d: readable_doc.clone(), region: region() })), 2);
    assert_eq!(count(ex(&fx.febe, other, Op::CountV { d: readable_doc.clone(), region: region() })), 1);

    // The window applies the rule BEFORE its slice (PUB-6.14), so a window of
    // one returns the link this caller may see rather than an empty batch.
    let w = page(ex(
        &fx.febe,
        other,
        Op::WindowV { d: readable_doc, region: region(), cur: None, n: 1 },
    ));
    assert_eq!(w.batch, vec![readable_l]);
}

/// PUB-6.13 on the reads that name NO document: the descriptor's `home` slot
/// is a coverage constraint and not a doc-argument (PUB-6.12), so the consult
/// never fires and the result-set filter is the ONLY thing between a caller
/// and every link in the store. All three read-outs are filtered, the census
/// counts the set the enumeration returns, and the window skips a refused link
/// rather than counting it against `n`.
#[test]
fn the_descriptor_family_drops_links_homed_where_the_caller_cannot_read() {
    let (fx, unreadable) = setup_with_unreadable();
    let LinkPair { readable_doc, unreadable_l, readable_l, .. } =
        two_links_over_one_document(&fx, &unreadable);
    let other = fx.febe.open_session(OTHER);
    let q = || FourSet { from: SlotSpec::Spans(enc([&readable_doc])), ..FourSet::any() };

    let mine = addrs(ex(&fx.febe, fx.user, Op::FindLinksFtt { q: q() }));
    assert!(mine.contains(&unreadable_l) && mine.contains(&readable_l), "the owner reads both homes");
    let theirs = addrs(ex(&fx.febe, other, Op::FindLinksFtt { q: q() }));
    assert_eq!(theirs, vec![readable_l.clone()], "only the link homed where the caller reads");

    assert_eq!(count(ex(&fx.febe, fx.user, Op::CountFtt { q: q() })), mine.len());
    assert_eq!(
        count(ex(&fx.febe, other, Op::CountFtt { q: q() })),
        theirs.len(),
        "the census counts the set the enumeration returns"
    );

    let w = page(ex(&fx.febe, other, Op::WindowFtt { q: q(), cur: None, n: 1 }));
    assert_eq!(
        w.batch,
        vec![readable_l],
        "the link homed where the caller cannot read is skipped, not counted against n"
    );
}

/// PUB-6.12 and PUB-6.13 in one read, on BOTH lineage probes: each CLAIM is
/// dropped at its own home, while the probe KEY takes no rule — every key
/// below is itself homed where this caller cannot read, and every probe is
/// still ANSWERED. So a stranger probing a link it may not see learns the
/// claims living in documents it may read, and none of the others.
#[test]
fn supersession_claims_are_dropped_at_their_home_while_the_probe_key_takes_no_rule() {
    let (fx, unreadable) = setup_with_unreadable();
    let LinkPair { readable_doc, unreadable_doc, unreadable_l, readable_l } =
        two_links_over_one_document(&fx, &unreadable);
    // A third link in the unreadable home, so BOTH probe keys below are homed
    // where the stranger cannot read — the KEY half of the claim, in each
    // direction rather than one.
    let third = link_over(&fx, &unreadable_doc, &readable_doc);
    let sup = |home: &Address, old: &Address, new: &Address| {
        ack_addr(ex(
            &fx.febe,
            fx.user,
            Op::AssertSup { home: home.clone(), old: old.clone(), new: new.clone() },
        ))
        .0
    };
    // THREE DISTINCT `(old, new)` PAIRS, because a `[K_sup]` claim dedups on
    // its VALUE across every home the writer can read: two homes asserting one
    // pair are one claim, so a per-home pair is what makes these three claims.
    // The readable one names both probe keys; each of the other two shares one
    // key with it and lives where the stranger cannot read.
    let readable_claim = sup(&readable_doc, &unreadable_l, &third);
    let (by_old, by_new) =
        (sup(&unreadable_doc, &unreadable_l, &readable_l), sup(&unreadable_doc, &readable_l, &third));
    let other = fx.febe.open_session(OTHER);

    for (op, unreadable_claim) in [
        (Op::InClaims { y: unreadable_l, view: View::Active }, by_old),
        (Op::OutClaims { x: third, view: View::Active }, by_new),
    ] {
        let kind = op.kind();
        let mine: Vec<Address> =
            claims(ex(&fx.febe, fx.user, op.clone())).into_iter().map(|c| c.claim).collect();
        assert_eq!(mine.len(), 2, "{kind:?}: the owner reads both homes");
        assert!(mine.contains(&readable_claim) && mine.contains(&unreadable_claim));
        let theirs: Vec<Address> =
            claims(ex(&fx.febe, other, op)).into_iter().map(|c| c.claim).collect();
        assert_eq!(
            theirs,
            vec![readable_claim.clone()],
            "{kind:?}: the claim homed where the caller cannot read is dropped — and the probe \
             was answered, its own key being homed there too"
        );
    }
}

/// PUB-6.13 on the survival preview: the orphaned set drops every link whose
/// HOME the caller may not read, at link identity — so a stranger previewing a
/// delete in a document it CAN read is not handed the addresses of links
/// living in documents it cannot. The whole of the readable document's content
/// goes, so both links lose their last witness and what is left is the home
/// rule's alone.
#[test]
fn the_orphan_preview_drops_links_homed_where_the_caller_cannot_read() {
    let (fx, unreadable) = setup_with_unreadable();
    let LinkPair { readable_doc, unreadable_l, readable_l, .. } =
        two_links_over_one_document(&fx, &unreadable);
    let other = fx.febe.open_session(OTHER);
    let whole = || Op::DeleteOrphans { d: readable_doc.clone(), p: vp(1, 1), width: nat(3) };

    let mine = orphans(ex(&fx.febe, fx.user, whole())).orphaned;
    assert!(mine.contains(&unreadable_l) && mine.contains(&readable_l), "both lose their last witness");
    let theirs = orphans(ex(&fx.febe, other, whole())).orphaned;
    assert_eq!(theirs, vec![readable_l], "the link homed where the caller cannot read is dropped");
}

/// PUB-6.13 on the container family: FINDDOCSCONTAINING drops a container the
/// caller cannot read, at its identity. Both documents hold the same element —
/// one allocated it, the other transcludes it — so only the filter
/// distinguishes them.
#[test]
fn find_docs_containing_drops_a_container_the_caller_cannot_read() {
    let (fx, unreadable) = setup_with_unreadable();
    let readable_doc = create_doc(&fx);
    insert3(&fx, &readable_doc);
    let unreadable_doc = create_doc(&fx);
    ack(ex(
        &fx.febe,
        fx.user,
        Op::Copy { doc: unreadable_doc.clone(), at: vp(1, 1), specs: vec![vspec(&readable_doc, 1, 1)] },
    ));
    unreadable.lock().expect("no poisoning").push(unreadable_doc.clone());
    let other = fx.febe.open_session(OTHER);
    let region = || vec![RegionSpec { doc: readable_doc.clone(), spans: vec![vspan(1, 1, 1)] }];

    let mine = addrs(ex(&fx.febe, fx.user, Op::FindDocsContaining { regions: region() }));
    assert!(mine.contains(&readable_doc) && mine.contains(&unreadable_doc), "the owner sees both containers");
    let theirs = addrs(ex(&fx.febe, other, Op::FindDocsContaining { regions: region() }));
    assert!(theirs.contains(&readable_doc));
    assert!(!theirs.contains(&unreadable_doc), "an unreadable container is dropped at its identity");
}

/// PUB-8.46 / PUB-6.13: the world answers the CLASS unfiltered, in
/// link-address order, and the DOOR keeps only the rows whose HOME the caller
/// can read — so a draft edition's claim is invisible to a stranger and listed
/// for its owner. The dropped row sits BETWEEN the two survivors, so the order
/// is a claim the answer can break: with one survivor every order is the right
/// one. The seeded rows stand for claims; nothing here asserts they are links.
#[test]
fn an_edition_claim_homed_where_the_caller_cannot_read_is_dropped() {
    let (fx, unreadable) = setup_with_unreadable();
    let target = create_doc(&fx);
    let first_home = create_doc(&fx);
    let unreadable_home = create_doc(&fx);
    let second_home = create_doc(&fx);
    unreadable.lock().expect("no poisoning").push(unreadable_home.clone());
    let row = |home: &Address| EditionClaim {
        claim: home.clone(),
        home: home.clone(),
        to: enc([&target]),
        active: true,
    };
    seed_edition_claims(vec![row(&first_home), row(&unreadable_home), row(&second_home)]);
    let other = fx.febe.open_session(OTHER);

    let mine = edition_claims(ex(&fx.febe, fx.user, Op::EditionClaims { target: target.clone() }));
    assert_eq!(mine.len(), 3, "the owner reads every home, so every row is listed");
    let theirs = edition_claims(ex(&fx.febe, other, Op::EditionClaims { target }));
    assert_eq!(
        theirs.iter().map(|c| c.home.clone()).collect::<Vec<_>>(),
        vec![first_home, second_home],
        "the filter drops rows between survivors and never reorders them"
    );
}

// ───────────────────────── 4. the withheld item ─────────────────────────────

/// PUB-6.41: a delivery is masked per RUN, IN PLACE. A document the caller
/// may read, holding one transcluded run from a document it may not, answers
/// a `Withheld` item naming that ORIGIN at the run's own position — neither
/// dropped from the delivery nor raised as a rejection — with the readable
/// content on either side of it intact. So positions are preserved, one
/// unreadable origin costs its own positions and not its neighbours', and a
/// caller must handle the arm.
#[test]
fn a_delivery_masks_an_unreadable_origin_in_place() {
    let (fx, unreadable) = setup_with_unreadable();
    let readable_doc = create_doc(&fx);
    insert3(&fx, &readable_doc);
    let unreadable_origin = create_doc(&fx);
    insert3(&fx, &unreadable_origin);
    // One of the unreadable origin's positions transcluded into the MIDDLE of
    // the readable document, so "at its own position" is a claim with
    // neighbours on both sides: the readable document's V-order becomes
    // [readable#1, origin#1, readable#2, readable#3].
    ack(ex(
        &fx.febe,
        fx.user,
        Op::Copy { doc: readable_doc.clone(), at: vp(1, 2), specs: vec![vspec(&unreadable_origin, 1, 1)] },
    ));
    unreadable.lock().expect("no poisoning").push(unreadable_origin.clone());
    let other = fx.febe.open_session(OTHER);
    let whole = || Op::RetrieveV { specs: vec![Spec { doc: readable_doc.clone(), span: vspan(1, 1, 4) }] };

    // The owner reads both origins: four positions, nothing withheld.
    let (mine, _) = delivery(ex(&fx.febe, fx.user, whole()));
    assert_eq!(mine.len(), 4);
    assert!(
        mine.iter().all(|i| matches!(i, DeliveryItem::Content(_))),
        "the owner's delivery masks nothing: {mine:?}"
    );

    // The stranger reads the document and not the transcluded run's origin:
    // same length, same positions, one item replaced by the withheld arm.
    let (theirs, _) = delivery(ex(&fx.febe, other, whole()));
    assert_eq!(theirs.len(), 4, "a masked run is emitted, not dropped: {theirs:?}");
    match &theirs.as_slice()[1] {
        DeliveryItem::Withheld { origin, width } => {
            assert_eq!(origin, &unreadable_origin, "the withheld item names the run's ORIGIN document");
            assert_eq!(width, &nat(1), "…and the positions it stands for");
        }
        other => panic!("expected the transcluded run to be withheld at its own position: {other:?}"),
    }
    for (i, item) in theirs.iter().enumerate().filter(|(i, _)| *i != 1) {
        assert!(
            matches!(item, DeliveryItem::Content(_)),
            "position {i} is `readable_doc`'s own content and survives: {item:?}"
        );
    }
}

// ───────────────────────────────── 5. the guest ─────────────────────────────

/// §2/§6: a read resolves the session to an `Option<PrincipalId>` for the
/// PREDICATE, so a retired id is answered as the GUEST — masked, not gated.
/// The same read that answers while bound is WITHHELD after logout, and the
/// WRITE on that id is what is refused. Logout narrows the read surface; it
/// does not close it.
#[test]
fn a_retired_session_reads_as_the_guest_while_its_writes_are_refused() {
    let (fx, unreadable) = setup_with_unreadable();
    let d = create_doc(&fx);
    insert3(&fx, &d);
    unreadable.lock().expect("no poisoning").push(d.clone());

    let (set, _) = spanset(ex(&fx.febe, fx.user, Op::RetrieveDocVSpan { doc: d.clone() }));
    assert_ne!(set, SpanSet::empty(), "bound, and the owner: answered");

    fx.febe.close_session(fx.user);
    assert_withheld(
        ex(&fx.febe, fx.user, Op::RetrieveDocVSpan { doc: d.clone() }),
        OpKind::RetrieveDocVSpan,
        &d,
    );
    // A read naming no document is still ANSWERED on the retired id: the
    // masking is the predicate's, and the session gate is not a read's.
    let (prefix, _) = maybe_addr(ex(&fx.febe, fx.user, Op::PrincipalPrefix { id: USER }));
    assert!(prefix.is_some(), "logout narrows the read surface, it does not close it");

    let rej = rejected(ex(&fx.febe, fx.user, Op::Delete { doc: d, p: vp(1, 1), width: nat(1) }));
    assert_eq!(rej.code, RejectCode::Unauthenticated, "a write is gated where a read is masked");
}

// ──────────── 6. which predicate answers — the fork beneath all five ────────

/// The default front door — `OperationSurface::new` with no predicate
/// supplied, the LIVE DAEMON's configuration — answers the WORLD's own
/// `ReadableWorld::readable`. Every other test in this file supplies a
/// predicate, so this is the arm no other door test takes: a front door that
/// stopped consulting the world would serve every private draft to every
/// caller with the rest of this file green.
#[test]
fn the_worlds_own_predicate_masks_when_none_is_supplied() {
    let fx = setup(); // NO supplied predicate
    let d = create_doc(&fx);
    insert3(&fx, &d);
    seed_unreadable_world(vec![d.clone()]);
    let other = fx.febe.open_session(OTHER);

    let (set, _) = spanset(ex(&fx.febe, fx.user, Op::RetrieveDocVSpan { doc: d.clone() }));
    assert_ne!(set, SpanSet::empty(), "the owner reads its own document");
    assert_withheld(
        ex(&fx.febe, other, Op::RetrieveDocVSpan { doc: d.clone() }),
        OpKind::RetrieveDocVSpan,
        &d,
    );
}

/// …and a SUPPLIED predicate OVERRIDES that world rather than narrowing it
/// (`with_read_predicate`): the historical door supplies the HEAD's predicate
/// precisely because the world it reconstructs would answer differently
/// (PUB-6.48), so a door that conjoined the two would withhold exactly what
/// `/op-at N` exists to disclose.
#[test]
fn a_supplied_predicate_overrides_the_world_rather_than_narrowing_it() {
    let (fx, unreadable) = setup_with_unreadable(); // the SUPPLIED arm
    let d = create_doc(&fx);
    insert3(&fx, &d);
    // The world refuses this document to the stranger; the supplied predicate
    // admits it — its own list stays empty.
    seed_unreadable_world(vec![d.clone()]);
    assert!(unreadable.lock().expect("no poisoning").is_empty());
    let other = fx.febe.open_session(OTHER);

    let (set, _) = spanset(ex(&fx.febe, other, Op::RetrieveDocVSpan { doc: d }));
    assert_ne!(set, SpanSet::empty(), "the supplied predicate is the whole answer");
}
