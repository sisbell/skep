//! THE READ PATH'S use of the one predicate, pinned at the engine-free seam
//! `common`'s readability fixture gives it (PUB round 2, lane 3.3; PUB-6.1,
//! PUB-6.4, PUB-6.6, PUB-6.8, PUB-6.12, PUB-6.13, PUB-8.46).
//!
//! Four claims, all of them disclosure claims, and each a separate rule:
//!
//! 1. the DOC-ARGUMENT CONSULT — the first unreadable NAMED document of a
//!    read answers WITHHELD naming itself, ahead of every other validation;
//! 2. the LINK-ADDRESS ABSENCE RULE — a link homed in an unreadable document
//!    reads as `⊥`, exactly as a never-deposited address, never as ⟨⟩ and
//!    never as a refusal that would confirm the link exists;
//! 3. the RESULT-SET FILTER — a read whose arguments are all readable still
//!    drops each RESULT the caller may not read, at its identity;
//! 4. the GUEST — a session resolving to no principal is MASKED, not gated.
//!
//! The write path's use of the same predicate is `source_gate.rs`.
//!
//! Three words, three concepts, each the corpus's: a DOCUMENT is unreadable
//! (PUB-6.1), a REQUEST is refused, an ANSWER is withheld.

use crate::common;

use common::*;
use skep_febe::{
    enc, Address, EditionClaim, FourSet, Op, OpKind, RegionSpec, RejectCode, Response, SlotArg,
    SlotSpec, Span, SpanSet, Spec, Tumbler, View, FROM, TO,
};

/// One link over `over`'s content, homed in `home` — the shape both the
/// absence rule and the result-set filter turn on, since the endsets decide
/// which region index it stabs and the HOME decides who may see it.
fn link_over(fx: &Fixture, home: &Address, over: &Address) -> Address {
    ack_addr(ex(
        &fx.febe,
        fx.user,
        Op::MakeLink {
            home: home.clone(),
            from: SlotArg::Resolve(vec![vspec(over, 1, 1)]), // populated
            to: SlotArg::Addrs(vec![]),                      // ⟨⟩
            ty: SlotArg::Resolve(vec![vspec(over, 3, 1)]),
        },
    ))
    .0
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
    let a = create_doc(&fx);
    insert3(&fx, &a);
    let b = create_doc(&fx);
    insert3(&fx, &b);
    unreadable.lock().expect("no poisoning").extend([a.clone(), b.clone()]);
    let other = fx.febe.open_session(OTHER);
    let sp1 = || vspan(1, 1, 1);

    // (op, the document the answer must name)
    let cases: Vec<(Op, &Address)> = vec![
        (Op::RetrieveDocVSpan { doc: a.clone() }, &a),
        (Op::RetrieveDocVSpanSet { doc: a.clone() }, &a),
        (Op::ShowOrigin { doc: a.clone(), span: sp1() }, &a),
        // Two named documents: the first DECLARED one speaks, either way round.
        (Op::ShowDeletions { d_a: a.clone(), d_b: b.clone() }, &a),
        (Op::ShowDeletions { d_a: b.clone(), d_b: a.clone() }, &b),
        // Across an op's lists: rho1's regions before rho2's.
        (
            Op::Compare {
                rho1: vec![RegionSpec { doc: b.clone(), spans: vec![sp1()] }],
                rho2: vec![RegionSpec { doc: a.clone(), spans: vec![sp1()] }],
            },
            &b,
        ),
        // Within a list, by index.
        (
            Op::RetrieveV {
                specs: vec![
                    Spec { doc: b.clone(), span: sp1() },
                    Spec { doc: a.clone(), span: sp1() },
                ],
            },
            &b,
        ),
        (
            Op::FindDocsContaining {
                regions: vec![
                    RegionSpec { doc: b.clone(), spans: vec![sp1()] },
                    RegionSpec { doc: a.clone(), spans: vec![sp1()] },
                ],
            },
            &b,
        ),
        // The region family's `d`.
        (Op::Image { d: a.clone(), region: vec![sp1()] }, &a),
        (Op::FindLinksV { d: a.clone(), region: vec![sp1()] }, &a),
        (Op::CountV { d: a.clone(), region: vec![sp1()] }, &a),
        (Op::WindowV { d: a.clone(), region: vec![sp1()], cur: None, n: 1 }, &a),
        (Op::RetrieveEndsets { d: a.clone(), region: vec![sp1()] }, &a),
        (Op::DeleteOrphans { d: a.clone(), p: vp(1, 1), width: nat(1) }, &a),
        // The two publication reads: the H1 row (PUB-8.12, PUB-8.46).
        (Op::DocMetadata { doc: a.clone() }, &a),
        (Op::EditionClaims { target: b.clone() }, &b),
    ];
    for (op, named) in cases {
        let kind = op.kind();
        assert_withheld(ex(&fx.febe, other, op), kind, named);
    }

    // The consult is per principal: the owner reads its own documents.
    let (set, _) = spanset(ex(&fx.febe, fx.user, Op::RetrieveDocVSpan { doc: a }));
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
/// homed in an unreadable document is left to M8's own absence answer, and is
/// never withheld — a withheld there would confirm the link exists.
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

    // The LINK's home unreadable, `d` readable: whatever M8 answers, it is
    // not a withheld — the link is not a doc-argument.
    unreadable.lock().expect("no poisoning").push(home);
    let d = create_doc(&fx);
    insert3(&fx, &d);
    for op in [
        Op::Project { a: link.clone(), slot: FROM, d: d.clone() },
        Op::DiscoverableFrom { a: link, d },
    ] {
        let kind = op.kind();
        if let Response::Rejected(rej) = ex(&fx.febe, other, op) {
            assert_ne!(
                rej.code,
                RejectCode::Withheld,
                "{kind:?}: a link is not a doc-argument (PUB-6.8)"
            );
        }
    }
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
/// caller cannot read. A link homed in an unreadable draft covers `open`'s
/// content, so it stabs the region index either way; only the filter removes
/// it.
#[test]
fn link_discovery_drops_links_homed_where_the_caller_cannot_read() {
    let (fx, unreadable) = setup_with_unreadable();
    let open = create_doc(&fx);
    insert3(&fx, &open);
    let secret = create_doc(&fx);
    let hidden = link_over(&fx, &secret, &open);
    let shown = link_over(&fx, &open, &open);
    unreadable.lock().expect("no poisoning").push(secret);
    let other = fx.febe.open_session(OTHER);
    let region = || vec![vspan(1, 1, 3)];

    let mine = addrs(ex(&fx.febe, fx.user, Op::FindLinksV { d: open.clone(), region: region() }));
    assert!(mine.contains(&hidden) && mine.contains(&shown), "the owner reads both homes");
    let theirs = addrs(ex(&fx.febe, other, Op::FindLinksV { d: open.clone(), region: region() }));
    assert!(theirs.contains(&shown), "a link homed where the caller reads survives");
    assert!(!theirs.contains(&hidden), "a link homed in an unreadable document is dropped");

    // The census counts what the caller may see, by the same rule.
    assert_eq!(count(ex(&fx.febe, fx.user, Op::CountV { d: open.clone(), region: region() })), 2);
    assert_eq!(count(ex(&fx.febe, other, Op::CountV { d: open, region: region() })), 1);
}

/// PUB-6.13 on the container family: FINDDOCSCONTAINING drops a container the
/// caller cannot read, at its identity. Both documents hold the same element —
/// one allocated it, the other transcludes it — so only the filter
/// distinguishes them.
#[test]
fn find_docs_containing_drops_a_container_the_caller_cannot_read() {
    let (fx, unreadable) = setup_with_unreadable();
    let open = create_doc(&fx);
    insert3(&fx, &open);
    let secret = create_doc(&fx);
    ack(ex(
        &fx.febe,
        fx.user,
        Op::Copy { doc: secret.clone(), at: vp(1, 1), specs: vec![vspec(&open, 1, 1)] },
    ));
    unreadable.lock().expect("no poisoning").push(secret.clone());
    let other = fx.febe.open_session(OTHER);
    let region = || vec![RegionSpec { doc: open.clone(), spans: vec![vspan(1, 1, 1)] }];

    let mine = addrs(ex(&fx.febe, fx.user, Op::FindDocsContaining { regions: region() }));
    assert!(mine.contains(&open) && mine.contains(&secret), "the owner sees both containers");
    let theirs = addrs(ex(&fx.febe, other, Op::FindDocsContaining { regions: region() }));
    assert!(theirs.contains(&open));
    assert!(!theirs.contains(&secret), "an unreadable container is dropped at its identity");
}

/// PUB-8.46 / PUB-6.13: the world answers the CLASS unfiltered, and the DOOR
/// keeps only the rows whose HOME the caller can read — so a draft edition's
/// claim is invisible to a stranger and listed for its owner. The seeded rows
/// stand for claims; nothing here asserts they are links.
#[test]
fn an_edition_claim_homed_where_the_caller_cannot_read_is_dropped() {
    let (fx, unreadable) = setup_with_unreadable();
    let target = create_doc(&fx);
    let open_home = create_doc(&fx);
    let draft_home = create_doc(&fx);
    unreadable.lock().expect("no poisoning").push(draft_home.clone());
    let row = |home: &Address| EditionClaim {
        claim: home.clone(),
        home: home.clone(),
        to: enc([&target]),
        active: true,
    };
    seed_edition_claims(vec![row(&open_home), row(&draft_home)]);
    let other = fx.febe.open_session(OTHER);

    let mine = edition_claims(ex(&fx.febe, fx.user, Op::EditionClaims { target: target.clone() }));
    assert_eq!(mine.len(), 2, "the owner reads both homes, so both rows are listed");
    let theirs = edition_claims(ex(&fx.febe, other, Op::EditionClaims { target }));
    assert_eq!(theirs.len(), 1, "the draft-homed claim is dropped");
    assert_eq!(theirs[0].home, open_home);
}

// ───────────────────────────────── 4. the guest ─────────────────────────────

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
