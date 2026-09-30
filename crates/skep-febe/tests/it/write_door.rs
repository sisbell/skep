//! THE WRITE SIDE'S CONSULT at M10's door (PUB round 2, lane 3.3c; PUB-6.23,
//! PUB-6.24, PUB-6.6, PUB-6.36, PUB-6.38), pinned at the engine-free seam
//! `common`'s readability fixture gives it.
//!
//! What is pinned HERE is the door's own contract, independent of how the
//! predicate is derived: which arguments it consults, in what order, what it
//! answers, and — load-bearing — that it stands BEHIND the destination's own
//! gate and never speaks ahead of the store's `published_target` or
//! `not_owner`, nor lets anything built from a source it did not consult
//! speak there. Beside it, the gates the door is silent for, which run on
//! nothing but the visibility class M10 lends a store for one write: the
//! publish shot's source gate in M5, and the link writes' dedup in M7.
//!
//! The read path's use of the same predicate is `read_door.rs`.

use crate::common;

use common::*;
use skep_address::{document_of, elem_addr, Address, ElemPos};
use skep_febe::{
    Deposit, Disposition, Op, OpKind, PrincipalId, RejectCode, Run, SessionId, Shot, ShotRun,
    SlotArg, SuccessorSpec, VSpec, MAX_SLOT_SPANS,
};

/// The stranger's account and session, plus one DRAFT of its own — the
/// destination every cross-owner write below lands in.
fn stranger(fx: &Fixture) -> (SessionId, Address) {
    let (prefix, _) = maybe_addr(ex(&fx.febe, fx.boot, Op::NextAccountPrefix { parent: node1() }));
    let prefix = prefix.expect("a second delegable prefix");
    let (account, _) = ack_addr(ex(
        &fx.febe,
        fx.boot,
        Op::Delegate { new_prefix: prefix.tumbler().clone(), new_id: OTHER },
    ));
    let session = fx.febe.open_session(OTHER);
    let (their_draft, _) = ack_addr(ex(
        &fx.febe,
        session,
        Op::CreateNewDocument { account, published: Some(false) },
    ));
    (session, their_draft)
}

/// The account of a delegated principal, read back through the surface.
fn account_of(fx: &Fixture, session: SessionId, id: PrincipalId) -> Address {
    maybe_addr(ex(&fx.febe, session, Op::PrincipalPrefix { id }))
        .0
        .expect("a delegated principal has an account")
}

/// A PUBLISHED edition in the stranger's own account — a destination the
/// caller OWNS, which the two cells that turn on the destination's own
/// publication state both need.
fn stranger_edition(fx: &Fixture, session: SessionId) -> Address {
    let account = account_of(fx, session, OTHER);
    ack_addr(ex(&fx.febe, session, Op::CreateNewDocument { account, published: Some(true) })).0
}

/// A ghost name in `doc`'s never-occupied subspace 3 — an address-form type.
fn ghost_type(doc: &Address, ordinal: u32) -> Address {
    elem_addr(ElemPos { doc: doc.clone(), subspace: nat(3), ordinal: nat(ordinal) })
        .unwrap_or_else(|_| panic!("valid element position"))
}

/// PUB-6.23 / PUB-6.4: a `copy` whose source the caller may not read is
/// WITHHELD naming the source; with two specs, the FIRST unreadable one in
/// index order is named; and the same copy from the OWNER lands — the consult
/// is per principal, exactly as the read side's is.
#[test]
fn a_copy_is_withheld_naming_its_first_unreadable_source() {
    let (fx, unreadable) = setup_with_unreadable();
    let unreadable_doc = create_doc(&fx);
    insert3(&fx, &unreadable_doc);
    unreadable.lock().expect("no poisoning").push(unreadable_doc.clone());
    let (other, their_draft) = stranger(&fx);
    ack_addr(ex(
        &fx.febe,
        other,
        Op::Insert {
            doc: their_draft.clone(),
            at: vp(1, 1),
            values: vec![skep_content::Val::new(vec![b'x'])],
            deposit: Deposit::Undeclared,
        },
    ));

    // One spec, unreadable: withheld, the source named.
    let r = ex(&fx.febe, other, Op::Copy { doc: their_draft.clone(), at: vp(1, 2), specs: vec![vspec(&unreadable_doc, 1, 1)] });
    assert_withheld(r, OpKind::Copy, &unreadable_doc);
    // Two specs, the SECOND unreadable: `site.addr` is the second (PUB-6.4).
    let r = ex(
        &fx.febe,
        other,
        Op::Copy { doc: their_draft.clone(), at: vp(1, 2), specs: vec![vspec(&their_draft, 1, 1), vspec(&unreadable_doc, 1, 1)] },
    );
    assert_withheld(r, OpKind::Copy, &unreadable_doc);
    // Nothing was placed by either refusal.
    let before = fx.febe.log_position();
    let r = ex(&fx.febe, other, Op::Copy { doc: their_draft.clone(), at: vp(1, 2), specs: vec![vspec(&unreadable_doc, 1, 1)] });
    assert!(matches!(r, skep_febe::Response::Rejected(_)));
    assert_eq!(fx.febe.log_position(), before, "a withheld copy commits nothing");

    // The owner reads its own document, so its copy of the same source lands.
    let user_draft = create_doc(&fx);
    ack(ex(&fx.febe, fx.user, Op::Copy { doc: user_draft, at: vp(1, 1), specs: vec![vspec(&unreadable_doc, 1, 2)] }));
}

/// PUB-6.36 slot 1 ahead of slot 6 (PUB-6.38 "after the destination's
/// `not_owner`"): a stranger writing into a document it does NOT own is
/// answered `not_owner` by the store, never `withheld` by the door — whether
/// the write is a copy, a link with a resolve slot, an edit with an
/// unreadable original, or a supersession claim over unreadable endpoints. A
/// session that may not write here is never told whether it may read there.
#[test]
fn the_destinations_own_gate_stands_ahead_of_the_consult() {
    let (fx, unreadable) = setup_with_unreadable();
    let unreadable_doc = create_doc(&fx);
    insert3(&fx, &unreadable_doc);
    let (l1, _) = ack_addr(ex(
        &fx.febe,
        fx.user,
        Op::MakeLink {
            home: unreadable_doc.clone(),
            from: SlotArg::Addrs(vec![]),
            to: SlotArg::Addrs(vec![]),
            ty: SlotArg::Addrs(vec![ghost_type(&unreadable_doc, 1)]),
            replaces: None,
        },
    ));
    let (l2, _) = ack_addr(ex(
        &fx.febe,
        fx.user,
        Op::MakeLink {
            home: unreadable_doc.clone(),
            from: SlotArg::Addrs(vec![]),
            to: SlotArg::Addrs(vec![]),
            ty: SlotArg::Addrs(vec![ghost_type(&unreadable_doc, 2)]),
            replaces: None,
        },
    ));
    unreadable.lock().expect("no poisoning").push(unreadable_doc.clone());
    let (other, _their_draft) = stranger(&fx);

    let assert_not_owner = |r: skep_febe::Response, kind: OpKind| {
        let rej = rejected(r);
        assert_eq!(rej.op, kind);
        assert_eq!(rej.code, RejectCode::NotOwner, "slot 1 speaks first: {rej}");
        assert_eq!(rej.site.expect("the failing home").addr.as_ref(), Some(&unreadable_doc));
    };
    assert_not_owner(
        ex(&fx.febe, other, Op::Copy { doc: unreadable_doc.clone(), at: vp(1, 4), specs: vec![vspec(&unreadable_doc, 1, 1)] }),
        OpKind::Copy,
    );
    assert_not_owner(
        ex(
            &fx.febe,
            other,
            Op::MakeLink {
                home: unreadable_doc.clone(),
                from: SlotArg::Addrs(vec![]),
                to: SlotArg::Resolve(vec![vspec(&unreadable_doc, 1, 1)]),
                ty: SlotArg::Addrs(vec![ghost_type(&unreadable_doc, 3)]),
                replaces: None,
            },
        ),
        OpKind::MakeLink,
    );
    assert_not_owner(
        ex(
            &fx.febe,
            other,
            Op::EditLink {
                original: l1.clone(),
                successor: SuccessorSpec {
                    from: vec![],
                    to: vec![vspec(&unreadable_doc, 1, 1)],
                    ty: SlotArg::Addrs(vec![ghost_type(&unreadable_doc, 4)]),
                },
                d_s: unreadable_doc.clone(),
                d_a: unreadable_doc.clone(),
            },
        ),
        OpKind::EditLink,
    );
    assert_not_owner(
        ex(&fx.febe, other, Op::AssertSup { home: unreadable_doc.clone(), old: l1, new: l2 }),
        OpKind::AssertSup,
    );
}

/// PUB-6.36 slot 1 ahead of everything built from a source (PUB-6.38; the
/// deferral in `consult_write`): an edit into a destination the caller may
/// not write is answered alike WHATEVER an unconsulted successor source
/// holds. Where the door deferred, the sources were never consulted, so
/// nothing M10 builds from their arrangements may speak ahead of the store's
/// gate — M7's `editlink` asks its home gate before its own span budget for
/// the same reason. Two private drafts differing in ARRANGEMENT alone — one
/// region split into two runs, one contiguous — must draw one answer, or the
/// answer is an oracle on a document the caller may not read: the store's
/// `not_owner`, and with a later spec at fault, that spec's own fault,
/// wherever an unread source crossed the slot's budget ahead of it.
#[test]
fn an_edit_refused_its_destination_answers_alike_whatever_its_unreadable_source_holds() {
    let (fx, unreadable) = setup_with_unreadable();
    // USER's: readable to the stranger, and not the stranger's to write.
    let (user_draft, original) = linked_doc(&fx);
    let fragmented = create_doc(&fx);
    insert3(&fx, &fragmented);
    ack(ex(&fx.febe, fx.user, Op::Delete { doc: fragmented.clone(), p: vp(1, 2), width: nat(1) }));
    let contiguous = create_doc(&fx);
    insert3(&fx, &contiguous);
    let runs_over = |d: &Address| {
        runs(ex(&fx.febe, fx.user, Op::Image { d: d.clone(), region: vec![vspan(1, 1, 2)] })).len()
    };
    assert_eq!(
        (runs_over(&fragmented), runs_over(&contiguous)),
        (2, 1),
        "premise: the two sources differ in arrangement alone"
    );
    unreadable.lock().expect("no poisoning").extend([fragmented.clone(), contiguous.clone()]);
    let (other, _their_draft) = stranger(&fx);
    // Enough specs that the fragmented source's spans cross the slot's
    // budget and the contiguous source's do not; `fault` appends a spec the
    // request itself gets wrong.
    let edit = |source: &Address, fault: Option<VSpec>| {
        let mut from =
            vec![VSpec { source: source.clone(), span: vspan(1, 1, 2) }; MAX_SLOT_SPANS / 2 + 1];
        from.extend(fault);
        Op::EditLink {
            original: original.clone(),
            successor: SuccessorSpec {
                from,
                to: vec![],
                ty: SlotArg::Addrs(vec![ghost_type(&user_draft, 1)]),
            },
            d_s: user_draft.clone(),
            d_a: user_draft.clone(),
        }
    };

    let before = fx.febe.log_position();
    let over_fragmented = rejected(ex(&fx.febe, other, edit(&fragmented, None)));
    assert_eq!(
        over_fragmented.code,
        RejectCode::NotOwner,
        "slot 1 speaks first: {over_fragmented}"
    );
    assert_eq!(over_fragmented.site.as_ref().and_then(|s| s.addr.as_ref()), Some(&user_draft));
    assert_eq!(
        over_fragmented,
        rejected(ex(&fx.febe, other, edit(&contiguous, None))),
        "one answer, whatever an unreadable source holds"
    );

    // A link-subspace span is the request's own fault, and it sits AFTER
    // the specs over which the fragmented source crosses the budget.
    let ill_formed = || Some(VSpec { source: user_draft.clone(), span: vspan(2, 1, 1) });
    let at_fault = rejected(ex(&fx.febe, other, edit(&fragmented, ill_formed())));
    assert_eq!(at_fault.code, RejectCode::IllFormedSpec, "the request's own fault: {at_fault}");
    assert_eq!(
        at_fault,
        rejected(ex(&fx.febe, other, edit(&contiguous, ill_formed()))),
        "a later spec's fault answers alike, wherever an unread source crossed the budget"
    );
    assert_eq!(fx.febe.log_position(), before, "a refused edit commits nothing");
}

/// PUB-6.36 slot 1 over BOTH of `edit_link`'s homes: the door judges an
/// edit's sources only where the caller may write EVERY home it deposits
/// into, so a stranger owning one and not the other is answered the store's
/// `not_owner`, naming the home it may not write — never `withheld` about the
/// source. Both orders, so the rule is ALL of the homes, not the first or the
/// last.
#[test]
fn an_edit_owning_one_of_its_two_homes_is_refused_not_owner_never_withheld() {
    let (fx, unreadable) = setup_with_unreadable();
    let (user_draft, original) = linked_doc(&fx);
    let unreadable_doc = create_doc(&fx);
    insert3(&fx, &unreadable_doc);
    unreadable.lock().expect("no poisoning").push(unreadable_doc.clone());
    let (other, their_draft) = stranger(&fx);

    for (d_s, d_a) in [(&their_draft, &user_draft), (&user_draft, &their_draft)] {
        let rej = rejected(ex(
            &fx.febe,
            other,
            Op::EditLink {
                original: original.clone(),
                successor: SuccessorSpec {
                    from: vec![],
                    to: vec![vspec(&unreadable_doc, 1, 1)],
                    ty: SlotArg::Addrs(vec![ghost_type(&their_draft, 1)]),
                },
                d_s: d_s.clone(),
                d_a: d_a.clone(),
            },
        ));
        assert_eq!(rej.op, OpKind::EditLink);
        assert_eq!(rej.code, RejectCode::NotOwner, "d_s {d_s}, d_a {d_a}: {rej}");
        assert_eq!(
            rej.site.as_ref().and_then(|s| s.addr.as_ref()),
            Some(&user_draft),
            "the home the stranger may not write"
        );
    }
}

/// PUB-6.23 on `version`: a fork of a source the caller may not read is
/// WITHHELD naming it; the same fork of a readable source lands in the
/// caller's own account (PUB-2.14's cross-owner arm, untouched).
#[test]
fn a_version_of_an_unreadable_source_is_withheld_and_of_a_readable_one_lands() {
    let (fx, unreadable) = setup_with_unreadable();
    let unreadable_doc = create_doc(&fx);
    insert3(&fx, &unreadable_doc);
    let readable_doc = create_doc(&fx);
    insert3(&fx, &readable_doc);
    unreadable.lock().expect("no poisoning").push(unreadable_doc.clone());
    let (other, _their_draft) = stranger(&fx);

    assert_withheld(
        ex(&fx.febe, other, Op::Version { d_src: unreadable_doc.clone(), published: None }),
        OpKind::Version,
        &unreadable_doc,
    );
    ack_addr(ex(&fx.febe, other, Op::Version { d_src: readable_doc, published: None }));
}

/// PUB-6.23 / PUB-6.24 on `make_link`: a RESOLVE-form slot into a source the
/// caller may not read is WITHHELD naming it — the slots consulted in the
/// declared order, so an unreadable `ty` is named only after a readable
/// `to` — while the SAME slot in ADDRESS FORM is ungated: an address is not
/// secret and needs no read to write, so the link lands, its endset the name
/// verbatim.
#[test]
fn a_resolve_slot_into_an_unreadable_source_is_withheld_and_the_address_form_is_not() {
    let (fx, unreadable) = setup_with_unreadable();
    let unreadable_doc = create_doc(&fx);
    insert3(&fx, &unreadable_doc);
    unreadable.lock().expect("no poisoning").push(unreadable_doc.clone());
    let (other, their_draft) = stranger(&fx);
    ack_addr(ex(
        &fx.febe,
        other,
        Op::Insert {
            doc: their_draft.clone(),
            at: vp(1, 1),
            values: vec![skep_content::Val::new(vec![b'x'])],
            deposit: Deposit::Undeclared,
        },
    ));

    assert_withheld(
        ex(
            &fx.febe,
            other,
            Op::MakeLink {
                home: their_draft.clone(),
                from: SlotArg::Addrs(vec![]),
                to: SlotArg::Resolve(vec![vspec(&unreadable_doc, 1, 1)]),
                ty: SlotArg::Addrs(vec![ghost_type(&their_draft, 1)]),
                replaces: None,
            },
        ),
        OpKind::MakeLink,
        &unreadable_doc,
    );
    // Declared order: a readable `to` (the stranger's own document) is
    // consulted before the unreadable `ty`, and the answer names the `ty`.
    assert_withheld(
        ex(
            &fx.febe,
            other,
            Op::MakeLink {
                home: their_draft.clone(),
                from: SlotArg::Addrs(vec![]),
                to: SlotArg::Resolve(vec![vspec(&their_draft, 1, 1)]),
                ty: SlotArg::Resolve(vec![vspec(&unreadable_doc, 1, 1)]),
                replaces: None,
            },
        ),
        OpKind::MakeLink,
        &unreadable_doc,
    );
    // The address form names an I-position INSIDE the unreadable document and
    // is admitted (PUB-6.24): the recorded endset is the name, unresolved.
    let inside = elem_addr(ElemPos { doc: unreadable_doc.clone(), subspace: nat(1), ordinal: nat(1) })
        .unwrap_or_else(|_| panic!("valid element position"));
    let (link, _) = ack_addr(ex(
        &fx.febe,
        other,
        Op::MakeLink {
            home: their_draft.clone(),
            from: SlotArg::Addrs(vec![]),
            to: SlotArg::Addrs(vec![inside.clone()]),
            ty: SlotArg::Addrs(vec![ghost_type(&their_draft, 1)]),
            replaces: None,
        },
    ));
    let value =
        link_value(ex(&fx.febe, other, Op::ReadLink { a: link })).expect("the stranger's own link");
    assert_eq!(value.to_slot().addrs().next(), Some(inside.tumbler()), "the name, verbatim");
}

/// PUB-6.6 on writes: a link homed in a document the caller may not read is
/// answered exactly as an address no link occupies — `edit_link.original`
/// takes the op's own `original_not_resident`, `assert_sup.old`/`new` its
/// `endpoint_not_resident` — never a `withheld` confirming the link exists
/// and never `not_owner`. Within `edit_link` the link-address argument speaks
/// ahead of the successor's sources (declaration order); a readable original
/// with an unreadable successor source is `withheld` naming that source; and
/// the OWNER's identical edit lands, the consult being per principal.
#[test]
fn a_link_homed_in_an_unreadable_document_answers_absence_to_a_write() {
    let (fx, unreadable) = setup_with_unreadable();
    let unreadable_doc = create_doc(&fx);
    insert3(&fx, &unreadable_doc);
    let readable_home = create_doc(&fx);
    insert3(&fx, &readable_home);
    let in_unreadable = |ordinal: u32| {
        ack_addr(ex(
            &fx.febe,
            fx.user,
            Op::MakeLink {
                home: unreadable_doc.clone(),
                from: SlotArg::Addrs(vec![]),
                to: SlotArg::Addrs(vec![]),
                ty: SlotArg::Addrs(vec![ghost_type(&unreadable_doc, ordinal)]),
                replaces: None,
            },
        ))
        .0
    };
    let (unreadable_l1, unreadable_l2) = (in_unreadable(1), in_unreadable(2));
    let (readable_l, _) = ack_addr(ex(
        &fx.febe,
        fx.user,
        Op::MakeLink {
            home: readable_home.clone(),
            from: SlotArg::Addrs(vec![]),
            to: SlotArg::Addrs(vec![]),
            ty: SlotArg::Addrs(vec![ghost_type(&readable_home, 1)]),
            replaces: None,
        },
    ));
    unreadable.lock().expect("no poisoning").push(unreadable_doc.clone());
    let (other, their_draft) = stranger(&fx);
    let successor = |to: Vec<skep_arrangement::VSpec>, ordinal: u32| SuccessorSpec {
        from: vec![],
        to,
        ty: SlotArg::Addrs(vec![ghost_type(&their_draft, ordinal)]),
    };

    // `original` homed in the unreadable document: the op's own absence answer.
    let rej = rejected(ex(
        &fx.febe,
        other,
        Op::EditLink { original: unreadable_l1.clone(), successor: successor(vec![], 1), d_s: their_draft.clone(), d_a: their_draft.clone() },
    ));
    assert_eq!(rej.op, OpKind::EditLink);
    assert_eq!(rej.code, RejectCode::OriginalNotResident, "absence, never withheld: {rej}");
    assert_eq!(rej.disposition, Disposition::Reorder);
    assert!(rej.site.is_none() && rej.detail.is_none(), "exactly a never-deposited address's answer");

    // Both unreadable — the link-address argument is declared first and speaks.
    let rej = rejected(ex(
        &fx.febe,
        other,
        Op::EditLink { original: unreadable_l1.clone(), successor: successor(vec![vspec(&unreadable_doc, 1, 1)], 2), d_s: their_draft.clone(), d_a: their_draft.clone() },
    ));
    assert_eq!(rej.code, RejectCode::OriginalNotResident, "original ahead of successor: {rej}");

    // A readable original, an unreadable successor source: withheld, naming it.
    assert_withheld(
        ex(
            &fx.febe,
            other,
            Op::EditLink { original: readable_l.clone(), successor: successor(vec![vspec(&unreadable_doc, 1, 1)], 3), d_s: their_draft.clone(), d_a: their_draft.clone() },
        ),
        OpKind::EditLink,
        &unreadable_doc,
    );

    // `assert_sup` over endpoints homed in the unreadable document.
    let rej = rejected(ex(
        &fx.febe,
        other,
        Op::AssertSup { home: their_draft.clone(), old: unreadable_l1.clone(), new: unreadable_l2.clone() },
    ));
    assert_eq!(rej.op, OpKind::AssertSup);
    assert_eq!(rej.code, RejectCode::EndpointNotResident, "absence, never withheld: {rej}");
    assert_eq!(rej.disposition, Disposition::Reorder);
    // One readable endpoint beside an unreadable one answers the same way.
    let rej = rejected(ex(
        &fx.febe,
        other,
        Op::AssertSup { home: their_draft.clone(), old: readable_l.clone(), new: unreadable_l2.clone() },
    ));
    assert_eq!(rej.code, RejectCode::EndpointNotResident);

    // The OWNER reads its document: the same edit and the same claim land.
    ack_edit(ex(
        &fx.febe,
        fx.user,
        Op::EditLink {
            original: unreadable_l1.clone(),
            successor: SuccessorSpec { from: vec![], to: vec![vspec(&unreadable_doc, 1, 1)], ty: SlotArg::Addrs(vec![ghost_type(&unreadable_doc, 9)]) },
            d_s: unreadable_doc.clone(),
            d_a: unreadable_doc.clone(),
        },
    ));
    ack_addr(ex(&fx.febe, fx.user, Op::AssertSup { home: unreadable_doc.clone(), old: unreadable_l1, new: unreadable_l2 }));
}

/// PUB-6.36 slot 5 ahead of slot 6: the ONE cell where both apply — a source
/// the caller may not read, copied into a PUBLISHED destination the caller
/// OWNS — answers `published_target`, never `withheld`, and answers it
/// byte-identically to the store's own refusal (same code, disposition, no
/// site, no detail). Both neighbouring cells are unchanged, which is what
/// makes this a statement about ORDER rather than about either refusal.
#[test]
fn an_in_place_edit_of_a_published_destination_outranks_the_source_consult() {
    let (fx, unreadable) = setup_with_unreadable();
    let unreadable_doc = create_doc(&fx);
    insert3(&fx, &unreadable_doc);
    unreadable.lock().expect("no poisoning").push(unreadable_doc.clone());
    let (other, their_draft) = stranger(&fx);
    let their_edition = stranger_edition(&fx, other);

    let before = fx.febe.log_position();
    let rej = rejected(ex(
        &fx.febe,
        other,
        Op::Copy { doc: their_edition.clone(), at: vp(1, 1), specs: vec![vspec(&unreadable_doc, 1, 1)] },
    ));
    assert_eq!(rej.op, OpKind::Copy);
    assert_eq!(rej.code, RejectCode::PublishedTarget, "slot 5 speaks before slot 6: {rej}");
    assert_eq!(rej.disposition, Disposition::Permanent);
    assert!(rej.site.is_none() && rej.detail.is_none(), "byte-identical to the store's refusal");
    assert_eq!(fx.febe.log_position(), before, "a refused copy commits nothing");

    // A DRAFT destination still meets the source consult…
    assert_withheld(
        ex(&fx.febe, other, Op::Copy { doc: their_draft, at: vp(1, 1), specs: vec![vspec(&unreadable_doc, 1, 1)] }),
        OpKind::Copy,
        &unreadable_doc,
    );
    // …and a READABLE source into the same published destination still meets
    // `published_target`, one layer later and in the same bytes.
    let readable_doc = create_doc(&fx);
    insert3(&fx, &readable_doc);
    let rej = rejected(ex(
        &fx.febe,
        other,
        Op::Copy { doc: their_edition, at: vp(1, 1), specs: vec![vspec(&readable_doc, 1, 1)] },
    ));
    assert_eq!(rej.code, RejectCode::PublishedTarget);
    assert!(rej.site.is_none() && rej.detail.is_none());
}

/// PUB-6.38, the deferral's OTHER half: the destination's own gate is
/// registration AND ownership, and both stand ahead of the consult. A copy
/// into an unregistered address in the caller's OWN account — one ω names the
/// caller for, by the longest-prefix rule — answers the store's
/// `doc_not_registered`, never a withheld.
#[test]
fn an_unregistered_destination_also_stands_ahead_of_the_consult() {
    let (fx, unreadable) = setup_with_unreadable();
    let unreadable_doc = create_doc(&fx);
    insert3(&fx, &unreadable_doc);
    unreadable.lock().expect("no poisoning").push(unreadable_doc.clone());
    let (other, _their_draft) = stranger(&fx);
    let ghost = ghost_doc(&account_of(&fx, other, OTHER), 77);

    let rej = rejected(ex(
        &fx.febe,
        other,
        Op::Copy { doc: ghost, at: vp(1, 1), specs: vec![vspec(&unreadable_doc, 1, 1)] },
    ));
    assert_eq!(rej.op, OpKind::Copy);
    assert_eq!(rej.code, RejectCode::DocNotRegistered, "registration stands ahead: {rej}");
}

/// PUB-6.23 / PUB-8.1, the SHOT's source gate: the door is SILENT here
/// (`publish` is `NotTaken`), so the only thing that can refuse a run
/// windowing an unreadable origin is the VISIBILITY CLASS M10 lends M5 —
/// `visible_to`, the same value the five link writes lend M7, which M5
/// evaluates per ORIGIN over the shot's own working world. A shot supplying
/// such a run is WITHHELD naming that origin; the owner's identical shot
/// lands, so the class is the SESSION's and not a constant.
#[test]
fn a_shot_windowing_an_unreadable_origin_is_withheld_naming_it() {
    let (fx, unreadable) = setup_with_unreadable();
    let unreadable_edition = create_edition(&fx);
    let (edition_start, _) = deposit3(&fx, &unreadable_edition);
    unreadable.lock().expect("no poisoning").push(unreadable_edition.clone());
    let (other, _their_draft) = stranger(&fx);
    let their_edition = stranger_edition(&fx, other);

    // No base: neither edition has a chain member yet, so the shot appends
    // the trunk's first (PUB-2.39's memberless arm).
    let shot = || Shot {
        base: None,
        draft: None,
        runs: vec![ShotRun {
            origin: unreadable_edition.clone(),
            run: Run::new(edition_start.clone(), nat(3)).expect("a content run"),
        }],
    };
    let before = fx.febe.log_position();
    assert_withheld(
        ex(&fx.febe, other, Op::Publish { doc: their_edition, shot: shot() }),
        OpKind::Publish,
        &unreadable_edition,
    );
    assert_eq!(fx.febe.log_position(), before, "a withheld shot commits nothing");

    ack_addr(ex(&fx.febe, fx.user, Op::Publish { doc: unreadable_edition.clone(), shot: shot() }));
}

/// PUB-6.25 / PUB-6.26 on the LINK writes: a `[K_sup]` claim dedups on its
/// value across homes (M7) — but only onto an incumbent the writer may read,
/// which is the visibility class M10 lends the link writer for the one
/// write. The owner's assertion from a second home is the control: it IS
/// answered the incumbent, zero-step. The stranger's identical assertion
/// must mint its own claim in its own home; handed the one homed where it
/// cannot read, it would learn that a link lives there, and where.
#[test]
fn a_link_writes_dedup_never_hands_back_a_claim_homed_where_the_writer_cannot_read() {
    let (fx, unreadable) = setup_with_unreadable();
    let (user_draft, l1) = linked_doc(&fx);
    let (l2, _) = ack_addr(ex(
        &fx.febe,
        fx.user,
        Op::MakeLink {
            home: user_draft.clone(),
            from: SlotArg::Resolve(vec![vspec(&user_draft, 1, 1)]),
            to: SlotArg::Resolve(vec![vspec(&user_draft, 2, 1)]),
            ty: SlotArg::Resolve(vec![vspec(&user_draft, 3, 1)]),
            replaces: None,
        },
    ));
    let unreadable_home = create_doc(&fx);
    unreadable.lock().expect("no poisoning").push(unreadable_home.clone());
    let (other, their_draft) = stranger(&fx);
    let sup = |home: &Address| Op::AssertSup {
        home: home.clone(),
        old: l1.clone(),
        new: l2.clone(),
    };
    let (unreadable_claim, _) = ack_addr(ex(&fx.febe, fx.user, sup(&unreadable_home)));

    let before = fx.febe.log_position();
    assert_eq!(
        ack_addr(ex(&fx.febe, fx.user, sup(&user_draft))),
        (unreadable_claim.clone(), before),
        "the control: the owner's dedup reaches across homes, zero-step"
    );
    let (theirs, at) = ack_addr(ex(&fx.febe, other, sup(&their_draft)));
    assert_ne!(theirs, unreadable_claim, "never a claim homed where the writer cannot read");
    assert_eq!(document_of(&theirs), Some(their_draft), "the writer's own claim, in its own home");
    assert!(at > before, "minted, not a dedup hit");
}
