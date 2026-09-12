//! THE WRITE SIDE'S CONSULT at M10's door (PUB round 2, lane 3.3c; PUB-6.23,
//! PUB-6.24, PUB-6.6, PUB-6.36, PUB-6.38), pinned at the engine-free seam
//! `common`'s readability fixture gives it.
//!
//! What is pinned HERE is the door's own contract, independent of how the
//! predicate is derived: which arguments it consults, in what order, what it
//! answers, and — load-bearing — that it stands BEHIND the destination's own
//! gate and never speaks ahead of the store's `published_target` or
//! `not_owner`. Beside it, the ONE source gate the door is silent for: the
//! publish shot's, which runs on nothing but the visibility class M10 lends
//! M5.
//!
//! The read path's use of the same predicate is `read_door.rs`.

use crate::common;

use common::*;
use skep_address::{elem_addr, Address, ElemPos};
use skep_febe::{
    Deposit, Disposition, Op, OpKind, PrincipalId, RejectCode, Run, SessionId, Shot, ShotRun,
    SlotArg, SuccessorSpec,
};

/// The stranger's own account and session, plus one private document of its
/// own — the destination every cross-owner write below lands in.
fn stranger(fx: &Fixture) -> (SessionId, Address) {
    let (prefix, _) = maybe_addr(ex(&fx.febe, fx.boot, Op::NextAccountPrefix { parent: node1() }));
    let prefix = prefix.expect("a second delegable prefix");
    let (account, _) = ack_addr(ex(
        &fx.febe,
        fx.boot,
        Op::Delegate { new_prefix: prefix.tumbler().clone(), new_id: OTHER },
    ));
    let session = fx.febe.open_session(OTHER);
    let (own, _) = ack_addr(ex(
        &fx.febe,
        session,
        Op::CreateNewDocument { account, published: Some(false) },
    ));
    (session, own)
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
fn a_copy_from_an_unreadable_source_is_withheld_naming_the_first_such_spec() {
    let (fx, unreadable) = setup_with_unreadable();
    let d = create_doc(&fx);
    insert3(&fx, &d);
    unreadable.lock().expect("no poisoning").push(d.clone());
    let (other, own) = stranger(&fx);
    ack_addr(ex(
        &fx.febe,
        other,
        Op::Insert {
            doc: own.clone(),
            at: vp(1, 1),
            values: vec![skep_content::Val::new(vec![b'x'])],
            deposit: Deposit::Undeclared,
        },
    ));

    // One spec, unreadable: withheld, the source named.
    let r = ex(&fx.febe, other, Op::Copy { doc: own.clone(), at: vp(1, 2), specs: vec![vspec(&d, 1, 1)] });
    assert_withheld(r, OpKind::Copy, &d);
    // Two specs, the SECOND unreadable: `site.addr` is the second (PUB-6.4).
    let r = ex(
        &fx.febe,
        other,
        Op::Copy { doc: own.clone(), at: vp(1, 2), specs: vec![vspec(&own, 1, 1), vspec(&d, 1, 1)] },
    );
    assert_withheld(r, OpKind::Copy, &d);
    // Nothing was placed by either refusal.
    let before = fx.febe.log_position();
    let r = ex(&fx.febe, other, Op::Copy { doc: own.clone(), at: vp(1, 2), specs: vec![vspec(&d, 1, 1)] });
    assert!(matches!(r, skep_febe::Response::Rejected(_)));
    assert_eq!(fx.febe.log_position(), before, "a withheld copy commits nothing");

    // The owner reads its own document, so its copy of the same source lands.
    let e = create_doc(&fx);
    ack(ex(&fx.febe, fx.user, Op::Copy { doc: e, at: vp(1, 1), specs: vec![vspec(&d, 1, 2)] }));
}

/// PUB-6.36 slot 1 ahead of slot 6 (PUB-6.38 "after the destination's
/// `not_owner`"): a stranger writing into a document it does NOT own is
/// answered `not_owner` by the store, never `withheld` by the door — whether
/// the write is a copy, a link with a resolve slot, an edit with an
/// unreadable original, or a supersession claim over unreadable endpoints. A
/// session that may not write here is never told whether it may read there.
#[test]
fn the_destination_s_ownership_stands_ahead_of_the_consult() {
    let (fx, unreadable) = setup_with_unreadable();
    let d = create_doc(&fx);
    insert3(&fx, &d);
    let (l1, _) = ack_addr(ex(
        &fx.febe,
        fx.user,
        Op::MakeLink {
            home: d.clone(),
            from: SlotArg::Addrs(vec![]),
            to: SlotArg::Addrs(vec![]),
            ty: SlotArg::Addrs(vec![ghost_type(&d, 1)]),
        },
    ));
    let (l2, _) = ack_addr(ex(
        &fx.febe,
        fx.user,
        Op::MakeLink {
            home: d.clone(),
            from: SlotArg::Addrs(vec![]),
            to: SlotArg::Addrs(vec![]),
            ty: SlotArg::Addrs(vec![ghost_type(&d, 2)]),
        },
    ));
    unreadable.lock().expect("no poisoning").push(d.clone());
    let (other, _own) = stranger(&fx);

    let not_owner = |r: skep_febe::Response, kind: OpKind| {
        let rej = rejected(r);
        assert_eq!(rej.op, kind);
        assert_eq!(rej.code, RejectCode::NotOwner, "slot 1 speaks first: {rej}");
        assert_eq!(rej.site.expect("the failing home").addr.as_ref(), Some(&d));
    };
    not_owner(
        ex(&fx.febe, other, Op::Copy { doc: d.clone(), at: vp(1, 4), specs: vec![vspec(&d, 1, 1)] }),
        OpKind::Copy,
    );
    not_owner(
        ex(
            &fx.febe,
            other,
            Op::MakeLink {
                home: d.clone(),
                from: SlotArg::Addrs(vec![]),
                to: SlotArg::Resolve(vec![vspec(&d, 1, 1)]),
                ty: SlotArg::Addrs(vec![ghost_type(&d, 3)]),
            },
        ),
        OpKind::MakeLink,
    );
    not_owner(
        ex(
            &fx.febe,
            other,
            Op::EditLink {
                original: l1.clone(),
                successor: SuccessorSpec {
                    from: vec![],
                    to: vec![vspec(&d, 1, 1)],
                    ty: SlotArg::Addrs(vec![ghost_type(&d, 4)]),
                },
                d_s: d.clone(),
                d_a: d.clone(),
            },
        ),
        OpKind::EditLink,
    );
    not_owner(
        ex(&fx.febe, other, Op::AssertSup { home: d.clone(), old: l1, new: l2 }),
        OpKind::AssertSup,
    );
}

/// PUB-6.23 on `version`: a fork of a source the caller may not read is
/// WITHHELD naming it; the same fork of a readable source lands in the
/// caller's own account (PUB-2.14's cross-owner arm, untouched).
#[test]
fn a_version_of_an_unreadable_source_is_withheld_and_of_a_readable_one_lands() {
    let (fx, unreadable) = setup_with_unreadable();
    let d = create_doc(&fx);
    insert3(&fx, &d);
    let e = create_doc(&fx);
    insert3(&fx, &e);
    unreadable.lock().expect("no poisoning").push(d.clone());
    let (other, _own) = stranger(&fx);

    assert_withheld(
        ex(&fx.febe, other, Op::Version { d_src: d.clone(), published: None }),
        OpKind::Version,
        &d,
    );
    ack_addr(ex(&fx.febe, other, Op::Version { d_src: e, published: None }));
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
    let d = create_doc(&fx);
    insert3(&fx, &d);
    unreadable.lock().expect("no poisoning").push(d.clone());
    let (other, own) = stranger(&fx);
    ack_addr(ex(
        &fx.febe,
        other,
        Op::Insert {
            doc: own.clone(),
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
                home: own.clone(),
                from: SlotArg::Addrs(vec![]),
                to: SlotArg::Resolve(vec![vspec(&d, 1, 1)]),
                ty: SlotArg::Addrs(vec![ghost_type(&own, 1)]),
            },
        ),
        OpKind::MakeLink,
        &d,
    );
    // Declared order: a readable `to` (the stranger's own document) is
    // consulted before the unreadable `ty`, and the answer names the `ty`.
    assert_withheld(
        ex(
            &fx.febe,
            other,
            Op::MakeLink {
                home: own.clone(),
                from: SlotArg::Addrs(vec![]),
                to: SlotArg::Resolve(vec![vspec(&own, 1, 1)]),
                ty: SlotArg::Resolve(vec![vspec(&d, 1, 1)]),
            },
        ),
        OpKind::MakeLink,
        &d,
    );
    // The address form names an I-position INSIDE the unreadable document and
    // is admitted (PUB-6.24): the recorded endset is the name, unresolved.
    let inside = elem_addr(ElemPos { doc: d.clone(), subspace: nat(1), ordinal: nat(1) })
        .unwrap_or_else(|_| panic!("valid element position"));
    let (link, _) = ack_addr(ex(
        &fx.febe,
        other,
        Op::MakeLink {
            home: own.clone(),
            from: SlotArg::Addrs(vec![]),
            to: SlotArg::Addrs(vec![inside.clone()]),
            ty: SlotArg::Addrs(vec![ghost_type(&own, 1)]),
        },
    ));
    let value = link_value(ex(&fx.febe, other, Op::ReadLink { a: link })).expect("the stranger's own link");
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
    let d = create_doc(&fx);
    insert3(&fx, &d);
    let e = create_doc(&fx);
    insert3(&fx, &e);
    let in_d = |ordinal: u32| {
        ack_addr(ex(
            &fx.febe,
            fx.user,
            Op::MakeLink {
                home: d.clone(),
                from: SlotArg::Addrs(vec![]),
                to: SlotArg::Addrs(vec![]),
                ty: SlotArg::Addrs(vec![ghost_type(&d, ordinal)]),
            },
        ))
        .0
    };
    let (unreadable_l1, unreadable_l2) = (in_d(1), in_d(2));
    let (public_l, _) = ack_addr(ex(
        &fx.febe,
        fx.user,
        Op::MakeLink {
            home: e.clone(),
            from: SlotArg::Addrs(vec![]),
            to: SlotArg::Addrs(vec![]),
            ty: SlotArg::Addrs(vec![ghost_type(&e, 1)]),
        },
    ));
    unreadable.lock().expect("no poisoning").push(d.clone());
    let (other, own) = stranger(&fx);
    let successor = |to: Vec<skep_arrangement::VSpec>, ordinal: u32| SuccessorSpec {
        from: vec![],
        to,
        ty: SlotArg::Addrs(vec![ghost_type(&own, ordinal)]),
    };

    // `original` homed in the unreadable document: the op's own absence answer.
    let rej = rejected(ex(
        &fx.febe,
        other,
        Op::EditLink { original: unreadable_l1.clone(), successor: successor(vec![], 1), d_s: own.clone(), d_a: own.clone() },
    ));
    assert_eq!(rej.op, OpKind::EditLink);
    assert_eq!(rej.code, RejectCode::OriginalNotResident, "absence, never withheld: {rej}");
    assert_eq!(rej.disposition, Disposition::Reorder);
    assert!(rej.site.is_none() && rej.detail.is_none(), "exactly a never-deposited address's answer");

    // Both unreadable — the link-address argument is declared first and speaks.
    let rej = rejected(ex(
        &fx.febe,
        other,
        Op::EditLink { original: unreadable_l1.clone(), successor: successor(vec![vspec(&d, 1, 1)], 2), d_s: own.clone(), d_a: own.clone() },
    ));
    assert_eq!(rej.code, RejectCode::OriginalNotResident, "original ahead of successor: {rej}");

    // A readable original, an unreadable successor source: withheld, naming it.
    assert_withheld(
        ex(
            &fx.febe,
            other,
            Op::EditLink { original: public_l.clone(), successor: successor(vec![vspec(&d, 1, 1)], 3), d_s: own.clone(), d_a: own.clone() },
        ),
        OpKind::EditLink,
        &d,
    );

    // `assert_sup` over endpoints homed in the unreadable document.
    let rej = rejected(ex(
        &fx.febe,
        other,
        Op::AssertSup { home: own.clone(), old: unreadable_l1.clone(), new: unreadable_l2.clone() },
    ));
    assert_eq!(rej.op, OpKind::AssertSup);
    assert_eq!(rej.code, RejectCode::EndpointNotResident, "absence, never withheld: {rej}");
    assert_eq!(rej.disposition, Disposition::Reorder);
    // One readable endpoint beside an unreadable one answers the same way.
    let rej = rejected(ex(
        &fx.febe,
        other,
        Op::AssertSup { home: own.clone(), old: public_l.clone(), new: unreadable_l2.clone() },
    ));
    assert_eq!(rej.code, RejectCode::EndpointNotResident);

    // The OWNER reads its document: the same edit and the same claim land.
    ack_edit(ex(
        &fx.febe,
        fx.user,
        Op::EditLink {
            original: unreadable_l1.clone(),
            successor: SuccessorSpec { from: vec![], to: vec![vspec(&d, 1, 1)], ty: SlotArg::Addrs(vec![ghost_type(&d, 9)]) },
            d_s: d.clone(),
            d_a: d.clone(),
        },
    ));
    ack_addr(ex(&fx.febe, fx.user, Op::AssertSup { home: d.clone(), old: unreadable_l1, new: unreadable_l2 }));
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
    let d = create_doc(&fx);
    insert3(&fx, &d);
    unreadable.lock().expect("no poisoning").push(d.clone());
    let (other, own) = stranger(&fx);
    let published = stranger_edition(&fx, other);

    let before = fx.febe.log_position();
    let rej = rejected(ex(
        &fx.febe,
        other,
        Op::Copy { doc: published.clone(), at: vp(1, 1), specs: vec![vspec(&d, 1, 1)] },
    ));
    assert_eq!(rej.op, OpKind::Copy);
    assert_eq!(rej.code, RejectCode::PublishedTarget, "slot 5 speaks before slot 6: {rej}");
    assert_eq!(rej.disposition, Disposition::Permanent);
    assert!(rej.site.is_none() && rej.detail.is_none(), "byte-identical to the store's refusal");
    assert_eq!(fx.febe.log_position(), before, "a refused copy commits nothing");

    // A DRAFT destination still meets the source consult…
    assert_withheld(
        ex(&fx.febe, other, Op::Copy { doc: own, at: vp(1, 1), specs: vec![vspec(&d, 1, 1)] }),
        OpKind::Copy,
        &d,
    );
    // …and a READABLE source into the same published destination still meets
    // `published_target`, one layer later and in the same bytes.
    let open = create_doc(&fx);
    insert3(&fx, &open);
    let rej = rejected(ex(
        &fx.febe,
        other,
        Op::Copy { doc: published, at: vp(1, 1), specs: vec![vspec(&open, 1, 1)] },
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
    let d = create_doc(&fx);
    insert3(&fx, &d);
    unreadable.lock().expect("no poisoning").push(d.clone());
    let (other, _own) = stranger(&fx);
    let ghost = ghost_doc(&account_of(&fx, other, OTHER), 77);

    let rej = rejected(ex(
        &fx.febe,
        other,
        Op::Copy { doc: ghost, at: vp(1, 1), specs: vec![vspec(&d, 1, 1)] },
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
    let e = create_edition(&fx);
    let (e_start, _) = deposit3(&fx, &e);
    unreadable.lock().expect("no poisoning").push(e.clone());
    let (other, _own) = stranger(&fx);
    let theirs = stranger_edition(&fx, other);

    // No base: neither edition has a chain member yet, so the shot appends
    // the trunk's first (PUB-2.39's memberless arm).
    let shot = || Shot {
        base: None,
        draft: None,
        runs: vec![ShotRun {
            origin: e.clone(),
            run: Run::new(e_start.clone(), nat(3)).expect("a content run"),
        }],
    };
    let before = fx.febe.log_position();
    assert_withheld(
        ex(&fx.febe, other, Op::Publish { doc: theirs, shot: shot() }),
        OpKind::Publish,
        &e,
    );
    assert_eq!(fx.febe.log_position(), before, "a withheld shot commits nothing");

    ack_addr(ex(&fx.febe, fx.user, Op::Publish { doc: e.clone(), shot: shot() }));
}
