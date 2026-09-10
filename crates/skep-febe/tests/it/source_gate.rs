//! THE WRITE SIDE'S CONSULT at M10's door (PUB round 2, lane 3.3c; PUB-6.23,
//! PUB-6.24, PUB-6.6, PUB-6.36, PUB-6.38), pinned at the engine-free seam.
//!
//! The front door answers ONE predicate, so a supplied `Consult` that refuses
//! a document to everyone but its owner is what a private draft looks like
//! to this suite — the miniature world carries no exception set or grant
//! fold, and the engine's own predicate is the daemon suites' to exercise
//! (`skepd/tests/source_gate.rs`). What is pinned HERE is the door's own
//! contract, independent of how the predicate is derived: which arguments it
//! consults, in what order, what it answers, and — load-bearing — that it
//! stands BEHIND the destination's ownership and never speaks ahead of the
//! store's `not_owner`.

use crate::common;

use std::sync::{Arc, Mutex};

use common::*;
use skep_address::{elem_addr, Address, ElemPos};
use skep_febe::{Disposition, Op, OpKind, RejectCode, SlotArg, SuccessorSpec};
use skep_namespace::PrincipalId;

/// A second principal, delegated under the genesis node beside [`USER`]:
/// the NON-ENTITLED stranger of every cell below.
const OTHER: PrincipalId = PrincipalId(8);

/// The documents the supplied predicate REFUSES to everyone but [`USER`] — a
/// draft of USER's, as far as the door can tell. Shared with the consult
/// closure and filled once the documents exist.
type Hidden = Arc<Mutex<Vec<Address>>>;

/// The standard fixture under a predicate that admits USER everywhere and
/// refuses `hidden` to every other principal — the shape the engine's own
/// predicate takes on a private draft (the owner reads by the subtree
/// clause, a stranger does not).
fn setup_hiding() -> (Fixture, Hidden) {
    let hidden: Hidden = Arc::new(Mutex::new(Vec::new()));
    let consult = {
        let hidden = Arc::clone(&hidden);
        Box::new(move |principal: Option<PrincipalId>, doc: &Address| {
            principal == Some(USER) || !hidden.lock().expect("no poisoning").contains(doc)
        })
    };
    let febe = operation().with_consult(consult);
    let boot = febe.bootstrap_session();
    let (prefix, _) = maybe_addr(ex(&febe, boot, Op::NextAccountPrefix { parent: node1() }));
    let prefix = prefix.expect("the genesis node has a delegable next-form prefix");
    let (account, _) = ack_addr(ex(
        &febe,
        boot,
        Op::Delegate { new_prefix: prefix.tumbler().clone(), new_id: USER },
    ));
    let user = febe.open_session(USER);
    (Fixture { febe, boot, user, account }, hidden)
}

/// The stranger's own account and session, plus one private document of its
/// own — the destination every cross-owner write below lands in.
fn stranger(fx: &Fixture) -> (skep_febe::SessionId, Address) {
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

/// A ghost name in `doc`'s never-occupied subspace 3 — an address-form type.
fn ghost_type(doc: &Address, ordinal: u32) -> Address {
    elem_addr(ElemPos { doc: doc.clone(), subspace: nat(3), ordinal: nat(ordinal) })
        .unwrap_or_else(|_| panic!("valid element position"))
}

/// PUB-8.4/8.5 at the door: `withheld`, `reorder`, `site.addr` the document,
/// no `detail`.
fn assert_withheld(r: skep_febe::Response, kind: OpKind, doc: &Address) {
    let rej = rejected(r);
    assert_eq!(rej.op, kind);
    assert_eq!(rej.code, RejectCode::Withheld, "{rej}");
    assert_eq!(rej.disposition, Disposition::Reorder);
    assert_eq!(rej.site.expect("the withheld document rides the site").addr.as_ref(), Some(doc));
    assert!(rej.detail.is_none(), "PUB-8.5: no detail on this code, ever");
}

/// PUB-6.23 / PUB-6.4: a `copy` whose source the caller may not read is
/// WITHHELD naming the source; with two specs, the FIRST unreadable one in
/// index order is named; and the same copy from the OWNER lands — the consult
/// is per principal, exactly as the read side's is.
#[test]
fn a_copy_from_a_refused_source_is_withheld_naming_the_first_unreadable_spec() {
    let (fx, hidden) = setup_hiding();
    let d = create_doc(&fx);
    insert3(&fx, &d);
    hidden.lock().expect("no poisoning").push(d.clone());
    let (other, own) = stranger(&fx);
    ack_addr(ex(
        &fx.febe,
        other,
        Op::Insert {
            doc: own.clone(),
            at: vp(1, 1),
            values: vec![skep_content::Val::new(vec![b'x'])],
            deposit: false,
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
    let (fx, hidden) = setup_hiding();
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
    hidden.lock().expect("no poisoning").push(d.clone());
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
fn a_version_of_a_refused_source_is_withheld_and_of_a_readable_one_lands() {
    let (fx, hidden) = setup_hiding();
    let d = create_doc(&fx);
    insert3(&fx, &d);
    let e = create_doc(&fx);
    insert3(&fx, &e);
    hidden.lock().expect("no poisoning").push(d.clone());
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
fn a_resolve_slot_into_a_refused_source_is_withheld_and_the_address_form_is_not() {
    let (fx, hidden) = setup_hiding();
    let d = create_doc(&fx);
    insert3(&fx, &d);
    hidden.lock().expect("no poisoning").push(d.clone());
    let (other, own) = stranger(&fx);
    ack_addr(ex(
        &fx.febe,
        other,
        Op::Insert {
            doc: own.clone(),
            at: vp(1, 1),
            values: vec![skep_content::Val::new(vec![b'x'])],
            deposit: false,
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
    // The address form names an I-position INSIDE the refused document and
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
fn a_link_homed_in_a_refused_document_answers_absence_to_a_write() {
    let (fx, hidden) = setup_hiding();
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
    let (hidden_l1, hidden_l2) = (in_d(1), in_d(2));
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
    hidden.lock().expect("no poisoning").push(d.clone());
    let (other, own) = stranger(&fx);
    let successor = |to: Vec<skep_arrangement::VSpec>, ordinal: u32| SuccessorSpec {
        from: vec![],
        to,
        ty: SlotArg::Addrs(vec![ghost_type(&own, ordinal)]),
    };

    // `original` homed in the refused document: the op's own absence answer.
    let rej = rejected(ex(
        &fx.febe,
        other,
        Op::EditLink { original: hidden_l1.clone(), successor: successor(vec![], 1), d_s: own.clone(), d_a: own.clone() },
    ));
    assert_eq!(rej.op, OpKind::EditLink);
    assert_eq!(rej.code, RejectCode::OriginalNotResident, "absence, never withheld: {rej}");
    assert_eq!(rej.disposition, Disposition::Reorder);
    assert!(rej.site.is_none() && rej.detail.is_none(), "exactly a never-deposited address's answer");

    // Both unreadable — the link-address argument is declared first and speaks.
    let rej = rejected(ex(
        &fx.febe,
        other,
        Op::EditLink { original: hidden_l1.clone(), successor: successor(vec![vspec(&d, 1, 1)], 2), d_s: own.clone(), d_a: own.clone() },
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

    // `assert_sup` over endpoints homed in the refused document.
    let rej = rejected(ex(
        &fx.febe,
        other,
        Op::AssertSup { home: own.clone(), old: hidden_l1.clone(), new: hidden_l2.clone() },
    ));
    assert_eq!(rej.op, OpKind::AssertSup);
    assert_eq!(rej.code, RejectCode::EndpointNotResident, "absence, never withheld: {rej}");
    assert_eq!(rej.disposition, Disposition::Reorder);
    // One readable endpoint beside an unreadable one answers the same way.
    let rej = rejected(ex(
        &fx.febe,
        other,
        Op::AssertSup { home: own.clone(), old: public_l.clone(), new: hidden_l2.clone() },
    ));
    assert_eq!(rej.code, RejectCode::EndpointNotResident);

    // The OWNER reads its document: the same edit and the same claim land.
    ack_edit(ex(
        &fx.febe,
        fx.user,
        Op::EditLink {
            original: hidden_l1.clone(),
            successor: SuccessorSpec { from: vec![], to: vec![vspec(&d, 1, 1)], ty: SlotArg::Addrs(vec![ghost_type(&d, 9)]) },
            d_s: d.clone(),
            d_a: d.clone(),
        },
    ));
    ack_addr(ex(&fx.febe, fx.user, Op::AssertSup { home: d.clone(), old: hidden_l1, new: hidden_l2 }));
}
