//! The in-place advance refusal (PUB-2.11) on the four edits, and the
//! declared deposit that clears it.

use skep_address::{validate, Address, Nat, Tumbler};
use skep_arrangement::{
    Caller, CopyError, DeleteError, Deposit, HasM5, InsertError, RearrangeError, VPos, VSpec,
    VersionError, Vstream,
};
use skep_kernel::TxnError;
use skep_namespace::{HasM3, Namespace, PrincipalId};

use crate::common::*;

#[test]
fn in_place_edits_refuse_a_published_target_and_commit_nothing() {
    // PUB-2.11: insert, copy-into, delete and re-arrange on a PUBLISHED
    // target refuse `PublishedTarget` — after registration and ω, BEFORE
    // every shape check (each op is also asked in a frame that is
    // mis-shaped, and the publication verdict is the one that speaks) — and
    // commit nothing. The same four on the private draft are admitted as
    // before.
    let k = mem_kernel();
    let vs = deposit_abc(&k);
    let before = k.current_seq();
    // An undeclared append at the edition's fresh position IS an in-place
    // edit (RES-209 item 5's cost, closed by the DECLARED horn).
    assert!(matches!(
        rejected(vs.insert(P1, &pdoc(), vp(1, 4), vec![val(b"x")], Deposit::Undeclared)),
        InsertError::PublishedTarget
    ));
    // Ahead of the shape checks: empty values in the link subspace.
    assert!(matches!(
        rejected(vs.insert(P1, &pdoc(), vp(2, 0), vec![], Deposit::Undeclared)),
        InsertError::PublishedTarget
    ));
    assert!(matches!(
        rejected(vs.copy(
            P1,
            &pdoc(),
            vp(1, 4),
            &[VSpec {
                source: doc1(),
                span: vspan(1, 1, 1),
            }]
        )),
        CopyError::PublishedTarget
    ));
    assert!(matches!(
        rejected(vs.copy(P1, &pdoc(), vp(2, 99), &[])),
        CopyError::PublishedTarget
    ));
    assert!(matches!(
        rejected(vs.delete(P1, &pdoc(), vp(1, 1), n(1))),
        DeleteError::PublishedTarget
    ));
    assert!(matches!(
        rejected(vs.delete(P1, &pdoc(), vp(2, 9), n(0))),
        DeleteError::PublishedTarget
    ));
    assert!(matches!(
        rejected(vs.rearrange(P1, &pdoc(), &[vp(1, 1), vp(1, 2), vp(1, 3)])),
        RearrangeError::PublishedTarget
    ));
    assert!(matches!(
        rejected(vs.rearrange(P1, &pdoc(), &[])),
        RearrangeError::PublishedTarget
    ));
    // `Caller::System` is not exempt (PUB-6.28): a fire never advances a
    // published arrangement in place, by any of the four. Each frame below
    // would otherwise be admitted or answer for its own shape — the copy's
    // empty spec list with EmptyResult, the rest by committing.
    assert!(matches!(
        rejected(vs.insert(Caller::System, &pdoc(), vp(1, 4), vec![val(b"s")], Deposit::Undeclared)),
        InsertError::PublishedTarget
    ));
    assert!(matches!(
        rejected(vs.copy(Caller::System, &pdoc(), vp(1, 4), &[])),
        CopyError::PublishedTarget
    ));
    assert!(matches!(
        rejected(vs.delete(Caller::System, &pdoc(), vp(1, 1), n(1))),
        DeleteError::PublishedTarget
    ));
    assert!(matches!(
        rejected(vs.rearrange(Caller::System, &pdoc(), &[vp(1, 1), vp(1, 2), vp(1, 3)])),
        RearrangeError::PublishedTarget
    ));
    assert_eq!(k.current_seq(), before, "every refusal is a clean no-op");
    let s = k.snapshot();
    assert_eq!(s.world().m5().content_count(&pdoc()), n(3));
    assert_eq!(read_v(&s, &pdoc(), 1), b"a".to_vec());
    // The draft beside it takes the same four edits.
    insert_abc(&k);
    vs.copy(
        P1,
        &doc1(),
        vp(1, 4),
        &[VSpec {
            source: pdoc(),
            span: vspan(1, 1, 1),
        }],
    )
    .expect("copy-into a draft commits");
    vs.delete(P1, &doc1(), vp(1, 4), n(1)).expect("delete in a draft commits");
    vs.rearrange(P1, &doc1(), &[vp(1, 1), vp(1, 2), vp(1, 3)])
        .expect("rearrange in a draft commits");
}

#[test]
fn ownership_stands_ahead_of_the_published_target_refusal() {
    // PUB-6.36 slot 1 before slot 5: a stranger's edit of a published
    // document answers `NotOwner`, learning nothing about publication, and an
    // unregistered target answers registration (PUB-6.37) — never a
    // publication code, even for the caller who would own it.
    let k = mem_kernel();
    let vs = deposit_abc(&k);
    let p2 = Caller::Principal(PrincipalId(2));
    // Each of the four edits, a stranger's, on the published edition: both
    // refusals apply to every one of them, and ω is the one that speaks.
    assert!(matches!(
        rejected(vs.insert(p2, &pdoc(), vp(1, 4), vec![val(b"x")], Deposit::Undeclared)),
        InsertError::NotOwner(d) if d == pdoc()
    ));
    assert!(matches!(
        rejected(vs.copy(p2, &pdoc(), vp(1, 4), &[])),
        CopyError::NotOwner(d) if d == pdoc()
    ));
    assert!(matches!(
        rejected(vs.delete(p2, &pdoc(), vp(1, 1), n(1))),
        DeleteError::NotOwner(d) if d == pdoc()
    ));
    assert!(matches!(
        rejected(vs.rearrange(p2, &pdoc(), &[vp(1, 1), vp(1, 2), vp(1, 3)])),
        RearrangeError::NotOwner(d) if d == pdoc()
    ));
    // A declaration clears the publication refusal and nothing else: the
    // stranger's DECLARED deposit at the edition's fresh position — the one
    // insert publication admits — still meets ω.
    assert!(matches!(
        rejected(vs.insert(p2, &pdoc(), vp(1, 4), vec![val(b"x")], declared())),
        InsertError::NotOwner(d) if d == pdoc()
    ));
    let never_minted_member = a(&[1, 0, 1, 0, 3, 7]);
    assert!(matches!(
        rejected(vs.insert(P1, &never_minted_member, vp(1, 1), vec![val(b"x")], Deposit::Undeclared)),
        InsertError::DocNotRegistered
    ));
    assert!(matches!(
        rejected(vs.delete(P1, &never_minted_member, vp(1, 1), n(1))),
        DeleteError::DocNotRegistered
    ));
    assert!(matches!(
        rejected(vs.rearrange(P1, &never_minted_member, &[vp(1, 1), vp(1, 2), vp(1, 3)])),
        RearrangeError::DocNotRegistered
    ));
    assert!(matches!(
        rejected(vs.copy(P1, &never_minted_member, vp(1, 1), &[])),
        CopyError::DocNotRegistered
    ));
    assert!(matches!(
        rejected(vs.version(PrincipalId(1), &never_minted_member, None)),
        VersionError::SourceNotRegistered
    ));
}

#[test]
fn a_declared_deposit_at_a_fresh_position_clears_the_refusal() {
    // PUB-2.59 / PUB-2.61 / PUB-2.63 / PUB-9.13 (DECLARED): the deposit's
    // untyped first `insert` carries a declaration, and a DECLARED insert at
    // FRESH positions of a published head is admitted — appending, disturbing
    // no arrangement. The declaration exempts nothing by itself: the shape
    // must bear it out.
    let k = mem_kernel();
    let vs = Vstream::new(&k);
    let (start, _) = vs
        .insert(P1, &pdoc(), vp(1, 1), vec![val(b"atom")], declared())
        .expect("the first deposit lands at the empty edition's fresh position 1");
    assert_eq!(start, pca(1));
    vs.insert(P1, &pdoc(), vp(1, 2), vec![val(b"x"), val(b"y")], declared())
        .expect("a later deposit appends past the arranged extent");
    assert_eq!(k.snapshot().world().m5().content_count(&pdoc()), n(3));
    // Declared, but touching an ARRANGED position: refused with PUB-2.11's
    // code — never a bypass.
    let before = k.current_seq();
    assert!(matches!(
        rejected(vs.insert(P1, &pdoc(), vp(1, 2), vec![val(b"z")], declared())),
        InsertError::PublishedTarget
    ));
    assert!(matches!(
        rejected(vs.insert(P1, &pdoc(), vp(1, 3), vec![val(b"z")], declared())),
        InsertError::PublishedTarget
    ));
    // Declared in the LINK subspace: not a deposit shape at all.
    assert!(matches!(
        rejected(vs.insert(P1, &pdoc(), vp(2, 4), vec![val(b"z")], declared())),
        InsertError::PublishedTarget
    ));
    // Declared past the append boundary: fresh, so the refusal is cleared
    // and the op's own shape check answers.
    assert!(matches!(
        rejected(vs.insert(P1, &pdoc(), vp(1, 9), vec![val(b"z")], declared())),
        InsertError::OutOfBounds
    ));
    // Declared with nothing to deposit: the shape check after the refusal.
    assert!(matches!(
        rejected(vs.insert(P1, &pdoc(), vp(1, 4), vec![], declared())),
        InsertError::EmptyContent
    ));
    assert_eq!(k.current_seq(), before);
    // Into a PRIVATE document the declaration is inert: declared or not,
    // fresh or interior, whatever type it names, the insert is an ordinary
    // draft edit.
    insert_abc(&k);
    vs.insert(P1, &doc1(), vp(1, 4), vec![val(b"d")], declared())
        .expect("a declared append into a draft commits");
    vs.insert(P1, &doc1(), vp(1, 2), vec![val(b"i")], declared())
        .expect("a declared interior insert into a draft commits — the declaration is inert there");
    vs.insert(P1, &doc1(), vp(1, 6), vec![val(b"g")], Deposit::Declared(pdoc()))
        .expect("a declaration naming no class type is as inert in a draft as one naming a held type");
    assert_eq!(k.snapshot().world().m5().content_count(&doc1()), n(6));
}

#[test]
fn the_declaration_names_the_class_and_the_door_admits_a_held_type_alone() {
    // PUB-2.11 / PUB-2.64 (RES-249, RES-261): the declaration carries the
    // record class's TYPE, and a declared insert on a published target is
    // admitted only where that type is one the deposit class holds — today
    // ENROLL and RETIRE, the two classes that deposit an atom.
    let k = mem_kernel();
    let vs = Vstream::new(&k);
    let (enroll_start, _) = vs
        .insert(P1, &pdoc(), vp(1, 1), vec![val(b"an enrollment record")], Deposit::Declared(enroll_ty()))
        .expect("a declared ENROLL atom at a fresh position is admitted");
    assert_eq!(enroll_start, pca(1));
    let (retire_start, _) = vs
        .insert(P1, &pdoc(), vp(1, 2), vec![val(b"a retire record")], Deposit::Declared(retire_ty()))
        .expect("a declared RETIRE atom at a fresh position is admitted");
    assert_eq!(retire_start, pca(2));
    // A declared NON-member at the one position a member is admitted at: the
    // classes whose deposit is their typed link alone — the grant (`3.90`),
    // the edition claim (`3.14`), `successor-of` (`3.59`), the claim link
    // (`3.3`) — deposit no atom, and the deposit class never holds their
    // types; a SUBTYPE beneath a member is no member, membership being
    // equality; and an address that is no type at all — the target itself,
    // its own content, an account — is none either. Each answers as an
    // undeclared append does.
    let commons = |ordinal: u32| a(&[1, 1, 0, 1, 0, 1, 0, 3, ordinal]);
    let before = k.current_seq();
    let non_members = [
        ("the grant type", commons(90)),
        ("the edition-claim type", commons(14)),
        ("successor-of", commons(59)),
        ("the claim link's type", commons(3)),
        ("a subtype beneath ENROLL", a(&[1, 1, 0, 1, 0, 1, 0, 3, 1, 1])),
        ("the first unallocated commons ordinal", commons(4)),
        ("the target itself", pdoc()),
        ("the target's own content", pca(1)),
        ("an account", a(&[1, 0, 1])),
    ];
    for (name, ty) in non_members {
        assert!(
            matches!(
                rejected(vs.insert(P1, &pdoc(), vp(1, 3), vec![val(b"prose")], Deposit::Declared(ty))),
                InsertError::PublishedTarget
            ),
            "{name}"
        );
    }
    // The class test is the store's and is caller-blind: no ω check stands
    // on the System path, and the type test still does.
    assert!(matches!(
        rejected(vs.insert(Caller::System, &pdoc(), vp(1, 3), vec![val(b"s")], Deposit::Declared(commons(90)))),
        InsertError::PublishedTarget
    ));
    // The two shape clauses stand beside it, unmoved: a declared MEMBER at
    // an arranged position, and an UNDECLARED append at the fresh one.
    assert!(matches!(
        rejected(vs.insert(P1, &pdoc(), vp(1, 2), vec![val(b"z")], Deposit::Declared(retire_ty()))),
        InsertError::PublishedTarget
    ));
    assert!(matches!(
        rejected(vs.insert(P1, &pdoc(), vp(1, 3), vec![val(b"z")], Deposit::Undeclared)),
        InsertError::PublishedTarget
    ));
    assert_eq!(k.current_seq(), before, "a refused declaration commits nothing");
    assert_eq!(k.snapshot().world().m5().content_count(&pdoc()), n(2));
    // A non-member's refusal is the TARGET's, ahead of the op's own shape
    // checks — where a member past the append boundary is told its position
    // is bad, a non-member there is told its target is published.
    assert!(matches!(
        rejected(vs.insert(P1, &pdoc(), vp(1, 9), vec![val(b"z")], Deposit::Declared(commons(90)))),
        InsertError::PublishedTarget
    ));
    assert!(matches!(
        rejected(vs.insert(P1, &pdoc(), vp(1, 9), vec![val(b"z")], Deposit::Declared(enroll_ty()))),
        InsertError::OutOfBounds
    ));
}

#[test]
fn the_door_admits_a_declared_type_exactly_when_it_equals_a_held_type() {
    // RES-249: membership in the deposit class is EQUALITY — a subtype
    // beneath a member is no member, and nothing ABOVE one is either. Asked
    // of every address one step from a member in the tumbler tree, generated
    // rather than chosen: each T4-valid PREFIX of each member (its type
    // subspace, the ghost home document, that document's account, its node),
    // each member, each member's first CHILD, and the two commons ordinals
    // beside them — at the one position a published document admits a
    // deposit. A door testing containment in either direction, or the
    // document or subspace a type lies in, admits one of these.
    let k = mem_kernel();
    let vs = Vstream::new(&k);
    let mut family: Vec<Address> = Vec::new();
    for member in [enroll_ty(), retire_ty()] {
        let comps: Vec<Nat> = member.tumbler().iter().cloned().collect();
        for len in 1..=comps.len() {
            let prefix = Tumbler::new(comps[..len].iter().cloned()).expect("a prefix is nonempty");
            if let Ok(address) = validate(prefix) {
                family.push(address);
            }
        }
        let child = Tumbler::new(comps.iter().cloned().chain([n(1)])).expect("nonempty");
        family.push(validate(child).expect("a member's child is T4-valid"));
    }
    family.extend([3, 4].map(|ordinal| a(&[1, 1, 0, 1, 0, 1, 0, 3, ordinal])));
    family.sort();
    family.dedup();
    assert_eq!(family.len(), 11, "five shared prefixes, two members, two children, two siblings");
    let mut admitted: Vec<Address> = Vec::new();
    for ty in &family {
        let held = *ty == enroll_ty() || *ty == retire_ty();
        let n_c = k.snapshot().world().m5().content_count(&pdoc());
        let at = VPos::content(&n_c + &n(1));
        match vs.insert(P1, &pdoc(), at, vec![val(b"x")], Deposit::Declared(ty.clone())) {
            Ok(_) => admitted.push(ty.clone()),
            Err(TxnError::Rejected(InsertError::PublishedTarget)) => {}
            Err(other) => panic!("{ty:?}: expected an admission or PublishedTarget, got {other:?}"),
        }
        assert_eq!(admitted.contains(ty), held, "{ty:?}: admitted exactly when it equals a held type");
    }
    assert_eq!(admitted, vec![enroll_ty(), retire_ty()]);
}

#[test]
fn a_version_member_target_is_judged_as_its_document() {
    // PUB-2.15 on the four edits: a member of a PUBLISHED document is refused
    // whatever its own journaled bit says, and a member of a PRIVATE document
    // is edited whatever its own says — the fixture's members carry the
    // contradicting bits, so this cannot pass by reading the member.
    let k = mem_kernel_of(genesis_with_members());
    let vs = Vstream::new(&k);
    let member_of_edition = a(&[1, 0, 1, 0, 3, 1]);
    let member_of_draft = a(&[1, 0, 1, 0, 1, 1]);
    assert!(matches!(
        rejected(vs.insert(P1, &member_of_edition, vp(1, 1), vec![val(b"x")], Deposit::Undeclared)),
        InsertError::PublishedTarget
    ));
    assert!(matches!(
        rejected(vs.delete(P1, &member_of_edition, vp(1, 1), n(1))),
        DeleteError::PublishedTarget
    ));
    assert!(matches!(
        rejected(vs.rearrange(P1, &member_of_edition, &[vp(1, 1), vp(1, 2), vp(1, 3)])),
        RearrangeError::PublishedTarget
    ));
    assert!(matches!(
        rejected(vs.copy(P1, &member_of_edition, vp(1, 1), &[])),
        CopyError::PublishedTarget
    ));
    // A declared deposit into the member of the edition is admitted (it is
    // the head's exempt act) — the member's own bit decides nothing either way.
    vs.insert(P1, &member_of_edition, vp(1, 1), vec![val(b"atom")], declared())
        .expect("a declared deposit into a published document's member commits");
    // The private document's member takes every edit.
    let (start, _) = vs
        .insert(P1, &member_of_draft, vp(1, 1), vec![val(b"a"), val(b"b")], Deposit::Undeclared)
        .expect("a private document's member is edited in place");
    assert_eq!(start, a(&[1, 0, 1, 0, 1, 1, 0, 1, 1]));
    vs.delete(P1, &member_of_draft, vp(1, 1), n(1))
        .expect("delete in a private document's member commits");
}

#[test]
fn an_accounts_home_is_a_published_target_from_its_flagless_first_mint() {
    // PUB-8.21 composed with PUB-2.11, through M3's REAL create path rather
    // than a bit the fixture stamps itself: the flagless first mint into an
    // empty account is the account's HOME, born published, so the write path
    // treats it as it treats any edition — an undeclared insert refuses, and
    // content enters it only by a DECLARED deposit at a fresh position
    // (PUB-2.59, PUB-9.13). The account's next flagless mint is private by
    // default (PUB-1.1) and takes an ordinary insert. This is the seam a
    // fixture writer meets first: a home minted and then inserted into
    // undeclared is refused, and that is the rule working.
    let k = mem_kernel();
    let ns = Namespace::new(&k);
    let vs = Vstream::new(&k);
    let p2 = Caller::Principal(PrincipalId(2));
    // Principal 2's account holds no documents at genesis.
    let p2_account = a(&[1, 0, 2]);
    let (home, _) = ns
        .create_new_document(PrincipalId(2), &p2_account, None)
        .expect("the flagless first mint into an empty account commits");
    assert_eq!(home, a(&[1, 0, 2, 0, 1]));
    assert!(
        k.snapshot().world().m3().published(&home),
        "the flagless first mint is the home, born published (PUB-8.21)"
    );
    let before = k.current_seq();
    assert!(matches!(
        rejected(vs.insert(p2, &home, vp(1, 1), vec![val(b"hi")], Deposit::Undeclared)),
        InsertError::PublishedTarget
    ));
    assert_eq!(k.current_seq(), before, "the refusal commits nothing");
    let (start, _) = vs
        .insert(p2, &home, vp(1, 1), vec![val(b"hi")], declared())
        .expect("a declared deposit at the home's fresh position commits");
    assert_eq!(start, a(&[1, 0, 2, 0, 1, 0, 1, 1]));
    assert_eq!(k.snapshot().world().m5().content_count(&home), n(1));
    // The account's SECOND flagless mint is a draft: an undeclared insert is
    // admitted there as into any private document.
    let (draft, _) = ns
        .create_new_document(PrincipalId(2), &p2_account, None)
        .expect("a later flagless mint into the account commits");
    assert_eq!(draft, a(&[1, 0, 2, 0, 2]));
    assert!(
        !k.snapshot().world().m3().published(&draft),
        "a later flagless mint is private by default (PUB-1.1)"
    );
    vs.insert(p2, &draft, vp(1, 1), vec![val(b"hi")], Deposit::Undeclared)
        .expect("an undeclared insert into the account's draft commits");
}
