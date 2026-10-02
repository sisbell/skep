//! The ownership gate (as amended 2026-08-16): ω exact in both directions,
//! registration before ownership, the System caller's one exemption, and
//! transclusion's foreign sources.

use skep_arrangement::{
    Caller, CopyError, DeleteError, Deposit, HasM5, InsertError, PublishError, RearrangeError, Shot,
    VSpec, Vstream,
};
use skep_namespace::PrincipalId;

use crate::common::*;

#[test]
fn edit_ops_reject_a_sibling_principal_and_commit_nothing() {
    // The probe matrix, store-level: sibling principal 2 (account [1,0,2])
    // against P1's doc1 — insert / delete / rearrange / copy-DEST all reject
    // NotOwner carrying doc1; each rejection is a clean no-op; the owner's
    // identical op still commits.
    let k = mem_kernel();
    let vs = insert_abc(&k);
    let p2 = Caller::Principal(PrincipalId(2));
    let before = k.current_seq();
    assert!(matches!(
        rejected(vs.insert(p2, &doc1(), vp(1, 4), vec![val(b"x")], Deposit::Undeclared)),
        InsertError::NotOwner(d) if d == doc1()
    ));
    assert!(matches!(
        rejected(vs.delete(p2, &doc1(), vp(1, 1), n(1))),
        DeleteError::NotOwner(d) if d == doc1()
    ));
    assert!(matches!(
        rejected(vs.rearrange(p2, &doc1(), &[vp(1, 1), vp(1, 2), vp(1, 3)])),
        RearrangeError::NotOwner(d) if d == doc1()
    ));
    assert!(matches!(
        rejected(vs.copy(
            p2,
            &doc1(),
            vp(1, 4),
            &[VSpec {
                source: doc1(),
                span: vspan(1, 1, 1),
            }]
        )),
        CopyError::NotOwner(d) if d == doc1()
    ));
    // The ω gate precedes every shape check INSERT makes: an empty value
    // list from a non-owner is refused as NotOwner, not as EmptyContent.
    assert!(matches!(
        rejected(vs.insert(p2, &doc1(), vp(1, 1), vec![], Deposit::Undeclared)),
        InsertError::NotOwner(d) if d == doc1()
    ));
    assert_eq!(k.current_seq(), before, "ownership rejections leave no state change");
    vs.delete(P1, &doc1(), vp(1, 1), n(1))
        .expect("the owner's delete still commits");
}

#[test]
fn an_unregistered_document_never_yields_an_ownership_verdict() {
    // `gate_write`'s order, and the reason for it: a write aimed at an
    // address that names no document is refused for that, and the caller
    // learns nothing about who would have owned it. The caller MUST be one
    // that fails the ω check — ω of an unregistered address still resolves
    // by longest registered prefix, so P1 owns [1,0,1,0,9] and would pass,
    // leaving both orders agreeing on DocNotRegistered.
    let k = mem_kernel();
    let vs = insert_abc(&k);
    let unregistered_doc = a(&[1, 0, 1, 0, 9]);
    let p2 = Caller::Principal(PrincipalId(2));
    assert!(matches!(
        rejected(vs.insert(p2, &unregistered_doc, vp(1, 1), vec![val(b"x")], Deposit::Undeclared)),
        InsertError::DocNotRegistered
    ));
    assert!(matches!(
        rejected(vs.delete(p2, &unregistered_doc, vp(1, 1), n(1))),
        DeleteError::DocNotRegistered
    ));
    assert!(matches!(
        rejected(vs.rearrange(p2, &unregistered_doc, &[vp(1, 1), vp(1, 2), vp(1, 3)])),
        RearrangeError::DocNotRegistered
    ));
    assert!(matches!(
        rejected(vs.copy(
            p2,
            &unregistered_doc,
            vp(1, 1),
            &[VSpec {
                source: doc1(),
                span: vspan(1, 1, 1),
            }]
        )),
        CopyError::DocNotRegistered
    ));
    // The shot opens at the same door: its slot 1 answers registration
    // before ω, and the other order would answer `NotOwner(unregistered_doc)`.
    assert!(matches!(
        rejected(vs.publish(
            p2,
            &unregistered_doc,
            Shot { base: None, draft: None, runs: vec![] },
            &readable_by(PrincipalId(2))
        )),
        PublishError::DocNotRegistered
    ));
}

#[test]
fn the_system_caller_bypasses_the_owner_check_but_not_registration() {
    // `Caller::System` is the in-process automation path (M9's rule firings
    // and predicate-def writes), exempt from ω by architecture rather than
    // by omission — it carries no principal, so ω could never match it. The
    // exemption is exactly one check wide: registration still gates, and so
    // does publication (`in_place_edits_refuse_a_published_target_and_commit_nothing`).
    let k = mem_kernel();
    let vs = Vstream::new(&k);
    let (start, _) = vs
        .insert(Caller::System, &doc1(), vp(1, 1), vec![val(b"s")], Deposit::Undeclared)
        .expect("the automation path writes without a principal");
    assert_eq!(start, ca(1));
    assert_eq!(
        k.snapshot().world().m5().point(&doc1(), &vp(1, 1)),
        Some(ca(1))
    );
    // And into a document owned by a different principal — the exemption is
    // not "System happens to own this one".
    let subdoc = a(&[1, 0, 1, 1, 0, 1]);
    vs.insert(Caller::System, &subdoc, vp(1, 1), vec![val(b"s")], Deposit::Undeclared)
        .expect("no document's ω restricts the automation path");
    // Registration is not waived.
    assert!(matches!(
        rejected(vs.insert(Caller::System, &a(&[1, 0, 1, 0, 9]), vp(1, 1), vec![val(b"x")], Deposit::Undeclared)),
        InsertError::DocNotRegistered
    ));
}

#[test]
fn ownership_is_exact_in_both_directions() {
    // Exclusive delegation (ASN-0042 O2/O3/O8): ω is EXACT account match,
    // never prefix containment — the parent account's principal does not own
    // the sub-delegated account's document, and the sub-account's principal
    // does not own the parent's.
    let k = mem_kernel();
    let vs = insert_abc(&k);
    let sub = Caller::Principal(PrincipalId(3)); // account [1,0,1,1], under [1,0,1]
    let subdoc = a(&[1, 0, 1, 1, 0, 1]);
    // Sub-delegated child vs the parent's doc.
    assert!(matches!(
        rejected(vs.insert(sub, &doc1(), vp(1, 4), vec![val(b"x")], Deposit::Undeclared)),
        InsertError::NotOwner(_)
    ));
    // Parent vs the child's doc.
    assert!(matches!(
        rejected(vs.insert(P1, &subdoc, vp(1, 1), vec![val(b"x")], Deposit::Undeclared)),
        InsertError::NotOwner(_)
    ));
    // The sub-account's own principal edits its own doc.
    vs.insert(sub, &subdoc, vp(1, 1), vec![val(b"s")], Deposit::Undeclared)
        .expect("sub-owner insert commits");
}

#[test]
fn copy_reads_foreign_sources_into_an_owned_destination() {
    // Transclusion is unrestricted by ownership: only the DESTINATION is
    // ω-gated. Principal 2 forks P1's empty doc2 into its own account
    // (denial-as-fork, O10), then transcludes P1's doc1 content into it —
    // and both are P1's PRIVATE drafts. M5 admits both because readability
    // is the caller's gate (PUB-6.23), which this suite, driving M5
    // directly, does not run; on the wire M10's pre-dispatch consult would
    // refuse both as `withheld`.
    let k = mem_kernel();
    let vs = insert_abc(&k);
    let p2 = Caller::Principal(PrincipalId(2));
    let (fork, _) = vs
        .version(PrincipalId(2), &doc2(), None)
        .expect("cross-owner fork commits");
    vs.copy(
        p2,
        &fork,
        vp(1, 1),
        &[VSpec {
            source: doc1(),
            span: vspan(1, 1, 2),
        }],
    )
    .expect("foreign-SOURCE copy into an owned destination commits");
    let s = k.snapshot();
    assert_eq!(s.world().m5().content_count(&fork), n(2));
    // A PUBLISHED source is transcluded as freely (PUB-2.28's copy is what
    // stages a published head into a draft).
    deposit_abc(&k);
    vs.copy(
        p2,
        &fork,
        vp(1, 3),
        &[VSpec {
            source: pdoc(),
            span: vspan(1, 1, 3),
        }],
    )
    .expect("a published source is copied into a draft");
    assert_eq!(k.snapshot().world().m5().content_count(&fork), n(5));
}
