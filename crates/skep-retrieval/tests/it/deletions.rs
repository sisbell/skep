//! §D SHOWDELETIONS (ASN-0075): each half the existing addresses deleted from
//! one document and current in the other, deduplicated and T1-ordered, read
//! off the addresses as named.

use skep_arrangement::VSpec;
use skep_namespace::PrincipalId;
use skep_retrieval::{Deletions, DeletionsError, Delivery, DeliveryItem, Query};

use crate::common::*;

#[test]
fn show_deletions_reports_the_existing_addresses_deleted_from_one_current_in_the_other() {
    // ASN-0075 D-IDENT: each half is a set of the EXISTING I-addresses
    // deleted-from-one ∧ current-in-the-other, listed deduplicated and
    // T1-ascending (M6's presentation); slot semantics follow the argument
    // order.
    let k = mem_kernel();
    let vs = insert3(&k);
    vs.copy(
        P1,
        &doc2(),
        vp(1, 1),
        &[VSpec {
            source: doc1(),
            span: vspan(1, 1, 2),
        }],
    )
    .expect("copy commits"); // doc2 = [ca1, ca2]
    vs.delete(P1, &doc1(), vp(1, 2), n(1)).expect("delete commits"); // doc1 = [ca1, ca3]; deleted ca2
    vs.delete(P1, &doc2(), vp(1, 1), n(1)).expect("delete commits"); // doc2 = [ca2]; deleted ca1
    let s = k.snapshot();
    let q = Query::new(&s);
    let got = ok_of(q.show_deletions(&doc1(), &doc2()));
    assert_eq!(
        got,
        Deletions {
            deleted_from_a_with_b: vec![ca(2)], // deleted from doc1, current in doc2
            deleted_from_b_with_a: vec![ca(1)], // deleted from doc2, current in doc1
        }
    );
    // Swapping the arguments swaps the halves.
    let got = ok_of(q.show_deletions(&doc2(), &doc1()));
    assert_eq!(
        got,
        Deletions {
            deleted_from_a_with_b: vec![ca(1)],
            deleted_from_b_with_a: vec![ca(2)],
        }
    );
}

#[test]
fn show_deletions_dedups_multiplicity_and_admits_empty_documents() {
    // ASN-0075: intra-document transclusion multiplicity collapses (sets,
    // not bags); registered-empty documents are admissible with empty halves;
    // an unregistered document is the typed failure (d_a checked first).
    let k = mem_kernel();
    {
        // Registered-but-empty on both sides ⇒ empty halves.
        let s = k.snapshot();
        let q = Query::new(&s);
        let got = ok_of(q.show_deletions(&doc1(), &doc2()));
        assert_eq!(
            got,
            Deletions {
                deleted_from_a_with_b: vec![],
                deleted_from_b_with_a: vec![],
            }
        );
        assert!(matches!(
            err_of(q.show_deletions(&unregistered(), &doc1())),
            DeletionsError::DocNotRegistered(d) if d == unregistered()
        ));
        assert!(matches!(
            err_of(q.show_deletions(&doc1(), &unregistered())),
            DeletionsError::DocNotRegistered(d) if d == unregistered()
        ));
    }
    let vs = insert3(&k);
    // doc2 holds ca1 TWICE; doc1 then deletes ca1.
    vs.copy(
        P1,
        &doc2(),
        vp(1, 1),
        &[VSpec {
            source: doc1(),
            span: vspan(1, 1, 1),
        }],
    )
    .expect("copy commits");
    vs.copy(
        P1,
        &doc2(),
        vp(1, 2),
        &[VSpec {
            source: doc1(),
            span: vspan(1, 1, 1),
        }],
    )
    .expect("copy commits");
    vs.delete(P1, &doc1(), vp(1, 1), n(1)).expect("delete commits");
    let s = k.snapshot();
    let q = Query::new(&s);
    let got = ok_of(q.show_deletions(&doc1(), &doc2()));
    // ca1 appears ONCE despite doc2's double placement (dedup — the halves
    // are set comprehensions).
    assert_eq!(
        got,
        Deletions {
            deleted_from_a_with_b: vec![ca(1)],
            deleted_from_b_with_a: vec![],
        }
    );
}

#[test]
fn show_deletions_excludes_an_address_a_document_deleted_and_holds_again() {
    // DELETED is present-tense — (a, d) ∈ R ∧ a ∉ ran(M(d)) — so an address
    // a document dropped and took back is current there, not deleted. A
    // record of delete EVENTS would list it; the relation minus the
    // arrangement does not.
    let k = mem_kernel();
    let vs = insert3(&k); // doc1 = [ca1, ca2, ca3]
    vs.copy(
        P1,
        &doc2(),
        vp(1, 1),
        &[VSpec {
            source: doc1(),
            span: vspan(1, 1, 1),
        }],
    )
    .expect("copy commits"); // doc2 = [ca1]
    vs.delete(P1, &doc1(), vp(1, 1), n(1))
        .expect("delete commits"); // doc1 = [ca2, ca3]
    {
        let s = k.snapshot();
        let q = Query::new(&s);
        assert_eq!(
            ok_of(q.show_deletions(&doc1(), &doc2())),
            Deletions {
                deleted_from_a_with_b: vec![ca(1)],
                deleted_from_b_with_a: vec![],
            }
        );
    }
    vs.copy(
        P1,
        &doc1(),
        vp(1, 3),
        &[VSpec {
            source: doc2(),
            span: vspan(1, 1, 1),
        }],
    )
    .expect("copy commits"); // doc1 = [ca2, ca3, ca1]: ca1 is back
    let s = k.snapshot();
    let q = Query::new(&s);
    assert_eq!(
        ok_of(q.show_deletions(&doc1(), &doc2())),
        Deletions::default()
    );
}

#[test]
fn show_deletions_orders_a_multi_address_half_by_tumbler_not_by_arrangement() {
    // A half is the whole set, listed T1-ascending — never the order the
    // containing document happens to arrange it in, which is D-ORD's own
    // clause that the operation takes no input ordering to preserve; the
    // T1 listing itself is M6's presentation. doc2 holds ca2 BEFORE ca1
    // after the rearrange, so arrangement order and T1 order disagree and
    // only one of them is the documented answer.
    let k = mem_kernel();
    let vs = insert3(&k); // doc1 = [ca1, ca2, ca3]
    vs.copy(
        P1,
        &doc2(),
        vp(1, 1),
        &[VSpec {
            source: doc1(),
            span: vspan(1, 1, 2),
        }],
    )
    .expect("copy commits"); // doc2 = [ca1, ca2]
    vs.rearrange(P1, &doc2(), &[vp(1, 1), vp(1, 2), vp(1, 3)])
        .expect("rearrange commits"); // doc2 = [ca2, ca1]
    vs.delete(P1, &doc1(), vp(1, 1), n(3))
        .expect("delete commits"); // doc1 drops all three
    let s = k.snapshot();
    let q = Query::new(&s);
    assert_eq!(
        ok_of(q.show_deletions(&doc1(), &doc2())),
        Deletions {
            // Enumerated from doc2 as [ca2, ca1] and returned SORTED; ca3 is
            // deleted from doc1 but not current in doc2, so it is not in the
            // half.
            deleted_from_a_with_b: vec![ca(1), ca(2)],
            deleted_from_b_with_a: vec![],
        }
    );
}

#[test]
fn show_deletions_names_the_first_unregistered_document() {
    // §Errors: both documents must be registered and `d_a` is checked FIRST,
    // so the rejection follows the ARGUMENT ORDER, not whichever address
    // happens to be looked at first.
    let k = mem_kernel();
    insert3(&k);
    let s = k.snapshot();
    let q = Query::new(&s);
    assert_eq!(
        err_of(q.show_deletions(&unregistered(), &unregistered2())),
        DeletionsError::DocNotRegistered(unregistered())
    );
    assert_eq!(
        err_of(q.show_deletions(&unregistered2(), &unregistered())),
        DeletionsError::DocNotRegistered(unregistered2())
    );
}

#[test]
fn show_deletions_enumerates_the_address_named_and_does_not_float() {
    // Crate doc, *Which arrangement an operation answers from*: SHOWDELETIONS
    // reads the arrangement of the address NAMED. CURRENT(·, pdoc) is pdoc's
    // own, not its head's — so an address the head holds and pdoc does not is
    // in neither half under pdoc's name, and is in one under the head's.
    let k = mem_kernel();
    let vs = deposit3(&k); // pdoc = [pca1, pca2, pca3]
    let (fork, _) = vs
        .version(PrincipalId(1), &pdoc(), None)
        .expect("fork commits");
    let (start, _) = vs
        .insert(P1, &fork, vp(1, 4), vec![val(b"z")], declared())
        .expect("head deposit commits");
    assert_eq!(start, vca(1)); // the head holds vca1 at V4; pdoc's own arrangement never will
    vs.copy(
        P1,
        &doc1(),
        vp(1, 1),
        &[VSpec {
            source: fork.clone(),
            span: vspan(1, 4, 1),
        }],
    )
    .expect("copy commits"); // doc1 = [vca1]
    vs.delete(P1, &doc1(), vp(1, 1), n(1))
        .expect("delete commits"); // DELETED(vca1, doc1)
    let s = k.snapshot();
    let q = Query::new(&s);
    // The premise: a floating reader delivers the head's fourth byte under
    // pdoc's name.
    assert_eq!(
        ok_of(q.retrieve_v(&[spec(pdoc(), vspan(1, 4, 1))])),
        Delivery(vec![DeliveryItem::Content(val(b"z"))])
    );
    // Named the head, vca1 is current there and deleted from doc1.
    assert_eq!(
        ok_of(q.show_deletions(&doc1(), &fork)),
        Deletions {
            deleted_from_a_with_b: vec![vca(1)],
            deleted_from_b_with_a: vec![],
        }
    );
    // Named pdoc, its OWN arrangement is read, and it holds no vca1.
    assert_eq!(
        ok_of(q.show_deletions(&doc1(), &pdoc())),
        Deletions::default()
    );
}
