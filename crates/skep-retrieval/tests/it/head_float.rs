//! Which arrangement an operation answers from (crate doc): a published
//! address floats to its trunk head, a pinned member answers its own, and
//! registered-empty is decided of the surface — every floating operation
//! moving with the head, and FINDDOCSCONTAINING not.

use skep_address::{Address, SpanSet};
use skep_arrangement::{HasM5, Vstream};
use skep_namespace::PrincipalId;
use skep_retrieval::{Delivery, DeliveryItem, OriginError, Query};

use crate::common::*;

#[test]
fn a_published_address_answers_from_its_trunk_head_once_it_has_one() {
    // Head-float (PUB-2.49/2.53), the policy the crate doc states under
    // *Which arrangement an operation answers from*: a bare PUBLISHED address
    // is gated and reported under its own name and answers its trunk head's
    // arrangement — its own while memberless. Every floating operation moves
    // when the head does; the head, a version address, answers itself; and
    // the two that do not float keep answering the address named.
    let k = mem_kernel();
    let vs = deposit3(&k); // pdoc = [a, b, c], memberless
    {
        let s = k.snapshot();
        let q = Query::new(&s);
        // Memberless: its own arrangement.
        assert_eq!(
            ok_of(q.doc_vspanset(&pdoc())),
            SpanSet::singleton(vspan(1, 1, 3))
        );
    }
    let (fork, _) = vs.version(PrincipalId(1), &pdoc(), None).expect("fork commits");
    assert_eq!(fork, vdoc()); // the trunk's first member, and so its head
    vs.insert(P1, &fork, vp(1, 4), vec![val(b"z")], declared())
        .expect("fork deposit commits"); // head = [a, b, c, z]
    let s = k.snapshot();
    let q = Query::new(&s);
    // The extents: pdoc named, the head answers — four positions, not three.
    assert_eq!(
        ok_of(q.doc_vspanset(&pdoc())),
        SpanSet::singleton(vspan(1, 1, 4))
    );
    assert_eq!(
        ok_of(q.doc_vspan(&pdoc())),
        SpanSet::singleton(vspan(1, 1, 4))
    );
    // The delivery: the head's fourth byte, delivered under pdoc's name.
    assert_eq!(
        ok_of(q.retrieve_v(&[spec(pdoc(), vspan(1, 1, 4))])),
        Delivery(vec![
            DeliveryItem::Content(val(b"a")),
            DeliveryItem::Content(val(b"b")),
            DeliveryItem::Content(val(b"c")),
            DeliveryItem::Content(val(b"z")),
        ])
    );
    // The origins: the head's fourth run was allocated by the fork.
    assert_eq!(
        ok_of(q.show_origin_v(&pdoc(), &vspan(1, 1, 4))),
        vec![pdoc(), vdoc()]
    );
    // COMPARE: both regions resolve against the one head arrangement, and the
    // feet still NAME the addresses asked about — pdoc on one side, the fork
    // on the other — at positions that agree.
    let rep = ok_of(q.compare(
        &[region_spec(pdoc(), vec![vspan(1, 1, 4)])],
        &[region_spec(fork.clone(), vec![vspan(1, 1, 4)])],
    ));
    assert_eq!(rep.len(), 2, "one pair per run of the shared arrangement");
    assert!(rep
        .iter()
        .all(|c| c.d1 == pdoc() && c.d2 == fork && c.u1 == c.u2));
    // The head answers itself, so the two names read one arrangement.
    assert_eq!(ok_of(q.doc_vspanset(&fork)), ok_of(q.doc_vspanset(&pdoc())));
    // FINDDOCSCONTAINING does not float: pdoc's OWN arrangement has no fourth
    // position, so a region naming it covers nothing — where the head's would
    // have named the fork. This is the seam the crate doc records.
    assert_eq!(
        ok_of(q.find_docs_containing(&[region_spec(pdoc(), vec![vspan(1, 4, 1)])])),
        Vec::<Address>::new()
    );
    assert_eq!(
        ok_of(q.find_docs_containing(&[region_spec(fork, vec![vspan(1, 4, 1)])])),
        vec![vdoc()]
    );
}

#[test]
fn a_published_address_with_an_empty_arrangement_of_its_own_reports_its_head() {
    // The two decisions every operation opens with, at their intersection:
    // registered-empty is decided of the SURFACE, not of the address named.
    // A published document that holds nothing itself reports the empty form
    // only while it is memberless — or while its head is empty too; once the
    // head holds content, the bare address answers the head's, its own
    // arrangement still empty. `version` admits an empty surface, so this is
    // the edition-then-fork shape, not a contrivance.
    let k = mem_kernel();
    let vs = Vstream::new(&k);
    {
        let s = k.snapshot();
        let q = Query::new(&s);
        // Memberless and empty: the registered-empty form, under its own name.
        assert_eq!(ok_of(q.doc_vspanset(&pdoc())), SpanSet::empty());
        assert_eq!(
            ok_of(q.retrieve_v(&[spec(pdoc(), vspan(1, 1, 1))])),
            Delivery::default()
        );
        assert_eq!(
            err_of(q.show_origin_v(&pdoc(), &vspan(1, 1, 1))),
            OriginError::EmptySubspace
        );
    }
    let (fork, _) = vs
        .version(PrincipalId(1), &pdoc(), None)
        .expect("a fork of an empty surface commits");
    assert_eq!(fork, vdoc());
    {
        let s = k.snapshot();
        let q = Query::new(&s);
        // A head that is itself empty still answers ⟨⟩ — the emptiness is
        // the head's.
        assert_eq!(ok_of(q.doc_vspanset(&pdoc())), SpanSet::empty());
    }
    vs.insert(P1, &fork, vp(1, 1), vec![val(b"z")], declared())
        .expect("head deposit commits");
    let s = k.snapshot();
    let q = Query::new(&s);
    // The premise: pdoc's OWN arrangement still holds nothing.
    assert_eq!(s.world().m5().content_count(&pdoc()), n(0));
    // Named pdoc, the five floating operations answer the head's one
    // position.
    assert_eq!(
        ok_of(q.doc_vspanset(&pdoc())),
        SpanSet::singleton(vspan(1, 1, 1))
    );
    assert_eq!(
        ok_of(q.doc_vspan(&pdoc())),
        SpanSet::singleton(vspan(1, 1, 1))
    );
    assert_eq!(
        ok_of(q.retrieve_v(&[spec(pdoc(), vspan(1, 1, 1))])),
        Delivery(vec![DeliveryItem::Content(val(b"z"))])
    );
    assert_eq!(
        ok_of(q.show_origin_v(&pdoc(), &vspan(1, 1, 1))),
        vec![vdoc()]
    );
    assert_eq!(
        ok_of(q.compare(
            &[region_spec(pdoc(), vec![vspan(1, 1, 1)])],
            &[region_spec(fork, vec![vspan(1, 1, 1)])],
        ))
        .len(),
        1
    );
    // And the one that does not float reads the empty arrangement named.
    assert_eq!(
        ok_of(q.find_docs_containing(&[region_spec(pdoc(), vec![vspan(1, 1, 1)])])),
        Vec::<Address>::new()
    );
}

#[test]
fn a_pinned_member_answers_its_own_arrangement_after_the_head_moves_on() {
    // "A version address answers its own member, forever" (PUB-2.50), at the
    // one address that can tell M5's reading surface from its deposit surface
    // and from the trunk head: a member the chain has moved past. With one
    // member the three agree, which is why the head-float test cannot see
    // which of them M6 asks.
    let k = mem_kernel();
    let vs = deposit3(&k); // pdoc = [a, b, c]
    let (first, _) = vs
        .version(PrincipalId(1), &pdoc(), None)
        .expect("first fork commits");
    let (second, _) = vs
        .version(PrincipalId(1), &pdoc(), None)
        .expect("second fork commits");
    assert_eq!(first, vdoc());
    assert_eq!(second, a(&[1, 0, 1, 0, 3, 2])); // the trunk's second member, now its head
    vs.insert(P1, &second, vp(1, 4), vec![val(b"z")], declared())
        .expect("head deposit commits"); // head = [a, b, c, z]
    let s = k.snapshot();
    let q = Query::new(&s);
    // The bare address and the head read four positions…
    assert_eq!(
        ok_of(q.doc_vspanset(&pdoc())),
        SpanSet::singleton(vspan(1, 1, 4))
    );
    assert_eq!(
        ok_of(q.doc_vspanset(&second)),
        SpanSet::singleton(vspan(1, 1, 4))
    );
    // …and the pinned member its own three: an overrunning request clips at
    // ITS extent and SHOWORIGIN refuses past it, whatever the head holds.
    assert_eq!(
        ok_of(q.doc_vspanset(&first)),
        SpanSet::singleton(vspan(1, 1, 3))
    );
    assert_eq!(
        ok_of(q.retrieve_v(&[spec(first.clone(), vspan(1, 1, 4))])),
        Delivery(vec![
            DeliveryItem::Content(val(b"a")),
            DeliveryItem::Content(val(b"b")),
            DeliveryItem::Content(val(b"c")),
        ])
    );
    assert_eq!(
        err_of(q.show_origin_v(&first, &vspan(1, 1, 4))),
        OriginError::RangeNotPresent
    );
    // COMPARE, the fifth floating operation, at the same address: the pinned
    // member's region resolves ITS three positions, so against the head's
    // four there is one pair (the shared prefix) and not two — a compare that
    // asked M5's deposit surface would resolve `first` as the head and report
    // the head's fourth run against itself as well.
    let rep = ok_of(q.compare(
        &[region_spec(first.clone(), vec![vspan(1, 1, 4)])],
        &[region_spec(second.clone(), vec![vspan(1, 1, 4)])],
    ));
    assert_eq!(rep.len(), 1);
    let pair = &rep.as_slice()[0];
    assert_eq!(
        (pair.d1.clone(), pair.d2.clone(), pair.width.clone()),
        (first.clone(), second.clone(), n(3))
    );
}
