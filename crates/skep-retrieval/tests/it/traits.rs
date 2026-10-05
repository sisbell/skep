//! The derive policy, the marshaling seam M10 codes against: results and
//! errors serialize (`CorrPair`/`CompareReport` field by field), every
//! rejection is a `std::error::Error`, requests and fault vocabularies key a
//! map, the answer collections behave like std's, and the handle and its
//! answers cross threads.
//!
//! This binary compiles as a FOREIGN crate, so these tests witness the
//! derive policy's consequences: every result and every error M6 hands back
//! renders, so `assert_eq!` compiles against any of them in this binary
//! exactly as it does for M10 — a delivery included, whose content items
//! render by BYTE LENGTH and never by payload; each registry rejection's
//! message names the document it refused; and the two fault vocabularies
//! key a map, which is the derive a consumer could not supply for itself.

use std::collections::{HashMap, HashSet};

use skep_arrangement::VSpec;
use skep_retrieval::{
    CompareError, CompareReport, Deletions, DeletionsError, Delivery, DeliveryItem, ExtentError,
    FindError, Operand, OriginError, Query, RegionSpec, RetrieveError, SpanFault, Spec,
};

use crate::common::*;

#[test]
fn results_and_errors_marshal_through_serialize_per_the_derive_policy() {
    // §Public interface derive policy: results/errors are Serialize (the
    // derive policy's marshaling affordance; bincode is M2's actual wire
    // format, and the shipped codec marshals by hand); CorrPair/
    // CompareReport are not — they carry M5's VPos — and marshal
    // FIELD-BY-FIELD, every leaf serializing individually, VPos's Nat fields
    // included.
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
    .expect("copy commits");
    let s = k.snapshot();
    let q = Query::new(&s);
    let delivery = ok_of(q.retrieve_v(&[spec(doc1(), vspan(1, 1, 3))]));
    assert!(!bincode::serialize(&delivery).expect("Delivery serializes").is_empty());
    let extent = ok_of(q.doc_vspan(&doc1()));
    assert!(!bincode::serialize(&extent).expect("SpanSet serializes").is_empty());
    let deletions = ok_of(q.show_deletions(&doc1(), &doc2()));
    assert!(!bincode::serialize(&deletions).expect("Deletions serializes").is_empty());
    let e = err_of(q.retrieve_v(&[spec(unregistered(), vspan(1, 1, 1))]));
    assert!(!bincode::serialize(&e).expect("RetrieveError serializes").is_empty());
    assert!(!bincode::serialize(&SpanFault::NotOrdinalLevel)
        .expect("SpanFault serializes")
        .is_empty());
    assert!(!bincode::serialize(&Operand::First)
        .expect("Operand serializes")
        .is_empty());
    // Request types serialize too (all-pub-field values).
    assert!(!bincode::serialize(&spec(doc1(), vspan(1, 1, 1)))
        .expect("Spec serializes")
        .is_empty());
    let region = region_spec(doc1(), vec![vspan(1, 1, 1)]);
    assert!(!bincode::serialize(&region)
        .expect("RegionSpec serializes")
        .is_empty());
    // CorrPair: field-by-field marshaling (no whole-value Serialize).
    let rep = ok_of(q.compare(
        &[region_spec(doc1(), vec![vspan(1, 1, 3)])],
        &[region_spec(doc2(), vec![vspan(1, 1, 2)])],
    ));
    assert_eq!(rep.len(), 1);
    let pair = &rep.as_slice()[0];
    assert!(!bincode::serialize(&pair.d1).expect("Address serializes").is_empty());
    assert!(!bincode::serialize(&pair.u1.subspace).expect("Nat serializes").is_empty());
    assert!(!bincode::serialize(&pair.u1.ordinal).expect("Nat serializes").is_empty());
    assert!(!bincode::serialize(&pair.d2).expect("Address serializes").is_empty());
    assert!(!bincode::serialize(&pair.width).expect("Nat serializes").is_empty());
    // Withholding Serialize is not withholding everything else: a consumer
    // can clone a report, compare two of them, and print one in a failure
    // message. `assert_eq!` on M6's results and errors compiles from a
    // foreign crate, the delivery path included.
    assert_eq!(rep.clone(), rep);
    assert_eq!(
        deletions,
        Deletions {
            deleted_from_a_with_b: vec![],
            deleted_from_b_with_a: vec![]
        }
    );
    assert_eq!(err_of(q.doc_vspan(&unregistered())), ExtentError::DocNotRegistered);
    assert_eq!(format!("{:?}", Operand::Second), "Second");
    assert!(!format!("{rep:?}").is_empty());
    assert!(!format!("{delivery:?}").is_empty());
    // The registry rejection names the offending document, in M1's dotted
    // decimal — the payload the variant carries, not discarded by Display.
    assert!(format!("{e}").contains(&unregistered().to_string()));
}

#[test]
fn a_delivery_renders_items_by_length_and_address_and_never_by_payload() {
    // A value renders as its byte length and never a byte — `Val`'s own
    // `Debug`, which `DeliveryItem`'s hand-written `Debug` keeps, in the shape
    // its card states. A payload byte in any rendering is the failure this
    // test exists to name.
    assert_eq!(
        format!("{:?}", DeliveryItem::Content(val(b"hello"))),
        "Content(5 bytes)"
    );
    assert_eq!(
        format!("{:?}", DeliveryItem::Ref(la(1))),
        format!("Ref({})", la(1))
    );
    assert_eq!(
        format!(
            "{:?}",
            DeliveryItem::Withheld {
                origin: doc1(),
                width: n(2)
            }
        ),
        format!("Withheld({}, 2 wide)", doc1())
    );
    assert!(!format!("{:?}", DeliveryItem::Content(val(b"secret"))).contains("secret"));
    assert_eq!(
        format!(
            "{:?}",
            Delivery(vec![
                DeliveryItem::Content(val(b"a")),
                DeliveryItem::Content(val(b"bc"))
            ])
        ),
        "Delivery([Content(1 bytes), Content(2 bytes)])"
    );
}

#[test]
fn every_rejection_is_a_std_error() {
    // §Errors: a foreign caller boxes an M6 rejection like any other error in
    // the workspace — the shape `?` into a `Box<dyn Error>` and anyhow need,
    // and one the orphan rule would forbid the caller from supplying. Each is
    // a LEAF: no variant wraps another error, so none has a source.
    fn boxed(
        e: impl std::error::Error + Send + Sync + 'static,
    ) -> Box<dyn std::error::Error + Send + Sync> {
        assert!(e.source().is_none(), "M6 rejections are leaves");
        Box::new(e)
    }
    assert!(!boxed(ExtentError::DocNotRegistered).to_string().is_empty());
    assert!(!boxed(RetrieveError::MalformedSpec {
        index: 0,
        fault: SpanFault::StartTooShallow,
    })
    .to_string()
    .is_empty());
    assert!(
        !boxed(OriginError::MalformedSpan(SpanFault::NotLevelUniform))
            .to_string()
            .is_empty()
    );
    // A boxed rejection still renders the document its variant carries.
    assert!(boxed(DeletionsError::DocNotRegistered(unregistered()))
        .to_string()
        .contains(&unregistered().to_string()));
    assert!(!boxed(CompareError::NotContentSubspace {
        operand: Operand::First,
        region: 0,
        index: 0,
    })
    .to_string()
    .is_empty());
    assert!(!boxed(FindError::MalformedSpan {
        region: 0,
        index: 0,
        fault: SpanFault::NotOrdinalLevel,
    })
    .to_string()
    .is_empty());
}

#[test]
fn every_registry_rejection_names_the_document_it_refused() {
    // §Errors: `Display` names the offending document in M1's dotted decimal
    // wherever the variant carries one — which is the whole value of carrying
    // it, a message that drops the payload localizing nothing.
    let d = unregistered().to_string();
    for message in [
        RetrieveError::DocNotRegistered(unregistered()).to_string(),
        DeletionsError::DocNotRegistered(unregistered()).to_string(),
        CompareError::DocNotRegistered(unregistered()).to_string(),
        FindError::DocNotRegistered(unregistered()).to_string(),
    ] {
        assert!(message.contains(&d), "{message} names no document");
    }
}

#[test]
fn the_fault_vocabularies_key_a_map_a_consumer_could_not_key_itself() {
    // §Errors derive policy: SpanFault and Operand carry `Hash` because a
    // consumer keying by one cannot supply the impl — both the trait and the
    // type are foreign to it. A per-(operand, fault) counter is the shape a
    // transport instruments M6's rejections with, and until M10 derives `Hash`
    // on `FaultSite` this is the only thing standing between the derive and a
    // cleanup that removes it as unused.
    let mut counts: HashMap<(Operand, SpanFault), usize> = HashMap::new();
    for site in [
        (Operand::First, SpanFault::NotOrdinalLevel),
        (Operand::First, SpanFault::NotOrdinalLevel),
        (Operand::Second, SpanFault::NotOrdinalLevel),
        (Operand::First, SpanFault::StartTooShallow),
    ] {
        *counts.entry(site).or_default() += 1;
    }
    assert_eq!(counts[&(Operand::First, SpanFault::NotOrdinalLevel)], 2);
    assert_eq!(counts.len(), 3, "the three distinct sites key apart");
}

#[test]
fn a_request_keys_a_set_as_its_m5_twin_does() {
    // §Public interface derive policy: `Spec` and `RegionSpec` carry `Hash`
    // for the reason the fault vocabularies do — a consumer keying by one
    // cannot supply the impl — and because M5's `VSpec`, the same shape one
    // seam over, already does. Collapsing COMPARE's redundant repeated
    // windows before sending is the consumer.
    let mut regions: HashSet<RegionSpec> = HashSet::new();
    regions.insert(region_spec(doc1(), vec![vspan(1, 1, 1)]));
    regions.insert(region_spec(doc1(), vec![vspan(1, 1, 1)])); // the repeat collapses
    regions.insert(region_spec(doc2(), vec![vspan(1, 1, 1)]));
    assert_eq!(regions.len(), 2);
    let specs: HashSet<Spec> = HashSet::from([spec(doc1(), vspan(1, 1, 1))]);
    assert!(specs.contains(&spec(doc1(), vspan(1, 1, 1))));
}

#[test]
fn the_answer_collections_behave_like_std_collections() {
    // §Public interface: Delivery and CompareReport are collections, so a
    // consumer walks, measures and collects one without naming the Vec
    // inside it — impls the orphan rule would forbid a consumer from adding.
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
    .expect("copy commits");
    let s = k.snapshot();
    let q = Query::new(&s);
    let delivery = ok_of(q.retrieve_v(&[spec(doc1(), vspan(1, 1, 3))]));
    assert_eq!(delivery.len(), 3);
    assert!(!delivery.is_empty());
    assert_eq!(delivery.iter().count(), 3);
    assert_eq!(delivery.as_slice()[0], DeliveryItem::Content(val(b"a")));
    // Borrowed walk, then an owned one that collects straight back.
    let borrowed: Vec<&DeliveryItem> = (&delivery).into_iter().collect();
    assert_eq!(borrowed.len(), 3);
    let round: Delivery = delivery.clone().into_iter().collect();
    assert_eq!(round, delivery);
    // The empty answers are the defaults, and an empty spec-set yields one.
    assert_eq!(ok_of(q.retrieve_v(&[])), Delivery::default());
    assert!(Delivery::default().is_empty());
    assert_eq!(Deletions::default(), ok_of(q.show_deletions(&doc1(), &doc2())));
    let rep = ok_of(q.compare(
        &[region_spec(doc1(), vec![vspan(1, 1, 3)])],
        &[region_spec(doc2(), vec![vspan(1, 1, 2)])],
    ));
    assert_eq!(rep.len(), 1);
    assert!(!rep.is_empty());
    assert_eq!(rep.iter().count(), 1);
    assert_eq!(rep.as_slice()[0].d1, doc1());
    let round: CompareReport = rep.clone().into_iter().collect();
    assert_eq!(round, rep);
    assert!(CompareReport::default().is_empty());
    // A report of two documents that share no address IS the default.
    let empty = ok_of(q.compare(
        &[region_spec(doc1(), vec![vspan(1, 1, 3)])],
        &[region_spec(doc1(), vec![])],
    ));
    assert_eq!(empty, CompareReport::default());
}

#[test]
fn the_query_handle_and_its_answers_cross_threads() {
    // Auto traits are promises made by what a type CONTAINS, and a threaded
    // front door depends on them; a private field could revoke one with no
    // signature changing, so the promise is pinned here.
    fn is_send_sync<T: Send + Sync>() {}
    is_send_sync::<Query<'static, World>>();
    is_send_sync::<Delivery>();
    is_send_sync::<CompareReport>();
    is_send_sync::<Deletions>();
    is_send_sync::<RetrieveError>();
}
