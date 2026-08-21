//! The serde trust boundary (design preamble): symmetric shadow round-trips
//! under a self-describing format, flat-tumbler Address journaling with level
//! re-derivation, and the no-unguarded-mint rule on every validating
//! deserialize path.

mod common;

use common::*;
use skep_address::*;

#[test]
fn tumbler_round_trips_and_revalidates_at_the_boundary() {
    let x = t(&[1, 0, 2, 0, 5]);
    let json = serde_json::to_string(&x).unwrap();
    // Symmetric shadow: the serialize side emits exactly the `Vec<Nat>` shape
    // the validating `try_from` side reads, so the round trip below holds by
    // construction and not by the two shapes happening to agree.
    assert_eq!(
        json,
        serde_json::to_string(&x.iter().cloned().collect::<Vec<Nat>>()).unwrap()
    );
    assert_eq!(serde_json::from_str::<Tumbler>(&json).unwrap(), x);
    // The mint path rejects the empty sequence (T0) on replay.
    assert!(serde_json::from_str::<Tumbler>("[]").is_err());
    // T0(a) crosses the journal boundary intact — a narrowed component would
    // truncate here, where nothing downstream could tell it had.
    let big = tumbler([n(1), beyond_u64(), n(0), n(5)]);
    let json = serde_json::to_string(&big).unwrap();
    assert_eq!(serde_json::from_str::<Tumbler>(&json).unwrap(), big);
}

#[test]
fn address_serializes_as_its_bare_tumbler_and_revalidates() {
    let a = addr(&[1, 0, 2, 0, 5, 0, 1, 9]);
    let json = serde_json::to_string(&a).unwrap();
    // Journal entries stay flat tumblers: the Address wire shape IS the tumbler's.
    assert_eq!(json, serde_json::to_string(a.tumbler()).unwrap());
    let back: Address = serde_json::from_str(&json).unwrap();
    assert_eq!(back, a);
    assert_eq!(back.level(), Level::Element); // level re-derived, never persisted
    // A non-T4 tumbler cannot mint an Address through deserialization.
    let bad = serde_json::to_string(&t(&[1, 0, 0, 2])).unwrap();
    assert!(serde_json::from_str::<Address>(&bad).is_err());
}

#[test]
fn span_round_trips_as_the_start_width_pair() {
    let s = sp(&[1, 0, 2], &[1, 0, 5]);
    let json = serde_json::to_string(&s).unwrap();
    // Symmetric shadow: the serialize side emits exactly the (start, width)
    // pair shape the deserialize side expects — self-describing formats
    // round-trip by construction, not coincidence.
    assert_eq!(
        json,
        serde_json::to_string(&(s.start().clone(), s.width().clone())).unwrap()
    );
    assert_eq!(serde_json::from_str::<Span>(&json).unwrap(), s);
    // A zero-width pair cannot mint a Span (T12 re-checked on replay).
    let bad = serde_json::to_string(&(t(&[1]), t(&[0]))).unwrap();
    assert!(serde_json::from_str::<Span>(&bad).is_err());
}

#[test]
fn span_set_round_trips_with_component_spans_validated() {
    let ss = spanset(&[sp(&[1], &[3]), sp(&[7], &[9])]);
    let json = serde_json::to_string(&ss).unwrap();
    assert_eq!(serde_json::from_str::<SpanSet>(&json).unwrap(), ss);
    // The shape the refusal below is written against: a sequence of
    // (start, width) pairs, each minted through `Span::new`. Without this, the
    // `is_err()` beneath would hold just as well if the set's wire shape were
    // something else entirely, and would say nothing about T12.
    let good = serde_json::to_string(&vec![(t(&[1]), t(&[2]))]).unwrap();
    assert_eq!(
        serde_json::from_str::<SpanSet>(&good).unwrap(),
        SpanSet::singleton(sp(&[1], &[3])) // start [1] ⊕ width [2] = reach [3]
    );
    // Component spans deserialize through Span's shadows: one bad span poisons
    // the set.
    let bad = serde_json::to_string(&vec![(t(&[1]), t(&[0, 1]))]).unwrap(); // ActionPointTooDeep
    assert!(serde_json::from_str::<SpanSet>(&bad).is_err());
}

#[test]
fn level_and_class_round_trip() {
    for l in [Level::Node, Level::Account, Level::Document, Level::Element] {
        let json = serde_json::to_string(&l).unwrap();
        assert_eq!(serde_json::from_str::<Level>(&json).unwrap(), l);
    }
    // The classifier's five answers, `Invalid` included: neither carries a
    // standing invariant, so both sides are derived and the round trip is the
    // whole claim.
    for c in [
        Class::Node,
        Class::Account,
        Class::Document,
        Class::Element,
        Class::Invalid,
    ] {
        let json = serde_json::to_string(&c).unwrap();
        assert_eq!(serde_json::from_str::<Class>(&json).unwrap(), c);
    }
}
