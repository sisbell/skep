//! The write path's type-recognition input (PUB-6.30, PUB-6.64; owner ruling
//! D3, 2026-09-05): `WriteTypes` beside `TypeAddrs` — precedence (the
//! credential kinds first; the classes prefix-free, so their own order
//! decides nothing), the one-span `Equal`-to-subtree discipline, a subtype by
//! prefix, the home-conditional member, and `kind_of` unchanged. The class
//! addresses are test placeholders in the commons doc's link subspace,
//! exactly as `common`'s credential types are: this crate is parametric over
//! them, the engine pins the real ones.

use crate::common;

use common::{addr, panics_past_two, tum, unit, width_at_last, T_CLAIM, T_ENROLL, T_RETIRE};
use skep_address::Span;
use skep_identity::{AuditClass, CredentialKind, TargetClass, TypeAddrs, WriteTypes};

// Placeholder class addresses, prefix-free among themselves and distinct
// from the three credential placeholders.
const T_GRANT: &[u32] = &[1, 1, 0, 1, 0, 1, 0, 2, 90];
const T_SUCCESSOR_OF: &[u32] = &[1, 1, 0, 1, 0, 1, 0, 2, 59];
const T_ENDORSE: &[u32] = &[1, 1, 0, 1, 0, 1, 0, 2, 42];
const T_CONSUMPTION_MARKER: &[u32] = &[1, 1, 0, 1, 0, 1, 0, 2, 91];
const T_JOURNAL_DESIGNATION: &[u32] = &[1, 1, 0, 1, 0, 1, 0, 2, 22];
const T_RAIL_RECORD: &[u32] = &[1, 1, 0, 1, 0, 1, 0, 2, 60];
const T_STEWARD_CLASSIFICATION: &[u32] = &[1, 1, 0, 1, 0, 1, 0, 2, 61];

fn credential() -> TypeAddrs {
    TypeAddrs::new(addr(T_ENROLL), addr(T_RETIRE), addr(T_CLAIM))
}

/// The list in PUB-6.64's order.
fn audit_list() -> Vec<(AuditClass, skep_address::Address)> {
    vec![
        (AuditClass::SuccessorOf, addr(T_SUCCESSOR_OF)),
        (AuditClass::DelegatorEndorsement, addr(T_ENDORSE)),
        (AuditClass::ConsumptionMarker, addr(T_CONSUMPTION_MARKER)),
        (AuditClass::JournalDesignation, addr(T_JOURNAL_DESIGNATION)),
        (AuditClass::RailRecord, addr(T_RAIL_RECORD)),
        (AuditClass::StewardClassification, addr(T_STEWARD_CLASSIFICATION)),
    ]
}

fn types() -> WriteTypes {
    WriteTypes::new(credential(), addr(T_GRANT), audit_list())
}

/// Every address answers its own arm: the three credential kinds through
/// the same rule the fold reads, the grant, and each audit-view member.
#[test]
fn every_class_address_answers_its_own_arm() {
    let t = types();
    assert_eq!(
        t.target_class(&[unit(T_ENROLL)]),
        Some(TargetClass::Credential(CredentialKind::Enroll))
    );
    assert_eq!(
        t.target_class(&[unit(T_RETIRE)]),
        Some(TargetClass::Credential(CredentialKind::Retire))
    );
    assert_eq!(
        t.target_class(&[unit(T_CLAIM)]),
        Some(TargetClass::Credential(CredentialKind::Claim))
    );
    assert_eq!(t.target_class(&[unit(T_GRANT)]), Some(TargetClass::Grant));
    for (class, a) in audit_list() {
        let span = skep_address::subtree_of(a.tumbler());
        assert_eq!(
            t.target_class(&[span]),
            Some(TargetClass::AuditView(class)),
            "{} is {class:?}",
            a.tumbler()
        );
    }
}

/// An address under no class is an ORDINARY link: a ghost type of some
/// document's own, a content position, an unrelated subspace-3 name.
#[test]
fn an_unclassified_address_is_ordinary() {
    let t = types();
    assert_eq!(t.target_class(&[unit(&[1, 1, 0, 5, 0, 3, 0, 3, 6, 1])]), None, "a ghost type");
    assert_eq!(t.target_class(&[unit(&[1, 1, 0, 5, 0, 3, 0, 1, 1])]), None, "a content position");
    assert_eq!(t.target_class(&[unit(&[1, 1, 0, 1, 0, 1, 0, 2, 14])]), None, "another name");
}

/// PRECEDENCE: the credential kinds answer FIRST and win, so a class address
/// that is a credential type would be unreachable — refused at construction,
/// exactly as `TypeAddrs::new` refuses a repeated credential address.
#[test]
#[should_panic(expected = "credential type address")]
fn a_class_at_a_credential_address_is_refused_at_construction() {
    let _ = WriteTypes::new(credential(), addr(T_ENROLL), audit_list());
}

/// PREFIX-FREEDOM within the list: two prefix-related class addresses put
/// one address under two classes, which the declared order would then decide
/// — refused at construction (here the later class, under the earlier, would
/// be unreachable for every slot).
#[test]
#[should_panic(expected = "prefix-related")]
fn prefix_related_class_addresses_are_refused_at_construction() {
    let mut list = audit_list();
    // A rail "subtype" pinned as its own class beneath the rail's address.
    list.push((AuditClass::StewardClassification, addr(&[1, 1, 0, 1, 0, 1, 0, 2, 60, 1])));
    let _ = WriteTypes::new(credential(), addr(T_GRANT), list);
}

/// The grant is held to the list's rule: a list address under the grant's
/// prefix puts one address under two classes, refused the same way.
#[test]
#[should_panic(expected = "prefix-related")]
fn a_list_address_under_the_grant_is_refused_at_construction() {
    let mut list = audit_list();
    list.push((AuditClass::RailRecord, addr(&[1, 1, 0, 1, 0, 1, 0, 2, 90, 7])));
    let _ = WriteTypes::new(credential(), addr(T_GRANT), list);
}

/// PREFIX-FREEDOM is what makes the classes' declared order decide nothing:
/// no address is under two classes, so the same classes listed in REVERSE
/// classify every class address, and a subtype under each, exactly as the
/// declared order does. The one order that decides is the credential kinds
/// answering first.
#[test]
fn the_declared_order_of_the_classes_decides_nothing() {
    let declared = types();
    let mut list = audit_list();
    list.reverse();
    let reversed = WriteTypes::new(credential(), addr(T_GRANT), list);
    for class_addr in [
        T_GRANT,
        T_SUCCESSOR_OF,
        T_ENDORSE,
        T_CONSUMPTION_MARKER,
        T_JOURNAL_DESIGNATION,
        T_RAIL_RECORD,
        T_STEWARD_CLASSIFICATION,
    ] {
        let subtype: Vec<u32> = class_addr.iter().copied().chain([1]).collect();
        for slot in [vec![unit(class_addr)], vec![unit(&subtype)]] {
            let answer = declared.target_class(&slot);
            assert!(answer.is_some(), "{class_addr:?}: the fixture's address is at or under a class");
            assert_eq!(reversed.target_class(&slot), answer, "{class_addr:?}");
        }
    }
}

/// RES-207/PUB-6.64 — which audit-view classes are members only where the
/// link's own home is published: the steward's classification link, and no
/// other. The whole table, so a flipped answer is discovered here rather than
/// as a permanent refusal the spec does not make.
#[test]
fn only_the_steward_classification_requires_a_published_home() {
    for (class, _) in audit_list() {
        assert_eq!(
            class.requires_published_home(),
            class == AuditClass::StewardClassification,
            "{class:?}"
        );
    }
}

/// `Equal` ONLY (AUTH-2.22's discipline): a slot of two spans, a span that
/// CONTAINS the class's subtree, and a span that merely overlaps it answer
/// nothing — a member is exactly one span `Equal` to a class subtree (or a
/// subtype's, below).
#[test]
fn only_a_single_span_equal_to_a_class_subtree_is_a_member() {
    let t = types();
    // Two spans, both members on their own: not a member as a slot.
    assert_eq!(t.target_class(&[unit(T_GRANT), unit(T_RAIL_RECORD)]), None);
    assert_eq!(t.target_class(&[]), None);
    // A span covering the grant's subtree AND its sibling: Containment, not
    // Equal — and not the unit subtree of its own start either.
    let start = tum(T_GRANT);
    let len = start.len();
    let wide = Span::new(start, width_at_last(len, 2)).expect("a positive width");
    assert_eq!(t.target_class(&[wide]), None);
    // A span starting one BELOW the grant, two wide: ProperOverlap of the
    // grant's subtree, no member of anything.
    let below = tum(&[1, 1, 0, 1, 0, 1, 0, 2, 89]);
    let len = below.len();
    let straddle = Span::new(below, width_at_last(len, 2)).expect("a positive width");
    assert_eq!(t.target_class(&[straddle]), None);
}

/// Arity once, in at most TWO steps: a many-span slot is an ordinary link
/// without its walk being counted or collected, so the store's own endset is
/// classified in place. Both spans are the grant's own unit subtree, so a
/// rule that read only the first span would answer `Grant` here.
#[test]
fn a_many_span_slot_is_ordinary_in_two_steps() {
    let span = unit(T_GRANT);
    assert_eq!(types().target_class(panics_past_two(&span)), None);
}

/// A SUBTYPE BY PREFIX is its class's member (L10: hierarchy is prefix — one
/// subtree span matches a type and its subtypes): `endorse.trust` is in the
/// delegator endorsement's class, a grant subtype is a grant, two levels down
/// too. A "subtype" of a CREDENTIAL type is nothing: `kind_of` is `Equal`-only
/// (the fold's frozen rule) and the classes do not reach it.
#[test]
fn a_subtype_by_prefix_is_a_member_of_its_class() {
    let t = types();
    assert_eq!(
        t.target_class(&[unit(&[1, 1, 0, 1, 0, 1, 0, 2, 42, 2])]),
        Some(TargetClass::AuditView(AuditClass::DelegatorEndorsement)),
        "endorse.trust"
    );
    assert_eq!(t.target_class(&[unit(&[1, 1, 0, 1, 0, 1, 0, 2, 90, 3])]), Some(TargetClass::Grant));
    assert_eq!(
        t.target_class(&[unit(&[1, 1, 0, 1, 0, 1, 0, 2, 59, 1, 4])]),
        Some(TargetClass::AuditView(AuditClass::SuccessorOf)),
        "two levels down"
    );
    assert_eq!(t.target_class(&[unit(&[1, 1, 0, 1, 0, 1, 0, 2, 1, 7])]), None, "no credential subtypes");
}

/// `kind_of` UNCHANGED: on every slot — a credential unit, a credential
/// "subtype" (`None`), a two-span slot (`None`), a class address (`None`) —
/// the target classifier's `Credential` arm is exactly the answer `kind_of`
/// gives on the `TypeAddrs` the input was built from, in both directions.
#[test]
fn kind_of_is_unchanged_and_is_the_credential_arm() {
    let t = types();
    let plain = credential();
    for slot in [
        vec![unit(T_ENROLL)],
        vec![unit(T_RETIRE)],
        vec![unit(T_CLAIM)],
        vec![unit(&[1, 1, 0, 1, 0, 1, 0, 2, 1, 7])],
        vec![unit(T_ENROLL), unit(T_RETIRE)],
        vec![unit(T_GRANT)],
    ] {
        match plain.kind_of(&slot) {
            Some(kind) => assert_eq!(t.target_class(&slot), Some(TargetClass::Credential(kind))),
            None => assert!(!matches!(t.target_class(&slot), Some(TargetClass::Credential(_)))),
        }
    }
}
