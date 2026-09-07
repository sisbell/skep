//! The write path's type-recognition input (PUB-6.30, PUB-6.64; owner ruling
//! D3, 2026-09-05): `WriteTypes` beside `TypeAddrs` — precedence (credential
//! > grant > list), the one-span `Equal`-to-subtree discipline, a subtype by
//! prefix, and `kind_of` unchanged. The class addresses are test placeholders
//! in the commons doc's link subspace, exactly as `common`'s credential types
//! are: this crate is parametric over them, the engine pins the real ones.

mod common;

use common::{addr, tum, unit, width_at_last, T_CLAIM, T_ENROLL, T_RETIRE};
use skep_address::Span;
use skep_identity::{AuditClass, CredentialKind, TypeAddrs, WriteClass, WriteTypes};

// Placeholder class addresses, prefix-free among themselves and distinct
// from the three credential placeholders.
const T_GRANT: &[u32] = &[1, 1, 0, 1, 0, 1, 0, 2, 90];
const T_SUCCESSOR_OF: &[u32] = &[1, 1, 0, 1, 0, 1, 0, 2, 59];
const T_ENDORSE: &[u32] = &[1, 1, 0, 1, 0, 1, 0, 2, 42];
const T_MARKER: &[u32] = &[1, 1, 0, 1, 0, 1, 0, 2, 91];
const T_DESIGNATION: &[u32] = &[1, 1, 0, 1, 0, 1, 0, 2, 22];
const T_RAIL: &[u32] = &[1, 1, 0, 1, 0, 1, 0, 2, 60];
const T_STEWARD: &[u32] = &[1, 1, 0, 1, 0, 1, 0, 2, 61];

fn credential() -> TypeAddrs {
    TypeAddrs::new(addr(T_ENROLL), addr(T_RETIRE), addr(T_CLAIM))
}

/// The list in PUB-6.64's order.
fn audit_list() -> Vec<(AuditClass, skep_address::Address)> {
    vec![
        (AuditClass::SuccessorOf, addr(T_SUCCESSOR_OF)),
        (AuditClass::DelegatorEndorsement, addr(T_ENDORSE)),
        (AuditClass::ConsumptionMarker, addr(T_MARKER)),
        (AuditClass::JournalDesignation, addr(T_DESIGNATION)),
        (AuditClass::RailRecord, addr(T_RAIL)),
        (AuditClass::StewardClassification, addr(T_STEWARD)),
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
        t.write_class(&[unit(T_ENROLL)]),
        Some(WriteClass::Credential(CredentialKind::Enroll))
    );
    assert_eq!(
        t.write_class(&[unit(T_RETIRE)]),
        Some(WriteClass::Credential(CredentialKind::Retire))
    );
    assert_eq!(
        t.write_class(&[unit(T_CLAIM)]),
        Some(WriteClass::Credential(CredentialKind::Claim))
    );
    assert_eq!(t.write_class(&[unit(T_GRANT)]), Some(WriteClass::Grant));
    for (class, a) in audit_list() {
        let span = skep_address::subtree_of(a.tumbler());
        assert_eq!(
            t.write_class(&[span]),
            Some(WriteClass::AuditView(class)),
            "{} is {class:?}",
            a.tumbler()
        );
    }
}

/// An address naming no class is an ORDINARY link: a ghost type of some
/// document's own, a content position, an unrelated subspace-3 name.
#[test]
fn an_unclassified_address_is_ordinary() {
    let t = types();
    assert_eq!(t.write_class(&[unit(&[1, 1, 0, 5, 0, 3, 0, 3, 6, 1])]), None, "a ghost type");
    assert_eq!(t.write_class(&[unit(&[1, 1, 0, 5, 0, 3, 0, 1, 1])]), None, "a content position");
    assert_eq!(t.write_class(&[unit(&[1, 1, 0, 1, 0, 1, 0, 2, 14])]), None, "another name");
}

/// PRECEDENCE: the credential kinds answer FIRST and win, so a class address
/// that is a credential type would be unreachable — refused at construction,
/// exactly as `TypeAddrs::new` refuses a repeated credential address.
#[test]
#[should_panic(expected = "credential type address")]
fn a_class_at_a_credential_address_is_refused_at_construction() {
    let _ = WriteTypes::new(credential(), addr(T_ENROLL), audit_list());
}

/// PRECEDENCE within the list: the first match answers, so two class
/// addresses that are prefix-related would shadow one another — refused at
/// construction (the later class would be unreachable for every slot).
#[test]
#[should_panic(expected = "prefix-related")]
fn prefix_related_class_addresses_are_refused_at_construction() {
    let mut list = audit_list();
    // A rail "subtype" pinned as its own class beneath the rail's address.
    list.push((AuditClass::StewardClassification, addr(&[1, 1, 0, 1, 0, 1, 0, 2, 60, 1])));
    let _ = WriteTypes::new(credential(), addr(T_GRANT), list);
}

/// The grant precedes the list: a list address under the grant's prefix is
/// the same shadowing, refused the same way.
#[test]
#[should_panic(expected = "prefix-related")]
fn a_list_address_under_the_grant_is_refused_at_construction() {
    let mut list = audit_list();
    list.push((AuditClass::RailRecord, addr(&[1, 1, 0, 1, 0, 1, 0, 2, 90, 7])));
    let _ = WriteTypes::new(credential(), addr(T_GRANT), list);
}

/// `Equal` ONLY (AUTH-2.22's discipline): a slot of two spans, a span that
/// CONTAINS the class's subtree, and a span that merely overlaps it answer
/// nothing — a member is exactly one span `Equal` to a class subtree (or a
/// subtype's, below).
#[test]
fn only_a_single_span_equal_to_a_class_subtree_is_a_member() {
    let t = types();
    // Two spans, both members on their own: not a member as a slot.
    assert_eq!(t.write_class(&[unit(T_GRANT), unit(T_RAIL)]), None);
    assert_eq!(t.write_class(&[]), None);
    // A span covering the grant's subtree AND its sibling: Containment, not
    // Equal — and not the unit subtree of its own start either.
    let start = tum(T_GRANT);
    let len = start.len();
    let wide = Span::new(start, width_at_last(len, 2)).expect("a positive width");
    assert_eq!(t.write_class(&[wide]), None);
    // A span starting one BELOW the grant, two wide: ProperOverlap of the
    // grant's subtree, no member of anything.
    let below = tum(&[1, 1, 0, 1, 0, 1, 0, 2, 89]);
    let len = below.len();
    let straddle = Span::new(below, width_at_last(len, 2)).expect("a positive width");
    assert_eq!(t.write_class(&[straddle]), None);
}

/// A SUBTYPE BY PREFIX is its class's member (L10: hierarchy is prefix — one
/// subtree span matches a type and its subtypes): `endorse.trust` is a
/// delegator endorsement, a grant subtype is a grant, two levels down too.
/// A "subtype" of a CREDENTIAL type is nothing: `kind_of` is `Equal`-only
/// (the fold's frozen rule) and the classes do not reach it.
#[test]
fn a_subtype_by_prefix_is_a_member_of_its_class() {
    let t = types();
    assert_eq!(
        t.write_class(&[unit(&[1, 1, 0, 1, 0, 1, 0, 2, 42, 2])]),
        Some(WriteClass::AuditView(AuditClass::DelegatorEndorsement)),
        "endorse.trust"
    );
    assert_eq!(t.write_class(&[unit(&[1, 1, 0, 1, 0, 1, 0, 2, 90, 3])]), Some(WriteClass::Grant));
    assert_eq!(
        t.write_class(&[unit(&[1, 1, 0, 1, 0, 1, 0, 2, 59, 1, 4])]),
        Some(WriteClass::AuditView(AuditClass::SuccessorOf)),
        "two levels down"
    );
    assert_eq!(t.write_class(&[unit(&[1, 1, 0, 1, 0, 1, 0, 2, 1, 7])]), None, "no credential subtypes");
}

/// `kind_of` UNCHANGED: the credential half of the input IS the fold's
/// `TypeAddrs`, answering the same on every slot — a credential unit, a
/// credential "subtype" (`None`), a two-span slot (`None`) — and the write
/// classifier's `Credential` arm is exactly that answer lifted.
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
        assert_eq!(t.credential().kind_of(&slot), plain.kind_of(&slot), "the same instance's rule");
        match plain.kind_of(&slot) {
            Some(kind) => assert_eq!(t.write_class(&slot), Some(WriteClass::Credential(kind))),
            None => assert!(!matches!(t.write_class(&slot), Some(WriteClass::Credential(_)))),
        }
    }
    assert_eq!(t.credential(), &plain, "the input carries the fold's own instance, unchanged");
}
