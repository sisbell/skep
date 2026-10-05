//! The seeding check's three arms — each proved on a list this suite builds,
//! the shipped table passing against the rows commons-map lists as the
//! build's.

use skep_address::Address;
use skep_registry::{
    commons_type, rows, seeding_check, t_binding, t_policy_link, t_successor_of, t_takedown, Kind,
    Row, SeedingRefusal, Subtype,
};

/// The rows commons-map's disjointness paragraph lists as built or placed
/// beside the registry's: the credentials `3.1`–`3.3`, the comment type
/// `3.5` with a subtype, `replaces` `3.12`, the edition `3.14` with its test
/// subtype, the mail type `3.15`, the journal designation `3.22`, endorse
/// `3.42` with a subtype, the rail record `3.60`, the steward classification
/// `3.61`, media's cell kind `3.89`, the grant `3.90` with its test subtype
/// and the consumption marker `3.91`.
fn the_maps_other_rows() -> Vec<Address> {
    [
        &[1][..],
        &[2],
        &[3],
        &[5],
        &[5, 5],
        &[12],
        &[14],
        &[14, 2],
        &[15],
        &[22],
        &[42],
        &[42, 2],
        &[60],
        &[61],
        &[89],
        &[90],
        &[90, 1],
        &[91],
    ]
    .iter()
    .map(|ordinals| commons_type(ordinals))
    .collect()
}

/// The shipped table with one row's address moved.
fn moved(kind: Kind, subtype: Option<Subtype>, to: &[u32]) -> Vec<Row> {
    rows()
        .iter()
        .map(|r| {
            let mut r = r.clone();
            if r.kind == kind && r.subtype == subtype {
                r.address = commons_type(to);
            }
            r
        })
        .collect()
}

/// The shipped table without one row.
fn without(kind: Kind, subtype: Option<Subtype>) -> Vec<Row> {
    rows().iter().filter(|r| !(r.kind == kind && r.subtype == subtype)).cloned().collect()
}

/// REG-1.24, REG-1.30, REG-1.31 — the shipped rows against the rows the map
/// lists as the build's and the map's own neighbours: no collision at the
/// subtree grain, and `3.5` is no prefix of `3.55` (prefix is by element).
#[test]
fn the_shipped_rows_are_disjoint_from_every_other_row_the_map_lists() {
    assert_eq!(seeding_check(rows(), &the_maps_other_rows()), Ok(()));
    assert_eq!(seeding_check(rows(), std::iter::empty()), Ok(()));
}

/// REG-1.30 — the disjointness arm, both directions: a foreign row placed
/// inside the policy link's kind (the mail type, REG-1.31's sharpest case),
/// a foreign row under the binding, a foreign row AT a registry row (the
/// first row to meet it in table order is named — the kind above it), and
/// a foreign row ABOVE the registry's whole block.
#[test]
fn the_disjointness_arm_refuses_a_foreign_row_inside_above_or_at_a_registry_row() {
    for (foreign, registry) in [
        (&[58, 6][..], t_policy_link()),
        (&[55, 1][..], t_binding()),
        (&[57, 2][..], t_takedown()),
        (&[59][..], t_successor_of()),
    ] {
        let f = commons_type(foreign);
        assert_eq!(
            seeding_check(rows(), std::iter::once(&f)),
            Err(SeedingRefusal::Disjointness { registry: registry.clone(), foreign: f.clone() }),
            "{}",
            f.tumbler()
        );
    }
    // Above the block: the subspace itself contains every row; the first
    // row in table order is the one named.
    let subspace = skep_address::validate(
        skep_address::Tumbler::new([1u32, 1, 0, 1, 0, 1, 0, 3].map(skep_address::Nat::from))
            .expect("a tumbler"),
    )
    .expect("an address");
    assert_eq!(
        seeding_check(rows(), std::iter::once(&subspace)),
        Err(SeedingRefusal::Disjointness { registry: t_binding().clone(), foreign: subspace })
    );
    let refusal = seeding_check(rows(), std::iter::once(&commons_type(&[58, 6]))).unwrap_err();
    assert_eq!(refusal.arm(), "disjointness");
    assert!(refusal.to_string().starts_with("disjointness:"), "{refusal}");
}

/// REG-1.29 — the completeness arm: a kind with no row, a subtype with no
/// row, and a subtype whose row stands under another kind (REG-1.20: a
/// subtype's row is a prefix under ITS OWN kind's row).
#[test]
fn the_completeness_arm_refuses_a_missing_kind_or_subtype_row() {
    assert_eq!(
        seeding_check(&without(Kind::Binding, None), std::iter::empty()),
        Err(SeedingRefusal::Completeness { kind: Kind::Binding, subtype: None })
    );
    assert_eq!(
        seeding_check(&without(Kind::PolicyLink, Some(Subtype::Disavowal)), std::iter::empty()),
        Err(SeedingRefusal::Completeness { kind: Kind::PolicyLink, subtype: Some(Subtype::Disavowal) })
    );
    let misplaced = moved(Kind::PolicyLink, Some(Subtype::Disavowal), &[57, 9]);
    let refusal = seeding_check(&misplaced, std::iter::empty()).unwrap_err();
    assert_eq!(
        refusal,
        SeedingRefusal::Completeness { kind: Kind::PolicyLink, subtype: Some(Subtype::Disavowal) }
    );
    assert_eq!(refusal.arm(), "completeness");
    assert!(refusal.to_string().contains("the disavowal has no row under the policy link"), "{refusal}");
    // A kind's row moved under another kind is caught too: the subtype rows
    // under it lose their kind's prefix.
    let moved_kind = moved(Kind::PolicyLink, None, &[57, 5]);
    assert!(matches!(
        seeding_check(&moved_kind, std::iter::empty()),
        Err(SeedingRefusal::Completeness { kind: Kind::PolicyLink, subtype: Some(_) })
    ));
}

/// REG-1.25 — the count arm: a sixth kind row, a kind row outside the
/// reserve's five ordinals, and two kind rows at one ordinal.
#[test]
fn the_count_arm_holds_the_kind_rows_to_the_reserves_five_ordinals() {
    let mut sixth: Vec<Row> = rows().to_vec();
    sixth.push(Row {
        kind: Kind::Binding,
        subtype: None,
        address: commons_type(&[54]),
        deposits: true,
        type_value: Some("binding"),
    });
    assert_eq!(
        seeding_check(&sixth, std::iter::empty()),
        Err(SeedingRefusal::Count { kind_rows: 6, row: None })
    );
    let outside = moved(Kind::Binding, None, &[54]);
    assert_eq!(
        seeding_check(&outside, std::iter::empty()),
        Err(SeedingRefusal::Count { kind_rows: 5, row: Some(commons_type(&[54])) })
    );
    let doubled = moved(Kind::Endpoint, None, &[55]);
    let refusal = seeding_check(&doubled, std::iter::empty()).unwrap_err();
    assert_eq!(refusal, SeedingRefusal::Count { kind_rows: 5, row: Some(commons_type(&[55])) });
    assert_eq!(refusal.arm(), "count");
    assert!(refusal.to_string().starts_with("count:"), "{refusal}");
}

/// REG-1.32 — the arms run in the stated order: a list faulting on all
/// three answers disjointness; one faulting on the last two answers
/// completeness.
#[test]
fn the_arms_run_in_order() {
    let mut faulty = without(Kind::PolicyLink, Some(Subtype::Disavowal));
    faulty.push(Row {
        kind: Kind::Binding,
        subtype: None,
        address: commons_type(&[54]),
        deposits: true,
        type_value: Some("binding"),
    });
    let foreign = commons_type(&[55, 1]);
    assert_eq!(seeding_check(&faulty, std::iter::once(&foreign)).unwrap_err().arm(), "disjointness");
    assert_eq!(seeding_check(&faulty, std::iter::empty()).unwrap_err().arm(), "completeness");
}
