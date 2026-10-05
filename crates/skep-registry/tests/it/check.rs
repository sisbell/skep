//! The seeding check's three arms — each proved on a list this suite builds,
//! the shipped table passing against the rows commons-map lists as the
//! build's.

use skep_address::Address;
use skep_registry::{
    commons_type, rows, seeding_check, t_binding, t_policy_link, t_successor_of, t_takedown_record,
    Kind, Row, RowOf, SeedingRefusal, Subtype,
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
fn moved(of: RowOf, to: &[u32]) -> Vec<Row> {
    rows()
        .iter()
        .map(|r| {
            let mut r = r.clone();
            if r.of == of {
                r.address = commons_type(to);
            }
            r
        })
        .collect()
}

/// The shipped table without one row.
fn without(of: RowOf) -> Vec<Row> {
    rows().iter().filter(|r| r.of != of).cloned().collect()
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
        (&[57, 2][..], t_takedown_record()),
        (&[59][..], t_successor_of()),
    ] {
        let f = commons_type(foreign);
        assert_eq!(
            seeding_check(rows(), std::iter::once(&f)),
            Err(SeedingRefusal::Disjointness { registry: registry.clone(), foreign: f.clone() }),
            "{f}"
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
    // The operator's sentence names the registry's row and the foreign one,
    // each a commons row.
    let refusal = seeding_check(rows(), std::iter::once(&commons_type(&[58, 6]))).unwrap_err();
    assert_eq!(refusal.arm(), "disjointness");
    assert_eq!(
        refusal.to_string(),
        "disjointness: the registry row 1.1.0.1.0.1.0.3.58 and the foreign commons row \
         1.1.0.1.0.1.0.3.58.6 meet at the subtree grain"
    );
}

/// REG-1.29 — the completeness arm: a kind with no row, a subtype with no
/// row, and a subtype whose row stands under another kind (REG-1.20: a
/// subtype's row is a prefix under ITS OWN kind's row).
#[test]
fn the_completeness_arm_refuses_a_missing_kind_or_subtype_row() {
    assert_eq!(
        seeding_check(&without(RowOf::Kind(Kind::Binding)), std::iter::empty()),
        Err(SeedingRefusal::Completeness { missing: RowOf::Kind(Kind::Binding) })
    );
    assert_eq!(
        seeding_check(&without(RowOf::Subtype(Subtype::Disavowal)), std::iter::empty()),
        Err(SeedingRefusal::Completeness { missing: RowOf::Subtype(Subtype::Disavowal) })
    );
    let misplaced = moved(RowOf::Subtype(Subtype::Disavowal), &[57, 9]);
    let refusal = seeding_check(&misplaced, std::iter::empty()).unwrap_err();
    assert_eq!(
        refusal,
        SeedingRefusal::Completeness { missing: RowOf::Subtype(Subtype::Disavowal) }
    );
    assert_eq!(refusal.arm(), "completeness");
    assert!(refusal.to_string().contains("the disavowal has no row under the policy link"), "{refusal}");
    // A kind's row moved under another kind is caught too: the subtype rows
    // under it lose their kind's prefix.
    let moved_kind = moved(RowOf::Kind(Kind::PolicyLink), &[57, 5]);
    assert!(matches!(
        seeding_check(&moved_kind, std::iter::empty()),
        Err(SeedingRefusal::Completeness { missing: RowOf::Subtype(s) })
            if s.kind() == Kind::PolicyLink
    ));
}

/// REG-1.29 — EVERY row's absence refuses, naming that row: for each of the
/// twelve, the shipped table without it answers the completeness arm with
/// exactly that row missing, in the operator's sentence (REG-1.33: the
/// sentence is what a repair in the image is read off). One sentence per row
/// of the table, in its order, so a row the table gains (REG-1.19) owes a
/// line here; and a kind or a subtype the arm's own lists (`Kind::ALL`,
/// `Subtype::ALL`) leave out answers `Ok` where this test reads a refusal.
#[test]
fn the_completeness_arm_names_each_of_the_twelve_rows_missing() {
    let missing: [(RowOf, &str); 12] = [
        (RowOf::Kind(Kind::Binding), "completeness: the binding has no row"),
        (RowOf::Kind(Kind::Endpoint), "completeness: the endpoint has no row"),
        (RowOf::Kind(Kind::TakedownRecord), "completeness: the takedown record has no row"),
        (
            RowOf::Subtype(Subtype::TakedownBase),
            "completeness: the takedown record's base reading has no row under the takedown \
             record",
        ),
        (
            RowOf::Subtype(Subtype::TakedownLifted),
            "completeness: lifted has no row under the takedown record",
        ),
        (RowOf::Kind(Kind::PolicyLink), "completeness: the policy link has no row"),
        (
            RowOf::Subtype(Subtype::PolicyLinkOwn),
            "completeness: the policy link's own reading has no row under the policy link",
        ),
        (
            RowOf::Subtype(Subtype::Disavowal),
            "completeness: the disavowal has no row under the policy link",
        ),
        (
            RowOf::Subtype(Subtype::ExpulsionGround),
            "completeness: an expulsion's ground record has no row under the policy link",
        ),
        (
            RowOf::Subtype(Subtype::SuccessionGround),
            "completeness: a succession's ground record has no row under the policy link",
        ),
        (
            RowOf::Subtype(Subtype::SuccessionPolicy),
            "completeness: the org-chosen succession policy has no row under the policy link",
        ),
        (RowOf::Kind(Kind::SuccessorOf), "completeness: successor-of has no row"),
    ];
    assert!(
        rows().iter().map(|r| r.of).eq(missing.iter().map(|(of, _)| *of)),
        "one sentence per row of the table, in its order"
    );
    for (of, sentence) in missing {
        let refusal = seeding_check(&without(of), std::iter::empty())
            .expect_err(&format!("the table without {of:?} seeds"));
        assert_eq!(refusal, SeedingRefusal::Completeness { missing: of }, "{of:?}");
        assert_eq!(refusal.to_string(), sentence, "{of:?}");
    }
}

/// REG-1.20 — a subtype's row is UNDER its kind's row and never AT it: each
/// of the seven, moved onto its own kind's bare ordinal — the equal case of
/// "a prefix under", a tumbler being a prefix of itself — is no row of that
/// subtype, so its deposits never ride an ordinal REG-1.18 keeps bare.
#[test]
fn the_completeness_arm_refuses_a_subtype_row_on_its_kinds_own_ordinal() {
    let subtypes: Vec<Subtype> = rows().iter().filter_map(|r| r.of.subtype()).collect();
    assert_eq!(subtypes.len(), 7);
    for subtype in subtypes {
        let on_its_kind: Vec<Row> = rows()
            .iter()
            .map(|r| {
                let mut r = r.clone();
                if r.of == RowOf::Subtype(subtype) {
                    r.address = subtype.kind().row().address.clone();
                }
                r
            })
            .collect();
        assert_eq!(
            seeding_check(&on_its_kind, std::iter::empty()),
            Err(SeedingRefusal::Completeness { missing: RowOf::Subtype(subtype) }),
            "{subtype:?} on its kind's own ordinal"
        );
    }
}

/// REG-1.25 — the count arm: a sixth kind row, a kind row at `3.54` — the
/// reserve's, outside the registry range (REG-1.24) — and two kind rows at
/// one ordinal.
#[test]
fn the_count_arm_holds_the_kind_rows_to_the_registry_ranges_five_ordinals() {
    let mut sixth: Vec<Row> = rows().to_vec();
    sixth.push(Row {
        of: RowOf::Kind(Kind::Binding),
        address: commons_type(&[54]),
        type_value: Some("binding"),
    });
    let refusal = seeding_check(&sixth, std::iter::empty()).unwrap_err();
    assert_eq!(refusal, SeedingRefusal::Count { kind_row_count: 6, row: None });
    assert_eq!(
        refusal.to_string(),
        "count: 6 kind rows against the registry range's 5 ordinals 3.55-3.59"
    );
    // The operator's sentence names the range the row is outside: `3.54`
    // is the reserve's and no ordinal of the registry range.
    let outside = moved(RowOf::Kind(Kind::Binding), &[54]);
    let refusal = seeding_check(&outside, std::iter::empty()).unwrap_err();
    assert_eq!(
        refusal,
        SeedingRefusal::Count { kind_row_count: 5, row: Some(commons_type(&[54])) }
    );
    assert_eq!(
        refusal.to_string(),
        "count: of 5 kind rows, 1.1.0.1.0.1.0.3.54 is no bare ordinal of the registry range \
         3.55-3.59 left to it"
    );
    let doubled = moved(RowOf::Kind(Kind::Endpoint), &[55]);
    let refusal = seeding_check(&doubled, std::iter::empty()).unwrap_err();
    assert_eq!(
        refusal,
        SeedingRefusal::Count { kind_row_count: 5, row: Some(commons_type(&[55])) }
    );
    assert_eq!(refusal.arm(), "count");
    assert!(refusal.to_string().starts_with("count:"), "{refusal}");
}

/// REG-1.32 — the arms run in the stated order: a list faulting on all
/// three answers disjointness; one faulting on the last two answers
/// completeness.
#[test]
fn the_arms_run_in_order() {
    let mut faulty = without(RowOf::Subtype(Subtype::Disavowal));
    faulty.push(Row {
        of: RowOf::Kind(Kind::Binding),
        address: commons_type(&[54]),
        type_value: Some("binding"),
    });
    let foreign = commons_type(&[55, 1]);
    assert_eq!(seeding_check(&faulty, std::iter::once(&foreign)).unwrap_err().arm(), "disjointness");
    assert_eq!(seeding_check(&faulty, std::iter::empty()).unwrap_err().arm(), "completeness");
}
