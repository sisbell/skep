//! The twelve rows from outside the crate: what the table's public surface
//! shows. What only `rows.rs`'s privates can show — the registry range, its
//! ordinal reader, and `row_at` against the type subspace's own prefix — is
//! that module's unit suite.

use skep_address::{is_prefix, Address};
use skep_registry::{
    commons_type, rows, t_binding, t_disavowal, t_endpoint, t_expulsion_ground, t_policy_link,
    t_policy_link_own, t_succession_ground, t_succession_policy, t_successor_of, t_takedown_base,
    t_takedown_lifted, t_takedown_record, Kind, Row, RowOf, Subtype,
};

/// One row's held reader.
type Reader = fn() -> &'static Address;

/// REG-1.14, REG-1.15, REG-1.26 — twelve rows: five kinds, seven subtype
/// rows, each kind's subtype rows under it, at the map's addresses.
#[test]
fn the_table_holds_five_kinds_and_seven_subtype_rows() {
    assert_eq!(rows().len(), 12);
    assert_eq!(rows().iter().filter(|r| matches!(r.of, RowOf::Kind(_))).count(), 5);
    assert_eq!(rows().iter().filter(|r| matches!(r.of, RowOf::Subtype(_))).count(), 7);
    for kind in Kind::ALL {
        assert!(rows().iter().any(|r| r.of == RowOf::Kind(kind)), "{kind:?}");
    }
    for subtype in Subtype::ALL {
        let (r, k) = (subtype.row(), subtype.kind().row());
        assert!(is_prefix(k.address.tumbler(), r.address.tumbler()), "{subtype:?}");
    }
    let readers: [(Reader, &str); 12] = [
        (t_binding, "55"),
        (t_endpoint, "56"),
        (t_takedown_record, "57"),
        (t_takedown_base, "57.1"),
        (t_takedown_lifted, "57.2"),
        (t_policy_link, "58"),
        (t_policy_link_own, "58.1"),
        (t_disavowal, "58.2"),
        (t_expulsion_ground, "58.3"),
        (t_succession_ground, "58.4"),
        (t_succession_policy, "58.5"),
        (t_successor_of, "59"),
    ];
    for (read, tail) in readers {
        assert_eq!(read().to_string(), format!("1.1.0.1.0.1.0.3.{tail}"));
    }
}

/// REG-1.18 — the map's "Deposits" column: `3.55`, `3.56`, `3.59` and every
/// subtype row carry deposits; `3.57` and `3.58` carry none.
#[test]
fn the_deposits_column_follows_the_bare_ordinal_test() {
    let none: Vec<String> =
        rows().iter().filter(|r| !r.carries_deposits()).map(|r| r.address.to_string()).collect();
    assert_eq!(none, ["1.1.0.1.0.1.0.3.57", "1.1.0.1.0.1.0.3.58"]);
}

/// Every row's address is the ghost home document's subspace-3 element
/// at the ordinals the map pins, spelled as a client spells it.
#[test]
fn the_twelve_rows_sit_at_the_maps_addresses() {
    let spelled: Vec<String> = rows().iter().map(|r| r.address.to_string()).collect();
    assert_eq!(
        spelled,
        [
            "1.1.0.1.0.1.0.3.55",
            "1.1.0.1.0.1.0.3.56",
            "1.1.0.1.0.1.0.3.57",
            "1.1.0.1.0.1.0.3.57.1",
            "1.1.0.1.0.1.0.3.57.2",
            "1.1.0.1.0.1.0.3.58",
            "1.1.0.1.0.1.0.3.58.1",
            "1.1.0.1.0.1.0.3.58.2",
            "1.1.0.1.0.1.0.3.58.3",
            "1.1.0.1.0.1.0.3.58.4",
            "1.1.0.1.0.1.0.3.58.5",
            "1.1.0.1.0.1.0.3.59",
        ]
    );
}

/// The readers are the table's rows, one apiece and held: two reads
/// hand back the same address, not two equal ones.
#[test]
fn every_reader_is_one_held_row() {
    let readers: [fn() -> &'static Address; 12] = [
        t_binding,
        t_endpoint,
        t_takedown_record,
        t_takedown_base,
        t_takedown_lifted,
        t_policy_link,
        t_policy_link_own,
        t_disavowal,
        t_expulsion_ground,
        t_succession_ground,
        t_succession_policy,
        t_successor_of,
    ];
    for (read, row) in readers.iter().zip(rows()) {
        assert!(std::ptr::eq(read(), &row.address), "{}", row.address);
        assert!(std::ptr::eq(read(), read()), "{}: rebuilt per read", row.address);
    }
}

/// REG-1.18's test, as the map's "Deposits" column records it: the three
/// one-reading kinds and every subtype row carry deposits; the two bare
/// ordinals of the kinds that read more than one way carry none.
#[test]
fn the_bare_ordinal_carries_deposits_exactly_where_the_kind_reads_one_way() {
    for r in rows() {
        let bare_of_a_many_reading_kind =
            matches!(r.of, RowOf::Kind(Kind::TakedownRecord | Kind::PolicyLink));
        assert_eq!(r.carries_deposits(), !bare_of_a_many_reading_kind, "{:?}", r.of);
    }
}

/// REG-1.18's test read off the table's ADDRESSES: a row carries
/// deposits exactly where no other row nests under it — so the column
/// computed off the subtypes' kinds agrees with the readings the table
/// places under each kind.
#[test]
fn a_row_carries_deposits_exactly_where_no_reading_nests_under_it() {
    for r in rows() {
        let nested = rows()
            .iter()
            .any(|s| s.address != r.address && is_prefix(r.address.tumbler(), s.address.tumbler()));
        assert_eq!(r.carries_deposits(), !nested, "{}", r.address);
    }
}

/// Every row nests under its own kind's row alone: a subtype row is a
/// PREFIX under its own kind's row (REG-1.20) and under no other kind's,
/// and a kind's own row is that row itself, under no other kind's — the
/// kind rows are pairwise prefix-free.
#[test]
fn every_row_nests_under_its_own_kinds_row_alone() {
    let kind_rows: Vec<&Row> = rows().iter().filter(|r| matches!(r.of, RowOf::Kind(_))).collect();
    for (i, a) in kind_rows.iter().enumerate() {
        for b in &kind_rows[i + 1..] {
            assert!(
                !is_prefix(a.address.tumbler(), b.address.tumbler())
                    && !is_prefix(b.address.tumbler(), a.address.tumbler())
            );
        }
    }
    for r in rows().iter().filter(|r| matches!(r.of, RowOf::Subtype(_))) {
        for k in &kind_rows {
            let nested = is_prefix(k.address.tumbler(), r.address.tumbler());
            assert_eq!(nested, k.of.kind() == r.of.kind(), "{:?} under {:?}", r.of, k.of);
        }
    }
}

/// The `type` strings are the rules' names lowercased and hyphenated
/// (REG-1.86 (a)), present at the seven body-bearing rows and at none of
/// the other five: the three link-alone rows and the two bare ordinals
/// that carry no deposit (REG-1.18).
#[test]
fn the_type_strings_stand_at_the_body_bearing_rows_alone() {
    let typed: Vec<(Option<Subtype>, Option<&str>)> =
        rows().iter().map(|r| (r.of.subtype(), r.type_value)).collect();
    assert_eq!(
        typed,
        [
            (None, Some("binding")),
            (None, Some("endpoint")),
            (None, None),
            (Some(Subtype::TakedownBase), Some("takedown")),
            (Some(Subtype::TakedownLifted), None),
            (None, None),
            (Some(Subtype::PolicyLinkOwn), None),
            (Some(Subtype::Disavowal), Some("disavowal")),
            (Some(Subtype::ExpulsionGround), Some("expulsion-ground")),
            (Some(Subtype::SuccessionGround), Some("succession-ground")),
            (Some(Subtype::SuccessionPolicy), Some("succession-policy")),
            (None, None),
        ]
    );
}

/// Each kind and each subtype names its own row of the table, held: a
/// kind its bare row, a subtype the row under the kind it names — and
/// the row's [`RowOf`] reads back the kind and the subtype it is of.
#[test]
fn each_kind_and_subtype_names_its_own_row() {
    for kind in Kind::ALL {
        let r = kind.row();
        assert_eq!((r.of, r.of.kind(), r.of.subtype()), (RowOf::Kind(kind), kind, None));
        assert!(std::ptr::eq(r, kind.row()), "{kind:?}");
    }
    for subtype in Subtype::ALL {
        let r = subtype.row();
        let of = (r.of, r.of.kind(), r.of.subtype());
        assert_eq!(of, (RowOf::Subtype(subtype), subtype.kind(), Some(subtype)));
        assert!(std::ptr::eq(r, subtype.row()), "{subtype:?}");
    }
    assert_eq!(&Kind::Binding.row().address, t_binding());
    assert_eq!(&Subtype::Disavowal.row().address, t_disavowal());
    assert_eq!(Kind::SuccessorOf.row().type_value, None);
}

/// `commons_type` PANICS on no ordinal, as its doc states: the commons' type
/// subspace itself, above every row, is no row and never answered as one.
#[test]
#[should_panic(expected = "a commons row names at least one ordinal")]
fn commons_type_panics_on_an_empty_ordinal_list() {
    let _ = commons_type(&[]);
}

/// … and PANICS on a zero among the ordinals, by a check of its own whose
/// message names the caller's broken obligation: a row is an element at
/// positive ordinals — a zero there would be a fourth zero component, which
/// no T4-valid address holds.
#[test]
#[should_panic(expected = "a commons row's ordinals are positive")]
fn commons_type_panics_on_a_zero_ordinal() {
    let _ = commons_type(&[58, 0]);
}

/// THE MAP'S ORDER, as `rows()` states it: ascending in the tumbler order
/// (T1), each kind by its ordinal followed by its subtype rows by theirs — so
/// the policy link and its readings stand ahead of `successor-of`, though
/// `Kind::ALL`, REG-1.14's order, lists `successor-of` first. A row the table
/// gains (REG-1.19) takes its place by its address.
#[test]
fn the_rows_stand_in_ascending_tumbler_order() {
    for pair in rows().windows(2) {
        let (a, b) = (&pair[0].address, &pair[1].address);
        assert!(a < b, "{a} stands ahead of {b}");
    }
    let kinds: Vec<Kind> = rows()
        .iter()
        .filter_map(|r| match r.of {
            RowOf::Kind(kind) => Some(kind),
            RowOf::Subtype(_) => None,
        })
        .collect();
    assert_eq!(
        kinds,
        [Kind::Binding, Kind::Endpoint, Kind::TakedownRecord, Kind::PolicyLink, Kind::SuccessorOf]
    );
}
