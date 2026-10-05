//! The twelve rows from outside the crate.

use skep_address::{is_prefix, Address};
use skep_registry::{
    commons_type, rows, t_binding, t_disavowal, t_endpoint, t_expulsion_ground, t_policy_link,
    t_policy_link_own, t_succession_ground, t_succession_policy, t_successor_of, t_takedown_base,
    t_takedown_lifted, t_takedown_record, Kind, RowOf, Subtype,
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
