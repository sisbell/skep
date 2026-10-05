//! The twelve rows from outside the crate.

use skep_address::{is_prefix, Address};
use skep_registry::{
    rows, t_binding, t_disavowal, t_endpoint, t_expulsion_ground, t_policy_link, t_policy_link_own,
    t_succession_ground, t_succession_policy, t_successor_of, t_takedown, t_takedown_base,
    t_takedown_lifted, Kind, Subtype,
};

/// One row's held reader.
type Reader = fn() -> &'static Address;

/// REG-1.14, REG-1.15, REG-1.26 — twelve rows: five kinds, seven subtype
/// rows, each kind's subtype rows under it, at the map's addresses.
#[test]
fn the_table_holds_five_kinds_and_seven_subtype_rows() {
    assert_eq!(rows().len(), 12);
    assert_eq!(rows().iter().filter(|r| r.subtype.is_none()).count(), 5);
    assert_eq!(rows().iter().filter(|r| r.subtype.is_some()).count(), 7);
    for kind in Kind::ALL {
        assert!(rows().iter().any(|r| r.kind == kind && r.subtype.is_none()), "{kind:?}");
    }
    for subtype in Subtype::ALL {
        let (r, k) = (subtype.row(), subtype.kind().row());
        assert!(is_prefix(k.address.tumbler(), r.address.tumbler()), "{subtype:?}");
    }
    let readers: [(Reader, &str); 12] = [
        (t_binding, "55"),
        (t_endpoint, "56"),
        (t_takedown, "57"),
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
        assert_eq!(read().tumbler().to_string(), format!("1.1.0.1.0.1.0.3.{tail}"));
    }
}

/// REG-1.18 — the map's "Deposits" column: `3.55`, `3.56`, `3.59` and every
/// subtype row carry deposits; `3.57` and `3.58` carry none.
#[test]
fn the_deposits_column_follows_the_bare_ordinal_test() {
    let none: Vec<String> = rows()
        .iter()
        .filter(|r| !r.deposits())
        .map(|r| r.address.tumbler().to_string())
        .collect();
    assert_eq!(none, ["1.1.0.1.0.1.0.3.57", "1.1.0.1.0.1.0.3.58"]);
}
