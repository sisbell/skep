//! The twelve rows from outside the crate. Commons-map's table is
//! transcribed here ONCE, [`THE_MAP`], and every question the map answers of
//! a row is asked of every line; beside it stand the laws the table holds
//! whatever its lines, and `commons_type`'s panics. What only `rows.rs`'s
//! privates can show — the registry range, its ordinal reader, and `row_at`
//! against the type subspace's own prefix — is that module's unit suite.

use skep_address::{is_prefix, Address};
use skep_registry::{
    commons_type, rows, t_binding, t_disavowal, t_endpoint, t_expulsion_ground, t_policy_link,
    t_policy_link_own, t_succession_ground, t_succession_policy, t_successor_of, t_takedown_base,
    t_takedown_lifted, t_takedown_record, Kind, Row, RowOf, Subtype,
};

/// One line of commons-map's table "THE REGISTRY'S TWELVE ROWS", as this
/// suite transcribes it: what the row is the row of, its held reader, its
/// ordinals under the commons' type subspace, the `type` string its body
/// carries, and whether a deposit rides its address (the map's "Deposits"
/// column, REG-1.18).
struct MapLine {
    of: RowOf,
    read: fn() -> &'static Address,
    ordinals: &'static str,
    type_value: Option<&'static str>,
    carries_deposits: bool,
}

/// THE MAP, line by line in its order — this suite's ONE transcription of
/// the table, kept as the engine's ledger tests keep their `PINS`: every
/// question the map answers of a row is asked of every line at once
/// (`the_table_is_the_maps_line_by_line`), so a row the table gains
/// (REG-1.15) owes one line here and meets every question where it joins.
/// No line already here changes its Deposits: a new subtype row joins under
/// the takedown record or the policy link, whose bare ordinals carry no
/// deposit already (REG-1.19), and a kind that reads one way takes none
/// (REG-1.86, HOW A FORM CHANGES LATER).
const THE_MAP: [MapLine; 12] = [
    MapLine {
        of: RowOf::Kind(Kind::Binding),
        read: t_binding,
        ordinals: "55",
        type_value: Some("binding"),
        carries_deposits: true,
    },
    MapLine {
        of: RowOf::Kind(Kind::Endpoint),
        read: t_endpoint,
        ordinals: "56",
        type_value: Some("endpoint"),
        carries_deposits: true,
    },
    MapLine {
        of: RowOf::Kind(Kind::TakedownRecord),
        read: t_takedown_record,
        ordinals: "57",
        type_value: None,
        carries_deposits: false,
    },
    MapLine {
        of: RowOf::Subtype(Subtype::TakedownBase),
        read: t_takedown_base,
        ordinals: "57.1",
        type_value: Some("takedown"),
        carries_deposits: true,
    },
    MapLine {
        of: RowOf::Subtype(Subtype::TakedownLifted),
        read: t_takedown_lifted,
        ordinals: "57.2",
        type_value: None,
        carries_deposits: true,
    },
    MapLine {
        of: RowOf::Kind(Kind::PolicyLink),
        read: t_policy_link,
        ordinals: "58",
        type_value: None,
        carries_deposits: false,
    },
    MapLine {
        of: RowOf::Subtype(Subtype::PolicyLinkOwn),
        read: t_policy_link_own,
        ordinals: "58.1",
        type_value: None,
        carries_deposits: true,
    },
    MapLine {
        of: RowOf::Subtype(Subtype::Disavowal),
        read: t_disavowal,
        ordinals: "58.2",
        type_value: Some("disavowal"),
        carries_deposits: true,
    },
    MapLine {
        of: RowOf::Subtype(Subtype::ExpulsionGround),
        read: t_expulsion_ground,
        ordinals: "58.3",
        type_value: Some("expulsion-ground"),
        carries_deposits: true,
    },
    MapLine {
        of: RowOf::Subtype(Subtype::SuccessionGround),
        read: t_succession_ground,
        ordinals: "58.4",
        type_value: Some("succession-ground"),
        carries_deposits: true,
    },
    MapLine {
        of: RowOf::Subtype(Subtype::SuccessionPolicy),
        read: t_succession_policy,
        ordinals: "58.5",
        type_value: Some("succession-policy"),
        carries_deposits: true,
    },
    MapLine {
        of: RowOf::Kind(Kind::SuccessorOf),
        read: t_successor_of,
        ordinals: "59",
        type_value: None,
        carries_deposits: true,
    },
];

/// REG-1.14, REG-1.15, REG-1.18, REG-1.26, REG-1.86 (a) — THE TABLE IS THE
/// MAP'S, line by line, in its order and no line short: each row is the
/// row of its line's kind or subtype, at its line's address, with its line's
/// `type` string and deposits, and its reader hands back that row's own
/// address, held — two reads one address, not two equal ones.
#[test]
fn the_table_is_the_maps_line_by_line() {
    assert_eq!(rows().len(), THE_MAP.len(), "one line per row of the table");
    for (r, line) in rows().iter().zip(&THE_MAP) {
        let (of, read) = (line.of, line.read);
        assert_eq!(r.of, of);
        assert_eq!(r.address.to_string(), format!("1.1.0.1.0.1.0.3.{}", line.ordinals), "{of:?}");
        assert_eq!(r.type_value, line.type_value, "{of:?}");
        assert_eq!(
            r.carries_deposits(),
            line.carries_deposits,
            "{of:?}: no line's Deposits moves — a kind that reads one way takes no subtype row \
             (REG-1.86, HOW A FORM CHANGES LATER)"
        );
        assert!(std::ptr::eq(read(), &r.address), "{of:?}: the reader is the row's own address");
        assert!(std::ptr::eq(read(), read()), "{of:?}: rebuilt per read");
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

/// THE MAP'S ORDER as a law, whatever the table's lines: `rows()` ascends in
/// the tumbler order (T1), as its doc states, so a row the table gains
/// (REG-1.15) takes its place by its address. The instance — the policy link
/// and its readings ahead of `successor-of`, though `Kind::ALL`, REG-1.14's
/// order, lists `successor-of` first — is [`THE_MAP`]'s line order.
#[test]
fn the_rows_stand_in_ascending_tumbler_order() {
    for pair in rows().windows(2) {
        let (a, b) = (&pair[0].address, &pair[1].address);
        assert!(a < b, "{a} stands ahead of {b}");
    }
}
