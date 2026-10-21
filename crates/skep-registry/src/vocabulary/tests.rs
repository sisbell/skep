use std::collections::BTreeSet;

use skep_address::{is_prefix, Nat, Tumbler};

use super::*;
use crate::rows;

/// Every type the brief's table names, by path, in the order the table
/// holds them — the table transcribed once more, so a row dropped or
/// renumbered in `vocabulary.rs` fails here by name.
const PATHS: [&str; 108] = [
    "1", "2", "3", "4", "5", "5.1", "5.2", "5.3", "5.4", "5.5", "5.6", "5.7", "5.8", "5.9", "5.10",
    "6", "6.1", "6.2", "6.3", "7", "8", "9", "9.1", "9.2", "9.3", "10", "10.1", "10.2", "10.3",
    "10.4", "11", "12", "13", "14", "14.1", "14.2", "14.3", "14.4", "14.5", "15", "15.1", "15.2",
    "15.3", "15.4", "16", "17", "18", "18.1", "18.2", "18.3", "19", "20", "21", "21.1", "21.2",
    "21.3", "21.4", "21.5", "21.6", "21.7", "21.8", "22", "27", "27.1", "27.2", "27.2.1", "27.2.2", "27.3", "28", "30", "40", "41", "42",
    "42.1", "42.2", "42.3", "43", "44", "44.1", "44.2", "45", "50", "55", "56", "57", "57.1",
    "57.2", "58", "58.1", "58.2", "58.3", "58.4", "58.5", "59", "60", "61", "70", "88", "89", "90", "91", "100", "101", "102", "103", "104", "104.1", "105",
];

/// The ordinals the table must NOT name: the reserved structural and
/// social extensions beyond the built ones, the registry-machinery reserve
/// `3.51`–`3.54`, the proxy kind's `3.87`, the test-only `3.90.1`, the
/// file-metadata family's reserved `3.27.4`, the literary set's free
/// `3.106`, and the unallocated ranges' first ordinals.
const NOT_SEEDED: [&[u32]; 22] = [
    &[27, 4],
    &[23],
    &[24],
    &[25],
    &[26],
    &[29],
    &[46],
    &[47],
    &[48],
    &[49],
    &[51],
    &[52],
    &[53],
    &[54],
    &[62],
    &[71],
    &[80],
    &[87],
    &[90, 1],
    &[92],
    &[106],
    &[110],
];

fn path_of(d: &Definition) -> String {
    d.ordinals.iter().map(ToString::to_string).collect::<Vec<_>>().join(".")
}

/// THE TABLE IS THE BRIEF's, ROW FOR ROW: the paths in order, each row's
/// address the type subspace's element at its ordinals, its name a
/// lowercase token, its purpose and endset shape non-empty — and every
/// address distinct.
#[test]
fn the_table_holds_every_type_the_build_names_in_path_order() {
    let rows = vocabulary();
    assert_eq!(rows.len(), PATHS.len());
    let paths: Vec<String> = rows.iter().map(path_of).collect();
    assert_eq!(paths, PATHS, "the table's paths, in order");
    let mut seen = BTreeSet::new();
    for d in rows {
        assert_eq!(
            d.address.tumbler().to_string(),
            format!("1.1.0.1.0.1.0.3.{}", path_of(d)),
            "the address is the type subspace's element at the row's path"
        );
        assert!(seen.insert(d.address.clone()), "{} is spelled twice", d.address);
        assert!(
            !d.name.is_empty()
                && d.name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
                && !d.name.starts_with('-')
                && !d.name.ends_with('-'),
            "{}: the name {:?} is one lowercase token",
            d.address,
            d.name
        );
        assert!(!d.purpose.trim().is_empty(), "{}: a purpose", d.address);
        assert!(!d.endsets.trim().is_empty(), "{}: an endset shape", d.address);
        assert!(!d.purpose.contains('\n') && !d.endsets.contains('\n'), "{}: one line each", d.address);
    }
}

/// THE ORDER IS THE TUMBLER's (T1), ascending — the order the daemon writes
/// the sections and the links in — so `3.5.10` follows `3.5.9` and precedes
/// `3.6`, and `defines` `3.50` stands ahead of the registry's `3.55`.
#[test]
fn the_rows_stand_in_ascending_tumbler_order() {
    let rows = vocabulary();
    for pair in rows.windows(2) {
        assert!(
            pair[0].address.tumbler() < pair[1].address.tumbler(),
            "{} comes before {}",
            pair[0].address,
            pair[1].address
        );
    }
}

/// A SUBTYPE NESTS UNDER ITS TYPE'S ROW ALONE (L10: hierarchy is prefix):
/// every row of two ordinals has the one-ordinal row above it in the table,
/// and no row is a prefix of another but a type of its own subtypes.
#[test]
fn every_subtype_row_nests_under_a_type_the_table_holds() {
    let rows = vocabulary();
    for d in rows {
        if d.ordinals.len() > 1 {
            let above = &d.ordinals[..d.ordinals.len() - 1];
            assert!(
                rows.iter().any(|t| t.ordinals == above),
                "{}: the type above it is a row",
                d.address
            );
        }
        assert!(d.ordinals.len() <= 3, "{}: at most a type, a subtype and a value", d.address);
    }
    for a in rows {
        for b in rows {
            if a.address != b.address && is_prefix(a.address.tumbler(), b.address.tumbler()) {
                assert!(
                    b.ordinals.len() > a.ordinals.len() && b.ordinals[..a.ordinals.len()] == *a.ordinals,
                    "{} is a prefix of {} and no type of it",
                    a.address,
                    b.address
                );
            }
        }
    }
}

/// THE REGISTRY'S TWELVE ROWS ARE IN THE TABLE at the addresses `rows.rs`
/// spells, and with the `type` string a body-bearing row carries where the
/// row has one — the body's `type` and the vocabulary's name being one word
/// for the binding, the endpoint, the takedown's base reading, the
/// disavowal and the three ground and policy records.
#[test]
fn the_registry_rows_are_in_the_table_as_rows_rs_spells_them() {
    for r in rows() {
        let d = definition_at(&r.address)
            .unwrap_or_else(|| panic!("{} is a registry row and no definition", r.address));
        if let Some(type_value) = r.type_value {
            assert_eq!(d.name, type_value, "{}: the body's type string is the name", r.address);
        }
    }
    assert_eq!(definition_at(rows::t_successor_of()).map(|d| d.name), Some("successor-of"));
    assert_eq!(definition_at(rows::t_takedown_record()).map(|d| d.name), Some("takedown-record"));
    assert_eq!(definition_at(rows::t_takedown_lifted()).map(|d| d.name), Some("lifted"));
    assert_eq!(definition_at(rows::t_policy_link()).map(|d| d.name), Some("policy-link"));
    assert_eq!(definition_at(rows::t_policy_link_own()).map(|d| d.name), Some("policy"));
}

/// WHAT IS NOT SEEDED answers no definition: the reserved ordinals beyond
/// the built ones, the unallocated reserve, the proxy kind's `3.87`, the
/// test-only `3.90.1`, the file-metadata family's reserved `3.27.4`, the
/// literary set's free ordinals, and an address beneath or above a row.
#[test]
fn nothing_is_named_at_an_ordinal_nobody_allocated() {
    for ordinals in NOT_SEEDED {
        assert_eq!(definition_at(&commons_type(ordinals)), None, "3.{ordinals:?} is not seeded");
    }
    let subspace = Tumbler::new([1u32, 1, 0, 1, 0, 1, 0, 3].map(Nat::from)).expect("nonempty");
    let subspace = skep_address::validate(subspace).expect("T4-valid");
    assert_eq!(definition_at(&subspace), None, "the subspace itself is no row");
    assert_eq!(definition_at(&commons_type(&[13, 1])), None, "beneath citation");
}

/// THE META-TYPE is `3.50`, named `defines`, held once, and it is the one
/// row whose definition link types itself.
#[test]
fn the_meta_type_is_the_tables_own_row() {
    let defines = defines_type();
    assert_eq!(defines.tumbler().to_string(), "1.1.0.1.0.1.0.3.50");
    let row = definition_at(defines).expect("a row");
    assert_eq!(row.name, "defines");
    assert!(std::ptr::eq(defines, &row.address), "one held address, not a copy");
    assert!(std::ptr::eq(defines_type(), defines_type()), "held across reads");
}

/// THE SECTION the daemon writes: four newline-ended lines — the name alone
/// on the first, the address on the second, the purpose, the endset shape —
/// and no two rows' sections are one another's bytes, nor does one section
/// contain another at a line start, so the daemon finds a section a crash
/// left unlinked by its exact bytes and never another row's.
#[test]
fn a_section_opens_with_the_name_alone_and_is_the_rows_own() {
    let rows = vocabulary();
    for d in rows {
        let section = d.section();
        let lines: Vec<&str> = section.split('\n').collect();
        assert_eq!(lines.len(), 5, "{}: four lines, each ended by a newline", d.address);
        assert_eq!(lines[0], d.name);
        assert_eq!(lines[1], d.address.tumbler().to_string());
        assert_eq!(lines[2], d.purpose);
        assert_eq!(lines[3], d.endsets);
        assert_eq!(lines[4], "");
    }
    let sections: Vec<String> = rows.iter().map(Definition::section).collect();
    for (i, a) in sections.iter().enumerate() {
        for (j, b) in sections.iter().enumerate() {
            if i != j {
                assert!(
                    !b.contains(a.as_str()),
                    "{}'s section lies inside {}'s",
                    rows[i].address,
                    rows[j].address
                );
            }
        }
    }
    let citation = definition_at(&commons_type(&[13])).expect("citation");
    assert_eq!(
        citation.section(),
        "citation\n1.1.0.1.0.1.0.3.13\nA citation: a passage cites another.\nfrom: the citing \
         passage; to: the passage cited.\n"
    );
}

/// THE TABLE IS ONE HELD VALUE: two reads are one instance, and a row read
/// by address is the table's own and no copy.
#[test]
fn the_table_is_one_held_value() {
    assert!(std::ptr::eq(vocabulary(), vocabulary()));
    let a = &vocabulary()[0];
    assert!(std::ptr::eq(a, definition_at(&a.address).expect("the first row")));
}
