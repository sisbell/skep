use std::collections::BTreeSet;

use skep_address::{is_prefix, Nat, Tumbler};

use super::*;
use crate::rows;

/// Every type the brief's table names, by path, in the order the table
/// holds them — the table transcribed once more, so a row dropped or
/// renumbered in `vocabulary.rs` fails here by name.
const PATHS: &[&str] = &[
    "1", "2", "3", "4", "5", "5.1", "5.2", "5.3", "5.4", "5.5", "5.6", "5.7", "5.8", "5.9", "5.10",
    "6", "6.1", "6.2", "6.3", "7", "8", "9", "9.1", "9.2", "9.3", "10", "10.1", "10.2", "10.3",
    "10.4", "11", "12", "13", "14", "14.1", "14.2", "14.3", "14.4", "14.5", "15", "15.1", "15.2",
    "15.3", "15.4", "16", "17", "18", "18.1", "18.2", "18.3", "19", "20", "21", "21.1", "21.2",
    "21.3", "21.4", "21.5", "21.6", "21.7", "21.8", "22", "23", "23.1", "23.2", "23.3", "23.4", "23.5", "23.6", "23.7", "24", "25", "27", "27.1", "27.2", "27.2.1", "27.2.2", "27.3", "28", "30", "40", "41", "42",
    "42.1", "42.2", "42.3", "43", "44", "44.1", "44.2", "45", "46", "46.1", "46.3", "46.4", "46.5",
    "50", "54", "54.1", "54.1.1", "54.1.2", "54.2", "54.2.1", "54.2.2", "54.2.3", "54.3", "54.4",
    "55", "56", "57", "57.1",
    "57.2", "58", "58.1", "58.2", "58.3", "58.4", "58.5", "59", "60", "61", "63", "63.1", "63.2",
    "63.3", "63.4", "63.5", "63.6", "70", "71", "88", "89", "90", "91", "100", "101", "102", "102.1", "103", "104", "104.1", "105",
];

/// The ordinals the table must not name.
///
/// They are the reserved structural and
/// social extensions beyond the built ones — `3.23` inline, `3.24` the
/// held removal and `3.25` marks seeded, `3.26` held for run-of until its
/// pin, `3.29` free — the
/// registry-machinery reserve's unallocated `3.51`–`3.53` (REG-1.24: `3.54`
/// is the registration kind's, and the reserve's others name nothing), the
/// ordinals under the registration no row takes yet — past its approval,
/// past the request's two kinds and past the reply's three answers — the
/// code-link family's `3.63.7`, held for uses until its pin, the
/// proxy kind's `3.87`, the test-only `3.90.1`, the file-metadata family's
/// reserved `3.27.4`, the reader-state family's reserved `3.46.2`, the
/// literary set's free `3.106`, and the unallocated ranges' first ordinals
/// (`3.71` read-with now seeded beside layout, the tier's next free `3.72`
/// unnamed).
const NOT_SEEDED: &[&[u32]] = &[
    &[27, 4],
    &[26],
    &[29],
    &[46, 2],
    &[47],
    &[48],
    &[49],
    &[51],
    &[52],
    &[53],
    &[54, 5],
    &[54, 1, 3],
    &[54, 2, 4],
    &[62],
    &[63, 7],
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

/// THE REGISTRY'S ROWS ARE IN THE TABLE at the addresses `rows.rs` spells,
/// every one, and with the `type` string a body-bearing row carries where
/// the row has one — the body's `type` and the vocabulary's name being one
/// word for the binding, the endpoint, the takedown's base reading, the
/// disavowal, the three ground and policy records and the registration's
/// six bodies — and the table names nothing else inside the registry range
/// (REG-1.24): a row at or under `3.54`–`3.59` is a row of `rows.rs`.
#[test]
fn the_registry_rows_are_in_the_table_as_rows_rs_spells_them() {
    for r in rows() {
        let d = definition_at(&r.address)
            .unwrap_or_else(|| panic!("{} is a registry row and no definition", r.address));
        if let Some(type_value) = r.type_value {
            assert_eq!(d.name, type_value, "{}: the body's type string is the name", r.address);
        }
    }
    let in_the_range: Vec<&Definition> =
        vocabulary().iter().filter(|d| rows::REGISTRY_RANGE.contains(&d.ordinals[0])).collect();
    assert_eq!(in_the_range.len(), rows().len(), "the range holds the registry's rows alone");
    for d in in_the_range {
        assert!(crate::row_at(&d.address).is_some(), "{}: a row of rows.rs", d.address);
    }
    assert_eq!(definition_at(rows::t_registration()).map(|d| d.name), Some("registration"));
    assert_eq!(definition_at(rows::t_request()).map(|d| d.name), Some("request"));
    assert_eq!(definition_at(rows::t_reply()).map(|d| d.name), Some("reply"));
    assert_eq!(definition_at(rows::t_approval()).map(|d| d.name), Some("approval"));
    assert_eq!(definition_at(rows::t_successor_of()).map(|d| d.name), Some("successor-of"));
    assert_eq!(definition_at(rows::t_takedown_record()).map(|d| d.name), Some("takedown-record"));
    assert_eq!(definition_at(rows::t_takedown_lifted()).map(|d| d.name), Some("lifted"));
    assert_eq!(definition_at(rows::t_policy_link()).map(|d| d.name), Some("policy-link"));
    assert_eq!(definition_at(rows::t_policy_link_own()).map(|d| d.name), Some("policy"));
}

/// THE REGISTRATION FAMILY IS THE COMMONS MAP'S, WORD FOR WORD (REG-1.14,
/// REG-1.15, REG-1.26; the map's table of the family's names, purposes and
/// endsets, the owner's words, permanent once a board writes them): the ten
/// rows at `3.54` and under it, read by address, each held to its name, its
/// purpose and its endsets as the map prints them — a row that carries no
/// deposit saying so in its purpose and leading its endsets "from and to:",
/// a record row's endsets reading "from: …; to: …". A name may repeat under
/// a different parent, which gives it its context: `request` repeats mail's
/// `3.15.3` and `approval` an assignment's `3.18.3`.
#[test]
fn the_registration_rows_are_the_commons_maps_word_for_word() {
    let the_map: [(&[u32], &str, &str, &str); 10] = [
        (
            &[54],
            "registration",
            "The records of a board's request to join a registry; read through the rows under it; no deposit rides the kind itself.",
            "from and to: as the rows under it say.",
        ),
        (
            &[54, 1],
            "request",
            "A board's request to join; read through its kinds below; no deposit rides this row itself.",
            "from and to: as the rows under it say.",
        ),
        (
            &[54, 1, 1],
            "fresh",
            "A request from an org with no board yet: it asks for its account and its board.",
            "from: the record's atom; to: the account that writes this board's bindings.",
        ),
        (
            &[54, 1, 2],
            "board-carries-on",
            "A request from an org that keeps its own board: it asks for its account alone.",
            "from: the record's atom; to: the account that writes this board's bindings.",
        ),
        (
            &[54, 2],
            "reply",
            "The registry's answer to a request; read through its answers below; no deposit rides this row itself.",
            "from and to: as the rows under it say.",
        ),
        (
            &[54, 2, 1],
            "approved",
            "The request is approved: the new account's address and number.",
            "from: the record's atom; to: the request answered.",
        ),
        (
            &[54, 2, 2],
            "refused",
            "The request is refused for a fault in it, never a judgment of the person.",
            "from: the record's atom; to: the request answered.",
        ),
        (
            &[54, 2, 3],
            "denied",
            "An officer denies the request, citing a clause of the door's policy.",
            "from: the record's atom; to: the request answered.",
        ),
        (
            &[54, 3],
            "vouch",
            "One account speaking for an applicant.",
            "from: the record's atom; to: the account that writes this board's bindings.",
        ),
        (
            &[54, 4],
            "approval",
            "Ties the account a registrar made to the request it answers; a link alone.",
            "from: the genesis the approval wrote; to: the request answered.",
        ),
    ];
    for (ordinals, name, purpose, endsets) in the_map {
        let row = definition_at(&commons_type(ordinals))
            .unwrap_or_else(|| panic!("3.{ordinals:?}: a row"));
        assert_eq!(row.name, name, "3.{ordinals:?}: the name");
        assert_eq!(row.purpose, purpose, "{name}: the purpose");
        assert_eq!(row.endsets, endsets, "{name}: the endsets");
        let registry_row = crate::row_at(&row.address).expect("a row of rows.rs");
        assert_eq!(
            row.endsets.starts_with("from and to:"),
            !registry_row.carries_deposits(),
            "{name}: a row that carries no deposit leads its endsets \"from and to:\""
        );
    }
    let family: Vec<&Definition> = vocabulary().iter().filter(|d| d.ordinals[0] == 54).collect();
    assert_eq!(family.len(), the_map.len(), "the family is the rows held above");
    let name = |ordinals: &[u32]| definition_at(&commons_type(ordinals)).map(|d| d.name);
    assert_eq!((name(&[15, 3]), name(&[18, 3])), (Some("request"), Some("approval")));
}

/// WHAT IS NOT SEEDED answers no definition: the reserved ordinals beyond
/// the built ones, the unallocated reserve, the proxy kind's `3.87`, the
/// test-only `3.90.1`, the file-metadata family's reserved `3.27.4`, the
/// reader-state family's reserved `3.46.2`, the literary set's free
/// ordinals, and an address beneath or above a row — the inline family's
/// eighth style, the reader-state family's sixth state and the
/// counterpart's second subtype among the last.
#[test]
fn nothing_is_named_at_an_ordinal_nobody_allocated() {
    for &ordinals in NOT_SEEDED {
        assert_eq!(definition_at(&commons_type(ordinals)), None, "3.{ordinals:?} is not seeded");
    }
    let subspace = Tumbler::new([1u32, 1, 0, 1, 0, 1, 0, 3].map(Nat::from)).expect("nonempty");
    let subspace = skep_address::validate(subspace).expect("T4-valid");
    assert_eq!(definition_at(&subspace), None, "the subspace itself is no row");
    assert_eq!(definition_at(&commons_type(&[13, 1])), None, "beneath citation");
    assert_eq!(definition_at(&commons_type(&[23, 8])), None, "beneath inline, past its seven");
    assert_eq!(definition_at(&commons_type(&[46, 2])), None, "beneath reader-state: kept for flagged");
    assert_eq!(definition_at(&commons_type(&[46, 6])), None, "beneath reader-state, past spam");
    assert_eq!(definition_at(&commons_type(&[102, 2])), None, "beneath counterpart, past the correspondence");
}

/// THE LINK-SETS ROWS (the commons seeding round, pinned 2026-10-27): the
/// eleven rows stand at the addresses the map pins, under the map's token
/// names — `inline` the family's parent with its seven styles nested under
/// it, `held-removal` a type of its own in the structural reserve,
/// `read-with` in the presentation tier beside layout, `correspondence` a
/// subtype under counterpart — and the correspondence's and the held
/// removal's rows are the shapes the design states, the parent `counterpart`
/// keeping its own two-sided one.
#[test]
fn the_link_sets_rows_stand_at_their_pinned_addresses() {
    let name = |ordinals: &[u32]| definition_at(&commons_type(ordinals)).map(|d| d.name);
    assert_eq!(name(&[23]), Some("inline"));
    for (ordinal, style) in [
        (1, "emphasis"),
        (2, "strong"),
        (3, "code"),
        (4, "mark"),
        (5, "strikethrough"),
        (6, "subscript"),
        (7, "superscript"),
    ] {
        let row = definition_at(&commons_type(&[23, ordinal])).expect("a style's row");
        assert_eq!(row.name, style);
        assert_eq!(row.endsets, "from: empty; to: the span styled.", "{style}: a mark's shape");
    }
    assert_eq!(name(&[24]), Some("held-removal"));
    assert_eq!(name(&[71]), Some("read-with"));
    assert_eq!(name(&[102, 1]), Some("correspondence"));
    assert_eq!(name(&[102]), Some("counterpart"), "the parent keeps its own row");
    let held = definition_at(&commons_type(&[24])).expect("the held removal's row");
    assert_eq!(held.endsets, "from: empty; to: the published mark, by address.");
    let correspondence = definition_at(&commons_type(&[102, 1])).expect("the correspondence's row");
    assert_eq!(
        correspondence.endsets,
        "from: the run's draft-native span; to: the member's span it became, both of one width."
    );
    assert_eq!(
        definition_at(&commons_type(&[102])).expect("counterpart").endsets,
        "from: the one passage; to: its counterpart."
    );
}

/// Checks that the marks row stands at `3.25` with its words.
///
/// It stands in the structural reserve after the held
/// removal, under the map's token name and held to its purpose and its
/// endsets word for word: the link a mark of a draft carries, `from` the
/// mark's whole content and `to` the draft, homed in the mark — a two-sided
/// link, never the one-sided shape the inline style `mark` `3.23.4` keeps.
#[test]
fn the_marks_row_stands_at_3_25_with_its_words() {
    let marks = definition_at(&commons_type(&[25])).expect("the marks row");
    assert_eq!(marks.address.tumbler().to_string(), "1.1.0.1.0.1.0.3.25");
    assert_eq!(marks.name, "marks");
    assert_eq!(
        marks.purpose,
        "A mark: a private copy holding a draft's whole content by identity, kept to diff against later; the link says what the copy is and which draft it marks."
    );
    assert_eq!(marks.endsets, "from: the mark's whole content; to: the draft; homed in the mark.");
    let style = definition_at(&commons_type(&[23, 4])).expect("the inline style's row");
    assert_eq!(
        (style.name, style.endsets),
        ("mark", "from: empty; to: the span styled."),
        "the style keeps its own row"
    );
    let after: Vec<&[u32]> = vocabulary()
        .iter()
        .map(|d| d.ordinals)
        .skip_while(|ordinals| *ordinals != [24])
        .take(3)
        .collect();
    assert_eq!(
        after,
        [&[24][..], &[25], &[27]],
        "in path order, between the held removal and the file-metadata family"
    );
}

/// Checks that the code-link family stands at `3.63` with its words.
///
/// The parent and its six kinds stand in the agentic tier after the
/// steward's classification and before layout, under the map's token names
/// and held to their purposes and endsets word for word (commons-map
/// decision 11 (a)): the parent, written by nothing, says its endsets are
/// the rows' under it; `fixes`, `concerns`, `tests`, `explains`, `guides`
/// and `found-while` follow in the prototype's order. Nothing stands at
/// `3.63.7`, whose pin the map holds for `uses` (decision 11 (h)).
#[test]
fn the_code_link_family_stands_at_3_63_with_its_words() {
    let the_map: [(&[u32], &str, &str, &str); 7] = [
        (
            &[63],
            "code-link",
            "The code-link family's parent: links on code held in a tree — what an issue concerns and where it was found, what a change fixes, what a test checks, what a text explains, what guidance governs, what code uses — each a kind under this one; a link typed at the parent itself is written by nothing.",
            "from and to: as the rows under it say.",
        ),
        (
            &[63, 1],
            "fixes",
            "A change fixes an issue: the issue is closed while such a link to it stands.",
            "from: the link's own words (why, who) and the changed text; to: the issue.",
        ),
        (
            &[63, 2],
            "concerns",
            "An issue is about this code; one to a tree's manifest makes its document an issue of that tree.",
            "from: the issue's words (why, who), or its title in the one to the manifest; to: the code, or the tree.",
        ),
        (
            &[63, 3],
            "tests",
            "A test checks this code.",
            "from: the link's own words (why, who) and the test; to: the code it checks.",
        ),
        (
            &[63, 4],
            "explains",
            "A text explains this code.",
            "from: the link's own words (why, who) and the text; to: the code it explains.",
        ),
        (
            &[63, 5],
            "guides",
            "Guidance governs a part of a tree: some lines, a file, a folder, the whole tree.",
            "from: the link's own words (why, who) and the guidance; to: what it governs.",
        ),
        (
            &[63, 6],
            "found-while",
            "An issue was found while this work was being done.",
            "from: the issue's words (what was being done, who); to: the work, or the tree.",
        ),
    ];
    for (ordinals, name, purpose, endsets) in the_map {
        let row = definition_at(&commons_type(ordinals))
            .unwrap_or_else(|| panic!("3.{ordinals:?}: a row"));
        let path = ordinals.iter().map(ToString::to_string).collect::<Vec<_>>().join(".");
        assert_eq!(row.address.tumbler().to_string(), format!("1.1.0.1.0.1.0.3.{path}"));
        assert_eq!(row.name, name, "3.{path}: the name");
        assert_eq!(row.purpose, purpose, "{name}: the purpose");
        assert_eq!(row.endsets, endsets, "{name}: the endsets");
    }
    let around: Vec<&[u32]> = vocabulary()
        .iter()
        .map(|d| d.ordinals)
        .skip_while(|ordinals| *ordinals != [61])
        .take(9)
        .collect();
    assert_eq!(
        around,
        [&[61][..], &[63], &[63, 1], &[63, 2], &[63, 3], &[63, 4], &[63, 5], &[63, 6], &[70]],
        "in path order, between the steward's classification and layout"
    );
    assert_eq!(definition_at(&commons_type(&[63, 7])), None, "uses: its pin held");
}

/// THE MAIL ROWS ADDRESS A MAILBOX: `mail` `3.15` and its four subtypes,
/// read by address, each held to its name, its purpose and its endsets word
/// for word — mail is addressed to a mailbox, a reply answers a letter or a
/// passage of it, and `urgent`, `invitation` and `request` keep their own
/// purposes — and no line of the family's sections says mail is sent, or
/// that it goes to the recipient account.
#[test]
fn the_mail_rows_address_a_mailbox() {
    let rows: [(&[u32], &str, &str, &str); 5] = [
        (
            &[15],
            "mail",
            "Mail: a message addressed to an account's mailbox.",
            "from: the message's text; to: the recipient's mailbox, and for a reply the letter, or \
             the passage of it, answered.",
        ),
        (&[15, 1], "urgent", "Mail marked urgent.", "from: the message's text; to: the recipient's mailbox."),
        (
            &[15, 2],
            "invitation",
            "Mail that invites its recipient.",
            "from: the invitation's text; to: the recipient's mailbox.",
        ),
        (
            &[15, 3],
            "request",
            "Mail that asks something of its recipient.",
            "from: the request's text; to: the recipient's mailbox.",
        ),
        (
            &[15, 4],
            "broadcast",
            "Mail addressed to many mailboxes at once.",
            "from: the message's text; to: the recipients' mailboxes.",
        ),
    ];
    for (ordinals, name, purpose, endsets) in rows {
        let row = definition_at(&commons_type(ordinals))
            .unwrap_or_else(|| panic!("3.{ordinals:?}: a row"));
        assert_eq!(row.name, name, "3.{ordinals:?}: the name");
        assert_eq!(row.purpose, purpose, "{name}: the purpose");
        assert_eq!(row.endsets, endsets, "{name}: the endsets");
    }
    let family: Vec<&Definition> = vocabulary().iter().filter(|d| d.ordinals[0] == 15).collect();
    assert_eq!(family.len(), rows.len(), "the family is the five rows held above");
    for d in family {
        for line in d.section().lines() {
            assert!(!line.contains("sent"), "{}: mail is addressed, never sent: {line:?}", d.name);
            assert!(
                !line.contains("recipient account"),
                "{}: mail goes to a mailbox: {line:?}",
                d.name
            );
        }
    }
}

/// THE READER-STATE FAMILY: the parent `reader-state` at `3.46` and its four
/// states — `seen` `3.46.1`, `acknowledged` `3.46.3`, `important` `3.46.4`
/// and `spam` `3.46.5` — read by address, each held to its name, its
/// purpose and its endsets word for word, with `3.46.2` between them
/// unwritten. `acknowledged` is a reader's state and `acknowledgment` `3.19`
/// a credit for a part in a work: two names at two rows. And no row of the
/// family is a mark: the account that records the state speaks in `from`,
/// so no endsets line starts "from: empty", and no purpose or endsets line
/// holds the word "mark".
#[test]
fn the_reader_state_rows_stand_under_their_names_and_are_no_marks() {
    let rows: [(&[u32], &str, &str); 5] = [
        (&[46], "reader-state", "A reader's own state for a mailing they received."),
        (&[46, 1], "seen", "A mailing its reader has seen."),
        (&[46, 3], "acknowledged", "A mailing its reader acknowledges receiving."),
        (&[46, 4], "important", "A mailing its reader holds important."),
        (&[46, 5], "spam", "A mailing its reader judges to be spam."),
    ];
    for (ordinals, name, purpose) in rows {
        let row = definition_at(&commons_type(ordinals))
            .unwrap_or_else(|| panic!("3.{ordinals:?}: a row"));
        assert_eq!(row.name, name, "3.{ordinals:?}: the name");
        assert_eq!(row.purpose, purpose, "{name}: the purpose");
        assert_eq!(
            row.endsets, "from: the account recording it; to: the mail link.",
            "{name}: the endsets"
        );
    }
    let name = |ordinals: &[u32]| definition_at(&commons_type(ordinals)).map(|d| d.name);
    assert_eq!(
        (name(&[46, 3]), name(&[19])),
        (Some("acknowledged"), Some("acknowledgment")),
        "a reader's state and a credit for a part in a work, under two names"
    );
    let family: Vec<&Definition> = vocabulary().iter().filter(|d| d.ordinals[0] == 46).collect();
    assert_eq!(family.len(), rows.len(), "the family is the five rows held above");
    for d in family {
        assert!(
            !d.endsets.starts_with("from: empty"),
            "{}: the account speaks in `from`, so no mark",
            d.name
        );
        for line in [d.purpose, d.endsets] {
            assert!(
                !line.contains("mark"),
                "{}: the word is not used of a reader's state: {line:?}",
                d.name
            );
        }
    }
}

/// NO FORK ROW STANDS (B3-S10): the board records where a staged draft began
/// in its own state, at the `stage` operation, and no link of a client's
/// says it — nothing answers at `3.9.4`, no row is named `fork`, alternative
/// keeps its three subtypes, and the table holds one row a path of this
/// suite's transcription, the seed's one link and one section per row.
#[test]
fn no_fork_row_stands_under_alternative() {
    let name = |ordinals: &[u32]| definition_at(&commons_type(ordinals)).map(|d| d.name);
    assert_eq!(name(&[9, 4]), None, "no row at 3.9.4");
    assert!(vocabulary().iter().all(|d| d.name != "fork"), "no row named fork");
    assert_eq!(name(&[9]), Some("alternative"), "the parent keeps its own row");
    assert_eq!((name(&[9, 1]), name(&[9, 2]), name(&[9, 3])), (Some("draft"), Some("revision"), Some("branch")));
    assert_eq!(vocabulary().len(), PATHS.len(), "the table's rows");
}

/// THE ENDSETS BY ROLE (the commons map's standing rule, F5): every mark —
/// the heading, the paragraph and its eight kinds, lang, the inline family,
/// the held removal, the file-metadata family's bare facts — has an empty
/// `from` and its matter in `to`; the claim `3.3` stands as built, the
/// rule's one named exception, and no row says "to: empty" but the sayings
/// with no subject (the claim, the endpoint, the targetless binding's and
/// the any-principal grant's alternatives).
#[test]
fn every_mark_says_from_empty_and_its_matter_in_to() {
    let endsets = |ordinals: &[u32]| definition_at(&commons_type(ordinals)).expect("a row").endsets;
    assert_eq!(endsets(&[20]), "from: empty; to: the heading's text; its level a parameter span in the type slot.");
    assert_eq!(endsets(&[21]), "from: empty; to: the paragraph's text.");
    for (ordinal, matter) in [
        (1, "the paragraph's text"),
        (2, "the quoted text"),
        (3, "the code's text"),
        (4, "the list's text"),
        (5, "the note's text"),
        (6, "the definition's text"),
        (7, "the example's text"),
        (8, "the warning's text"),
    ] {
        assert_eq!(endsets(&[21, ordinal]), format!("from: empty; to: {matter}."), "3.21.{ordinal}");
    }
    assert_eq!(endsets(&[30]), "from: empty; to: the passage.");
    for ordinals in [&[23][..], &[23, 2], &[24], &[27, 2], &[27, 2, 1], &[57, 2], &[58, 1]] {
        assert!(endsets(ordinals).starts_with("from: empty; to: "), "3.{ordinals:?}: a mark");
    }
    assert_eq!(endsets(&[3]), "from: the claiming account; to: empty.", "the claim stands as built");
    let to_empty: Vec<&str> = vocabulary()
        .iter()
        .filter(|d| d.endsets.ends_with("to: empty."))
        .map(|d| d.name)
        .collect();
    assert_eq!(to_empty, ["claim", "endpoint"], "the sayings with no subject alone");
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
