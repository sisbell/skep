//! THE STRINGS TABLE: every row names an id of the four kinds, every slot it
//! names is one of the six the program fills, every `{` opening one, and its
//! D-rows are the deployment notes' words; and a row shown where a slot it
//! names is not filled is the showing code's bug, caught in every test
//! build.

use super::*;

/// The notes' D-table (`_designs/deployment-notes.md` §4 step 1 and §12),
/// as LITERALS: each row's words with `skep.host` and ⟨the owner's
/// address⟩ as the notes write them.
const NOTES: [(&str, &str); 11] = [
    ("D-1", "A board of your own at a name under skep.host. Your keys stay on your device: this page makes none."),
    ("D-2", "Your board's name"),
    ("D-2", "one label: letters, digits and hyphens; it becomes ⟨name⟩.skep.host"),
    ("D-3", "Your record"),
    ("D-3", "On your own device run `skep keygen --anchors --anchor-out <a> --anchor-out <b>` (two papers, kept apart) or `skep keygen --payload`, and paste the one line it printed. Paste only what it printed: it holds no private key."),
    ("D-4", "That name is taken, or is not one label of letters, digits and hyphens. Choose another."),
    ("D-5", "This is not a record skep keygen printed. Paste the whole line, exactly as printed."),
    ("D-6", "This record names a preview key. A hosted board enrolls the production kind alone: make the record again with a client that generates it."),
    ("D-7", "Your board is being made. Keep this page open: it shows your board when it is live."),
    ("D-8", "Your board could not be made. Nothing stands under your name; try again later, or write to ⟨the owner's address⟩."),
    ("D-9", "Your invite code"),
];

/// Every row of the table.
const TABLE: [Words; 33] = [
    SIGNUP_LEAD,
    SIGNUP_KEPT,
    ADDRESS_LABEL,
    SIGNUP_BUTTON,
    SIGNUP_REFUSED,
    SIGNUP_FAILED,
    THANKS,
    CLAIM_LEAD,
    NAME_LABEL,
    NAME_HELP,
    RECORD_LABEL,
    RECORD_HELP,
    INVITE_LABEL,
    CLAIM_BUTTON,
    NAME_REFUSED,
    RECORD_REFUSED,
    PREVIEW_REFUSED,
    INVITE_REFUSED,
    BEING_MADE,
    STATUS_URL,
    FAILED,
    LIVE,
    OPERATOR,
    ANCHORLESS,
    PUBLIC_VENUE,
    FACTS,
    FIRST_ACT,
    SECOND_ACT,
    REPLY_STATUS_URL,
    MAIL_SUBJECT,
    NOT_FOUND,
    BAD_FORM,
    TOO_LARGE,
];

/// THE STRINGS TABLE: every row names an id of the four kinds, every slot it
/// names is one of the six the program fills, every `{` opening one, and its
/// D-rows are the notes' words — the notes' `skep.host` the `{suffix}` slot,
/// ⟨the owner's address⟩ the `{owner_address}` one.
#[test]
fn the_strings_table_names_each_rows_id_and_carries_the_notes_words() {
    for row in TABLE {
        assert!(["DRAFT", "RULED", "RULED-SUBSTANCE / DRAFT-WORDING"].contains(&row.id) || row.id.starts_with("D-"), "{row:?}");
        for slot in row.slots() {
            assert!(["suffix", "owner_address", "status_url", "origin", "principal", "account"].contains(&slot), "{row:?}");
        }
        assert_eq!(row.slots().count(), row.text.matches('{').count(), "{row:?}: a `{{` that no `}}` closes");
    }
    let mut d_rows: Vec<(&str, String)> =
        TABLE.iter().filter(|r| r.id.starts_with("D-")).map(|r| (r.id, r.text.replace("{suffix}", "skep.host").replace("{owner_address}", "⟨the owner's address⟩"))).collect();
    let mut notes: Vec<(&str, String)> = NOTES.iter().map(|(id, text)| (*id, (*text).to_owned())).collect();
    d_rows.sort();
    notes.sort();
    assert_eq!(d_rows, notes);
}

/// A ROW SHOWN WITHOUT A SLOT IT NAMES IS THE SHOWING CODE's BUG: D-8
/// filled with no owner's address fails in every debug build — every test
/// build.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "is shown where a slot it names is not filled")]
fn a_row_shown_without_a_slot_it_names_is_the_callers_bug() {
    fill(FAILED, &[]);
}
