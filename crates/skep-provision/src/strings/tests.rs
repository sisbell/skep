//! THE STRINGS TABLE: every row names an id of the four kinds, every slot
//! it holds is one a page fills, and its D-rows are the deployment notes'
//! words.

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
    LEAD,
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
    REPLY_STATUS,
    MAIL_SUBJECT,
    NOT_FOUND,
    BAD_FORM,
    TOO_LARGE,
];

/// THE STRINGS TABLE: every row names an id of the four kinds, every slot it
/// holds is one a page fills, and its D-rows are the notes' words — the
/// notes' `skep.host` the `{suffix}` slot, ⟨the owner's address⟩ the
/// `{owner_address}` one.
#[test]
fn the_strings_table_names_each_rows_id_and_carries_the_notes_words() {
    for row in TABLE {
        assert!(["DRAFT", "RULED", "RULED-SUBSTANCE / DRAFT-WORDING"].contains(&row.id) || row.id.starts_with("D-"), "{row:?}");
        let mut rest = row.text;
        while let Some(open) = rest.find('{') {
            let close = rest[open..].find('}').expect("a closed slot") + open;
            assert!(["suffix", "owner_address", "status", "origin", "principal", "account"].contains(&&rest[open + 1..close]), "{row:?}");
            rest = &rest[close + 1..];
        }
    }
    let mut d_rows: Vec<(&str, String)> =
        TABLE.iter().filter(|r| r.id.starts_with("D-")).map(|r| (r.id, r.text.replace("{suffix}", "skep.host").replace("{owner_address}", "⟨the owner's address⟩"))).collect();
    let mut notes: Vec<(&str, String)> = NOTES.iter().map(|(id, text)| (*id, (*text).to_owned())).collect();
    d_rows.sort();
    notes.sort();
    assert_eq!(d_rows, notes);
}
