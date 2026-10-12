//! T11 — THE REPLY: the operator sentence and the public-venue statement
//! always; the anchorless sentence iff the record carried no anchor; the
//! `local_trust` clause never; the public origin everywhere and the dialed
//! one nowhere; the two acts composed from the `skep` command's own format
//! strings with the public origin, AUTH-5.87's sentence and the read's
//! limit in them; the three facts; the status address last; and the mail's
//! text the page's text with the headers before it.

use super::*;
use crate::pages::{fill, ANCHORLESS, OPERATOR, PUBLIC_VENUE};
use crate::record::Name;
use crate::sender::Message;

const ORIGIN: &str = "https://alice.skep.host";
const STATUS: &str = "https://skep.host/status/0123456789abcdef0123456789abcdef";

/// THE `skep` COMMAND's OWN FORMAT STRINGS for the two acts
/// (`skep-cli`'s `commands/claim.rs`, the hosted arm's fifth and sixth DATA
/// lines), as LITERALS with the public origin and the principal 1 where the
/// binary puts the dialed origin and its principal, and where its second
/// act writes `<origin>`.
const FIRST_ACT_AS_THE_BINARY_WRITES_IT: &str = "first act: from the device that generated the payload run `skep verify --board https://alice.skep.host --principal 1 --payload <the record it printed>` (or `--anchor <a> --anchor <b>`): the genesis record compared entry for entry, fingerprint and anchor flag, against what that device composed — it confirms the keys on the board, and it cannot tell you the board will open a session for you";
const SECOND_ACT_AS_THE_BINARY_WRITES_IT: &str = "second act: in your first signed session the setup act runs — `skep claim --board https://alice.skep.host --dir <store>` from that device performs it: creating your account also creates a space for your agents beneath it, and its home";

/// T11: THE OPERATOR SENTENCE AND THE PUBLIC-VENUE STATEMENT ALWAYS — the
/// latter verbatim — and THE ANCHORLESS SENTENCE IFF `anchorless`.
#[test]
fn the_ruled_strings_by_condition() {
    for anchorless in [false, true] {
        let reply = text(ORIGIN, anchorless, STATUS);
        assert!(reply.contains(OPERATOR.text), "{anchorless}");
        assert!(reply.contains(PUBLIC_VENUE.text), "{anchorless}");
        assert!(reply.contains("every edit to this page, including what you later remove, is public history —"), "the notes' quoted opening");
        assert_eq!(reply.contains(ANCHORLESS.text), anchorless);
        assert_eq!(reply.contains("skep recover"), anchorless);
    }
}

/// T11: THE `local_trust` CLAUSE NEVER: its key words — local trust, a
/// party reaching the loopback, writing with no key at all, reading every
/// draft — appear under neither input.
#[test]
fn the_local_trust_clause_never() {
    for anchorless in [false, true] {
        let reply = text(ORIGIN, anchorless, STATUS).to_lowercase();
        for words in ["local trust", "local_trust", "loopback", "no key at all", "every draft", "with local trust on"] {
            assert!(!reply.contains(words), "{words}: {reply}");
        }
    }
}

/// T11: THE PUBLIC ORIGIN EVERYWHERE — the facts and both acts — and the
/// DIALED `127.0.0.1:8642` NOWHERE, the binary's `<origin>` filled.
#[test]
fn the_public_origin_everywhere_and_the_dialed_one_nowhere() {
    let reply = text(ORIGIN, true, STATUS);
    assert_eq!(reply.matches(ORIGIN).count(), 3, "the origin fact and the two acts");
    assert!(!reply.contains("127.0.0.1"));
    assert!(!reply.contains("8642"));
    assert!(!reply.contains("<origin>"));
    assert!(!reply.contains('{') && !reply.contains('}'), "every slot filled");
}

/// T11: THE TWO ACTS, composed from the binary's own format strings with
/// the public origin: `skep verify --board <public> --principal 1
/// --payload`, the read's limit in the reply's own words; `skep claim
/// --board <public> --dir`, AUTH-5.87's sentence — each the binary's line
/// whole.
#[test]
fn the_two_acts_are_the_binarys_with_the_public_origin() {
    let reply = text(ORIGIN, false, STATUS);
    assert!(reply.contains("skep verify --board https://alice.skep.host --principal 1 --payload"));
    assert!(reply.contains("skep claim --board https://alice.skep.host --dir"));
    assert!(reply.contains("creating your account also creates a space for your agents beneath it, and its home"));
    assert!(reply.contains("it cannot tell you the board will open a session for you"));
    assert!(reply.contains(FIRST_ACT_AS_THE_BINARY_WRITES_IT));
    assert!(reply.contains(SECOND_ACT_AS_THE_BINARY_WRITES_IT));
}

/// The order: the heading, the operator sentence, the anchorless sentence
/// where it stands, the public-venue statement, the three facts as the
/// command spells them, the two acts, and the status address LAST.
#[test]
fn the_reply_in_its_order_with_the_status_address_last() {
    let reply = text(ORIGIN, true, STATUS);
    let blocks: Vec<&str> = reply.trim_end().split("\n\n").collect();
    assert_eq!(
        blocks,
        vec![
            "Your board is live.",
            OPERATOR.text,
            ANCHORLESS.text,
            PUBLIC_VENUE.text,
            "account 1.0.1\nprincipal 1\norigin https://alice.skep.host",
            FIRST_ACT_AS_THE_BINARY_WRITES_IT,
            SECOND_ACT_AS_THE_BINARY_WRITES_IT,
            "This reply stays at https://skep.host/status/0123456789abcdef0123456789abcdef",
        ]
    );
    assert!(reply.ends_with(&format!("{STATUS}\n")));
    assert_eq!(text(ORIGIN, false, STATUS).trim_end().split("\n\n").count(), 7, "no anchorless block");
}

/// T11: THE MAIL's TEXT IS THE PAGE's TEXT AND THE HEADERS: the body the
/// one function renders, after the headers and their blank line.
#[test]
fn the_mails_text_is_the_pages_with_the_headers() {
    let page = text(ORIGIN, true, STATUS);
    let message = Message {
        name: Name::parse(b"alice").expect("a name"),
        to: "person@example.com".into(),
        from: "noreply@skep.host".into(),
        reply_to: "owner@skep.host".into(),
        subject: fill(crate::pages::MAIL_SUBJECT, &[]),
        body: page.clone(),
    };
    let headers = "To: person@example.com\nFrom: noreply@skep.host\nReply-To: owner@skep.host\nSubject: Your board is live\nMIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: 8bit\n";
    assert_eq!(message.text(), format!("{headers}\n{page}"));
}
