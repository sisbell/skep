//! T11 — THE REPLY: the operator sentence and the public-venue statement
//! always; the anchorless sentence iff the record carried no anchor; the
//! `local_trust` clause never; the public origin everywhere and the dialed
//! one nowhere; the two acts the `skep` command's own lines, read back from
//! `skep-cli`'s `src/commands/claim.rs`, with the public origin, AUTH-5.87's
//! sentence and the read's limit in them; the three facts; the status
//! URL last; and the mail's text the page's text with the headers
//! before it.

use super::*;
use crate::name::Name;
use crate::sender::Message;
use crate::strings::{fill, ANCHORLESS, OPERATOR, PUBLIC_VENUE};

const ORIGIN: &str = "https://alice.skep.host";
const STATUS: &str = "https://skep.host/status/0123456789abcdef0123456789abcdef";

/// ONE ACT LINE AS `skep claim --hosted` WRITES IT, read back at test time
/// from `skep-cli`'s `src/commands/claim.rs` (the hosted arm's fifth and
/// sixth DATA lines): the string literal that begins `prefix`, its
/// `\`-continued lines joined as Rust joins them (the line break and the
/// next line's leading whitespace dropped), its `{}`s filled in the order
/// the hosted arm passes them — the origin, then the principal — and its
/// `<origin>` filled, with this suite's public origin and the principal 1.
/// An edit to either act there is a red test here until the strings table
/// follows it.
fn binary_act(prefix: &str) -> String {
    let source = std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../skep-cli/src/commands/claim.rs")).expect("skep-cli's claim command");
    let start = source.find(&format!("\"{prefix}")).unwrap_or_else(|| panic!("claim.rs writes no literal beginning {prefix:?}")) + 1;
    let literal = &source[start..start + source[start..].find('"').expect("the literal's end")];
    let joined: String = literal.split("\\\n").enumerate().map(|(i, piece)| if i == 0 { piece } else { piece.trim_start() }).collect();
    joined.replacen("{}", ORIGIN, 1).replacen("{}", "1", 1).replace("<origin>", ORIGIN)
}

/// T11: THE OPERATOR SENTENCE AND THE PUBLIC-VENUE STATEMENT ALWAYS — the
/// latter verbatim — and THE ANCHORLESS SENTENCE IFF `anchorless`.
#[test]
fn each_ruled_string_shows_by_its_condition() {
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
fn the_local_trust_clause_never_shows() {
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
fn the_public_origin_shows_everywhere_and_the_dialed_one_nowhere() {
    let reply = text(ORIGIN, true, STATUS);
    assert_eq!(reply.matches(ORIGIN).count(), 3, "the origin fact and the two acts");
    assert!(!reply.contains("127.0.0.1"));
    assert!(!reply.contains("8642"));
    assert!(!reply.contains("<origin>"));
    assert!(!reply.contains('{') && !reply.contains('}'), "every slot filled");
}

/// T11: THE TWO ACTS, the binary's own lines with the public origin:
/// `skep verify --board <public> --principal 1 --payload`, the read's limit
/// in the reply's own words; `skep claim --board <public> --dir`,
/// AUTH-5.87's sentence — each the line `skep claim --hosted` writes, read
/// back from its source, whole.
#[test]
fn the_two_acts_are_the_binarys_with_the_public_origin() {
    let reply = text(ORIGIN, false, STATUS);
    assert!(reply.contains("skep verify --board https://alice.skep.host --principal 1 --payload"));
    assert!(reply.contains("skep claim --board https://alice.skep.host --dir"));
    assert!(reply.contains("creating your account also creates a space for your agents beneath it, and its home"));
    assert!(reply.contains("it cannot tell you the board will open a session for you"));
    let (first, second) = (binary_act("first act: "), binary_act("second act: "));
    assert!(reply.contains(&first), "the reply's first act is not the binary's: {first}");
    assert!(reply.contains(&second), "the reply's second act is not the binary's: {second}");
}

/// The order: the heading, the operator sentence, the anchorless sentence
/// where it stands, the public-venue statement, the three facts as the
/// command spells them, the two acts, and the status URL LAST.
#[test]
fn the_reply_keeps_its_order_with_the_status_url_last() {
    let reply = text(ORIGIN, true, STATUS);
    let (first, second) = (binary_act("first act: "), binary_act("second act: "));
    let blocks: Vec<&str> = reply.trim_end().split("\n\n").collect();
    assert_eq!(
        blocks,
        vec![
            "Your board is live.",
            OPERATOR.text,
            ANCHORLESS.text,
            PUBLIC_VENUE.text,
            "account 1.0.1\nprincipal 1\norigin https://alice.skep.host",
            first.as_str(),
            second.as_str(),
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
        subject: fill(crate::strings::MAIL_SUBJECT, &[]),
        body: page.clone(),
    };
    let headers = "To: person@example.com\nFrom: noreply@skep.host\nReply-To: owner@skep.host\nSubject: Your board is live\nMIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: 8bit\n";
    assert_eq!(message.text(), format!("{headers}\n{page}"));
}
