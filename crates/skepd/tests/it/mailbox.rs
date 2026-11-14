//! The mailbox's mint over the wire (the mailbox design §3).
//!
//! `create_well_known_document {account}` mints the account's mailbox, the
//! private document at its well-known slot, once. Over a real board the
//! suite holds what a board shows of it: the mint's feed row, shown to its
//! owner's class and omitted for a guest and a stranger; what `doc_metadata`
//! answers a stranger at the address, minted and unminted; the system
//! account's refusal on an unclaimed board and a claimed one; a mail link
//! made before the mint, found before and after it by a search that reads no
//! mailbox; two sessions calling at once, answered one address over one
//! commit; a later call answered at the position it was judged at,
//! committing nothing; and the refusals an owner with no home page, an
//! address of no account and an unclaimed board each meet.
//!
//! The suite spells no document number: an address a board hands out is
//! [`nth_document`]'s, and a mailbox's is the namespace's own answer
//! ([`mailbox_of`]).

use crate::common;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;

use common::*;
use serde_json::{json, Value};

/// The refusal a frame naming the system account meets, `code:detail`.
const NO_WELL_KNOWN: &str = "credential_refused:system_account_no_well_known";

/// Returns the address of `account`'s mailbox, minted or not.
///
/// It is the namespace's answer for the account's well-known slot
/// (`skep_namespace::mailbox_address`).
fn mailbox_of(account: &str) -> String {
    let account = skep_resolve::parse_address(account).expect("an account's address");
    skep_namespace::mailbox_address(&account).expect("an account has a mailbox slot").to_string()
}

/// Returns the op's frame naming `account`.
fn mint_frame(account: &str) -> String {
    format!(r#"{{"op":"create_well_known_document","account":"{account}"}}"#)
}

/// Returns the mail type's address, read off the registry's table by name.
fn mail_type() -> String {
    let row = skep_registry::vocabulary().iter().find(|row| row.name == "mail");
    row.expect("the vocabulary names the mail type").address.to_string()
}

/// Returns the feed's page since `since`, as `token` reads it.
fn changes_page(port: u16, token: Option<&str>, since: u64) -> Value {
    let (st, body) = http(port, "GET", &format!("/changes?since={since}"), token, b"");
    assert_eq!(st, 200, "changes: {}", String::from_utf8_lossy(&body));
    json(&body)
}

/// Asserts that `doc` names no document to `token`'s reader.
fn assert_unregistered(port: u16, token: Option<&str>, doc: &str, who: &str) {
    let v = doc_metadata(port, token, doc);
    assert_eq!(expect_resp(&v, "rejected")["code"].as_str(), Some("doc_not_registered"), "{who}: {v}");
}

/// Checks that the mint's feed row is its owner's class's alone.
///
/// The mint commits one row: `op` the wire name, `docs` the mailbox, a bare
/// session's write, never signed. Each session of the owner's reads it
/// whole. A guest and a stranger are served no entry for it — omitted, never
/// present with nulled fields — and the `last` of their page is the `since`
/// they asked from, so a masked mint moves no reader's paging (wire.md §The
/// change feed). A second call adds no row.
#[test]
fn the_mints_feed_row_is_shown_to_its_owners_class_and_omitted_for_a_guest_and_a_stranger() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let stranger = seat_stranger(port, 911);
    let mailbox = mailbox_of(CLAIMANT_ACCOUNT);
    let before = head_position(port);
    let ack = op(port, Some(&owner), &mint_frame(CLAIMANT_ACCOUNT));
    assert_eq!(acked_addr(&ack), mailbox, "the account's mailbox: {ack}");
    let at = acked_at(&ack);
    assert_eq!(at, head_position(port), "the ack's position is the head");
    // The owner's class: the row, whole, under each of its sessions.
    for (who, token) in [("the session that minted", &owner), ("a signed session of the owner's", &signed)] {
        let page = changes_page(port, Some(token), before);
        let rows = page["changes"].as_array().expect("changes");
        assert_eq!(rows.len(), 1, "{who}: one write, one row: {page}");
        let row = &rows[0];
        assert_eq!((row["at"].as_u64(), row["op"].as_str()), (Some(at), Some("create_well_known_document")), "{who}: {row}");
        assert_eq!(row["docs"], json!([mailbox]), "{who}: the document the mint made: {row}");
        assert_eq!(row["key"].as_str(), Some("bare"), "{who}: a bare session's write: {row}");
        assert!(row.get("attest").is_none(), "{who}: the mint is never signed: {row}");
        assert_eq!(page["last"].as_u64(), Some(at), "{who}: {page}");
    }
    // A guest and a stranger: no entry, and a page that ends where it began.
    for (who, token) in [("a guest", None), ("a stranger", Some(stranger.session.as_str()))] {
        let page = changes_page(port, token, before);
        assert_eq!(page["changes"], json!([]), "{who}: the row is omitted: {page}");
        assert_eq!((page["last"].as_u64(), page["more"].as_bool()), (Some(before), Some(false)), "{who}: `since` echoed: {page}");
    }
    // A second call commits nothing: the owner's page holds the one row.
    assert_eq!(acked_addr(&op(port, Some(&signed), &mint_frame(CLAIMANT_ACCOUNT))), mailbox, "the same address");
    let rows = changes_page(port, Some(&owner), before)["changes"].as_array().expect("changes").len();
    assert_eq!(rows, 1, "one row, whatever is called after it");
    sd.shutdown();
}

/// Checks that a stranger can tell a minted mailbox from an unminted one.
///
/// Before the mint the mailbox's address names no document, to every reader
/// and its owner among them: `doc_metadata` answers `doc_not_registered`.
/// Once minted it is a registered private document: a stranger and a guest
/// are answered `withheld` naming it, and its owner reads it — private, its
/// own account's, minted at the ack. So a mint is a fact anyone can detect,
/// once (the mailbox design §3), and the mailbox of an account that has
/// minted none names no document still.
#[test]
fn a_stranger_is_answered_withheld_on_a_minted_mailbox_and_doc_not_registered_on_an_unminted_one() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let stranger = seat_stranger(port, 912);
    let mailbox = mailbox_of(CLAIMANT_ACCOUNT);
    for (who, token) in [("its owner", Some(owner.as_str())), ("a stranger", Some(stranger.session.as_str())), ("a guest", None)] {
        assert_unregistered(port, token, &mailbox, who);
    }
    let ack = op(port, Some(&owner), &mint_frame(CLAIMANT_ACCOUNT));
    assert_eq!(acked_addr(&ack), mailbox, "{ack}");
    assert_withheld(&doc_metadata(port, Some(&stranger.session), &mailbox), &mailbox);
    assert_withheld(&doc_metadata(port, None, &mailbox), &mailbox);
    let meta = doc_metadata(port, Some(&owner), &mailbox);
    let m = expect_resp(&meta, "doc_metadata");
    assert_eq!((m["doc"].as_str(), m["owner"].as_str()), (Some(mailbox.as_str()), Some(CLAIMANT_ACCOUNT)), "its own account's: {meta}");
    assert_eq!((m["published"].as_bool(), m["at"].as_u64()), (Some(false), Some(acked_at(&ack))), "private, minted at the ack: {meta}");
    // The stranger's own mailbox is unminted, to the stranger and the owner.
    let theirs = mailbox_of(&stranger.account);
    assert_unregistered(port, Some(&stranger.session), &theirs, "the stranger, of its own mailbox");
    assert_unregistered(port, Some(&owner), &theirs, "the owner, of the stranger's mailbox");
    sd.shutdown();
}

/// Checks that a frame naming the system account is refused by its token.
///
/// The system account's documents stand from the board's birth, and the
/// document at its well-known slot is the head document, no mailbox (the
/// mailbox design §2). An ordinary session naming that account is refused
/// `credential_refused:system_account_no_well_known`, permanent, and nothing
/// commits: on a board no one has claimed, where the refusal stands ahead of
/// the claim's gate, and on the same board once claimed, from a bare session
/// and from a signed one. Every session here is the claimant's.
#[test]
fn a_frame_naming_the_system_account_is_refused_on_an_unclaimed_board_and_a_claimed_one() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn_unclaimed(dir.path());
    let port = sd.port();
    let system = skep_namespace::system_account().to_string();
    let head_document = skep_namespace::head_document().to_string();
    assert_eq!(mailbox_of(&system), head_document, "the premise: the system account's slot holds the head document");
    let refused = |who: &str, token: &str| {
        let before = head_position(port);
        let v = op(port, Some(token), &mint_frame(&system));
        assert_eq!(verdict(&v), NO_WELL_KNOWN, "{who}: {v}");
        assert_eq!((v["disposition"].as_str(), v["op"].as_str()), (Some("permanent"), Some("create_well_known_document")), "{who}: {v}");
        assert_eq!(head_position(port), before, "{who}: nothing committed");
    };
    // Unclaimed: the ceremony's first four steps seat the claimant and mint
    // its home page.
    ceremony_before_the_claim(port);
    assert!(!claimed(port), "the premise: no one has claimed the board");
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    refused("a bare session, unclaimed", &open_session(port, CLAIMANT_PRINCIPAL));
    refused("a signed session, unclaimed", &signed);
    // Claimed.
    expect_resp(&op(port, Some(&signed), &claim_frame(CLAIMANT_DOC1, CLAIMANT_ACCOUNT)), "ack_addr");
    assert!(claimed(port), "the premise: the board is claimed");
    refused("a bare session, claimed", &open_session(port, CLAIMANT_PRINCIPAL));
    refused("a signed session, claimed", &signed);
    let meta = doc_metadata(port, None, &head_document);
    let m = expect_resp(&meta, "doc_metadata");
    assert_eq!((m["owner"].as_str(), m["published"].as_bool()), (Some(system.as_str()), Some(true)), "the slot's document is the head document, as it stood: {meta}");
    sd.shutdown();
}

/// Checks that mail needs no mailbox document.
///
/// A mail link whose `to` is a reader's mailbox address is made while
/// nothing is minted there, and the search by that address and the mail type
/// finds it: as the reader, to whom the mailbox itself answers
/// `doc_not_registered`, as the writer and as a guest. The reader then mints
/// the mailbox, and the same search answers each of them the same link — the
/// writer and the guest among them, who are withheld the mailbox itself: the
/// search consults no document at the address it searches by. The link is
/// kept in the letter, so the mailbox holds none (the mailbox design §3).
#[test]
fn a_mail_link_made_before_the_mint_is_found_before_and_after_it_by_a_search_that_reads_no_mailbox() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let writer = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let reader = seat_stranger(port, 913);
    let mailbox = mailbox_of(&reader.account);
    let mail = mail_type();
    // A public letter of the writer's, and its one mail link, kept in it.
    let letter = edition_with(port, &writer, "hello");
    let link = acked_addr(&typed_link(port, &writer, &letter, &[letter.as_str()], &[mailbox.as_str()], &mail));
    let search = ftt_frame("find_links_ftt", r#""any""#, r#""any""#, &unit_span(&mailbox), &unit_span(&mail));
    let readers = [("the reader", Some(reader.session.as_str())), ("the writer", Some(writer.as_str())), ("a guest", None)];
    let found = |when: &str| {
        for (who, token) in readers {
            assert_eq!(addrs_of(&op(port, token, &search)), [link.as_str()], "{when}: {who} finds the letter's link");
        }
    };
    assert_unregistered(port, Some(&reader.session), &mailbox, "the premise: nothing is minted at the mailbox");
    found("before the mint");
    assert_eq!(acked_addr(&op(port, Some(&reader.session), &mint_frame(&reader.account))), mailbox, "the reader mints the mailbox");
    assert_withheld(&doc_metadata(port, Some(&writer), &mailbox), &mailbox);
    assert_withheld(&doc_metadata(port, None, &mailbox), &mailbox);
    found("after the mint");
    assert!(find_links_ftt_home(port, Some(&reader.session), &mailbox).is_empty(), "the link is the letter's: the mailbox holds none");
    sd.shutdown();
}

/// Checks that two sessions calling at once mint one mailbox.
///
/// Two sessions of the owner's send the op from one start line. Each is
/// acknowledged the one address, at or after the mint's position; the log
/// gains one commit — the owner's feed one row, the head standing at it —
/// and the mailbox's metadata names that commit.
#[test]
fn two_sessions_calling_at_once_are_answered_one_address_over_one_commit() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let sessions = [open_session(port, CLAIMANT_PRINCIPAL), open_session(port, CLAIMANT_PRINCIPAL)];
    let mailbox = mailbox_of(CLAIMANT_ACCOUNT);
    let frame = mint_frame(CLAIMANT_ACCOUNT);
    let before = head_position(port);
    // The start line: each caller spins at it until both stand there, so
    // the two requests leave together.
    let (ready, go) = (AtomicUsize::new(0), AtomicBool::new(false));
    let acks: Vec<Value> = thread::scope(|s| {
        let calls: Vec<_> = sessions
            .iter()
            .map(|session| {
                let (ready, go, frame) = (&ready, &go, &frame);
                s.spawn(move || {
                    ready.fetch_add(1, Ordering::SeqCst);
                    while !go.load(Ordering::SeqCst) {
                        std::hint::spin_loop();
                    }
                    op(port, Some(session), frame)
                })
            })
            .collect();
        while ready.load(Ordering::SeqCst) < sessions.len() {
            std::hint::spin_loop();
        }
        go.store(true, Ordering::SeqCst);
        calls.into_iter().map(|call| call.join().expect("a call's thread")).collect()
    });
    let page = changes_page(port, Some(&sessions[0]), before);
    let rows = page["changes"].as_array().expect("changes");
    assert_eq!(rows.len(), 1, "one commit, one row: {page}");
    let minted_at = rows[0]["at"].as_u64().expect("the row's position");
    assert_eq!((rows[0]["op"].as_str(), &rows[0]["docs"]), (Some("create_well_known_document"), &json!([mailbox])), "{page}");
    assert_eq!(head_position(port), minted_at, "the log gained the mint's commit and no other");
    for ack in &acks {
        assert_eq!(acked_addr(ack), mailbox, "each call is answered the one address: {ack}");
        assert!(acked_at(ack) >= minted_at, "at or after the mint's position: {ack}");
    }
    assert!(acks.iter().any(|ack| acked_at(ack) == minted_at), "one of the two is the mint's own acknowledgment: {acks:?}");
    assert_eq!(doc_metadata(port, Some(&sessions[1]), &mailbox)["at"].as_u64(), Some(minted_at), "the mailbox was minted at that commit");
    sd.shutdown();
}

/// Checks the position a later call is answered at.
///
/// The first call's `at` is the mint's commit. Once another write has moved
/// the head, a second call — another session's, carrying no `id` — is
/// answered the same `addr` with `at` the head it was judged at, not the
/// mint's, and commits nothing: the head stands, and the feed holds the two
/// rows it held. A re-send under the first request's `id`, on its session,
/// is answered the first acknowledgment whole (wire.md §Namespace;
/// §Correlation and idempotency). The mint moves no count: the account's
/// next document takes the number it would have taken.
#[test]
fn a_later_call_is_answered_the_same_address_at_the_position_it_was_judged_at() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let mailbox = mailbox_of(CLAIMANT_ACCOUNT);
    let before = head_position(port);
    let with_id = format!(r#"{{"op":"create_well_known_document","account":"{CLAIMANT_ACCOUNT}","id":"mailbox-1"}}"#);
    let first = op(port, Some(&owner), &with_id);
    let minted_at = acked_at(&first);
    assert_eq!(acked_addr(&first), mailbox, "{first}");
    assert_eq!(owner_draft(port, &owner), nth_document(CLAIMANT_ACCOUNT, 2), "the mint moved no count");
    let head = head_position(port);
    assert!(head > minted_at, "the premise: a later write moved the head past the mint");
    let second = op(port, Some(&open_session(port, CLAIMANT_PRINCIPAL)), &mint_frame(CLAIMANT_ACCOUNT));
    assert_eq!((acked_addr(&second), acked_at(&second)), (mailbox, head), "the same address, at the position the call was judged at: {second}");
    assert_eq!(op(port, Some(&owner), &with_id), first, "a re-send under the first request's `id` is the first acknowledgment whole");
    assert_eq!(head_position(port), head, "neither call committed anything");
    let page = changes_page(port, Some(&owner), before);
    let ops: Vec<&str> = page["changes"].as_array().expect("changes").iter().filter_map(|row| row["op"].as_str()).collect();
    assert_eq!(ops, ["create_well_known_document", "create_new_document"], "the mint's row and the draft's, and no row of a later call: {page}");
    sd.shutdown();
}

/// Checks the refusals an owner and a stranger meet on a claimed board.
///
/// The owner of an account that holds no document is refused
/// `credential_refused:mint_home_first`: the home page stays every account's
/// first document. The home page minted, the mailbox lands, and the
/// account's next document takes the number it would have taken. An address
/// that names no registered account is `not_an_account` to the one caller
/// who owns the space it names — a prefix never delegated under its account,
/// a document's address — and `not_owner` to anyone else, as another's
/// account is, its mailbox minted or not. No refusal commits.
#[test]
fn an_owner_with_no_home_page_is_refused_mint_home_first_and_an_address_of_no_account_not_an_account() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let (account, session) = bootstrap_delegate(port, 914);
    let mailbox = mailbox_of(&account);
    let before = head_position(port);
    let v = op(port, Some(&session), &mint_frame(&account));
    assert_eq!(verdict(&v), "credential_refused:mint_home_first", "{v}");
    assert_eq!(head_position(port), before, "refused ahead of any commit");
    assert_unregistered(port, Some(&session), &mailbox, "the owner, of the mailbox it was refused");
    assert_eq!(create_doc(port, &session, &account), nth_document(&account, 1), "the home page is the account's first document");
    assert_eq!(acked_addr(&op(port, Some(&session), &mint_frame(&account))), mailbox, "the home page minted, the mailbox lands");
    assert_eq!(create_doc(port, &session, &account), nth_document(&account, 2), "the mint moved no count");
    // The store's two refusals. The claimant owns the space under its own
    // account, where no prefix has been delegated, and its own home page.
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let undelegated = next_prefix_under(port, Some(&owner), CLAIMANT_ACCOUNT);
    let standing = head_position(port);
    let cells = [
        ("the owner of the space an undelegated prefix lies in", &owner, undelegated.as_str(), "not_an_account", "reorder"),
        ("an owner naming its own home page's address", &owner, CLAIMANT_DOC1, "not_an_account", "reorder"),
        ("a stranger naming that undelegated prefix", &session, undelegated.as_str(), "not_owner", "permanent"),
        ("a stranger naming an account whose mailbox is unminted", &session, CLAIMANT_ACCOUNT, "not_owner", "permanent"),
        ("a stranger naming an account whose mailbox is minted", &owner, account.as_str(), "not_owner", "permanent"),
    ];
    for (who, token, named, code, disposition) in cells {
        let v = op(port, Some(token), &mint_frame(named));
        let rej = expect_resp(&v, "rejected");
        assert_eq!((rej["code"].as_str(), rej["disposition"].as_str(), rej["op"].as_str()), (Some(code), Some(disposition), Some("create_well_known_document")), "{who}: {v}");
    }
    assert_eq!(head_position(port), standing, "no refusal commits");
    assert_unregistered(port, Some(&owner), &mailbox_of(CLAIMANT_ACCOUNT), "the claimant's mailbox, which no refused call minted");
    sd.shutdown();
}

/// Checks that an unclaimed board refuses the op `claim_first`.
///
/// The claimant's account holds its home page, so the mint's own refusals
/// pass and the claim's gate answers: an unclaimed board admits the claim
/// ceremony's writes alone, from a bare session and a signed one, and
/// answers a caller who does not own the account the same. Nothing commits.
/// Once the board is claimed the same call lands.
#[test]
fn an_unclaimed_board_refuses_the_op_claim_first_from_an_account_with_a_home_page() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn_unclaimed(dir.path());
    let port = sd.port();
    ceremony_before_the_claim(port);
    assert!(!claimed(port), "the premise: no one has claimed the board");
    let mailbox = mailbox_of(CLAIMANT_ACCOUNT);
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let before = head_position(port);
    let callers = [("the owner's bare session", open_session(port, CLAIMANT_PRINCIPAL)), ("the owner's signed session", signed.clone()), ("a session that does not own the account", open_session(port, 0))];
    for (who, token) in &callers {
        let v = op(port, Some(token), &mint_frame(CLAIMANT_ACCOUNT));
        assert_eq!(verdict(&v), "credential_refused:claim_first", "{who}: {v}");
    }
    assert_eq!(head_position(port), before, "no refusal commits");
    assert_unregistered(port, Some(&signed), &mailbox, "the owner, of the mailbox it was refused");
    expect_resp(&op(port, Some(&signed), &claim_frame(CLAIMANT_DOC1, CLAIMANT_ACCOUNT)), "ack_addr");
    assert!(claimed(port), "the premise: the board is claimed");
    assert_eq!(acked_addr(&op(port, Some(&open_session(port, CLAIMANT_PRINCIPAL)), &mint_frame(CLAIMANT_ACCOUNT))), mailbox, "claimed, the same call lands");
    sd.shutdown();
}
