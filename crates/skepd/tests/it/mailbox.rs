//! The mailbox over the wire (the mailbox design §3).
//!
//! The board creates every account's mailbox, the private document at its
//! well-known slot 2, in the commit that mints the account's home page; and
//! `create_well_known_document {account, slot: 2}` answers it standing, once
//! the home stands (the other three slots, and what holds of every slot,
//! are `well_known.rs`'s). Over a real board the suite holds what a board
//! shows of it: the claimant's mailbox, dated at its home by the claim; the
//! home's feed row, naming the mailbox to its owner's class and reduced to
//! the home for a guest and a stranger, the mailbox's one row; that every
//! account with a home answers a stranger `withheld` at its mailbox, and one
//! with none `doc_not_registered`; the system account's refusal on an
//! unclaimed board and a claimed one; a mail link made before the mailbox,
//! found before and after it by a search that reads no mailbox; two first
//! mints racing, answered one mailbox beside the first; a call at slot 2
//! answered at the position it was judged at, committing nothing and saying
//! so; and the refusals an owner with no home page, an address of no
//! account and an unclaimed board each meet.
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

/// Returns the op's frame naming `account` and the mailbox's slot.
fn mint_frame(account: &str) -> String {
    format!(r#"{{"op":"create_well_known_document","account":"{account}","slot":{}}}"#, skep_namespace::MAILBOX_SLOT)
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

/// Checks that the claim leaves the claimant's mailbox standing, dated at
/// its home.
///
/// The claim ceremony mints the claimant's home page, and the board creates
/// the account's mailbox in that same commit (the mailbox design §3): to its
/// owner the mailbox answers `doc_metadata` private, its own account's,
/// dated at the home's own position; a guest and a stranger are answered
/// `withheld` naming it. A call at slot 2 then is answered the mailbox
/// standing — `"committed": false`, at the head it was judged at — the head
/// does not move and the feed gains no row.
#[test]
fn a_claim_leaves_the_claimants_mailbox_dated_at_its_home() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let stranger = seat_stranger(port, 910);
    let mailbox = mailbox_of(CLAIMANT_ACCOUNT);
    let home = doc_metadata(port, Some(&owner), CLAIMANT_DOC1);
    let home_at = expect_resp(&home, "doc_metadata")["at"].as_u64().expect("the home's position");
    let meta = doc_metadata(port, Some(&owner), &mailbox);
    let m = expect_resp(&meta, "doc_metadata");
    assert_eq!((m["doc"].as_str(), m["owner"].as_str()), (Some(mailbox.as_str()), Some(CLAIMANT_ACCOUNT)), "its own account's: {meta}");
    assert_eq!((m["published"].as_bool(), m["at"].as_u64()), (Some(false), Some(home_at)), "private, dated at its home: {meta}");
    assert_withheld(&doc_metadata(port, None, &mailbox), &mailbox);
    assert_withheld(&doc_metadata(port, Some(&stranger.session), &mailbox), &mailbox);
    let head = head_position(port);
    let ack = op(port, Some(&owner), &mint_frame(CLAIMANT_ACCOUNT));
    assert_eq!((acked_addr(&ack), acked_at(&ack)), (mailbox, head), "the mailbox standing, at the head the call was judged at: {ack}");
    assert_eq!(ack["committed"], json!(false), "and it says it committed nothing: {ack}");
    assert_eq!(head_position(port), head, "the head does not move");
    assert_eq!(changes_page(port, Some(&owner), head)["changes"], json!([]), "no row is added");
    sd.shutdown();
}

/// Checks that a mailbox's one row is its home's, and a call at slot 2 adds
/// none.
///
/// An account's first mint commits the home and its mailbox in one commit,
/// and its one feed row says so: `op` `create_new_document`, a bare
/// session's write, unsigned here, `docs` the home and then the mailbox, to
/// the owner's class. A guest and a stranger are served the same row
/// reduced to the home — the mailbox withheld, never present with nulled
/// fields (wire.md §The change feed). A call at slot 2 after it, from each
/// of two sessions of the owner's, is answered the mailbox standing and
/// adds no row.
#[test]
fn the_mailboxs_one_row_is_its_homes_and_a_call_at_slot_2_adds_none() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let (account, owner) = bootstrap_delegate(port, 911);
    let stranger = seat_stranger(port, 921);
    let before = head_position(port);
    let ack = op(port, Some(&owner), &create_frame(&account, None));
    let (home, at) = (acked_addr(&ack), acked_at(&ack));
    assert_eq!(home, nth_document(&account, 1), "the account's home page: {ack}");
    assert_eq!(at, head_position(port), "the ack's position is the head");
    let mailbox = mailbox_of(&account);
    let page = changes_page(port, Some(&owner), before);
    let rows = page["changes"].as_array().expect("changes");
    assert_eq!(rows.len(), 1, "one write, one row: {page}");
    let row = &rows[0];
    assert_eq!((row["at"].as_u64(), row["op"].as_str()), (Some(at), Some("create_new_document")), "{row}");
    assert_eq!(row["docs"], json!([home, mailbox]), "the home, then the mailbox its commit created: {row}");
    assert_eq!(row["key"].as_str(), Some("bare"), "a bare session's write: {row}");
    assert!(row.get("attest").is_none(), "unsigned: {row}");
    for (who, token) in [("a guest", None), ("a stranger", Some(stranger.session.as_str()))] {
        let page = changes_page(port, token, before);
        let rows = page["changes"].as_array().expect("changes");
        assert_eq!(rows.len(), 1, "{who}: the home's row is served: {page}");
        assert_eq!((rows[0]["at"].as_u64(), &rows[0]["docs"]), (Some(at), &json!([home])), "{who}: reduced to the home: {page}");
    }
    for token in [owner.clone(), open_session(port, 911)] {
        let v = op(port, Some(&token), &mint_frame(&account));
        assert_eq!((acked_addr(&v), &v["committed"]), (mailbox.clone(), &json!(false)), "the mailbox standing: {v}");
    }
    assert_eq!(head_position(port), at, "no call at slot 2 committed");
    let rows = changes_page(port, Some(&owner), before)["changes"].as_array().expect("changes").len();
    assert_eq!(rows, 1, "one row, whatever is called after it");
    sd.shutdown();
}

/// Checks that every account holding a home page holds its mailbox.
///
/// The board creates the mailbox with the home page, whoever mints it: the
/// claimant's at the claim, a seated stranger's from its own bare session,
/// and two accounts beneath the claimant's — its agent space, keyless, and
/// a later sub-account — each minting its home from its own session. Each
/// owner reads its own mailbox private, dated at its home; a guest and
/// every account outside the owner's subtree are answered `withheld` naming
/// it, and an account in it — the claimant above its sub-accounts, each
/// sub-account below the claimant — reads it, as it reads every draft
/// there (the read predicate's subtree clause, PUB-7.24). An account
/// holding no home page holds no mailbox: its `.0.2` answers
/// `doc_not_registered`, as its `.0.1` does, so the answer at `.0.2` tells
/// a stranger nothing its home's own absence does not.
#[test]
fn every_account_with_a_home_answers_a_stranger_withheld_at_its_mailbox() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let claimant = open_session(port, CLAIMANT_PRINCIPAL);
    let stranger = seat_stranger(port, 912);
    let sub = seat_sub_account(port, &claimant, 922);
    // `seat_sub_account` holds the claimant's agent space for this
    // principal, keyless, and seats the later child.
    let agent_space = format!("{CLAIMANT_ACCOUNT}.1");
    let agent = open_session(port, 100_922);
    assert_eq!(create_doc(port, &agent, &agent_space), nth_document(&agent_space, 1), "the agent space's home page");
    let homed = [
        (CLAIMANT_ACCOUNT.to_string(), claimant.clone()),
        (stranger.account.clone(), stranger.session.clone()),
        (sub.account.clone(), sub.session.clone()),
        (agent_space, agent),
    ];
    for (account, session) in &homed {
        let mailbox = mailbox_of(account);
        let home_at = expect_resp(&doc_metadata(port, Some(session), &nth_document(account, 1)), "doc_metadata")["at"].as_u64();
        let meta = doc_metadata(port, Some(session), &mailbox);
        let m = expect_resp(&meta, "doc_metadata");
        assert_eq!((m["published"].as_bool(), m["at"].as_u64()), (Some(false), home_at), "{account}: its owner reads it, dated at its home: {meta}");
        assert_withheld(&doc_metadata(port, None, &mailbox), &mailbox);
        for (other, reader) in homed.iter().filter(|(other, _)| other != account) {
            let in_the_subtree = other.starts_with(&format!("{account}.")) || account.starts_with(&format!("{other}."));
            let v = doc_metadata(port, Some(reader), &mailbox);
            if in_the_subtree {
                assert_eq!(expect_resp(&v, "doc_metadata")["doc"].as_str(), Some(mailbox.as_str()), "{other} reads {account}'s mailbox by the subtree clause: {v}");
            } else {
                assert_withheld(&v, &mailbox);
            }
        }
    }
    let (homeless, session) = bootstrap_delegate(port, 932);
    for (who, token) in [("the owner", Some(session.as_str())), ("a stranger", Some(stranger.session.as_str())), ("a guest", None)] {
        assert_unregistered(port, token, &mailbox_of(&homeless), who);
        assert_unregistered(port, token, &nth_document(&homeless, 1), who);
    }
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
/// A mail link whose `to` is a reader's mailbox address is made while the
/// reader holds no home page, so nothing is minted at the address, and the
/// search by that address and the mail type finds it: as the reader, to
/// whom the mailbox itself answers `doc_not_registered`, as the writer and
/// as a guest. The reader then mints its home page, the board creating the
/// mailbox beside it, and the same search answers each of them the same
/// link — the writer and the guest among them, who are withheld the mailbox
/// itself: the search consults no document at the address it searches by.
/// The link is kept in the letter, so the mailbox holds none (the mailbox
/// design §3).
#[test]
fn a_mail_link_made_before_the_home_is_found_before_and_after_it_by_a_search_that_reads_no_mailbox() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let writer = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let (reader_account, reader) = bootstrap_delegate(port, 913);
    let mailbox = mailbox_of(&reader_account);
    let mail = mail_type();
    // A public letter of the writer's, and its one mail link, kept in it.
    let letter = edition_with(port, &writer, "hello");
    let link = acked_addr(&typed_link(port, &writer, &letter, &[letter.as_str()], &[mailbox.as_str()], &mail));
    let search = ftt_frame("find_links_ftt", r#""any""#, r#""any""#, &unit_span(&mailbox), &unit_span(&mail));
    let readers = [("the reader", Some(reader.as_str())), ("the writer", Some(writer.as_str())), ("a guest", None)];
    let found = |when: &str| {
        for (who, token) in readers {
            assert_eq!(addrs_of(&op(port, token, &search)), [link.as_str()], "{when}: {who} finds the letter's link");
        }
    };
    assert_unregistered(port, Some(&reader), &mailbox, "the premise: nothing is minted at the mailbox");
    found("before the home");
    assert_eq!(create_doc(port, &reader, &reader_account), nth_document(&reader_account, 1), "the reader mints its home page");
    assert_withheld(&doc_metadata(port, Some(&writer), &mailbox), &mailbox);
    assert_withheld(&doc_metadata(port, None, &mailbox), &mailbox);
    found("after the home");
    assert!(find_links_ftt_home(port, Some(&reader), &mailbox).is_empty(), "the link is the letter's: the mailbox holds none");
    sd.shutdown();
}

/// Checks that two sessions minting at once create one mailbox, beside the
/// first document.
///
/// Two sessions of a fresh account's owner send `create_new_document` from
/// one start line. One is answered the account's doc 1, its home, and the
/// other its first ordinary document: exactly one mint is the account's
/// first, and its commit alone creates the mailbox. The log gains the two
/// commits — three records, the home's two and the later document's one,
/// the home's landing first — the owner's feed two rows, the home's naming
/// the home and the mailbox and the later one its document alone, and the
/// mailbox's metadata dates it at the home's commit.
#[test]
fn two_sessions_minting_at_once_create_one_mailbox_beside_the_first_document() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let (account, first) = bootstrap_delegate(port, 915);
    let sessions = [first, open_session(port, 915)];
    let frame = create_frame(&account, None);
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
    let (home, later) = (nth_document(&account, 1), nth_document(&account, 2));
    let at_of = |doc: &str| {
        let ack = acks.iter().find(|ack| acked_addr(ack) == doc).unwrap_or_else(|| panic!("one call minted {doc}: {acks:?}"));
        acked_at(ack)
    };
    let (home_at, later_at) = (at_of(&home), at_of(&later));
    assert_eq!((home_at, later_at), (before + 2, before + 3), "the home's two records first, then the later document's one: {acks:?}");
    assert_eq!(head_position(port), later_at, "the log gained the two commits and no other");
    let mailbox = mailbox_of(&account);
    let page = changes_page(port, Some(&sessions[0]), before);
    let rows: Vec<(Option<u64>, &Value)> = page["changes"].as_array().expect("changes").iter().map(|row| (row["at"].as_u64(), &row["docs"])).collect();
    assert_eq!(rows, [(Some(home_at), &json!([home, mailbox])), (Some(later_at), &json!([later]))], "{page}");
    assert_eq!(doc_metadata(port, Some(&sessions[1]), &mailbox)["at"].as_u64(), Some(home_at), "the mailbox was created at the home's commit");
    sd.shutdown();
}

/// Checks the position a call at slot 2 is answered at.
///
/// On the claimed board the claimant's mailbox stands from the claim, so a
/// first call is answered the mailbox standing — `at` the head it was
/// judged at, `"committed": false` — and commits nothing. Once another
/// write has moved the head, a second call — another session's, carrying
/// no `id` — is answered the same `addr` with `at` the new head, and
/// `"committed": false`. A re-send under the first request's `id`, on its
/// session, is answered the first acknowledgment whole (wire.md §Namespace;
/// §Correlation and idempotency). The mailbox moved no count: the account's
/// next document takes the number it would have taken, and the feed holds
/// the draft's row alone.
#[test]
fn a_call_at_slot_2_is_answered_the_mailbox_standing_at_the_position_it_was_judged_at() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let mailbox = mailbox_of(CLAIMANT_ACCOUNT);
    let before = head_position(port);
    let with_id = format!(r#"{{"op":"create_well_known_document","account":"{CLAIMANT_ACCOUNT}","id":"mailbox-1","slot":2}}"#);
    let first = op(port, Some(&owner), &with_id);
    assert_eq!((acked_addr(&first), acked_at(&first)), (mailbox.clone(), before), "the mailbox standing, at the head the call was judged at: {first}");
    assert_eq!(first["committed"], json!(false), "and it says it committed nothing: {first}");
    assert_eq!(owner_draft(port, &owner), nth_document(CLAIMANT_ACCOUNT, 2), "the mailbox moved no count");
    let head = head_position(port);
    assert!(head > before, "the premise: a later write moved the head");
    let second = op(port, Some(&open_session(port, CLAIMANT_PRINCIPAL)), &mint_frame(CLAIMANT_ACCOUNT));
    assert_eq!((acked_addr(&second), acked_at(&second)), (mailbox, head), "the same address, at the position the call was judged at: {second}");
    assert_eq!(second["committed"], json!(false), "and it says it committed nothing: {second}");
    assert_eq!(op(port, Some(&owner), &with_id), first, "a re-send under the first request's `id` is the first acknowledgment whole");
    assert_eq!(head_position(port), head, "no call at slot 2 committed anything");
    let page = changes_page(port, Some(&owner), before);
    let ops: Vec<&str> = page["changes"].as_array().expect("changes").iter().filter_map(|row| row["op"].as_str()).collect();
    assert_eq!(ops, ["create_new_document"], "the draft's row, and no row of a call at slot 2: {page}");
    sd.shutdown();
}

/// Checks the refusals an owner and a stranger meet on a claimed board.
///
/// The owner of an account that holds no document is refused
/// `credential_refused:mint_home_first`: the home page stays every account's
/// first document. The home page minted, the mailbox stands beside it — a
/// call at slot 2 answers it, committing nothing — and the account's next
/// document takes the number it would have taken. An address that names no
/// registered account is `not_an_account` to the one caller who owns the
/// space it names — a prefix never delegated under its account, a
/// document's address — and `not_owner` to anyone else, as another's
/// account is, its mailbox standing or not. No refusal commits.
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
    let standing = op(port, Some(&session), &mint_frame(&account));
    assert_eq!((acked_addr(&standing), &standing["committed"]), (mailbox.clone(), &json!(false)), "the home page minted, the mailbox stands beside it: {standing}");
    assert_eq!(create_doc(port, &session, &account), nth_document(&account, 2), "the mailbox moved no count");
    // The store's two refusals. The claimant owns the space under its own
    // account, where no prefix has been delegated, and its own home page.
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let (homeless, _) = bootstrap_delegate(port, 924);
    let undelegated = next_prefix_under(port, Some(&owner), CLAIMANT_ACCOUNT);
    let standing = head_position(port);
    let cells = [
        ("the owner of the space an undelegated prefix lies in", &owner, undelegated.as_str(), "not_an_account", "reorder"),
        ("an owner naming its own home page's address", &owner, CLAIMANT_DOC1, "not_an_account", "reorder"),
        ("a stranger naming that undelegated prefix", &session, undelegated.as_str(), "not_owner", "permanent"),
        ("a stranger naming an account with no home page and no mailbox", &session, homeless.as_str(), "not_owner", "permanent"),
        ("a stranger naming an account whose mailbox stands", &owner, account.as_str(), "not_owner", "permanent"),
    ];
    for (who, token, named, code, disposition) in cells {
        let v = op(port, Some(token), &mint_frame(named));
        let rej = expect_resp(&v, "rejected");
        assert_eq!((rej["code"].as_str(), rej["disposition"].as_str(), rej["op"].as_str()), (Some(code), Some(disposition), Some("create_well_known_document")), "{who}: {v}");
    }
    assert_eq!(head_position(port), standing, "no refusal commits");
    assert_unregistered(port, Some(&owner), &mailbox_of(&homeless), "the homeless account's mailbox, which no refused call minted");
    sd.shutdown();
}

/// Checks that an unclaimed board refuses the op `claim_first`.
///
/// The claimant's account holds its home page — and, from the home's own
/// commit, its mailbox — so the mint's own refusals pass and the claim's
/// gate answers: an unclaimed board admits the claim ceremony's writes
/// alone, from a bare session and a signed one, and answers a caller who
/// does not own the account the same. Nothing commits, and the mailbox
/// stands as the home's commit left it. Once the board is claimed the same
/// call is answered the mailbox standing, committing nothing.
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
    let home_at = expect_resp(&doc_metadata(port, Some(&signed), CLAIMANT_DOC1), "doc_metadata")["at"].as_u64();
    let meta = doc_metadata(port, Some(&signed), &mailbox);
    assert_eq!(
        (expect_resp(&meta, "doc_metadata")["published"].as_bool(), meta["at"].as_u64()),
        (Some(false), home_at),
        "the mailbox stands as the home's commit left it: {meta}"
    );
    expect_resp(&op(port, Some(&signed), &claim_frame(CLAIMANT_DOC1, CLAIMANT_ACCOUNT)), "ack_addr");
    assert!(claimed(port), "the premise: the board is claimed");
    let claimed_head = head_position(port);
    let v = op(port, Some(&open_session(port, CLAIMANT_PRINCIPAL)), &mint_frame(CLAIMANT_ACCOUNT));
    assert_eq!((acked_addr(&v), &v["committed"]), (mailbox, &json!(false)), "claimed, the same call is answered the mailbox standing: {v}");
    assert_eq!(head_position(port), claimed_head, "and commits nothing");
    sd.shutdown();
}
