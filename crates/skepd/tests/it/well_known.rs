//! The well-known creation over the wire, at every slot (wire.md §Namespace).
//!
//! `create_well_known_document {account, slot}` creates one of an account's
//! four well-known documents at its slot, in the slot's own state and
//! holding nothing: the mailbox at 2, private, and the bio at 3, the link
//! page at 4 and the account's policy document at 5, each published. Over a
//! real board the suite holds what a board shows of the three published
//! slots and of the four together: a signed creation lands published and
//! empty, a guest reads it and its feed row while the mailbox stays
//! withheld; a slot is created once and one slot never answers for
//! another; the mailbox, standing from the account's home commit, answers a
//! bare session's call at slot 2, and a signature a signed session attaches
//! to that call is dropped; a request with no slot, or
//! with a number no slot has, is refused before any write; a published
//! slot's creation is publish-class on a claimed board, refused bare,
//! unsigned and badly signed in the published mint's own order; its
//! signature names the slot's own address under the op's own token; the
//! system account is refused at every slot; the first words of a slot's
//! document are an ordinary `stage` and `publish`; every other refusal
//! keeps its token at every slot; and no creation moves a count. The
//! mailbox's own cells are `mailbox.rs`'s.
//!
//! The suite spells no document number but a slot's: an address a board
//! hands out is [`nth_document`]'s, and a slot's is the namespace's own
//! answer ([`slot_of`]).

use crate::common;

use common::*;
use serde_json::{json, Value};
use skep_identity::{entry_body_empty, entry_frame, ContentFreeOp, DocTerm, SigAlgRow};
use skep_kernel::Seq;
use skep_namespace::WellKnownSlot;

/// The three slots whose document is created published, by number.
const PUBLISHED_SLOTS: [u32; 3] =
    [skep_namespace::BIO_SLOT, skep_namespace::LINK_PAGE_SLOT, skep_namespace::POLICY_SLOT];

/// The policy document's slot, the one the registry's door reads.
const POLICY: u32 = skep_namespace::POLICY_SLOT;

/// The refusals of the write-path check and the gates before it, `code:detail`.
const SIGNED_SESSION_REQUIRED: &str = "credential_refused:signed_session_required";
const ATTESTATION_REQUIRED: &str = "credential_refused:attestation_required";
const BAD_SIGNATURE: &str = "credential_refused:attestation_invalid:signature";
const NO_WELL_KNOWN: &str = "credential_refused:system_account_no_well_known";
const MINT_HOME_FIRST: &str = "credential_refused:mint_home_first";

/// Returns the address of `account`'s document at slot `number`.
///
/// It is the namespace's own answer for the slot
/// (`skep_namespace::well_known_address`), created or not.
fn slot_of(account: &str, number: u32) -> String {
    let account = skep_resolve::parse_address(account).expect("an account's address");
    let slot = WellKnownSlot::named(number).expect("a well-known slot's number");
    skep_namespace::well_known_address(&account, slot).expect("an account has the slot").to_string()
}

/// Returns the op's frame naming `account` and `slot`.
fn creation_frame(account: &str, slot: u32) -> String {
    format!(r#"{{"op":"create_well_known_document","account":"{account}","slot":{slot}}}"#)
}

/// Returns the feed's rows since `since`, as `token` reads them.
fn changes_since(port: u16, token: Option<&str>, since: u64) -> Vec<Value> {
    let (st, body) = http(port, "GET", &format!("/changes?since={since}"), token, b"");
    assert_eq!(st, 200, "changes: {}", String::from_utf8_lossy(&body));
    json(&body)["changes"].as_array().expect("changes").clone()
}

/// Returns a draft's recorded base, the count the copy took and its source.
fn base_of(port: u16, token: &str, doc: &str) -> (Option<String>, Option<String>, Option<String>) {
    let v = doc_metadata(port, Some(token), doc);
    let meta = expect_resp(&v, "doc_metadata");
    let s = |member: &str| meta[member].as_str().map(str::to_string);
    (s("base"), s("base_copied"), s("source"))
}

/// Asserts that `doc` names no document to `token`'s reader.
fn assert_unregistered(port: u16, token: Option<&str>, doc: &str, who: &str) {
    let v = doc_metadata(port, token, doc);
    assert_eq!(expect_resp(&v, "rejected")["code"].as_str(), Some("doc_not_registered"), "{who}: {v}");
}

/// A keyed account beside the claimant's, with its home minted.
///
/// The account is top-level under node 1, keyed by its genesis in the
/// claimant's doc 1 (a hire), and no door's: an ordinary account. The
/// answer is the account, a signed session under its own key and a bare one.
fn an_ordinary_keyed_account(port: u16, registrar: &str, id: u64) -> (String, String, String) {
    let key = distinct_key(u8::try_from(id).expect("a small id"));
    let (account, _) = bootstrap_delegate(port, id);
    let signed = hire(port, registrar, CLAIMANT_DOC1, &account, id, &key);
    let home = acked_addr(&op(port, Some(&signed), &create_frame(&account, Some(true))));
    assert_eq!(home, nth_document(&account, 1), "the account's home");
    (account, signed, open_session(port, id))
}

/// Checks that a signed creation at each published slot lands published and
/// empty, read by a guest, its feed row public where the mailbox's is masked.
///
/// On a claimed board the claimant's signed session creates the bio, the
/// link page and the policy document, each answered `ack_addr` with the
/// slot's own address and committed under the session's signature: the
/// commit marker carries the attestation, and the feed row its `attest` and
/// no testimony. Each document is published and holds nothing — a guest and
/// a stranger read its metadata, published and the account's own, no birth
/// version, and its empty content — where the mailbox beside them, standing
/// from the claim's home commit and answered so to a call at slot 2, is
/// withheld from both. A guest's feed page and the owner's each carry the
/// three creations' rows and no other: the call at slot 2 committed
/// nothing. And none of the four calls moves a count: the account's next
/// document takes the number it would have taken.
#[test]
fn a_signed_creation_at_each_published_slot_lands_published_and_empty_and_a_guest_reads_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let stranger = seat_stranger(port, 921);
    // The count before: the account's next document is the one after this.
    let counted = owner_draft(port, &owner);
    let before = head_position(port);

    let mailbox = slot_of(CLAIMANT_ACCOUNT, skep_namespace::MAILBOX_SLOT);
    let standing = op(port, Some(&owner), &creation_frame(CLAIMANT_ACCOUNT, skep_namespace::MAILBOX_SLOT));
    assert_eq!((acked_addr(&standing), &standing["committed"]), (mailbox.clone(), &json!(false)), "the mailbox stands from the claim: {standing}");
    let mut created = Vec::new();
    for slot in PUBLISHED_SLOTS {
        let document = slot_of(CLAIMANT_ACCOUNT, slot);
        assert_eq!(document, format!("{CLAIMANT_ACCOUNT}.0.{slot}"), "the slot's own address");
        for (who, token) in [("its owner", Some(owner.as_str())), ("a guest", None)] {
            assert_unregistered(port, token, &document, who);
        }
        let ack = op(port, Some(&signed), &creation_frame(CLAIMANT_ACCOUNT, slot));
        assert_eq!(acked_addr(&ack), document, "slot {slot}: {ack}");
        assert!(ack.get("committed").is_none(), "slot {slot}: the creation committed: {ack}");
        let at = acked_at(&ack);
        assert_eq!(at, head_position(port), "slot {slot}: the ack's position is the head");
        assert!(
            sd.daemon().attestation_at(Seq(at)).expect("the journal").is_some(),
            "slot {slot}: the marker carries the owner's signature"
        );
        // Published and empty, to every reader.
        for (who, token) in [("a guest", None), ("a stranger", Some(stranger.session.as_str())), ("its owner", Some(owner.as_str()))] {
            let meta = doc_metadata(port, token, &document);
            let m = expect_resp(&meta, "doc_metadata");
            assert_eq!((m["doc"].as_str(), m["owner"].as_str()), (Some(document.as_str()), Some(CLAIMANT_ACCOUNT)), "slot {slot}, {who}: {meta}");
            assert_eq!((m["published"].as_bool(), m["at"].as_u64()), (Some(true), Some(at)), "slot {slot}, {who}: published, created at the ack: {meta}");
            assert!(m["birth"].is_null(), "slot {slot}, {who}: it holds no version: {meta}");
            assert_eq!(content_extent(port, token, &document), 0, "slot {slot}, {who}: it holds no content");
        }
        created.push((slot, document, at));
    }
    // The mailbox beside them is private.
    assert_withheld(&doc_metadata(port, None, &mailbox), &mailbox);
    assert_withheld(&doc_metadata(port, Some(&stranger.session), &mailbox), &mailbox);

    // The feed: a guest and a stranger are served the three creations' rows
    // and no entry for the mailbox's; the owner is served all four.
    for (who, token) in [("a guest", None), ("a stranger", Some(stranger.session.as_str()))] {
        let rows = changes_since(port, token, before);
        let served: Vec<(u64, &str, &Value)> =
            rows.iter().map(|row| (row["at"].as_u64().expect("at"), row["op"].as_str().expect("op"), &row["docs"])).collect();
        let expected: Vec<(u64, &str, Value)> =
            created.iter().map(|(_, document, at)| (*at, "create_well_known_document", json!([document]))).collect();
        assert_eq!(served.len(), expected.len(), "{who}: the three creations' rows, the mailbox's omitted: {rows:?}");
        for ((at, op, docs), (want_at, want_op, want_docs)) in served.iter().zip(&expected) {
            assert_eq!((at, op, *docs), (want_at, want_op, want_docs), "{who}: {rows:?}");
        }
        for row in &rows {
            assert!(row["attest"].is_object() && row.get("key").is_none(), "{who}: the creation reads signed, no testimony beside it: {row}");
        }
    }
    let owners = changes_since(port, Some(&owner), before);
    let named: Vec<(&str, &Value)> = owners.iter().map(|row| (row["op"].as_str().expect("op"), &row["docs"])).collect();
    let expected: Vec<(&str, Value)> =
        created.iter().map(|(_, document, _)| ("create_well_known_document", json!([document]))).collect();
    assert_eq!(named.len(), expected.len(), "the owner's page: the three creations' rows and no other: {owners:?}");
    for ((op, docs), (want_op, want_docs)) in named.iter().zip(&expected) {
        assert_eq!((op, *docs), (want_op, want_docs), "{owners:?}");
    }

    // No count moved: the next document is the one after the draft counted.
    let next = owner_draft(port, &owner);
    let number = |doc: &str| doc.rsplit('.').next().and_then(|n| n.parse::<u64>().ok()).expect("a document number");
    assert_eq!(number(&next), number(&counted) + 1, "the four calls moved no count: {counted} then {next}");
    sd.shutdown();
}

/// Checks that a slot is created once, per slot.
///
/// The bio's creation, carrying an `id`, commits. Once another write has
/// moved the head, a second call at the bio's slot is answered the same
/// address with `"committed": false`, at the head it was judged at: it
/// commits nothing, the head stands and no feed row is added. The policy
/// document's creation after it commits a document of its own at its own
/// address — a document at one slot never answers for another — and a
/// re-send of the first request under its `id`, on its session, is answered
/// the first acknowledgment whole.
#[test]
fn a_slot_is_created_once_and_a_resend_under_the_first_id_answers_from_the_memo() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let (bio, policy) = (slot_of(CLAIMANT_ACCOUNT, skep_namespace::BIO_SLOT), slot_of(CLAIMANT_ACCOUNT, POLICY));
    let before = head_position(port);
    let with_id = format!(r#"{{"op":"create_well_known_document","account":"{CLAIMANT_ACCOUNT}","id":"bio-1","slot":{}}}"#, skep_namespace::BIO_SLOT);
    let first = op(port, Some(&signed), &with_id);
    let created_at = acked_at(&first);
    assert_eq!(acked_addr(&first), bio, "{first}");
    assert!(first.get("committed").is_none(), "the creation committed: its ack carries no member: {first}");
    owner_draft(port, &owner);
    let head = head_position(port);
    assert!(head > created_at, "the premise: a later write moved the head past the creation");

    // A second call at the slot: the same address, nothing committed.
    for (who, token) in [("the same signed session", signed.clone()), ("another signed session", open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key()))] {
        let second = op(port, Some(&token), &creation_frame(CLAIMANT_ACCOUNT, skep_namespace::BIO_SLOT));
        assert_eq!((acked_addr(&second), acked_at(&second)), (bio.clone(), head), "{who}: the same address, at the position the call was judged at: {second}");
        assert_eq!(second["committed"], json!(false), "{who}: and it says it committed nothing: {second}");
    }
    assert_eq!(head_position(port), head, "no second call committed anything");
    assert_eq!(changes_since(port, Some(&owner), before).len(), 2, "the creation's row and the draft's, and no row of a later call");

    // Another slot: its own document, whatever stands at the bio's.
    assert_unregistered(port, Some(&owner), &policy, "the owner, of the policy document before its creation");
    let other = op(port, Some(&signed), &creation_frame(CLAIMANT_ACCOUNT, POLICY));
    assert_eq!(acked_addr(&other), policy, "the bio standing answers nothing for the policy document: {other}");
    assert!(other.get("committed").is_none(), "the policy document's creation committed: {other}");
    let after = head_position(port);
    assert_eq!(acked_at(&other), after, "{other}");

    // The memo: the first request, re-sent under its id on its session.
    assert_eq!(op(port, Some(&signed), &with_id), first, "a re-send under the first request's `id` is the first acknowledgment whole");
    assert_eq!(head_position(port), after, "the re-send committed nothing");
    let rows = changes_since(port, Some(&owner), before);
    let named: Vec<(&str, &Value)> = rows.iter().map(|row| (row["op"].as_str().expect("op"), &row["docs"])).collect();
    assert_eq!(named.len(), 3, "{rows:?}");
    assert_eq!((named[0].0, named[0].1), ("create_well_known_document", &json!([bio])), "{rows:?}");
    assert_eq!(named[1].0, "create_new_document", "{rows:?}");
    assert_eq!((named[2].0, named[2].1), ("create_well_known_document", &json!([policy])), "{rows:?}");
    sd.shutdown();
}

/// Checks that the mailbox answers a bare session's call standing:
/// private, its commit unsigned, made once.
///
/// On a claimed board the claimant's mailbox stands from the claim's home
/// commit. A bare session's `create_well_known_document` at slot 2 is
/// admitted with no `attest` and answered the mailbox standing, `"committed":
/// false`, at the head: private — a guest is withheld it — dated at the home,
/// whose commit made it, that marker's signature slot empty, the ceremony's
/// home mint being a bare session's. The call commits nothing and adds no
/// row, and a second answers the same.
#[test]
fn the_mailbox_answers_a_bare_sessions_call_standing_private_unsigned_and_once() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let mailbox = slot_of(CLAIMANT_ACCOUNT, skep_namespace::MAILBOX_SLOT);
    let before = head_position(port);
    let frame = creation_frame(CLAIMANT_ACCOUNT, skep_namespace::MAILBOX_SLOT);
    for call in ["the first call", "a second call"] {
        let ack = op_as_written(port, Some(&owner), &frame);
        assert_eq!((acked_addr(&ack), acked_at(&ack), &ack["committed"]), (mailbox.clone(), before, &json!(false)), "{call}: the mailbox standing: {ack}");
    }
    assert_eq!(head_position(port), before, "no call committed anything");
    assert_eq!(changes_since(port, Some(&owner), before), Vec::<Value>::new(), "no call added a row");
    let home = doc_metadata(port, Some(&owner), CLAIMANT_DOC1);
    let home_at = expect_resp(&home, "doc_metadata")["at"].as_u64().expect("the home's position");
    let meta = doc_metadata(port, Some(&owner), &mailbox);
    let m = expect_resp(&meta, "doc_metadata");
    assert_eq!((m["published"].as_bool(), m["at"].as_u64()), (Some(false), Some(home_at)), "private, dated at the home: {meta}");
    assert_withheld(&doc_metadata(port, None, &mailbox), &mailbox);
    assert!(sd.daemon().attestation_at(Seq(home_at)).expect("the journal").is_none(), "the home's commit, the mailbox's, is unsigned");
    sd.shutdown();
}

/// Checks that an `attest` on a call at the mailbox's slot is admitted and
/// dropped.
///
/// A signed session sends the call at slot 2 with the `attest` a shell
/// attaches to every write of the checked set — composed over the slot's own
/// address under the op's token, valid — and the board admits the request
/// and drops the signature unverified, answering the mailbox standing,
/// private, `"committed": false`, with nothing written. An `attest` that
/// verifies over no frame is dropped the same way, never judged: a second
/// account's call, its mailbox standing from its own home's commit, is
/// answered the same.
#[test]
fn a_signed_sessions_mailbox_request_carrying_an_attest_is_admitted_and_the_signature_dropped() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let (account, theirs, _) = an_ordinary_keyed_account(port, &signed, 73);
    let frame = creation_frame(CLAIMANT_ACCOUNT, skep_namespace::MAILBOX_SLOT);
    let attested = attach_attest(port, &signed, &frame);
    assert!(json(attested.as_bytes())["attest"].is_object(), "the premise: the frame carries an attest: {attested}");
    let unverifiable = with_unverifiable_attest(&creation_frame(&account, skep_namespace::MAILBOX_SLOT));
    let cells = [
        ("a valid attest", signed.as_str(), attested.as_str(), CLAIMANT_ACCOUNT),
        ("an attest that verifies over no frame", theirs.as_str(), unverifiable.as_str(), account.as_str()),
    ];
    for (what, token, sent, named) in cells {
        let mailbox = slot_of(named, skep_namespace::MAILBOX_SLOT);
        let before = head_position(port);
        let ack = op_as_written(port, Some(token), sent);
        assert_eq!((acked_addr(&ack), acked_at(&ack), &ack["committed"]), (mailbox.clone(), before, &json!(false)), "{what}: admitted, the mailbox standing: {ack}");
        assert_eq!(head_position(port), before, "{what}: nothing written");
        let meta = doc_metadata(port, Some(token), &mailbox);
        assert_eq!(expect_resp(&meta, "doc_metadata")["published"].as_bool(), Some(false), "{what}: private: {meta}");
        assert_withheld(&doc_metadata(port, None, &mailbox), &mailbox);
        assert_eq!(changes_since(port, Some(token), before), Vec::<Value>::new(), "{what}: no row");
    }
    sd.shutdown();
}

/// Checks that a request with no slot, or a number no slot has, is refused
/// before any write.
///
/// `slot` is required, and names one of the four: a frame without it, and
/// one whose `slot` is doc 1's number, a number of the reserved block past
/// the named four, an ordinary document's, a string or a fraction, is
/// refused at the parse — `malformed`, the frame unparsed, its detail naming
/// the member — from a bare session, a signed one and a guest alike, and
/// with an `attest` riding it. The head does not move, no slot past the
/// mailbox holds a document, and the mailbox stands as the claim's home
/// commit left it.
#[test]
fn a_request_with_no_slot_or_a_number_no_slot_has_is_refused_before_any_write() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let before = head_position(port);
    let slots = ["0", "1", "6", "62", "63", "64", "65", "-2", "2.5", r#""2""#, r#""5""#, r#""policy""#, "true", "[5]"];
    let mut frames = vec![("no slot".to_string(), format!(r#"{{"op":"create_well_known_document","account":"{CLAIMANT_ACCOUNT}"}}"#))];
    for slot in slots {
        frames.push((format!("slot {slot}"), format!(r#"{{"op":"create_well_known_document","account":"{CLAIMANT_ACCOUNT}","slot":{slot}}}"#)));
    }
    for (what, frame) in &frames {
        let attested = with_unverifiable_attest(frame);
        for (who, token, sent) in [("a bare session", Some(owner.as_str()), frame), ("a signed session", Some(signed.as_str()), frame), ("a signed session, an attest riding", Some(signed.as_str()), &attested), ("a guest", None, frame)] {
            let v = op_as_written(port, token, sent);
            let rej = expect_resp(&v, "rejected");
            assert_eq!((rej["code"].as_str(), rej["op"].as_str(), rej["disposition"].as_str()), (Some("malformed"), Some("unparseable"), Some("permanent")), "{what}, {who}: {v}");
            assert!(rej["detail"].as_str().is_some_and(|d| d.contains("'slot'")), "{what}, {who}: the detail names the member: {v}");
        }
    }
    assert_eq!(head_position(port), before, "no refused request moved the head");
    for number in 3..=6u32 {
        assert_unregistered(port, Some(&owner), &format!("{CLAIMANT_ACCOUNT}.0.{number}"), "the owner, of a slot no refused request filled");
    }
    let home_at = expect_resp(&doc_metadata(port, Some(&owner), CLAIMANT_DOC1), "doc_metadata")["at"].as_u64();
    let mailbox = doc_metadata(port, Some(&owner), &slot_of(CLAIMANT_ACCOUNT, skep_namespace::MAILBOX_SLOT));
    assert_eq!(expect_resp(&mailbox, "doc_metadata")["at"].as_u64(), home_at, "the mailbox, as the claim's home commit left it: {mailbox}");
    sd.shutdown();
}

/// Checks that a published slot's creation is publish-class, refused in the
/// published mint's order.
///
/// On a claimed board, at the bio's, the link page's and the policy
/// document's slot alike: a bare session is refused
/// `signed_session_required`; a signed session sending no `attest` is
/// refused `attestation_required`; and one sending an `attest` that
/// verifies over no frame is refused `attestation_invalid:signature` — the
/// three answers, in the order and by the tokens, a mint born published
/// meets from the same three hands. Nothing commits, and no slot holds a
/// document after; the valid frame then lands.
#[test]
fn a_published_slots_creation_is_refused_bare_unsigned_and_badly_signed_in_the_published_mints_order() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let before = head_position(port);
    // The control: a mint born published, from the same three hands.
    let mint = create_frame(CLAIMANT_ACCOUNT, Some(true));
    let of_the_mint = [
        verdict(&op_as_written(port, Some(&owner), &mint)),
        verdict(&op_as_written(port, Some(&signed), &mint)),
        verdict(&op_as_written(port, Some(&signed), &with_unverifiable_attest(&mint))),
    ];
    assert_eq!(of_the_mint, [SIGNED_SESSION_REQUIRED, ATTESTATION_REQUIRED, BAD_SIGNATURE], "the published mint's three refusals");
    for slot in PUBLISHED_SLOTS {
        let frame = creation_frame(CLAIMANT_ACCOUNT, slot);
        let answers = [
            op_as_written(port, Some(&owner), &frame),
            op_as_written(port, Some(&signed), &frame),
            op_as_written(port, Some(&signed), &with_unverifiable_attest(&frame)),
        ];
        assert_eq!(answers.each_ref().map(verdict), of_the_mint.clone(), "slot {slot}: a bare session, no attest, a bad attest: {answers:?}");
        for v in &answers {
            assert_eq!(v["op"].as_str(), Some("create_well_known_document"), "{v}");
        }
        // A bare session's attest changes nothing: the session is what is
        // refused.
        let v = op_as_written(port, Some(&owner), &with_unverifiable_attest(&frame));
        assert_eq!(verdict(&v), SIGNED_SESSION_REQUIRED, "slot {slot}: a bare session, an attest riding: {v}");
        assert_unregistered(port, Some(&owner), &slot_of(CLAIMANT_ACCOUNT, slot), "the owner, of a slot every refusal left empty");
    }
    assert_eq!(head_position(port), before, "no refusal committed");
    for slot in PUBLISHED_SLOTS {
        let ack = op(port, Some(&signed), &creation_frame(CLAIMANT_ACCOUNT, slot));
        assert_eq!(acked_addr(&ack), slot_of(CLAIMANT_ACCOUNT, slot), "slot {slot}: signed and attested, it lands: {ack}");
    }
    sd.shutdown();
}

/// Checks that the creation's signature names its slot and its own token.
///
/// The frame a creation's `attest` signs carries the slot document's own
/// address as its `doc`, under the op's own token: a member signed for the
/// bio's slot and sent with the policy document's is refused
/// `attestation_invalid:signature`, and so is one signed over the parent
/// account, the three mints' term, and one signed over the policy
/// document's address under `create_new_document`'s token. Nothing commits
/// under any of them, at either slot. The member signed for the policy
/// document's slot, at that slot, is admitted.
#[test]
fn a_frame_signed_for_one_slot_is_refused_at_another_and_under_another_ops_token() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let before = head_position(port);
    let (bio, policy) = (skep_namespace::BIO_SLOT, POLICY);
    let attest_of = |frame: &str| json(frame.as_bytes())["attest"].clone();
    // The attest a signer makes for the frame `signed_for`, sent on `sent`.
    let carrying = |sent: &str, attest: Value| {
        let mut v = json(sent.as_bytes());
        v["attest"] = attest;
        v.to_string()
    };
    let for_the_bio = attest_of(&attach_attest(port, &signed, &creation_frame(CLAIMANT_ACCOUNT, bio)));
    assert!(for_the_bio.is_object(), "the premise: the signer attests a creation");
    let at_the_policy_slot = creation_frame(CLAIMANT_ACCOUNT, policy);
    let v = op_as_written(port, Some(&signed), &carrying(&at_the_policy_slot, for_the_bio));
    assert_eq!(verdict(&v), BAD_SIGNATURE, "a frame signed for slot {bio}, sent with slot {policy}: {v}");
    assert_eq!(v["disposition"].as_str(), Some("permanent"), "{v}");

    // Frames a careless signer could make for the policy document's
    // creation, each signed by the session's own key.
    let term = board_term(port).expect("a claimed board has its head");
    let alg = SigAlgRow::of_tag(FIXTURE_TAG).expect("tag 1").token;
    let address = |text: &str| skep_resolve::parse_address(text).expect("an address");
    let (account, document) = (address(CLAIMANT_ACCOUNT), address(&slot_of(CLAIMANT_ACCOUNT, policy)));
    let sign = |doc: &skep_address::Address, op: ContentFreeOp| {
        let bytes = entry_frame(alg, term, &account, DocTerm::One(doc), &entry_body_empty(op));
        attest_member(&hybrid_signer(&device_key()).sign(&bytes))
    };
    for (what, attest) in [
        ("signed over the parent account, the mints' term", sign(&account, ContentFreeOp::CreateWellKnownDocument)),
        ("signed under `create_new_document`'s token over the slot's address", sign(&document, ContentFreeOp::CreateNewDocument)),
        ("signed under `create_new_document`'s token over the account", sign(&account, ContentFreeOp::CreateNewDocument)),
    ] {
        let v = op_as_written(port, Some(&signed), &carrying(&at_the_policy_slot, attest));
        assert_eq!(verdict(&v), BAD_SIGNATURE, "{what}: {v}");
    }
    assert_eq!(head_position(port), before, "no refused frame committed");
    for slot in [bio, policy] {
        assert_unregistered(port, Some(&owner), &slot_of(CLAIMANT_ACCOUNT, slot), "the owner, of a slot no refused frame filled");
    }
    // The frame the board composes: the slot's address, the op's own token.
    let v = op_as_written(port, Some(&signed), &carrying(&at_the_policy_slot, sign(&document, ContentFreeOp::CreateWellKnownDocument)));
    assert_eq!(acked_addr(&v), slot_of(CLAIMANT_ACCOUNT, policy), "signed for slot {policy}, at slot {policy}: admitted: {v}");
    assert_eq!(acked_at(&v), before + 1);
    sd.shutdown();
}

/// Checks that the system account is refused at every slot, at the door.
///
/// A frame naming the system account answers
/// `credential_refused:system_account_no_well_known`, permanent, at the
/// mailbox's, the bio's, the link page's and the policy document's slot,
/// from a bare session and a signed one, with an `attest` riding or none —
/// ahead of the publish-class gate, so a bare session is never told to sign.
/// Nothing commits, and the account's own documents stand untouched: its
/// head document and its time document published, its staging draft private,
/// and no document at its number 5.
#[test]
fn the_system_account_is_refused_at_every_slot_and_its_own_documents_stand_untouched() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let system = skep_namespace::system_account().to_string();
    let before = head_position(port);
    for slot in WellKnownSlot::ALL.map(WellKnownSlot::number) {
        let frame = creation_frame(&system, slot);
        for (who, token, sent) in [
            ("a bare session", owner.as_str(), frame.clone()),
            ("a signed session", signed.as_str(), frame.clone()),
            ("a signed session, an attest riding", signed.as_str(), with_unverifiable_attest(&frame)),
            ("a signed session, its own attest", signed.as_str(), attach_attest(port, &signed, &frame)),
        ] {
            let v = op_as_written(port, Some(token), &sent);
            assert_eq!(verdict(&v), NO_WELL_KNOWN, "slot {slot}, {who}: {v}");
            assert_eq!((v["disposition"].as_str(), v["op"].as_str()), (Some("permanent"), Some("create_well_known_document")), "slot {slot}, {who}: {v}");
        }
    }
    assert_eq!(head_position(port), before, "no refused frame committed");
    let published = |doc: &str| {
        let meta = doc_metadata(port, None, doc);
        let m = expect_resp(&meta, "doc_metadata");
        assert_eq!((m["owner"].as_str(), m["published"].as_bool()), (Some(system.as_str()), Some(true)), "{doc}, as it stood: {meta}");
    };
    published(&skep_namespace::head_document().to_string());
    published(&skep_namespace::time_document().to_string());
    let staging = skep_namespace::staging_draft().to_string();
    assert_eq!(staging, slot_of(&system, skep_namespace::BIO_SLOT), "the premise: the system account's number 3 is its staging draft");
    assert_withheld(&doc_metadata(port, None, &staging), &staging);
    assert_unregistered(port, None, &slot_of(&system, POLICY), "a guest, of the system account's number 5");
    sd.shutdown();
}

/// Checks that a slot document takes its first words by an ordinary stage and
/// publish.
///
/// On an ordinary account — a keyed account beside the claimant's, no
/// door's — the policy document is created, published and empty. A `stage`
/// from it mints a private draft whose recorded base is the slot document
/// itself, its chain holding no member, the copy taking nothing. The owner
/// writes in the draft, and a `publish` naming the slot document as `doc`
/// lands its first version, `<account>.0.5.1`, which a guest reads, at the
/// member's address and at the bare document's. A second draft, staged from
/// the document — now its head — and published on that base, lands
/// `<account>.0.5.2`. Nothing in `stage` or `publish` knows a slot.
#[test]
fn a_policy_document_takes_its_first_words_by_an_ordinary_stage_and_publish() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let registrar = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let (account, signed, bare) = an_ordinary_keyed_account(port, &registrar, 74);
    assert_ne!(account, CLAIMANT_ACCOUNT, "the premise: no door's account");
    let policy = acked_addr(&op(port, Some(&signed), &creation_frame(&account, POLICY)));
    assert_eq!(policy, format!("{account}.0.{POLICY}"), "the account's policy document");
    let meta = doc_metadata(port, None, &policy);
    let m = expect_resp(&meta, "doc_metadata");
    assert_eq!((m["published"].as_bool(), m["birth"].is_null()), (Some(true), true), "a guest reads it: published, no version: {meta}");
    assert_eq!(content_extent(port, None, &policy), 0, "and empty");

    // The first words: a draft staged from the document, its base recorded.
    let draft = stage_of(port, &bare, &policy);
    assert_eq!(
        base_of(port, &bare, &draft),
        (Some(policy.clone()), Some("0".to_string()), Some(policy.clone())),
        "the slot document is the draft's base, its chain empty, the copy taking nothing"
    );
    assert_withheld(&doc_metadata(port, None, &draft), &draft);
    let first = acked_addr(&insert_text(port, &bare, &draft, 1, "open"));
    let v1 = shot(port, &signed, &policy, None, Some(&draft), &[run(&draft, &first, 4)]);
    assert_eq!(v1, format!("{policy}.1"), "the document's first version");
    assert_eq!(text_of(port, None, &v1, 1, 4), "open", "a guest reads the version");
    assert_eq!(text_of(port, None, &policy, 1, 4), "open", "and the bare document, at its head");
    let meta = doc_metadata(port, None, &policy);
    assert_eq!(expect_resp(&meta, "doc_metadata")["birth"].as_str(), Some(v1.as_str()), "{meta}");

    // The next version: staged from the document, which is now its head.
    let next = stage_of(port, &bare, &policy);
    assert_eq!(base_of(port, &bare, &next), (Some(v1.clone()), Some("4".to_string()), Some(v1.clone())), "the head, its whole count");
    let more = acked_addr(&insert_text(port, &bare, &next, 5, "!"));
    let mut runs = shot_runs(port, Some(&bare), &policy, 1, 4);
    runs.push(run(&next, &more, 1));
    let v2 = shot(port, &signed, &policy, Some((&v1, 4)), Some(&next), &runs);
    assert_eq!(v2, format!("{policy}.2"), "the document's second version");
    assert_eq!(text_of(port, None, &policy, 1, 5), "open!", "a guest reads the head");
    assert_eq!(text_of(port, None, &v1, 1, 4), "open", "and the first version as it stood");
    sd.shutdown();
}

/// Checks that every other refusal keeps its order and token at every slot.
///
/// An account holding no document answers `mint_home_first` at the bio's,
/// the link page's and the policy document's slot, from a bare session and
/// from a signed one alike, ahead of the signature's refusals: the home page
/// stays every account's first document. At the policy document's slot a
/// caller who does not own the account is refused the store's `not_owner`,
/// bare or signed and whatever it signed; the owner of the space an
/// undelegated prefix lies in, naming it, the store's `not_an_account`
/// behind the signature's own refusals; a guest `unauthenticated`; and on a
/// board no one has claimed every caller `claim_first`. No refusal commits.
#[test]
fn every_other_refusal_keeps_its_order_and_token_at_every_slot() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let registrar = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    // An account keyed and holding no document: its home is not yet minted.
    let key = distinct_key(75);
    let (homeless, _) = bootstrap_delegate(port, 75);
    let homeless_signed = hire(port, &registrar, CLAIMANT_DOC1, &homeless, 75, &key);
    let homeless_bare = open_session(port, 75);
    let (account, theirs_signed, theirs_bare) = an_ordinary_keyed_account(port, &registrar, 76);
    let before = head_position(port);
    for slot in PUBLISHED_SLOTS {
        let frame = creation_frame(&homeless, slot);
        for (who, token, sent) in [
            ("its owner, bare", homeless_bare.as_str(), frame.clone()),
            ("its owner, signed, no attest", homeless_signed.as_str(), frame.clone()),
            ("its owner, signed and attested", homeless_signed.as_str(), attach_attest(port, &homeless_signed, &frame)),
        ] {
            let v = op_as_written(port, Some(token), &sent);
            assert_eq!(verdict(&v), MINT_HOME_FIRST, "slot {slot}, an account holding no document, {who}: {v}");
        }
        assert_unregistered(port, Some(&homeless_bare), &slot_of(&homeless, slot), "the owner, of the slot it was refused");
    }
    // A caller who does not own the account.
    let at_the_policy_slot = creation_frame(CLAIMANT_ACCOUNT, POLICY);
    for (who, token, sent) in [
        ("a stranger, bare", theirs_bare.as_str(), at_the_policy_slot.clone()),
        ("a stranger, signed, no attest", theirs_signed.as_str(), at_the_policy_slot.clone()),
        ("a stranger, signed, an attest riding", theirs_signed.as_str(), with_unverifiable_attest(&at_the_policy_slot)),
        ("the claimant, of the stranger's account", open_session(port, CLAIMANT_PRINCIPAL).as_str(), creation_frame(&account, POLICY)),
    ] {
        let v = op_as_written(port, Some(token), &sent);
        let rej = expect_resp(&v, "rejected");
        assert_eq!((rej["code"].as_str(), rej["disposition"].as_str(), rej["op"].as_str()), (Some("not_owner"), Some("permanent"), Some("create_well_known_document")), "{who}: {v}");
    }
    // No such account: the signature's refusals stand first, as at a mint
    // born published, and the store's answer behind them.
    let undelegated = next_prefix_under(port, Some(&registrar), CLAIMANT_ACCOUNT);
    let nowhere = creation_frame(&undelegated, POLICY);
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    assert_eq!(verdict(&op_as_written(port, Some(&bare), &nowhere)), SIGNED_SESSION_REQUIRED, "the owner of the space, bare");
    assert_eq!(verdict(&op_as_written(port, Some(&registrar), &nowhere)), ATTESTATION_REQUIRED, "the owner of the space, signed, no attest");
    let v = op(port, Some(&registrar), &nowhere);
    let rej = expect_resp(&v, "rejected");
    assert_eq!((rej["code"].as_str(), rej["disposition"].as_str()), (Some("not_an_account"), Some("reorder")), "the owner of the space, signed and attested: {v}");
    // A guest.
    let v = op_as_written(port, None, &at_the_policy_slot);
    assert_eq!(expect_resp(&v, "rejected")["code"].as_str(), Some("unauthenticated"), "a guest: {v}");
    assert_eq!(head_position(port), before, "no refusal commits");
    sd.shutdown();

    // A board no one has claimed.
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn_unclaimed(dir.path());
    let port = sd.port();
    ceremony_before_the_claim(port);
    assert!(!claimed(port), "the premise: no one has claimed the board");
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let before = head_position(port);
    for slot in WellKnownSlot::ALL.map(WellKnownSlot::number) {
        let frame = creation_frame(CLAIMANT_ACCOUNT, slot);
        for (who, token) in [("the owner's bare session", open_session(port, CLAIMANT_PRINCIPAL)), ("the owner's signed session", signed.clone()), ("a session that does not own the account", open_session(port, 0))] {
            let v = op_as_written(port, Some(&token), &frame);
            assert_eq!(verdict(&v), "credential_refused:claim_first", "slot {slot}, {who}: {v}");
        }
    }
    assert_eq!(head_position(port), before, "no refusal commits");
    sd.shutdown();
}
