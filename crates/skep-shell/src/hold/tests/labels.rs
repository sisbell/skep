//! The label another device's key goes by on a moved face (skep #869).
//!
//! `admitted_labels` is held to the signature-filtered table over records
//! built here: a key is named by the label its admitting record carried, a
//! key enrolled under none, one whose record no key of the set signed and
//! another account's are named by nothing, a since-retired key keeps its
//! name; a delegated account is named through its delegator's records in
//! journal order, a delegator's key signing no genesis made before it, and
//! nothing is named where a delegated account's record is read below the
//! floor, while the claimant's own position-free records name their keys
//! under a claim the floor stands in for. Over the fake board: a read is
//! made once per hands read and kept, a key it does not name read again
//! only at a row past its head, none for a key the store holds or under a
//! bare session; a read that fails — the death signal at one of its
//! token-free reads among them — names the fingerprint, says one line
//! until a read next succeeds, leaves the session standing and what an
//! earlier read gave in place; a kept label is rendered inert; and the head
//! a read makes feeds the board's state.

use std::collections::HashMap;

use skep_client::board::{T_ENROLL, T_RETIRE};
use skep_client::derive::records::{Hand as RecordHand, Kind, Record, Records};
use skep_client::sheet::{render_inert, Label};
use skep_client::sign::{sig_hex, signer_from_seed, RecordFrame, Signer};
use skep_identity::{canonical_record, BoardTerm, Enrollment, Fingerprint};

use super::super::labels::{accounts_read, admitted_labels, AccountLabels};
use super::*;

const CLAIMANT: &str = "1.0.1";

/// An account the claimant handed off.
///
/// Its genesis homes in the claimant's doc 1, signed by the claimant's key.
const GIVEN: &str = "1.0.1.2";

/// `H.1`'s pair, every record frame's term here.
fn term() -> BoardTerm {
    BoardTerm { log_position: 1, chain: [7; 32] }
}

fn key(seed: u8) -> impl Signer {
    signer_from_seed(&[seed; 32])
}

fn fingerprint(signer: &impl Signer) -> Fingerprint {
    signer.fingerprint()
}

/// One entry of an enrollment record.
fn entry(signer: &impl Signer, anchor: bool, label: Option<&str>) -> Enrollment {
    Enrollment::new(signer.public_key().clone(), anchor, label.map(str::to_string)).unwrap()
}

/// What a credential record acts on, by its kind.
enum Body<'a> {
    Enroll(&'a [Enrollment]),
    Retire(&'a [Fingerprint]),
}

/// Returns a credential record on `subject`, read at `position`.
///
/// It is homed in `home_account`'s doc 1 at the link `link`, its `sig` by
/// `hand` over the record frame, none for the ceremony's own genesis.
fn record(subject: &str, home_account: &str, link: u64, body: Body<'_>, hand: Option<&dyn Signer>, position: Option<u64>) -> Record {
    let (kind, ty, sigless, enrolled, retired) = match body {
        Body::Enroll(entries) => (Kind::Enroll, T_ENROLL, canonical_record(entries, None), entries.to_vec(), Vec::new()),
        Body::Retire(fingerprints) => (Kind::Retire, T_RETIRE, canonical_record(fingerprints, None), Vec::new(), fingerprints.to_vec()),
    };
    let home = format!("{home_account}.0.1");
    let sig = hand.map(|hand| {
        let frame = RecordFrame { alg: hand.public_key().alg(), board: term(), home_account, home: &home, ty, to: &[subject], sigless: sigless.as_bytes() }.compose().expect("the record frame composes");
        sig_hex(&hand.sign(&frame))
    });
    Record {
        kind,
        link: format!("{home}.0.2.{link}"),
        home: home.clone(),
        home_account: home_account.to_string(),
        subject: subject.to_string(),
        atom: format!("{home}.0.1.{link}"),
        bytes: sigless.clone().into_bytes(),
        sigless,
        sig,
        enrolled,
        retired,
        position,
        base: position.map(|at| at - 1),
        hand: RecordHand::Bare,
        anchor_grade: false,
    }
}

/// The claimant's own genesis, read at `position`.
fn genesis(entries: &[Enrollment], position: Option<u64>) -> Record {
    record(CLAIMANT, CLAIMANT, 1, Body::Enroll(entries), None, position)
}

/// One account's read, the claim link read at 12 and no floor met.
fn read(account: &str, records: Vec<Record>) -> Records {
    Records { account: account.to_string(), records, head: 100, floor: None, claim_entry: Some(12), claimed: true }
}

/// One account's read above a floor at 30, the claim link's position lost.
fn read_above_the_floor(account: &str, records: Vec<Record>) -> Records {
    Records { floor: Some(30), claim_entry: None, ..read(account, records) }
}

fn labels_of(reads: Vec<Records>, account: &str) -> HashMap<String, String> {
    admitted_labels(reads, account, CLAIMANT, Some(term()))
}

fn label<'m>(named: &'m HashMap<String, String>, signer: &impl Signer) -> Option<&'m str> {
    named.get(&fingerprint(signer).to_hex()).map(String::as_str)
}

/// Checks that a verified record names its key and no other record does.
///
/// A second device a holder's key enrolled is named by its record's label; a
/// key enrolled under no label, and a key planted by a record whose `sig` no
/// key of the set verifies, are named by nothing (the mutants that read the
/// labels off the records unfiltered, or hand a key an empty label).
#[test]
fn a_verified_record_names_its_key_and_a_planted_or_unlabelled_one_nothing() {
    let (anchor, device, second, plain, plant) = (key(1), key(2), key(3), key(4), key(5));
    let records = vec![
        genesis(&[entry(&anchor, true, Some("paper")), entry(&device, false, Some("notebook"))], Some(9)),
        record(CLAIMANT, CLAIMANT, 2, Body::Enroll(&[entry(&second, false, Some("second"))]), Some(&device), Some(20)),
        record(CLAIMANT, CLAIMANT, 3, Body::Enroll(&[entry(&plain, false, None)]), Some(&device), Some(22)),
        record(CLAIMANT, CLAIMANT, 4, Body::Enroll(&[entry(&plant, false, Some("plant"))]), Some(&plant), Some(24)),
    ];
    let named = labels_of(vec![read(CLAIMANT, records)], CLAIMANT);
    assert_eq!(label(&named, &second), Some("second"), "{named:?}");
    assert_eq!(label(&named, &device), Some("notebook"), "the host-trusted genesis names its keys: {named:?}");
    assert_eq!(label(&named, &plain), None, "a key enrolled under no label: {named:?}");
    assert_eq!(label(&named, &plant), None, "a key whose labelling record no key verifies: {named:?}");
}

/// Checks that a label is the account's own.
///
/// The labels are the asked account's admissions alone: a delegator's read
/// is merged for its table, and its keys are named by nothing under the
/// account beneath it, nor a key of that account under the delegator (the
/// mutant that takes every account's admissions names a stranger's device).
#[test]
fn another_accounts_key_is_named_by_nothing() {
    let (anchor, device, recipient) = (key(1), key(2), key(3));
    let reads = || {
        let given_genesis = record(GIVEN, CLAIMANT, 5, Body::Enroll(&[entry(&recipient, false, Some("recipient"))]), Some(&anchor), Some(20));
        vec![read(CLAIMANT, vec![genesis(&[entry(&anchor, true, Some("paper")), entry(&device, false, Some("notebook"))], Some(9))]), read(GIVEN, vec![given_genesis])]
    };
    let under_the_delegator = labels_of(reads(), CLAIMANT);
    assert_eq!((label(&under_the_delegator, &device), label(&under_the_delegator, &recipient)), (Some("notebook"), None), "{under_the_delegator:?}");
    let under_the_given = labels_of(reads(), GIVEN);
    assert_eq!((label(&under_the_given, &device), label(&under_the_given, &recipient)), (None, Some("recipient")), "{under_the_given:?}");
}

/// Checks that a key since retired keeps its name.
///
/// The labels come from every admission, so the rows it wrote before its
/// retirement still go by the device's name (the mutant that takes the
/// table's current set names it by hex alone).
#[test]
fn a_key_since_retired_keeps_its_name() {
    let (anchor, device, second) = (key(1), key(2), key(3));
    let records = vec![
        genesis(&[entry(&anchor, true, Some("paper")), entry(&device, false, Some("notebook"))], Some(9)),
        record(CLAIMANT, CLAIMANT, 2, Body::Enroll(&[entry(&second, false, Some("second"))]), Some(&device), Some(20)),
        record(CLAIMANT, CLAIMANT, 3, Body::Retire(&[fingerprint(&second)]), Some(&device), Some(24)),
    ];
    let named = labels_of(vec![read(CLAIMANT, records)], CLAIMANT);
    assert_eq!(label(&named, &second), Some("second"), "{named:?}");
}

/// Checks that a delegated account is named through its delegator's records.
///
/// The claimant's read and the handed-off account's are merged: the genesis
/// homed in the claimant's doc 1, signed under the claimant's table, and the
/// holder act beneath it name their keys (the mutant that reads the account
/// alone, or leaves the claimant's read out, names nothing here).
#[test]
fn a_delegated_account_is_named_through_its_delegators_records() {
    let (anchor, device, recipient, phone) = (key(1), key(2), key(3), key(4));
    let reads = vec![
        read(CLAIMANT, vec![genesis(&[entry(&anchor, true, Some("paper")), entry(&device, false, Some("notebook"))], Some(9))]),
        read(
            GIVEN,
            vec![
                record(GIVEN, CLAIMANT, 5, Body::Enroll(&[entry(&recipient, false, Some("recipient"))]), Some(&anchor), Some(20)),
                record(GIVEN, GIVEN, 1, Body::Enroll(&[entry(&phone, false, Some("phone"))]), Some(&recipient), Some(24)),
            ],
        ),
    ];
    let named = labels_of(reads, GIVEN);
    assert_eq!((label(&named, &recipient), label(&named, &phone)), (Some("recipient"), Some("phone")), "{named:?}");
}

/// Checks that the merged records keep the journal's order across accounts.
///
/// A delegator's device key signs a genesis: enrolled before that genesis
/// it admits it, enrolled after it admits nothing (the mutant that hands the
/// table the reads in their order judges the later enrollment first and
/// names a recipient no key of the set at its base signed).
#[test]
fn a_delegators_key_enrolled_after_the_genesis_it_signed_admits_nothing() {
    let (device, delegate, recipient) = (key(1), key(2), key(3));
    let named_with_the_key_enrolled_at = |enrolled_at: u64| {
        let reads = vec![
            read(
                CLAIMANT,
                vec![
                    genesis(&[entry(&device, false, Some("notebook"))], Some(9)),
                    record(CLAIMANT, CLAIMANT, 2, Body::Enroll(&[entry(&delegate, false, Some("delegate"))]), Some(&device), Some(enrolled_at)),
                ],
            ),
            read(GIVEN, vec![record(GIVEN, CLAIMANT, 5, Body::Enroll(&[entry(&recipient, false, Some("recipient"))]), Some(&delegate), Some(20))]),
        ];
        labels_of(reads, GIVEN)
    };
    assert_eq!(label(&named_with_the_key_enrolled_at(15), &recipient), Some("recipient"), "enrolled before the genesis it signed");
    assert!(named_with_the_key_enrolled_at(25).is_empty(), "enrolled after: nothing is admitted");
}

/// Checks that a claim below the floor still names the claimant's keys.
///
/// The claim link's position is lost below the floor, yet the claimant's
/// position-free genesis is host-trusted and a later holder's record is
/// judged after it, in the read's own order, so each names its key (the
/// mutant that builds no claim without a position names nothing at a board
/// that has reclaimed).
#[test]
fn a_claim_below_the_floor_still_names_the_claimants_keys() {
    let (anchor, device, second) = (key(1), key(2), key(3));
    let records = vec![
        genesis(&[entry(&anchor, true, Some("paper")), entry(&device, false, Some("notebook"))], None),
        record(CLAIMANT, CLAIMANT, 2, Body::Enroll(&[entry(&second, false, Some("second"))]), Some(&device), None),
    ];
    let named = labels_of(vec![read_above_the_floor(CLAIMANT, records)], CLAIMANT);
    assert_eq!((label(&named, &device), label(&named, &second)), (Some("notebook"), Some("second")), "{named:?}");
}

/// Checks that a delegated account is named above the floor and not below it.
///
/// Its genesis read at a position above the floor stands after the
/// claimant's position-free records and is named; read position-free, no
/// order crosses the accounts and nothing is named, so the mutant that takes
/// the concatenation for the journal's order admits it by hand.
#[test]
fn a_delegated_account_is_named_above_the_floor_and_not_below_it() {
    let (anchor, device, recipient) = (key(1), key(2), key(3));
    let named_with_the_genesis_at = |position: Option<u64>| {
        let reads = vec![
            read_above_the_floor(CLAIMANT, vec![genesis(&[entry(&anchor, true, Some("paper")), entry(&device, false, Some("notebook"))], None)]),
            read_above_the_floor(GIVEN, vec![record(GIVEN, CLAIMANT, 5, Body::Enroll(&[entry(&recipient, false, Some("recipient"))]), Some(&anchor), position)]),
        ];
        labels_of(reads, GIVEN)
    };
    assert_eq!(label(&named_with_the_genesis_at(Some(40)), &recipient), Some("recipient"), "above the floor");
    assert!(named_with_the_genesis_at(None).is_empty(), "below it no order crosses the accounts");
}

/// Checks the accounts a read takes, the claimant's first.
///
/// The rest come top-down, each once, so a claimant's session makes one
/// read (the mutant that walks bottom-up judges a genesis before its
/// delegator's keys).
#[test]
fn a_read_takes_the_claimant_then_the_accounts_above_the_sets_top_down() {
    let cells: [(&str, &str, &[&str]); 4] = [
        ("1.0.1", "1.0.1", &["1.0.1"]),
        ("1.0.1", "1.0.1.2", &["1.0.1", "1.0.1.2"]),
        ("1.0.1", "1.0.1.2.3", &["1.0.1", "1.0.1.2", "1.0.1.2.3"]),
        ("1.0.1", "1.0.2", &["1.0.1", "1.0.2"]),
    ];
    for (claimant, account, chain) in cells {
        assert_eq!(accounts_read(claimant, account), chain, "the claimant {claimant}, the account {account}");
    }
}

/// A `/changes` row of a write by `key`, at `at`.
fn row(at: u64, key: &str) -> Value {
    json!({"at": at, "op": "insert", "key": key, "docs": [DOC]})
}

/// A key this ground's store does not hold.
fn stranger() -> String {
    "ff".repeat(32)
}

/// The hand of a key named by its fingerprint alone.
fn unlabelled(key: &str) -> Value {
    json!({"key": "other", "fingerprint": key})
}

/// The hands of `rows`, as the `held` event carries them.
fn hands(g: &Ground, rows: &[Value]) -> Vec<Value> {
    g.holds.hands_of(&g.session, rows).iter().map(Hand::json).collect()
}

/// How many `find_links_ftt` reads the fake board has answered.
fn links_reads(g: &Ground) -> usize {
    g.fake.links_reads.load(Ordering::SeqCst)
}

/// The lines the hold said of a read that failed.
fn failures_said(g: &Ground) -> Vec<String> {
    said_containing(g, "could not be read to name another device's key")
}

/// The `find_links_ftt` reads one read of the ground's account makes.
///
/// They are the claim link's and the two discovery reads', the fake's
/// answers finding no link.
const LINKS_READS_PER_READ: usize = 3;

/// Checks that a read is kept and made again only for a key past its head.
///
/// The first hands read reads the account, and a later face at or below that
/// read's head reads nothing, a key it does not name included; a row past
/// the head makes one read more, at most one for a page however many keys
/// it names (the mutant that reads again for any key not named never
/// settles for a key no record admits; the one that reads per key).
#[test]
fn a_read_is_kept_and_made_again_only_for_a_key_past_its_head() {
    let g = ground();
    let key = stranger();
    assert_eq!(hands(&g, &[row(5, &key)]), [unlabelled(&key)]);
    assert_eq!(links_reads(&g), LINKS_READS_PER_READ, "one read of the account");
    assert_eq!(hands(&g, &[row(5, &key), row(10, &key)]), [unlabelled(&key)]);
    assert_eq!(links_reads(&g), LINKS_READS_PER_READ, "a key at or below the read's head reads nothing");
    g.fake.log_position.store(20, Ordering::SeqCst);
    assert_eq!(hands(&g, &[row(11, &key)]), [unlabelled(&key)]);
    assert_eq!(links_reads(&g), 2 * LINKS_READS_PER_READ, "a row past the head makes one read");
    assert_eq!(hands(&g, &[row(11, &key)]), [unlabelled(&key)]);
    assert_eq!(links_reads(&g), 2 * LINKS_READS_PER_READ, "and the read's head is past the row now");
    let (second, third) = ("aa".repeat(32), "bb".repeat(32));
    assert_eq!(hands(&g, &[row(30, &second), row(31, &third)]), [unlabelled(&second), unlabelled(&third)]);
    assert_eq!(links_reads(&g), 3 * LINKS_READS_PER_READ, "two keys past the head, one read");
}

/// Checks that a key this store holds reads no record.
#[test]
fn a_key_the_store_holds_makes_no_read() {
    let store = TempDir::new().unwrap();
    let facts = writer_facts(&store);
    let KeyId(held) = FileStore::open(store.path().join("store")).generate(Some(Label::new("phone").unwrap())).unwrap();
    let g = ground_in(store, facts, 0);
    assert_eq!(hands(&g, &[row(5, &held.to_hex())]), [json!({"key": "other", "fingerprint": held.to_hex(), "label": "phone"})], "the store's own label");
    assert_eq!(links_reads(&g), 0, "no read for a key the store holds");
}

/// Checks that a bare session names the fingerprint and reads nothing.
#[test]
fn a_bare_session_reads_no_record() {
    let g = bare_ground();
    let key = stranger();
    assert_eq!(hands(&g, &[row(5, &key)]), [unlabelled(&key)]);
    assert_eq!(links_reads(&g), 0, "a bare session holds no account to read");
}

/// Checks that a read that fails names the fingerprint and says one line.
///
/// Refused, or met by the death signal at one of its token-free reads, the
/// hand goes by its fingerprint, one line says so however many faces follow,
/// and the session stands — the failure is never the session's death; the
/// first read that then succeeds says one line more, and the next says
/// nothing (the mutants that read the failure as a death of the read, or
/// say it per face).
#[test]
fn a_read_that_fails_names_the_fingerprint_says_one_line_and_leaves_the_session() {
    for (cell, answer) in [("a busy board", respond(503, json!({"error": "history_busy"}))), ("the death signal", closed())] {
        let g = ground();
        let key = stranger();
        g.fake.links_answer.every(answer);
        for _ in 0..2 {
            assert_eq!(hands(&g, &[row(5, &key)]), [unlabelled(&key)], "{cell}");
        }
        assert_eq!(failures_said(&g).len(), 1, "{cell}: one line while it stands: {:?}", g.said.lock().unwrap());
        assert!(!g.session.is_ending() && g.sessions.get(&g.session.reference).is_some(), "{cell}: the session stands");
        g.fake.links_answer.clear();
        assert_eq!(hands(&g, &[row(5, &key)]), [unlabelled(&key)], "{cell}");
        assert_eq!(said_containing(&g, "credential records read again").len(), 1, "{cell}: the end of it said once");
        assert_eq!(hands(&g, &[row(30, &key)]), [unlabelled(&key)], "{cell}");
        assert_eq!(said_containing(&g, "credential records read again").len(), 1, "{cell}: a healthy read says nothing");
    }
}

/// Checks that the head a label read makes feeds the board's state.
///
/// The board is claimed and its head record stands garbled after the
/// session's open read it whole, so the label read is the first to meet it:
/// the read fails, the state says `head_unreadable`, and the key is named by
/// its fingerprint (skep #865; the mutant that reads the term off the
/// session makes a read of the head no state hears of).
#[test]
fn the_head_a_label_read_makes_feeds_the_boards_state() {
    let fake = Fake::new();
    fake.no_head.store(true, Ordering::SeqCst);
    fake.unclaimed.store(true, Ordering::SeqCst);
    let store = TempDir::new().unwrap();
    let facts = writer_facts(&store);
    let g = ground_over(fake, store, facts, 0);
    assert_eq!(g.holds.state("b-1"), BoardState::Running, "the board no one has claimed, its head owed nothing");
    g.fake.unclaimed.store(false, Ordering::SeqCst);
    g.fake.no_head.store(false, Ordering::SeqCst);
    g.fake.head_garbled.store(true, Ordering::SeqCst);
    let key = stranger();
    assert_eq!(hands(&g, &[row(5, &key)]), [unlabelled(&key)]);
    assert_eq!(g.holds.state("b-1").as_str(), "head_unreadable", "the state the head's read left");
    assert_eq!(failures_said(&g).len(), 1, "{:?}", g.said.lock().unwrap());
}

/// Checks that what an earlier read gave stands past a read that fails.
///
/// A key the kept read names keeps its label through a failed read another
/// key's row made, and is named inert (the mutants that drop the kept read
/// at a failure, or hand the page the record's label as written).
#[test]
fn a_failed_read_leaves_what_an_earlier_read_named_and_labels_are_inert() {
    let g = ground();
    let (named, other) = (stranger(), "aa".repeat(32));
    g.holds.lock("b-1").labels.insert(CLAIMANT.to_string(), AccountLabels::naming(&named, "\u{202e}laptop", 10));
    g.fake.links_answer.every(respond(503, json!({"error": "history_busy"})));
    assert_eq!(hands(&g, &[row(11, &other), row(5, &named)]), [unlabelled(&other), json!({"key": "other", "fingerprint": named, "label": render_inert("\u{202e}laptop")})]);
    assert_eq!(hands(&g, &[row(11, &other), row(5, &named)]).len(), 2, "the failed read stands alone");
    assert_eq!(failures_said(&g).len(), 1, "{:?}", g.said.lock().unwrap());
}
