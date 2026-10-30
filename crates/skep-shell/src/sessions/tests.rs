//! The session table, a session's end and the reason its end carries.
//!
//! The suite checks a session registered under a fresh reference, beside the
//! board it stands at; its end run once whichever caller meets the death — a
//! second caller answering the first's reason, two callers at once one
//! derivation, a caller that panics mid-end leaving the end to the next — and a
//! signed session's death read off its set and its account, the retirement
//! ahead of the genesis, its hand this store's own only where that can be said,
//! and a retirement read naming the position it read whatever its hand; a
//! principal's supplement following its standing sessions, a key's diagnosis
//! named by the list it stands in, a session's key attesting the ten kinds with
//! an entry frame alone and a write going out under a signed session alone, and
//! a frame no attest is owed for borrowed as it stands, never copied.

use std::io::Read;
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::sync::Condvar;
use std::thread;
use std::time::Duration;

use skep_client::derive::records::{Kind, Record};
use skep_client::dial::{DialError, Dialer, Headers, PlainHttp, Request, RequestHead, Response, StreamedResponse};
use skep_client::Origin;
use skep_identity::Enrollment;

use super::*;

/// The supplements a test records: each widen by reference, each
/// narrow by principal.
#[derive(Default)]
struct Recorded(Vec<String>);

impl Supplements for Recorded {
    fn widen(&mut self, session: &Arc<SessionEntry>) {
        self.0.push(format!("widen {}", session.reference));
    }

    fn narrow(&mut self, principal: u64) {
        self.0.push(format!("narrow {principal}"));
    }
}

/// A signed session's `Open` as `principal`, acting as `account`, its set
/// `set_account`'s.
fn signed_open(principal: u64, account: &str, set_account: &str) -> Open {
    let kind = SessionKind::Signed { fingerprint: Fingerprint::parse_hex(&"5a".repeat(32)).unwrap(), set_account: set_account.into() };
    let facts = Facts { principal, account: Some(account.into()), kind };
    Open { token: Token::parse(&"9f".repeat(16)).unwrap(), facts, opened_at: 0 }
}

/// A board nothing answers at: a port bound and let go.
fn nowhere() -> Arc<Board> {
    let port = TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port();
    Arc::new(Board::new(Origin::parse(&format!("http://127.0.0.1:{port}")).unwrap(), PlainHttp::new()))
}

/// The entry of `board` under `reference`: a board as the table registers a
/// session at it.
fn at(reference: &str, board: Arc<Board>) -> BoardEntry {
    BoardEntry { reference: reference.into(), board }
}

/// A dialer that holds each exchange at its gate until the test opens it,
/// counting them, then answers that the board did not answer.
struct Gated {
    calls: AtomicUsize,
    entered: Mutex<Sender<()>>,
    gate: (Mutex<bool>, Condvar),
}

impl Dialer for Gated {
    fn exchange(&self, _: &Origin, _: &Request) -> Result<Response, DialError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let _ = self.entered.lock().unwrap().send(());
        let (gate, opened) = &self.gate;
        let _held = opened.wait_while(gate.lock().unwrap(), |open| !*open).unwrap();
        Err(DialError::Connect("held, then let go".into()))
    }

    fn stream(&self, _: &Origin, _: &RequestHead, _: &mut dyn Read, _: &mut dyn FnMut(&Headers)) -> Result<StreamedResponse, DialError> {
        Err(DialError::Connect("no stream here".into()))
    }
}

/// The table: a session registered under a fresh reference, beside the
/// board it was registered at, and its supplement widened, listed by board,
/// found by reference; a session by reference is a signed one whose set is
/// above its account, and a bare session, which authenticated against no
/// set, never is.
#[test]
fn the_table_registers_sessions_under_fresh_references() {
    let (board, sessions) = (nowhere(), Sessions::new(None, Arc::new(|_: &str| {})));
    let mut supplements = Recorded::default();
    let one = sessions.register(&at("b-1", Arc::clone(&board)), signed_open(1, "1.0.1.1", "1.0.1"), &mut supplements);
    let two = sessions.register(&at("b-2", nowhere()), signed_open(2, "1.0.1.1", "1.0.1.1"), &mut supplements);
    assert!(one.reference.starts_with("s-") && one.reference != two.reference);
    assert!(Arc::ptr_eq(&one.board, &board) && !Arc::ptr_eq(&two.board, &board), "each session holds the board it was registered at");
    assert_eq!(supplements.0, [format!("widen {}", one.reference), format!("widen {}", two.reference)]);
    assert_eq!(sessions.len(), 2);
    assert_eq!(sessions.on_board("b-1").len(), 1);
    assert!(one.facts.by_reference());
    assert!(!sessions.get(&two.reference).unwrap().facts.by_reference());
    assert!(!Facts { principal: 3, account: Some("1.0.1.1".into()), kind: SessionKind::Bare }.by_reference());
}

/// THE END, ONCE: the first `end` takes the session out of the table,
/// derives the reason (the arm of the board that does not answer), emits
/// one `session-died` and narrows; a second `end` of the same death
/// answers the same reason and does nothing else; nothing is left to
/// `close`. A session closed first is closed once, and a death met after
/// the close answers the reason the page's own close carries.
#[test]
fn a_session_ends_once_and_a_second_caller_answers_the_first_reason() {
    let (board, sessions, bus) = (nowhere(), Sessions::new(None, Arc::new(|_: &str| {})), EventBus::new());
    let rx = bus.subscribe();
    let mut supplements = Recorded::default();
    let entry = sessions.register(&at("b-1", Arc::clone(&board)), signed_open(1, "1.0.1", "1.0.1"), &mut supplements);
    let reason = sessions.end(&entry, &mut supplements, &bus);
    assert_eq!(reason["arm"], "unreachable", "{reason}");
    assert!(sessions.get(&entry.reference).is_none());
    let died: Vec<_> = rx.try_iter().collect();
    assert_eq!(died.len(), 1);
    assert_eq!((died[0].name, died[0].data["session"].as_str()), (EventName::SessionDied, Some(entry.reference.as_str())));
    assert_eq!(died[0].data["reason"], reason);
    assert_eq!(supplements.0.last().map(String::as_str), Some("narrow 1"));
    let touched = supplements.0.len();
    assert_eq!(sessions.end(&entry, &mut supplements, &bus), reason, "the second caller answers the first's reason");
    assert!(rx.try_recv().is_err(), "and emits nothing");
    assert_eq!(supplements.0.len(), touched, "and touches no supplement");
    assert!(sessions.close(&entry.reference).is_none(), "nothing is left to close");
    let closed_first = sessions.register(&at("b-1", board), signed_open(1, "1.0.1", "1.0.1"), &mut supplements);
    assert!(sessions.close(&closed_first.reference).is_some());
    assert!(sessions.close(&closed_first.reference).is_none(), "closed once");
    assert_eq!(sessions.end(&closed_first, &mut supplements, &bus), closed(), "a death met after the close answers its reason");
    assert!(rx.try_recv().is_err());
}

/// ONE SUPPLEMENT PER PRINCIPAL: a session that ends hands its
/// principal's supplement to another session of the principal standing
/// at its board, and narrows it where none stands there — a session of
/// the principal at another board takes nothing; a close releases it the
/// same way.
#[test]
fn a_principals_supplement_follows_its_standing_sessions() {
    let (board, sessions, bus) = (nowhere(), Sessions::new(None, Arc::new(|_: &str| {})), EventBus::new());
    let mut supplements = Recorded::default();
    let first = sessions.register(&at("b-1", Arc::clone(&board)), signed_open(1, "1.0.1", "1.0.1"), &mut supplements);
    let second = sessions.register(&at("b-1", Arc::clone(&board)), signed_open(1, "1.0.1", "1.0.1"), &mut supplements);
    sessions.register(&at("b-2", nowhere()), signed_open(1, "1.0.1", "1.0.1"), &mut supplements);
    supplements.0.clear();
    sessions.end(&first, &mut supplements, &bus);
    assert_eq!(supplements.0, [format!("widen {}", second.reference)], "the session standing at the board takes the supplement");
    sessions.end(&second, &mut supplements, &bus);
    assert_eq!(supplements.0.last().map(String::as_str), Some("narrow 1"), "none stands at b-1, and the session at b-2 takes nothing");
    let third = sessions.register(&at("b-1", Arc::clone(&board)), signed_open(1, "1.0.1", "1.0.1"), &mut supplements);
    let fourth = sessions.register(&at("b-1", board), signed_open(1, "1.0.1", "1.0.1"), &mut supplements);
    supplements.0.clear();
    assert!(sessions.close(&third.reference).is_some());
    sessions.release("b-1", 1, &mut supplements);
    assert_eq!(supplements.0, [format!("widen {}", fourth.reference)]);
    assert!(sessions.close(&fourth.reference).is_some());
    sessions.release("b-1", 1, &mut supplements);
    assert_eq!(supplements.0.last().map(String::as_str), Some("narrow 1"));
}

/// Two callers meet one death at once: the second waits on the entry's
/// `OnceLock` while the first derives the reason, then answers that reason —
/// one derivation (one dial), one event, one supplement touched.
#[test]
fn a_second_caller_waits_for_the_reason_the_first_derives() {
    let (entered, at_the_dial) = channel();
    let gated = Arc::new(Gated { calls: AtomicUsize::new(0), entered: Mutex::new(entered), gate: (Mutex::new(false), Condvar::new()) });
    let board = Arc::new(Board::new(Origin::parse("http://127.0.0.1:9").unwrap(), Arc::clone(&gated)));
    let (sessions, bus) = (Sessions::new(None, Arc::new(|_: &str| {})), EventBus::new());
    let rx = bus.subscribe();
    let entry = sessions.register(&at("b-1", board), signed_open(1, "1.0.1", "1.0.1"), &mut Recorded::default());
    let (mut first_caller, mut second_caller) = (Recorded::default(), Recorded::default());
    let (first, second) = thread::scope(|s| {
        let first = s.spawn(|| sessions.end(&entry, &mut first_caller, &bus));
        at_the_dial.recv().unwrap();
        let second = s.spawn(|| sessions.end(&entry, &mut second_caller, &bus));
        thread::sleep(Duration::from_millis(50));
        *gated.gate.0.lock().unwrap() = true;
        gated.gate.1.notify_all();
        (first.join().unwrap(), second.join().unwrap())
    });
    assert_eq!(first["arm"], "unreachable", "{first}");
    assert_eq!(second, first);
    assert_eq!(gated.calls.load(Ordering::SeqCst), 1, "the reason was derived once");
    assert_eq!(rx.try_iter().filter(|e| e.name == EventName::SessionDied).count(), 1);
    assert_eq!((first_caller.0, second_caller.0), (vec!["narrow 1".to_string()], vec![]));
}

/// A dialer whose first exchange panics, every later one unanswered.
struct PanicsOnce(AtomicUsize);

impl Dialer for PanicsOnce {
    fn exchange(&self, _: &Origin, _: &Request) -> Result<Response, DialError> {
        assert!(self.0.fetch_add(1, Ordering::SeqCst) > 0, "the first dial panics");
        Err(DialError::Connect("unanswered".into()))
    }

    fn stream(&self, _: &Origin, _: &RequestHead, _: &mut dyn Read, _: &mut dyn FnMut(&Headers)) -> Result<StreamedResponse, DialError> {
        Err(DialError::Connect("no stream here".into()))
    }
}

/// A board answering `/health` as a claimed board under local trust, and
/// `key_set` with the answer `sets` holds for the account the frame names —
/// every other read refused, so a death's read of the records finds none.
struct KeySets(HashMap<&'static str, Value>);

impl Dialer for KeySets {
    fn exchange(&self, _: &Origin, req: &Request) -> Result<Response, DialError> {
        let answer = |v: Value| Ok(Response { status: 200, headers: Headers::default(), body: v.to_string().into_bytes() });
        if req.path.starts_with("/health") {
            return answer(json!({"ok": true, "log_position": 10, "auth": {"claimant": "1.0.1", "local_trust": true, "origins": [], "signed_origins": []}, "writes": {"halted": false}}));
        }
        let frame: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
        match (frame["op"].as_str(), frame["account"].as_str().and_then(|account| self.0.get(account))) {
            (Some("key_set"), Some(set)) => answer(set.clone()),
            _ => answer(json!({"resp": "rejected", "code": "doc_not_registered", "disposition": "reorder"})),
        }
    }

    fn stream(&self, _: &Origin, _: &RequestHead, _: &mut dyn Read, _: &mut dyn FnMut(&Headers)) -> Result<StreamedResponse, DialError> {
        Err(DialError::Connect("no stream here".into()))
    }
}

/// A `key_set` answer as of `as_of`: the keys `enrolled`, the fingerprints
/// `retired`.
fn key_set_answer(as_of: u64, enrolled: &[&skep_identity::PublicKey], retired: &[Fingerprint]) -> Value {
    let enrolled: Vec<Value> = enrolled.iter().map(|k| json!({"alg": k.alg(), "key": k.to_hex(), "fingerprint": Fingerprint::of(k).to_hex()})).collect();
    let retired: Vec<Value> = retired.iter().map(|f| json!({"fingerprint": f.to_hex()})).collect();
    json!({"resp": "key_set", "as_of": as_of, "enrolled": enrolled, "retired": retired})
}

/// Checks that a signed session's death is read off its set and its account.
///
/// It is §4b.2's arms, in `derive_death`'s order: its key standing in the
/// retired list of the set it authenticated against is the retirement, in
/// AUTH-5.77's no-hand form where the board withholds the records that would
/// name the hand, `own` null and the fork unsaid (AUTH-5.27); a session by
/// reference whose acted-as account now holds a set of its own is the genesis,
/// the `seeded` arm naming the set's first key; that account keyless still, the
/// restart; and where both stand the retirement is read first. The mutants that
/// drop either arm, read the enrolled list for the retired one, take the
/// session's set for its account's, read the genesis first, or answer a death
/// whose record was not read `own` false each face the page a restart, the
/// wrong death, or another hand's.
#[test]
fn a_signed_sessions_death_is_read_off_its_set_and_its_account() {
    let key = skep_client::sign::signer_from_seed(&[7; 32]).public_key().clone();
    let session_key = Fingerprint::parse_hex(&"5a".repeat(32)).unwrap();
    let (retired, empty, seeded) = (key_set_answer(4, &[], &[session_key]), key_set_answer(4, &[], &[]), key_set_answer(9, &[&key], &[]));
    let no_hand = json!({"arm": "retired", "fingerprint": "5a".repeat(32), "own": null, "hand": null, "position": null, "label": null});
    let genesis = json!({"arm": "seeded", "account": "1.0.1.1", "as_of": 9, "writer": Fingerprint::of(&key).to_hex()});
    let cells = [
        ("its key retired", signed_open(1, "1.0.1", "1.0.1"), vec![("1.0.1", retired.clone())], no_hand.clone()),
        ("its account seeded", signed_open(1, "1.0.1.1", "1.0.1"), vec![("1.0.1", empty.clone()), ("1.0.1.1", seeded.clone())], genesis),
        ("its account keyless still", signed_open(1, "1.0.1.1", "1.0.1"), vec![("1.0.1", empty.clone()), ("1.0.1.1", empty)], json!({"arm": "restart", "reopened": false})),
        ("both at once", signed_open(1, "1.0.1.1", "1.0.1"), vec![("1.0.1", retired), ("1.0.1.1", seeded)], no_hand),
    ];
    for (cell, open, sets, reason) in cells {
        let board = Arc::new(Board::new(Origin::parse("http://127.0.0.1:9").unwrap(), KeySets(sets.into_iter().collect())));
        let sessions = Sessions::new(None, Arc::new(|_: &str| {}));
        let entry = sessions.register(&at("b-1", board), open, &mut Recorded::default());
        assert_eq!(sessions.end(&entry, &mut Recorded::default(), &EventBus::new()), reason, "{cell}");
        assert_eq!(sessions.len(), 0, "{cell}: the session left the table");
    }
}

/// Checks that the fork on a retirement's hand is taken only where it can be.
///
/// It is the fork of AUTH-5.28 and AUTH-5.77, cell by cell: the session's own
/// key is this store's whether or not the store could be listed, or listed
/// without that key's file (AUTH-5.28: "the token's own key as its hand");
/// another key is this store's where the listing holds it and not where it does
/// not; a bare row and the board's daemon are no key's either way, and a `sig`
/// no key verifies is none of this store's keys where they were tried; another
/// key, or a `sig` no key verifies, beside a store that could not be listed is
/// unsaid, never `false`, a store holding no keys (SP-14); and no record read,
/// or a hand not read, is unsaid whatever the store answers (AUTH-5.27;
/// AUTH-5.77's no-hand form). The mutants that read a failed listing as an
/// empty one, drop the session's own key, never consult the listing, read every
/// hand beside a failed listing as this store's own, or answer an unread hand
/// `false` each answer a cell otherwise.
#[test]
fn a_retirements_hand_is_this_stores_own_only_where_that_can_be_said() {
    let session = Fingerprint::parse_hex(&"5a".repeat(32)).unwrap();
    let public = skep_client::sign::signer_from_seed(&[7; 32]).public_key().clone();
    let other = Fingerprint::of(&public);
    let holding: &[(Fingerprint, PublicKey)] = &[(other, public)];
    let empty: &[(Fingerprint, PublicKey)] = &[];
    let unread = Hand::Unreadable("below the retention floor".into());
    let cells = [
        ("the session's key, the store unlisted", Some(Hand::Key(session)), None, Some(true)),
        ("the session's key, listed without its file", Some(Hand::Key(session)), Some(empty), Some(true)),
        ("another key the listing holds", Some(Hand::Key(other)), Some(holding), Some(true)),
        ("another key the listing does not hold", Some(Hand::Key(other)), Some(empty), Some(false)),
        ("another key, the store unlisted", Some(Hand::Key(other)), None, None),
        ("a bare row, the store unlisted", Some(Hand::Bare), None, Some(false)),
        ("the daemon's own, the store unlisted", Some(Hand::System), None, Some(false)),
        ("a sig no key verifies, the store listed", Some(Hand::NoKeyVerifies), Some(empty), Some(false)),
        ("a sig no key verifies, the store unlisted", Some(Hand::NoKeyVerifies), None, None),
        ("no record read, the store listed", None, Some(empty), None),
        ("a hand not read, the store listed", Some(unread.clone()), Some(empty), None),
        ("a hand not read, the store unlisted", Some(unread), None, None),
    ];
    for (cell, hand, own_keys, own) in cells {
        assert_eq!(hand_is_own(hand.as_ref(), &session, own_keys), own, "{cell}");
    }
}

/// Returns a credential record of `kind`, read at `position` under `hand`.
///
/// It enrolls `enrolled` or retires `retired`; its link, home and atom are
/// placeholders, and it carries no bytes and no signature, which no reason
/// reads.
fn record(kind: Kind, enrolled: Vec<Enrollment>, retired: Vec<Fingerprint>, position: Option<u64>, hand: Hand) -> Record {
    Record {
        kind,
        link: "1.0.1.0.1.0.2.1".into(),
        home: "1.0.1.0.1".into(),
        home_account: "1.0.1".into(),
        subject: "1.0.1".into(),
        atom: "1.0.1.0.1.0.1.1".into(),
        bytes: Vec::new(),
        sigless: String::new(),
        sig: None,
        enrolled,
        retired,
        position,
        base: None,
        hand,
        anchor_grade: false,
    }
}

/// Checks that a retirement record read names its position whatever its hand.
///
/// A record read keeps the position it was read at: where its hand could not be
/// named, a row whose testimony was lost, the reason names that position and no
/// hand, `own` null (AUTH-5.77's no-hand form; AUTH-5.27); a key's hand is
/// named with its label, a bare row's as `bare`, and the board's daemon and a
/// `sig` no key verifies by no hand, each at its position and none of this
/// store's keys; and below the floor, where no record names the key, or where
/// no records were read, the reason names no position and leaves the fork
/// unsaid. The mutants that drop the position of a hand not named, or answer an
/// unread hand or a missing record `own` false, each answer a cell otherwise.
#[test]
fn a_retirement_read_names_its_position_whatever_its_hand() {
    let key = skep_client::sign::signer_from_seed(&[7; 32]).public_key().clone();
    let fp = Fingerprint::of(&key);
    let listed: &[(Fingerprint, PublicKey)] = &[];
    let enrollment = record(Kind::Enroll, vec![Enrollment::new(key, false, Some("notebook".into())).unwrap()], Vec::new(), Some(3), Hand::Bare);
    let read = |records: Vec<Record>| Records { account: "1.0.1".into(), records, head: 10, floor: None, claim_entry: None, claimed: true };
    let retired_by = |hand: Hand, position: Option<u64>| read(vec![enrollment.clone(), record(Kind::Retire, Vec::new(), vec![fp], position, hand)]);
    let reason = |own: Option<bool>, hand: Option<&str>, position: Option<u64>, label: Option<&str>| -> Value {
        json!({"arm": "retired", "fingerprint": fp.to_string(), "own": own, "hand": hand, "position": position, "label": label})
    };
    let lost = Hand::Unreadable("the row's testimony was lost (`key: null`)".into());
    let floor = Hand::Unreadable("below the retention floor: the position does not answer, and the hand with it".into());
    let cells = [
        ("a lost testimony at 7", Some(retired_by(lost, Some(7))), reason(None, None, Some(7), None)),
        ("below the floor", Some(retired_by(floor, None)), reason(None, None, None, None)),
        ("the session's own key at 7", Some(retired_by(Hand::Key(fp), Some(7))), reason(Some(true), Some(fp.to_string().as_str()), Some(7), Some("notebook"))),
        ("a bare row at 7", Some(retired_by(Hand::Bare, Some(7))), reason(Some(false), Some("bare"), Some(7), None)),
        ("a sig no key verifies at 7", Some(retired_by(Hand::NoKeyVerifies, Some(7))), reason(Some(false), None, Some(7), None)),
        ("the board's daemon at 7", Some(retired_by(Hand::System, Some(7))), reason(Some(false), None, Some(7), None)),
        ("no retirement record names the key", Some(read(vec![enrollment.clone()])), reason(None, None, None, None)),
        ("no records read", None, reason(None, None, None, None)),
    ];
    for (cell, records, expected) in cells {
        assert_eq!(retired_reason(&fp, records.as_ref(), Some(listed)), expected, "{cell}");
    }
}

/// A caller that panics mid-end ends nothing, and the next caller derives
/// the reason and says the one `session-died`.
#[test]
fn a_caller_that_panics_mid_end_leaves_the_end_to_the_next() {
    let board = Arc::new(Board::new(Origin::parse("http://127.0.0.1:9").unwrap(), PanicsOnce(AtomicUsize::new(0))));
    let (sessions, bus) = (Sessions::new(None, Arc::new(|_: &str| {})), EventBus::new());
    let rx = bus.subscribe();
    let entry = sessions.register(&at("b-1", board), signed_open(1, "1.0.1", "1.0.1"), &mut Recorded::default());
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| sessions.end(&entry, &mut Recorded::default(), &bus)));
    assert!(panicked.is_err() && rx.try_recv().is_err(), "the first caller ended nothing");
    assert_eq!(sessions.end(&entry, &mut Recorded::default(), &bus)["arm"], "unreachable");
    assert_eq!(rx.try_iter().filter(|e| e.name == EventName::SessionDied).count(), 1);
}

/// THE KEY's DIAGNOSIS names a key face by the list the key stands in — the
/// one rule `session`'s and `bind`'s refusals share: an enrolled key
/// answers `Ok`, and no read is made; a retired key is `retired`, its face
/// composed without the records a board that does not answer withholds; a
/// key in neither list is `not_enrolled` (the mutants that name every face
/// one name, or one list's face the other's).
#[test]
fn a_keys_diagnosis_is_named_by_the_list_it_stands_in() {
    let public = skep_client::sign::signer_from_seed(&[7; 32]).public_key().clone();
    let fingerprint = Fingerprint::of(&public);
    let key = KeyFacts { path: std::path::PathBuf::from("/nowhere/key"), fingerprint, public: public.clone(), label: None, anchor: false };
    let walk = |set: skep_client::KeySet| Walk { account: "1.0.1".into(), set_account: "1.0.1".into(), set, visited: vec!["1.0.1".into()] };
    let enrolled = skep_client::KeySet { as_of: 1, enrolled: vec![skep_client::board::EnrolledKey { fingerprint, key: public, anchor: false }], retired: Vec::new() };
    let retired = skep_client::KeySet { as_of: 1, enrolled: Vec::new(), retired: vec![skep_client::board::RetiredKey { fingerprint, anchor: false }] };
    let board = nowhere();
    assert!(diagnose_key(&board, &walk(enrolled), &key, Site::Session).is_ok(), "an enrolled key is diagnosed enrolled");
    let refused = diagnose_key(&board, &walk(retired), &key, Site::Session).unwrap_err();
    assert_eq!((refused.name(), refused.to_value()["kind"].as_str()), ("retired", Some("halt")), "{refused}");
    let refused = diagnose_key(&board, &walk(skep_client::KeySet::default()), &key, Site::Tail).unwrap_err();
    assert_eq!((refused.name(), refused.to_value()["kind"].as_str()), ("not_enrolled", Some("halt")), "{refused}");
}

/// A SESSION's KEY ATTESTS the ten kinds that have an entry frame and no
/// other: a signed session names the key that opened it for an `insert`
/// and none for a `delete`, and a bare session names none for either —
/// what `attest` signs with and the burst's door keeps an attest's room for
/// (the mutants that attest a bare session's write, or every kind, leave
/// the burst's door keeping room no send takes, or none where a send does).
/// And a WRITE goes out under the signed session alone: the bare one, the
/// keyless session for reading, may write nothing (foundations §3.3 state
/// 3; the mutant that lets a bare session write commits a `bare` write no
/// key signed).
#[test]
fn a_sessions_key_attests_the_checked_kinds_alone() {
    let sessions = Sessions::new(None, Arc::new(|_: &str| {}));
    let signed = sessions.register(&at("b-1", nowhere()), signed_open(1, "1.0.1", "1.0.1"), &mut Recorded::default());
    let SessionKind::Signed { fingerprint, .. } = &signed.facts.kind else { panic!("a signed session holds a key") };
    assert_eq!((signed.attesting_key("insert"), signed.attesting_key("delete")), (Some(fingerprint), None));
    let facts = Facts { principal: 2, account: Some("1.0.2".into()), kind: SessionKind::Bare };
    let bare = sessions.register(&at("b-1", nowhere()), Open { token: Token::parse(&"8e".repeat(16)).unwrap(), facts, opened_at: 0 }, &mut Recorded::default());
    assert_eq!((bare.attesting_key("insert"), bare.attesting_key("delete")), (None, None));
    assert_eq!((signed.may_write(), bare.may_write()), (true, false), "a write goes out under the signed session alone");
}

/// A FRAME NO ATTEST IS OWED FOR is borrowed as it stands, never copied: a
/// bare session's insert, a signed session's `delete` (outside the checked
/// set), and a signed session's insert whose attest the page supplied —
/// each answered before any read, the board one nothing answers at, whose
/// silence would answer `attest_not_composed` (the mutant that copies the
/// frame on every path pays a deep copy per send for nothing; the one that
/// reads the board's `H.1` first refuses a frame it was never to sign).
#[test]
fn a_frame_no_attest_is_owed_for_is_borrowed_as_it_stands() {
    let (sessions, store) = (Sessions::new(None, Arc::new(|_: &str| {})), FileStore::open("/nonexistent/store"));
    let signed = sessions.register(&at("b-1", nowhere()), signed_open(1, "1.0.1", "1.0.1"), &mut Recorded::default());
    let facts = Facts { principal: 2, account: Some("1.0.2".into()), kind: SessionKind::Bare };
    let bare = sessions.register(&at("b-1", nowhere()), Open { token: Token::parse(&"8e".repeat(16)).unwrap(), facts, opened_at: 0 }, &mut Recorded::default());
    let insert = json!({"op": "insert", "doc": "1.0.1.0.1", "values": ["a"]});
    let delete = json!({"op": "delete", "doc": "1.0.1.0.1", "p": {"subspace": "1", "ordinal": "1"}, "width": "1"});
    let supplied = json!({"op": "insert", "doc": "1.0.1.0.1", "values": ["a"], "attest": {"alg": "x", "sig": "00"}});
    for (session, frame) in [(&bare, &insert), (&signed, &delete), (&signed, &supplied)] {
        assert!(matches!(session.attest(&store, frame), Ok(Cow::Borrowed(as_it_stands)) if std::ptr::eq(as_it_stands, frame)), "{frame}");
    }
}
