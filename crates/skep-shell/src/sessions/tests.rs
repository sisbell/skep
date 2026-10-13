//! THE SESSION TABLE's FENCE: a session registered under a fresh reference,
//! beside the board it stands at; its END run once whichever hand meets the
//! death — a second hand answering the first's reason, two hands at once one
//! derivation, a hand that panics mid-end leaving the end to the next — a
//! principal's supplement following its standing sessions, and a key's
//! standing named by the list it stands in.

use std::io::Read;
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::sync::Condvar;
use std::thread;
use std::time::Duration;

use skep_client::dial::{DialError, Dialer, Headers, PlainHttp, Request, RequestHead, Response, StreamedResponse};
use skep_client::Origin;

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
    let (board, sessions) = (nowhere(), Sessions::new(None));
    let mut supplements = Recorded::default();
    let one = sessions.register("b-1", Arc::clone(&board), signed_open(1, "1.0.1.1", "1.0.1"), &mut supplements);
    let two = sessions.register("b-2", nowhere(), signed_open(2, "1.0.1.1", "1.0.1.1"), &mut supplements);
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
fn a_session_ends_once_and_a_second_hand_answers_the_first_reason() {
    let (board, sessions, bus) = (nowhere(), Sessions::new(None), EventBus::new());
    let rx = bus.subscribe();
    let mut supplements = Recorded::default();
    let entry = sessions.register("b-1", Arc::clone(&board), signed_open(1, "1.0.1", "1.0.1"), &mut supplements);
    let reason = sessions.end(&entry, &mut supplements, &bus);
    assert_eq!(reason["arm"], "unreachable", "{reason}");
    assert!(sessions.get(&entry.reference).is_none());
    let died: Vec<_> = rx.try_iter().collect();
    assert_eq!(died.len(), 1);
    assert_eq!((died[0].name, died[0].data["session"].as_str()), (EventName::SessionDied, Some(entry.reference.as_str())));
    assert_eq!(died[0].data["reason"], reason);
    assert_eq!(supplements.0.last().map(String::as_str), Some("narrow 1"));
    let touched = supplements.0.len();
    assert_eq!(sessions.end(&entry, &mut supplements, &bus), reason, "the second hand answers the first's reason");
    assert!(rx.try_recv().is_err(), "and emits nothing");
    assert_eq!(supplements.0.len(), touched, "and touches no supplement");
    assert!(sessions.close(&entry.reference).is_none(), "nothing is left to close");
    let closed_first = sessions.register("b-1", board, signed_open(1, "1.0.1", "1.0.1"), &mut supplements);
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
    let (board, sessions, bus) = (nowhere(), Sessions::new(None), EventBus::new());
    let mut supplements = Recorded::default();
    let first = sessions.register("b-1", Arc::clone(&board), signed_open(1, "1.0.1", "1.0.1"), &mut supplements);
    let second = sessions.register("b-1", Arc::clone(&board), signed_open(1, "1.0.1", "1.0.1"), &mut supplements);
    sessions.register("b-2", nowhere(), signed_open(1, "1.0.1", "1.0.1"), &mut supplements);
    supplements.0.clear();
    sessions.end(&first, &mut supplements, &bus);
    assert_eq!(supplements.0, [format!("widen {}", second.reference)], "the session standing at the board takes the supplement");
    sessions.end(&second, &mut supplements, &bus);
    assert_eq!(supplements.0.last().map(String::as_str), Some("narrow 1"), "none stands at b-1, and the session at b-2 takes nothing");
    let third = sessions.register("b-1", Arc::clone(&board), signed_open(1, "1.0.1", "1.0.1"), &mut supplements);
    let fourth = sessions.register("b-1", board, signed_open(1, "1.0.1", "1.0.1"), &mut supplements);
    supplements.0.clear();
    assert!(sessions.close(&third.reference).is_some());
    sessions.release("b-1", 1, &mut supplements);
    assert_eq!(supplements.0, [format!("widen {}", fourth.reference)]);
    assert!(sessions.close(&fourth.reference).is_some());
    sessions.release("b-1", 1, &mut supplements);
    assert_eq!(supplements.0.last().map(String::as_str), Some("narrow 1"));
}

/// Two hands meet one death at once: the second waits on the entry's
/// `OnceLock` while the first derives the reason, then answers that reason —
/// one derivation (one dial), one event, one supplement touched.
#[test]
fn a_second_hand_waits_for_the_reason_the_first_derives() {
    let (entered, at_the_dial) = channel();
    let gated = Arc::new(Gated { calls: AtomicUsize::new(0), entered: Mutex::new(entered), gate: (Mutex::new(false), Condvar::new()) });
    let board = Arc::new(Board::new(Origin::parse("http://127.0.0.1:9").unwrap(), Arc::clone(&gated)));
    let (sessions, bus) = (Sessions::new(None), EventBus::new());
    let rx = bus.subscribe();
    let entry = sessions.register("b-1", board, signed_open(1, "1.0.1", "1.0.1"), &mut Recorded::default());
    let (mut first_hand, mut second_hand) = (Recorded::default(), Recorded::default());
    let (first, second) = thread::scope(|s| {
        let first = s.spawn(|| sessions.end(&entry, &mut first_hand, &bus));
        at_the_dial.recv().unwrap();
        let second = s.spawn(|| sessions.end(&entry, &mut second_hand, &bus));
        thread::sleep(Duration::from_millis(50));
        *gated.gate.0.lock().unwrap() = true;
        gated.gate.1.notify_all();
        (first.join().unwrap(), second.join().unwrap())
    });
    assert_eq!(first["arm"], "unreachable", "{first}");
    assert_eq!(second, first);
    assert_eq!(gated.calls.load(Ordering::SeqCst), 1, "the reason was derived once");
    assert_eq!(rx.try_iter().filter(|e| e.name == EventName::SessionDied).count(), 1);
    assert_eq!((first_hand.0, second_hand.0), (vec!["narrow 1".to_string()], vec![]));
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

/// A hand that panics mid-end ends nothing, and the next hand derives
/// the reason and says the one `session-died`.
#[test]
fn a_hand_that_panics_mid_end_leaves_the_end_to_the_next() {
    let board = Arc::new(Board::new(Origin::parse("http://127.0.0.1:9").unwrap(), PanicsOnce(AtomicUsize::new(0))));
    let (sessions, bus) = (Sessions::new(None), EventBus::new());
    let rx = bus.subscribe();
    let entry = sessions.register("b-1", board, signed_open(1, "1.0.1", "1.0.1"), &mut Recorded::default());
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| sessions.end(&entry, &mut Recorded::default(), &bus)));
    assert!(panicked.is_err() && rx.try_recv().is_err(), "the first hand ended nothing");
    assert_eq!(sessions.end(&entry, &mut Recorded::default(), &bus)["arm"], "unreachable");
    assert_eq!(rx.try_iter().filter(|e| e.name == EventName::SessionDied).count(), 1);
}

/// THE KEY's STANDING names a key face by the list the key stands in — the
/// one rule `session`'s and `bind`'s refusals share: an enrolled key
/// answers `Ok`, and no read is made; a retired key is `retired`, its face
/// composed without the records a board that does not answer withholds; a
/// key in neither list is `not_enrolled` (the mutants that name every face
/// one name, or one list's face the other's).
#[test]
fn a_keys_standing_is_named_by_the_list_it_stands_in() {
    let public = skep_client::sign::signer_from_seed(&[7; 32]).public_key().clone();
    let fingerprint = Fingerprint::of(&public);
    let key = KeyFacts { path: std::path::PathBuf::from("/nowhere/key"), fingerprint, public: public.clone(), label: None, anchor: false };
    let walk = |set: skep_client::KeySet| Walk { account: "1.0.1".into(), set_account: "1.0.1".into(), set, visited: vec!["1.0.1".into()] };
    let enrolled = skep_client::KeySet { as_of: 1, enrolled: vec![skep_client::board::EnrolledKey { fingerprint, key: public, anchor: false }], retired: Vec::new() };
    let retired = skep_client::KeySet { as_of: 1, enrolled: Vec::new(), retired: vec![skep_client::board::RetiredKey { fingerprint, anchor: false }] };
    let board = nowhere();
    assert!(key_standing(&board, &walk(enrolled), &key, Site::Session).is_ok(), "an enrolled key stands");
    let refused = key_standing(&board, &walk(retired), &key, Site::Session).unwrap_err();
    assert_eq!((refused.name(), refused.to_value()["kind"].as_str()), ("retired", Some("halt")), "{refused}");
    let refused = key_standing(&board, &walk(skep_client::KeySet::default()), &key, Site::Tail).unwrap_err();
    assert_eq!((refused.name(), refused.to_value()["kind"].as_str()), ("not_enrolled", Some("halt")), "{refused}");
}
