//! THE SESSION TABLE and A SESSION's END (`client.md` §4b.1's `session`
//! row; §4b.2's `session-died`). The table holds every session this shell
//! opened for the page — the token, which never leaves this process, under
//! the opaque reference the page holds (`refs`) — and the FACTS a death's
//! arm is derived from: the principal, the account, the kind (bare, or
//! signed content-scoped), the key that opened it and the account whose
//! set it authenticated against. The two openings are here too, so the
//! shell's `session` call and the restart arm's silent re-open (AUTH-5.31)
//! share one: the BARE bind as the claimant on the permissive board, and
//! the SIGNED content-scoped handshake behind AUTH-5.65's pre-check, each
//! refusal under the armed name the row spells.
//!
//! THE END ([`Sessions::end`]): a death signal is met by two hands — the
//! shell, when a call's token answers `Skepd-Session: closed`, and the
//! board's feed thread, when its consumer's read or a drafts page does —
//! and both run the one sequence here, so the arm is derived once, the
//! restart arm's re-open is registered whichever hand met it, and one
//! `session-died` goes out. The entry's own lock is the gate: the hand that
//! takes it first ends the session, a hand that comes second answers the
//! first's arm. An entry leaves the table by that sequence or by a close —
//! the page's own, or the shell's stop ([`Sessions::close`]) — and no
//! other way.
//!
//! THE ARM (`session-died(session, reason)`, "ONE ARM PER E2 TRIGGER,
//! derived by the shell from public reads"): a bare session on a board now
//! ENFORCING died at the FLIP; a signed session whose key now stands in
//! the retired list died at a RETIREMENT — AUTH-5.28's own-hand arm where
//! this store's key wrote it, AUTH-5.77's where another did, the hand named
//! by its position and label off the admitted record read; a session
//! opened BY REFERENCE whose acted-as account now holds a set of its own
//! died at a GENESIS (the SEEDED arm); else the shell re-opens where it
//! holds a key — `403 prefix_blocked` is the BLOCK's arm, a session that
//! opens is the RESTART arm re-opened silently, and a board that does not
//! answer is said so. The page's own `close` is its own arm.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use serde_json::{json, Value};
use skep_client::board::{KeySetAnswer, Opened, Scope, SessionBody, Token};
use skep_client::ceremony::handshake::{handshake_prechecked, Site};
use skep_client::derive::records::{credential_records, Hand};
use skep_client::derive::{origin_arm, precheck, KeyDiagnosis, Mode};
use skep_client::sheet::render_inert;
use skep_client::store::{FileStore, KeySelector, KeyStore, Purpose, StoreError};
use skep_client::Board;
use skep_identity::Fingerprint;

use crate::events::{EventBus, SESSION_DIED};
use crate::refs::session_name;
use crate::refusal::{Name, Refusal};

/// A session's kind: the bare bind, or the signed content-scoped handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Bare,
    Content,
}

impl Kind {
    /// The kind as the bridge spells it.
    #[cfg(test)]
    pub fn name(self) -> &'static str {
        match self {
            Kind::Bare => "bare",
            Kind::Content => "content",
        }
    }
}

/// The facts a session was opened with — what its death's arm reads.
#[derive(Debug, Clone)]
pub struct Facts {
    pub principal: u64,
    /// `principal_prefix(principal)`, where the board answered one.
    pub account: Option<String>,
    pub kind: Kind,
    /// The key that opened a signed session.
    pub fingerprint: Option<Fingerprint>,
    /// The account whose set the signed session authenticated against —
    /// the account itself, or the nearest above it that holds a set.
    pub set_account: Option<String>,
}

impl Facts {
    /// Whether the session opened BY REFERENCE — against a set above its
    /// own account.
    pub fn by_reference(&self) -> bool {
        matches!((&self.account, &self.set_account), (Some(a), Some(s)) if a != s)
    }
}

/// One session this shell holds for the page.
#[derive(Debug)]
pub struct SessionEntry {
    /// The reference the page holds.
    pub reference: String,
    /// The board reference it stands at.
    pub board: String,
    /// The token — this process's alone.
    pub token: Token,
    pub facts: Facts,
    /// The arm its end carried, once a hand has ended it — held locked
    /// while a hand derives it, so a second hand waits for that arm.
    end: Mutex<Option<Value>>,
}

/// A board's drafts supplements as the hand that registers or ends a
/// session reaches them (`client.md` §4e.3's WIDEN and NARROW): the shell
/// through the board's feed handle, the feed's thread directly.
pub trait Supplements {
    /// `entry`'s supplement mounted under its token — a principal's
    /// mounted supplement taking the new token.
    fn widen(&mut self, entry: &Arc<SessionEntry>);
    /// `principal`'s supplement saved and unmounted.
    fn narrow(&mut self, principal: u64);
}

/// The table, by reference.
#[derive(Debug, Default)]
pub struct Sessions {
    map: Mutex<HashMap<String, Arc<SessionEntry>>>,
}

impl Sessions {
    /// No session.
    pub fn new() -> Sessions {
        Sessions::default()
    }

    /// The session `reference` names, where this shell holds one.
    pub fn get(&self, reference: &str) -> Option<Arc<SessionEntry>> {
        self.map.lock().expect("the sessions' lock").get(reference).cloned()
    }

    /// Every session at `board`, in no order.
    pub fn on_board(&self, board: &str) -> Vec<Arc<SessionEntry>> {
        self.map.lock().expect("the sessions' lock").values().filter(|e| e.board == board).cloned().collect()
    }

    /// Every session, in no order.
    pub fn all(&self) -> Vec<Arc<SessionEntry>> {
        self.map.lock().expect("the sessions' lock").values().cloned().collect()
    }

    /// How many sessions stand.
    pub fn len(&self) -> usize {
        self.map.lock().expect("the sessions' lock").len()
    }

    /// A session opened at `board`, REGISTERED: entered under a fresh
    /// reference — never the token's — and its drafts supplement widened;
    /// the entry.
    pub fn register(&self, board: &str, open: Open, supplements: &mut dyn Supplements) -> Arc<SessionEntry> {
        let entry = self.enter(board, open);
        supplements.widen(&entry);
        entry
    }

    /// THE END of a session whose token met the death signal, run by
    /// whichever hand met it (the module doc). Under the entry's lock the
    /// session leaves the table and its arm is derived from public reads;
    /// on the restart arm the re-opened session enters under a fresh
    /// reference, named in the arm as `session`. Then `session-died` goes
    /// out and the drafts supplement is widened under the re-opened token,
    /// or narrowed — NARROW "at `session-died` in every arm but the shell's
    /// own restart" (`client.md` §4e.3). A hand that finds the arm already
    /// derived answers it and does nothing else. The arm.
    pub fn end(&self, entry: &SessionEntry, board: &Board, store: Option<&FileStore>, supplements: &mut dyn Supplements, bus: &EventBus) -> Value {
        // A hand that panicked mid-end left the lock poisoned and the arm
        // unset: the next hand takes the end over rather than wait on it.
        let mut end = entry.end.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(arm) = &*end {
            return arm.clone();
        }
        self.remove(&entry.reference);
        let death = reason(board, store, entry);
        let mut arm = death.reason;
        let reopened = death.reopened.map(|open| self.enter(&entry.board, open));
        if let Some(r) = &reopened {
            arm["session"] = Value::from(r.reference.as_str());
        }
        *end = Some(arm.clone());
        drop(end);
        bus.emit(SESSION_DIED, json!({"session": entry.reference, "reason": arm}));
        match &reopened {
            Some(r) => supplements.widen(r),
            None => supplements.narrow(entry.facts.principal),
        }
        arm
    }

    /// A CLOSE — the page's own, or the shell's stop: the session out of
    /// the table, its end settled as the `closed` arm under the entry's
    /// lock; the entry, or `None` where this shell holds no session under
    /// `reference` any more — a death met first, or a close before.
    pub fn close(&self, reference: &str) -> Option<Arc<SessionEntry>> {
        let entry = self.get(reference)?;
        {
            let mut end = entry.end.lock().unwrap_or_else(PoisonError::into_inner);
            if end.is_some() {
                return None;
            }
            self.remove(reference);
            *end = Some(closed());
        }
        Some(entry)
    }

    fn enter(&self, board: &str, open: Open) -> Arc<SessionEntry> {
        let entry = Arc::new(SessionEntry { reference: session_name(), board: board.to_string(), token: open.token, facts: open.facts, end: Mutex::new(None) });
        self.map.lock().expect("the sessions' lock").insert(entry.reference.clone(), Arc::clone(&entry));
        entry
    }

    fn remove(&self, reference: &str) -> Option<Arc<SessionEntry>> {
        self.map.lock().expect("the sessions' lock").remove(reference)
    }
}

/// A session opened: the token and its facts.
pub struct Open {
    pub token: Token,
    pub facts: Facts,
}

/// THE BARE BIND as `principal` (`client.md` §4b.4; AUTH-4.26): honoured on
/// the unclaimed and the CLAIMED-PERMISSIVE board from this loopback peer,
/// which sends no `Origin`; refused on ENFORCING with the board's one 401,
/// carried verbatim.
pub fn open_bare(board: &Board, principal: u64) -> Result<Open, Refusal> {
    let token = match board.session_open(SessionBody::Bare { principal }).map_err(Refusal::of)? {
        Opened::Token(t) => t,
        Opened::Rejected => {
            return Err(Refusal::Board(skep_client::Refused {
                status: 401,
                code: "session_rejected".into(),
                detail: None,
                op: None,
                body: json!({"error": "session_rejected"}),
            }))
        }
        Opened::Blocked { record } => return Err(Refusal::Blocked(skep_client::Blocked { record, named_by: board.dialed().as_str().to_string(), ground: None })),
    };
    let account = board.principal_prefix(principal).map_err(Refusal::of)?;
    Ok(Open { token, facts: Facts { principal, account, kind: Kind::Bare, fingerprint: None, set_account: None } })
}

/// THE SIGNED CONTENT-SCOPED HANDSHAKE as `principal` with the store's key
/// for (this board, the principal) — §3.5's lookup — behind AUTH-5.65's
/// pre-check, each refusal under the armed name the `session` row spells.
pub fn open_signed(board: &Board, store: &FileStore, principal: u64) -> Result<Open, Refusal> {
    let health = board.health().map_err(Refusal::of)?;
    let key = match store.select(&KeySelector::Board { origin: board.dialed(), principal: Some(principal) }, Purpose::Sign) {
        Ok(key) => key,
        Err(StoreError::NoSelection { keys }) => {
            return Err(Refusal::of_named(Name::NO_KEY, skep_client::store::arm4_face(store, &keys, Mode::of(&health))));
        }
        Err(e) => return Err(Refusal::of_named(Name::STORE_UNREADABLE, e.into())),
    };
    let signer = store.signer(&KeySelector::Path(&key.path)).map_err(|e| Refusal::of_named(Name::STORE_UNREADABLE, e.into()))?;
    if let Err(h) = origin_arm(board.signed(), &health) {
        return Err(Refusal::of_named(Name::ORIGIN_STATE, h));
    }
    let pre = precheck(board, principal, &key.fingerprint).map_err(|h| Refusal::of_named(Name::NOT_REGISTERED, h))?;
    let own = [(key.fingerprint, key.public.clone())];
    match pre.diagnosis {
        KeyDiagnosis::Enrolled { .. } => {}
        KeyDiagnosis::Retired { .. } => {
            let h = skep_client::ceremony::handshake::key_face(board, &pre.walk, &key.fingerprint, &own, Site::Session).expect_err("a retired key is faced");
            return Err(Refusal::of_named(Name::RETIRED, h));
        }
        KeyDiagnosis::Neither => {
            let h = skep_client::ceremony::handshake::key_face(board, &pre.walk, &key.fingerprint, &own, Site::Session).expect_err("a key in neither list is faced");
            return Err(Refusal::of_named(Name::NOT_ENROLLED, h));
        }
    }
    let session = handshake_prechecked(board, Scope::Content, &*signer, &pre, Site::Session).map_err(|h| Refusal::of_named(Name::BUSY, h))?;
    let facts = Facts {
        principal,
        account: Some(session.account().to_string()),
        kind: Kind::Content,
        fingerprint: Some(session.fingerprint()),
        set_account: Some(pre.walk.set_account.clone()),
    };
    Ok(Open { token: session.into_token(), facts })
}

/// Why a session died, and — on the restart arm under a key this store
/// holds — the session re-opened silently in its place.
struct Death {
    reason: Value,
    reopened: Option<Open>,
}

/// The page's own `close`: its own arm.
pub fn closed() -> Value {
    json!({"arm": "closed"})
}

/// THE ARM for a death signal met on `entry`'s token (the module doc), the
/// reads made now; `store` where the shell holds a key store for the
/// restart arm's re-open. Run inside [`Sessions::end`] alone, under the
/// entry's lock: the re-open it makes is a session no other hand registers.
fn reason(board: &Board, store: Option<&FileStore>, entry: &SessionEntry) -> Death {
    let none = |reason: Value| Death { reason, reopened: None };
    let health = match board.health() {
        Ok(h) => h,
        Err(h) => return none(json!({"arm": "unreachable", "text": h.to_string()})),
    };
    let mode = Mode::of(&health);
    let facts = &entry.facts;
    if facts.kind == Kind::Bare {
        if mode == Mode::Enforcing {
            return none(json!({"arm": "mode", "mode": mode.name()}));
        }
        return none(json!({"arm": "restart", "reopened": false}));
    }
    // A signed session: the retirement, read off the set it authenticated
    // against and the admitted record read.
    if let (Some(fp), Some(set_account)) = (facts.fingerprint, facts.set_account.as_deref()) {
        if let Ok(KeySetAnswer::Set(set)) = board.key_set(set_account) {
            if set.retired(&fp).is_some() {
                let own: Vec<(Fingerprint, skep_identity::PublicKey)> =
                    store.and_then(|s| s.device_keys().ok()).into_iter().flatten().map(|k| (k.fingerprint, k.public)).collect();
                let records = credential_records(board, set_account, &own).ok();
                let retirement = records.as_ref().and_then(|r| r.retirement_of(&fp));
                let (hand, position, label, own_hand) = match retirement.map(|rec| (&rec.hand, rec.position)) {
                    Some((Hand::Key(hand), position)) => {
                        let label = records.as_ref().and_then(|r| r.label_of(hand)).map(|l| render_inert(&l));
                        let own_hand = own.iter().any(|(f, _)| f == hand);
                        (Some(hand.to_string()), position, label, own_hand)
                    }
                    Some((Hand::Bare, position)) => (Some("bare".to_string()), position, None, false),
                    _ => (None, None, None, false),
                };
                return none(json!({
                    "arm": "retired",
                    "fingerprint": fp.to_string(),
                    "own": own_hand,
                    "hand": hand,
                    "position": position,
                    "label": label,
                }));
            }
        }
        // The seeded arm: a session by reference whose acted-as account now
        // holds a set of its own.
        if facts.by_reference() {
            if let Some(account) = facts.account.as_deref() {
                if let Ok(KeySetAnswer::Set(set)) = board.key_set(account) {
                    if !set.is_empty() {
                        let writer = set.enrolled.first().map(|e| e.fingerprint.to_string());
                        return none(json!({"arm": "seeded", "account": account, "as_of": set.as_of, "writer": writer}));
                    }
                }
            }
        }
    }
    // The restart arm, or the block met at the re-open.
    let Some(store) = store else { return none(json!({"arm": "restart", "reopened": false})) };
    match open_signed(board, store, facts.principal) {
        Ok(open) => Death { reason: json!({"arm": "restart", "reopened": true}), reopened: Some(open) },
        Err(Refusal::Blocked(b)) => none(json!({"arm": "blocked", "record": b.record, "ground": b.ground})),
        Err(other) => none(json!({"arm": "restart", "reopened": false, "refused": other.name()})),
    }
}

#[cfg(test)]
mod tests {
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
        fn widen(&mut self, entry: &Arc<SessionEntry>) {
            self.0.push(format!("widen {}", entry.reference));
        }

        fn narrow(&mut self, principal: u64) {
            self.0.push(format!("narrow {principal}"));
        }
    }

    fn open(principal: u64, account: &str, set_account: &str) -> Open {
        let facts = Facts { principal, account: Some(account.into()), kind: Kind::Content, fingerprint: None, set_account: Some(set_account.into()) };
        Open { token: Token::parse(&"9f".repeat(16)).unwrap(), facts }
    }

    /// A board nothing answers at: a port bound and let go.
    fn nowhere() -> Board {
        let port = TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port();
        Board::new(Origin::parse(&format!("http://127.0.0.1:{port}")).unwrap(), PlainHttp::new())
    }

    /// A dialer that holds each exchange until the test opens it, counting
    /// them, then answers that the board did not answer.
    struct Held {
        calls: AtomicUsize,
        entered: Mutex<Sender<()>>,
        open: (Mutex<bool>, Condvar),
    }

    impl Dialer for Held {
        fn exchange(&self, _: &Origin, _: &Request) -> Result<Response, DialError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let _ = self.entered.lock().unwrap().send(());
            let (open, opened) = &self.open;
            let _held = opened.wait_while(open.lock().unwrap(), |open| !*open).unwrap();
            Err(DialError::Connect("held, then let go".into()))
        }

        fn stream(&self, _: &Origin, _: &RequestHead, _: &mut dyn Read, _: &mut dyn FnMut(&Headers)) -> Result<StreamedResponse, DialError> {
            Err(DialError::Connect("no stream here".into()))
        }
    }

    /// The table: a session registered under a fresh reference and its
    /// supplement widened, listed by board, found by reference; a session
    /// by reference is one whose set is above its account.
    #[test]
    fn the_table_registers_sessions_under_fresh_references() {
        let sessions = Sessions::new();
        let mut supplements = Recorded::default();
        let one = sessions.register("b-1", open(1, "1.0.1.1", "1.0.1"), &mut supplements);
        let two = sessions.register("b-2", open(2, "1.0.1.1", "1.0.1.1"), &mut supplements);
        assert!(one.reference.starts_with("s-") && one.reference != two.reference);
        assert_eq!(supplements.0, [format!("widen {}", one.reference), format!("widen {}", two.reference)]);
        assert_eq!(sessions.len(), 2);
        assert_eq!(sessions.on_board("b-1").len(), 1);
        assert!(one.facts.by_reference());
        assert!(!sessions.get(&two.reference).unwrap().facts.by_reference());
        assert_eq!(Kind::Bare.name(), "bare");
    }

    /// THE END, ONCE: the first `end` takes the session out of the table,
    /// derives the arm (the board's that does not answer), emits one
    /// `session-died` and narrows; a second `end` of the same death answers
    /// the same arm and does nothing else; nothing is left to `close`. A
    /// session closed first is closed once, and a death met after the close
    /// answers the page's own arm.
    #[test]
    fn a_session_ends_once_and_a_second_hand_answers_the_first_arm() {
        let (board, sessions, bus) = (nowhere(), Sessions::new(), EventBus::new());
        let rx = bus.subscribe();
        let mut supplements = Recorded::default();
        let entry = sessions.register("b-1", open(1, "1.0.1", "1.0.1"), &mut supplements);
        let arm = sessions.end(&entry, &board, None, &mut supplements, &bus);
        assert_eq!(arm["arm"], "unreachable", "{arm}");
        assert!(sessions.get(&entry.reference).is_none());
        let died: Vec<_> = rx.try_iter().collect();
        assert_eq!(died.len(), 1);
        assert_eq!((died[0].name, died[0].data["session"].as_str()), ("session-died", Some(entry.reference.as_str())));
        assert_eq!(died[0].data["reason"], arm);
        assert_eq!(supplements.0.last().map(String::as_str), Some("narrow 1"));
        let touched = supplements.0.len();
        assert_eq!(sessions.end(&entry, &board, None, &mut supplements, &bus), arm, "the second hand answers the first's arm");
        assert!(rx.try_recv().is_err(), "and emits nothing");
        assert_eq!(supplements.0.len(), touched, "and touches no supplement");
        assert!(sessions.close(&entry.reference).is_none(), "nothing is left to close");
        let closed = sessions.register("b-1", open(1, "1.0.1", "1.0.1"), &mut supplements);
        assert!(sessions.close(&closed.reference).is_some());
        assert!(sessions.close(&closed.reference).is_none(), "closed once");
        assert_eq!(sessions.end(&closed, &board, None, &mut supplements, &bus), super::closed(), "a death met after the close answers its arm");
        assert!(rx.try_recv().is_err());
    }

    /// Two hands meet one death at once: the second waits on the entry's
    /// lock while the first derives the arm, then answers that arm — one
    /// derivation (one dial), one event, one supplement touched.
    #[test]
    fn a_second_hand_waits_for_the_arm_the_first_derives() {
        let (entered, at_the_dial) = channel();
        let held = Arc::new(Held { calls: AtomicUsize::new(0), entered: Mutex::new(entered), open: (Mutex::new(false), Condvar::new()) });
        let board = Board::new(Origin::parse("http://127.0.0.1:9").unwrap(), Arc::clone(&held));
        let (sessions, bus) = (Sessions::new(), EventBus::new());
        let rx = bus.subscribe();
        let entry = sessions.register("b-1", open(1, "1.0.1", "1.0.1"), &mut Recorded::default());
        let (mut first_hand, mut second_hand) = (Recorded::default(), Recorded::default());
        let (first, second) = thread::scope(|s| {
            let first = s.spawn(|| sessions.end(&entry, &board, None, &mut first_hand, &bus));
            at_the_dial.recv().unwrap();
            let second = s.spawn(|| sessions.end(&entry, &board, None, &mut second_hand, &bus));
            thread::sleep(Duration::from_millis(50));
            *held.open.0.lock().unwrap() = true;
            held.open.1.notify_all();
            (first.join().unwrap(), second.join().unwrap())
        });
        assert_eq!(first["arm"], "unreachable", "{first}");
        assert_eq!(second, first);
        assert_eq!(held.calls.load(Ordering::SeqCst), 1, "the arm was derived once");
        assert_eq!(rx.try_iter().filter(|e| e.name == "session-died").count(), 1);
        assert_eq!((first_hand.0, second_hand.0), (vec!["narrow 1".to_string()], vec![]));
    }
}
