//! THE SESSION TABLE and A SESSION's END (`client.md` §4b.1's `session`
//! row; §4b.2's `session-died`). The table holds every session this shell
//! opened for the page — the token, which never leaves this process, under
//! the opaque reference the page holds (`refs`) — and the FACTS a death's
//! arm is derived from: the principal, the account, and the kind — bare,
//! or signed content-scoped with the key that opened it and the account
//! whose set it authenticated against. The two openings are here too, so the
//! shell's `session` call and the restart arm's silent re-open (AUTH-5.31)
//! share one: the BARE bind as the claimant on the permissive board, and
//! the SIGNED content-scoped handshake behind AUTH-5.65's pre-check, each
//! refusal under the armed name the row spells. A write under a session
//! that holds a key carries the attest that key signs
//! ([`SessionEntry::attest`]), whichever hand sends it — a call's `op`, or
//! the held-burst resend's.
//!
//! THE END ([`Sessions::end`]): a death signal is met by two hands — the
//! shell, when a call's token answers `Skepd-Session: closed`, and the
//! board's feed thread, when its consumer's read or a drafts page does —
//! and both run the one sequence here, so the arm is derived once, the
//! restart arm's re-open is registered whichever hand met it, and one
//! `session-died` goes out. The entry's `OnceLock` is the gate: the hand
//! whose initializer runs ends the session, a hand that comes while it runs
//! waits and answers that arm, and a hand that panics mid-end leaves the
//! cell unset for the next to take the end over. An entry leaves the table
//! by that sequence or by a close —
//! the page's own, or the shell's stop ([`Sessions::close`]) — and no
//! other way.
//!
//! ONE SUPPLEMENT PER PRINCIPAL ([`Sessions::release`]): the consumer holds
//! one drafts supplement per (board, principal), and two tabs open two
//! sessions of one principal; a session that leaves the table hands the
//! supplement to another session of its principal standing at its board,
//! and only where none stands is it narrowed.
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
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

use serde_json::{json, Value};
use skep_client::board::{KeySetAnswer, Opened, Scope, SessionBody, Token};
use skep_client::ceremony::handshake::{handshake_prechecked, Site};
use skep_client::derive::records::{credential_records, Hand};
use skep_client::derive::{origin_arm, precheck, KeyDiagnosis, Mode};
use skep_client::sheet::render_inert;
use skep_client::sign::Signer;
use skep_client::store::{FileStore, KeyFacts, KeySelector, KeyStore, Purpose, StoreError};
use skep_client::{Board, Origin};
use skep_identity::Fingerprint;

use crate::attest::{wants_attest, Composer, Unattested};
use crate::events::{EventBus, EventName};
use crate::refs::session_reference;
use crate::refusal::{Name, Refusal};

/// A session's kind: the bare bind, or the signed content-scoped handshake —
/// the key that opened it, and the account whose set it authenticated
/// against (the account itself, or the nearest above it that holds one).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    Bare,
    Signed { fingerprint: Fingerprint, set_account: String },
}

/// The facts a session was opened with — what its death's arm reads.
#[derive(Debug, Clone)]
pub struct Facts {
    pub principal: u64,
    /// `principal_prefix(principal)`, where the board answered one.
    pub account: Option<String>,
    pub kind: Kind,
}

impl Facts {
    /// Whether the session opened BY REFERENCE — a signed session whose set
    /// stands above its own account.
    pub fn by_reference(&self) -> bool {
        matches!((&self.account, &self.kind), (Some(account), Kind::Signed { set_account, .. }) if account != set_account)
    }
}

/// One session this shell holds for the page.
#[derive(Debug)]
pub struct SessionEntry {
    /// The reference the page holds.
    pub reference: String,
    /// The reference of the board it stands at.
    pub board_reference: String,
    /// The token — this process's alone.
    pub token: Token,
    pub facts: Facts,
    /// The board's log position read BEFORE the session opened: a held
    /// burst's `base` on a document no acked write of this session names
    /// (§3c.2), so the resend's read sees every row that could have moved it.
    pub opened_at: u64,
    /// The arm its end carried, set once by the hand that ended it — a
    /// second hand waits while the first derives it, then answers it.
    end: OnceLock<Value>,
}

impl SessionEntry {
    /// THE ATTEST a write under this session carries (`attest`'s rule):
    /// composed and signed by the key that opened the session, where the
    /// session holds one and [`wants_attest`] admits the frame — the one
    /// place the composer's precondition is discharged; the frame as it
    /// stands otherwise, and where the board has no `H.1` to sign over (the
    /// board judges that write). Refused `attest_not_composed` where the
    /// composer could not sign — nothing is then to be sent — and with the
    /// board's refusal, or `unreachable`, where a read it needed was refused
    /// or not answered; [`Unattested::Closed`] where a read it made met the
    /// session's death signal, whose end is the caller's to run.
    pub fn attest(&self, board: &Board, store: &FileStore, frame: &mut Value) -> Result<(), Unattested> {
        let Kind::Signed { fingerprint: fp, .. } = &self.facts.kind else { return Ok(()) };
        if !wants_attest(frame) {
            return Ok(());
        }
        let Some(term) = board.board_term().map_err(Refusal::from)? else { return Ok(()) };
        let signer = signer(store, &store.key_path(fp))?;
        let account = self.facts.account.as_deref().ok_or_else(|| Refusal::shell(Name::NO_ACCOUNT, json!({})))?;
        let composer = Composer { board, token: &self.token, signer: &*signer, account, term };
        composer.attach(frame)
    }
}

/// A board's drafts supplements as the hand that registers or ends a
/// session reaches them (`client.md` §4e.3's WIDEN and NARROW): the shell
/// through the board's feed handle, the feed's thread directly.
pub trait Supplements {
    /// `session`'s supplement mounted under its token — a principal's
    /// mounted supplement taking the new token.
    fn widen(&mut self, session: &Arc<SessionEntry>);
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

    /// Every session at the board `board_reference` names, in no order.
    pub fn on_board(&self, board_reference: &str) -> Vec<Arc<SessionEntry>> {
        self.map.lock().expect("the sessions' lock").values().filter(|e| e.board_reference == board_reference).cloned().collect()
    }

    /// Every session, in no order.
    pub fn all(&self) -> Vec<Arc<SessionEntry>> {
        self.map.lock().expect("the sessions' lock").values().cloned().collect()
    }

    /// How many sessions stand.
    pub fn len(&self) -> usize {
        self.map.lock().expect("the sessions' lock").len()
    }

    /// A session opened at the board `board_reference` names, REGISTERED:
    /// entered under a fresh reference — never the token's — and its drafts
    /// supplement widened; the entry.
    pub fn register(&self, board_reference: &str, open: Open, supplements: &mut dyn Supplements) -> Arc<SessionEntry> {
        let entry = self.enter(board_reference, open);
        supplements.widen(&entry);
        entry
    }

    /// THE END of a session whose token met the death signal, run by
    /// whichever hand met it (the module doc). In the entry's `OnceLock` the
    /// session leaves the table and its arm is derived from public reads;
    /// on the restart arm the re-opened session enters under a fresh
    /// reference, named in the arm as `session`. Then `session-died` goes
    /// out and the drafts supplement is widened under the re-opened token,
    /// or RELEASED ([`Sessions::release`]) — NARROW "at `session-died` in
    /// every arm but the shell's own restart" (`client.md` §4e.3) where no
    /// other session of the principal stands at the board, the supplement
    /// handed to one that does. A hand that finds the arm already derived
    /// answers it and does nothing else. The arm. PRECONDITION, the
    /// caller's: `board` is the board `entry` stands at, and `store` the
    /// signed mode's key store — `None` under the bare mode, whose sessions
    /// no end re-opens.
    pub fn end(&self, entry: &SessionEntry, board: &Board, store: Option<&FileStore>, supplements: &mut dyn Supplements, bus: &EventBus) -> Value {
        let (mut ended_here, mut reopened) = (false, None);
        let arm = entry
            .end
            .get_or_init(|| {
                ended_here = true;
                self.remove(&entry.reference);
                let death = derive_death(board, store, entry);
                let mut arm = death.reason;
                reopened = death.reopened.map(|open| self.enter(&entry.board_reference, open));
                if let Some(r) = &reopened {
                    arm["session"] = Value::from(r.reference.as_str());
                }
                arm
            })
            .clone();
        if !ended_here {
            return arm;
        }
        bus.emit(EventName::SessionDied, json!({"session": entry.reference, "reason": arm}));
        match &reopened {
            Some(r) => supplements.widen(r),
            None => self.release(&entry.board_reference, entry.facts.principal, supplements),
        }
        arm
    }

    /// A principal's supplement at the board `board_reference` names, given
    /// up by a session that has left the table: the consumer holds ONE
    /// supplement per principal, so it is handed to another session of the
    /// principal standing there — that session's token widened in — and
    /// narrowed (`client.md` §4e.3's NARROW) where none stands.
    pub fn release(&self, board_reference: &str, principal: u64, supplements: &mut dyn Supplements) {
        match self.on_board(board_reference).into_iter().find(|s| s.facts.principal == principal) {
            Some(standing) => supplements.widen(&standing),
            None => supplements.narrow(principal),
        }
    }

    /// A CLOSE — the page's own, or the shell's stop: the session's end
    /// settled as the `closed` arm — waiting, as a second hand's `end` does,
    /// for a hand deriving another — and the session out of the table; the
    /// entry, or `None` where this shell holds no session under `reference`
    /// any more — a death met first, or a close before.
    pub fn close(&self, reference: &str) -> Option<Arc<SessionEntry>> {
        let entry = self.get(reference)?;
        entry.end.set(closed()).ok()?;
        self.remove(reference);
        Some(entry)
    }

    fn enter(&self, board_reference: &str, open: Open) -> Arc<SessionEntry> {
        let entry = Arc::new(SessionEntry { reference: session_reference(), board_reference: board_reference.to_string(), token: open.token, facts: open.facts, opened_at: open.opened_at, end: OnceLock::new() });
        self.map.lock().expect("the sessions' lock").insert(entry.reference.clone(), Arc::clone(&entry));
        entry
    }

    fn remove(&self, reference: &str) -> Option<Arc<SessionEntry>> {
        self.map.lock().expect("the sessions' lock").remove(reference)
    }
}

/// A session opened: the token, its facts, and the board's log position
/// read before the open ([`SessionEntry::opened_at`]).
pub struct Open {
    pub token: Token,
    pub facts: Facts,
    pub opened_at: u64,
}

/// THE BARE BIND as `principal` (`client.md` §4b.4; AUTH-4.26): honoured on
/// the unclaimed and the CLAIMED-PERMISSIVE board from this loopback peer,
/// which sends no `Origin`; refused on ENFORCING with the board's one 401,
/// carried verbatim. The board's position is read first, so a row landing
/// between that read and the open is one a resend's read sees, never one it
/// skips.
pub fn open_bare(board: &Board, principal: u64) -> Result<Open, Refusal> {
    let opened_at = board.health()?.log_position();
    let token = match board.session_open(SessionBody::Bare { principal })? {
        Opened::Token(t) => t,
        Opened::Rejected => return Err(Refusal::board(401, json!({"error": "session_rejected"}))),
        Opened::Blocked { record } => return Err(Refusal::Blocked(skep_client::Blocked { record, named_by: board.dialed().as_str().to_string(), ground: None })),
    };
    let account = board.principal_prefix(principal)?;
    Ok(Open { token, facts: Facts { principal, account, kind: Kind::Bare }, opened_at })
}

/// THE STORE's KEY for (`origin`, `principal`) to sign with — §3.5's
/// lookup — under the armed names every row that signs spells: `no_key`
/// under arm 4's face where the store selects none (`mode` read for that
/// face alone), `store_unreadable` where the store cannot be read.
pub fn signing_key(store: &FileStore, origin: &Origin, principal: u64, mode: impl FnOnce() -> Mode) -> Result<KeyFacts, Refusal> {
    match store.select(&KeySelector::Board { origin, principal: Some(principal) }, Purpose::Sign) {
        Ok(key) => Ok(key),
        Err(StoreError::NoSelection { keys }) => Err(Refusal::of_named(Name::NO_KEY, skep_client::store::arm4_face(store, &keys, mode()))),
        Err(e) => Err(Refusal::of_named(Name::STORE_UNREADABLE, e.into())),
    }
}

/// The signer of the store's key at `path`: `store_unreadable` where its
/// file cannot be read.
pub fn signer(store: &FileStore, path: &Path) -> Result<Box<dyn Signer>, Refusal> {
    store.signer(&KeySelector::Path(path)).map_err(|e| Refusal::of_named(Name::STORE_UNREADABLE, e.into()))
}

/// THE SIGNED CONTENT-SCOPED HANDSHAKE as `principal` with the store's key
/// for (this board, the principal) — [`signing_key`] — behind AUTH-5.65's
/// pre-check, each refusal under the armed name the `session` row spells;
/// the board's position taken from the `/health` read it makes first.
pub fn open_signed(board: &Board, store: &FileStore, principal: u64) -> Result<Open, Refusal> {
    let health = board.health()?;
    let key = signing_key(store, board.dialed(), principal, || Mode::of(&health))?;
    let signer = signer(store, &key.path)?;
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
        kind: Kind::Signed { fingerprint: session.fingerprint(), set_account: pre.walk.set_account.clone() },
    };
    Ok(Open { token: session.into_token(), facts, opened_at: health.log_position() })
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

/// THE DEATH of `entry`, whose token met the death signal: its arm derived
/// from the reads made now (the module doc), and on the restart arm the
/// session re-opened in its place; `store` where the shell holds a key store
/// for that re-open. Run inside [`Sessions::end`] alone, under the
/// entry's lock: the re-open it makes is a session no other hand registers.
fn derive_death(board: &Board, store: Option<&FileStore>, entry: &SessionEntry) -> Death {
    let none = |reason: Value| Death { reason, reopened: None };
    let health = match board.health() {
        Ok(h) => h,
        Err(h) => return none(json!({"arm": "unreachable", "text": h.to_string()})),
    };
    let mode = Mode::of(&health);
    let facts = &entry.facts;
    let Kind::Signed { fingerprint: fp, set_account } = &facts.kind else {
        if mode == Mode::Enforcing {
            return none(json!({"arm": "mode", "mode": mode.name()}));
        }
        return none(json!({"arm": "restart", "reopened": false}));
    };
    // A signed session: the retirement, read off the set it authenticated
    // against and the admitted record read.
    if let Ok(KeySetAnswer::Set(set)) = board.key_set(set_account) {
        if set.retired(fp).is_some() {
            let own: Vec<(Fingerprint, skep_identity::PublicKey)> =
                store.and_then(|s| s.device_keys().ok()).into_iter().flatten().map(|k| (k.fingerprint, k.public)).collect();
            let records = credential_records(board, set_account, &own).ok();
            let retirement = records.as_ref().and_then(|r| r.retirement_of(fp));
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
        fn widen(&mut self, session: &Arc<SessionEntry>) {
            self.0.push(format!("widen {}", session.reference));
        }

        fn narrow(&mut self, principal: u64) {
            self.0.push(format!("narrow {principal}"));
        }
    }

    fn open(principal: u64, account: &str, set_account: &str) -> Open {
        let kind = Kind::Signed { fingerprint: Fingerprint::parse_hex(&"5a".repeat(32)).unwrap(), set_account: set_account.into() };
        let facts = Facts { principal, account: Some(account.into()), kind };
        Open { token: Token::parse(&"9f".repeat(16)).unwrap(), facts, opened_at: 0 }
    }

    /// A board nothing answers at: a port bound and let go.
    fn nowhere() -> Board {
        let port = TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port();
        Board::new(Origin::parse(&format!("http://127.0.0.1:{port}")).unwrap(), PlainHttp::new())
    }

    /// A dialer that holds each exchange at its gate until the test opens it,
    /// counting them, then answers that the board did not answer.
    struct Gated {
        calls: AtomicUsize,
        entered: Mutex<Sender<()>>,
        open: (Mutex<bool>, Condvar),
    }

    impl Dialer for Gated {
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
    /// by reference is a signed one whose set is above its account, and a
    /// bare session, which authenticated against no set, never is.
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
        assert!(!Facts { principal: 3, account: Some("1.0.1.1".into()), kind: Kind::Bare }.by_reference());
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
        assert_eq!((died[0].name, died[0].data["session"].as_str()), (EventName::SessionDied, Some(entry.reference.as_str())));
        assert_eq!(died[0].data["reason"], arm);
        assert_eq!(supplements.0.last().map(String::as_str), Some("narrow 1"));
        let touched = supplements.0.len();
        assert_eq!(sessions.end(&entry, &board, None, &mut supplements, &bus), arm, "the second hand answers the first's arm");
        assert!(rx.try_recv().is_err(), "and emits nothing");
        assert_eq!(supplements.0.len(), touched, "and touches no supplement");
        assert!(sessions.close(&entry.reference).is_none(), "nothing is left to close");
        let closed_first = sessions.register("b-1", open(1, "1.0.1", "1.0.1"), &mut supplements);
        assert!(sessions.close(&closed_first.reference).is_some());
        assert!(sessions.close(&closed_first.reference).is_none(), "closed once");
        assert_eq!(sessions.end(&closed_first, &board, None, &mut supplements, &bus), closed(), "a death met after the close answers its arm");
        assert!(rx.try_recv().is_err());
    }

    /// ONE SUPPLEMENT PER PRINCIPAL: a session that ends hands its
    /// principal's supplement to another session of the principal standing
    /// at its board, and narrows it where none stands there — a session of
    /// the principal at another board takes nothing; a close releases it the
    /// same way.
    #[test]
    fn a_principals_supplement_follows_its_standing_sessions() {
        let (board, sessions, bus) = (nowhere(), Sessions::new(), EventBus::new());
        let mut supplements = Recorded::default();
        let first = sessions.register("b-1", open(1, "1.0.1", "1.0.1"), &mut supplements);
        let second = sessions.register("b-1", open(1, "1.0.1", "1.0.1"), &mut supplements);
        sessions.register("b-2", open(1, "1.0.1", "1.0.1"), &mut supplements);
        supplements.0.clear();
        sessions.end(&first, &board, None, &mut supplements, &bus);
        assert_eq!(supplements.0, [format!("widen {}", second.reference)], "the session standing at the board takes the supplement");
        sessions.end(&second, &board, None, &mut supplements, &bus);
        assert_eq!(supplements.0.last().map(String::as_str), Some("narrow 1"), "none stands at b-1, and the session at b-2 takes nothing");
        let third = sessions.register("b-1", open(1, "1.0.1", "1.0.1"), &mut supplements);
        let fourth = sessions.register("b-1", open(1, "1.0.1", "1.0.1"), &mut supplements);
        supplements.0.clear();
        assert!(sessions.close(&third.reference).is_some());
        sessions.release("b-1", 1, &mut supplements);
        assert_eq!(supplements.0, [format!("widen {}", fourth.reference)]);
        assert!(sessions.close(&fourth.reference).is_some());
        sessions.release("b-1", 1, &mut supplements);
        assert_eq!(supplements.0.last().map(String::as_str), Some("narrow 1"));
    }

    /// Two hands meet one death at once: the second waits on the entry's
    /// lock while the first derives the arm, then answers that arm — one
    /// derivation (one dial), one event, one supplement touched.
    #[test]
    fn a_second_hand_waits_for_the_arm_the_first_derives() {
        let (entered, at_the_dial) = channel();
        let gated = Arc::new(Gated { calls: AtomicUsize::new(0), entered: Mutex::new(entered), open: (Mutex::new(false), Condvar::new()) });
        let board = Board::new(Origin::parse("http://127.0.0.1:9").unwrap(), Arc::clone(&gated));
        let (sessions, bus) = (Sessions::new(), EventBus::new());
        let rx = bus.subscribe();
        let entry = sessions.register("b-1", open(1, "1.0.1", "1.0.1"), &mut Recorded::default());
        let (mut first_hand, mut second_hand) = (Recorded::default(), Recorded::default());
        let (first, second) = thread::scope(|s| {
            let first = s.spawn(|| sessions.end(&entry, &board, None, &mut first_hand, &bus));
            at_the_dial.recv().unwrap();
            let second = s.spawn(|| sessions.end(&entry, &board, None, &mut second_hand, &bus));
            thread::sleep(Duration::from_millis(50));
            *gated.open.0.lock().unwrap() = true;
            gated.open.1.notify_all();
            (first.join().unwrap(), second.join().unwrap())
        });
        assert_eq!(first["arm"], "unreachable", "{first}");
        assert_eq!(second, first);
        assert_eq!(gated.calls.load(Ordering::SeqCst), 1, "the arm was derived once");
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
    /// the arm and says the one `session-died`.
    #[test]
    fn a_hand_that_panics_mid_end_leaves_the_end_to_the_next() {
        let board = Board::new(Origin::parse("http://127.0.0.1:9").unwrap(), PanicsOnce(AtomicUsize::new(0)));
        let (sessions, bus) = (Sessions::new(), EventBus::new());
        let rx = bus.subscribe();
        let entry = sessions.register("b-1", open(1, "1.0.1", "1.0.1"), &mut Recorded::default());
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| sessions.end(&entry, &board, None, &mut Recorded::default(), &bus)));
        assert!(panicked.is_err() && rx.try_recv().is_err(), "the first hand ended nothing");
        assert_eq!(sessions.end(&entry, &board, None, &mut Recorded::default(), &bus)["arm"], "unreachable");
        assert_eq!(rx.try_iter().filter(|e| e.name == EventName::SessionDied).count(), 1);
    }
}
