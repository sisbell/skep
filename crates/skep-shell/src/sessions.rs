//! THE SESSION TABLE and A SESSION's END (`client.md` §4b.1's `session`
//! row; §4b.2's `session-died`). The table holds every session this shell
//! opened for the page — the token, which never leaves this process, beside
//! the board it is valid at, under the opaque reference the page holds
//! (`refs`) — and the FACTS a death's arm is derived from: the principal,
//! the account, and the kind — bare, or signed content-scoped with the key
//! that opened it and the account whose set it authenticated against. A
//! session's every collaborator reads its board off the session, so no
//! caller pairs a token with a board by hand. The two openings are here
//! too, so the shell's `session` call and the restart arm's silent re-open
//! (AUTH-5.31) share one: the BARE bind as the claimant on the permissive
//! board, and the SIGNED content-scoped handshake behind AUTH-5.65's
//! pre-check, each refusal under the armed name the row spells. A write
//! under a session that holds a key carries the attest that key signs
//! ([`SessionEntry::attest`]), whichever hand sends it — a call's `op`, or
//! the held-burst resend's.
//!
//! THE END ([`Sessions::end`]): a death signal is met by two hands — the
//! shell, when a call's token answers `Skepd-Session: closed`, and the
//! board's feed thread, when its consumer's read or a drafts page does —
//! and both run the one sequence here, so the reason is derived once, the
//! restart arm's re-open is registered whichever hand met it — at the dying
//! session's board, under the key store the table holds for it — and one
//! `session-died` goes out. The entry's `OnceLock` is the gate: the hand
//! whose initializer runs ends the session, a hand that comes while it runs
//! waits and answers that reason, and a hand that panics mid-end leaves the
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
use skep_client::ceremony::handshake::{handshake_prechecked, key_face, Site};
use skep_client::derive::records::{credential_records, Hand};
use skep_client::derive::{origin_arm, precheck, KeyDiagnosis, Mode, Walk};
use skep_client::search::SessionRef;
use skep_client::sheet::render_inert;
use skep_client::sign::Signer;
use skep_client::store::{FileStore, KeyFacts, KeySelector, KeyStore, Purpose, StoreError};
use skep_client::{Board, Origin};
use skep_identity::Fingerprint;

use crate::attest::{wants_attest, Composer, Unattested};
use crate::events::{EventBus, EventName};
use crate::refs::{session_reference, BoardEntry};
use crate::refusal::{Name, Refusal};

/// A session's kind: the bare bind, or the signed content-scoped handshake —
/// the key that opened it, and the account whose set it authenticated
/// against (the account itself, or the nearest above it that holds one).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionKind {
    Bare,
    Signed { fingerprint: Fingerprint, set_account: String },
}

/// The facts a session was opened with — what its death's arm reads.
#[derive(Debug, Clone)]
pub struct Facts {
    pub principal: u64,
    /// `principal_prefix(principal)`, where the board answered one.
    pub account: Option<String>,
    pub kind: SessionKind,
}

impl Facts {
    /// Whether the session opened BY REFERENCE — a signed session whose set
    /// stands above its own account.
    fn by_reference(&self) -> bool {
        matches!((&self.account, &self.kind), (Some(account), SessionKind::Signed { set_account, .. }) if account != set_account)
    }
}

/// One session this shell holds for the page.
#[derive(Debug)]
pub struct SessionEntry {
    /// The reference the page holds.
    pub reference: String,
    /// The reference of the board it stands at.
    pub board_reference: String,
    /// The board it stands at — the one its token is valid at; the same
    /// `Arc` the shell's board entry and the board's hold keep.
    pub board: Arc<Board>,
    /// The token — this process's alone.
    pub token: Token,
    pub facts: Facts,
    /// The board's log position read BEFORE the session opened: a held
    /// burst's `base` on a document no acked write of this session names
    /// (§3c.2), so the resend's read sees every row that could have moved it.
    pub opened_at: u64,
    /// The reason its end carried, set once by the hand that ended it — a
    /// second hand waits while the first derives it, then answers it.
    end: OnceLock<Value>,
}

impl SessionEntry {
    /// THE ATTEST a write under this session carries (`attest`'s rule):
    /// composed at the session's own board and signed by the key that opened
    /// the session, where the session holds one and [`wants_attest`] admits
    /// the frame — the one place the composer's precondition is discharged;
    /// the frame as it stands otherwise, and where the board has no `H.1` to
    /// sign over (the board judges that write). Refused — nothing is then to
    /// be sent — `attest_not_composed` where the composer, or the read of
    /// the board's `H.1` it signs over, halted; `store_unreadable` where the
    /// session's key file cannot be read; `no_account` where the board
    /// answered the session no account; and with the board's refusal, or
    /// `unreachable`, where a read it needed was refused or not answered;
    /// [`Unattested::Died`] where a read it made met the session's death
    /// signal, whose end is the caller's to run.
    pub fn attest(&self, store: &FileStore, frame: &mut Value) -> Result<(), Unattested> {
        let SessionKind::Signed { fingerprint: fp, .. } = &self.facts.kind else { return Ok(()) };
        if !wants_attest(frame) {
            return Ok(());
        }
        let Some(board_term) = self.board.board_term()? else { return Ok(()) };
        let signer = signer(store, &store.key_path(fp))?;
        let account = self.facts.account.as_deref().ok_or_else(|| Refusal::shell(Name::NO_ACCOUNT, json!({})))?;
        let composer = Composer { board: &self.board, token: &self.token, signer: &*signer, account, board_term };
        composer.attach(frame)
    }

    /// The session as the search consumer reads it: its token, its principal
    /// and its account — `""` where the board answered it none, as a search
    /// under it reads; no supplement mounts for such a session.
    pub fn session_ref(&self) -> SessionRef<'_> {
        SessionRef { token: &self.token, principal: self.facts.principal, account: self.facts.account.as_deref().unwrap_or("") }
    }
}

/// A board's drafts supplements as the hand that registers or ends a
/// session reaches them (`client.md` §4e.3's WIDEN and NARROW): the shell
/// through the board's feed handle, the feed thread directly.
pub trait Supplements {
    /// `session`'s supplement mounted under its token — a principal's
    /// mounted supplement taking the new token.
    fn widen(&mut self, session: &Arc<SessionEntry>);
    /// `principal`'s supplement saved and unmounted.
    fn narrow(&mut self, principal: u64);
}

/// The table, by reference, and the key store a death's derivation reads:
/// the store the restart arm re-opens a session under — the signed mode's,
/// none under the bare mode, whose sessions no end re-opens silently — and
/// whose own keys name a retirement's own hand.
#[derive(Debug)]
pub struct Sessions {
    entries: Mutex<HashMap<String, Arc<SessionEntry>>>,
    reopen_store: Option<Arc<FileStore>>,
}

impl Sessions {
    /// No session, every end derived under `reopen_store`.
    pub fn new(reopen_store: Option<Arc<FileStore>>) -> Sessions {
        Sessions { entries: Mutex::new(HashMap::new()), reopen_store }
    }

    /// The session `reference` names, where this shell holds one.
    pub fn get(&self, reference: &str) -> Option<Arc<SessionEntry>> {
        self.entries.lock().expect("the sessions' lock").get(reference).cloned()
    }

    /// Every session at the board `board_reference` names, in no order.
    pub fn on_board(&self, board_reference: &str) -> Vec<Arc<SessionEntry>> {
        self.entries.lock().expect("the sessions' lock").values().filter(|e| e.board_reference == board_reference).cloned().collect()
    }

    /// Every session, in no order.
    pub fn all(&self) -> Vec<Arc<SessionEntry>> {
        self.entries.lock().expect("the sessions' lock").values().cloned().collect()
    }

    /// How many sessions stand.
    pub fn len(&self) -> usize {
        self.entries.lock().expect("the sessions' lock").len()
    }

    /// A session opened at `board`, REGISTERED: entered under a fresh
    /// reference — never the token's — its board beside its token, and its
    /// drafts supplement widened; the entry. The board's reference and the
    /// board itself are read off its entry, so every collaborator after reads
    /// the pair off the session.
    pub fn register(&self, board: &BoardEntry, open: Open, supplements: &mut dyn Supplements) -> Arc<SessionEntry> {
        let entry = self.enter(&board.reference, Arc::clone(&board.board), open);
        supplements.widen(&entry);
        entry
    }

    /// THE END of a session whose token met the death signal, run by
    /// whichever hand met it (the module doc). In the entry's `OnceLock` the
    /// session leaves the table and its reason is derived from public reads
    /// at its board; on the restart arm the re-opened session enters under a
    /// fresh reference at the same board, named in the reason as `session`.
    /// Then `session-died` goes out and the drafts supplement is widened
    /// under the re-opened token, or RELEASED ([`Sessions::release`]) —
    /// NARROW "at `session-died` in every arm but the shell's own restart"
    /// (`client.md` §4e.3) where no other session of the principal stands at
    /// the board, the supplement handed to one that does. A hand that finds
    /// the reason already derived answers it and does nothing else. The
    /// reason.
    pub fn end(&self, entry: &SessionEntry, supplements: &mut dyn Supplements, bus: &EventBus) -> Value {
        let (mut ended_here, mut reopened) = (false, None);
        let reason = entry
            .end
            .get_or_init(|| {
                ended_here = true;
                self.remove(&entry.reference);
                let death = derive_death(self.reopen_store.as_deref(), entry);
                let mut reason = death.reason;
                reopened = death.reopened.map(|open| self.enter(&entry.board_reference, Arc::clone(&entry.board), open));
                if let Some(r) = &reopened {
                    reason["session"] = Value::from(r.reference.as_str());
                }
                reason
            })
            .clone();
        if !ended_here {
            return reason;
        }
        bus.emit(EventName::SessionDied, json!({"session": entry.reference, "reason": reason}));
        match &reopened {
            Some(r) => supplements.widen(r),
            None => self.release(&entry.board_reference, entry.facts.principal, supplements),
        }
        reason
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

    /// A session entered under a fresh reference at the board
    /// `board_reference` names, `board` beside its token: the one place a
    /// token is paired with a board, its two callers each passing a pair read
    /// whole — `register` off a board's entry, `end`'s re-open off the session
    /// it replaces.
    fn enter(&self, board_reference: &str, board: Arc<Board>, open: Open) -> Arc<SessionEntry> {
        let entry = Arc::new(SessionEntry {
            reference: session_reference(),
            board_reference: board_reference.to_string(),
            board,
            token: open.token,
            facts: open.facts,
            opened_at: open.opened_at,
            end: OnceLock::new(),
        });
        self.entries.lock().expect("the sessions' lock").insert(entry.reference.clone(), Arc::clone(&entry));
        entry
    }

    fn remove(&self, reference: &str) -> Option<Arc<SessionEntry>> {
        self.entries.lock().expect("the sessions' lock").remove(reference)
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
    Ok(Open { token, facts: Facts { principal, account, kind: SessionKind::Bare }, opened_at })
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

/// THE KEY's STANDING in the set `walk` reached (AUTH-5.25), under the armed
/// names every row that signs spells: `Ok` where the key is enrolled;
/// `retired` where it stands in the retired list (AUTH-2.98), `not_enrolled`
/// where it stands in neither — each with the face `key_face` composes at
/// `site`.
pub fn key_standing(board: &Board, walk: &Walk, key: &KeyFacts, site: Site) -> Result<(), Refusal> {
    let own = [(key.fingerprint, key.public.clone())];
    key_face(board, walk, &key.fingerprint, &own, site).map_err(|h| {
        let name = match KeyDiagnosis::of(&walk.set, &key.fingerprint) {
            KeyDiagnosis::Retired { .. } => Name::RETIRED,
            _ => Name::NOT_ENROLLED,
        };
        Refusal::of_named(name, h)
    })
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
    key_standing(board, &pre.walk, &key, Site::Session)?;
    let session = handshake_prechecked(board, Scope::Content, &*signer, &pre, Site::Session).map_err(|h| Refusal::of_named(Name::BUSY, h))?;
    let facts = Facts {
        principal,
        account: Some(session.account().to_string()),
        kind: SessionKind::Signed { fingerprint: session.fingerprint(), set_account: pre.walk.set_account.clone() },
    };
    Ok(Open { token: session.into_token(), facts, opened_at: health.log_position() })
}

/// Why a session died, and — on the restart arm under a key this store
/// holds — the session re-opened silently in its place.
struct Death {
    reason: Value,
    reopened: Option<Open>,
}

/// The reason the page's own `close` carries: its own arm, `closed`.
pub fn closed() -> Value {
    json!({"arm": "closed"})
}

/// THE DEATH of `entry`, whose token met the death signal: its reason
/// derived from the reads made now at its board (the module doc), and on the
/// restart arm the session re-opened in its place; `store` where the shell
/// holds a key store for that re-open. Run inside [`Sessions::end`] alone,
/// in the entry's `OnceLock`: the re-open it makes is a session no other
/// hand registers.
fn derive_death(store: Option<&FileStore>, entry: &SessionEntry) -> Death {
    let board: &Board = &entry.board;
    let not_reopened = |reason: Value| Death { reason, reopened: None };
    let health = match board.health() {
        Ok(h) => h,
        Err(h) => return not_reopened(json!({"arm": "unreachable", "text": h.to_string()})),
    };
    let mode = Mode::of(&health);
    let facts = &entry.facts;
    let SessionKind::Signed { fingerprint: fp, set_account } = &facts.kind else {
        if mode == Mode::Enforcing {
            return not_reopened(json!({"arm": "mode", "mode": mode.name()}));
        }
        return not_reopened(json!({"arm": "restart", "reopened": false}));
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
            return not_reopened(json!({
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
                    return not_reopened(json!({"arm": "seeded", "account": account, "as_of": set.as_of, "writer": writer}));
                }
            }
        }
    }
    // The restart arm, or the block met at the re-open.
    let Some(store) = store else { return not_reopened(json!({"arm": "restart", "reopened": false})) };
    match open_signed(board, store, facts.principal) {
        Ok(open) => Death { reason: json!({"arm": "restart", "reopened": true}), reopened: Some(open) },
        Err(Refusal::Blocked(b)) => not_reopened(json!({"arm": "blocked", "record": b.record, "ground": b.ground})),
        Err(other) => not_reopened(json!({"arm": "restart", "reopened": false, "refused": other.name()})),
    }
}

#[cfg(test)]
mod tests;
