//! The session table and a session's end.
//!
//! They are `client.md` §4b.1's `session` row and §4b.2's `session-died`.
//! The table holds every session this shell opened for the page — the
//! token, which never leaves this process, beside the board it is valid at,
//! under the opaque reference the page holds (`refs`) — and the facts a
//! death's arm is derived from: the principal, the account, and the kind —
//! bare, or signed content-scoped with the key that opened it and the
//! account whose set it authenticated against. A session's every
//! collaborator reads its board off the session, so no caller pairs a token
//! with a board by hand. The two openings are here too, so the shell's
//! `session` call and the restart arm's silent re-open (AUTH-5.31) share
//! one: the bare bind as a principal on the permissive board, and the signed
//! content-scoped handshake behind AUTH-5.65's pre-check, each refusal under
//! the armed name the row spells. A bare session is the keyless session for
//! reading alone: no write goes out under it ([`SessionEntry::may_write`];
//! foundations §3.3 state 3). A write under a session that holds a key
//! carries the attest that key signs where one is owed
//! ([`SessionEntry::attest`]), whichever caller sends it — a call's `op`, or
//! the held-burst resend's.
//!
//! **The end** ([`Sessions::end`]). A death signal is met by two callers —
//! the shell, when a call's token answers `Skepd-Session: closed`, and the
//! board's feed thread, when its consumer's read or a drafts page does — and
//! both run the one sequence here, so the reason is derived once, the
//! restart arm's re-open is registered whichever caller met it — at the
//! dying session's board, under the key store the table holds for it — and
//! one `session-died` goes out. The entry's `OnceLock` is the gate: the
//! caller whose initializer runs ends the session, a caller that comes while
//! it runs waits and answers that reason, and a caller that panics mid-end
//! leaves the cell unset for the next to take the end over. A caller here is
//! the code that meets the death; a hand is the corpus's, the writer of a
//! record or a row (§3c.5, §4b.2), as the arm below names a retirement's. An
//! entry leaves the table by that sequence or by a close — the page's own,
//! or the shell's stop ([`Sessions::close`]) — and no other way.
//!
//! **One supplement per principal** ([`Sessions::release`]). The consumer
//! holds one drafts supplement per (board, principal), and two tabs open two
//! sessions of one principal; a session that leaves the table hands the
//! supplement to another session of its principal standing at its board,
//! and only where none stands is it narrowed.
//!
//! **The arm** (`session-died(session, reason)`, "one arm per E2 trigger,
//! derived by the shell from public reads"). A bare session on a board now
//! `ENFORCING` died at the flip; a signed session whose key now stands in the
//! retired list died at a retirement — AUTH-5.28's own-hand arm where this
//! store's key wrote it, AUTH-5.77's where another did, the hand named by its
//! position and label off the admitted record read. The fork is the reason's
//! `own`: the session's own key is this store's whatever the store answers
//! (AUTH-5.28: "the token's own key as its hand"), and another key is this
//! store's where the store's listing holds it. A store that cannot be listed
//! leaves the fork on another key unsaid, `own` null — the face that asserts
//! neither arm (AUTH-5.77) — its failure said on `Talk` with its file and
//! never read as a store holding no keys (SP-14, SP-12). A retirement whose
//! record was not read, or whose hand was not — below the floor, a row whose
//! testimony was lost — leaves the fork unsaid too, `own` null, naming the
//! position it read, where it read one, and no hand (AUTH-5.77's no-hand form;
//! AUTH-5.27). A session opened by reference whose acted-as account now holds a
//! set of its own died at a genesis (the `seeded` arm); else the shell re-opens
//! where it holds a key — `403 prefix_blocked` is the block's arm, a session
//! that opens is the `restart` arm re-opened silently, and a board that does
//! not answer is said so. The page's own `close` is its own arm.

use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

use serde_json::{json, Value};
use skep_client::board::{KeySetAnswer, Opened, Scope, SessionBody, Token};
use skep_client::ceremony::handshake::{handshake_prechecked, key_face, Site};
use skep_client::derive::records::{credential_records, Hand, Records};
use skep_client::derive::{origin_arm, precheck, KeyDiagnosis, Mode, Walk};
use skep_client::search::SessionRef;
use skep_client::sheet::render_inert;
use skep_client::sign::Signer;
use skep_client::store::{FileStore, KeyFacts, KeySelector, KeyStore, Purpose, StoreError};
use skep_client::{Board, Origin};
use skep_identity::{Fingerprint, PublicKey};

use crate::attest::{in_checked_set, wants_attest, Composer, Unattested};
use crate::events::{EventBus, EventName};
use crate::refs::{session_reference, BoardEntry};
use crate::refusal::{Name, Refusal};
use crate::Talk;

/// A session's kind: the bare bind, which reads alone, or the signed one.
///
/// The signed content-scoped handshake writes too, and holds the key that
/// opened it and the account whose set it authenticated against (the
/// account itself, or the nearest above it that holds one).
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
    /// Returns whether the session opened by reference.
    ///
    /// It did where it is a signed session whose set stands above its own
    /// account.
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
    /// The board it stands at, the one its token is valid at.
    ///
    /// It is the same `Arc` the shell's board entry and the board's hold
    /// keep.
    pub board: Arc<Board>,
    /// The token — this process's alone.
    pub token: Token,
    pub facts: Facts,
    /// The board's log position, read before the session opened.
    ///
    /// It is a held burst's `base` on a document where the shell knows the
    /// position of no write of its principal's — no ack, and no landing the
    /// resend's read found (§3c.2) — so the resend's read sees every row that
    /// could have moved it.
    pub opened_at: u64,
    /// The reason its end carried, set once by the caller that ended it.
    ///
    /// A second caller waits while the first derives it, then answers it.
    end: OnceLock<Value>,
}

impl SessionEntry {
    /// Returns whether a write may go out under this session: a signed one's.
    ///
    /// A bare session is the keyless session for reading alone (foundations
    /// §3.3 state 3: "the shell refuses every write in it, no `bare` write
    /// ever committed by this client"), the dev provider's `--session bare`
    /// among them: the `op` row refuses every write kind under it, and
    /// `resolve(send)`, before any dial, and the held-burst resend sends
    /// under a signed session alone.
    pub fn may_write(&self) -> bool {
        matches!(self.facts.kind, SessionKind::Signed { .. })
    }

    /// Returns the key a write of `op` under this session is attested with.
    ///
    /// It is the key that opened it, where the session holds one and `op` is
    /// one of the ten kinds that have an entry frame
    /// (`attest::in_checked_set`); none otherwise. It is what
    /// [`SessionEntry::attest`] signs with, and what the burst's door keeps
    /// an attest's room for (`Burst::admit`).
    pub fn attesting_key(&self, op: &str) -> Option<&Fingerprint> {
        match &self.facts.kind {
            SessionKind::Signed { fingerprint, .. } if in_checked_set(op) => Some(fingerprint),
            _ => None,
        }
    }

    /// Returns the attest a write under this session carries, on its frame.
    ///
    /// The attest (`attest`'s rule) is composed at the session's own board
    /// and signed by the key [`SessionEntry::attesting_key`] names for the
    /// frame's op, where it names one and [`wants_attest`] admits the frame —
    /// the one place the composer's precondition is discharged — and attached
    /// to a copy of the frame, the one copy made; the frame is borrowed as it
    /// stands otherwise, and where the board has no `H.1` to sign over (the
    /// board judges that write).
    ///
    /// # Errors
    ///
    /// Nothing is then to be sent. Returns `attest_not_composed` where the
    /// composer, or the read of the board's `H.1` it signs over, halted;
    /// `store_unreadable` where the session's key file cannot be read;
    /// `no_account` where the board answered the session no account; the
    /// board's refusal, or `unreachable`, where a read it needed was refused
    /// or not answered; and [`Unattested::Died`] where a read it made met the
    /// session's death signal, whose end is the caller's to run.
    pub fn attest<'f>(&self, store: &FileStore, frame: &'f Value) -> Result<Cow<'f, Value>, Unattested> {
        let Some(fp) = frame["op"].as_str().and_then(|op| self.attesting_key(op)) else { return Ok(Cow::Borrowed(frame)) };
        if !wants_attest(frame) {
            return Ok(Cow::Borrowed(frame));
        }
        let Some(board_term) = self.board.board_term()? else { return Ok(Cow::Borrowed(frame)) };
        let signer = signer(store, &store.key_path(fp))?;
        let account = self.facts.account.as_deref().ok_or_else(|| Refusal::shell(Name::NO_ACCOUNT, json!({})))?;
        let composer = Composer { board: &self.board, token: &self.token, signer: &*signer, account, board_term };
        let mut attested = frame.clone();
        composer.attach(&mut attested)?;
        Ok(Cow::Owned(attested))
    }

    /// Returns the session as the search consumer reads it (`SessionRef`).
    ///
    /// It is skep-client's `SessionRef`, a view lending the consumer its
    /// token, its principal and its account — `""` where the board answered
    /// it none, as a search under it reads; no supplement mounts for such a
    /// session. It is no session reference of the pin's (`client.md` §4b.1):
    /// that is [`SessionEntry::reference`], a name that grants nothing.
    pub fn search_view(&self) -> SessionRef<'_> {
        SessionRef { token: &self.token, principal: self.facts.principal, account: self.facts.account.as_deref().unwrap_or("") }
    }
}

/// The drafts supplements of a board, as a session's caller reaches them.
///
/// The caller registers or ends a session (`client.md` §4e.3's widen and
/// narrow): the shell reaches them through the board's feed handle, the feed
/// thread directly.
pub trait Supplements {
    /// Mounts `session`'s supplement under its token.
    ///
    /// A principal's mounted supplement takes the new token.
    fn widen(&mut self, session: &Arc<SessionEntry>);
    /// Saves and unmounts `principal`'s supplement.
    fn narrow(&mut self, principal: u64);
}

/// The table, by reference, and the key store a death's derivation reads.
///
/// The store is the one the restart arm re-opens a session under — the
/// signed mode's, none under the bare mode, whose sessions no end re-opens
/// silently — and whose own keys name a retirement's own hand. Where a
/// death's derivation cannot list that store, it says so on the table's
/// `Talk` sink, the shell's own window and never the page (SP-12). Its
/// `Debug` leaves out the sink, a closure.
pub struct Sessions {
    entries: Mutex<HashMap<String, Arc<SessionEntry>>>,
    reopen_store: Option<Arc<FileStore>>,
    talk: Talk,
}

impl fmt::Debug for Sessions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sessions").field("entries", &self.entries).field("reopen_store", &self.reopen_store).finish_non_exhaustive()
    }
}

impl Sessions {
    /// Returns a table of no session, every end derived under `reopen_store`.
    ///
    /// What a death's derivation cannot read of that store is said on `talk`.
    pub fn new(reopen_store: Option<Arc<FileStore>>, talk: Talk) -> Sessions {
        Sessions { entries: Mutex::new(HashMap::new()), reopen_store, talk }
    }

    /// Returns the session `reference` names, where this shell holds one.
    ///
    /// # Panics
    ///
    /// Panics where the sessions' lock is poisoned.
    pub fn get(&self, reference: &str) -> Option<Arc<SessionEntry>> {
        self.entries.lock().expect("the sessions' lock").get(reference).cloned()
    }

    /// Returns every session at the board `board_reference` names, in no order.
    ///
    /// # Panics
    ///
    /// Panics where the sessions' lock is poisoned.
    pub fn on_board(&self, board_reference: &str) -> Vec<Arc<SessionEntry>> {
        self.entries.lock().expect("the sessions' lock").values().filter(|e| e.board_reference == board_reference).cloned().collect()
    }

    /// Returns every session, in no order.
    ///
    /// # Panics
    ///
    /// Panics where the sessions' lock is poisoned.
    pub fn all(&self) -> Vec<Arc<SessionEntry>> {
        self.entries.lock().expect("the sessions' lock").values().cloned().collect()
    }

    /// Returns how many sessions stand.
    ///
    /// # Panics
    ///
    /// Panics where the sessions' lock is poisoned.
    pub fn len(&self) -> usize {
        self.entries.lock().expect("the sessions' lock").len()
    }

    /// Registers a session opened at `board` and returns its entry.
    ///
    /// It is entered under a fresh reference — never the token's — its board
    /// beside its token, and its drafts supplement widened. The board's
    /// reference and the board itself are read off its entry, so every
    /// collaborator after reads the pair off the session.
    pub fn register(&self, board: &BoardEntry, open: Open, supplements: &mut dyn Supplements) -> Arc<SessionEntry> {
        let entry = self.enter(&board.reference, Arc::clone(&board.board), open);
        supplements.widen(&entry);
        entry
    }

    /// Ends a session whose token met the death signal and returns the reason.
    ///
    /// It is run by whichever caller met it (the module doc). In the entry's
    /// `OnceLock` the session leaves the table and its reason is derived from
    /// public reads at its board; on the restart arm the re-opened session
    /// enters under a fresh reference at the same board, named in the reason
    /// as `session`. Then `session-died` goes out and the drafts supplement is
    /// widened under the re-opened token, or released ([`Sessions::release`])
    /// — narrow "at `session-died` in every arm but the shell's own restart"
    /// (`client.md` §4e.3) where no other session of the principal stands at
    /// the board, the supplement handed to one that does. A caller that finds
    /// the reason already derived answers it and does nothing else.
    pub fn end(&self, entry: &SessionEntry, supplements: &mut dyn Supplements, bus: &EventBus) -> Value {
        let (mut ended_here, mut reopened) = (false, None);
        let reason = entry
            .end
            .get_or_init(|| {
                ended_here = true;
                self.remove(&entry.reference);
                let death = derive_death(self.reopen_store.as_deref(), &self.talk, entry);
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

    /// Releases a principal's supplement at the board `board_reference` names.
    ///
    /// It is given up by a session that has left the table: the consumer
    /// holds one supplement per principal, so it is handed to another session
    /// of the principal standing there — that session's token widened in —
    /// and narrowed (`client.md` §4e.3's narrow) where none stands.
    pub fn release(&self, board_reference: &str, principal: u64, supplements: &mut dyn Supplements) {
        match self.on_board(board_reference).into_iter().find(|s| s.facts.principal == principal) {
            Some(standing) => supplements.widen(&standing),
            None => supplements.narrow(principal),
        }
    }

    /// Closes a session: the page's own close, or the shell's stop.
    ///
    /// The session's end is settled as the `closed` arm — waiting, as a
    /// second caller's `end` does, for a caller deriving another — and the
    /// session is out of the table. It returns the entry, or `None` where
    /// this shell holds no session under `reference` any more — a death met
    /// first, or a close before.
    pub fn close(&self, reference: &str) -> Option<Arc<SessionEntry>> {
        let entry = self.get(reference)?;
        entry.end.set(closed()).ok()?;
        self.remove(reference);
        Some(entry)
    }

    /// Enters a session under a fresh reference, `board` beside its token.
    ///
    /// The session stands at the board `board_reference` names. It is the
    /// one place a token is paired with a board, its two callers each passing
    /// a pair read whole — `register` off a board's entry, `end`'s re-open
    /// off the session it replaces.
    ///
    /// # Panics
    ///
    /// Panics where the sessions' lock is poisoned.
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

/// A session opened: the token, its facts, and the board's log position.
///
/// The position is read before the open ([`SessionEntry::opened_at`]).
#[derive(Debug)]
pub struct Open {
    pub token: Token,
    pub facts: Facts,
    pub opened_at: u64,
}

/// Opens the bare bind as `principal` (`client.md` §4b.4; AUTH-4.26).
///
/// It is honoured on the unclaimed and the `CLAIMED-PERMISSIVE` board from
/// this loopback peer, which sends no `Origin`. The board's position is read
/// first, so a row landing between that read and the open is one the
/// session's drafts feed reads from its open ([`SessionEntry::opened_at`]),
/// never one it skips. The session reads alone ([`SessionEntry::may_write`]).
///
/// # Errors
///
/// Returns the board's one 401 on `ENFORCING`, `session_rejected`, carried
/// verbatim; the block where the board answers `403 prefix_blocked`, its
/// ground unread; and the board's refusal, or `unreachable`, where the
/// position read, the open or the account read is refused or not answered.
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

/// Returns the store's key for (`origin`, `principal`) to sign with.
///
/// It is §3.5's lookup, under the armed names every row that signs spells.
///
/// # Errors
///
/// Returns `no_key` under arm 4's face where the store selects none (`mode`
/// read for that face alone), and `store_unreadable` where the store cannot
/// be read.
pub fn signing_key(store: &FileStore, origin: &Origin, principal: u64, mode: impl FnOnce() -> Mode) -> Result<KeyFacts, Refusal> {
    match store.select(&KeySelector::Board { origin, principal: Some(principal) }, Purpose::Sign) {
        Ok(key) => Ok(key),
        Err(StoreError::NoSelection { keys }) => Err(Refusal::of_named(Name::NO_KEY, skep_client::store::arm4_face(store, &keys, mode()))),
        Err(e) => Err(Refusal::of_named(Name::STORE_UNREADABLE, e.into())),
    }
}

/// Returns the signer of the store's key at `path`.
///
/// # Errors
///
/// Returns `store_unreadable` where its file cannot be read.
pub fn signer(store: &FileStore, path: &Path) -> Result<Box<dyn Signer>, Refusal> {
    store.signer(&KeySelector::Path(path)).map_err(|e| Refusal::of_named(Name::STORE_UNREADABLE, e.into()))
}

/// Diagnoses the key in the set `walk` reached.
///
/// It is `client.md` §2.2's three-state diagnosis, "shared by `verify`,
/// `session`'s pre-check and `enroll`" (AUTH-5.25), faced under the armed
/// names every row that signs spells: `Ok` where the key is enrolled.
///
/// # Errors
///
/// Returns `retired` where the key stands in the retired list (AUTH-2.98),
/// and `not_enrolled` where it stands in neither — each with the face
/// `key_face` composes at `site`.
pub fn diagnose_key(board: &Board, walk: &Walk, key: &KeyFacts, site: Site) -> Result<(), Refusal> {
    let own = [(key.fingerprint, key.public.clone())];
    key_face(board, walk, &key.fingerprint, &own, site).map_err(|h| {
        let name = match KeyDiagnosis::of(&walk.set, &key.fingerprint) {
            KeyDiagnosis::Retired { .. } => Name::RETIRED,
            _ => Name::NOT_ENROLLED,
        };
        Refusal::of_named(name, h)
    })
}

/// Opens the signed content-scoped handshake as `principal`.
///
/// It signs with the store's key for (this board, the principal) —
/// [`signing_key`] — behind AUTH-5.65's pre-check, the board's position taken
/// from the `/health` read it makes first.
///
/// # Errors
///
/// Each refusal is under the armed name the `session` row spells. In this
/// order: the board's refusal, or `unreachable`, at the `/health` read;
/// `no_key` or `store_unreadable` for the store's key ([`signing_key`]), and
/// `store_unreadable` where its file cannot be read; `origin_state`;
/// `not_registered` where the pre-check halts; `retired` or `not_enrolled`
/// ([`diagnose_key`]); and `busy` where the handshake halts after the
/// pre-check passed. A board's refusal, a block or an unanswered read along
/// the way is carried as its own member.
pub fn open_signed(board: &Board, store: &FileStore, principal: u64) -> Result<Open, Refusal> {
    let health = board.health()?;
    let key = signing_key(store, board.dialed(), principal, || Mode::of(&health))?;
    let signer = signer(store, &key.path)?;
    if let Err(h) = origin_arm(board.signed(), &health) {
        return Err(Refusal::of_named(Name::ORIGIN_STATE, h));
    }
    let pre = precheck(board, principal, &key.fingerprint).map_err(|h| Refusal::of_named(Name::NOT_REGISTERED, h))?;
    diagnose_key(board, &pre.walk, &key, Site::Session)?;
    let session = handshake_prechecked(board, Scope::Content, &*signer, &pre, Site::Session).map_err(|h| Refusal::of_named(Name::BUSY, h))?;
    let facts = Facts {
        principal,
        account: Some(session.account().to_string()),
        kind: SessionKind::Signed { fingerprint: session.fingerprint(), set_account: pre.walk.set_account.clone() },
    };
    Ok(Open { token: session.into_token(), facts, opened_at: health.log_position() })
}

/// Why a session died, and the session re-opened in its place, where one is.
///
/// A session is re-opened silently on the restart arm, under a key this
/// store holds.
#[derive(Debug)]
struct Death {
    reason: Value,
    reopened: Option<Open>,
}

/// Returns the reason the page's own `close` carries: its own arm, `closed`.
pub fn closed() -> Value {
    json!({"arm": "closed"})
}

/// Derives the death of `entry`, whose token met the death signal.
///
/// Its reason is derived from the reads made now at its board (the module
/// doc), and on the restart arm the session is re-opened in its place;
/// `store` is given where the shell holds a key store for that re-open, and
/// where the retirement's arm cannot list that store's keys the failure is
/// said on `talk`. It runs inside [`Sessions::end`] alone, in the entry's
/// `OnceLock`: the re-open it makes is a session no other caller registers,
/// and what it says is said once per death.
fn derive_death(store: Option<&FileStore>, talk: &Talk, entry: &SessionEntry) -> Death {
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
            // This store's keys, tried first at the record's signature. A
            // listing the store refuses is said with its file and leaves the
            // fork on another hand unsaid, never read as a store holding no
            // keys (SP-14, SP-12).
            let own_keys = match store.map(FileStore::device_keys).transpose() {
                Ok(keys) => Some(keys.into_iter().flatten().map(|k| (k.fingerprint, k.public)).collect::<Vec<_>>()),
                Err(e) => {
                    let reference = &entry.reference;
                    talk(&format!("session-died: {reference}'s key {fp} stands retired, and the key store could not be listed to tell this store's keys from another's ({e})"));
                    None
                }
            };
            let records = credential_records(board, set_account, own_keys.as_deref().unwrap_or_default()).ok();
            return not_reopened(retired_reason(fp, records.as_ref(), own_keys.as_deref()));
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

/// Returns the reason of a session whose key `fp` stands retired.
///
/// It is the `retired` arm (`client.md` §4b.2, §9 item 30): the key, the
/// hand the retirement record names, the position it was read at and the
/// retiring key's label, with `own` the fork [`hand_is_own`] takes. A record
/// read keeps its position whatever its hand: where the hand could not be
/// named it names the position it read and no hand (AUTH-5.77's no-hand
/// form), and where no record was read, no position.
fn retired_reason(fp: &Fingerprint, records: Option<&Records>, own_keys: Option<&[(Fingerprint, PublicKey)]>) -> Value {
    let retirement = records.and_then(|r| r.retirement_of(fp));
    let own = hand_is_own(retirement.map(|rec| &rec.hand), fp, own_keys);
    let (hand, position, label) = match retirement.map(|rec| (&rec.hand, rec.position)) {
        Some((Hand::Key(hand), position)) => {
            let label = records.and_then(|r| r.label_of(hand)).map(|l| render_inert(&l));
            (Some(hand.to_string()), position, label)
        }
        Some((Hand::Bare, position)) => (Some("bare".to_string()), position, None),
        Some((Hand::System | Hand::NoKeyVerifies | Hand::Unreadable(_), position)) => (None, position, None),
        None => (None, None, None),
    };
    json!({
        "arm": "retired",
        "fingerprint": fp.to_string(),
        "own": own,
        "hand": hand,
        "position": position,
        "label": label,
    })
}

/// Returns whether a retirement's hand is this store's own key.
///
/// It is the fork of AUTH-5.28 and AUTH-5.77 the reason's `own` carries
/// (`client.md` §4b.2: "where this store's own key retired itself"). The
/// session's own `key` is this store's whatever the store answers
/// (AUTH-5.28: "the token's own key as its hand"); a bare row and the
/// board's own daemon are no key's; another key is this store's where
/// `own_keys` holds it, and a `sig` no key verifies is none of its keys where
/// they were tried. Where the store could not list its keys, `own_keys` none,
/// either is unsaid: the answer is none, the face that asserts neither arm
/// (AUTH-5.77), never the answer a store holding no keys would give (SP-14).
/// Where no record was read, or its hand was not, the fork cannot be taken
/// whatever the store answers: none again (AUTH-5.77's no-hand form;
/// AUTH-5.27: no death chrome without a record that shows a death).
fn hand_is_own(hand: Option<&Hand>, key: &Fingerprint, own_keys: Option<&[(Fingerprint, PublicKey)]>) -> Option<bool> {
    match (hand, own_keys) {
        (None | Some(Hand::Unreadable(_)), _) => None,
        (Some(Hand::Key(hand)), _) if hand == key => Some(true),
        (Some(Hand::Bare | Hand::System), _) => Some(false),
        (Some(Hand::Key(hand)), Some(keys)) => Some(keys.iter().any(|(f, _)| f == hand)),
        (Some(Hand::NoKeyVerifies), Some(_)) => Some(false),
        (Some(Hand::Key(_) | Hand::NoKeyVerifies), None) => None,
    }
}

#[cfg(test)]
mod tests;
