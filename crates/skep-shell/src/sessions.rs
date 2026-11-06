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
//! the held-burst resend's — and none goes out unsigned where a signature is
//! owed: the board term it signs over is read at the session's board
//! ([`SessionEntry::signing_term`], through [`board_head`], the one
//! classifier of a board's head the held store's directory reads too), and
//! a head record that stands and cannot be read, one the board served
//! garbled, or a claimed board that serves none, refuses the write
//! `head_unreadable` (SP-14).
//!
//! **The end** ([`Sessions::end`]). A death signal is met by two callers —
//! the shell, when a call's token answers `Skepd-Session: closed`, and the
//! board's feed thread, when its consumer's read or a drafts page does — and
//! both run the one sequence here, so the reason is derived once, the
//! restart arm's re-open is made whichever caller met it — at the dying
//! session's board, under the key store the table holds for it — and one
//! `session-died` goes out. The entry's `OnceLock` is the gate: the caller
//! whose initializer runs ends the session, a caller that comes while it
//! runs waits and answers that reason, and a caller that panics mid-end
//! leaves the cell unset for the next to take the end over. In that
//! initializer the entry STANDS IN THE TABLE, marked ENDING first
//! ([`SessionEntry::is_ending`]), while its reason is derived from public
//! reads: a call that arrives meanwhile finds it ([`Sessions::get`]), dials,
//! meets the death and waits on the lock, answered `session_died` with the
//! reason and never `session_ended` (skep #626); and no read, resend or
//! release picks it, since [`Sessions::on_board`] leaves an ending entry out
//! — a resend under a dead token (skep #530) and a drafts read under one are
//! never made. On the restart arm the re-opened session is built there —
//! its reference minted, named in the reason as `session` — and NOT
//! entered. What the initializer leaves is the swap it owes ([`Ended`]).
//!
//! **The swap, on the feed thread** ([`Supplements::ended`],
//! [`Sessions::swap`]). The caller that ended the session hands the swap to
//! its supplements: the dying entry leaves the table, the re-opened one
//! enters, the dying reference's reason is kept, `session-died` goes out
//! with it, and the re-opened token is widened or the supplement released
//! ([`Sessions::release`]) — one sequence, in that order, the table's two
//! moves and the keep under one lock. A call thread's supplements are the
//! board's feed handle, which sends the swap to the board's FEED THREAD as
//! one command ordered against its rows and waits for it, so the death is
//! said after every row of the tick it fell in and before any row or face of
//! the re-opened session (skep #748, #703); the feed thread's own path runs
//! it inline, between its rows; and where the feed thread has stopped the
//! caller runs it itself, so every death leaves the table and is said once.
//! A caller is the code that meets the death; a hand is the corpus's, the
//! writer of a record or a row (§3c.5, §4b.2), as the arm below names a
//! retirement's. An entry leaves the table by that swap or by a close — the
//! page's own, or the shell's stop ([`Sessions::close`]) — and no other way.
//!
//! **The ended references and the run** ([`Sessions::ended_reason`]). The
//! table keeps a bounded ring of this run's ended references with their
//! reasons — the swap's dying reference with the reason derived, a close's
//! with its own arm — the newest [`ENDED_KEPT`] of them, so a call that
//! names a reference after its end is answered `session_died` with the
//! reason, the re-opened reference among its members where one was (skep
//! #532). Each table mints one run id at its birth and every session
//! reference under it (`refs`), so a shell that restarted under a page can
//! tell a reference of its earlier run from one it never issued (skep #625).
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
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use serde_json::{json, Value};
use skep_client::board::{KeySetAnswer, Opened, Scope, SessionBody, Token};
use skep_client::ceremony::handshake::{handshake_prechecked, key_face, Site};
use skep_client::derive::records::{credential_records, Hand, Records};
use skep_client::derive::{origin_arm, precheck, KeyDiagnosis, Mode, Walk};
use skep_client::halt::{Face, Halt};
use skep_client::search::SessionRef;
use skep_client::sheet::render_inert;
use skep_client::sign::Signer;
use skep_client::store::{FileStore, KeyFacts, KeySelector, KeyStore, Purpose, StoreError};
use skep_client::{Board, DialError, Origin};
use skep_identity::{BoardTerm, Fingerprint, PublicKey};

use crate::attest::{in_checked_set, wants_attest, Composer, Unattested};
use crate::events::{EventBus, EventName};
use crate::refs::{run_id, session_reference, BoardEntry};
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
    /// resend's read found (§3c.2) — so the resend's read, from that base,
    /// meets every row that could be the line's own landing (§3c.5).
    pub opened_at: u64,
    /// Whether the session's end is under way or done.
    ///
    /// It is set first by the caller that ends the session, before the
    /// reason is derived, and never cleared: from then on the entry stands
    /// in the table for a call to find and wait on, and for nothing else
    /// (the module doc).
    ending: AtomicBool,
    /// The reason its end carried, set once by the caller that ended it.
    ///
    /// A second caller waits while the first derives it, then answers it.
    end: OnceLock<Value>,
}

impl SessionEntry {
    /// Returns whether the session's end is under way or done.
    ///
    /// An ending session stands in the table for a call to find and wait on
    /// (the module doc): [`Sessions::on_board`] leaves it out, so no drafts
    /// read, no resend and no release of a supplement picks it.
    pub fn is_ending(&self) -> bool {
        self.ending.load(Ordering::SeqCst)
    }

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

    /// Returns the board term a signed write under this session signs over.
    ///
    /// It is the board's head as [`board_head`] classifies it, read at the
    /// session's own board: `H.1`'s pair; none where the board serves no
    /// head record and names no claimant — a board no one has claimed, which
    /// takes a write unsigned. A head record that stands and cannot be read,
    /// and a claimed board that serves none, are never read as no record
    /// (SP-14): a write owed a signature is then never sent without one.
    ///
    /// # Errors
    ///
    /// [`board_head`]'s: `unreachable` where a read it makes goes
    /// unanswered, and `head_unreadable` where the head record stands and
    /// cannot be read, was served garbled, or is owed and not served.
    pub fn signing_term(&self) -> Result<Option<BoardTerm>, Refusal> {
        board_head(&self.board)
    }

    /// Returns the attest a write under this session carries, on its frame.
    ///
    /// The attest (`attest`'s rule) is composed at the session's own board
    /// over the board term [`SessionEntry::signing_term`] reads, and signed
    /// by the key [`SessionEntry::attesting_key`] names for the frame's op,
    /// where it names one and [`wants_attest`] admits the frame — the one
    /// place the composer's precondition is discharged — and attached to a
    /// copy of the frame, the one copy made; the frame is borrowed as it
    /// stands otherwise, and at a board no one has claimed that serves no
    /// head record, which takes the write unsigned.
    ///
    /// # Errors
    ///
    /// Nothing is then to be sent. The checks run in this order, the first
    /// that holds answering:
    ///
    /// 1. `head_unreadable` and `unreachable` where the board term cannot be
    ///    had ([`SessionEntry::signing_term`]);
    /// 2. `store_unreadable` where the session's key file cannot be read;
    /// 3. `no_account` where the board answered the session no account;
    /// 4. the composer's: `attest_not_composed` where it halted, the board's
    ///    refusal or `unreachable` where a read it made was refused or not
    ///    answered, and [`Unattested::Died`] where a read it made met the
    ///    session's death signal, whose end is the caller's to run.
    pub fn attest<'f>(&self, store: &FileStore, frame: &'f Value) -> Result<Cow<'f, Value>, Unattested> {
        let Some(fp) = frame["op"].as_str().and_then(|op| self.attesting_key(op)) else { return Ok(Cow::Borrowed(frame)) };
        if !wants_attest(frame) {
            return Ok(Cow::Borrowed(frame));
        }
        let Some(board_term) = self.signing_term()? else { return Ok(Cow::Borrowed(frame)) };
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

/// Classifies the board's head: a term, none, `head_unreadable` or unreachable.
///
/// It is the one decision of what `H.1` says, shared by the attest a signed
/// write owes ([`SessionEntry::signing_term`]) and by the held store's
/// directory (`hold`'s `Directory::of`), so the two never disagree on what a
/// board's head is. `Ok(Some)` is `H.1`'s pair, read by `Board::board_term`,
/// which keeps a pair once read; `Ok(None)` a board that serves no head
/// record and names no claimant through `/health` — a board no one has
/// claimed, which takes a write unsigned and holds no held text (`client.md`
/// §3c.1). Every other answer is a failure, never an absence (SP-14).
///
/// **A garbled answer is the board's** (skep #728). An `H.1` read, or the
/// claimant arm's `/health` read, that the board answered with bytes that
/// are no HTTP response, a body that is no JSON, or an answer past the
/// client's answer cap (`DialError::Response`, `DialError::TooLarge`) is
/// `head_unreadable`, its cause "served garbled" and the error: the board was
/// reached and answered, so the fault is its head record's to repair, never
/// the network's — and the burst so held is skipped at each probe until the
/// head reads, not retried as a lost connection would be. Every other dial
/// error — a connection never made, a timeout, a connection the board closed
/// before its answer's head was whole, an answer cut short — is the board
/// away, `unreachable` (skep #758).
///
/// # Errors
///
/// Returns `unreachable` where a read it makes — the head record's, then
/// `/health`'s — goes unanswered; and `head_unreadable`, a halt's face
/// naming why, where the head record stands and cannot be read, was served
/// garbled, the board refuses its read, or the board serves none and names
/// a claimant or cannot say through `/health` whether it does.
pub(crate) fn board_head(board: &Board) -> Result<Option<BoardTerm>, Refusal> {
    match board.board_term() {
        Ok(Some(board_term)) => Ok(Some(board_term)),
        Ok(None) => match board.health() {
            Ok(health) => match health.claimant() {
                None => Ok(None),
                Some(claimant) => Err(head_unreadable(format!("the board names {claimant} its claimant and serves no head record (`H.1`)"))),
            },
            Err(Halt::Dial(e)) => Err(garbled_or_away(e, "the board serves no head record (`H.1`), and its `/health`")),
            Err(h) => Err(head_unreadable(format!("the board serves no head record (`H.1`), and its `/health` could not say whether it is claimed: {h}"))),
        },
        Err(Halt::Dial(e)) => Err(garbled_or_away(e, "the board's head record (`H.1`)")),
        Err(Halt::Halt(face)) => Err(head_unreadable(format!("{}: {}", face.state, face.cause))),
        Err(h) => Err(head_unreadable(format!("the board refused the read of its head record (`H.1`): {h}"))),
    }
}

/// Splits a read's dial error: a garbled answer is the board's, the rest is
/// the board away (skep #728).
///
/// `read` names what was read, for the garbled face's cause: the board
/// answered, and its answer was no HTTP, no JSON or past the cap, so the
/// fault is `head_unreadable`'s; a connection never made, a timeout, a
/// connection closed before the answer's head was whole or an answer cut
/// short says nothing of the head, and is `unreachable`.
fn garbled_or_away(e: DialError, read: &str) -> Refusal {
    match e {
        DialError::Response(_) | DialError::TooLarge { .. } => head_unreadable(format!("{read} served garbled: {e}")),
        other => Refusal::Unreachable(other),
    }
}

/// Returns `head_unreadable`: a signed write's signature could not be made.
///
/// Its face says the write was not sent, `why` the board's head record could
/// not be read as its cause — the record standing and not reading, a claimed
/// board serving none, or the board's answer to the read served garbled
/// (skep #728) — and that a held burst is resent once it reads.
fn head_unreadable(why: String) -> Refusal {
    Refusal::named(
        Name::HEAD_UNREADABLE,
        Face {
            state: "this write was not sent: its signature names the board's head record (`H.1`), which could not be read".to_string(),
            cause: why,
            act: "nothing was sent unsigned: a held burst is resent once the record reads again, and another write may be made again then; the record is the board's own, its operator's to repair — never your keys".to_string(),
            path: None,
        },
    )
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
    /// Runs the swap a session's end owes ([`Sessions::swap`]) with these
    /// supplements.
    ///
    /// It runs the swap here, inline, with `self` as the supplements: the
    /// feed thread's own path and every fake take it so. The call threads'
    /// supplements, a board's feed handle, override it to hand the swap to
    /// the feed thread as one command and wait (`feed`'s `Cmd::Ended`).
    fn ended(&mut self, sessions: &Sessions, ended: Ended, bus: &EventBus) {
        sessions.swap(ended, self, bus);
    }
}

/// A session's end, derived, and the swap it owes ([`Sessions::swap`]).
///
/// It is what [`Sessions::end`]'s initializer leaves for the supplements to
/// run: the dying entry, still in the table; the session re-opened in its
/// place on the restart arm, built and not yet entered; and the reason,
/// which names the re-opened reference as `session` where one is.
#[derive(Debug, Clone)]
pub struct Ended {
    pub dying: Arc<SessionEntry>,
    pub reopened: Option<Arc<SessionEntry>>,
    pub reason: Value,
}

/// How many of this run's ended references the table keeps with their
/// reasons: the newest, the oldest dropped.
pub const ENDED_KEPT: usize = 1024;

/// The table's two parts, under one lock.
struct Table {
    /// Every session that stands — an ending one among them, until its swap.
    live: HashMap<String, Arc<SessionEntry>>,
    /// This run's ended references with their reasons, the newest last.
    ended: VecDeque<(String, Value)>,
}

impl Table {
    /// Keeps `reference` as ended with `reason`, the oldest dropped past
    /// [`ENDED_KEPT`].
    fn keep(&mut self, reference: &str, reason: Value) {
        if self.ended.len() >= ENDED_KEPT {
            self.ended.pop_front();
        }
        self.ended.push_back((reference.to_string(), reason));
    }
}

/// The table, by reference, and the key store a death's derivation reads.
///
/// The store is the one the restart arm re-opens a session under — the
/// signed mode's, none under the bare mode, whose sessions no end re-opens
/// silently — and whose own keys name a retirement's own hand. Where a
/// death's derivation cannot list that store, it says so on the table's
/// `Talk` sink, the shell's own window and never the page (SP-12). The
/// table mints one run id at its birth and every session reference under it
/// (the module doc). Its `Debug` leaves out the sink, a closure, and counts
/// the ended references it keeps.
pub struct Sessions {
    table: Mutex<Table>,
    /// This run's id: eight hex every session reference carries (`refs`).
    run: String,
    reopen_store: Option<Arc<FileStore>>,
    talk: Talk,
}

impl fmt::Debug for Sessions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let table = self.table.lock().expect("the sessions' lock");
        f.debug_struct("Sessions").field("run", &self.run).field("live", &table.live).field("ended", &table.ended.len()).field("reopen_store", &self.reopen_store).finish_non_exhaustive()
    }
}

impl Sessions {
    /// Returns a table of no session, every end derived under `reopen_store`.
    ///
    /// What a death's derivation cannot read of that store is said on `talk`.
    /// The table mints its run id here: each shell opened is one run.
    pub fn new(reopen_store: Option<Arc<FileStore>>, talk: Talk) -> Sessions {
        Sessions { table: Mutex::new(Table { live: HashMap::new(), ended: VecDeque::new() }), run: run_id(), reopen_store, talk }
    }

    /// Returns this run's id, the eight hex every session reference of this
    /// table carries.
    pub fn run(&self) -> &str {
        &self.run
    }

    /// Returns the session `reference` names, where this shell holds one.
    ///
    /// An ending session is found here (the module doc): a call that finds
    /// one dials, meets the death and waits on its end.
    ///
    /// # Panics
    ///
    /// Panics where the sessions' lock is poisoned.
    pub fn get(&self, reference: &str) -> Option<Arc<SessionEntry>> {
        self.table.lock().expect("the sessions' lock").live.get(reference).cloned()
    }

    /// Returns the reason `reference`'s end carried, where this run ended it.
    ///
    /// It is the newest [`ENDED_KEPT`] ended references' (the module doc): a
    /// death's reason as derived, the re-opened reference named in it where
    /// one was, or a close's own arm; `None` for a reference still standing,
    /// one this run dropped from the ring, or one it never issued.
    ///
    /// # Panics
    ///
    /// Panics where the sessions' lock is poisoned.
    pub fn ended_reason(&self, reference: &str) -> Option<Value> {
        self.table.lock().expect("the sessions' lock").ended.iter().rev().find(|(r, _)| r == reference).map(|(_, reason)| reason.clone())
    }

    /// Returns every session standing at the board `board_reference` names,
    /// in no order.
    ///
    /// A session whose end is under way is left out (the module doc): the
    /// drafts reads, the resend, a re-emit and a supplement's release each
    /// serve a live session, and none goes out under a dying token.
    ///
    /// # Panics
    ///
    /// Panics where the sessions' lock is poisoned.
    pub fn on_board(&self, board_reference: &str) -> Vec<Arc<SessionEntry>> {
        self.table.lock().expect("the sessions' lock").live.values().filter(|e| e.board_reference == board_reference && !e.is_ending()).cloned().collect()
    }

    /// Returns every session in the table, in no order, an ending one among
    /// them.
    ///
    /// Its one caller is the shell's stop, which closes each; a close does
    /// nothing to an entry whose end is set.
    ///
    /// # Panics
    ///
    /// Panics where the sessions' lock is poisoned.
    pub fn all(&self) -> Vec<Arc<SessionEntry>> {
        self.table.lock().expect("the sessions' lock").live.values().cloned().collect()
    }

    /// Returns how many sessions stand in the table.
    ///
    /// # Panics
    ///
    /// Panics where the sessions' lock is poisoned.
    pub fn len(&self) -> usize {
        self.table.lock().expect("the sessions' lock").live.len()
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
    /// `OnceLock`, the entry still in the table and marked ending first, its
    /// reason is derived from public reads at its board; on the restart arm
    /// the re-opened session is built under a fresh reference at the same
    /// board, named in the reason as `session`, and not yet entered. Then the
    /// swap is handed to `supplements` ([`Supplements::ended`]): the table's
    /// two moves, the reason kept, `session-died`, and the re-opened token
    /// widened or the supplement released ([`Sessions::release`]) — narrow
    /// "at `session-died` in every arm but the shell's own restart"
    /// (`client.md` §4e.3) where no other session of the principal stands at
    /// the board, the supplement handed to one that does. A caller that finds
    /// the reason already derived answers it and does nothing else.
    ///
    /// # Panics
    ///
    /// Panics where `entry` is not in the table while its end is unset: an
    /// entry leaves the table by its swap or its close alone, each after its
    /// end is set.
    pub fn end(&self, entry: &SessionEntry, supplements: &mut dyn Supplements, bus: &EventBus) -> Value {
        let mut owed = None;
        let reason = entry
            .end
            .get_or_init(|| {
                entry.ending.store(true, Ordering::SeqCst);
                let dying = self.get(&entry.reference).expect("a session whose end is not yet derived stands in the table");
                let (reason, reopened) = match derive_death(self.reopen_store.as_deref(), &self.talk, entry) {
                    Death::Reason(reason) => (reason, None),
                    Death::Reopened(open) => {
                        let reopened = self.fresh(&entry.board_reference, Arc::clone(&entry.board), open);
                        (restart_reason(Some(&reopened.reference), None), Some(reopened))
                    }
                };
                owed = Some(Ended { dying, reopened, reason: reason.clone() });
                reason
            })
            .clone();
        if let Some(ended) = owed {
            supplements.ended(self, ended, bus);
        }
        reason
    }

    /// Runs the swap a session's end owes, with `supplements`.
    ///
    /// It is the one sequence every [`Supplements::ended`] reaches, in this
    /// order: the dying entry leaves the table and the re-opened one enters,
    /// the dying reference kept with its reason ([`Sessions::ended_reason`])
    /// — the three under one lock, so no read of the table falls between
    /// them; `session-died` `{session, reason}` goes out; then the re-opened
    /// token is widened, or the dying session's supplement released
    /// ([`Sessions::release`]). It runs on the board's feed thread for a
    /// death a call met, between the thread's rows, and inline for one the
    /// feed thread met (the module doc).
    pub fn swap<S: Supplements + ?Sized>(&self, ended: Ended, supplements: &mut S, bus: &EventBus) {
        let Ended { dying, reopened, reason } = ended;
        self.leave(&dying.reference, reopened.as_ref(), reason.clone());
        bus.emit(EventName::SessionDied, json!({"session": dying.reference, "reason": reason}));
        match &reopened {
            Some(r) => supplements.widen(r),
            None => self.release(&dying.board_reference, dying.facts.principal, supplements),
        }
    }

    /// Releases a principal's supplement at the board `board_reference` names.
    ///
    /// It is given up by a session that has left the table: the consumer
    /// holds one supplement per principal, so it is handed to another session
    /// of the principal standing there — that session's token widened in —
    /// and narrowed (`client.md` §4e.3's narrow) where none stands; an ending
    /// session never takes it ([`Sessions::on_board`]).
    pub fn release<S: Supplements + ?Sized>(&self, board_reference: &str, principal: u64, supplements: &mut S) {
        match self.on_board(board_reference).into_iter().find(|s| s.facts.principal == principal) {
            Some(standing) => supplements.widen(&standing),
            None => supplements.narrow(principal),
        }
    }

    /// Closes a session: the page's own close, or the shell's stop.
    ///
    /// The session's end is settled as the `closed` arm — waiting, as a
    /// second caller's `end` does, for a caller deriving another — and the
    /// session is out of the table, its reference kept with that arm
    /// ([`Sessions::ended_reason`]). It returns the entry, or `None` where
    /// this shell holds no session under `reference` any more — a death met
    /// first, or a close before.
    pub fn close(&self, reference: &str) -> Option<Arc<SessionEntry>> {
        let entry = self.get(reference)?;
        entry.end.set(closed()).ok()?;
        self.leave(reference, None, closed());
        Some(entry)
    }

    /// Takes `dying` out of the table, enters `reopened` where one is, and
    /// keeps `dying` as ended with `reason` — under one lock.
    ///
    /// It is the table's half of the swap, and a close's leave.
    ///
    /// # Panics
    ///
    /// Panics where the sessions' lock is poisoned.
    fn leave(&self, dying: &str, reopened: Option<&Arc<SessionEntry>>, reason: Value) {
        let mut table = self.table.lock().expect("the sessions' lock");
        table.live.remove(dying);
        if let Some(r) = reopened {
            table.live.insert(r.reference.clone(), Arc::clone(r));
        }
        table.keep(dying, reason);
    }

    /// Enters a session under a fresh reference, `board` beside its token.
    ///
    /// The session stands at the board `board_reference` names. It is the
    /// one place a registered session is paired with a board: `register`
    /// passes the pair read whole off a board's entry; the restart arm's
    /// re-open is built by [`Sessions::fresh`] off the session it replaces
    /// and entered at the swap.
    ///
    /// # Panics
    ///
    /// Panics where the sessions' lock is poisoned.
    fn enter(&self, board_reference: &str, board: Arc<Board>, open: Open) -> Arc<SessionEntry> {
        let entry = self.fresh(board_reference, board, open);
        self.table.lock().expect("the sessions' lock").live.insert(entry.reference.clone(), Arc::clone(&entry));
        entry
    }

    /// Builds a session's entry under a fresh reference of this run, at the
    /// board `board_reference` names, entering nothing.
    fn fresh(&self, board_reference: &str, board: Arc<Board>, open: Open) -> Arc<SessionEntry> {
        Arc::new(SessionEntry {
            reference: session_reference(&self.run),
            board_reference: board_reference.to_string(),
            board,
            token: open.token,
            facts: open.facts,
            opened_at: open.opened_at,
            ending: AtomicBool::new(false),
            end: OnceLock::new(),
        })
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

/// Why a session died: its reason, or the session re-opened in its place.
///
/// A session is re-opened silently on the restart arm, under a key this
/// store holds; its reason, the restart arm naming it, is composed where its
/// reference is minted ([`Sessions::end`]).
#[derive(Debug)]
enum Death {
    Reason(Value),
    Reopened(Open),
}

/// Returns the reason the page's own `close` carries: its own arm, `closed`.
pub fn closed() -> Value {
    json!({"arm": "closed"})
}

/// Returns the `unreachable` arm: the board did not answer, `text` the halt.
pub(crate) fn unreachable_reason(text: &str) -> Value {
    json!({"arm": "unreachable", "text": text})
}

/// Returns the `mode` arm: a bare session died at the flip to `mode`.
pub(crate) fn mode_reason(mode: Mode) -> Value {
    json!({"arm": "mode", "mode": mode.name()})
}

/// Returns the `restart` arm: `reopened` where `session` names the session
/// re-opened silently in the dying one's place, and `refused` the name of
/// the re-open's refusal where one was tried and refused.
pub(crate) fn restart_reason(session: Option<&str>, refused: Option<&str>) -> Value {
    let mut reason = json!({"arm": "restart", "reopened": session.is_some()});
    if let Some(session) = session {
        reason["session"] = Value::from(session);
    }
    if let Some(refused) = refused {
        reason["refused"] = Value::from(refused);
    }
    reason
}

/// Returns the `seeded` arm: a session by reference whose acted-as
/// `account` now holds a set of its own, `as_of` the set's position and
/// `writer` its first enrolled key.
pub(crate) fn seeded_reason(account: &str, as_of: u64, writer: Option<&str>) -> Value {
    json!({"arm": "seeded", "account": account, "as_of": as_of, "writer": writer})
}

/// Returns the `blocked` arm: the re-open met `403 prefix_blocked`, `record`
/// the block's record and `ground` its ground where read.
pub(crate) fn blocked_reason(record: &str, ground: Option<&str>) -> Value {
    json!({"arm": "blocked", "record": record, "ground": ground})
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
    let health = match board.health() {
        Ok(h) => h,
        Err(h) => return Death::Reason(unreachable_reason(&h.to_string())),
    };
    let mode = Mode::of(&health);
    let facts = &entry.facts;
    let SessionKind::Signed { fingerprint: fp, set_account } = &facts.kind else {
        if mode == Mode::Enforcing {
            return Death::Reason(mode_reason(mode));
        }
        return Death::Reason(restart_reason(None, None));
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
            return Death::Reason(retired_reason(fp, records.as_ref(), own_keys.as_deref()));
        }
    }
    // The seeded arm: a session by reference whose acted-as account now
    // holds a set of its own.
    if facts.by_reference() {
        if let Some(account) = facts.account.as_deref() {
            if let Ok(KeySetAnswer::Set(set)) = board.key_set(account) {
                if !set.is_empty() {
                    let writer = set.enrolled.first().map(|e| e.fingerprint.to_string());
                    return Death::Reason(seeded_reason(account, set.as_of, writer.as_deref()));
                }
            }
        }
    }
    // The restart arm, or the block met at the re-open.
    let Some(store) = store else { return Death::Reason(restart_reason(None, None)) };
    match open_signed(board, store, facts.principal) {
        Ok(open) => Death::Reopened(open),
        Err(Refusal::Blocked(b)) => Death::Reason(blocked_reason(&b.record, b.ground.as_deref())),
        Err(other) => Death::Reason(restart_reason(None, Some(other.name()))),
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
pub(crate) fn retired_reason(fp: &Fingerprint, records: Option<&Records>, own_keys: Option<&[(Fingerprint, PublicKey)]>) -> Value {
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
