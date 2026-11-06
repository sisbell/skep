//! The follower write of `client.md` §3c.6 — a `make_link` or a `nullify`
//! the page hands the shell with the burst it waits on, the `op` row's
//! `after` (§4b.1) — reached from the `op` row alone: a formatting chord
//! pressed while the burst before it is unanswered, its mark drawn at once,
//! is written at the burst's ack (B3-S13's row rule; D6 BM-61), and at the
//! shell's stop it is finished behind the window as the burst is, never
//! lost with the page that held it.
//!
//! **The bursts kept.** Every burst the `op` row sends under a session with
//! a string `id` of at most [`MAX_BURST_ID_BYTES`] bytes — the wire's
//! per-session idempotency key — is entered in that session's table before
//! it is dialed, and its outcome after its answer ([`Followers::sent`]): in
//! flight, acked, or not acked with the hold's cause or the refusal's name.
//! An insert's entry keeps the positions its frame mints, and the I-address
//! its ack names, the first it minted (wire.md §Arrangement, `insert`): an
//! insert is the one burst whose ack names its words. A session's table
//! keeps its newest [`BURSTS_KEPT`] answered bursts, and beside them every
//! burst in flight or followed (SP-17); it goes at the session's
//! `session-died` ([`Followers::ended`]).
//!
//! **The follower** ([`Follower::of`], read at the row's door): `after`
//! names the `id` of a burst the session sent, on a `make_link` or a
//! `nullify` alone; and a PIECE — `{"burst", "offset", "width"}` beside the
//! spans of a `make_link`'s `from` or `to` in the I-span form — names
//! `width` positions of that burst's own words from its `offset`, positions
//! as the board seats them: a byte of a text, one an atom. The follower
//! waits for the burst's answer, then for every follower of the burst that
//! came before it ([`Followers::follow`]), and then:
//!
//! * the burst acked: its frame, each piece resolved to the I-span
//!   `{"start": <the ack's I-address advanced by offset>, "width":
//!   "<width>"}`, goes by the one path every session write takes, and the
//!   call is answered with the follower's own answer;
//! * the burst not acked — held, or refused: `not_followed`, `why: "burst"`
//!   with the burst's cause, nothing dialed and nothing held, a link write
//!   being none of the held kinds;
//! * a follower of the burst before it not acked: `not_followed`, `why:
//!   "ahead"` — a chord's writes are one step (D6 BM-69), so no step lands
//!   half.
//!
//! A burst answered before its follower arrives is followed from its kept
//! outcome: the page hands a write over while it has not seen the ack, not
//! while the board has not given it. A follower whose burst is not yet in
//! the table waits [`BURST_ARRIVAL_WAIT`] for it — no transport keeps two
//! calls of one page in order — and is refused `no_such_burst` after.
//!
//! **The stop.** [`Followers::drain`] runs at the shell's stop before any
//! session closes (§3c.6 step (2)): it waits until every follower handed
//! over has its answer — its burst's dial, then its own — or for
//! [`FOLLOW_AT_STOP`], and then answers each one still waiting
//! `not_followed`, `why: "stop"`, as it answers every follower after it. A
//! crash loses a burst's followers with the burst.
//!
//! Each `not_followed` is said in the shell's own window as it is answered,
//! since the page that asked may be gone (SP-12).

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use skep_client::address::is_address_text;
use skep_client::dial::{CONNECT_TIMEOUT, IO_TIMEOUT};
use skep_client::sheet::render_inert;

use crate::hold::is_burst;
use crate::refusal::{Name, Refusal};
use crate::wire::values_of;
use crate::Talk;

/// The longest burst `id` a session's table keeps, and the longest `after`.
///
/// In bytes. A burst whose `id` is longer is sent as any burst is and kept
/// nowhere, and an `after` past it is refused at the row's door.
pub(super) const MAX_BURST_ID_BYTES: usize = 128;

/// The answered bursts a session's table keeps, the newest.
///
/// A follower names one of the page's last few bursts — the board commits
/// one at a time (§7b) — so the table keeps this many beside every burst in
/// flight or followed, which it never lets go.
const BURSTS_KEPT: usize = 64;

/// How long a follower waits for its burst to reach the table.
///
/// The page sends the burst, then its follower; two calls cross a transport
/// in no promised order, so a follower that overtakes its burst waits this
/// long for it before it is refused `no_such_burst`.
const BURST_ARRIVAL_WAIT: Duration = Duration::from_secs(1);

/// How long the shell's stop waits for the followers handed over.
///
/// It is two exchanges at the dialer's own bounds, a connect and a read's
/// wait each — the burst's, then its follower's (§3c.6 step (2), whose bound
/// is the dialer's until S2 reports): a board that does not answer is cut
/// off within it.
pub(super) const FOLLOW_AT_STOP: Duration = Duration::from_secs(2 * (CONNECT_TIMEOUT.as_secs() + IO_TIMEOUT.as_secs()));

/// One slot a piece may stand in: a `make_link`'s `from` or `to`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Slot {
    From,
    To,
}

impl Slot {
    /// Returns the slot as the frame spells it.
    fn name(self) -> &'static str {
        match self {
            Slot::From => "from",
            Slot::To => "to",
        }
    }

    /// Returns the member a refusal of the slot names.
    fn what(self) -> &'static str {
        match self {
            Slot::From => "frame.from",
            Slot::To => "frame.to",
        }
    }
}

/// A piece of a follower's end: `width` positions of the burst's words.
///
/// They run from the burst's `offset`-th position, counted from 0; the piece
/// stands at `index` among its slot's spans.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Piece {
    slot: Slot,
    index: usize,
    offset: u64,
    width: u64,
}

/// A follower write as the `op` row's door read it (SP-18).
///
/// It is the `id` of the burst it follows and the pieces of its ends, in
/// the order the frame holds them. Made by [`Follower::of`] alone, so every
/// follower the table waits on is one the door checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Follower {
    after: String,
    pieces: Vec<Piece>,
}

impl Follower {
    /// Returns the follower the `op` row's session form names, where one is.
    ///
    /// `frame` is the row's frame and `at` its position where the page sent
    /// the `/op-at` form. An `after` absent or `null` names none; then the
    /// frame is a follower of nothing, and a piece in it is refused below.
    ///
    /// # Errors
    ///
    /// In this order, each `malformed_args`:
    ///
    /// 1. naming `after` where it is present and no string of at most
    ///    [`MAX_BURST_ID_BYTES`] bytes;
    /// 2. naming `after` where it rides an `/op-at` frame, which reads and
    ///    follows nothing, or a frame that is no `make_link` and no
    ///    `nullify`;
    /// 3. for a `make_link` or a `nullify`, at the first member of the frame
    ///    in key order where a piece — an object with a `burst` member — is
    ///    not of its place and form: naming the member (`frame.from`,
    ///    `frame.to`, `frame.ty`, or another) where the piece stands anywhere
    ///    but among the spans of a `make_link`'s `from` or `to` in the I-span
    ///    form; naming the slot where its members are other than `burst`,
    ///    `offset` and `width`, its `burst` no string, its `offset` no
    ///    natural or its `width` no natural of 1 or more, or its `burst` not
    ///    the `after` given; naming `after` where no `after` is given.
    pub(super) fn of(args: &Value, frame: &Value, at: Option<u64>) -> Result<Option<Follower>, Refusal> {
        let after = match args.get("after") {
            None | Some(Value::Null) => None,
            Some(v) => Some(v.as_str().filter(|id| id.len() <= MAX_BURST_ID_BYTES).ok_or_else(|| Refusal::malformed("after"))?),
        };
        let op = frame["op"].as_str().unwrap_or("");
        let followable = matches!(op, "make_link" | "nullify");
        if after.is_some() && (at.is_some() || !followable) {
            return Err(Refusal::malformed("after"));
        }
        let mut pieces = Vec::new();
        if followable {
            for (member, value) in frame.as_object().into_iter().flatten() {
                let slot = match (op, member.as_str()) {
                    ("make_link", "from") => Some(Slot::From),
                    ("make_link", "to") => Some(Slot::To),
                    _ => None,
                };
                match (slot, ispans(value)) {
                    (Some(slot), Some(spans)) => {
                        for (index, span) in spans.iter().enumerate() {
                            if span.get("burst").is_some() {
                                pieces.push(piece(span, slot, index, after)?);
                            } else if holds_piece(span) {
                                return Err(Refusal::malformed(slot.what()));
                            }
                        }
                    }
                    _ if holds_piece(value) => return Err(Refusal::malformed(format!("frame.{member}"))),
                    _ => {}
                }
            }
        }
        Ok(after.map(|after| Follower { after: after.to_string(), pieces }))
    }
}

/// Returns the spans of a slot in the I-span form, `{"spans": […]}`.
///
/// It answers none where the slot is of another form, or where a member
/// beside its list holds a piece, which stands nowhere a piece may.
fn ispans(slot: &Value) -> Option<&Vec<Value>> {
    let members = slot.as_object()?;
    let spans = members.get("spans")?.as_array()?;
    members.iter().all(|(member, value)| member == "spans" || !holds_piece(value)).then_some(spans)
}

/// Returns whether `v` holds a piece at any depth: an object with `burst`.
fn holds_piece(v: &Value) -> bool {
    match v {
        Value::Object(members) => members.contains_key("burst") || members.values().any(holds_piece),
        Value::Array(items) => items.iter().any(holds_piece),
        _ => false,
    }
}

/// Returns the piece `v` spells, at `index` among `slot`'s spans.
///
/// # Errors
///
/// Returns `malformed_args` naming the slot where the piece is not
/// `{burst, offset, width}` alone, each of its form, or where `burst` is not
/// `after`; and naming `after` where none is given.
fn piece(v: &Value, slot: Slot, index: usize, after: Option<&str>) -> Result<Piece, Refusal> {
    let malformed = || Refusal::malformed(slot.what());
    let members = v.as_object().filter(|members| members.len() == 3).ok_or_else(malformed)?;
    let burst = members.get("burst").and_then(Value::as_str).ok_or_else(malformed)?;
    let offset = members.get("offset").and_then(Value::as_u64).ok_or_else(malformed)?;
    let width = members.get("width").and_then(Value::as_u64).filter(|w| *w >= 1).ok_or_else(malformed)?;
    match after {
        None => Err(Refusal::malformed("after")),
        Some(after) if after == burst => Ok(Piece { slot, index, offset, width }),
        Some(_) => Err(malformed()),
    }
}

/// The first I-address an insert minted, split at its last component.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Minted {
    prefix: String,
    first: u64,
}

impl Minted {
    /// Returns the address an insert's ack names, split, where it reads.
    fn of(addr: &str) -> Option<Minted> {
        let (prefix, last) = addr.rsplit_once('.').filter(|_| is_address_text(addr))?;
        Some(Minted { prefix: prefix.to_string(), first: last.parse().ok()? })
    }

    /// Returns the I-span a piece names, where its start is spellable.
    ///
    /// It is `width` positions from the minted address advanced by
    /// `offset`, in the wire's I-span form (wire.md §Links (writes)).
    fn span(&self, piece: Piece) -> Option<Value> {
        let start = self.first.checked_add(piece.offset)?;
        Some(json!({"start": format!("{}.{start}", self.prefix), "width": piece.width.to_string()}))
    }
}

/// What a kept burst's call answered, as its followers read it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {
    /// Its call has not answered.
    InFlight,
    /// Acked: an insert's minted address where its ack names one that reads.
    Acked(Option<Minted>),
    /// Not acked: held under the hold's cause, or refused under its name.
    NotAcked(String),
}

impl Outcome {
    /// Returns the outcome of a burst's answer; an insert's names its words.
    fn of(answer: &Result<Value, Refusal>, insert: bool) -> Outcome {
        match answer {
            Ok(v) if v["resp"] == "held" => Outcome::NotAcked(v["cause"].as_str().unwrap_or("held").to_string()),
            Ok(v) => Outcome::Acked(v["addr"].as_str().filter(|_| insert).and_then(Minted::of)),
            Err(refusal) => Outcome::NotAcked(refusal.name().to_string()),
        }
    }
}

/// One burst a session's table keeps.
///
/// `issued` and `served` are the followers' turns — handed out in arrival
/// order, `served` the one whose turn it is — and `holders` the followers
/// holding one, none of which the table lets go of the burst before.
/// `broken` is whether a follower of it ended unacked.
#[derive(Debug)]
struct Kept {
    serial: u64,
    id: String,
    /// The positions an insert's frame mints; none for any other kind.
    positions: Option<u64>,
    outcome: Outcome,
    issued: u64,
    served: u64,
    holders: usize,
    broken: bool,
}

/// One session's table: its bursts kept, oldest first, and its followers.
///
/// `waiting` counts the followers inside [`Followers::follow`] for the
/// session — waiting for their burst to arrive, holding a turn, or dialing
/// — and `ended` is whether the session ended under them.
#[derive(Debug, Default)]
struct Table {
    bursts: VecDeque<Kept>,
    waiting: usize,
    ended: bool,
}

impl Table {
    /// Lets go of the oldest answered bursts past [`BURSTS_KEPT`].
    ///
    /// A burst in flight, or one a follower holds a turn of, is kept beside
    /// them and counts toward none.
    fn trim(&mut self) {
        let free = |kept: &Kept| kept.outcome != Outcome::InFlight && kept.holders == 0;
        let mut excess = self.bursts.iter().filter(|kept| free(kept)).count().saturating_sub(BURSTS_KEPT);
        self.bursts.retain(|kept| {
            let goes = excess > 0 && free(kept);
            excess -= usize::from(goes);
            !goes
        });
    }

    /// Returns the kept burst of `serial`.
    ///
    /// # Panics
    ///
    /// Panics where none is kept: a burst a follower holds a turn of is let
    /// go only at the session's end, which the follower reads first.
    fn kept(&mut self, serial: u64) -> &mut Kept {
        self.bursts.iter_mut().find(|kept| kept.serial == serial).expect("a burst a follower holds a turn of is kept until its session ends")
    }
}

/// The table's stand to the shell's stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stop {
    Running,
    /// The stop waits on the followers handed over ([`Followers::drain`]).
    Draining,
    /// The stop's wait is over: every follower waiting, or arriving, is
    /// refused `stop`.
    Closed,
}

/// The tables, by session reference, and the stop.
#[derive(Debug)]
struct State {
    tables: HashMap<String, Table>,
    stop: Stop,
    next_serial: u64,
}

impl State {
    /// Leaves a follower of `session`: its turn of `held`'s burst ended,
    /// `acked` where its own dial was acked.
    ///
    /// The turn passes to the follower after it where the turn was this
    /// one's, the burst is `broken` where the follower was not acked, and
    /// the session's table goes once no follower waits in it and it keeps
    /// no burst.
    fn leave(&mut self, session: &str, held: Option<(u64, u64)>, acked: bool) {
        let Some(table) = self.tables.get_mut(session) else { return };
        if let Some((serial, ticket)) = held {
            if let Some(kept) = table.bursts.iter_mut().find(|kept| kept.serial == serial) {
                kept.holders -= 1;
                if kept.served == ticket {
                    kept.served += 1;
                }
                kept.broken |= !acked;
            }
        }
        table.waiting -= 1;
        if table.waiting == 0 && table.bursts.is_empty() {
            self.tables.remove(session);
        }
    }

    /// Returns how many followers wait, in every session's table.
    fn waiting(&self) -> usize {
        self.tables.values().map(|table| table.waiting).sum()
    }
}

/// Why a follower is refused `not_followed`, as its detail's `why` says.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Why {
    /// The burst was not acked: the hold's cause, or the refusal's name.
    Burst(String),
    /// A follower of the burst before it was not acked.
    Ahead,
    /// The burst's ack names no I-address its pieces resolve against.
    Ack,
    /// The shell's stop came before the burst's answer.
    Stop,
}

/// What [`Followers::follow`] answered a follower.
#[derive(Debug)]
pub(super) enum Followed {
    /// Its own answer, or its refusal.
    Answered(Result<Value, Refusal>),
    /// Its session ended while it waited: the call answers as a call on an
    /// ended session does.
    Ended,
}

/// A burst the `op` row is sending, kept for its followers.
///
/// Its outcome is set by [`SentBurst::settle`] from the call's answer, and
/// read by every follower as it is set; dropped unsettled — the call
/// unwound — the burst is not acked, `unanswered`, so no follower waits on
/// it for ever.
#[must_use = "the burst's followers wait on the outcome `SentBurst::settle` sets"]
pub(super) struct SentBurst<'a> {
    followers: &'a Followers,
    session: String,
    serial: u64,
    insert: bool,
    outcome: Option<Outcome>,
}

impl SentBurst<'_> {
    /// Sets the burst's outcome from the answer its call gives.
    pub(super) fn settle(mut self, answer: &Result<Value, Refusal>) {
        self.outcome = Some(Outcome::of(answer, self.insert));
    }
}

impl Drop for SentBurst<'_> {
    fn drop(&mut self) {
        let outcome = self.outcome.take().unwrap_or_else(|| Outcome::NotAcked("unanswered".to_string()));
        let mut state = self.followers.lock();
        if let Some(table) = state.tables.get_mut(&self.session) {
            if let Some(kept) = table.bursts.iter_mut().find(|kept| kept.serial == self.serial) {
                kept.outcome = outcome;
            }
            table.trim();
        }
        drop(state);
        self.followers.moved.notify_all();
    }
}

/// A follower's turn while its write is dialed, outside the table's lock.
///
/// Dropped — the dial answered, or unwound — the follower leaves the table
/// ([`State::leave`]), `acked` where its answer was.
struct Seat<'a> {
    followers: &'a Followers,
    session: &'a str,
    serial: u64,
    ticket: u64,
    acked: bool,
}

impl Drop for Seat<'_> {
    fn drop(&mut self) {
        self.followers.lock().leave(self.session, Some((self.serial, self.ticket)), self.acked);
        self.followers.moved.notify_all();
    }
}

/// The bursts every session sent, kept for their followers, and the
/// followers waiting on them.
///
/// One lock and one condition over every table: a burst's outcome, a
/// follower's leaving, a session's end and the stop each wake every waiter,
/// which reads its own state again. The lock guards bookkeeping alone and is
/// never held across a dial; a panic under it leaves that bookkeeping whole,
/// so the lock is taken past a poisoning and a guard's drop never panics.
pub(super) struct Followers {
    state: Mutex<State>,
    moved: Condvar,
    talk: Talk,
}

impl Followers {
    /// Returns an empty table, its `not_followed` lines said on `talk`.
    pub(super) fn new(talk: Talk) -> Followers {
        Followers { state: Mutex::new(State { tables: HashMap::new(), stop: Stop::Running, next_serial: 0 }), moved: Condvar::new(), talk }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Waits on the condition until it is told, or until `deadline`.
    fn wait<'s>(&self, state: MutexGuard<'s, State>, deadline: Option<Instant>) -> MutexGuard<'s, State> {
        match deadline {
            None => self.moved.wait(state).unwrap_or_else(PoisonError::into_inner),
            Some(deadline) => self.moved.wait_timeout(state, deadline.saturating_duration_since(Instant::now())).unwrap_or_else(PoisonError::into_inner).0,
        }
    }

    /// Enters a burst the `op` row is about to send under `session`.
    ///
    /// It is entered where its frame is one of the five kinds and carries a
    /// string `id` of at most [`MAX_BURST_ID_BYTES`] bytes, and the session's
    /// table has not ended; `stands`, asked once it is entered, says whether
    /// the session still stands, and a table entered for a session ended
    /// under the call is let go. None is answered where the burst is kept
    /// nowhere. Every follower waiting for a burst of its `id` is woken.
    pub(super) fn sent(&self, session: &str, frame: &Value, stands: impl Fn() -> bool) -> Option<SentBurst<'_>> {
        let id = frame["id"].as_str().filter(|id| id.len() <= MAX_BURST_ID_BYTES && is_burst(frame))?;
        let insert = frame["op"] == "insert";
        let positions = if insert { values_of(&frame["values"]).ok().map(|values| values.len() as u64) } else { None };
        let mut state = self.lock();
        let serial = state.next_serial;
        state.next_serial += 1;
        let table = state.tables.entry(session.to_string()).or_default();
        if table.ended {
            return None;
        }
        table.bursts.push_back(Kept { serial, id: id.to_string(), positions, outcome: Outcome::InFlight, issued: 0, served: 0, holders: 0, broken: false });
        table.trim();
        drop(state);
        self.moved.notify_all();
        if !stands() {
            self.ended(session);
            return None;
        }
        Some(SentBurst { followers: self, session: session.to_string(), serial, insert, outcome: None })
    }

    /// Answers a follower once its burst is answered (the module doc).
    ///
    /// `frame` is its write and `dial` sends it by the one path every
    /// session write takes, answering the follower's own answer; `stands`
    /// says whether `session` still stands, asked where no burst arrived.
    ///
    /// # Errors
    ///
    /// In this order, each as [`Followed::Answered`]'s refusal:
    ///
    /// 1. `not_followed`, `why: "stop"`, where the shell's stop has ended
    ///    its wait ([`Followers::drain`]);
    /// 2. `no_such_burst` naming `after` where no burst of its `id` reaches
    ///    the session's table within [`BURST_ARRIVAL_WAIT`] — or
    ///    [`Followed::Ended`] where the session no longer stands;
    /// 3. `malformed_args` naming the slot of the first piece where the
    ///    burst names no positions — it is no insert, or an insert whose
    ///    `values` are not the wire's forms — or the slot of the first piece
    ///    past the insert's positions;
    /// 4. once the burst is answered and every follower before it has left:
    ///    `not_followed` with `why: "burst"` and the burst's cause where it
    ///    was not acked, `why: "ahead"` where a follower before it was not,
    ///    `why: "ack"` where the ack names no I-address its pieces resolve
    ///    against, and `why: "stop"` where the stop's wait ended first;
    /// 5. the dial's own answer.
    ///
    /// [`Followed::Ended`] answers where the session ended while it waited.
    pub(super) fn follow(&self, session: &str, follower: Follower, frame: Value, stands: impl Fn() -> bool, dial: impl FnOnce(Value) -> Result<Value, Refusal>) -> Followed {
        let Follower { after, pieces } = follower;
        let refused = |why: Why| Followed::Answered(Err(self.not_followed(&after, why)));
        let mut state = self.lock();
        if state.stop == Stop::Closed {
            drop(state);
            return refused(Why::Stop);
        }
        state.tables.entry(session.to_string()).or_default().waiting += 1;
        // The burst's arrival.
        let arrival = Instant::now() + BURST_ARRIVAL_WAIT;
        let serial = loop {
            let stop = state.stop;
            let table = state.tables.get(session).expect("a follower's own count keeps its table");
            let found = table.bursts.iter().rev().find(|kept| kept.id == after).map(|kept| kept.serial);
            match (table.ended, stop, found) {
                (true, _, _) => return self.left(state, session, None, || Followed::Ended),
                (_, Stop::Closed, _) => return self.left(state, session, None, || refused(Why::Stop)),
                (_, _, Some(serial)) => break serial,
                _ if Instant::now() >= arrival => {
                    let unknown = || Followed::Answered(Err(Refusal::shell(Name::NO_SUCH_BURST, json!({"after": after}))));
                    return self.left(state, session, None, || if stands() { unknown() } else { Followed::Ended });
                }
                _ => state = self.wait(state, Some(arrival)),
            }
        };
        // The pieces against the burst, then the follower's turn.
        let table = state.tables.get_mut(session).expect("a follower's own count keeps its table");
        let kept = table.kept(serial);
        let unnamed = match (pieces.first(), kept.positions) {
            (None, _) => None,
            (Some(first), None) => Some(first.slot),
            (Some(_), Some(positions)) => pieces.iter().find(|p| p.offset.checked_add(p.width).is_none_or(|end| end > positions)).map(|p| p.slot),
        };
        if let Some(slot) = unnamed {
            return self.left(state, session, None, || Followed::Answered(Err(Refusal::malformed(slot.what()))));
        }
        let ticket = kept.issued;
        kept.issued += 1;
        kept.holders += 1;
        let held = Some((serial, ticket));
        let minted = loop {
            let stop = state.stop;
            let table = state.tables.get_mut(session).expect("a follower's own count keeps its table");
            if table.ended {
                return self.left(state, session, held, || Followed::Ended);
            }
            if stop == Stop::Closed {
                return self.left(state, session, held, || refused(Why::Stop));
            }
            let kept = table.kept(serial);
            if kept.served == ticket {
                let why = match &kept.outcome {
                    Outcome::InFlight => None,
                    Outcome::NotAcked(cause) => Some(Why::Burst(cause.clone())),
                    Outcome::Acked(_) if kept.broken => Some(Why::Ahead),
                    Outcome::Acked(minted) => break minted.clone(),
                };
                if let Some(why) = why {
                    return self.left(state, session, held, || refused(why));
                }
            }
            state = self.wait(state, None);
        };
        drop(state);
        let mut seat = Seat { followers: self, session, serial, ticket, acked: false };
        let Some(frame) = resolved(frame, &pieces, minted.as_ref()) else {
            drop(seat);
            return refused(Why::Ack);
        };
        let answer = dial(frame);
        seat.acked = answer.is_ok();
        drop(seat);
        Followed::Answered(answer)
    }

    /// Leaves a follower unacked ([`State::leave`]) and wakes every waiter,
    /// then answers what `followed` makes, outside the lock.
    fn left(&self, mut state: MutexGuard<'_, State>, session: &str, held: Option<(u64, u64)>, followed: impl FnOnce() -> Followed) -> Followed {
        state.leave(session, held, false);
        drop(state);
        self.moved.notify_all();
        followed()
    }

    /// Waits for every follower handed over, until `deadline`: the stop.
    ///
    /// It answers once no follower waits, or at `deadline`, from which on
    /// every follower still waiting — and every one that arrives after — is
    /// refused `not_followed`, `why: "stop"`; one already dialing is left to
    /// its dial, and the number still under way at the deadline is said in
    /// the shell's own window. A second drain finds the wait over.
    pub(super) fn drain(&self, deadline: Instant) {
        let mut state = self.lock();
        if state.stop == Stop::Closed {
            return;
        }
        state.stop = Stop::Draining;
        while state.waiting() > 0 && Instant::now() < deadline {
            state = self.wait(state, Some(deadline));
        }
        let under_way = state.waiting();
        state.stop = Stop::Closed;
        drop(state);
        self.moved.notify_all();
        if under_way > 0 {
            self.say(format_args!(
                "stop: {under_way} write(s) handed over with their bursts were still under way at the stop's {} s bound; each still waiting is refused `not_followed`, and the sessions close under the rest",
                FOLLOW_AT_STOP.as_secs()
            ));
        }
    }

    /// Lets go of `session`'s table: the session ended.
    ///
    /// Every follower waiting in it answers [`Followed::Ended`], and no burst
    /// of the session is entered after.
    pub(super) fn ended(&self, session: &str) {
        let mut state = self.lock();
        if let Some(table) = state.tables.get_mut(session) {
            table.ended = true;
            table.bursts.clear();
            if table.waiting == 0 {
                state.tables.remove(session);
            }
        }
        drop(state);
        self.moved.notify_all();
    }

    /// Returns the `not_followed` refusal for `why`, said in the shell's own
    /// window as it is answered (SP-12): the page that asked may be gone.
    ///
    /// The burst's `id` and the board's cause are rendered inert (SP-20).
    fn not_followed(&self, after: &str, why: Why) -> Refusal {
        let (token, cause, words) = match &why {
            Why::Burst(cause) => ("burst", Some(cause.as_str()), format!("its burst was not acked (`{}`)", render_inert(cause))),
            Why::Ahead => ("ahead", None, "a write after the same burst before it was not acked, and a chord's writes are one step".to_string()),
            Why::Ack => ("ack", None, "its burst's ack names no I-address its pieces resolve against".to_string()),
            Why::Stop => ("stop", None, "the shell's stop came before its burst's answer".to_string()),
        };
        self.say(format_args!("op: the write after burst `{}` was not sent: {words}; nothing of it was written", render_inert(after)));
        let mut detail = json!({"after": after, "why": token});
        if let Some(cause) = cause {
            detail["cause"] = Value::from(cause);
        }
        Refusal::shell(Name::NOT_FOLLOWED, detail)
    }

    /// Says `line` on `Talk`.
    fn say(&self, line: impl fmt::Display) {
        (self.talk)(&line.to_string());
    }

    /// Returns how many followers wait, in every session's table.
    #[cfg(test)]
    pub(super) fn waiting(&self) -> usize {
        self.lock().waiting()
    }

    /// Returns whether the stop's wait on the followers has begun: under way,
    /// or over.
    #[cfg(test)]
    pub(super) fn stopping(&self) -> bool {
        self.lock().stop != Stop::Running
    }

    /// Returns the `id`s `session`'s table keeps, oldest first.
    #[cfg(test)]
    fn kept_ids(&self, session: &str) -> Vec<String> {
        self.lock().tables.get(session).map(|table| table.bursts.iter().map(|kept| kept.id.clone()).collect()).unwrap_or_default()
    }
}

/// Returns a follower's frame, each piece resolved against `minted`.
///
/// It answers the frame as it stands where it holds no piece; none where a
/// piece stands and the burst's ack named no address, or a piece's start is
/// past what an address spells.
fn resolved(mut frame: Value, pieces: &[Piece], minted: Option<&Minted>) -> Option<Value> {
    for piece in pieces {
        let span = minted?.span(*piece)?;
        *frame.get_mut(piece.slot.name())?.get_mut("spans")?.get_mut(piece.index)? = span;
    }
    Some(frame)
}

#[cfg(test)]
mod tests;
