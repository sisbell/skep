//! The follower write of `client.md` §3c.6 — a `make_link`, a `nullify` or
//! a `delete` the page hands the shell with the burst it waits on, the `op`
//! row's `after` (§4b.1) — reached from the `op` row alone: a formatting
//! chord pressed while the burst before it is unanswered, its mark drawn at
//! once, is written at the burst's ack (B3-S13's row rule; D6 BM-61), and so
//! is an undo's `delete` of the burst's own words pressed in that interval
//! (D6 BM-34, BM-73); at the shell's stop each is finished behind the window
//! as the burst is, never lost with the page that held it (SWEEP 11 CLOSE
//! C8 (a)).
//!
//! **The bursts kept.** Every burst the `op` row sends under a session with
//! a string `id` of at most [`MAX_BURST_ID_BYTES`] bytes — the wire's
//! per-session idempotency key — is entered in that session's table before
//! it is dialed, and its outcome after its answer ([`Followers::sent`]): in
//! flight, acked, or not acked with the hold's cause or the refusal's name.
//! An entry keeps its burst's document; an insert's keeps the positions its
//! frame mints, and the I-address its ack names, the first it minted in its
//! document's own content I-space (wire.md §Arrangement, `insert`), read by
//! the hold's one reader of it (`hold::minted_on`): an insert is the one
//! burst whose ack names its words. A session's table keeps its newest
//! [`BURSTS_KEPT`] answered bursts, and beside them every burst in flight or
//! followed (SP-17); it goes at the session's `session-died`
//! ([`Followers::ended`]).
//!
//! **The follower** ([`Follower::of`], read at the row's door): `after`
//! names the `id` of a burst the session sent, on a `make_link`, a `nullify`
//! or a `delete` alone. A PIECE names words of that burst's own, in
//! positions as the board seats them — a byte of a text, one an atom:
//! `{"burst", "offset", "width"}`, beside the spans of a `make_link`'s
//! `from` or `to` in the I-span form or beside the runs of a delete's
//! anchors' `span`, names `width` positions from its `offset`, and a
//! delete's `before` or `after` anchor in the piece form `{"burst",
//! "offset"}` (skep #969) names the one at its `offset`. The follower waits
//! for the burst's answer, then for every follower of the burst that came
//! before it ([`Followers::follow`]), and then:
//!
//! * the burst acked: its frame and its anchors — each piece resolved
//!   against the first I-address the ack names, advanced by its offset, to
//!   the I-span `{"start", "width": "<width>"}` or, at an anchor, to that
//!   I-address — go by the one path every session write takes, so a delete
//!   the board refuses as typed against an older state is shifted by them,
//!   and the call is answered with the follower's own answer, a delete's
//!   `held` where the hold holds it;
//! * the burst not acked — held, or refused: `not_followed`, `why: "burst"`
//!   with the burst's cause, nothing dialed and nothing held, a link write
//!   being none of the held kinds and a delete held behind no line of words
//!   the board may never have had (D6 BM-81);
//! * a follower of the burst before it not acked — refused, or held:
//!   `not_followed`, `why: "ahead"` — a chord's writes are one step (D6
//!   BM-69), so no step lands half.
//!
//! A burst answered before its follower arrives is followed from its kept
//! outcome: the page hands a write over while it has not seen the ack, not
//! while the board has not given it. A follower whose burst is not yet in
//! the table waits [`BURST_ARRIVAL_WAIT`] for it — no transport keeps two
//! calls of one page in order — and is refused `no_such_burst` after.
//!
//! **The close.** The page's close of a session (§4b.1's `close` row) is
//! entered in the session's table for as long as it runs
//! ([`Followers::closing`]), and waits there before it sends the frames it
//! carries (SWEEP 11 CLOSE C8 (a)): first for each burst its `after` names,
//! until that burst's call answers whatever it answers — an `id` no burst of
//! reaches the table within [`BURST_ARRIVAL_WAIT`] of the close is waited
//! for no longer ([`Closing::bursts`]) — then until no follower of the
//! session waits, for at most [`FOLLOW_AT_STOP`] ([`Closing::followers`]);
//! and once its frames are sent, for the followers again before it ends the
//! session. So the words the page handed over before its close are written
//! or held before the close's own, and a follower is never ended by the
//! close the same page asked for (§3c.6). Each wait ends where the session
//! ends or the stop's wait is over.
//!
//! **The stop.** [`Followers::drain`] runs at the shell's stop before any
//! session closes (§3c.6 step (2)): it waits until every follower handed
//! over has its answer — its burst's dial, then its own — and every close
//! under way has ended its session, or for [`FOLLOW_AT_STOP`], and then
//! answers each follower still waiting `not_followed`, `why: "stop"`, as it
//! answers every follower after it. A crash loses a burst's followers with
//! the burst.
//!
//! Each `not_followed` is said in the shell's own window as it is answered,
//! since the page that asked may be gone (SP-12).

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use skep_client::dial::{CONNECT_TIMEOUT, IO_TIMEOUT};
use skep_client::sheet::render_inert;

use crate::held::{i_address, Anchor, Anchors, MAX_ANCHOR_BYTES, MAX_BURST_ID_BYTES};
use crate::hold::{is_burst, minted_on};
use crate::refusal::{Name, Refusal};
use crate::wire::{json_len, values_of};
use crate::Talk;

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
/// long for it before it is refused `no_such_burst`, and the page's close
/// this long for a burst its `after` names ([`Closing::bursts`]).
pub(super) const BURST_ARRIVAL_WAIT: Duration = Duration::from_secs(1);

/// How long the shell's stop waits for the followers handed over.
///
/// It is two exchanges at the dialer's own bounds, a connect and a read's
/// wait each — the burst's, then its follower's (§3c.6 step (2), whose bound
/// is the dialer's until S2 reports): a board that does not answer is cut
/// off within it. A delete the board refuses as typed against an older state
/// makes up to three, its dial, the shift's read and the shifted dial; its
/// line is synced from that refusal on, so a stop past the bound loses
/// nothing of it. Each of the page's close's two waits for the followers is
/// held to it too ([`Closing::followers`]).
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

/// One anchor a piece may stand at: a delete's `before` or `after`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Edge {
    Before,
    After,
}

impl Edge {
    /// Returns the anchor as the anchors spell it.
    fn name(self) -> &'static str {
        match self {
            Edge::Before => "before",
            Edge::After => "after",
        }
    }
}

/// Where a piece of a follower stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Place {
    /// Among a `make_link`'s `from` or `to` spans, at the index given.
    Slot(Slot, usize),
    /// At a delete's `before` or `after` anchor.
    Edge(Edge),
    /// Among the runs of a delete's anchors' `span`, at the index given.
    Run(usize),
}

impl Place {
    /// Returns the member a refusal of the piece names.
    fn what(self) -> &'static str {
        match self {
            Place::Slot(slot, _) => slot.what(),
            Place::Edge(Edge::Before) => "anchors.before",
            Place::Edge(Edge::After) => "anchors.after",
            Place::Run(_) => "anchors.span",
        }
    }

    /// Returns whether the piece stands among a delete's anchors.
    fn in_anchors(self) -> bool {
        matches!(self, Place::Edge(_) | Place::Run(_))
    }
}

/// A piece of a follower: `width` positions of the burst's words.
///
/// They run from the burst's `offset`-th position, counted from 0, and the
/// piece stands at `place`; a piece at an anchor names one position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Piece {
    place: Place,
    offset: u64,
    width: u64,
}

/// What a follower writes: a link write, or a delete with its anchors.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Kind {
    /// A `make_link` or a `nullify`, its pieces among its ends.
    Link,
    /// A `delete`, its anchors as the page sent them, where it sent any.
    ///
    /// They are in the follower's form ([`delete_anchors`]), its pieces
    /// among them.
    Delete(Option<Value>),
}

/// A follower write as the `op` row's door read it (SP-18).
///
/// It is the `id` of the burst it follows, what it writes, and its pieces,
/// in the order the frame and then the anchors hold them. Made by
/// [`Follower::of`] alone, so every follower the table waits on is one the
/// door checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Follower {
    after: String,
    kind: Kind,
    pieces: Vec<Piece>,
}

impl Follower {
    /// Returns the follower the `op` row's session form names, where one is.
    ///
    /// `frame` is the row's frame and `at` its position where the page sent
    /// the `/op-at` form. An `after` absent or `null` names none; then the
    /// frame is a follower of nothing, and a piece in it is refused below.
    /// A delete follower's `anchors` are read here, in the follower's form,
    /// and by no other reader ([`Follower::reads_anchors`]).
    ///
    /// # Errors
    ///
    /// In this order, each `malformed_args`:
    ///
    /// 1. naming `after` where it is present and no string of at most
    ///    [`MAX_BURST_ID_BYTES`] bytes;
    /// 2. naming `after` where it rides an `/op-at` frame, which reads and
    ///    follows nothing, or a frame that is no `make_link`, no `nullify`
    ///    and no `delete`;
    /// 3. for a `make_link`, a `nullify` or a `delete`, at the first member
    ///    of the frame in key order where a piece — an object with a `burst`
    ///    member — is not of its place and form: naming the member
    ///    (`frame.from`, `frame.to`, `frame.ty`, `frame.p`, or another) where
    ///    the piece stands anywhere but among the spans of a `make_link`'s
    ///    `from` or `to` in the I-span form; naming the slot where its
    ///    members are other than `burst`, `offset` and `width`, its `burst`
    ///    no string, its `offset` no natural or its `width` no natural of 1
    ///    or more, or its `burst` not the `after` given; naming `after` where
    ///    no `after` is given;
    /// 4. for a delete follower, where its `anchors` are present and not of
    ///    the follower's form: naming `anchors`, then the place of a piece
    ///    naming another burst than the `after` given ([`delete_anchors`]).
    pub(super) fn of(args: &Value, frame: &Value, at: Option<u64>) -> Result<Option<Follower>, Refusal> {
        let after = match args.get("after") {
            None | Some(Value::Null) => None,
            Some(v) => Some(v.as_str().filter(|id| id.len() <= MAX_BURST_ID_BYTES).ok_or_else(|| Refusal::malformed("after"))?),
        };
        let op = frame["op"].as_str().unwrap_or("");
        let followable = matches!(op, "make_link" | "nullify" | "delete");
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
        let Some(after) = after else { return Ok(None) };
        let kind = if op == "delete" {
            let anchors = args.get("anchors").filter(|anchors| !anchors.is_null()).cloned();
            if let Some(anchors) = &anchors {
                pieces.extend(delete_anchors(anchors, after)?);
            }
            Kind::Delete(anchors)
        } else {
            Kind::Link
        };
        Ok(Some(Follower { after: after.to_string(), kind, pieces }))
    }

    /// Returns whether the follower read the `op` row's `anchors` itself.
    ///
    /// It did where it is a delete: its anchors are its own, read in the
    /// follower's form, and the row reads them no second time.
    pub(super) fn reads_anchors(&self) -> bool {
        matches!(self.kind, Kind::Delete(_))
    }
}

/// Returns the pieces of a delete follower's anchors, read in its form.
///
/// The form is the anchors' own (`held::Anchors::of`), save that a run of
/// the `span` may be a piece `{burst, offset, width}` of a `make_link`'s
/// form, and that every piece — a run's, or an anchor's piece `{burst,
/// offset}` (skep #969) — names words of the burst `after` names. The
/// anchors as given are held to [`MAX_ANCHOR_BYTES`], and the rest of them,
/// the run pieces left out, are read by `Anchors::of`, the one reader of
/// their form (SP-18). The pieces are answered in the anchors' order:
/// `before`'s, `after`'s, then the span's runs'.
///
/// # Errors
///
/// In this order, each `malformed_args`: naming `anchors` where the anchors
/// as given pass [`MAX_ANCHOR_BYTES`], a run piece is not of its form, or
/// the rest are not of the anchors' form; then naming `anchors.before`,
/// `anchors.after` or `anchors.span` at the first piece in that order whose
/// `burst` is not `after`.
fn delete_anchors(v: &Value, after: &str) -> Result<Vec<Piece>, Refusal> {
    let malformed = || Refusal::malformed("anchors");
    if json_len(v) > MAX_ANCHOR_BYTES {
        return Err(malformed());
    }
    let mut runs = Vec::new();
    let mut rest = v.clone();
    if let (Some(span), Some(members)) = (v.get("span").and_then(Value::as_array), rest.as_object_mut()) {
        let mut addressed = Vec::new();
        for (index, run) in span.iter().enumerate() {
            if run.get("burst").is_none() {
                addressed.push(run.clone());
                continue;
            }
            let (burst, offset, width) = piece_of(run).ok_or_else(malformed)?;
            runs.push((burst, Piece { place: Place::Run(index), offset, width }));
        }
        if !runs.is_empty() && addressed.is_empty() {
            members.remove("span");
        } else {
            members.insert("span".to_string(), Value::Array(addressed));
        }
    }
    let anchors = Anchors::of(&rest).ok_or_else(malformed)?;
    let mut pieces = Vec::new();
    for (edge, anchor) in [(Edge::Before, &anchors.before), (Edge::After, &anchors.after)] {
        if let Some(Anchor::Piece(piece)) = anchor {
            if piece.burst() != after {
                return Err(Refusal::malformed(Place::Edge(edge).what()));
            }
            pieces.push(Piece { place: Place::Edge(edge), offset: piece.offset(), width: 1 });
        }
    }
    for (burst, piece) in runs {
        if burst != after {
            return Err(Refusal::malformed(piece.place.what()));
        }
        pieces.push(piece);
    }
    Ok(pieces)
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
    let (burst, offset, width) = piece_of(v).ok_or_else(malformed)?;
    match after {
        None => Err(Refusal::malformed("after")),
        Some(after) if after == burst => Ok(Piece { place: Place::Slot(slot, index), offset, width }),
        Some(_) => Err(malformed()),
    }
}

/// Returns the `burst`, `offset` and `width` a piece spells.
///
/// The form is `{burst, offset, width}` alone, `burst` a string, `offset` a
/// natural and `width` a natural of 1 or more; any other value is of no
/// form.
fn piece_of(v: &Value) -> Option<(&str, u64, u64)> {
    let members = v.as_object().filter(|members| members.len() == 3)?;
    let burst = members.get("burst")?.as_str()?;
    let offset = members.get("offset")?.as_u64()?;
    let width = members.get("width")?.as_u64().filter(|w| *w >= 1)?;
    Some((burst, offset, width))
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
        let (prefix, first) = i_address(addr)?;
        Some(Minted { prefix: prefix.to_string(), first })
    }

    /// Returns the I-address `offset` positions past the minted one.
    ///
    /// It answers none where the address is past what one spells.
    fn at(&self, offset: u64) -> Option<String> {
        Some(format!("{}.{}", self.prefix, self.first.checked_add(offset)?))
    }

    /// Returns the I-span a piece names, where its start is spellable.
    ///
    /// It is `width` positions from the minted address advanced by
    /// `offset`, in the wire's I-span form (wire.md §Links (writes)), the
    /// form an anchors' `span` run takes too.
    fn span(&self, piece: Piece) -> Option<Value> {
        Some(json!({"start": self.at(piece.offset)?, "width": piece.width.to_string()}))
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
    /// Returns the outcome of a write's answer; an insert's names its words.
    ///
    /// `minting` is the document an insert mints into, none for another
    /// write: an insert's ack names its words where the hold's one reader of
    /// its minted address finds them in that document's own content I-space
    /// (`hold::minted_on`; SP-18).
    fn of(answer: &Result<Value, Refusal>, minting: Option<&str>) -> Outcome {
        match answer {
            Ok(v) if v["resp"] == "held" => Outcome::NotAcked(v["cause"].as_str().unwrap_or("held").to_string()),
            Ok(v) => Outcome::Acked(minting.and_then(|doc| minted_on(doc, v)).and_then(Minted::of)),
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
    /// The document the burst's frame names, where it names one.
    doc: Option<String>,
    /// The positions an insert's frame mints; none for any other kind.
    positions: Option<u64>,
    outcome: Outcome,
    issued: u64,
    served: u64,
    holders: usize,
    broken: bool,
}

/// One session's table: its bursts, oldest first, its followers, its closes.
///
/// `waiting` counts the followers inside [`Followers::follow`] for the
/// session — waiting for their burst to arrive, holding a turn, or dialing
/// — `closing` the page's closes of it under way ([`Closing`]), and `ended`
/// is whether the session ended under them.
#[derive(Debug, Default)]
struct Table {
    bursts: VecDeque<Kept>,
    waiting: usize,
    closing: usize,
    ended: bool,
}

impl Table {
    /// Returns whether the table holds nothing a waiter or a burst needs.
    ///
    /// No follower waits in it, no close runs in it and it keeps no burst:
    /// the table may go.
    fn idle(&self) -> bool {
        self.waiting == 0 && self.closing == 0 && self.bursts.is_empty()
    }

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
    /// Leaves a follower of `session`, its turn of `held`'s burst ended.
    ///
    /// `acked` is whether its own dial was acked. The turn passes to the
    /// follower after it where the turn was this one's, the burst is
    /// `broken` where the follower was not acked, and the session's table
    /// goes once it is idle ([`Table::idle`]).
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
        if table.idle() {
            self.tables.remove(session);
        }
    }

    /// Returns the followers waiting and the closes running, in every table.
    fn under_way(&self) -> (usize, usize) {
        self.tables.values().fold((0, 0), |(waiting, closing), table| (waiting + table.waiting, closing + table.closing))
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
    ///
    /// Or they resolve to anchors of no form `Anchors::of` reads.
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
    /// The document the burst mints into where it is an insert.
    minting: Option<String>,
    outcome: Option<Outcome>,
}

impl SentBurst<'_> {
    /// Sets the burst's outcome from the answer its call gives.
    pub(super) fn settle(mut self, answer: &Result<Value, Refusal>) {
        self.outcome = Some(Outcome::of(answer, self.minting.as_deref()));
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

/// The page's close of a session, under way (the module doc's close).
///
/// It is counted in the session's table from [`Followers::closing`], so the
/// shell's stop waits on it as on a follower; dropped — the close ended its
/// session, or unwound — it leaves the table, which goes once idle.
#[must_use = "the stop waits on a close until its guard drops"]
pub(super) struct Closing<'a> {
    followers: &'a Followers,
    session: String,
    started: Instant,
}

impl Closing<'_> {
    /// Waits until every burst `after` names has its answer (the module doc).
    ///
    /// The newest burst of each `id` the session's table keeps is waited on
    /// until its call answers, whatever it answers. An `id` no burst of
    /// reaches the table within [`BURST_ARRIVAL_WAIT`] of the close is waited
    /// for no longer, and those `id`s are returned, in `after`'s order, each
    /// once. The wait ends where the session ends or the stop's wait is
    /// over, returning none.
    ///
    /// # Panics
    ///
    /// Panics where the session's table is gone: the close's own count keeps
    /// it until the guard drops.
    pub(super) fn bursts(&self, after: &[String]) -> Vec<String> {
        let named: HashSet<&str> = after.iter().map(String::as_str).collect();
        let arrival = self.started + BURST_ARRIVAL_WAIT;
        let mut state = self.followers.lock();
        loop {
            let stop = state.stop;
            let table = state.tables.get(&self.session).expect("a close's own count keeps its table");
            if table.ended || stop == Stop::Closed {
                return Vec::new();
            }
            let (flying, arrived) = {
                let mut found = HashSet::new();
                let mut flying = false;
                for kept in table.bursts.iter().rev() {
                    if named.contains(kept.id.as_str()) && found.insert(kept.id.as_str()) {
                        flying |= kept.outcome == Outcome::InFlight;
                    }
                }
                (flying, found.len())
            };
            let arriving = arrived < named.len() && Instant::now() < arrival;
            if !flying && !arriving {
                let kept: HashSet<&str> = table.bursts.iter().map(|kept| kept.id.as_str()).collect();
                let mut missing = HashSet::new();
                return after.iter().filter(|id| !kept.contains(id.as_str()) && missing.insert(id.as_str())).cloned().collect();
            }
            state = self.followers.wait(state, arriving.then_some(arrival));
        }
    }

    /// Waits until no follower of the session waits (the module doc).
    ///
    /// It answers how many still wait at its bound, [`FOLLOW_AT_STOP`] from
    /// the call; none where they all answered, the session ended or the
    /// stop's wait is over.
    ///
    /// # Panics
    ///
    /// Panics where the session's table is gone: the close's own count keeps
    /// it until the guard drops.
    pub(super) fn followers(&self) -> usize {
        let deadline = Instant::now() + FOLLOW_AT_STOP;
        let mut state = self.followers.lock();
        loop {
            let stop = state.stop;
            let table = state.tables.get(&self.session).expect("a close's own count keeps its table");
            if table.waiting == 0 || table.ended || stop == Stop::Closed {
                return 0;
            }
            if Instant::now() >= deadline {
                return table.waiting;
            }
            state = self.followers.wait(state, Some(deadline));
        }
    }
}

impl Drop for Closing<'_> {
    fn drop(&mut self) {
        let mut state = self.followers.lock();
        if let Some(table) = state.tables.get_mut(&self.session) {
            table.closing -= 1;
            if table.idle() {
                state.tables.remove(&self.session);
            }
        }
        drop(state);
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
        let doc = frame["doc"].as_str().map(str::to_owned);
        let insert = frame["op"] == "insert";
        let positions = if insert { values_of(&frame["values"]).ok().map(|values| values.len() as u64) } else { None };
        let minting = doc.clone().filter(|_| insert);
        let mut state = self.lock();
        let serial = state.next_serial;
        state.next_serial += 1;
        let table = state.tables.entry(session.to_string()).or_default();
        if table.ended {
            return None;
        }
        table.bursts.push_back(Kept { serial, id: id.to_string(), doc, positions, outcome: Outcome::InFlight, issued: 0, served: 0, holders: 0, broken: false });
        table.trim();
        drop(state);
        self.moved.notify_all();
        if !stands() {
            self.ended(session);
            return None;
        }
        Some(SentBurst { followers: self, session: session.to_string(), serial, minting, outcome: None })
    }

    /// Answers a follower once its burst is answered (the module doc).
    ///
    /// `frame` is its write and `dial` sends it with its anchors — a
    /// delete's, its pieces resolved, none for a link write — by the one
    /// path every session write takes, answering the follower's own answer;
    /// `stands` says whether `session` still stands, asked where no burst
    /// arrived. The follower is acked where that answer is an ack, never
    /// where it is refused or `held`.
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
    /// 3. `malformed_args`, before the follower takes its turn
    ///    ([`unnamed`]): naming `frame.doc` where a delete's anchors name
    ///    words of a burst on another document; naming the place of the
    ///    first piece where the burst names no positions — it is no insert,
    ///    or an insert whose `values` are not the wire's forms — or of the
    ///    first piece past the insert's positions;
    /// 4. once the burst is answered and every follower before it has left:
    ///    `not_followed` with `why: "burst"` and the burst's cause where it
    ///    was not acked, `why: "ahead"` where a follower before it was not,
    ///    `why: "ack"` where the ack names no I-address its pieces resolve
    ///    against, or the anchors they resolve to are of no form
    ///    `Anchors::of` reads, and `why: "stop"` where the stop's wait ended
    ///    first;
    /// 5. the dial's own answer.
    ///
    /// [`Followed::Ended`] answers where the session ended while it waited.
    pub(super) fn follow(&self, session: &str, follower: Follower, frame: Value, stands: impl Fn() -> bool, dial: impl FnOnce(Value, Option<Anchors>) -> Result<Value, Refusal>) -> Followed {
        let Follower { after, kind, pieces } = follower;
        let anchors = match kind {
            Kind::Delete(anchors) => anchors,
            Kind::Link => None,
        };
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
        if let Some(what) = unnamed(&pieces, kept, frame["doc"].as_str()) {
            return self.left(state, session, None, || Followed::Answered(Err(Refusal::malformed(what))));
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
        let Some((frame, anchors)) = resolved(frame, anchors, &pieces, minted.as_ref()) else {
            drop(seat);
            return refused(Why::Ack);
        };
        let answer = dial(frame, anchors);
        seat.acked = matches!(Outcome::of(&answer, None), Outcome::Acked(_));
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

    /// Enters the page's close of `session` in its table, under way.
    ///
    /// `stands`, asked once it is entered, says whether the session still
    /// stands: where it does not, the table is let go as at the session's
    /// end ([`Followers::ended`]), so each of the close's waits answers at
    /// once.
    pub(super) fn closing(&self, session: &str, stands: impl Fn() -> bool) -> Closing<'_> {
        let started = Instant::now();
        self.lock().tables.entry(session.to_string()).or_default().closing += 1;
        if !stands() {
            self.ended(session);
        }
        Closing { followers: self, session: session.to_string(), started }
    }

    /// Waits for every follower handed over, until `deadline`: the stop.
    ///
    /// It answers once no follower waits and no close runs, or at
    /// `deadline`, from which on every follower still waiting — and every
    /// one that arrives after — is refused `not_followed`, `why: "stop"`; one
    /// already dialing is left to its dial, and a close under way to its
    /// frames, each of whose waits answers at once. The followers and the
    /// closes still under way at the deadline are said in the shell's own
    /// window. A second drain finds the wait over.
    pub(super) fn drain(&self, deadline: Instant) {
        let mut state = self.lock();
        if state.stop == Stop::Closed {
            return;
        }
        state.stop = Stop::Draining;
        while state.under_way() != (0, 0) && Instant::now() < deadline {
            state = self.wait(state, Some(deadline));
        }
        let (waiting, closing) = state.under_way();
        state.stop = Stop::Closed;
        drop(state);
        self.moved.notify_all();
        if waiting > 0 {
            self.say(format_args!(
                "stop: {waiting} write(s) handed over with their bursts were still under way at the stop's {} s bound; each still waiting is refused `not_followed`, and the sessions close under the rest",
                FOLLOW_AT_STOP.as_secs()
            ));
        }
        if closing > 0 {
            self.say(format_args!(
                "stop: {closing} of the page's close(s) were still under way at the stop's {} s bound; the sessions close under them, and each frame a close sends after its session's close is refused",
                FOLLOW_AT_STOP.as_secs()
            ));
        }
    }

    /// Lets go of `session`'s table: the session ended.
    ///
    /// Every follower waiting in it answers [`Followed::Ended`], every close
    /// running in it stops waiting, and no burst of the session is entered
    /// after.
    pub(super) fn ended(&self, session: &str) {
        let mut state = self.lock();
        if let Some(table) = state.tables.get_mut(session) {
            table.ended = true;
            table.bursts.clear();
            if table.idle() {
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
            Why::Ack => ("ack", None, "its burst's ack names no I-address its pieces resolve against, or they resolve to anchors of no form".to_string()),
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
        self.lock().under_way().0
    }

    /// Returns how many of the page's closes run, in every session's table.
    #[cfg(test)]
    pub(super) fn closes(&self) -> usize {
        self.lock().under_way().1
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

/// Returns the member a refusal names where `pieces` cannot name `kept`'s
/// words, before the follower takes its turn.
///
/// `doc` is the document the follower's frame names. In this order: a
/// delete's anchors naming words of a burst on another document than `doc`
/// name `frame.doc`; a burst that names no positions — no insert, or an
/// insert whose `values` are not the wire's forms — names the first piece's
/// place; a piece past the insert's positions names its own. None is
/// answered where the follower holds no piece, or every piece names words
/// the insert seats.
fn unnamed(pieces: &[Piece], kept: &Kept, doc: Option<&str>) -> Option<&'static str> {
    let first = pieces.first()?;
    if pieces.iter().any(|piece| piece.place.in_anchors()) && kept.doc.as_deref() != doc {
        return Some("frame.doc");
    }
    let Some(positions) = kept.positions else { return Some(first.place.what()) };
    pieces.iter().find(|piece| piece.offset.checked_add(piece.width).is_none_or(|end| end > positions)).map(|piece| piece.place.what())
}

/// Returns a follower's frame and anchors, each piece resolved against
/// `minted`.
///
/// A piece among a link's spans or a delete's span runs becomes the I-span
/// it names, and one at a delete's anchor the I-address; the anchors are
/// then read by `Anchors::of`, the one reader of their form. It answers the
/// frame and the anchors as they stand where they hold no piece; none where
/// a piece stands and the burst's ack named no address, a piece's start is
/// past what an address spells, or the resolved anchors are of no form
/// `Anchors::of` reads — past [`MAX_ANCHOR_BYTES`], an I-address spelling
/// longer than the piece it replaces.
fn resolved(mut frame: Value, mut anchors: Option<Value>, pieces: &[Piece], minted: Option<&Minted>) -> Option<(Value, Option<Anchors>)> {
    for piece in pieces {
        let minted = minted?;
        let (spot, resolved) = match piece.place {
            Place::Slot(slot, index) => (frame.get_mut(slot.name())?.get_mut("spans")?.get_mut(index)?, minted.span(*piece)?),
            Place::Edge(edge) => (anchors.as_mut()?.get_mut(edge.name())?, Value::from(minted.at(piece.offset)?)),
            Place::Run(index) => (anchors.as_mut()?.get_mut("span")?.get_mut(index)?, minted.span(*piece)?),
        };
        *spot = resolved;
    }
    let anchors = match anchors {
        Some(anchors) => Some(Anchors::of(&anchors)?),
        None => None,
    };
    Some((frame, anchors))
}

#[cfg(test)]
mod tests;
