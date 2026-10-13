//! THE HOLD (`client.md` §3c.4, §3c.5): the one path of every `/op` under a
//! session, the per-(board, principal) queue the shell consults on every
//! burst, and the resend walk that drains the queue once the board returns.
//!
//! EVERY `/op` UNDER A SESSION — `/op-at`'s aside, whose answer is the
//! board's own — goes out by ONE PATH, [`Holds::send`]: attested where the
//! session's key attests its kind, dialed, and each answer read once through
//! THE CLASSIFICATION TABLE ([`classify`]: §3c.4's HOLD(cause) / REISSUE /
//! NEITHER) — an ack carried and its `at` noted for the `base` of the next
//! hold on every document it names (§3c.2); a reissue-class answer reissued
//! within the call, a `write_busy` once after [`WRITE_BUSY_WAIT`], a first
//! and second `durability` as-is, so the page meets the ack or the next
//! refusal (§4b.1's `op` row); and anything else faced at the act, save a
//! BURST's hold-class answer or REFUSED run, which is held. A write the hold
//! never holds is faced where a burst's would be held (§3c.4: "a non-burst
//! write that fails … is faced at its act").
//!
//! A BURST is an `op` under a session (never the guest form) whose
//! `frame["op"]` is one of [`BURST_KINDS`] — the burst machine's five — on a
//! draft. It enters by ONE DOOR, [`Burst::admit`], which refuses at the act a
//! frame the board takes at no send — one past the board's frame cap, one
//! naming no document, an insert a signed session cannot attest — since a
//! held line of it could be sent and resolved never, and would hold every
//! later burst of its principal `behind` it; and it is held WITHOUT a dial
//! where a hold stands — the own node stopped, the board halted, a line of
//! the principal's already held. The resend sends each held line through the
//! same reader of an answer, a reissue-class answer there reissued at the
//! next probe.
//!
//! THE QUEUE is each principal's [`HeldQueue`], in `k` order across the
//! board's documents: copied to `held/<chain>/principal-<n>.held` where this
//! shell holds the board's directory (§3c.1), kept in memory alone where
//! another window holds it or the directory is out of reach (§3c.3), and
//! opened only under a session as its principal (P39) — at the session's
//! open, or at the first touch after it. THE PROBE ([`Holds::probe`]) and
//! THE RESEND it lets run, which drain the queue once the board returns,
//! are the child module `resend`'s.
//!
//! EACH BOARD's HOLD ITS OWN LOCK, the boards fixed at the open: a board's
//! appends, each synced to disk, its file's read at a session's open and its
//! resend's bookkeeping hold that board's lock alone, so no board's wait is
//! another's.

use std::collections::HashMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::Duration;

use serde_json::{json, Value};
use skep_client::board::{acked_at, Answer, Board, Health, Rejection};
use skep_client::halt::Halt;
use skep_client::store::FileStore;
use skep_client::DialError;
use skep_identity::BoardTerm;
use skep_search::Chain;

use crate::attest::{attest_room, in_checked_set, insert_terms, Unattested};
use crate::events::{EventBus, EventName};
use crate::held::{Done, DoneError, HaltWhy, HeldDir, HeldLine, HeldQueue, Opened, Reason, Unheld, MAX_HELD_FRAME_BYTES, MAX_HELD_LINES};
use crate::refusal::{Name, Refusal};
use crate::sessions::{SessionEntry, SessionKind, Sessions};
use crate::wire::{document_address, json_len, MAX_FRAME_BYTES};
use crate::Talk;

mod resend;

/// THE INTERIM PROBE CADENCE (§3c.4): `GET /health` at this interval while a
/// burst is held at a board — the lane's to tune.
pub const PROBE_CADENCE: Duration = Duration::from_secs(2);

/// THE SHORT WAIT before a `write_busy` is reissued (§3c.4: "a silent
/// reissue after a short wait") — INTERIM, the lane's to tune, as
/// [`PROBE_CADENCE`] is.
const WRITE_BUSY_WAIT: Duration = Duration::from_millis(50);

/// The burst machine's five kinds (§3c.4) — the ops the held store holds.
const BURST_KINDS: [&str; 5] = ["insert", "delete", "copy", "reinstate", "rearrange"];

/// Whether `frame` is a burst: one of the five kinds (§3c.4 says "on a draft
/// under the session" — the kind test is the shell's; a write on a document
/// that is no draft is the board's refusal, permanent, and so a refused run).
fn is_burst(frame: &Value) -> bool {
    frame["op"].as_str().is_some_and(|op| BURST_KINDS.contains(&op))
}

/// §3c.2's CAUSES, as a held line and its answer spell them; beside these, a
/// REFUSED run's line carries the board's own token.
mod cause {
    pub const UNREACHABLE: &str = "unreachable";
    pub const STOPPED: &str = "stopped";
    pub const POISONED: &str = "poisoned";
    pub const HALTED: &str = "halted";
    pub const DURABILITY: &str = "durability";
    pub const BEHIND: &str = "behind";
    pub const MOVED: &str = "moved";
    /// The ANSWER's cause and never a line's: a burst another window's lock
    /// keeps in this shell's memory alone (§3c.3).
    pub const OTHER_WINDOW: &str = "other_window";
}

/// What a write's dial answered that [`classify`] reads (§3c.4). The own
/// node STOPPED (no dial), an ACK and the death signal are not here: a stop
/// holds a burst before any dial, an ack is carried as any `op`'s, and the
/// death signal ends the session. A write the hold never holds is read here
/// as a burst is, and faced where a burst's answer would be held.
#[derive(Debug, Clone, Copy)]
enum DialOutcome<'a> {
    /// The dial failed at the transport.
    Dial(&'a DialError),
    /// The board refused: a `rejected` document's key, or a non-200's error,
    /// and the `disposition` the body rode.
    Rejected { code: &'a str, disposition: &'a str },
}

/// What the shell does with a write's outcome (§3c.4's table).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Decision {
    /// HOLD the write with this cause — a burst's line; a write the hold
    /// never holds faces it — `sent` whether the write MAY have landed
    /// (§3c.2): a dial made whose answer was lost, or a `poisoned` answer,
    /// whose frames the board's journal keeps for its restart.
    Hold { cause: &'static str, sent: bool },
    /// A REFUSED run — a `permanent` or `reorder` refusal, held with the
    /// board's token for its cause and its verdict beside it where the write
    /// is a burst.
    Refused,
    /// REISSUE, silently, of this kind — within the write's call; on a
    /// resend, at the next probe.
    Reissue(Reissue),
    /// NEITHER held nor reissued — faced at its act.
    Neither,
}

/// A REISSUE-class refusal (§3c.4's REISSUE row): its kind names the wait
/// before the reissue and the count [`classify`] bounds it by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reissue {
    /// `503 write_busy`, the board's write permits all held: reissued ONCE,
    /// after [`WRITE_BUSY_WAIT`].
    WriteBusy,
    /// `durability`, the board's durability barrier failed: reissued as-is,
    /// a first and a second time.
    Durability,
}

impl Reissue {
    /// The wait before the reissue.
    fn wait(self) -> Duration {
        match self {
            Reissue::WriteBusy => WRITE_BUSY_WAIT,
            Reissue::Durability => Duration::ZERO,
        }
    }
}

/// The reissues ONE write has been given so far, by kind — what
/// [`classify`] bounds the next by: a `write_busy` reissued once, a
/// `durability` twice, its third HOLDING a burst (§3c.4's rider). Counted by
/// the caller as it reissues ([`Reissues::note`]), so every reissue moves
/// the write toward its bound: a write is dialed four times at most.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Reissues {
    write_busy: u32,
    durability: u32,
}

impl Reissues {
    /// One reissue of `kind` given.
    fn note(&mut self, kind: Reissue) {
        match kind {
            Reissue::WriteBusy => self.write_busy += 1,
            Reissue::Durability => self.durability += 1,
        }
    }
}

/// THE CLASSIFICATION TABLE (§3c.4): a write's outcome, and the reissues
/// the SAME write has been given, to exactly one row — the one owner of
/// every reissue's bound.
fn classify(outcome: DialOutcome<'_>, given: Reissues) -> Decision {
    match outcome {
        DialOutcome::Dial(e) => match e {
            // No connection was made — the write did not leave.
            DialError::Connect(_) | DialError::Resolve(_) | DialError::Tls(_) => Decision::Hold { cause: cause::UNREACHABLE, sent: false },
            // The request left and its answer was no answer — it MAY have landed.
            DialError::Timeout(_) | DialError::Io(_) | DialError::Truncated { .. } | DialError::Response(_) | DialError::TooLarge { .. } => {
                Decision::Hold { cause: cause::UNREACHABLE, sent: true }
            }
            // The scheme this build does not hold, or a request refused before any
            // connection opened — faced as built, no probe ends either.
            DialError::NotHeld(_) | DialError::Request(_) => Decision::Neither,
            // A later transport error (the enum is non-exhaustive): the request
            // may have left, so hold `sent: true` — the resend reads first.
            _ => Decision::Hold { cause: cause::UNREACHABLE, sent: true },
        },
        DialOutcome::Rejected { code, disposition } => match code {
            // `poisoned` MAY have landed (§3c.2): the board's write path failed
            // AFTER the write's frames reached its journal, and a restart's open
            // "rebuilds the line from the journal" (wire.md §Rejection codes) —
            // a burst lands at the restart, so the resend READS before it
            // sends, as after a lost answer. A `halted` hold (the feed's
            // `writes.halted` read, before any dial) stays `sent: false`.
            "poisoned" => Decision::Hold { cause: cause::POISONED, sent: true },
            // "A silent reissue after a short wait" (§3c.4), once: the
            // reissue's own `write_busy` is the next refusal, faced.
            "write_busy" => {
                if given.write_busy == 0 {
                    Decision::Reissue(Reissue::WriteBusy)
                } else {
                    Decision::Neither
                }
            }
            // The rider (§3c.4): a THIRD `durability` on the same write HOLDS
            // a burst.
            "durability" => {
                if given.durability >= 2 {
                    Decision::Hold { cause: cause::DURABILITY, sent: false }
                } else {
                    Decision::Reissue(Reissue::Durability)
                }
            }
            _ => match disposition {
                "permanent" | "reorder" => Decision::Refused,
                _ => Decision::Neither,
            },
        },
    }
}

/// What an `/op` under a session answers the page (§4b.1's `op` row;
/// §3c.4).
pub enum OpAnswer {
    /// The board's ack, the shell's `held` for a burst, or the refusal
    /// faced at the act.
    Answered(Result<Value, Refusal>),
    /// The death signal on the session's token: the caller ends the session,
    /// and nothing is held (§3c.4: the death signal is neither).
    Died,
}

/// The person's two acts at a REFUSED run's face or a MOVED document's
/// (§4b.1's `resolve` row), as the row's `act` spells them — read off the
/// call's arguments by [`ResolveAct::named`] alone, so no act reaches the
/// hold that the row does not spell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveAct {
    /// `"drop"`: the line, and a refused run's `behind` lines with it, dropped.
    Drop,
    /// `"send"`: the document's waiting lines handed back to the automatic
    /// machine.
    Send,
}

impl ResolveAct {
    /// The act the row spells `act` — `"drop"` or `"send"` — and none for any
    /// other spelling.
    pub fn named(act: &str) -> Option<ResolveAct> {
        match act {
            "drop" => Some(ResolveAct::Drop),
            "send" => Some(ResolveAct::Send),
            _ => None,
        }
    }
}

/// What a `resolve` act did (§4b.1's `resolve` row), the call's answer `{}`
/// either way.
#[must_use = "a `HandedBack` document's resend waits on the probe its caller hands the board's feed thread"]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolved {
    /// `"drop"`: the line, and a refused run's `behind` lines with it,
    /// `done … dropped`.
    Dropped,
    /// `"send"`: the document's waiting lines re-marked `behind` and handed
    /// back to the automatic machine (§3c.4; §4b.1: "handed to the
    /// machine") — the caller hands the board's feed thread its probe, so
    /// the call answers once the lines are handed back, never after a
    /// resend's ack.
    HandedBack,
}

/// A BURST ADMITTED: a frame of [`BURST_KINDS`] some send of which the board
/// can take, and its document — what every held line is made of. Built by
/// [`Burst::admit`] alone, so the hold holds no frame the door did not see.
#[derive(Debug)]
pub struct Burst {
    frame: Value,
    doc: String,
}

impl Burst {
    /// THE DOOR a burst enters the hold by, the refusal faced at the act where
    /// the board would refuse the frame at EVERY send — each such frame, held,
    /// would be sent and resolved never, and hold every later burst of its
    /// principal `behind` it for the shell's life and past it on disk —
    /// checked in this order, the first unmet answering:
    ///
    /// * its op one of the five kinds, else `malformed_args`;
    /// * its `doc` a document address in its one spelling
    ///   (`wire::document_address`) — what the resend's read names `under`
    ///   and a held line is keyed by — else `malformed_args`;
    /// * its bytes as sent, and as every resend sends them — the attest
    ///   stripped and, under a session whose key attests the kind, the most
    ///   an attest adds ([`attest_room`]) — within the board's frame cap
    ///   ([`MAX_FRAME_BYTES`], which the board answers `413` past, unread),
    ///   else `frame_too_large`;
    /// * an insert such a session attests composable from the frame alone
    ///   ([`insert_terms`]: its trunk, its deposit, its values within the
    ///   board's count), else `attest_not_composed`, the composer's halt.
    pub fn admit(frame: Value, session: &SessionEntry) -> Result<Burst, Refusal> {
        if !is_burst(&frame) {
            return Err(Refusal::malformed("frame.op"));
        }
        let doc = frame["doc"].as_str().filter(|d| document_address(d).is_some()).ok_or_else(|| Refusal::malformed("frame.doc"))?.to_string();
        let attested = matches!(session.facts.kind, SessionKind::Signed { .. }) && frame["op"].as_str().is_some_and(in_checked_set);
        let sent_bytes = json_len(&frame);
        // The attest a page supplied is never stored, so a resend's frame is
        // the frame without its member — `,"attest":` and the value.
        let stripped_bytes = sent_bytes.saturating_sub(frame.get("attest").map_or(0, |a| r#","attest":"#.len() + json_len(a)));
        let resent_bytes = stripped_bytes + if attested { attest_room() } else { 0 };
        if sent_bytes.max(resent_bytes) > MAX_FRAME_BYTES {
            return Err(Refusal::shell(Name::FRAME_TOO_LARGE, json!({"bytes": sent_bytes.max(resent_bytes), "cap": MAX_FRAME_BYTES})));
        }
        if attested && frame["op"] == "insert" {
            insert_terms(&frame).map_err(|h| Refusal::of_named(Name::ATTEST_NOT_COMPOSED, h))?;
        }
        Ok(Burst { frame, doc })
    }

    /// The frame as the page composed it.
    fn frame(&self) -> &Value {
        &self.frame
    }

    /// The burst as a held line stores it (§3c.2): its document in its one
    /// spelling, and its frame with any `attest` stripped — the resend
    /// composes its own when it sends.
    fn into_stored(self) -> (String, Value) {
        let Burst { mut frame, doc } = self;
        if let Some(members) = frame.as_object_mut() {
            members.remove("attest");
        }
        (doc, frame)
    }
}

/// What ONE dial of a write answered, read once through the table.
enum Dialed {
    /// The board's ack.
    Acked(Value),
    /// A hold-class answer, or a REFUSED run: the line's reason for a burst,
    /// and the refusal the answer is, which a write the hold never holds
    /// faces.
    Held { reason: Reason, refusal: Refusal },
    /// A reissue-class answer: its kind, and the refusal it is where no
    /// reissue follows.
    Reissue { kind: Reissue, refusal: Refusal },
    /// Faced at the act: an answer the table holds and reissues nowhere, or
    /// the shell's own refusal where the attest could not be composed.
    Faced(Refusal),
    /// The death signal on the session's token, at the dial or at a read the
    /// attest's composer made.
    Died,
}

impl Dialed {
    /// A refusal read through the table: held for its cause, held as a
    /// REFUSED run with the board's `token` and verdict, reissued, or faced —
    /// each beside the refusal the answer is.
    fn refused(decision: Decision, token: &str, verdict: Value, refusal: Refusal) -> Dialed {
        match decision {
            Decision::Hold { cause, sent } => Dialed::Held { reason: Reason::of(cause, sent), refusal },
            Decision::Refused => Dialed::Held { reason: Reason::refused(token, verdict), refusal },
            Decision::Reissue(kind) => Dialed::Reissue { kind, refusal },
            Decision::Neither => Dialed::Faced(refusal),
        }
    }
}

/// What a send answers where its attest could not be composed
/// ([`Holds::attest_where_owed`]), nothing dialed: the death signal met at
/// one of the composer's reads; a read that did not reach the board held
/// like the dial's own failure, `sent: false`, since the write never left;
/// the composer's own refusal faced.
impl From<Unattested> for Dialed {
    fn from(why: Unattested) -> Dialed {
        match why {
            Unattested::Died => Dialed::Died,
            // The table's transport rows read no reissue count.
            Unattested::Refused(Refusal::Unreachable(e)) => match classify(DialOutcome::Dial(&e), Reissues::default()) {
                Decision::Hold { cause, .. } => Dialed::Held { reason: Reason::of(cause, false), refusal: Refusal::Unreachable(e) },
                _ => Dialed::Faced(Refusal::Unreachable(e)),
            },
            Unattested::Refused(refusal) => Dialed::Faced(refusal),
        }
    }
}

/// A frame as a send under a session dials it, ATTESTED WHERE AN ATTEST IS
/// OWED: a copy carrying the attest the session's key signs where that key
/// attests the frame's kind and no attest rides it yet
/// (`SessionEntry::attest`, `wants_attest`), and as it stands otherwise — a
/// bare session's frame, a read, a kind outside the checked set, an attest
/// the page supplied. Made by [`Holds::attest_where_owed`] alone, so
/// [`Holds::dial`] sends no frame the session's attest did not see — and
/// never the frame a held line keeps, which carries no attest (§3c.2).
struct AttestedWhereOwed(Value);

/// A held line's state, and a document's as the `held` event carries it
/// (§4b.1's `not_resolvable`; §4b.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeldState {
    Holding,
    Sending,
    Kept,
    Refused,
    Moved,
}

impl HeldState {
    fn as_str(self) -> &'static str {
        match self {
            HeldState::Holding => "holding",
            HeldState::Sending => "sending",
            HeldState::Kept => "kept",
            HeldState::Refused => "refused",
            HeldState::Moved => "moved",
        }
    }
}

/// A held line's state, in the words §4b.1's `resolve` row and §4b.2's
/// `held` event share: `refused` (a REFUSED run's), `moved` (a MOVED
/// document's), else `holding`; `sending` is the resend's, never a line's
/// at rest.
fn line_state(reason: &Reason) -> HeldState {
    if reason.refusal.is_some() {
        HeldState::Refused
    } else if reason.cause == cause::MOVED {
        HeldState::Moved
    } else {
        HeldState::Holding
    }
}

/// Whether a line waits for the person's act — a REFUSED run's, or a MOVED
/// document's (§3c.4, §3c.5): no probe sends it, and `resolve` alone moves it.
fn awaits_act(line: &HeldLine) -> bool {
    matches!(line_state(&line.reason), HeldState::Refused | HeldState::Moved)
}

/// The board's `held/<chain>/` (§3c.1) as this shell stands to it.
#[derive(Debug)]
enum Directory {
    /// Not this shell's yet — why: `H.1` not read, or the directory or its
    /// lock refused. Tried again at a session's open and at the probe.
    NotYet(String),
    /// This shell's for its life: the directory, and the `flock` on its lock.
    ThisWindow { dir: HeldDir, _lock: File },
    /// Another window holds the lock: every line here is kept in this
    /// shell's memory alone (§3c.3).
    OtherWindow,
}

impl Directory {
    /// The directory `H.1`'s read names (§3c.1): made `0700` and locked where
    /// the board term stands, another window's where its lock is held, and
    /// not yet this shell's — why said — where the board has no `H.1` (an
    /// unclaimed board keeps no held text) or the read, the directory or the
    /// lock refused.
    fn of(data_dir: &Path, board_term: Result<Option<BoardTerm>, Halt>) -> Directory {
        let board_term = match board_term {
            Ok(Some(board_term)) => board_term,
            Ok(None) => return Directory::NotYet("the board has no H.1 yet, and an unclaimed board keeps no held text".to_string()),
            Err(h) => return Directory::NotYet(format!("the board's H.1 could not be read: {h}")),
        };
        let dir = HeldDir::new(data_dir, Chain::from_bytes(board_term.chain));
        match dir.ensure().and_then(|()| dir.try_lock()) {
            Ok(Some(lock)) => Directory::ThisWindow { dir, _lock: lock },
            Ok(None) => Directory::OtherWindow,
            Err(e) => Directory::NotYet(format!("the held store could not be made or locked: {e}")),
        }
    }
}

/// Where a principal's held lines are kept at a board (§3c.3).
#[derive(Debug)]
enum Custody {
    /// Not yet opened: the next touch under a session of the principal opens
    /// its file.
    Unopened,
    /// In `principal-<n>.held`, each line synced before its answer.
    File,
    /// In memory alone, another window holding the board's lock: each
    /// answer's cause is `other_window`.
    OtherWindow,
    /// In memory alone, the file out of this shell's reach: each answer
    /// carries why as `unwritable`. The file is opened at a later touch that
    /// finds the queue empty, so no line is ever renumbered.
    Unwritable(String),
    /// Nowhere: P38's HALT (§3c.3) — no burst sent and no line held for the
    /// principal at this board, each act answered `store_halted` by the door
    /// every act takes, [`Holds::principal_hold`].
    Halted { path: PathBuf, why: HaltWhy },
}

impl Custody {
    /// Whether the custody stands for the shell's life.
    fn settled(&self) -> bool {
        matches!(self, Custody::File | Custody::OtherWindow | Custody::Halted { .. })
    }
}

/// One principal's hold at one board: where its lines are kept, the queue,
/// the `at` of its last ACKED write per document — the `base` a hold on
/// that document takes (§3c.2) — and the reissues each line's resend has
/// been given, counted across its probes.
#[derive(Debug)]
struct PrincipalHold {
    custody: Custody,
    queue: HeldQueue,
    last_acked: HashMap<String, u64>,
    reissues: HashMap<u64, Reissues>,
}

impl PrincipalHold {
    fn new() -> PrincipalHold {
        PrincipalHold { custody: Custody::Unopened, queue: HeldQueue::in_memory(), last_acked: HashMap::new(), reissues: HashMap::new() }
    }

    /// How many lines stand on `doc`.
    fn count(&self, doc: &str) -> u64 {
        self.queue.lines().iter().filter(|l| l.doc == doc).count() as u64
    }
}

/// One board's hold: its directory, the two states that hold every burst
/// before any dial, and each principal's queue.
#[derive(Debug)]
struct BoardHold {
    directory: Directory,
    /// Whether the last read of `/health.writes.halted` — the feed's tick, or
    /// the probe — answered true: every burst holds `halted` without a dial
    /// until a read answers false, which only a restart makes it (§3c.4;
    /// wire.md §The other endpoints).
    writes_halted: bool,
    /// Whether the own node is STOPPED by the person's act: every burst holds
    /// `stopped` without a dial, and the probe dials nothing until
    /// `set_node_state(Running)` clears it (§3c.4).
    node_stopped: bool,
    principals: HashMap<u64, PrincipalHold>,
}

/// One board of the holds: the board dialed, outside any lock, and its hold
/// under a lock of its own — held for a burst's line, its synced append and a
/// file's read at a session's open, and never across a dial.
#[derive(Debug)]
struct BoardSlot {
    board: Arc<Board>,
    hold: Mutex<BoardHold>,
    /// Whether a resend drains this board now: one drain per board at a
    /// time, whatever thread reaches [`Holds::probe`] — the board's feed
    /// thread every `PROBE_CADENCE`, at its daemon-running tick, and at the
    /// hand-overs of `resolve(send)` and `set_node_state(Running)` — so none
    /// double-sends.
    draining: AtomicBool,
}

impl BoardSlot {
    /// The board's hold, locked: this board's alone.
    fn lock(&self) -> MutexGuard<'_, BoardHold> {
        self.hold.lock().expect("a board's hold lock")
    }
}

/// THE HOLDS: every board's hold, shared by the shell (the `op` row's one
/// path, `held` and `resolve`, a session's open, `set_node_state`) and the
/// boards' feed threads (the probe, the `/health` read, the daemon-running
/// end).
/// The boards are the shell's, fixed at its open, each under its own lock.
/// A method about a session reaches its board through the session — its
/// `board_reference` the hold's key, its `board` the board dialed — and the
/// board-wide ones (`probe`, `set_node_stopped`, `node_stopped`,
/// `note_health`) take the board's reference. PRECONDITION, the caller's:
/// each reference names a board the holds were opened over — held by
/// construction, a session registered at one of the shell's boards and
/// each feed thread probing its own board; a reference outside them is a
/// bug of this crate's, and the method panics naming the obligation.
pub struct Holds {
    sessions: Arc<Sessions>,
    bus: Arc<EventBus>,
    /// The KEY store a signed session's attest is signed from
    /// (`SessionEntry::attest`); the held store is `held`'s files under
    /// `data_dir`.
    key_store: Arc<FileStore>,
    data_dir: PathBuf,
    talk: Talk,
    boards: HashMap<String, BoardSlot>,
}

impl Holds {
    /// The holds for a shell over `boards` — each board's reference and the
    /// board dialed, the shell's for its life: nothing is dialed and nothing
    /// on disk touched until a session opens at one.
    pub fn new(sessions: Arc<Sessions>, bus: Arc<EventBus>, key_store: Arc<FileStore>, data_dir: PathBuf, talk: Talk, boards: impl IntoIterator<Item = (String, Arc<Board>)>) -> Arc<Holds> {
        let boards = boards
            .into_iter()
            .map(|(reference, board)| {
                let hold = BoardHold { directory: Directory::NotYet("no session has opened at this board yet".to_string()), writes_halted: false, node_stopped: false, principals: HashMap::new() };
                (reference, BoardSlot { board, hold: Mutex::new(hold), draining: AtomicBool::new(false) })
            })
            .collect();
        Arc::new(Holds { sessions, bus, key_store, data_dir, talk, boards })
    }

    fn say(&self, line: impl AsRef<str>) {
        (self.talk)(line.as_ref());
    }

    /// The board `board_reference` names — the one place the type's
    /// precondition is asked, every method reaching a board through here.
    fn slot(&self, board_reference: &str) -> &BoardSlot {
        self.boards.get(board_reference).unwrap_or_else(|| panic!("PRECONDITION of `Holds`: `{board_reference}` names a board the holds were opened over"))
    }

    /// The hold of the board `board_reference` names, under that board's lock.
    fn lock(&self, board_reference: &str) -> MutexGuard<'_, BoardHold> {
        self.slot(board_reference).lock()
    }

    /// `f` over `principal`'s hold at the board, under the board's lock,
    /// where the principal has one there.
    fn with_principal<T>(&self, board_reference: &str, principal: u64, f: impl FnOnce(&mut PrincipalHold) -> T) -> Option<T> {
        self.lock(board_reference).principals.get_mut(&principal).map(f)
    }

    /// The own node's STOPPED state as its owner reports it (§3c.4): every
    /// burst holds `stopped`, and the probe waits for `Running` to resend.
    pub fn set_node_stopped(&self, board_reference: &str, stopped: bool) {
        self.lock(board_reference).node_stopped = stopped;
    }

    /// Whether the board's node stands STOPPED by its owner's act
    /// ([`Holds::set_node_stopped`]) — what `probe` answers for the own node,
    /// and what the feed reads when the board's stream fails, so a deliberate
    /// stop is announced `stopped` once and never `unreachable` beside it. A
    /// board that is not the own node answers false.
    pub fn node_stopped(&self, board_reference: &str) -> bool {
        self.lock(board_reference).node_stopped
    }

    /// A SESSION OPENED at the board (§3c.7 items 1 and 4): the board's
    /// directory established where it is not yet, and the session's
    /// principal's file read whole under its account — P38's faces kept, a
    /// misplaced file set aside and said in the shell's own window — so
    /// `held(session)` lists its lines at once and the next probe resends
    /// them. No other principal's file is opened (P39).
    pub fn open_session(&self, session: &SessionEntry) {
        let slot = self.slot(&session.board_reference);
        self.establish(slot);
        // A halted file is answered at the principal's next act.
        let _ = self.principal_hold(&mut slot.lock(), session);
    }

    /// The board's directory established where it is not yet: `H.1` read
    /// OUTSIDE the lock (the board keeps the term once found), the directory
    /// then made and locked under it. A hold never comes here: it never
    /// dials to learn where to write.
    fn establish(&self, slot: &BoardSlot) {
        if !matches!(slot.lock().directory, Directory::NotYet(_)) {
            return;
        }
        let board_term = slot.board.board_term();
        let mut board_hold = slot.lock();
        if matches!(board_hold.directory, Directory::NotYet(_)) {
            board_hold.directory = Directory::of(&self.data_dir, board_term);
        }
    }

    /// THE PRINCIPAL's HOLD at `board_hold`'s board — the one door every
    /// entry that names a principal takes: a session's open, a burst, a hold,
    /// `held` and `resolve`. A principal whose custody is not settled, and
    /// whose queue holds no line, is opened here under `session`'s account:
    /// its file where the board's directory is this shell's, memory alone
    /// otherwise. Under the session that stands, so the restart arm's re-open
    /// is covered too. Refused `store_halted` where P38 halted the
    /// principal's file (§3c.3): every act's refusal, answered at the door,
    /// so no act reaches a halted principal's queue.
    fn principal_hold<'b>(&self, board_hold: &'b mut BoardHold, session: &SessionEntry) -> Result<&'b mut PrincipalHold, Refusal> {
        let BoardHold { directory, principals, .. } = board_hold;
        let principal = session.facts.principal;
        let ph = principals.entry(principal).or_insert_with(PrincipalHold::new);
        if !ph.custody.settled() && ph.queue.lines().is_empty() {
            match directory {
                Directory::ThisWindow { dir, .. } => match dir.open_file(principal, session.facts.account.as_deref().unwrap_or("")) {
                    Ok(Opened::Live { queue, aside }) => {
                        if let Some(aside) = aside {
                            self.say(format!("held: principal {principal}'s held file named another board or principal, and is set aside at {}", aside.display()));
                        }
                        ph.queue = queue;
                        ph.custody = Custody::File;
                    }
                    Ok(Opened::Halted { path, why }) => ph.custody = Custody::Halted { path, why },
                    Err(e) => ph.custody = Custody::Unwritable(format!("the held file could not be read: {e}")),
                },
                Directory::OtherWindow => ph.custody = Custody::OtherWindow,
                Directory::NotYet(why) => ph.custody = Custody::Unwritable(why.clone()),
            }
        }
        if let Custody::Halted { path, why } = &ph.custody {
            return Err(store_halted(path, *why));
        }
        Ok(ph)
    }

    /// THE `op` ROW's SESSION FORM, `/op-at`'s aside: ONE frame under
    /// `session` at the board it stands at. A burst ([`is_burst`]) enters by
    /// its door and may be held (`send_burst`); any other frame — a write the
    /// hold never holds, or a read — is attested where an attest is owed,
    /// dialed and reissued within the call, its ack noted for the base, and
    /// every other answer faced as the refusal it is: a REFUSED run, a lost
    /// answer and a third `durability` among them (§3c.4: "a non-burst write
    /// that fails … is faced at its act").
    pub fn send(&self, session: &SessionEntry, frame: Value) -> OpAnswer {
        if is_burst(&frame) {
            return self.send_burst(session, frame);
        }
        match self.dial_within_call(session, &frame) {
            Dialed::Acked(ack) => {
                self.note_ack(session, &frame, &ack);
                OpAnswer::Answered(Ok(ack))
            }
            Dialed::Held { refusal, .. } | Dialed::Reissue { refusal, .. } | Dialed::Faced(refusal) => OpAnswer::Answered(Err(refusal)),
            Dialed::Died => OpAnswer::Died,
        }
    }

    /// THE BURST's WRITE PATH (§3c.4), its checks in this order, the first
    /// that holds answering: ADMITTED ([`Burst::admit`]), its refusal faced
    /// at the act; refused `store_halted` where P38 halted the principal's
    /// file (the door, [`Holds::principal_hold`]); HELD WITHOUT A DIAL where
    /// a hold stands at the board — the own node stopped, else the board
    /// halted, else a line of the principal's already held (`behind`); else
    /// dialed within the call ([`Holds::dial_within_call`]): an ack carried
    /// and its `at` noted; a hold-class answer or a REFUSED run held and
    /// answered `held` — a third `durability` among them (§3c.4's rider);
    /// anything else faced at the act.
    fn send_burst(&self, session: &SessionEntry, frame: Value) -> OpAnswer {
        let burst = match Burst::admit(frame, session) {
            Ok(burst) => burst,
            Err(refusal) => return OpAnswer::Answered(Err(refusal)),
        };
        {
            let mut board_hold = self.lock(&session.board_reference);
            let (node_stopped, writes_halted) = (board_hold.node_stopped, board_hold.writes_halted);
            let line_stands = match self.principal_hold(&mut board_hold, session) {
                Ok(ph) => !ph.queue.lines().is_empty(),
                Err(refusal) => return OpAnswer::Answered(Err(refusal)),
            };
            let hold_cause = if node_stopped {
                Some(cause::STOPPED)
            } else if writes_halted {
                Some(cause::HALTED)
            } else if line_stands {
                Some(cause::BEHIND)
            } else {
                None
            };
            if let Some(cause) = hold_cause {
                return OpAnswer::Answered(self.hold_line(&mut board_hold, session, burst, Reason::of(cause, false)));
            }
        }
        match self.dial_within_call(session, burst.frame()) {
            Dialed::Acked(ack) => {
                self.note_ack(session, burst.frame(), &ack);
                OpAnswer::Answered(Ok(ack))
            }
            Dialed::Held { reason, .. } => OpAnswer::Answered(self.hold(session, burst, reason)),
            Dialed::Reissue { refusal, .. } | Dialed::Faced(refusal) => OpAnswer::Answered(Err(refusal)),
            Dialed::Died => OpAnswer::Died,
        }
    }

    /// ONE WRITE's DIALS within its call (§4b.1's `op` row: reissue-class
    /// answers are "reissued by the shell and reach the page as the ack or
    /// the next refusal"): `frame` attested once where an attest is owed
    /// ([`Holds::attest_where_owed`]), then dialed, a reissue-class answer
    /// reissued as [`classify`] bounds it — a `write_busy` once after
    /// [`WRITE_BUSY_WAIT`], a first and second `durability` as-is — and the
    /// first other answer returned: never a reissue, so its caller meets the
    /// ack or the next refusal.
    fn dial_within_call(&self, session: &SessionEntry, frame: &Value) -> Dialed {
        let frame = match self.attest_where_owed(session, frame) {
            Ok(frame) => frame,
            Err(why) => return Dialed::from(why),
        };
        let mut given = Reissues::default();
        loop {
            match self.dial(session, &frame, given) {
                Dialed::Reissue { kind, .. } => {
                    given.note(kind);
                    thread::sleep(kind.wait());
                }
                dialed => return dialed,
            }
        }
    }

    /// HOLD an admitted burst for `reason`, as a dial's answer held it — the
    /// burst taken, its frame the held line's own: the `held` answer
    /// ([`Holds::hold_line`]), or `store_halted` where P38 halted the file.
    pub fn hold(&self, session: &SessionEntry, burst: Burst, reason: Reason) -> Result<Value, Refusal> {
        self.hold_line(&mut self.lock(&session.board_reference), session, burst, reason)
    }

    /// One line entered in the principal's queue at the session's board,
    /// `board_hold` that board's hold — the burst as stored, its frame
    /// carrying no attest, copied to its file where it has one, its `base`
    /// the `at` of the last acked write on the document or else the
    /// session's open position (§3c.2) — the `held` event emitted, and the
    /// answer: `{resp: held, held: <k>, cause}`, the cause `other_window`
    /// where another window's lock keeps the line in memory alone, and
    /// `unwritable` beside it — why — where the device refused its copy or
    /// the file is out of reach (§3c.3); `held_full` where the principal's
    /// queue holds its budget already (`held::MAX_HELD_FRAME_BYTES`'s bytes,
    /// or `held::MAX_HELD_LINES`'s lines), and nothing held.
    fn hold_line(&self, board_hold: &mut BoardHold, session: &SessionEntry, burst: Burst, reason: Reason) -> Result<Value, Refusal> {
        let ph = self.principal_hold(board_hold, session)?;
        let (doc, frame) = burst.into_stored();
        let id = frame["id"].as_str().map(str::to_owned);
        let base = ph.last_acked.get(&doc).copied().unwrap_or(session.opened_at);
        let state = line_state(&reason);
        let mut said = reason.cause.clone();
        let entered = ph.queue.hold(&doc, id.as_deref(), base, frame, reason).map_err(queue_refused)?;
        let unwritable = match &ph.custody {
            Custody::OtherWindow => {
                said = cause::OTHER_WINDOW.to_string();
                self.say(format!("held: another window holds this board's held text; {doc}'s burst is kept in memory alone"));
                None
            }
            Custody::Unwritable(why) => Some(why.clone()),
            _ => entered.unwritten.map(|e| e.to_string()),
        };
        let mut answer = json!({"resp": "held", "held": entered.k, "cause": said});
        if let Some(why) = unwritable {
            answer["unwritable"] = Value::from(why);
        }
        // `emit_held` touches the bus alone, so it is safe under the board's
        // lock.
        self.emit_held(session, &doc, ph.count(&doc), state, Some(&said));
        Ok(answer)
    }

    /// An ACKED session write noted (§3c.2): its `at` becomes the `base` of
    /// the next hold on every document its row names — whatever its kind,
    /// a burst's, a mint's or a link's, the first dial's and the resend's
    /// alike, each noted where its answer is read. A read, or a refusal,
    /// notes nothing.
    fn note_ack(&self, session: &SessionEntry, frame: &Value, ack: &Value) {
        let Some(at) = acked_at(ack) else { return };
        let docs = written_docs(frame, ack);
        if docs.is_empty() {
            return;
        }
        let mut board_hold = self.lock(&session.board_reference);
        let ph = board_hold.principals.entry(session.facts.principal).or_insert_with(PrincipalHold::new);
        for doc in docs {
            ph.last_acked.insert(doc.to_string(), at);
        }
    }

    /// `held(session)` → the acting principal's held lines at the session's
    /// board in resend order (§4b.1), from this principal's file and no
    /// other (P39); `store_halted` where P38 halted the file.
    pub fn lines(&self, session: &SessionEntry) -> Result<Value, Refusal> {
        let mut board_hold = self.lock(&session.board_reference);
        let ph = self.principal_hold(&mut board_hold, session)?;
        Ok(Value::Array(ph.queue.lines().iter().map(line_json).collect()))
    }

    /// `resolve(session, {held, act})` (§3c.4, §4b.1), checked and acted on
    /// under the board's one lock, its refusals in this order, the first
    /// that holds answering: `store_halted` where P38 halted the principal's
    /// file; `no_such_held` where no line of ordinal `k` stands;
    /// `not_resolvable` where the line awaits no act of the person's (P10).
    /// [`ResolveAct::Drop`] marks the line — and, for a refused run, every
    /// line held `behind` it on that document — `done … dropped`;
    /// [`ResolveAct::Send`] re-marks the document's waiting lines `behind`,
    /// handing them back to the automatic machine, and answers at once
    /// ([`Resolved::HandedBack`]): the probe that resends them is the
    /// caller's to hand the board's feed thread.
    pub fn resolve(&self, session: &SessionEntry, k: u64, act: ResolveAct) -> Result<Resolved, Refusal> {
        let mut board_hold = self.lock(&session.board_reference);
        let ph = self.principal_hold(&mut board_hold, session)?;
        let Some(line) = ph.queue.lines().iter().find(|l| l.k == k) else { return Err(Refusal::shell(Name::NO_SUCH_HELD, json!({"held": k}))) };
        // A line awaiting the person's act alone takes one (P10).
        if !awaits_act(line) {
            return Err(Refusal::shell(Name::NOT_RESOLVABLE, json!({"held": k})));
        }
        let doc = line.doc.clone();
        match act {
            ResolveAct::Drop => {
                let (count, state) = self.drop_run(ph, k, &doc);
                // `emit_held` touches the bus alone, so it is safe under the
                // board's lock.
                self.emit_held(session, &doc, count, state, None);
                Ok(Resolved::Dropped)
            }
            ResolveAct::Send => {
                // Re-enter the automatic machine (§3c.4, RULED "button then"):
                // the document's waiting lines re-marked `behind`, the read run
                // afresh at the next probe, and the refusal faced again where
                // it recurs.
                let ks: Vec<u64> = ph.queue.lines().iter().filter(|l| l.doc == doc && awaits_act(l)).map(|l| l.k).collect();
                for k in ks {
                    self.remark_line(ph, k, Reason::of(cause::BEHIND, false));
                }
                Ok(Resolved::HandedBack)
            }
        }
    }

    /// `"drop"`: the line `from` and every line after it on that document —
    /// a refused run's `behind` lines — marked `done … dropped`, the file
    /// compacting where the queue empties; answered for the `held` event its
    /// caller emits under the session that acted: the lines that stand on
    /// the document, and the state of the one that stands first now — a
    /// MOVED line held before the dropped one keeps the document `moved` —
    /// `kept` only where no line stands.
    fn drop_run(&self, ph: &mut PrincipalHold, from: u64, doc: &str) -> (u64, HeldState) {
        let ks: Vec<u64> = ph.queue.lines().iter().filter(|l| l.doc == doc && l.k >= from).map(|l| l.k).collect();
        for k in ks {
            self.done_line(ph, k, Done::Dropped);
        }
        let head = ph.queue.lines().iter().find(|l| l.doc == doc);
        (ph.count(doc), head.map_or(HeldState::Kept, |l| line_state(&l.reason)))
    }

    /// The board's `/health` as the feed's tick or the probe read it: its
    /// `writes.halted` (wire.md §The other endpoints) noted — every burst
    /// holds `halted` from the first `true` to the next `false` (§3c.4) —
    /// and answered.
    pub fn note_health(&self, board_reference: &str, health: &Health) -> bool {
        let writes_halted = health.body["writes"]["halted"].as_bool().unwrap_or(false);
        self.lock(board_reference).writes_halted = writes_halted;
        writes_halted
    }

    /// The frame a send under `session` dials ([`AttestedWhereOwed`]), its
    /// attest composed now where one is owed — or why none could be, nothing
    /// dialed, which the send answers as `Dialed`'s `From<Unattested>` reads
    /// it.
    fn attest_where_owed(&self, session: &SessionEntry, frame: &Value) -> Result<AttestedWhereOwed, Unattested> {
        let mut frame = frame.clone();
        session.attest(&self.key_store, &mut frame)?;
        Ok(AttestedWhereOwed(frame))
    }

    /// ONE DIAL of an [`AttestedWhereOwed`] frame under `session` at the
    /// board it stands at, its answer read ONCE through [`classify`], `given`
    /// the reissues this write has been given. A non-200 is read by its code,
    /// so `write_busy`'s 503 meets its row.
    fn dial(&self, session: &SessionEntry, frame: &AttestedWhereOwed, given: Reissues) -> Dialed {
        match session.board.op(Some(&session.token), &frame.0) {
            Ok(Answer::Closed) => Dialed::Died,
            Ok(Answer::Document(v)) => match Rejection::of(&v) {
                None => Dialed::Acked(v),
                Some(r) => {
                    let decision = classify(DialOutcome::Rejected { code: r.key(), disposition: v["disposition"].as_str().unwrap_or("") }, given);
                    let refusal = Refusal::from(r.refused(&v));
                    Dialed::refused(decision, &r.token(), v, refusal)
                }
            },
            Err(Halt::Dial(e)) => match classify(DialOutcome::Dial(&e), given) {
                Decision::Hold { cause, sent } => Dialed::Held { reason: Reason::of(cause, sent), refusal: Refusal::Unreachable(e) },
                _ => Dialed::Faced(Refusal::Unreachable(e)),
            },
            Err(Halt::Refused(r)) => {
                let decision = classify(DialOutcome::Rejected { code: &r.code, disposition: r.body["disposition"].as_str().unwrap_or("") }, given);
                // A REFUSED run's line keeps the verdict, and the refusal the
                // body it was read from: two owners, one copy.
                let (token, verdict) = (r.token(), r.body.clone());
                Dialed::refused(decision, &token, verdict, Refusal::Board(r))
            }
            Err(h) => Dialed::Faced(Refusal::from(h)),
        }
    }

    /// Re-mark one line in place — a hold that recurs, a refused run, a moved
    /// re-facing — its ordinal kept; a copy refused, by the device or past
    /// the file's re-mark budget, said on TALK.
    fn remark_line(&self, ph: &mut PrincipalHold, k: u64, reason: Reason) {
        if let Err(e) = ph.queue.remark(k, reason) {
            self.say(format!("held: line {k}'s new cause could not be written ({e}); a reopen reads its earlier one"));
        }
    }

    /// One line out of the queue, whatever the disk did; a `done` the device
    /// refused said on TALK.
    fn done_line(&self, ph: &mut PrincipalHold, k: u64, done: Done) {
        if let Err(DoneError::Unwritten(e)) = ph.queue.done(k, done) {
            self.say(format!("held: line {k} is settled, and its `done` could not be written ({e}); a reopen reads it as held, and its read decides it"));
        }
        ph.reissues.remove(&k);
    }

    /// Emit the `held` event (§4b.2): `{board, session, doc, held, state,
    /// cause?}`, under the session the change was made for, at its board.
    fn emit_held(&self, session: &SessionEntry, doc: &str, held: u64, state: HeldState, cause: Option<&str>) {
        let mut data = json!({"board": session.board_reference, "session": session.reference, "doc": doc, "held": held, "state": state.as_str()});
        if let Some(c) = cause {
            data["cause"] = Value::from(c);
        }
        self.bus.emit(EventName::Held, data);
    }
}

/// The refusal for what the queue refused (`held::Unheld`): the principal's
/// queue full — its frames' bytes or its lines — or — never for a burst
/// [`Burst::admit`] let in — a line no reader of the file reads.
fn queue_refused(why: Unheld) -> Refusal {
    match why {
        Unheld::Full { held_bytes, frame_bytes, held_lines } => Refusal::shell(
            Name::HELD_FULL,
            json!({"held_bytes": held_bytes, "frame_bytes": frame_bytes, "cap": MAX_HELD_FRAME_BYTES, "held_lines": held_lines, "line_cap": MAX_HELD_LINES}),
        ),
        Unheld::Unreadable => Refusal::malformed("frame.doc"),
    }
}

/// P38's halt face for `held(session)` and every act (§3c.3).
fn store_halted(path: &Path, why: HaltWhy) -> Refusal {
    Refusal::shell(Name::STORE_HALTED, json!({"path": path.display().to_string(), "why": why.token()}))
}

/// One held line as `held(session)` lists it (§4b.1): the line's members,
/// `refusal` beside a refused run's.
fn line_json(l: &HeldLine) -> Value {
    let mut line = json!({"held": l.k, "doc": l.doc, "base": l.base, "frame": l.frame, "cause": l.reason.cause, "sent": l.reason.sent, "time": l.time});
    if let Some(r) = &l.reason.refusal {
        line["refusal"] = r.clone();
    }
    line
}

/// The documents an acked write's `/changes` row names (wire.md §The change
/// feed: "the target for arrangement writes, the HOME for link writes, the
/// MINTED document for mints"), from its frame and its ack.
fn written_docs<'a>(frame: &'a Value, ack: &'a Value) -> Vec<&'a str> {
    let members: &[&str] = match frame["op"].as_str() {
        Some("create_new_document" | "fork" | "version" | "publish") => return ack["addr"].as_str().into_iter().collect(),
        Some("make_link" | "emit" | "nullify" | "assert_sup") => &["home"],
        Some("edit_link") => &["d_s", "d_a"],
        _ => &["doc"],
    };
    members.iter().filter_map(|m| frame[*m].as_str()).collect()
}

#[cfg(test)]
mod tests;
