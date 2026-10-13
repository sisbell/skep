//! THE HOLD (`client.md` §3c.4, §3c.5): a burst's write path, the
//! per-(board, principal) queue the shell consults on every burst, and the
//! resend walk that drains the queue once the board returns.
//!
//! A BURST is an `op` under a session (never the guest form) whose
//! `frame["op"]` is one of [`BURST_KINDS`] — the burst machine's five — on a
//! draft. It enters by ONE DOOR, [`Burst::admit`], which refuses at the act a
//! frame the board takes at no send — one past the board's frame cap, one
//! naming no document, an insert a signed session cannot attest — since a
//! held line of it could be sent and resolved never, and would hold every
//! later burst of its principal `behind` it. Its WRITE PATH is this module's,
//! at the first dial and at every resend alike: [`Holds::send_burst`] holds
//! it WITHOUT a dial where a hold stands — the own node stopped, the board
//! halted, a line of the principal's already held — and else attests it and
//! dials it, each answer read through THE CLASSIFICATION TABLE
//! ([`classify`]: §3c.4's HOLD(cause) / REISSUE / NEITHER): an ack carried
//! and its `at` noted, a hold-class answer or a REFUSED run held, a
//! reissue-class answer reissued within the call — a `write_busy` once after
//! [`WRITE_BUSY_WAIT`], a first and second `durability` as-is — and anything
//! else faced at the act. The resend sends each held line through the same
//! reader, a reissue-class answer there reissued at the next wake.
//!
//! THE QUEUE is each principal's [`HeldQueue`], in `k` order across the
//! board's documents: copied to `held/<chain>/principal-<n>.held` where this
//! shell holds the board's directory (§3c.1), kept in memory alone where
//! another window holds it or the directory is out of reach (§3c.3), and
//! opened only under a session as its principal (P39) — at the session's
//! open, or at the first touch after it. THE PROBE ([`Holds::probe`]) runs on
//! the feed worker's thread every [`PROBE_CADENCE`] while a line stands, and
//! there too at `resolve(send)`'s hand-over, because `Cmd::Tick` is driven by
//! COMMITTED writes and a poisoned, halted, stopped or unreachable board
//! commits nothing. THE RESEND it lets run is
//! AUTOMATIC at the hold's end and at reopen (J2): one READ per document
//! (`GET /changes`) before its first resend, with §3c.5's three outcomes —
//! (i) nothing landed, send from the head; (ii) the in-flight burst landed,
//! the head `done kept`; (iii) the site MOVED, no line sent and the lines
//! faced `moved`, NEVER rebased (J3) — and a read the board did not answer
//! decides nothing: the next wake reads again.
//!
//! EACH BOARD's HOLD ITS OWN LOCK, the boards fixed at the open: a board's
//! appends, each synced to disk, its file's read at a session's open and its
//! resend's bookkeeping hold that board's lock alone, so no board's wait is
//! another's.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::Duration;

use serde_json::{json, Value};
use skep_client::board::{acked_at, frames, Answer, Board, ChangesAnswer, ChangesQuery, Rejection};
use skep_client::halt::Halt;
use skep_client::store::FileStore;
use skep_client::DialError;
use skep_identity::BoardTerm;
use skep_search::Chain;

use crate::attest::{attest_room, delivered_values, document_address, in_checked_set, insert_terms, values_of, Unattested, MAX_FRAME_BYTES};
use crate::events::{EventBus, EventName};
use crate::held::{Done, DoneError, HaltWhy, HeldDir, HeldLine, HeldQueue, Opened, Reason, Unheld, MAX_HELD_FRAME_BYTES};
use crate::log::json_len;
use crate::refusal::{Name, Refusal};
use crate::sessions::{Kind, SessionEntry, Sessions};
use crate::Talk;

/// THE INTERIM PROBE CADENCE (§3c.4): `GET /health` at this interval while a
/// burst is held at a board — the lane's to tune.
pub const PROBE_CADENCE: Duration = Duration::from_secs(2);

/// THE SHORT WAIT before a `write_busy` is reissued (§3c.4: "a silent
/// reissue after a short wait") — INTERIM, the lane's to tune, as
/// [`PROBE_CADENCE`] is.
pub const WRITE_BUSY_WAIT: Duration = Duration::from_millis(50);

/// The burst machine's five kinds (§3c.4) — the ops the store holds.
pub const BURST_KINDS: [&str; 5] = ["insert", "delete", "copy", "reinstate", "rearrange"];

/// Whether `frame` is a burst: one of the five kinds (§3c.4 says "on a draft
/// under the session" — the kind test is the shell's; a write on a document
/// that is no draft is the board's refusal, permanent, and so a refused run).
pub fn is_burst(frame: &Value) -> bool {
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

/// What a burst's dial answered that [`classify`] reads (§3c.4). The own node
/// STOPPED (no dial), an ACK, the death signal and a non-burst write are not
/// here: a stop holds the burst before any dial, an ack is carried as any
/// `op`'s, the death signal ends the session, and a non-burst never comes.
#[derive(Debug, Clone, Copy)]
pub enum DialOutcome<'a> {
    /// The dial failed at the transport.
    Dial(&'a DialError),
    /// The board refused: a `rejected` document's key, or a non-200's error,
    /// and the `disposition` the body rode.
    Rejected { code: &'a str, disposition: &'a str },
}

/// What the shell does with a burst's outcome (§3c.4's table).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// HOLD the burst with this cause; `sent` whether the burst MAY have
    /// landed (§3c.2): a dial made whose answer was lost, or a `poisoned`
    /// answer, whose frames the board's journal keeps for its restart.
    Hold { cause: &'static str, sent: bool },
    /// A REFUSED run — a `permanent` or `reorder` refusal, held with the
    /// board's token for its cause and its verdict beside it.
    Refused,
    /// REISSUE, silently, of this kind — within the first dial's call; on a
    /// resend, at the next wake.
    Reissue(Reissue),
    /// NEITHER held nor reissued — faced at its act.
    Neither,
}

/// A REISSUE-class refusal (§3c.4's REISSUE row): its kind names the wait
/// before the reissue and the count [`classify`] bounds it by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reissue {
    /// `503 write_busy`, the board's write permits all held: reissued ONCE,
    /// after [`WRITE_BUSY_WAIT`].
    WriteBusy,
    /// `durability`, the board's durability barrier failed: reissued as-is,
    /// a first and a second time.
    Durability,
}

impl Reissue {
    /// The wait before the reissue.
    pub fn wait(self) -> Duration {
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
pub struct Reissues {
    write_busy: u32,
    durability: u32,
}

impl Reissues {
    /// One reissue of `kind` given.
    pub fn note(&mut self, kind: Reissue) {
        match kind {
            Reissue::WriteBusy => self.write_busy += 1,
            Reissue::Durability => self.durability += 1,
        }
    }
}

/// THE CLASSIFICATION TABLE (§3c.4): a burst's outcome, and the reissues
/// the SAME burst has been given, to exactly one row — the one owner of
/// every reissue's bound.
pub fn classify(outcome: DialOutcome<'_>, given: Reissues) -> Decision {
    match outcome {
        DialOutcome::Dial(e) => match e {
            // No connection was made — the burst did not leave.
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
            // AFTER the burst's frames reached its journal, and a restart's open
            // "rebuilds the line from the journal" (wire.md §Rejection codes) —
            // the burst lands at the restart, so the resend READS before it
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
            // The rider (§3c.4): a THIRD `durability` on the same burst HOLDS it.
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

/// THE REISSUE ROW alone, for a write the hold never holds — any `/op`
/// under a session but a burst's (§3c.4: "a non-burst write that fails … is
/// faced at its act"): the reissue `answer` owes, given the reissues the
/// write has been given; `None` where the answer is the write's to carry or
/// to face as it stands — its third `durability` among them, which a burst's
/// hold alone keeps.
pub fn reissue_of(answer: &Result<Answer, Halt>, given: Reissues) -> Option<Reissue> {
    let decision = match answer {
        Ok(Answer::Document(v)) => {
            let r = Rejection::of(v)?;
            classify(DialOutcome::Rejected { code: r.key(), disposition: v["disposition"].as_str().unwrap_or("") }, given)
        }
        Err(Halt::Refused(r)) => classify(DialOutcome::Rejected { code: &r.code, disposition: r.body["disposition"].as_str().unwrap_or("") }, given),
        _ => return None,
    };
    match decision {
        Decision::Reissue(kind) => Some(kind),
        _ => None,
    }
}

/// What a burst's `op` answers the page (§3c.4).
pub enum BurstAnswer {
    /// The board's ack, the shell's `held`, or the refusal faced at the act.
    Answered(Result<Value, Refusal>),
    /// The death signal on the session's token: the caller ends the session,
    /// and the burst is not held (§3c.4: the death signal is neither).
    Died,
}

/// What a `resolve` act did (§4b.1's `resolve` row), the call's answer `{}`
/// either way.
#[must_use = "a `Rearmed` document's resend waits on the probe its caller hands the board's worker"]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolved {
    /// `"drop"`: the line, and a refused run's `behind` lines with it,
    /// `done … dropped`.
    Dropped,
    /// `"send"`: the document's waiting lines re-armed `behind`, back in the
    /// automatic machine — the caller hands the board's worker its probe, so
    /// the call answers once the lines are handed back, never after a
    /// resend's ack.
    Rearmed,
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
    ///   (`attest::document_address`) — what the resend's read names `under`
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
        let attested = matches!(session.facts.kind, Kind::Signed { .. }) && frame["op"].as_str().is_some_and(in_checked_set);
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
    pub fn frame(&self) -> &Value {
        &self.frame
    }

    /// The frame's document, in its one spelling.
    pub fn doc(&self) -> &str {
        &self.doc
    }
}

/// What ONE dial of a burst answered, read once through the table.
enum Dialed {
    /// The board's ack.
    Acked(Value),
    /// A hold-class answer, or a REFUSED run: the line's reason.
    Held(Reason),
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
    /// REFUSED run with the board's `token` and verdict, reissued, or faced.
    fn refused(decision: Decision, token: &str, verdict: &Value, refusal: Refusal) -> Dialed {
        match decision {
            Decision::Hold { cause, sent } => Dialed::Held(Reason::of(cause, sent)),
            Decision::Refused => Dialed::Held(Reason::refused(token, verdict.clone())),
            Decision::Reissue(kind) => Dialed::Reissue { kind, refusal },
            Decision::Neither => Dialed::Faced(refusal),
        }
    }
}

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
/// document's (§3c.4, §3c.5): no wake sends it, and `resolve` alone moves it.
fn awaits_act(line: &HeldLine) -> bool {
    matches!(line_state(&line.reason), HeldState::Refused | HeldState::Moved)
}

/// THE OUTCOME of the resend's one read per document (§3c.5).
enum ReadOutcome {
    /// No row since `base` — send from the head.
    SendFromHead,
    /// The in-flight burst landed — the head is `done kept` with this `at`.
    Landed { at: Option<u64> },
    /// The site MOVED — no line sent, the lines faced `moved` (J3).
    Moved,
    /// The board answered no page — a refusal (`feed_rebuilding`), the
    /// death signal, no answer: nothing is decided, and the next wake reads
    /// again.
    Unread,
}

/// What ONE `retrieve_v` at a held burst's site says of its values (§3c.5's
/// content confirm).
enum Site {
    /// The values read back equal: the burst stands there.
    Equal,
    /// Other values, or none (the site out of the document's bounds).
    Differs,
    /// No read can decide: a burst of another kind than `insert`, or a frame
    /// that names no site.
    Unconfirmable,
    /// The board did not answer the read.
    Unread,
}

/// The board's `held/<chain>/` (§3c.1) as this shell stands to it.
enum Directory {
    /// Not this shell's yet — why: `H.1` not read, or the directory or its
    /// lock refused. Tried again at a session's open and at the probe.
    Unknown(String),
    /// This shell's for its life: the directory, and the `flock` on its lock.
    ThisWindow { dir: HeldDir, _lock: File },
    /// Another window holds the lock: every line here is kept in this
    /// shell's memory alone (§3c.3).
    OtherWindow,
}

impl Directory {
    /// The directory `H.1`'s read names (§3c.1): made `0700` and locked where
    /// the term stands, another window's where its lock is held, and not yet
    /// this shell's — why said — where the board has no `H.1` (an unclaimed
    /// board keeps no held text) or the read, the directory or the lock
    /// refused.
    fn of(data_dir: &Path, term: Result<Option<BoardTerm>, Halt>) -> Directory {
        let term = match term {
            Ok(Some(term)) => term,
            Ok(None) => return Directory::Unknown("the board has no H.1 yet, and an unclaimed board keeps no held text".to_string()),
            Err(h) => return Directory::Unknown(format!("the board's H.1 could not be read: {h}")),
        };
        let dir = HeldDir::new(data_dir, Chain::from_bytes(term.chain));
        match dir.ensure().and_then(|()| dir.try_lock()) {
            Ok(Some(lock)) => Directory::ThisWindow { dir, _lock: lock },
            Ok(None) => Directory::OtherWindow,
            Err(e) => Directory::Unknown(format!("the held store could not be made or locked: {e}")),
        }
    }
}

/// Where a principal's held lines are kept at a board (§3c.3).
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
    /// principal at this board, each act answered `store_halted`.
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
/// been given, counted across its wakes.
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
struct BoardSlot {
    board: Arc<Board>,
    hold: Mutex<BoardHold>,
}

impl BoardSlot {
    /// The board's hold, locked: this board's alone.
    fn lock(&self) -> MutexGuard<'_, BoardHold> {
        self.hold.lock().expect("a board's hold lock")
    }
}

/// THE HOLDS: every board's hold, shared by the shell (the `op` row's burst,
/// `held` and `resolve`, a session's open, `set_node_state`) and the feed
/// workers (the probe, the `writes.halted` read, the daemon-running end).
/// The boards are the shell's, fixed at its open, each under its own lock.
/// PRECONDITION of every method taking a `board_reference`, the caller's: it
/// names a board the holds were opened over — held by construction, a
/// session standing at one of the shell's boards and each feed worker
/// probing its own; a reference outside them is a bug of this crate's, and
/// the method panics naming the obligation.
pub struct Holds {
    sessions: Arc<Sessions>,
    bus: Arc<EventBus>,
    store: Arc<FileStore>,
    data_dir: PathBuf,
    talk: Talk,
    boards: HashMap<String, BoardSlot>,
    /// The boards a resend is draining now. [`Holds::probe`] is reached at
    /// the feed's cadence, its daemon-running tick and `resolve(send)`'s
    /// hand-over, and at `set_node_state(Running)`; one drain per board at a
    /// time, so none double-sends.
    resending: Mutex<HashSet<String>>,
}

/// A board's mark in [`Holds`]'s `resending` set, held for one drain and
/// cleared when the drain ends — however it ends, a dial that unwinds
/// included — so no board stays marked by a drain that never finished.
struct Draining<'h> {
    resending: &'h Mutex<HashSet<String>>,
    board_reference: &'h str,
}

impl<'h> Draining<'h> {
    /// The mark taken for `board_reference`, or `None` where a drain of it
    /// already runs.
    fn begin(resending: &'h Mutex<HashSet<String>>, board_reference: &'h str) -> Option<Draining<'h>> {
        // No guard is built where no mark was taken: dropped, it would clear
        // the mark of the drain that holds it.
        if !resending.lock().expect("the resend lock").insert(board_reference.to_string()) {
            return None;
        }
        Some(Draining { resending, board_reference })
    }
}

impl Drop for Draining<'_> {
    fn drop(&mut self) {
        // Run while a drain unwinds too: a poisoned set is still the set.
        self.resending.lock().unwrap_or_else(PoisonError::into_inner).remove(self.board_reference);
    }
}

impl Holds {
    /// The holds for a shell over `boards` — each board's reference and the
    /// board dialed, the shell's for its life: nothing is dialed and nothing
    /// on disk touched until a session opens at one.
    pub fn new(sessions: Arc<Sessions>, bus: Arc<EventBus>, store: Arc<FileStore>, data_dir: PathBuf, talk: Talk, boards: impl IntoIterator<Item = (String, Arc<Board>)>) -> Arc<Holds> {
        let boards = boards
            .into_iter()
            .map(|(reference, board)| {
                let hold = BoardHold { directory: Directory::Unknown("no session has opened at this board yet".to_string()), writes_halted: false, node_stopped: false, principals: HashMap::new() };
                (reference, BoardSlot { board, hold: Mutex::new(hold) })
            })
            .collect();
        Arc::new(Holds { sessions, bus, store, data_dir, talk, boards, resending: Mutex::new(HashSet::new()) })
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
    /// `held(session)` lists its lines at once and the probe's next wake
    /// resends them. No other principal's file is opened (P39).
    pub fn open_session(&self, board_reference: &str, session: &SessionEntry) {
        let slot = self.slot(board_reference);
        self.establish(slot);
        self.principal_hold(&mut slot.lock(), session);
    }

    /// The board's directory established where it is not yet: `H.1` read
    /// OUTSIDE the lock (the board keeps the term once found), the directory
    /// then made and locked under it. A hold never comes here: it never
    /// dials to learn where to write.
    fn establish(&self, slot: &BoardSlot) {
        if !matches!(slot.lock().directory, Directory::Unknown(_)) {
            return;
        }
        let term = slot.board.board_term();
        let mut board_hold = slot.lock();
        if matches!(board_hold.directory, Directory::Unknown(_)) {
            board_hold.directory = Directory::of(&self.data_dir, term);
        }
    }

    /// THE PRINCIPAL's HOLD at `board_hold`'s board — the one door every
    /// entry that names a principal takes: a session's open, a burst, a hold,
    /// `held` and `resolve`. A principal whose custody is not settled, and
    /// whose queue holds no line, is opened here under `session`'s account:
    /// its file where the board's directory is this shell's, memory alone
    /// otherwise. Under the session that stands, so the restart arm's re-open
    /// is covered too.
    fn principal_hold<'b>(&self, board_hold: &'b mut BoardHold, session: &SessionEntry) -> &'b mut PrincipalHold {
        let BoardHold { directory, principals, .. } = board_hold;
        let principal = session.facts.principal;
        let ph = principals.entry(principal).or_insert_with(PrincipalHold::new);
        if ph.custody.settled() || !ph.queue.lines().is_empty() {
            return ph;
        }
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
            Directory::Unknown(why) => ph.custody = Custody::Unwritable(why.clone()),
        }
        ph
    }

    /// THE BURST's WRITE PATH (§3c.4), the `op` row's for a burst, its
    /// checks in this order, the first that holds answering: ADMITTED
    /// ([`Burst::admit`]), its refusal faced at the act; refused
    /// `store_halted` where P38 halted the principal's file; HELD WITHOUT A
    /// DIAL where a hold stands at the board — the own node stopped, else the
    /// board halted, else a line of the principal's already held (`behind`);
    /// else attested and dialed, each answer read through the table: an ack
    /// carried and its `at` noted; a hold-class answer or a REFUSED run held
    /// and answered `held`; a reissue-class answer reissued within the call —
    /// a `write_busy` once after [`WRITE_BUSY_WAIT`], a first and second
    /// `durability` as-is — the reissue's own answer read as any dial's, so
    /// the page meets the ack or the next refusal, never `held` for a
    /// reissue-class one, save a third `durability`, which holds the burst
    /// (§4b.1's `op` row; §3c.4's rider); anything else faced at the act.
    pub fn send_burst(&self, board_reference: &str, session: &SessionEntry, frame: Value) -> BurstAnswer {
        let burst = match Burst::admit(frame, session) {
            Ok(burst) => burst,
            Err(refusal) => return BurstAnswer::Answered(Err(refusal)),
        };
        let slot = self.slot(board_reference);
        {
            let mut board_hold = slot.lock();
            let (node_stopped, writes_halted) = (board_hold.node_stopped, board_hold.writes_halted);
            let ph = self.principal_hold(&mut board_hold, session);
            if let Custody::Halted { path, why } = &ph.custody {
                return BurstAnswer::Answered(Err(store_halted(path, *why)));
            }
            let line_stands = !ph.queue.lines().is_empty();
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
                return BurstAnswer::Answered(self.hold_line(board_reference, &mut board_hold, session, &burst, Reason::of(cause, false)));
            }
        }
        let mut given = Reissues::default();
        loop {
            return match self.dial(&slot.board, session, burst.frame(), given) {
                Dialed::Acked(ack) => {
                    self.note_ack(board_reference, session, burst.frame(), &ack);
                    BurstAnswer::Answered(Ok(ack))
                }
                Dialed::Held(reason) => BurstAnswer::Answered(self.hold(board_reference, session, &burst, reason)),
                Dialed::Reissue { kind, .. } => {
                    given.note(kind);
                    thread::sleep(kind.wait());
                    continue;
                }
                Dialed::Faced(refusal) => BurstAnswer::Answered(Err(refusal)),
                Dialed::Died => BurstAnswer::Died,
            };
        }
    }

    /// HOLD an admitted burst for `reason`, as a dial's answer held it: the
    /// `held` answer ([`Holds::hold_line`]), or `store_halted` where P38
    /// halted the file.
    pub fn hold(&self, board_reference: &str, session: &SessionEntry, burst: &Burst, reason: Reason) -> Result<Value, Refusal> {
        self.hold_line(board_reference, &mut self.lock(board_reference), session, burst, reason)
    }

    /// One line entered in the principal's queue — copied to its file where
    /// it has one, its `base` the `at` of the last acked write on the document
    /// or else the session's open position (§3c.2) — the `held` event emitted,
    /// and the answer: `{resp: held, held: <k>, cause}`, the cause
    /// `other_window` where another window's lock keeps the line in memory
    /// alone, and `unwritable` beside it — why — where the device refused its
    /// copy or the file is out of reach (§3c.3); `held_full` where the
    /// principal's queue holds its budget already
    /// (`held::MAX_HELD_FRAME_BYTES`), and nothing held.
    fn hold_line(&self, board_reference: &str, board_hold: &mut BoardHold, session: &SessionEntry, burst: &Burst, reason: Reason) -> Result<Value, Refusal> {
        let ph = self.principal_hold(board_hold, session);
        if let Custody::Halted { path, why } = &ph.custody {
            return Err(store_halted(path, *why));
        }
        let doc = burst.doc();
        let base = ph.last_acked.get(doc).copied().unwrap_or(session.opened_at);
        let state = line_state(&reason);
        let mut said = reason.cause.clone();
        let entered = ph.queue.hold(doc, burst.frame()["id"].as_str(), base, strip_attest(burst.frame()), reason).map_err(unheld)?;
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
        // `emit_held` touches the bus alone, so it is safe under the holds' lock.
        self.emit_held(board_reference, session, doc, ph.count(doc), state, Some(&said));
        Ok(answer)
    }

    /// An ACKED session write noted (§3c.2): its `at` becomes the `base` of
    /// the next hold on every document its row names — whatever its kind,
    /// a burst's, a mint's or a link's, the shell's `op` and the resend's
    /// alike. A read, or a refusal, notes nothing.
    pub fn note_ack(&self, board_reference: &str, session: &SessionEntry, frame: &Value, ack: &Value) {
        let Some(at) = acked_at(ack) else { return };
        let docs = written_docs(frame, ack);
        if docs.is_empty() {
            return;
        }
        let mut board_hold = self.lock(board_reference);
        let ph = board_hold.principals.entry(session.facts.principal).or_insert_with(PrincipalHold::new);
        for doc in docs {
            ph.last_acked.insert(doc.to_string(), at);
        }
    }

    /// `held(session)` → the acting principal's held lines at the session's
    /// board in resend order (§4b.1), from this principal's file and no
    /// other (P39); `store_halted` where P38 halted the file.
    pub fn lines(&self, board_reference: &str, session: &SessionEntry) -> Result<Value, Refusal> {
        let mut board_hold = self.lock(board_reference);
        let ph = self.principal_hold(&mut board_hold, session);
        if let Custody::Halted { path, why } = &ph.custody {
            return Err(store_halted(path, *why));
        }
        Ok(Value::Array(ph.queue.lines().iter().map(line_json).collect()))
    }

    /// `resolve(session, {held, act})` (§3c.4, §4b.1), its refusals in this
    /// order, the first that holds answering: `store_halted` where P38
    /// halted the principal's file; `no_such_held` where no line of ordinal
    /// `k` stands; `not_resolvable` where the line awaits no act of the
    /// person's (P10), or `act` names none. `"drop"` marks the line — and,
    /// for a refused run, every line held `behind` it on that document —
    /// `done … dropped`; `"send"` re-arms the document's waiting lines
    /// `behind`, back in the automatic machine, and answers at once
    /// ([`Resolved::Rearmed`]): the probe that resends them is the caller's
    /// to hand the board's worker.
    pub fn resolve(&self, board_reference: &str, session: &SessionEntry, k: u64, act: &str) -> Result<Resolved, Refusal> {
        let doc = {
            let mut board_hold = self.lock(board_reference);
            let ph = self.principal_hold(&mut board_hold, session);
            if let Custody::Halted { path, why } = &ph.custody {
                return Err(store_halted(path, *why));
            }
            let Some(line) = ph.queue.lines().iter().find(|l| l.k == k) else { return Err(Refusal::shell(Name::NO_SUCH_HELD, json!({"held": k}))) };
            // A line awaiting the person's act alone takes one (P10).
            if !awaits_act(line) {
                return Err(Refusal::shell(Name::NOT_RESOLVABLE, json!({"held": k})));
            }
            line.doc.clone()
        };
        match act {
            "drop" => {
                self.drop_run(board_reference, session, k, &doc);
                Ok(Resolved::Dropped)
            }
            "send" => {
                // Re-enter the automatic machine (§3c.4, RULED "button then"):
                // the document's waiting lines re-armed `behind`, the read run
                // afresh at the next probe, and the refusal faced again where
                // it recurs.
                self.with_principal(board_reference, session.facts.principal, |ph| {
                    let ks: Vec<u64> = ph.queue.lines().iter().filter(|l| l.doc == doc && awaits_act(l)).map(|l| l.k).collect();
                    for k in ks {
                        self.remark_line(ph, k, Reason::of(cause::BEHIND, false));
                    }
                });
                Ok(Resolved::Rearmed)
            }
            other => Err(Refusal::shell(Name::NOT_RESOLVABLE, json!({"held": k, "act": other}))),
        }
    }

    /// `"drop"`: the line and every line after it on that document — a
    /// refused run's `behind` lines — marked `done … dropped`, the file
    /// compacting where the queue empties; the `held` event says it under
    /// the session that acted, in the state of the document's line that
    /// stands first now — a MOVED line held before the dropped one keeps the
    /// document `moved` — and `kept` only where no line stands.
    fn drop_run(&self, board_reference: &str, session: &SessionEntry, k: u64, doc: &str) {
        let Some((count, state)) = self.with_principal(board_reference, session.facts.principal, |ph| {
            let ks: Vec<u64> = ph.queue.lines().iter().filter(|l| l.doc == doc && l.k >= k).map(|l| l.k).collect();
            for d in ks {
                self.done_line(ph, d, Done::Dropped);
            }
            let head = ph.queue.lines().iter().find(|l| l.doc == doc);
            (ph.count(doc), head.map_or(HeldState::Kept, |l| line_state(&l.reason)))
        }) else {
            return;
        };
        self.emit_held(board_reference, session, doc, count, state, None);
    }

    /// THE PROBE (§3c.4), and the RESEND it lets run (§3c.5): reached on the
    /// board's feed worker every [`PROBE_CADENCE`], at its daemon-running
    /// tick and at `resolve(send)`'s hand-over, and by
    /// `set_node_state(Running)`. While a line stands at
    /// a board whose own node is not stopped, `/health` is read; where the
    /// board answers and takes writes, each standing session of a principal
    /// with lines resends them.
    pub fn probe(&self, board_reference: &str) {
        // Gathered under the lock and dialed outside it, so `op` never waits
        // on a dead board's connect timeout.
        let slot = self.slot(board_reference);
        let due = {
            let board_hold = slot.lock();
            !board_hold.node_stopped && board_hold.principals.values().any(|ph| !ph.queue.lines().is_empty())
        };
        if !due {
            return;
        }
        // One drain per board at a time, its mark cleared however it ends.
        let Some(_draining) = Draining::begin(&self.resending, board_reference) else { return };
        self.drain(board_reference, slot);
    }

    /// The probe's dial and the resend (the body of [`Holds::probe`], run
    /// once per board at a time).
    fn drain(&self, board_reference: &str, slot: &BoardSlot) {
        let board = &slot.board;
        // THE PROBE's one `/health` read (§3c.4): a board that does not answer
        // is read again at the next wake.
        let Ok(health) = board.health() else { return };
        let writes_halted = health.body["writes"]["halted"].as_bool().unwrap_or(false);
        self.note_health(board_reference, writes_halted);
        if writes_halted {
            return;
        }
        // The board answers and takes writes: the hold ends. A directory no
        // session's open could establish is tried again, and each standing
        // session of a principal with lines resends them.
        self.establish(slot);
        let principals: Vec<u64> = slot.lock().principals.iter().filter(|(_, ph)| !ph.queue.lines().is_empty()).map(|(p, _)| *p).collect();
        for principal in principals {
            let Some(session) = self.sessions.on_board(board_reference).into_iter().find(|s| s.facts.principal == principal) else { continue };
            self.resume(board_reference, board, &session);
        }
    }

    /// `writes.halted` as the feed's tick or the probe read it (§3c.4): every
    /// burst holds `halted` from the first `true` to the next `false`.
    pub fn note_health(&self, board_reference: &str, writes_halted: bool) {
        self.lock(board_reference).writes_halted = writes_halted;
    }

    /// THE RESEND for one session (§3c.5): each document with held lines read
    /// once, then its lines sent in `k` order from where the read left them.
    fn resume(&self, board_reference: &str, board: &Board, session: &SessionEntry) {
        let Some(docs) = self.with_principal(board_reference, session.facts.principal, |ph| {
            let mut docs: Vec<String> = Vec::new();
            for l in ph.queue.lines() {
                if !docs.contains(&l.doc) {
                    docs.push(l.doc.clone());
                }
            }
            docs
        }) else {
            return;
        };
        for doc in docs {
            self.resume_doc(board_reference, board, session, &doc);
        }
    }

    /// One document's resend: the read (§3c.5), then its outcome — a head
    /// awaiting the person's act read and sent never.
    fn resume_doc(&self, board_reference: &str, board: &Board, session: &SessionEntry, doc: &str) {
        let principal = session.facts.principal;
        let Some(head) = self.head_of(board_reference, principal, doc) else { return };
        if awaits_act(&head) {
            return;
        }
        match self.read_outcome(board, session, doc, &head) {
            ReadOutcome::Unread => {}
            ReadOutcome::Moved => {
                self.mark_moved(board_reference, principal, doc);
                self.emit_held(board_reference, session, doc, self.count(board_reference, principal, doc), HeldState::Moved, None);
            }
            ReadOutcome::Landed { at } => {
                self.done(board_reference, principal, head.k, Done::Kept { at });
                match self.count(board_reference, principal, doc) {
                    0 => self.emit_held(board_reference, session, doc, 0, HeldState::Kept, None),
                    rest => {
                        self.emit_held(board_reference, session, doc, rest, HeldState::Sending, None);
                        self.send_rest(board_reference, board, session, doc);
                    }
                }
            }
            ReadOutcome::SendFromHead => {
                self.emit_held(board_reference, session, doc, self.count(board_reference, principal, doc), HeldState::Sending, None);
                self.send_rest(board_reference, board, session, doc);
            }
        }
    }

    /// THE READ (§3c.5): `GET /changes?since=<base>&under=<doc>&drafts=true`
    /// under the session, at a page of two rows — the question is none, one,
    /// or more — to one of the outcomes. AT MOST ONE held burst can have
    /// landed without its ack (§7b's single writer): a `sent` head's one row
    /// is its landing where it is of the session's own hand ([`own_row`]),
    /// its `op` the head's and its site not contradicting it, or where the
    /// board LOST its testimony ([`testimony_lost`], the `poisoned` burst a
    /// restart replays) and the site confirms it; any other row is (iii).
    fn read_outcome(&self, board: &Board, session: &SessionEntry, doc: &str, head: &HeldLine) -> ReadOutcome {
        let query = ChangesQuery { since: head.base, under: Some(doc), drafts: true, limit: Some(2) };
        let page = match board.changes(Some(&session.token), &query) {
            Ok(ChangesAnswer::Page(page)) => page,
            // `base` aged below the floor: the arrangement alone decides.
            Ok(ChangesAnswer::HistoryReclaimed { .. }) => return self.reclaimed_outcome(board, session, doc, head),
            // A page of two rows too large to serve holds two rows or more.
            Ok(ChangesAnswer::TooLarge { .. }) => return ReadOutcome::Moved,
            Ok(_) | Err(_) => return ReadOutcome::Unread,
        };
        let [row] = page.changes.as_slice() else {
            return if page.changes.is_empty() { ReadOutcome::SendFromHead } else { ReadOutcome::Moved };
        };
        if !head.reason.sent || page.more {
            return ReadOutcome::Moved;
        }
        let landed = ReadOutcome::Landed { at: row["at"].as_u64() };
        if own_row(session, row) && row["op"].as_str() == head.frame["op"].as_str() {
            // A kind the site read cannot confirm trusts the op-and-hand match.
            return match self.site(board, session, doc, head) {
                Site::Equal | Site::Unconfirmable => landed,
                Site::Differs => ReadOutcome::Moved,
                Site::Unread => ReadOutcome::Unread,
            };
        }
        // A row whose TESTIMONY THE BOARD LOST — `docs`, `key` and `op` the
        // reserved null (wire.md §`/changes`): a commit the daemon never
        // recorded, re-derived from the journal at its open — which is what
        // a `poisoned` burst's landing at the restart is (§3c.2): the write
        // path records acks alone. The feed cannot say whose it is, so THE
        // ARRANGEMENT ALONE decides, as on `history_reclaimed` (§3c.5), and
        // decisively: an `insert` whose values read back equal is (ii); a
        // kind the site read cannot confirm faces the person (iii).
        if testimony_lost(row) {
            return match self.site(board, session, doc, head) {
                Site::Equal => landed,
                Site::Differs | Site::Unconfirmable => ReadOutcome::Moved,
                Site::Unread => ReadOutcome::Unread,
            };
        }
        ReadOutcome::Moved
    }

    /// A `history_reclaimed` on the read (§3c.5): the arrangement alone
    /// decides — a `sent` head's values read back equal at its site is (ii);
    /// any difference, a kind no read confirms, or a head never sent is
    /// (iii).
    fn reclaimed_outcome(&self, board: &Board, session: &SessionEntry, doc: &str, head: &HeldLine) -> ReadOutcome {
        if !head.reason.sent {
            return ReadOutcome::Moved;
        }
        match self.site(board, session, doc, head) {
            Site::Equal => ReadOutcome::Landed { at: None },
            Site::Differs | Site::Unconfirmable => ReadOutcome::Moved,
            Site::Unread => ReadOutcome::Unread,
        }
    }

    /// THE CONTENT CONFIRM (§3c.5): ONE `retrieve_v` at an `insert`'s site,
    /// as wide as the values its frame spells, the delivery read back as
    /// values and held to them.
    fn site(&self, board: &Board, session: &SessionEntry, doc: &str, head: &HeldLine) -> Site {
        if head.frame["op"].as_str() != Some("insert") {
            return Site::Unconfirmable;
        }
        let ordinal = head.frame["at"]["ordinal"].as_str().and_then(|o| o.parse::<u64>().ok());
        let (Ok(want), Some(from)) = (values_of(&head.frame["values"]), ordinal) else { return Site::Unconfirmable };
        match board.op(Some(&session.token), &frames::retrieve_v(doc, from, want.len() as u64)) {
            Ok(Answer::Document(v)) if Rejection::of(&v).is_none() => {
                if delivers(&v, &want) {
                    Site::Equal
                } else {
                    Site::Differs
                }
            }
            Ok(Answer::Document(_)) => Site::Differs,
            Ok(Answer::Closed) | Err(_) => Site::Unread,
        }
    }

    /// Send the document's lines from its head in `k` order, each a normal
    /// `op` under the session; stop at a line that awaits the person's act or
    /// is not taken.
    fn send_rest(&self, board_reference: &str, board: &Board, session: &SessionEntry, doc: &str) {
        while let Some(line) = self.head_of(board_reference, session.facts.principal, doc) {
            if awaits_act(&line) || !self.send_line(board_reference, board, session, &line) {
                break;
            }
        }
    }

    /// ONE held line sent as the `op` it is, under the session that stands —
    /// its attest composed NOW (§3c.2) — and settled by what the dial
    /// answered: an ack `done kept`; a hold-class answer or a REFUSED run
    /// re-marked and faced; a reissue-class answer counted against the line
    /// and reissued at the next wake, so its third `durability` holds it; a
    /// refusal the table holds nowhere left standing for the next wake,
    /// never `done`; the death signal left to the hand that ends the
    /// session — the session that stands resends after its read. Whether
    /// sending may go on to the document's next line.
    fn send_line(&self, board_reference: &str, board: &Board, session: &SessionEntry, line: &HeldLine) -> bool {
        let principal = session.facts.principal;
        let given = self.with_principal(board_reference, principal, |ph| ph.reissues.get(&line.k).copied()).flatten().unwrap_or_default();
        match self.dial(board, session, &line.frame, given) {
            Dialed::Acked(ack) => {
                self.note_ack(board_reference, session, &line.frame, &ack);
                self.done(board_reference, principal, line.k, Done::Kept { at: acked_at(&ack) });
                let rest = self.count(board_reference, principal, &line.doc);
                self.emit_held(board_reference, session, &line.doc, rest, if rest == 0 { HeldState::Kept } else { HeldState::Sending }, None);
                true
            }
            Dialed::Held(reason) => {
                let state = line_state(&reason);
                let said = reason.cause.clone();
                self.with_principal(board_reference, principal, |ph| self.remark_line(ph, line.k, reason));
                self.emit_held(board_reference, session, &line.doc, self.count(board_reference, principal, &line.doc), state, Some(&said));
                false
            }
            Dialed::Reissue { kind, refusal } => {
                // The rider's count (§3c.4), per line across its wakes: the
                // third `durability` holds it.
                self.with_principal(board_reference, principal, |ph| ph.reissues.entry(line.k).or_default().note(kind));
                self.say(format!("held: line {} on {} was not taken ({refusal}); it is sent again at the next wake", line.k, line.doc));
                false
            }
            Dialed::Faced(refusal) => {
                self.say(format!("held: line {} on {} was not taken ({refusal}); it is sent again at the next wake", line.k, line.doc));
                false
            }
            Dialed::Died => false,
        }
    }

    /// ONE DIAL of a burst under `session` — a copy of `frame` attested by
    /// the session's key ([`SessionEntry::attest`]) — and its answer read ONCE
    /// through [`classify`], `given` the reissues this burst has been given.
    /// A non-200 is read by its code, so `write_busy`'s 503 meets its row. A
    /// read the attest needed that did not reach the board is held like the
    /// dial's own failure, `sent: false`: the burst never left; one that met
    /// the death signal is the dial's own death signal.
    fn dial(&self, board: &Board, session: &SessionEntry, frame: &Value, given: Reissues) -> Dialed {
        let mut frame = frame.clone();
        match session.attest(board, &self.store, &mut frame) {
            Ok(()) => {}
            Err(Unattested::Closed) => return Dialed::Died,
            Err(Unattested::Refused(Refusal::Unreachable(e))) => {
                return match classify(DialOutcome::Dial(&e), given) {
                    Decision::Hold { cause, .. } => Dialed::Held(Reason::of(cause, false)),
                    _ => Dialed::Faced(Refusal::Unreachable(e)),
                };
            }
            Err(Unattested::Refused(refusal)) => return Dialed::Faced(refusal),
        }
        match board.op(Some(&session.token), &frame) {
            Ok(Answer::Closed) => Dialed::Died,
            Ok(Answer::Document(v)) => match Rejection::of(&v) {
                None => Dialed::Acked(v),
                Some(r) => {
                    let decision = classify(DialOutcome::Rejected { code: r.key(), disposition: v["disposition"].as_str().unwrap_or("") }, given);
                    Dialed::refused(decision, &r.token(), &v, Refusal::from(r.refused(&v)))
                }
            },
            Err(Halt::Dial(e)) => match classify(DialOutcome::Dial(&e), given) {
                Decision::Hold { cause, sent } => Dialed::Held(Reason::of(cause, sent)),
                _ => Dialed::Faced(Refusal::Unreachable(e)),
            },
            Err(Halt::Refused(r)) => {
                let decision = classify(DialOutcome::Rejected { code: &r.code, disposition: r.body["disposition"].as_str().unwrap_or("") }, given);
                let (token, verdict) = (r.token(), r.body.clone());
                Dialed::refused(decision, &token, &verdict, Refusal::Board(r))
            }
            Err(h) => Dialed::Faced(Refusal::from(h)),
        }
    }

    /// Mark every line of a MOVED document (J3): `cause: moved`, no line sent,
    /// NEVER rebased. The exact rebase by identity — the burst's anchor re-found
    /// and the delta placed after it — stays named as OPEN (§3c.5, the record §5
    /// Q3): it needs an anchor the page's frame does not carry today, and a
    /// silent inexact rebase could put words where the person did not. The
    /// page's half — what the burst machine does at a `held` answer, how it
    /// re-projects the held frames at a launch, the moved document's face — is
    /// the frontend lane's and in neither repository at this pin (UNVERIFIED
    /// HERE, the record §7 item 4; stated from assisted-frontend §7b).
    fn mark_moved(&self, board_reference: &str, principal: u64, doc: &str) {
        self.with_principal(board_reference, principal, |ph| {
            let ks: Vec<u64> = ph.queue.lines().iter().filter(|l| l.doc == doc).map(|l| l.k).collect();
            for k in ks {
                self.remark_line(ph, k, Reason::of(cause::MOVED, false));
            }
        });
    }

    /// Re-mark one line in place — a hold that recurs, a refused run, a moved
    /// re-facing — its ordinal kept; a copy the device refused said on TALK.
    fn remark_line(&self, ph: &mut PrincipalHold, k: u64, reason: Reason) {
        if let Err(e) = ph.queue.remark(k, reason) {
            self.say(format!("held: line {k}'s new cause could not be written ({e}); a reopen reads its earlier one"));
        }
    }

    /// Resolve one line `done` — [`Done::Kept`] or [`Done::Dropped`] — the
    /// file compacting where the queue empties.
    fn done(&self, board_reference: &str, principal: u64, k: u64, done: Done) {
        self.with_principal(board_reference, principal, |ph| self.done_line(ph, k, done));
    }

    /// One line out of the queue, whatever the disk did; a `done` the device
    /// refused said on TALK.
    fn done_line(&self, ph: &mut PrincipalHold, k: u64, done: Done) {
        if let Err(DoneError::Unwritten(e)) = ph.queue.done(k, done) {
            self.say(format!("held: line {k} is settled, and its `done` could not be written ({e}); a reopen reads it as held, and its read decides it"));
        }
        ph.reissues.remove(&k);
    }

    /// The document's head: its first standing line in `k` order.
    fn head_of(&self, board_reference: &str, principal: u64, doc: &str) -> Option<HeldLine> {
        self.with_principal(board_reference, principal, |ph| ph.queue.lines().iter().find(|l| l.doc == doc).cloned()).flatten()
    }

    /// How many lines stand on the document.
    fn count(&self, board_reference: &str, principal: u64, doc: &str) -> u64 {
        self.with_principal(board_reference, principal, |ph| ph.count(doc)).unwrap_or(0)
    }

    /// Emit the `held` event (§4b.2): `{board, session, doc, held, state,
    /// cause?}`, under the session the change was made for.
    fn emit_held(&self, board_reference: &str, session: &SessionEntry, doc: &str, held: u64, state: HeldState, cause: Option<&str>) {
        let mut data = json!({"board": board_reference, "session": session.reference, "doc": doc, "held": held, "state": state.as_str()});
        if let Some(c) = cause {
            data["cause"] = Value::from(c);
        }
        self.bus.emit(EventName::Held, data);
    }
}

/// Whether `delivery` delivers `want`, value for value and no more — read
/// lazily, so a board answering more than it was asked costs the comparison
/// the values asked for and one past them, never a value per position it
/// chose to deliver.
fn delivers(delivery: &Value, want: &[Cow<'_, [u8]>]) -> bool {
    let mut got = delivered_values(delivery);
    want.iter().all(|w| matches!(got.next(), Some(Ok(g)) if g == *w)) && got.next().is_none()
}

/// The refusal for a line the queue would not hold (`held::Unheld`): the
/// principal's queue full, or — never for a burst [`Burst::admit`] let in —
/// a line no reader of the file reads.
fn unheld(unheld: Unheld) -> Refusal {
    match unheld {
        Unheld::Full { held_bytes, frame_bytes } => Refusal::shell(Name::HELD_FULL, json!({"held_bytes": held_bytes, "frame_bytes": frame_bytes, "cap": MAX_HELD_FRAME_BYTES})),
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

/// The session's own hand on the feed (§3c.5), as an UNSIGNED entry's `key`
/// names it: its key's fingerprint, or `bare`.
fn own_hand(session: &SessionEntry) -> String {
    match &session.facts.kind {
        Kind::Signed { fingerprint, .. } => fingerprint.to_hex(),
        Kind::Bare => "bare".to_string(),
    }
}

/// Whether a `/changes` row is of the session's OWN hand (§3c.5). An
/// unsigned entry carries `key` — [`own_hand`]'s value. A SIGNED entry
/// carries NO `key` (wire.md §`/changes`: `key` is present iff the entry is
/// unsigned) and `attest` in its place, and is the session's own where the
/// session holds a key — §3c.5's "its `key` the session's fingerprint" reads
/// the unsigned form alone. The shell attests every `insert` ("Attach when in
/// doubt"), but the daemon keeps an attest on a publish-class write alone and
/// DROPS it on a draft's (wire.md §The two attestation codes), so a burst's
/// row is the unsigned form today, its `key` the signing key's fingerprint;
/// the signed form stands for a row the wire's rule admits. The read's other
/// two guards (`op` equal, the content confirmed) stand beside this one, so
/// another key's signed row still reads as (iii).
fn own_row(session: &SessionEntry, row: &Value) -> bool {
    if row["key"].as_str() == Some(own_hand(session).as_str()) {
        return true;
    }
    matches!(session.facts.kind, Kind::Signed { .. }) && row.get("key").is_none() && row.get("attest").is_some()
}

/// Whether a `/changes` row's testimony is LOST — `docs`, `key` and `op` the
/// reserved null (wire.md §`/changes`: "`null` ONLY for lost metadata"): a
/// commit the daemon never recorded, re-derived from the journal at its open
/// and classified to its documents, whose hand and kind the feed cannot name.
/// A signed row has no `key` but names its `op`; a bare session's row says
/// `bare`; neither is this.
fn testimony_lost(row: &Value) -> bool {
    row["docs"].is_null() && row["key"].is_null() && row["op"].is_null()
}

/// A frame with any `attest` stripped — the stored form carries none (§3c.2).
fn strip_attest(frame: &Value) -> Value {
    let mut frame = frame.clone();
    if let Some(obj) = frame.as_object_mut() {
        obj.remove("attest");
    }
    frame
}

#[cfg(test)]
mod tests;
