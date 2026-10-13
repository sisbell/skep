//! THE HOLD (`client.md` §3c.4, §3c.5): a burst's write path, the
//! per-(board, principal) queue the shell consults on every burst, and the
//! resend walk that drains the queue once the board returns.
//!
//! A BURST is an `op` under a session (never the guest form) whose
//! `frame["op"]` is one of [`BURST_KINDS`] — the burst machine's five — on a
//! draft. Its WRITE PATH is this module's, at the first dial and at every
//! resend alike: [`Holds::send_burst`] holds it WITHOUT a dial where a hold
//! stands — the own node stopped, the board halted, a line of the
//! principal's already held — and else attests it, dials it ONCE and reads
//! the answer once, through THE CLASSIFICATION TABLE ([`classify`]: §3c.4's
//! HOLD(cause) / REISSUE / NEITHER): an ack carried and its `at` noted, a
//! hold-class answer or a REFUSED run held, anything else faced at the act.
//! The resend sends each held line through the same reader.
//!
//! THE QUEUE is each principal's [`HeldFile`], in `k` order across the
//! board's documents: copied to `held/<chain>/principal-<n>.held` where this
//! shell holds the board's directory (§3c.1), kept in memory alone where
//! another window holds it or the directory is out of reach (§3c.3), and
//! opened only under a session as its principal (P39) — at the session's
//! open, or at the first touch after it. THE PROBE runs on the feed worker's
//! thread every [`PROBE_CADENCE`] while a line stands, because `Cmd::Tick` is
//! driven by COMMITTED writes and a poisoned, halted, stopped or unreachable
//! board commits nothing. THE RESEND ([`Holds::service`]) is AUTOMATIC at the
//! hold's end and at reopen (J2): one READ per document (`GET /changes`)
//! before its first resend, with §3c.5's three outcomes — (i) nothing
//! landed, send from the head; (ii) the in-flight burst landed, the head
//! `done kept`; (iii) the site MOVED, no line sent and the lines faced
//! `moved`, NEVER rebased (J3) — and a read the board did not answer decides
//! nothing: the next wake reads again.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use serde_json::{json, Value};
use skep_client::board::{acked_at, frames, Answer, Board, ChangesAnswer, ChangesQuery, Rejection};
use skep_client::halt::Halt;
use skep_client::store::FileStore;
use skep_client::DialError;
use skep_identity::BoardTerm;
use skep_search::Chain;

use crate::attest::{delivered_values, values_of};
use crate::events::{EventBus, HELD};
use crate::held::{DoneError, HaltWhy, HeldDir, HeldFile, HeldLine, Opened, Reason};
use crate::refusal::{Name, Refusal};
use crate::sessions::{SessionEntry, Sessions};
use crate::Talk;

/// THE INTERIM PROBE CADENCE (§3c.4): `GET /health` at this interval while a
/// burst is held at a board — the lane's to tune.
pub const PROBE_CADENCE: Duration = Duration::from_secs(2);

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
pub enum Outcome<'a> {
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
    /// REISSUE — `write_busy`, or a first or second `durability` (silent).
    Reissue,
    /// NEITHER held nor reissued — faced at its act.
    Neither,
}

/// THE CLASSIFICATION TABLE (§3c.4): a burst's outcome, and how many prior
/// `durability` refusals the SAME burst has met, to exactly one row.
pub fn classify(outcome: Outcome<'_>, durability_seen: u32) -> Decision {
    match outcome {
        Outcome::Dial(e) => match e {
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
        Outcome::Rejected { code, disposition } => match code {
            // `poisoned` MAY have landed (§3c.2): the board's write path failed
            // AFTER the burst's frames reached its journal, and a restart's open
            // "rebuilds the line from the journal" (wire.md §Rejection codes) —
            // the burst lands at the restart, so the resend READS before it
            // sends, as after a lost answer. A `halted` hold (the feed's
            // `writes.halted` read, before any dial) stays `sent: false`.
            "poisoned" => Decision::Hold { cause: cause::POISONED, sent: true },
            "write_busy" => Decision::Reissue,
            // The rider (§3c.4): a THIRD `durability` on the same burst HOLDS it.
            "durability" => {
                if durability_seen >= 2 {
                    Decision::Hold { cause: cause::DURABILITY, sent: false }
                } else {
                    Decision::Reissue
                }
            }
            _ => match disposition {
                "permanent" | "reorder" => Decision::Refused,
                _ => Decision::Neither,
            },
        },
    }
}

/// What a burst's `op` answers the page (§3c.4).
pub enum Sent {
    /// The board's ack, the shell's `held`, or the refusal faced at the act.
    Answered(Result<Value, Refusal>),
    /// The death signal on the session's token: the caller ends the session,
    /// and the burst is not held (§3c.4: the death signal is neither).
    Died,
}

/// What ONE dial of a burst answered, read once through the table.
enum Dialed {
    /// The board's ack.
    Acked(Value),
    /// A hold-class answer, or a REFUSED run: the line's reason.
    Held(Reason),
    /// Faced at the act: a reissue-class answer, one the table holds nowhere,
    /// or the shell's own refusal where the attest could not be composed.
    Faced(Refusal),
    /// The death signal on the session's token.
    Died,
}

impl Dialed {
    /// A refusal read through the table: held for its cause, held as a
    /// REFUSED run with the board's `token` and verdict, or faced.
    fn refused(decision: Decision, token: &str, verdict: &Value, faced: Refusal) -> Dialed {
        match decision {
            Decision::Hold { cause, sent } => Dialed::Held(Reason::of(cause, sent)),
            Decision::Refused => Dialed::Held(Reason::refused(token, verdict.clone())),
            Decision::Reissue | Decision::Neither => Dialed::Faced(faced),
        }
    }
}

/// A document's held state, as the `held` event names it (§4b.2).
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

/// Whether a line waits for the person's act — a REFUSED run's, or a MOVED
/// document's (§3c.4, §3c.5): no wake sends it, and `resolve` alone moves it.
fn awaits_act(line: &HeldLine) -> bool {
    line.reason.cause == cause::MOVED || line.reason.refusal.is_some()
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
    Held { dir: HeldDir, _lock: File },
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
    fn of(store_dir: &Path, term: Result<Option<BoardTerm>, Halt>) -> Directory {
        let term = match term {
            Ok(Some(term)) => term,
            Ok(None) => return Directory::Unknown("the board has no H.1 yet, and an unclaimed board keeps no held text".to_string()),
            Err(h) => return Directory::Unknown(format!("the board's H.1 could not be read: {h}")),
        };
        let dir = HeldDir::new(store_dir, Chain::from_bytes(term.chain));
        match dir.ensure().and_then(|()| dir.try_lock()) {
            Ok(Some(lock)) => Directory::Held { dir, _lock: lock },
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
/// that document takes (§3c.2) — and the `durability` refusals each line's
/// resend has met.
struct PrincipalHold {
    custody: Custody,
    file: HeldFile,
    last_acked: HashMap<String, u64>,
    durability: HashMap<u64, u32>,
}

impl PrincipalHold {
    fn new() -> PrincipalHold {
        PrincipalHold { custody: Custody::Unopened, file: HeldFile::in_memory(), last_acked: HashMap::new(), durability: HashMap::new() }
    }

    /// How many lines stand on `doc`.
    fn count(&self, doc: &str) -> u64 {
        self.file.lines().iter().filter(|l| l.doc == doc).count() as u64
    }
}

/// One board's hold: the board dialed, its directory, the two states that
/// hold every burst before any dial, and each principal's queue.
struct BoardHold {
    board: Arc<Board>,
    directory: Directory,
    /// Whether the last read of `/health.writes.halted` — the feed's tick, or
    /// the probe — answered true: every burst holds `halted` without a dial
    /// until a read answers false, which only a restart makes it (§3c.4;
    /// wire.md §The other endpoints).
    halted: bool,
    /// Whether the own node is STOPPED by the person's act: every burst holds
    /// `stopped` without a dial, and the probe dials nothing until
    /// `set_node_state(Running)` clears it (§3c.4).
    node_stopped: bool,
    principals: HashMap<u64, PrincipalHold>,
}

/// THE HOLDS: every board's hold, shared by the shell (the `op` row's burst,
/// `held` and `resolve`, a session's open, `set_node_state`) and the feed
/// workers (the probe, the `writes.halted` read, the daemon-running end).
pub struct Holds {
    sessions: Arc<Sessions>,
    bus: Arc<EventBus>,
    store: Arc<FileStore>,
    store_dir: PathBuf,
    talk: Talk,
    boards: Mutex<HashMap<String, BoardHold>>,
    /// The boards a resend is draining now. [`Holds::service`] is reached by
    /// the feed's probe and its daemon-running tick, `set_node_state(Running)`
    /// and `resolve(send)`; one drain per board at a time, so none
    /// double-sends.
    resending: Mutex<HashSet<String>>,
}

impl Holds {
    /// The holds for a shell: no board yet.
    pub fn new(sessions: Arc<Sessions>, bus: Arc<EventBus>, store: Arc<FileStore>, store_dir: PathBuf, talk: Talk) -> Arc<Holds> {
        Arc::new(Holds { sessions, bus, store, store_dir, talk, boards: Mutex::new(HashMap::new()), resending: Mutex::new(HashSet::new()) })
    }

    fn say(&self, line: impl AsRef<str>) {
        (self.talk)(line.as_ref());
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, BoardHold>> {
        self.boards.lock().expect("the holds' lock")
    }

    /// The board `reference` names, to dial outside the lock.
    fn board(&self, reference: &str) -> Option<Arc<Board>> {
        self.lock().get(reference).map(|b| Arc::clone(&b.board))
    }

    /// One board registered at open: nothing is dialed and nothing on disk
    /// touched until a session opens at it.
    pub fn register_board(&self, reference: &str, board: Arc<Board>) {
        self.lock().entry(reference.to_string()).or_insert_with(|| BoardHold {
            board,
            directory: Directory::Unknown("no session has opened at this board yet".to_string()),
            halted: false,
            node_stopped: false,
            principals: HashMap::new(),
        });
    }

    /// The own node's STOPPED state as its owner reports it (§3c.4): every
    /// burst holds `stopped`, and the probe waits for `Running` to resend.
    pub fn set_node_stopped(&self, reference: &str, stopped: bool) {
        if let Some(board) = self.lock().get_mut(reference) {
            board.node_stopped = stopped;
        }
    }

    /// Whether the board's node stands STOPPED by its owner's act
    /// ([`Holds::set_node_stopped`]) — what `probe` answers for the own node,
    /// and what the feed reads when the board's stream fails, so a deliberate
    /// stop is announced `stopped` once and never `unreachable` beside it. A
    /// board that is not the own node, or one the holds never registered,
    /// answers false.
    pub fn node_stopped(&self, reference: &str) -> bool {
        self.lock().get(reference).is_some_and(|b| b.node_stopped)
    }

    /// A SESSION OPENED at the board (§3c.7 items 1 and 4): the board's
    /// directory established where it is not yet, and the session's
    /// principal's file read whole under its account — P38's faces kept, a
    /// misplaced file set aside and said in the shell's own window — so
    /// `held(session)` lists its lines at once and the probe's next wake
    /// resends them. No other principal's file is opened (P39).
    pub fn open_session(&self, reference: &str, session: &SessionEntry) {
        let Some(board) = self.board(reference) else { return };
        self.establish(reference, &board);
        if let Some(b) = self.lock().get_mut(reference) {
            self.principal(b, session);
        }
    }

    /// The board's directory established where it is not yet: `H.1` read
    /// OUTSIDE the lock (the board keeps the term once found), the directory
    /// then made and locked under it. A hold never comes here: it never
    /// dials to learn where to write.
    fn establish(&self, reference: &str, board: &Board) {
        let unknown = self.lock().get(reference).is_some_and(|b| matches!(b.directory, Directory::Unknown(_)));
        if !unknown {
            return;
        }
        let term = board.board_term();
        if let Some(b) = self.lock().get_mut(reference) {
            if matches!(b.directory, Directory::Unknown(_)) {
                b.directory = Directory::of(&self.store_dir, term);
            }
        }
    }

    /// THE PRINCIPAL's HOLD at `board` — the one door every entry that names
    /// a principal takes: a session's open, a burst, a hold, `held` and
    /// `resolve`. A principal whose custody is not settled, and whose queue
    /// holds no line, is opened here under `session`'s account: its file where
    /// the board's directory is this shell's, memory alone otherwise. Under
    /// the session that stands, so the restart arm's re-open is covered too.
    fn principal<'b>(&self, board: &'b mut BoardHold, session: &SessionEntry) -> &'b mut PrincipalHold {
        let BoardHold { directory, principals, .. } = board;
        let n = session.facts.principal;
        let ph = principals.entry(n).or_insert_with(PrincipalHold::new);
        if ph.custody.settled() || !ph.file.lines().is_empty() {
            return ph;
        }
        match directory {
            Directory::Held { dir, .. } => match dir.open_file(n, session.facts.account.as_deref().unwrap_or("")) {
                Ok(Opened::Live { file, aside }) => {
                    if let Some(aside) = aside {
                        self.say(format!("held: principal {n}'s held file named another board or principal, and is set aside at {}", aside.display()));
                    }
                    ph.file = file;
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

    /// THE BURST's WRITE PATH (§3c.4), the `op` row's for a burst: HELD
    /// WITHOUT A DIAL where a hold stands at the board — the own node stopped,
    /// the board halted, a line of the principal's already held — and refused
    /// `store_halted` where P38 halted the principal's file; else attested,
    /// dialed ONCE and its answer read through the table: an ack carried and
    /// its `at` noted, a hold-class answer or a REFUSED run held and answered
    /// `held`, anything else faced at the act.
    pub fn send_burst(&self, reference: &str, session: &SessionEntry, frame: Value) -> Sent {
        let board = {
            let mut boards = self.lock();
            let at = boards.get_mut(reference).expect("a session stands at a board the holds registered");
            let (stopped, halted, board) = (at.node_stopped, at.halted, Arc::clone(&at.board));
            let ph = self.principal(at, session);
            if let Custody::Halted { path, why } = &ph.custody {
                return Sent::Answered(Err(store_halted(path, *why)));
            }
            let standing = !ph.file.lines().is_empty();
            let stands = if stopped {
                Some(cause::STOPPED)
            } else if halted {
                Some(cause::HALTED)
            } else if standing {
                Some(cause::BEHIND)
            } else {
                None
            };
            if let Some(why) = stands {
                return Sent::Answered(self.hold_line(reference, at, session, &frame, Reason::of(why, false)));
            }
            board
        };
        match self.dial(&board, session, &frame, 0) {
            Dialed::Acked(ack) => {
                self.note_ack(reference, session, &frame, &ack);
                Sent::Answered(Ok(ack))
            }
            Dialed::Held(reason) => Sent::Answered(self.hold(reference, session, &frame, reason)),
            Dialed::Faced(refusal) => Sent::Answered(Err(refusal)),
            Dialed::Died => Sent::Died,
        }
    }

    /// HOLD a burst for `reason`, as a dial's answer held it: the `held`
    /// answer ([`Holds::hold_line`]), or `store_halted` where P38 halted the
    /// file.
    pub fn hold(&self, reference: &str, session: &SessionEntry, frame: &Value, reason: Reason) -> Result<Value, Refusal> {
        let mut boards = self.lock();
        let board = boards.get_mut(reference).expect("a session stands at a board the holds registered");
        self.hold_line(reference, board, session, frame, reason)
    }

    /// One line entered in the principal's queue — copied to its file where
    /// it has one, its `base` the `at` of the last acked write on the document
    /// or else the session's open position (§3c.2) — the `held` event fired,
    /// and the answer: `{resp: held, held: <k>, cause}`, the cause
    /// `other_window` where another window's lock keeps the line in memory
    /// alone, and `unwritable` beside it — why — where the device refused its
    /// copy or the file is out of reach (§3c.3).
    fn hold_line(&self, reference: &str, board: &mut BoardHold, session: &SessionEntry, frame: &Value, reason: Reason) -> Result<Value, Refusal> {
        let ph = self.principal(board, session);
        if let Custody::Halted { path, why } = &ph.custody {
            return Err(store_halted(path, *why));
        }
        let doc = frame["doc"].as_str().unwrap_or_default();
        let base = ph.last_acked.get(doc).copied().unwrap_or(session.opened_at);
        let state = if reason.refusal.is_some() { HeldState::Refused } else { HeldState::Holding };
        let mut said = reason.cause.clone();
        let appended = ph.file.hold(doc, frame["id"].as_str(), base, strip_attest(frame), reason);
        let unwritable = match &ph.custody {
            Custody::OtherWindow => {
                said = cause::OTHER_WINDOW.to_string();
                self.say(format!("held: another window holds this board's held text; {doc}'s burst is kept in memory alone"));
                None
            }
            Custody::Unwritable(why) => Some(why.clone()),
            _ => appended.unwritten.map(|e| e.to_string()),
        };
        let mut answer = json!({"resp": "held", "held": appended.k, "cause": said});
        if let Some(why) = unwritable {
            answer["unwritable"] = Value::from(why);
        }
        // `fire` touches the bus alone, so it is safe under the holds' lock.
        self.fire(reference, session, doc, ph.count(doc), state, Some(&said));
        Ok(answer)
    }

    /// An ACKED session write noted (§3c.2): its `at` becomes the `base` of
    /// the next hold on every document its row names — whatever its kind,
    /// a burst's, a mint's or a link's, the shell's `op` and the resend's
    /// alike. A read, or a refusal, notes nothing.
    pub fn note_ack(&self, reference: &str, session: &SessionEntry, frame: &Value, ack: &Value) {
        let Some(at) = acked_at(ack) else { return };
        let docs = written_docs(frame, ack);
        if docs.is_empty() {
            return;
        }
        if let Some(board) = self.lock().get_mut(reference) {
            let ph = board.principals.entry(session.facts.principal).or_insert_with(PrincipalHold::new);
            for doc in docs {
                ph.last_acked.insert(doc.to_string(), at);
            }
        }
    }

    /// `held(session)` → the acting principal's held lines at the session's
    /// board in resend order (§4b.1), from this principal's file and no
    /// other (P39); `store_halted` where P38 halted the file.
    pub fn rows(&self, reference: &str, session: &SessionEntry) -> Result<Value, Refusal> {
        let mut boards = self.lock();
        let Some(board) = boards.get_mut(reference) else { return Ok(Value::Array(Vec::new())) };
        let ph = self.principal(board, session);
        if let Custody::Halted { path, why } = &ph.custody {
            return Err(store_halted(path, *why));
        }
        Ok(Value::Array(ph.file.lines().iter().map(row_json).collect()))
    }

    /// `resolve(session, {held, act})` (§3c.4): `"drop"` on a line that awaits
    /// the person's act marks it — and, for a refused run, every line held
    /// `behind` it on that document — `done … dropped`; `"send"` re-enters the
    /// automatic machine for that document. `no_such_held` / `not_resolvable`
    /// else.
    pub fn resolve(&self, reference: &str, session: &SessionEntry, k: u64, act: &str) -> Result<Value, Refusal> {
        let doc = {
            let mut boards = self.lock();
            let Some(board) = boards.get_mut(reference) else { return Err(Refusal::shell(Name::NO_SUCH_HELD, json!({"held": k}))) };
            let ph = self.principal(board, session);
            let Some(line) = ph.file.lines().iter().find(|l| l.k == k) else { return Err(Refusal::shell(Name::NO_SUCH_HELD, json!({"held": k}))) };
            // A line awaiting the person's act alone takes one (P10).
            if !awaits_act(line) {
                return Err(Refusal::shell(Name::NOT_RESOLVABLE, json!({"held": k})));
            }
            line.doc.clone()
        };
        match act {
            "drop" => {
                self.drop_run(reference, session, k, &doc);
                Ok(json!({}))
            }
            "send" => {
                // Re-enter the automatic machine (§3c.4, RULED "button then"):
                // the document's waiting lines re-armed `behind`, the read run
                // afresh, and the refusal faced again where it recurs.
                {
                    let mut boards = self.lock();
                    if let Some(ph) = principal_mut(&mut boards, reference, session.facts.principal) {
                        let ks: Vec<u64> = ph.file.lines().iter().filter(|l| l.doc == doc && awaits_act(l)).map(|l| l.k).collect();
                        for k in ks {
                            self.remark_line(ph, k, Reason::of(cause::BEHIND, false));
                        }
                    }
                }
                self.service(reference);
                Ok(json!({}))
            }
            other => Err(Refusal::shell(Name::NOT_RESOLVABLE, json!({"held": k, "act": other}))),
        }
    }

    /// `"drop"`: the line and every line after it on that document — a
    /// refused run's `behind` lines — marked `done … dropped`, the file
    /// compacting where the queue empties; the `held` event says it under
    /// the session that acted.
    fn drop_run(&self, reference: &str, session: &SessionEntry, k: u64, doc: &str) {
        let count = {
            let mut boards = self.lock();
            let Some(ph) = principal_mut(&mut boards, reference, session.facts.principal) else { return };
            let ks: Vec<u64> = ph.file.lines().iter().filter(|l| l.doc == doc && l.k >= k).map(|l| l.k).collect();
            for d in ks {
                self.done_line(ph, d, false, None);
            }
            ph.count(doc)
        };
        self.fire(reference, session, doc, count, HeldState::Kept, None);
    }

    /// THE PROBE and THE RESEND (§3c.4's end, §3c.5): reached by the feed's
    /// probe every [`PROBE_CADENCE`] and its daemon-running tick,
    /// `set_node_state(Running)` and `resolve(send)`. While a line stands at
    /// a board whose own node is not stopped, `/health` is read; where the
    /// board answers and takes writes, each standing session of a principal
    /// with lines resends them.
    pub fn service(&self, reference: &str) {
        // Gathered under the lock and dialed outside it, so `op` never waits
        // on a dead board's connect timeout.
        let due = self.lock().get(reference).is_some_and(|b| !b.node_stopped && b.principals.values().any(|ph| !ph.file.lines().is_empty()));
        if !due {
            return;
        }
        // One drain per board at a time.
        if !self.resending.lock().expect("the resend lock").insert(reference.to_string()) {
            return;
        }
        self.drain(reference);
        self.resending.lock().expect("the resend lock").remove(reference);
    }

    /// The probe's dial and the resend (the body of [`Holds::service`], run
    /// once per board at a time).
    fn drain(&self, reference: &str) {
        let Some(board) = self.board(reference) else { return };
        // THE PROBE's one `/health` read (§3c.4): a board that does not answer
        // is read again at the next wake.
        let Ok(health) = board.health() else { return };
        let halted = health.body["writes"]["halted"].as_bool().unwrap_or(false);
        self.note_health(reference, halted);
        if halted {
            return;
        }
        // The board answers and takes writes: the hold ends. A directory no
        // session's open could establish is tried again, and each standing
        // session of a principal with lines resends them.
        self.establish(reference, &board);
        let principals: Vec<u64> = self.lock().get(reference).map(|b| b.principals.iter().filter(|(_, ph)| !ph.file.lines().is_empty()).map(|(p, _)| *p).collect()).unwrap_or_default();
        for principal in principals {
            let Some(session) = self.sessions.on_board(reference).into_iter().find(|s| s.facts.principal == principal) else { continue };
            self.resume(reference, &board, &session);
        }
    }

    /// `writes.halted` as the feed's tick or the probe read it (§3c.4): every
    /// burst holds `halted` from the first `true` to the next `false`.
    pub fn note_health(&self, reference: &str, writes_halted: bool) {
        if let Some(board) = self.lock().get_mut(reference) {
            board.halted = writes_halted;
        }
    }

    /// THE RESEND for one session (§3c.5): each document with held lines read
    /// once, then its lines sent in `k` order from where the read left them.
    fn resume(&self, reference: &str, board: &Board, session: &SessionEntry) {
        let docs: Vec<String> = {
            let mut boards = self.lock();
            let Some(ph) = principal_mut(&mut boards, reference, session.facts.principal) else { return };
            let mut docs: Vec<String> = Vec::new();
            for l in ph.file.lines() {
                if !docs.contains(&l.doc) {
                    docs.push(l.doc.clone());
                }
            }
            docs
        };
        for doc in docs {
            self.resume_doc(reference, board, session, &doc);
        }
    }

    /// One document's resend: the read (§3c.5), then its outcome — a head
    /// awaiting the person's act read and sent never.
    fn resume_doc(&self, reference: &str, board: &Board, session: &SessionEntry, doc: &str) {
        let principal = session.facts.principal;
        let Some(head) = self.head_of(reference, principal, doc) else { return };
        if awaits_act(&head) {
            return;
        }
        match self.read_outcome(board, session, doc, &head) {
            ReadOutcome::Unread => {}
            ReadOutcome::Moved => {
                self.mark_moved(reference, principal, doc);
                self.fire(reference, session, doc, self.count(reference, principal, doc), HeldState::Moved, None);
            }
            ReadOutcome::Landed { at } => {
                self.done(reference, principal, head.k, true, at);
                match self.count(reference, principal, doc) {
                    0 => self.fire(reference, session, doc, 0, HeldState::Kept, None),
                    rest => {
                        self.fire(reference, session, doc, rest, HeldState::Sending, None);
                        self.send_rest(reference, board, session, doc);
                    }
                }
            }
            ReadOutcome::SendFromHead => {
                self.fire(reference, session, doc, self.count(reference, principal, doc), HeldState::Sending, None);
                self.send_rest(reference, board, session, doc);
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
        let at = head.frame["at"]["ordinal"].as_str().and_then(|o| o.parse::<u64>().ok());
        let (Ok(want), Some(from)) = (values_of(&head.frame["values"]), at) else { return Site::Unconfirmable };
        match board.op(Some(&session.token), &frames::retrieve_v(doc, from, want.len() as u64)) {
            Ok(Answer::Document(v)) if Rejection::of(&v).is_none() => {
                if delivered_values(&v).is_ok_and(|got| got == want) {
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
    fn send_rest(&self, reference: &str, board: &Board, session: &SessionEntry, doc: &str) {
        while let Some(line) = self.head_of(reference, session.facts.principal, doc) {
            if awaits_act(&line) || !self.send_line(reference, board, session, &line) {
                break;
            }
        }
    }

    /// ONE held line sent as the `op` it is, under the session that stands —
    /// its attest composed NOW (§3c.2) — and settled by what the dial
    /// answered: an ack `done kept`; a hold-class answer or a REFUSED run
    /// re-marked and faced; a refusal the table holds nowhere left standing
    /// for the next wake, never `done`; the death signal left to the hand
    /// that ends the session — the session that stands resends after its
    /// read. Whether sending may go on to the document's next line.
    fn send_line(&self, reference: &str, board: &Board, session: &SessionEntry, line: &HeldLine) -> bool {
        let principal = session.facts.principal;
        let seen = self.lock().get(reference).and_then(|b| b.principals.get(&principal)).and_then(|ph| ph.durability.get(&line.k).copied()).unwrap_or(0);
        match self.dial(board, session, &line.frame, seen) {
            Dialed::Acked(ack) => {
                self.note_ack(reference, session, &line.frame, &ack);
                self.done(reference, principal, line.k, true, acked_at(&ack));
                let rest = self.count(reference, principal, &line.doc);
                self.fire(reference, session, &line.doc, rest, if rest == 0 { HeldState::Kept } else { HeldState::Sending }, None);
                true
            }
            Dialed::Held(reason) => {
                let state = if reason.refusal.is_some() { HeldState::Refused } else { HeldState::Holding };
                let said = reason.cause.clone();
                if let Some(ph) = principal_mut(&mut self.lock(), reference, principal) {
                    self.remark_line(ph, line.k, reason);
                }
                self.fire(reference, session, &line.doc, self.count(reference, principal, &line.doc), state, Some(&said));
                false
            }
            Dialed::Faced(refusal) => {
                // The rider's count (§3c.4): the third `durability` holds.
                if matches!(&refusal, Refusal::Board(r) if r.code == "durability") {
                    if let Some(ph) = principal_mut(&mut self.lock(), reference, principal) {
                        *ph.durability.entry(line.k).or_insert(0) += 1;
                    }
                }
                self.say(format!("held: line {} on {} was not taken ({refusal}); it is sent again at the next wake", line.k, line.doc));
                false
            }
            Dialed::Died => false,
        }
    }

    /// ONE DIAL of a burst under `session` — a copy of `frame` attested by
    /// the session's key ([`SessionEntry::attest`]) — and its answer read ONCE
    /// through [`classify`], `durability_seen` the rider's count for this
    /// burst. A non-200 is read by its code, so `write_busy`'s 503 meets its
    /// row. A read the attest needed that did not reach the board is held
    /// like the dial's own failure, `sent: false`: the burst never left.
    fn dial(&self, board: &Board, session: &SessionEntry, frame: &Value, durability_seen: u32) -> Dialed {
        let mut frame = frame.clone();
        match session.attest(board, &self.store, &mut frame) {
            Ok(()) => {}
            Err(Refusal::Unreachable(e)) => {
                return match classify(Outcome::Dial(&e), 0) {
                    Decision::Hold { cause, .. } => Dialed::Held(Reason::of(cause, false)),
                    _ => Dialed::Faced(Refusal::Unreachable(e)),
                };
            }
            Err(refusal) => return Dialed::Faced(refusal),
        }
        match board.op(Some(&session.token), &frame) {
            Ok(Answer::Closed) => Dialed::Died,
            Ok(Answer::Document(v)) => match Rejection::of(&v) {
                None => Dialed::Acked(v),
                Some(r) => {
                    let decision = classify(Outcome::Rejected { code: r.key(), disposition: v["disposition"].as_str().unwrap_or("") }, durability_seen);
                    Dialed::refused(decision, &r.token(), &v, Refusal::of(r.refused(&v)))
                }
            },
            Err(Halt::Dial(e)) => match classify(Outcome::Dial(&e), 0) {
                Decision::Hold { cause, sent } => Dialed::Held(Reason::of(cause, sent)),
                _ => Dialed::Faced(Refusal::Unreachable(e)),
            },
            Err(Halt::Refused(r)) => {
                let decision = classify(Outcome::Rejected { code: &r.code, disposition: r.body["disposition"].as_str().unwrap_or("") }, durability_seen);
                let (token, verdict) = (r.token(), r.body.clone());
                Dialed::refused(decision, &token, &verdict, Refusal::Board(r))
            }
            Err(h) => Dialed::Faced(Refusal::of(h)),
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
    fn mark_moved(&self, reference: &str, principal: u64, doc: &str) {
        let mut boards = self.lock();
        let Some(ph) = principal_mut(&mut boards, reference, principal) else { return };
        let ks: Vec<u64> = ph.file.lines().iter().filter(|l| l.doc == doc).map(|l| l.k).collect();
        for k in ks {
            self.remark_line(ph, k, Reason::of(cause::MOVED, false));
        }
    }

    /// Re-mark one line in place — a hold that recurs, a refused run, a moved
    /// re-facing — its ordinal kept; a copy the device refused said on TALK.
    fn remark_line(&self, ph: &mut PrincipalHold, k: u64, reason: Reason) {
        if let Err(e) = ph.file.remark(k, reason) {
            self.say(format!("held: line {k}'s new cause could not be written ({e}); a reopen reads its earlier one"));
        }
    }

    /// Resolve one line `done` (kept or dropped), the file compacting where
    /// the queue empties.
    fn done(&self, reference: &str, principal: u64, k: u64, kept: bool, at: Option<u64>) {
        let mut boards = self.lock();
        if let Some(ph) = principal_mut(&mut boards, reference, principal) {
            self.done_line(ph, k, kept, at);
        }
    }

    /// One line out of the queue, whatever the disk did; a `done` the device
    /// refused said on TALK.
    fn done_line(&self, ph: &mut PrincipalHold, k: u64, kept: bool, at: Option<u64>) {
        if let Err(DoneError::Unwritten(e)) = ph.file.done(k, kept, at) {
            self.say(format!("held: line {k} is settled, and its `done` could not be written ({e}); a reopen reads it as held, and its read decides it"));
        }
        ph.durability.remove(&k);
    }

    /// The document's head: its first standing line in `k` order.
    fn head_of(&self, reference: &str, principal: u64, doc: &str) -> Option<HeldLine> {
        let mut boards = self.lock();
        principal_mut(&mut boards, reference, principal)?.file.lines().iter().find(|l| l.doc == doc).cloned()
    }

    /// How many lines stand on the document.
    fn count(&self, reference: &str, principal: u64, doc: &str) -> u64 {
        let mut boards = self.lock();
        principal_mut(&mut boards, reference, principal).map_or(0, |ph| ph.count(doc))
    }

    /// Fire the `held` event (§4b.2): `{board, session, doc, held, state,
    /// cause?}`, under the session the change was made for.
    fn fire(&self, reference: &str, session: &SessionEntry, doc: &str, held: u64, state: HeldState, cause: Option<&str>) {
        let mut data = json!({"board": reference, "session": session.reference, "doc": doc, "held": held, "state": state.as_str()});
        if let Some(c) = cause {
            data["cause"] = Value::from(c);
        }
        self.bus.emit(HELD, data);
    }
}

/// A principal's hold at a board, where one stands.
fn principal_mut<'b>(boards: &'b mut HashMap<String, BoardHold>, reference: &str, principal: u64) -> Option<&'b mut PrincipalHold> {
    boards.get_mut(reference)?.principals.get_mut(&principal)
}

/// P38's halt face for `held(session)` and every act (§3c.3).
fn store_halted(path: &Path, why: HaltWhy) -> Refusal {
    Refusal::shell(Name::STORE_HALTED, json!({"path": path.display().to_string(), "why": why.token()}))
}

/// One `held(session)` row (§4b.1): the line's members, `refusal` beside a
/// refused run's.
fn row_json(l: &HeldLine) -> Value {
    let mut row = json!({"held": l.k, "doc": l.doc, "base": l.base, "frame": l.frame, "cause": l.reason.cause, "sent": l.reason.sent, "time": l.time});
    if let Some(r) = &l.reason.refusal {
        row["refusal"] = r.clone();
    }
    row
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
    match session.facts.fingerprint {
        Some(fp) => fp.to_hex(),
        None => "bare".to_string(),
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
    session.facts.fingerprint.is_some() && row.get("key").is_none() && row.get("attest").is_some()
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
