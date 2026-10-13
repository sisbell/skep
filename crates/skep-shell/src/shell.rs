//! [`Shell`] — THE CORE (the dev provider record §2.2 (B)): the boards the
//! shell is opened over, each dialed through the one logging dialer and
//! named to the page by an opaque reference; the sessions it holds, each
//! named by a reference in the token's place (t5: "the page never holds a
//! token"); the SESSION MODE the shell was started in — BARE as the
//! claimant on the permissive board, or SIGNED content-scoped with a dev
//! key in the store (both ruled selectable per run); and ONE METHOD PER
//! ROW of `client.md` §4b.1, each taking the row's input as a value and
//! answering the row's output or a [`Refusal`] under the row's armed name,
//! the board's own refusals carried verbatim. The row methods are this
//! module's alone behind ONE DOOR, [`Shell::call`], which dispatches on the
//! bridge's spelling — one arm per call, the compiler holding the match
//! exhaustive — and logs every call, so no call reaches a row past the log;
//! [`Shell::fetch`] alone is public beside it, because it streams and its
//! transport logs it. The ten ceremonial rows — the key store's two and
//! the eight walks over `skep_client::ceremony` — are the child module
//! `ceremony`'s, `pub(super)` to the door; a transport runs each call on
//! the connection's thread. The page's two answers, [`Shell::answer`] and
//! [`Shell::cancel`], route to the walk that asked. A death signal a call
//! meets ends the session by the one sequence the board's feed thread runs
//! too (`Sessions::end`), and the call answers `session_died` with the
//! reason that sequence derived.
//!
//! WHAT THE SHELL REFUSES WITHOUT ASKING (ps3-5): a WRITE frame in the
//! guest form (the board would answer `unauthenticated`; no dial is made);
//! a BURST the board would take at no send — past its frame cap
//! (`frame_too_large`), naming no document in its one spelling
//! (`malformed_args` on `frame.doc`), an insert a signed session cannot
//! attest (`attest_not_composed`) — or one its principal's held queue
//! cannot keep (`held_full`, `store_halted`), each at the act (the hold's
//! door); and nothing else of a frame — `op` is a frame pipe, the frame's
//! semantics the wire's; a credential act from the page is refused by the
//! daemon's own `content_session` beneath the shell (ps3-7). A call's
//! ARGUMENTS are its row's (`shapes`' declarations): a required member
//! absent or of another form, and an optional member present in another
//! form, are refused `malformed_args` naming it, before any dial — never
//! read as absent; absent or `null`, an optional member is the row's
//! default. What it SIGNS: under a session that holds a key — the signed
//! mode's — every write of the ten kinds that have an entry frame, the
//! attest composed by `attest` from the shell's own reads, never from a
//! preimage the page supplies, and signed by the key that opened the
//! session (`SessionEntry::attest`). Every `/op` under a session, `/op-at`'s
//! aside, takes the hold's one path (`Holds::send`, §3c.4): a BURST — one of
//! the burst machine's five kinds — answered `held` where the board cannot
//! take it, every other write faced where a burst's would be held; each ack
//! noted for the hold's `base` (§3c.2), and every reissue-class answer
//! reissued within the call — a `write_busy` once after a short wait, a
//! first and second `durability` as-is — so the page meets the ack or the
//! next refusal (§4b.1's `op` row). Where the
//! library does not reach a row at this pin — `upload` and `restore`, whose
//! media walk is the shell's lane's and not in `skep-client` — the call
//! answers `not_reached` naming where it stops, never a silent stub;
//! `fetch` reaches the dialer's streamed form and no further (the
//! §Recovery order of the media design is not run here).

use std::fmt;
use std::io::Read;
use std::path::PathBuf;
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde_json::{json, Value};
use skep_client::address::is_address_text;
use skep_client::board::{AtAnswer, Board, Rejection};
use skep_client::derive::Mode;
use skep_client::dial::{Headers, Method, RequestHead};
use skep_client::halt::Halt;
use skep_client::search::SearchOpts;
use skep_client::store::{FileStore, KeyFacts};
use skep_client::Origin;

use crate::dev_arm::DevArm;
use crate::events::{Event, EventBus, EventName};
use crate::feed::{answer_without_index, BoardEntry, Feed, FeedThreads, Searcher, Shared};
use crate::hold::{Holds, OpAnswer, Resolved};
use crate::log::{CallOutcome, Log, LoggingDialer};
use crate::person::Pending;
use crate::refs::board_reference;
use crate::refusal::{Name, Refusal};
use crate::script;
use crate::sessions::{self, SessionEntry, Sessions};
use crate::wire::json_len;
use crate::Talk;

mod ceremony;

/// THE SESSION MODE a run names (P-5: both arms selectable per run): bare
/// as the principal on the permissive board, or signed content-scoped with
/// the store's key for the principal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionMode {
    Bare { principal: u64 },
    Signed { principal: u64 },
}

impl SessionMode {
    /// The principal the mode names.
    pub fn principal(self) -> u64 {
        match self {
            SessionMode::Bare { principal } | SessionMode::Signed { principal } => principal,
        }
    }

    /// The mode's name.
    pub fn name(self) -> &'static str {
        match self {
            SessionMode::Bare { .. } => "bare",
            SessionMode::Signed { .. } => "signed",
        }
    }
}

/// The dev arm a run names: the auto-answer, the default, or a script's
/// answers.
#[derive(Debug, Clone, Default)]
pub enum ArmConfig {
    #[default]
    Auto,
    Script(Vec<script::Answer>),
}

/// What a shell is opened over: [`ShellOptions::new`]'s four, and the two
/// a run may set beside them. Its `Debug` leaves out the TALK sink, a
/// closure.
#[derive(Clone)]
#[non_exhaustive]
pub struct ShellOptions {
    /// The boards, each a canonical origin dialed and signed at itself —
    /// distinct ([`Shell::open`]'s precondition).
    pub boards: Vec<Origin>,
    /// The dev key store — a throwaway directory, never `~/.skep` — and, at
    /// this pin, the data directory the index and the held store sit under
    /// (`client.md` §3c.1, §4e.4's drift).
    pub store_dir: PathBuf,
    /// The SESSION MODE every `session` call opens under (P-5).
    pub session_mode: SessionMode,
    pub arm: ArmConfig,
    /// Where the TALK lines go.
    pub talk: Talk,
    /// The board that is the shell's OWN node, where the verb runs one:
    /// `probe()`'s subject — one of `boards` ([`Shell::open`]'s
    /// precondition).
    pub own_node: Option<Origin>,
}

impl ShellOptions {
    /// A shell over `boards`, its key store at `store_dir`, its sessions
    /// opened in `session_mode` and its TALK lines on `talk`: the dev arm
    /// answering itself, and no own node.
    pub fn new(boards: Vec<Origin>, store_dir: PathBuf, session_mode: SessionMode, talk: Talk) -> ShellOptions {
        ShellOptions { boards, store_dir, session_mode, arm: ArmConfig::default(), talk, own_node: None }
    }
}

impl fmt::Debug for ShellOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShellOptions")
            .field("boards", &self.boards)
            .field("store_dir", &self.store_dir)
            .field("session_mode", &self.session_mode)
            .field("arm", &self.arm)
            .field("own_node", &self.own_node)
            .finish_non_exhaustive()
    }
}

/// The own node's state as the verb that owns it reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeState {
    Running,
    Stopped,
}

/// The write kinds of the wire (`docs/wire.md` §Operations): a frame of
/// one of these in the guest form is refused by the shell without a dial.
pub const WRITE_KINDS: [&str; 16] = [
    "delegate",
    "register_node",
    "create_new_document",
    "fork",
    "version",
    "insert",
    "delete",
    "copy",
    "reinstate",
    "rearrange",
    "publish",
    "make_link",
    "emit",
    "nullify",
    "assert_sup",
    "edit_link",
];

/// One CALL of §4b.1, as [`Shell::call`] dispatches it: one arm per call,
/// which the compiler holds exhaustive, and the list a transport admits a
/// call by, [`CALLS`], spelled from `Call::ALL` — so no call is listed that
/// the dispatch does not answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Call {
    Boards,
    Session,
    Close,
    Keygen,
    Fingerprint,
    Claim,
    Enroll,
    Bind,
    Recover,
    Rotate,
    Retire,
    Handoff,
    Accept,
    Health,
    Probe,
    Op,
    Upload,
    Fetch,
    Restore,
    Search,
    Held,
    Resolve,
}

impl Call {
    /// Every call, in §4b.1's order.
    const ALL: [Call; 22] = [
        Call::Boards,
        Call::Session,
        Call::Close,
        Call::Keygen,
        Call::Fingerprint,
        Call::Claim,
        Call::Enroll,
        Call::Bind,
        Call::Recover,
        Call::Rotate,
        Call::Retire,
        Call::Handoff,
        Call::Accept,
        Call::Health,
        Call::Probe,
        Call::Op,
        Call::Upload,
        Call::Fetch,
        Call::Restore,
        Call::Search,
        Call::Held,
        Call::Resolve,
    ];

    /// The call as the bridge spells it.
    const fn as_str(self) -> &'static str {
        match self {
            Call::Boards => "boards",
            Call::Session => "session",
            Call::Close => "close",
            Call::Keygen => "keygen",
            Call::Fingerprint => "fingerprint",
            Call::Claim => "claim",
            Call::Enroll => "enroll",
            Call::Bind => "bind",
            Call::Recover => "recover",
            Call::Rotate => "rotate",
            Call::Retire => "retire",
            Call::Handoff => "handoff",
            Call::Accept => "accept",
            Call::Health => "health",
            Call::Probe => "probe",
            Call::Op => "op",
            Call::Upload => "upload",
            Call::Fetch => "fetch",
            Call::Restore => "restore",
            Call::Search => "search",
            Call::Held => "held",
            Call::Resolve => "resolve",
        }
    }

    /// The call the bridge spells `name`.
    fn named(name: &str) -> Option<Call> {
        Call::ALL.into_iter().find(|call| call.as_str() == name)
    }
}

/// The twenty-two calls of §4b.1, as the bridge spells them, in its order:
/// the list a transport admits a call by, every name of it one
/// [`Shell::call`] answers.
pub const CALLS: [&str; Call::ALL.len()] = {
    let mut names = [""; Call::ALL.len()];
    let mut i = 0;
    while i < names.len() {
        names[i] = Call::ALL[i].as_str();
        i += 1;
    }
    names
};

/// A fetched blob: the head of the board's `200` — every other status is a
/// refusal — and its body, read to close.
pub struct Fetched {
    pub headers: Headers,
    pub body: Box<dyn Read + Send>,
}

impl fmt::Debug for Fetched {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fetched({} headers)", self.headers.0.len())
    }
}

/// THE SHELL. Dropping it stops it ([`Shell::shutdown`]), so its threads,
/// its sessions and the held store's locks never outlive it.
pub struct Shell {
    boards: Vec<Arc<BoardEntry>>,
    /// Each board's feed handle by the board's reference, fixed at the open:
    /// a call waiting on one board's feed thread holds nothing another call
    /// needs.
    feeds: Vec<(String, Feed)>,
    /// Each board's two feed threads, taken and stopped at the shell's stop.
    threads: Mutex<Vec<FeedThreads>>,
    sessions: Arc<Sessions>,
    bus: Arc<EventBus>,
    pending: Arc<Pending>,
    arm: Arc<DevArm>,
    log: Arc<Log>,
    store: Arc<FileStore>,
    /// THE HELD-BURST HOLDS (§3c): the one path of every `/op` under a
    /// session, the queue `held` and `resolve` read and act on, the own
    /// node's stopped state, and the resend the boards' feed threads drive.
    holds: Arc<Holds>,
    anchors: PathBuf,
    session_mode: SessionMode,
    talk: Talk,
    /// The own node's board reference, where the shell runs one.
    own_node_reference: Option<String>,
    host_name: String,
    date: String,
}

impl fmt::Debug for Shell {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Shell({} boards, {} sessions, {})", self.boards.len(), self.sessions.len(), self.session_mode.name())
    }
}

/// A principal argument as a call passes it: a non-negative integer no
/// greater than 2^53 − 1 (AUTH-6.36).
fn principal_arg(v: &Value) -> Option<u64> {
    v.as_u64().filter(|n| *n <= (1u64 << 53) - 1)
}

/// An OPTIONAL argument as its row declares it (`shapes`' declarations):
/// absent or `null` → `None`; present and of the form `read` takes →
/// `Some`; present and of no such form → `malformed_args` naming `member` —
/// asked once, here, and never read as absent.
fn optional<'a, T>(args: &'a Value, member: &str, read: impl FnOnce(&'a Value) -> Option<T>) -> Result<Option<T>, Refusal> {
    match args.get(member) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => read(v).map(Some).ok_or_else(|| Refusal::malformed(member)),
    }
}

/// THE FORM a call names (§4b.1's `op`, `fetch` and `search` rows): the
/// guest form — `guest: true`, no `session` — or the session form — a
/// `session`, no `guest: true`; any other combination names neither, and
/// is refused `malformed_args` naming `session`. Whether it is the guest
/// form.
fn guest_form(args: &Value) -> Result<bool, Refusal> {
    match (optional(args, "guest", Value::as_bool)?.unwrap_or(false), args.get("session")) {
        (true, None) => Ok(true),
        (false, Some(_)) => Ok(false),
        _ => Err(Refusal::malformed("session")),
    }
}

/// A `search` call's `opts` as declared (`SearchOpts`): an object where
/// present, each member of its form — `malformed_args` naming
/// `opts.<member>` where one is not — and where absent the defaults: the
/// bound limit, no offset, no reindex.
fn search_opts(args: &Value) -> Result<(SearchOpts, bool), Refusal> {
    optional(args, "opts", |v| v.is_object().then_some(()))?;
    let opts = &args["opts"];
    let in_opts = |member: &'static str| move |_: Refusal| Refusal::malformed(format!("opts.{member}"));
    let limit = optional(opts, "limit", Value::as_u64).map_err(in_opts("limit"))?;
    let offset = optional(opts, "offset", Value::as_u64).map_err(in_opts("offset"))?;
    let reindex = optional(opts, "reindex", Value::as_bool).map_err(in_opts("reindex"))?;
    let defaults = SearchOpts::default();
    let opts = SearchOpts { limit: limit.map_or(defaults.limit, |n| n as usize), offset: offset.map_or(defaults.offset, |n| n as usize) };
    Ok((opts, reindex.unwrap_or(false)))
}

/// Where a guest form reads (§4b.1): one of this shell's boards, or a
/// canonical origin its list holds no board at — a followed link's.
enum GuestTarget {
    Board(Arc<BoardEntry>),
    Origin(Origin),
}

/// `yyyy-mm-dd` from unix seconds (civil-from-days).
fn civil_date(secs: u64) -> String {
    let z = (secs / 86400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

/// The machine's host name for the anchor boxes' default: `HOSTNAME`,
/// `COMPUTERNAME`, else `dev-machine`; its first label, lowercased.
fn host_name() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .and_then(|t| {
            let line = t.lines().next().unwrap_or_default().trim();
            let name = line.split_once('.').map_or(line, |(n, _)| n).to_lowercase();
            (!name.is_empty()).then_some(name)
        })
        .unwrap_or_else(|| "dev-machine".to_string())
}

impl Shell {
    /// THE OPEN: one entry per board, the feed threads started, the store
    /// opened (nothing written until a key is made); nothing is dialed
    /// here, so nothing refuses — under the signed mode the key is checked
    /// at the first `session`, or before serving by
    /// [`Shell::check_signed_key`]. PRECONDITION, the caller's: `opts.boards`
    /// are distinct — one board twice would be two feeds and two held
    /// stores over one chain, the second another window's — and
    /// `opts.own_node`, where set, is one of them; `open` panics naming the
    /// one broken, before anything starts.
    pub fn open(opts: ShellOptions) -> Shell {
        assert!(opts.boards.iter().enumerate().all(|(i, origin)| !opts.boards[..i].contains(origin)), "ShellOptions' precondition: the boards are distinct");
        assert!(opts.own_node.as_ref().is_none_or(|own| opts.boards.contains(own)), "ShellOptions' precondition: own_node, where set, is one of the boards");
        let log = Arc::new(Log::new());
        let bus = Arc::new(EventBus::new());
        let store = Arc::new(FileStore::open(&opts.store_dir));
        // The store the restart arm re-opens a session under: the signed
        // mode's, none under the bare mode (a bare session is never
        // re-opened silently).
        let reopen_store = matches!(opts.session_mode, SessionMode::Signed { .. }).then(|| Arc::clone(&store));
        let sessions = Arc::new(Sessions::new(reopen_store));
        // The anchors BESIDE the store, never under it (§3.4 refuses a
        // destination under the store): `<store>-anchors/`.
        let anchors = {
            let mut name = opts.store_dir.as_os_str().to_owned();
            name.push("-anchors");
            PathBuf::from(name)
        };
        let arm = Arc::new(match opts.arm {
            ArmConfig::Auto => DevArm::auto(anchors.clone(), Arc::clone(&opts.talk)),
            ArmConfig::Script(answers) => DevArm::script(answers, Arc::clone(&opts.talk)),
        });
        let mut boards = Vec::new();
        let mut own_node_reference = None;
        for origin in &opts.boards {
            let board = Arc::new(Board::new(origin.clone(), LoggingDialer::new(Arc::clone(&log))));
            let entry = Arc::new(BoardEntry { reference: board_reference(), origin: origin.clone(), board });
            if opts.own_node.as_ref() == Some(origin) {
                own_node_reference = Some(entry.reference.clone());
            }
            boards.push(entry);
        }
        let boards_by_reference = boards.iter().map(|entry| (entry.reference.clone(), Arc::clone(&entry.board)));
        let holds = Holds::new(Arc::clone(&sessions), Arc::clone(&bus), Arc::clone(&store), opts.store_dir.clone(), Arc::clone(&opts.talk), boards_by_reference);
        let shared = Shared { bus: Arc::clone(&bus), sessions: Arc::clone(&sessions), data_dir: opts.store_dir.clone(), talk: Arc::clone(&opts.talk), holds: Arc::clone(&holds) };
        let threads: Vec<FeedThreads> = boards.iter().map(|entry| FeedThreads::spawn(Arc::clone(entry), shared.clone())).collect();
        let feeds = boards.iter().zip(&threads).map(|(entry, board_threads)| (entry.reference.clone(), board_threads.feed())).collect();
        let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        Shell {
            boards,
            feeds,
            threads: Mutex::new(threads),
            sessions,
            bus,
            pending: Arc::new(Pending::new()),
            arm,
            log,
            store,
            holds,
            anchors,
            session_mode: opts.session_mode,
            talk: opts.talk,
            own_node_reference,
            host_name: host_name(),
            date: civil_date(secs),
        }
    }

    /// The bus, for a transport's event stream.
    pub fn bus(&self) -> &Arc<EventBus> {
        &self.bus
    }

    /// One more subscriber to the event stream.
    pub fn subscribe(&self) -> Receiver<Event> {
        self.bus.subscribe()
    }

    /// The log, for `GET /bridge/log`.
    pub fn log(&self) -> &Arc<Log> {
        &self.log
    }

    /// Whether the dev arm is a script.
    pub fn arm_is_script(&self) -> bool {
        self.arm.is_script()
    }

    /// The board references issued, in the list's order.
    pub fn board_references(&self) -> Vec<String> {
        self.boards.iter().map(|entry| entry.reference.clone()).collect()
    }

    /// The own node's state as the verb that owns it reports it: what
    /// `probe` answers for that node, announced on the `daemon` event at its
    /// board (`client.md` §4b.2: "the shell owns the child process"); a
    /// shell that runs no node has none to report. A DELIBERATE STOP is
    /// said here ONCE: while it stands the board's feed announces no
    /// `unreachable` of its own, and `Running` here is the one `running`
    /// (`feed.rs`'s `unreachable`). `Running` ends the hold at the node's
    /// board and hands the board's feed thread its probe, as
    /// `resolve(send)` hands it: the caller waits on no dial.
    pub fn set_node_state(&self, state: NodeState) {
        let Some(board_reference) = &self.own_node_reference else { return };
        let running = matches!(state, NodeState::Running);
        let state = match state {
            NodeState::Running => "running",
            NodeState::Stopped => "stopped",
        };
        self.bus.emit(EventName::Daemon, json!({"board": board_reference, "state": state}));
        // The own node's STOPPED state is the hold's (§3c.4): every burst at
        // its board holds `stopped` without a dial, `probe` answers it, and
        // `Running` ends the hold, the resend run on the board's feed thread
        // where a session stands.
        self.holds.set_node_stopped(board_reference, !running);
        if running {
            self.feed(board_reference).probe();
        }
    }

    /// THE CHECK the signed mode makes before serving: the store's key for
    /// the principal at every board, its public facts — `no_key` where the
    /// store is keyless for one. Under the bare mode, `Ok` with no key: its
    /// sessions sign nothing.
    pub fn check_signed_key(&self) -> Result<Vec<KeyFacts>, Refusal> {
        let SessionMode::Signed { principal } = self.session_mode else { return Ok(Vec::new()) };
        let mut keys = Vec::new();
        for entry in &self.boards {
            let mode = || entry.board.health().map(|h| Mode::of(&h)).unwrap_or(Mode::Unclaimed);
            keys.push(sessions::signing_key(&self.store, &entry.origin, principal, mode)?);
        }
        Ok(keys)
    }

    fn say(&self, line: impl AsRef<str>) {
        (self.talk)(line.as_ref());
    }

    /// The feed handle of the board `board_reference` names.
    fn feed(&self, board_reference: &str) -> &Feed {
        self.feeds.iter().find(|(r, _)| r == board_reference).map(|(_, feed)| feed).expect("every board of this shell has its feed, fixed at the open")
    }

    /// The entry of the board a reference names, or THE PIN's unknown-board
    /// refusal.
    fn board_entry(&self, board_reference: &Value) -> Result<Arc<BoardEntry>, Refusal> {
        let Some(board_reference) = board_reference.as_str() else { return Err(Refusal::malformed("board")) };
        self.boards.iter().find(|entry| entry.reference == board_reference).cloned().ok_or_else(|| Refusal::shell(Name::UNKNOWN_BOARD, json!({"board": board_reference})))
    }

    /// The session a reference names, or THE PIN's "session ended".
    fn session(&self, session_reference: &Value) -> Result<Arc<SessionEntry>, Refusal> {
        let Some(session_reference) = session_reference.as_str() else { return Err(Refusal::malformed("session")) };
        self.sessions.get(session_reference).ok_or_else(|| Refusal::shell(Name::SESSION_ENDED, json!({"session": session_reference})))
    }

    /// A death signal met on `session`'s token under the shell's hands: the
    /// session ended by the one sequence the board's feed thread runs too,
    /// whichever hand came first; the call's refusal, carrying the reason.
    fn died(&self, session: &SessionEntry) -> Refusal {
        let reason = self.sessions.end(session, &mut self.feed(&session.board_reference), &self.bus);
        Refusal::shell(Name::SESSION_DIED, json!({"session": session.reference, "reason": reason}))
    }

    // ── THE CALLS ────────────────────────────────────────────────────────

    /// ONE CALL by name, the log kept: the row's method dispatched on the
    /// bridge's spelling, one arm per call; a name the bridge does not spell
    /// is answered `unknown_call` and logged by its length alone.
    pub fn call(&self, name: &str, args: &Value) -> Result<Value, Refusal> {
        let started = Instant::now();
        let bytes_in = json_len(args);
        let call = Call::named(name);
        let answer = match call {
            Some(Call::Boards) => Ok(self.boards()),
            Some(Call::Session) => self.session_call(args),
            Some(Call::Close) => self.close(args),
            Some(Call::Keygen) => self.keygen(args),
            Some(Call::Fingerprint) => self.fingerprint(args),
            Some(Call::Claim) => self.claim(args),
            Some(Call::Enroll) => self.enroll(args),
            Some(Call::Bind) => self.bind(args),
            Some(Call::Recover) => self.recover(args),
            Some(Call::Rotate) => self.rotate(args),
            Some(Call::Retire) => self.retire(args),
            Some(Call::Handoff) => self.handoff(args),
            Some(Call::Accept) => self.accept(args),
            Some(Call::Health) => self.health(args),
            Some(Call::Probe) => Ok(self.probe()),
            Some(Call::Op) => self.op(args),
            Some(Call::Upload) => self.upload(args),
            Some(Call::Fetch) => Err(Refusal::shell(Name::STREAMED_CALL, json!({"call": "fetch", "detail": "fetch streams its bytes: a transport serves it on its own route, and a direct caller takes `Shell::fetch`"}))),
            Some(Call::Restore) => self.restore(args),
            Some(Call::Search) => self.search(args),
            Some(Call::Held) => self.held(args),
            Some(Call::Resolve) => self.resolve(args),
            None => Err(Refusal::shell(Name::UNKNOWN_CALL, json!({"call": name}))),
        };
        let (bytes_out, outcome) = match &answer {
            Ok(v) => (json_len(v), CallOutcome::Result),
            Err(r) => (json_len(&r.to_value()), CallOutcome::Refused),
        };
        match call {
            Some(call) => self.log.call(call.as_str(), bytes_in, bytes_out, started.elapsed(), outcome),
            None => self.log.unknown_call(name.len(), bytes_in, bytes_out, started.elapsed()),
        }
        answer
    }

    /// `boards()` → `[{board, name, origin}]`: `name` the origin, v1's
    /// fallback (ps3-4: every board takes it while no board publishes a
    /// display name).
    fn boards(&self) -> Value {
        Value::Array(self.boards.iter().map(|entry| json!({"board": entry.reference, "name": entry.origin.as_str(), "origin": entry.origin.as_str()})).collect())
    }

    /// `session(board, principal)` → `{session, principal, account}`: the
    /// mode's opening as `principal`, the reference issued in the token's
    /// place.
    fn session_call(&self, args: &Value) -> Result<Value, Refusal> {
        let entry = self.board_entry(&args["board"])?;
        let principal = optional(args, "principal", principal_arg)?.unwrap_or(self.session_mode.principal());
        let open = match self.session_mode {
            SessionMode::Bare { .. } => sessions::open_bare(&entry.board, principal)?,
            SessionMode::Signed { .. } => sessions::open_signed(&entry.board, &self.store, principal)?,
        };
        let session = self.sessions.register(&entry.reference, Arc::clone(&entry.board), open, &mut self.feed(&entry.reference));
        // The principal's held file read whole at its session's open (§3c.7),
        // so `held(session)` lists its lines at once. The resend is NOT run
        // here: the page reads `held(session)` right after opening, and a
        // synchronous resend would clear the lines before it; the feed's probe
        // and its daemon-running tick drive it once a session stands (§3c.5).
        self.holds.open_session(&session);
        Ok(json!({"session": session.reference, "principal": principal, "account": session.facts.account}))
    }

    /// `close(session)` → `{}`: the session out of the table; its drafts
    /// rows read to the head under its token and its supplement released
    /// (`Feed::closing`, answered before the token closes); `POST
    /// /session/close` (idempotent at the board); and its own arm on
    /// `session-died`, after every `feed` row of the session. The close is
    /// the shell's act, whatever the board says — §4b.1's row arms no
    /// refusal at the board: a token the board did not close, or never
    /// answered for, is said on TALK and dies at the board's restart. A
    /// reference this shell holds no session under — stale, or ended by a
    /// death met first — answers "session ended".
    fn close(&self, args: &Value) -> Result<Value, Refusal> {
        let Some(session_reference) = args["session"].as_str() else { return Err(Refusal::malformed("session")) };
        let session = self.sessions.close(session_reference).ok_or_else(|| Refusal::shell(Name::SESSION_ENDED, json!({"session": session_reference})))?;
        self.feed(&session.board_reference).closing(&session);
        if let Err(h) = session.board.session_close(&session.token) {
            self.say(format!("close: the board did not close {}'s token ({h}); it dies at the board's restart", session.reference));
        }
        self.bus.emit(EventName::SessionDied, json!({"session": session.reference, "reason": sessions::closed()}));
        Ok(json!({}))
    }

    /// `health(board)` → `{health, mode}`: the `/health` document verbatim
    /// and the derived mode.
    fn health(&self, args: &Value) -> Result<Value, Refusal> {
        let entry = self.board_entry(&args["board"])?;
        let health = entry.board.health()?;
        Ok(json!({"health": health.body, "mode": Mode::of(&health).name()}))
    }

    /// `probe()` → `{daemon, dialed, signed}`: the own node's state where
    /// the shell runs one — `stopped` where its owner stopped it,
    /// `unreachable` where it does not answer, `running` else — and the
    /// first board's reachability where it runs none.
    fn probe(&self) -> Value {
        let entry = match &self.own_node_reference {
            Some(board_reference) => self.boards.iter().find(|entry| &entry.reference == board_reference),
            None => self.boards.first(),
        };
        let Some(entry) = entry else { return json!({"daemon": "unreachable", "dialed": null, "signed": null}) };
        let state = if self.holds.node_stopped(&entry.reference) {
            "stopped"
        } else if entry.board.health().is_ok() {
            "running"
        } else {
            "unreachable"
        };
        json!({"daemon": state, "dialed": entry.board.dialed().as_str(), "signed": entry.board.signed().as_str()})
    }

    /// THE GUEST FORM's TARGET (§4b.1's `op` and `search` rows): the board a
    /// reference names — `unknown_board` where this shell issued none — read
    /// first; else the CANONICAL ORIGIN given, parsed by §1.6's grammar and
    /// refused `not_canonical`, read as this shell's own board where its
    /// list holds one at that origin; `malformed_args` where neither is
    /// given.
    fn guest_target(&self, args: &Value) -> Result<GuestTarget, Refusal> {
        if optional(args, "board", Value::as_str)?.is_some() {
            return Ok(GuestTarget::Board(self.board_entry(&args["board"])?));
        }
        let origin = optional(args, "origin", Value::as_str)?.ok_or_else(|| Refusal::malformed("board or origin"))?;
        let origin = Origin::parse(origin).ok_or_else(|| Refusal::shell(Name::NOT_CANONICAL, json!({"origin": origin})))?;
        Ok(match self.boards.iter().find(|entry| entry.origin == origin) {
            Some(entry) => GuestTarget::Board(Arc::clone(entry)),
            None => GuestTarget::Origin(origin),
        })
    }

    /// The board the guest form dials, token-free: its target's origin.
    fn guest_board(&self, args: &Value) -> Result<Board, Refusal> {
        let origin = match self.guest_target(args)? {
            GuestTarget::Board(entry) => entry.origin.clone(),
            GuestTarget::Origin(origin) => origin,
        };
        Ok(Board::new(origin, LoggingDialer::new(Arc::clone(&self.log))))
    }

    /// The frame, and its `at` where the page sent the `/op-at` form.
    fn frame_of(args: &Value) -> Result<(Value, Option<u64>), Refusal> {
        let frame = &args["frame"];
        if !frame.is_object() {
            return Err(Refusal::malformed("frame"));
        }
        if let Some(at) = frame["at"].as_u64() {
            if frame["frame"].is_object() {
                return Ok((frame["frame"].clone(), Some(at)));
            }
        }
        Ok((frame.clone(), None))
    }

    /// A response document: the board's answer whole, a `rejected` document
    /// the board's refusal verbatim.
    fn document(v: Value) -> Result<Value, Refusal> {
        match Rejection::of(&v) {
            Some(r) => Err(Refusal::from(r.refused(&v))),
            None => Ok(v),
        }
    }

    /// `op(session, frame)` and the guest forms: ONE frame to the board the
    /// session stands at under its token, by the hold's one path
    /// ([`Holds::send`]) — the attest composed where the session holds a key
    /// and the kind has an entry frame, a burst held where the board cannot
    /// take it, a reissue-class answer reissued within the call, and an ack
    /// noted for the hold's `base` — an `/op-at` frame aside, its answer the
    /// board's own; or token-free at guest class, the board or origin named
    /// read first (`unknown_board`, `not_canonical`, `malformed_args`), then
    /// a write refused without a dial (`write_in_guest_form`). An `/op-at`
    /// refusal is the board's verdict, as every other is; a death signal met
    /// at the dial or at a read the attest needed ends the session.
    fn op(&self, args: &Value) -> Result<Value, Refusal> {
        let (frame, at) = Self::frame_of(args)?;
        if guest_form(args)? {
            let board = self.guest_board(args)?;
            let op = frame["op"].as_str().unwrap_or("");
            if WRITE_KINDS.contains(&op) {
                return Err(Refusal::shell(Name::WRITE_IN_GUEST_FORM, json!({"op": op})));
            }
            return match at {
                Some(at) => match board.op_at(None, at, &frame)? {
                    AtAnswer::Document(v) => Self::document(v),
                    other => Err(at_refusal(other)),
                },
                None => Self::document(board.guest(&frame)?),
            };
        }
        let session = self.session(&args["session"])?;
        let Some(at) = at else {
            return match self.holds.send(&session, frame) {
                OpAnswer::Answered(answer) => answer,
                OpAnswer::Died => Err(self.died(&session)),
            };
        };
        match session.board.op_at(Some(&session.token), at, &frame)? {
            AtAnswer::Document(v) => Self::document(v),
            AtAnswer::Closed => Err(self.died(&session)),
            other => Err(at_refusal(other)),
        }
    }

    /// `upload(session, target)`: NOT REACHED at this pin — `media.md`'s
    /// walk (the PUT and its resume, the create, the cell's insert, the
    /// typing link) is the shell's lane's and `skep-client` holds no media
    /// module; the provider would take a path.
    fn upload(&self, args: &Value) -> Result<Value, Refusal> {
        self.session(&args["session"])?;
        Err(Refusal::shell(Name::NOT_REACHED, json!({"call": "upload", "detail": "the media walk — the PUT and its resume, the create, the cell's insert, the typing link — is not in skep-client at this pin; the provider would take a path in `args`"})))
    }

    /// `restore(session, i)`: NOT REACHED at this pin, as `upload`.
    fn restore(&self, args: &Value) -> Result<Value, Refusal> {
        self.session(&args["session"])?;
        Err(Refusal::shell(Name::NOT_REACHED, json!({"call": "restore", "detail": "the repair is a plain upload matched by hash (media.md), and the media walk is not in skep-client at this pin"})))
    }

    /// `fetch(session, i)` and its guest forms: `GET /blob?i=<address>` on
    /// the dialer's streamed form, the bytes streamed back as the daemon
    /// checked them against the cell before its first byte — the client
    /// side of `media.md` §Recovery (the length held, the re-hash) is not
    /// run here. A non-200 is the board's refusal; the death signal on the
    /// head ends the session. The caller's, since `fetch` streams past the
    /// door: it logs the call — `Log::call("fetch", …)` with
    /// `CallOutcome::Stream` once the body is copied, `CallOutcome::Refused`
    /// for a refusal; `fetch` logs its dial alone — and reads the body to its
    /// end or drops it.
    pub fn fetch(&self, args: &Value) -> Result<Fetched, Refusal> {
        let i = args["i"].as_str().ok_or_else(|| Refusal::malformed("i"))?;
        if !is_address_text(i) {
            return Err(Refusal::malformed("i"));
        }
        let (board, token, session) = if guest_form(args)? {
            (Arc::new(self.guest_board(args)?), None, None)
        } else {
            let session = self.session(&args["session"])?;
            (Arc::clone(&session.board), Some(session.token.clone()), Some(session))
        };
        let mut headers = Vec::new();
        if let Some(t) = &token {
            headers.push(("Skepd-Session".to_string(), t.as_str().to_string()));
        }
        let head = RequestHead { method: Method::Get, path: format!("/blob?i={i}"), headers, content_length: None };
        let mut empty = std::io::empty();
        let resp = board.dialer().stream(board.dialed(), &head, &mut empty, &mut |_| {}).map_err(Refusal::Unreachable)?;
        if resp.headers.get("Skepd-Session").is_some_and(|v| v.trim() == "closed") {
            if let Some(session) = &session {
                return Err(self.died(session));
            }
        }
        if resp.status != 200 {
            let mut body = Vec::new();
            let reader = resp.body;
            let _ = reader.take(64 * 1024).read_to_end(&mut body);
            return Err(Refusal::board(resp.status, serde_json::from_slice(&body).unwrap_or(Value::Null)));
        }
        Ok(Fetched { headers: resp.headers, body: resp.body })
    }

    /// `search(session|guest, board, query, opts)` → `{hits, places, state}`
    /// off the board's consumer: the session form at the session's own
    /// board — a `board` given beside it naming that board, else
    /// `malformed_args` — and the guest form at the board its reference or
    /// its canonical origin names ([`Shell::guest_target`]), an origin this
    /// shell holds no board at answered with no index (`state: none`);
    /// `query_too_long` the shell's own bound.
    fn search(&self, args: &Value) -> Result<Value, Refusal> {
        let query = args["query"].as_str().ok_or_else(|| Refusal::malformed("query"))?;
        let (opts, reindex) = search_opts(args)?;
        let (board_reference, who) = if guest_form(args)? {
            match self.guest_target(args)? {
                GuestTarget::Board(entry) => (entry.reference.clone(), Searcher::Guest),
                // A followed link's origin this shell holds no index for.
                GuestTarget::Origin(_) => return Ok(answer_without_index()),
            }
        } else {
            let session = self.session(&args["session"])?;
            if optional(args, "board", Value::as_str)?.is_some_and(|board| board != session.board_reference) {
                return Err(Refusal::malformed("board"));
            }
            let who = Searcher::Session { principal: session.facts.principal, token: session.token.clone(), account: session.facts.account.clone().unwrap_or_default() };
            (session.board_reference.clone(), who)
        };
        self.feed(&board_reference).search(who, query, opts, reindex)
    }

    /// `held(session)` → the acting principal's held bursts at the session's
    /// board in resend order (§4b.1), from THIS principal's file and no other
    /// (P39); `store_halted` where a newer `v` or a damaged body halted it.
    fn held(&self, args: &Value) -> Result<Value, Refusal> {
        let session = self.session(&args["session"])?;
        self.holds.lines(&session)
    }

    /// `resolve(session, {held, act})` → `{}` (§4b.1): `"drop"` on a `refused`
    /// or `moved` line marks it (and a refused run's `behind` lines) dropped;
    /// `"send"` re-enters the automatic machine for that document, the call
    /// answering "once the line is handed to the machine, never after its
    /// ack" — the probe that resends it handed to the board's feed thread
    /// (`Feed::probe`); `store_halted`, `no_such_held` and `not_resolvable`
    /// as `Holds::resolve` orders them.
    fn resolve(&self, args: &Value) -> Result<Value, Refusal> {
        let session = self.session(&args["session"])?;
        let k = args["held"].as_u64().ok_or_else(|| Refusal::malformed("held"))?;
        let act = args["act"].as_str().ok_or_else(|| Refusal::malformed("act"))?;
        match self.holds.resolve(&session, k, act)? {
            Resolved::Dropped => {}
            Resolved::HandedBack => self.feed(&session.board_reference).probe(),
        }
        Ok(json!({}))
    }

    // ── THE TWO ANSWERS ──────────────────────────────────────────────────

    /// `answer(id, value)`: `value` handed to the walk that asked, of the
    /// form its moment's kind takes (`MomentEvent.kind`) — else
    /// `malformed_args` naming `value`, the moment still waiting;
    /// `no_such_moment` where no moment of that id waits.
    pub fn answer(&self, id: &str, value: Value) -> Result<(), Refusal> {
        self.pending.answer(id, value)
    }

    /// `cancel(id)`: the walk that asked abandoned at that moment;
    /// `no_such_moment` where no moment of that id waits.
    pub fn cancel(&self, id: &str) -> Result<(), Refusal> {
        self.pending.cancel(id)
    }

    // ── THE STOP ─────────────────────────────────────────────────────────

    /// THE CLEAN STOP: every pending moment cancelled, every session closed
    /// at its board, every board's feed threads stopped — each consumer
    /// saved and closed, each feed thread joined, so the `held/<chain>/`
    /// locks its holds kept are free once this returns. A second stop finds
    /// nothing left to stop, and dropping the shell runs it. NOTHING of the
    /// held-burst store is written here — every held line is already synced
    /// at its `op` (persist-first, §3c.6's step 3). UNVERIFIED HERE (the
    /// record §7 item 1): that the desktop framework's close hook runs this,
    /// and that the page's last `op` reaches the shell before the webview is
    /// destroyed, is the framework's to prove — no Tauri source is on this
    /// machine; a crash loses at most the open or in-flight burst (R14).
    pub fn shutdown(&self) {
        self.pending.cancel_all();
        for session in self.sessions.all() {
            if self.sessions.close(&session.reference).is_some() {
                let _ = session.board.session_close(&session.token);
            }
        }
        let threads = std::mem::take(&mut *self.threads.lock().expect("the feed threads' lock"));
        for board_threads in threads {
            board_threads.stop();
        }
    }
}

impl Drop for Shell {
    /// The clean stop where its owner made none ([`Shell::shutdown`]): no
    /// thread, session or lock of the shell outlives it.
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// An `/op-at` refusal as the board's verdict: the status and the error
/// document the wire answers it with (wire.md §Reading history), rebuilt
/// from the variant `skep-client` read them into — a member the variant
/// holds rides the body, as "when known" has it. The document and the
/// death signal are the caller's to read before this; an answer of any
/// other kind halts naming it.
fn at_refusal(a: AtAnswer) -> Refusal {
    let document = |error: &str, member: &str, known: Option<u64>| {
        let mut body = json!({"error": error});
        if let Some(n) = known {
            body[member] = Value::from(n);
        }
        body
    };
    let (status, body) = match a {
        AtAnswer::HistoryReclaimed { floor } => (410, document("history_reclaimed", "floor", floor)),
        AtAnswer::BeyondHead { head } => (400, document("beyond_head", "head", head)),
        AtAnswer::NotAPosition { nearest } => (400, document("not_a_position", "nearest", nearest)),
        AtAnswer::Busy => (503, json!({"error": "history_busy"})),
        other => {
            let state = format!("the board answered `/op-at` with {other:?}, which is no refusal the shell reads");
            return Refusal::from(Halt::face(state, "`skep-client` read an `/op-at` answer this shell does not carry", "report it: the shell's `op` row is behind the library"));
        }
    };
    Refusal::board(status, body)
}

#[cfg(test)]
mod tests;
