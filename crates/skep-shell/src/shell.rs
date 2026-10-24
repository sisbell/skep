//! [`Shell`], the core (the dev provider record §2.2 (B)).
//!
//! It holds the boards the shell is opened over, each dialed through the one
//! logging dialer and named to the page by an opaque reference; the sessions
//! it holds, each named by a reference in the token's place, so the page
//! never holds a token; the session mode the shell was started in — bare as
//! the run's principal on the permissive board, the keyless session that
//! reads alone, or signed content-scoped with a dev key in the store, which
//! writes too (both selectable per run); and one method per row of
//! `client.md` §4b.1 — and of `places`, the document index's listing beside
//! `search` (A-255) — each taking the row's input as a value and answering
//! the row's output or a [`Refusal`] under the row's armed name, the board's
//! own refusals carried verbatim — and of `changes`, the change feed's page
//! from a position at the session's class, read for a client that comes back
//! to a board. The row methods are this module's alone behind one door,
//! [`Shell::call`], which dispatches on the bridge's spelling — one arm per
//! call, the compiler holding the match exhaustive — and logs every call, so
//! no call reaches a row past the log; [`Shell::fetch`] alone is public
//! beside it, because it streams; it logs its own call as `call` does. The
//! ten ceremonial rows — the key store's two and the eight walks over
//! `skep_client::ceremony` — are the child module `ceremony`'s, `pub(super)`
//! to the door; a transport runs each call on the connection's thread. The
//! page's two answers, [`Shell::answer`] and [`Shell::cancel`], route to the
//! walk that asked; the secret and consent moments of a walk go to the dev
//! arm the run named ([`ArmConfig`]) — or, under [`ArmConfig::Refuse`], the
//! setting of a client with no person present, are refused `person_required`
//! and answered by nothing. A death signal a call meets ends the session by
//! the one sequence the board's feed thread runs too (`Sessions::end`), and
//! the call answers `session_died` with the reason that sequence derived.
//!
//! **What the shell refuses without asking.** A write frame in the guest
//! form ([`WRITE_KINDS`]; the board would answer `unauthenticated`, so no
//! dial is made); a write frame under a bare session, and its
//! `resolve(send)` — the keyless session reads alone (foundations §3.3
//! state 3), so no `bare` write of this shell's is ever committed
//! (`write_in_bare_session`, `SessionEntry::may_write`); and a call's
//! arguments not of its row's form (`shapes`' declarations): a required
//! member absent or of another form (`accept`'s `address`, absent, answers
//! `no_address`), and an optional member present in another form, refused
//! `malformed_args` naming it before any dial — never read as absent; absent
//! or `null`, an optional member is the row's default. Nothing else of a
//! frame: `op` is a frame pipe, the frame's semantics the wire's, and a
//! credential act from the page is refused by the daemon's own
//! `content_session` beneath the shell. Every other `/op` under a session,
//! `/op-at`'s aside, goes by the hold's one path (`Holds::send`): what a
//! burst is refused at the act for (`Burst::admit`), what is held and what
//! is reissued within the call are the hold's to say, and what a signed
//! session's attest signs is `SessionEntry::attest`'s. Where the library
//! does not reach a row at this pin — `upload` and `restore`, whose media
//! walk is not in `skep-client` — the call answers `not_reached` naming
//! where it stops, never a silent stub; `fetch` reaches the dialer's
//! streamed form and no further (the §Recovery order of the media design is
//! not run here).

use std::fmt;
use std::io::{self, Read};
use std::path::PathBuf;
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde_json::{json, Value};
use skep_address::Address;
use skep_client::address::is_address_text;
use skep_client::board::{AtAnswer, Board, Rejection};
use skep_client::derive::Mode;
use skep_client::dial::{Headers, Method, RequestHead};
use skep_client::halt::Halt;
use skep_client::search::{QueryTooLong, SearchOpts, QUERY_BOUND};
use skep_client::store::{FileStore, KeyFacts};
use skep_client::Origin;

use crate::dev_arm::DevArm;
use crate::events::{Event, EventBus, EventName};
use crate::feed::{answer_without_index, changes_since, places_without_index, query_too_long, BridgeSearchOpts, ChangesRead, Feed, FeedThreads, Searcher, Shared};
use crate::hold::{Holds, OpAnswer, ResolveAct, Resolved};
use crate::log::{CallOutcome, Log, ShellDialer};
use crate::person::{Answerer, Pending};
use crate::refs::BoardEntry;
use crate::refusal::{Name, Refusal};
use crate::script;
use crate::sessions::{self, SessionEntry, Sessions};
use crate::wire::{bounded_address, json_len};
use crate::Talk;

mod ceremony;

/// The session mode a run names, both arms selectable per run.
///
/// Bare opens each session as the principal on the permissive board, a
/// session for reading alone; signed opens it content-scoped with the
/// store's key for the principal, a session that writes too.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionMode {
    /// The bare bind as `principal`: the keyless session, which reads alone.
    ///
    /// It is foundations §3.3 state 3's session: every write under it is
    /// refused `write_in_bare_session` before any dial.
    Bare {
        /// The principal the run's sessions and ceremonial rows act as.
        ///
        /// They act as it where a call names none, save `claim`, which leaves
        /// the default to its walk.
        principal: u64,
    },
    /// The signed content-scoped handshake as `principal`, which writes.
    ///
    /// It opens under the key the store holds for the principal.
    Signed {
        /// The principal the run's sessions and ceremonial rows act as.
        ///
        /// They act as it where a call names none, save `claim`, which leaves
        /// the default to its walk.
        principal: u64,
    },
}

impl SessionMode {
    /// Returns the principal the mode names.
    pub fn principal(self) -> u64 {
        match self {
            SessionMode::Bare { principal } | SessionMode::Signed { principal } => principal,
        }
    }

    /// Returns the mode's name.
    pub fn name(self) -> &'static str {
        match self {
            SessionMode::Bare { .. } => "bare",
            SessionMode::Signed { .. } => "signed",
        }
    }
}

/// Who answers the secret and consent moments of a walk (`client.md` §4b.3).
///
/// It is the dev arm a run names — the auto-answer, the default, or a
/// script's answers — or no one, every such moment refused.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ArmConfig {
    /// The auto arm, which answers like a developer on a throwaway board.
    ///
    /// Each moment is answered that way, and the anchor files are placed
    /// beside the store.
    #[default]
    Auto,
    /// A script's answers, one per moment in order (`script`'s grammar).
    Script(Vec<script::Answer>),
    /// No person is present: an agent's client, or any unattended one.
    ///
    /// Every secret and consent moment is refused `person_required`, answered
    /// by no arm and sent to no page, and the walk is abandoned there; public
    /// moments still cross to the page as `moment` events, and a native
    /// statement is said on `Talk` as the arm would say it.
    Refuse,
}

/// What a shell is opened over.
///
/// It holds [`ShellOptions::new`]'s four, and the two a run may set beside
/// them. Its `Debug` leaves out the `Talk` sink, a closure.
#[derive(Clone)]
#[non_exhaustive]
pub struct ShellOptions {
    /// The boards, each a canonical origin dialed and signed at itself.
    ///
    /// They are distinct ([`Shell::open`]'s precondition).
    pub boards: Vec<Origin>,
    /// The dev key store, a throwaway directory and never `~/.skep`.
    ///
    /// At this pin it is also the data directory the index and the held
    /// store sit under (`client.md` §3c.1, §4e.4's drift).
    pub store_dir: PathBuf,
    /// The session mode every `session` call opens under.
    pub session_mode: SessionMode,
    /// Who answers the secret and consent moments: the auto arm unless set.
    pub arm: ArmConfig,
    /// Where the talk lines go.
    pub talk: Talk,
    /// The board that is the shell's own node, where the verb runs one.
    ///
    /// It is `probe()`'s subject, and one of `boards` ([`Shell::open`]'s
    /// precondition).
    pub own_node: Option<Origin>,
}

impl ShellOptions {
    /// Returns options for a shell over `boards`, its key store at `store_dir`.
    ///
    /// Its sessions open in `session_mode` and its talk lines go to `talk`;
    /// the dev arm answers itself, and no own node is set.
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NodeState {
    /// The node is running.
    Running,
    /// The node is stopped.
    Stopped,
}

/// The write kinds of the wire (`docs/wire.md` §Operations).
///
/// A frame of one of these in the guest form, or under a bare session, is
/// refused by the shell without a dial.
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

/// One call of the bridge, as [`Shell::call`] dispatches it.
///
/// It is a call of §4b.1, the document index's listing `places` (A-255), or
/// the change feed's page `changes`: one arm per call, which the compiler
/// holds exhaustive, and the list a transport admits a call by, [`CALLS`],
/// spelled from `Call::ALL` — so no call is listed that the dispatch does
/// not answer.
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
    Places,
    Held,
    Resolve,
    Changes,
}

impl Call {
    /// Every call, in §4b.1's order.
    ///
    /// `places` stands beside `search`, and the change feed's `changes` last.
    const ALL: [Call; 24] = [
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
        Call::Places,
        Call::Held,
        Call::Resolve,
        Call::Changes,
    ];

    /// Returns the call as the bridge spells it.
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
            Call::Places => "places",
            Call::Held => "held",
            Call::Resolve => "resolve",
            Call::Changes => "changes",
        }
    }

    /// Returns the call the bridge spells `name`.
    fn named(name: &str) -> Option<Call> {
        Call::ALL.into_iter().find(|call| call.as_str() == name)
    }
}

/// The bridge's twenty-four calls, as it spells them, in its order.
///
/// They are §4b.1's twenty-two, the document index's listing, `places`
/// (A-255), and the change feed's page, `changes`: the list a transport
/// admits a call by, every name of it one [`Shell::call`] answers.
pub const CALLS: [&str; Call::ALL.len()] = {
    let mut names = [""; Call::ALL.len()];
    let mut i = 0;
    while i < names.len() {
        names[i] = Call::ALL[i].as_str();
        i += 1;
    }
    names
};

/// A fetched blob: the head of the board's `200` and its body, read to close.
///
/// Every other status is a refusal; its call is logged as the body is
/// dropped.
#[non_exhaustive]
pub struct Fetched {
    /// The head of the board's `200`.
    pub headers: Headers,
    /// The body, read to close.
    pub body: Box<dyn Read + Send>,
}

impl fmt::Debug for Fetched {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fetched({} headers)", self.headers.0.len())
    }
}

/// A fetched body as [`Shell::fetch`] hands it out.
///
/// It is the board's stream, the bytes read through it counted, and the
/// call logged once, as it is dropped — `CallOutcome::Stream`, `bytes_out`
/// the bytes its reader took — so the call is the log's whether its body is
/// read to the end or dropped part-way, a page that hangs up mid-stream
/// among them.
struct LoggedBody {
    body: Box<dyn Read + Send>,
    log: Arc<Log>,
    bytes_in: usize,
    bytes_out: usize,
    started: Instant,
}

impl Read for LoggedBody {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.body.read(buf)?;
        self.bytes_out += n;
        Ok(n)
    }
}

impl Drop for LoggedBody {
    fn drop(&mut self) {
        self.log.call(Call::Fetch.as_str(), self.bytes_in, self.bytes_out, self.started.elapsed(), CallOutcome::Stream);
    }
}

/// The shell.
///
/// Dropping it stops it ([`Shell::shutdown`]): no feed thread, open session
/// or `held/<chain>/` lock of it outlives it, and each board's `/events`
/// reader, asked to stop, ends at its next read.
pub struct Shell {
    boards: Vec<Arc<BoardEntry>>,
    /// Each board's feed handle by the board's reference, fixed at the open.
    ///
    /// A call waiting on one board's feed thread holds nothing another call
    /// needs.
    feeds: Vec<(String, Feed)>,
    /// Each board's two feed threads, taken and stopped at the shell's stop.
    threads: Mutex<Vec<FeedThreads>>,
    sessions: Arc<Sessions>,
    bus: Arc<EventBus>,
    pending: Arc<Pending>,
    /// Who answers the secret and consent moments.
    ///
    /// It is the dev arm, or no one under [`ArmConfig::Refuse`], where the
    /// person refuses each.
    arm: Arc<Answerer>,
    log: Arc<Log>,
    /// The one dialer every board dials through, cloned.
    ///
    /// Every board — the shell's own and a guest form's — dials through it:
    /// one record, one stop (`ShellDialer::stop`, at [`Shell::shutdown`]), so
    /// a feed thread a board holds in a read without end is freed at its next
    /// exchange.
    dialer: ShellDialer,
    store: Arc<FileStore>,
    /// The held-burst holds (§3c).
    ///
    /// They are the one path of every `/op` the `op` row sends under a
    /// session, the queue `held` and `resolve` read and act on, the own
    /// node's stopped state, and the resend the boards' feed threads drive.
    holds: Arc<Holds>,
    session_mode: SessionMode,
    talk: Talk,
    /// The own node's board reference, where the shell runs one.
    own_node_reference: Option<String>,
    host_name: String,
}

impl fmt::Debug for Shell {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Shell({} boards, {} sessions, {})", self.boards.len(), self.sessions.len(), self.session_mode.name())
    }
}

/// Returns a principal argument as a call passes it, where `v` is one.
///
/// A principal is a non-negative integer no greater than 2^53 − 1
/// (AUTH-6.36).
fn principal_arg(v: &Value) -> Option<u64> {
    v.as_u64().filter(|n| *n <= (1u64 << 53) - 1)
}

/// Reads an optional argument as its row declares it (`shapes`' declarations).
///
/// Absent or `null`, it is `None`; present and of the form `read` takes, it
/// is `Some` — asked once, here, and never read as absent.
///
/// # Errors
///
/// Returns `malformed_args` naming `member` where it is present and of no
/// such form.
fn optional<'a, T>(args: &'a Value, member: &str, read: impl FnOnce(&'a Value) -> Option<T>) -> Result<Option<T>, Refusal> {
    match args.get(member) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => read(v).map(Some).ok_or_else(|| Refusal::malformed(member)),
    }
}

/// Returns whether the form a call names is the guest form.
///
/// The forms are §4b.1's (its `op`, `fetch` and `search` rows): the guest
/// form — `guest: true`, no `session` — or the session form — a `session`,
/// no `guest: true`.
///
/// # Errors
///
/// Returns `malformed_args` naming `guest` where it is present and no
/// boolean; any other combination names neither form, and is refused
/// `malformed_args` naming `session`.
fn guest_form(args: &Value) -> Result<bool, Refusal> {
    match (optional(args, "guest", Value::as_bool)?.unwrap_or(false), args.get("session")) {
        (true, None) => Ok(true),
        (false, Some(_)) => Ok(false),
        _ => Err(Refusal::malformed("session")),
    }
}

/// Reads a `search` call's `opts` as declared (`SearchOpts`).
///
/// They are an object where present, each member of its form, and where
/// absent the defaults: the bound limit, no offset, no reindex. A `limit` or
/// an `offset` past `usize` saturates — every hit, or past every hit, what
/// it means wherever `usize` holds it — and never wraps to a smaller bound.
///
/// # Errors
///
/// Returns `malformed_args` naming `opts` where it is present and no object,
/// then naming `opts.<member>` where a member is not of its form — `limit`,
/// then `offset`, then `reindex`.
fn search_opts(args: &Value) -> Result<BridgeSearchOpts, Refusal> {
    optional(args, "opts", |v| v.is_object().then_some(()))?;
    let opts = &args["opts"];
    let in_opts = |member: &'static str| move |_: Refusal| Refusal::malformed(format!("opts.{member}"));
    let limit = optional(opts, "limit", Value::as_u64).map_err(in_opts("limit"))?;
    let offset = optional(opts, "offset", Value::as_u64).map_err(in_opts("offset"))?;
    let reindex = optional(opts, "reindex", Value::as_bool).map_err(in_opts("reindex"))?;
    let saturate = |n: u64| usize::try_from(n).unwrap_or(usize::MAX);
    let defaults = SearchOpts::default();
    let bounds = SearchOpts { limit: limit.map_or(defaults.limit, saturate), offset: offset.map_or(defaults.offset, saturate) };
    Ok(BridgeSearchOpts { bounds, reindex: reindex.unwrap_or(false) })
}

/// Returns a `places` call's prefix, its `opts.under`, where it names one.
///
/// The prefix is an address in its one spelling (`is_address_text`), within
/// the component budget (`wire::bounded_address`); absent, the call lists
/// the whole index.
///
/// # Errors
///
/// In this order: `malformed_args` naming `opts` where it is present and no
/// object, then naming `opts.under` where that is present and no such
/// address.
fn places_under(args: &Value) -> Result<Option<Address>, Refusal> {
    optional(args, "opts", |v| v.is_object().then_some(()))?;
    let address = |v: &Value| v.as_str().filter(|text| is_address_text(text)).and_then(bounded_address);
    optional(&args["opts"], "under", address).map_err(|_| Refusal::malformed("opts.under"))
}

/// Where a guest form reads (§4b.1).
///
/// It is one of this shell's boards, or a canonical origin its list holds no
/// board at — a followed link's.
#[derive(Debug)]
enum GuestTarget {
    Board(Arc<BoardEntry>),
    Origin(Origin),
}

/// Returns today's date, read when a walk runs.
///
/// The anchor boxes' default is derived per run (§4.2 step 2), the label it
/// fills is permanent (AUTH-5.42), and a desktop shell runs for days.
fn today() -> String {
    civil_date(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0))
}

/// Returns `yyyy-mm-dd` from unix seconds (civil-from-days).
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

/// Returns the machine's host name for the anchor boxes' default.
///
/// It is `HOSTNAME`, `COMPUTERNAME`, else `dev-machine`; its first label,
/// lowercased.
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
    /// Opens the shell: one entry per board, the feed threads started.
    ///
    /// The store is opened (nothing written until a key is made); nothing is
    /// dialed here, so nothing refuses — under the signed mode the key is
    /// checked at the first `session`, or before serving by
    /// [`Shell::check_signed_key`].
    ///
    /// # Panics
    ///
    /// Panics where the caller's precondition is broken, naming the one
    /// broken, before anything starts: `opts.boards` are distinct — one board
    /// twice would be two feeds and two held stores over one chain, the
    /// second another window's — and `opts.own_node`, where set, is one of
    /// them.
    pub fn open(opts: ShellOptions) -> Shell {
        assert!(opts.boards.iter().enumerate().all(|(i, origin)| !opts.boards[..i].contains(origin)), "ShellOptions' precondition: the boards are distinct");
        assert!(opts.own_node.as_ref().is_none_or(|own| opts.boards.contains(own)), "ShellOptions' precondition: own_node, where set, is one of the boards");
        let log = Arc::new(Log::new());
        let dialer = ShellDialer::new(Arc::clone(&log));
        let bus = Arc::new(EventBus::new());
        let store = Arc::new(FileStore::open(&opts.store_dir));
        // The store the restart arm re-opens a session under: the signed
        // mode's, none under the bare mode (a bare session is never
        // re-opened silently).
        let reopen_store = matches!(opts.session_mode, SessionMode::Signed { .. }).then(|| Arc::clone(&store));
        let sessions = Arc::new(Sessions::new(reopen_store, Arc::clone(&opts.talk)));
        let arm = Arc::new(match opts.arm {
            // The auto arm places each anchor beside the store, never under it
            // (§3.4 refuses a destination under the store): `<store>-anchors/`.
            ArmConfig::Auto => {
                let mut anchors = opts.store_dir.as_os_str().to_owned();
                anchors.push("-anchors");
                Answerer::Arm(DevArm::auto(PathBuf::from(anchors), Arc::clone(&opts.talk)))
            }
            ArmConfig::Script(answers) => Answerer::Arm(DevArm::script(answers, Arc::clone(&opts.talk))),
            // No arm: the person refuses every secret and consent moment.
            ArmConfig::Refuse => Answerer::Refuse(Arc::clone(&opts.talk)),
        });
        let mut boards = Vec::new();
        let mut own_node_reference = None;
        for origin in &opts.boards {
            let entry = Arc::new(BoardEntry::new(Board::new(origin.clone(), dialer.clone())));
            if opts.own_node.as_ref() == Some(origin) {
                own_node_reference = Some(entry.reference.clone());
            }
            boards.push(entry);
        }
        let holds = Holds::new(Arc::clone(&sessions), Arc::clone(&bus), Arc::clone(&store), opts.store_dir.clone(), Arc::clone(&opts.talk), boards.iter().cloned());
        let shared = Shared { bus: Arc::clone(&bus), sessions: Arc::clone(&sessions), data_dir: opts.store_dir.clone(), talk: Arc::clone(&opts.talk), holds: Arc::clone(&holds) };
        let threads: Vec<FeedThreads> = boards.iter().map(|entry| FeedThreads::spawn(Arc::clone(entry), shared.clone())).collect();
        let feeds = boards.iter().zip(&threads).map(|(entry, board_threads)| (entry.reference.clone(), board_threads.feed())).collect();
        Shell {
            boards,
            feeds,
            threads: Mutex::new(threads),
            sessions,
            bus,
            pending: Arc::new(Pending::new()),
            arm,
            log,
            dialer,
            store,
            holds,
            session_mode: opts.session_mode,
            talk: opts.talk,
            own_node_reference,
            host_name: host_name(),
        }
    }

    /// Returns the bus, for a transport's event stream.
    pub fn bus(&self) -> &EventBus {
        &self.bus
    }

    /// Returns one more subscriber to the event stream.
    pub fn subscribe(&self) -> Receiver<Event> {
        self.bus.subscribe()
    }

    /// Returns the log, for `GET /bridge/log`.
    pub fn log(&self) -> &Log {
        &self.log
    }

    /// Returns whether the dev arm is a script.
    ///
    /// It is false where the run holds no arm.
    pub fn arm_is_script(&self) -> bool {
        matches!(&*self.arm, Answerer::Arm(arm) if arm.is_script())
    }

    /// Returns the board references issued, in the list's order.
    pub fn board_references(&self) -> Vec<String> {
        self.boards.iter().map(|entry| entry.reference.clone()).collect()
    }

    /// Sets the own node's state as the verb that owns it reports it.
    ///
    /// It is what `probe` answers for that node, announced on the `daemon`
    /// event at its board (`client.md` §4b.2: "the shell owns the child
    /// process"); a shell that runs no node has none to report. A deliberate
    /// stop is said here once: while it stands the board's feed announces no
    /// `unreachable` of its own, and `Running` here is the one `running`
    /// (`feed.rs`'s `unreachable`). `Running` ends the hold at the node's
    /// board and hands the board's feed thread its probe, as `resolve(send)`
    /// hands it: the caller waits on no dial.
    pub fn set_node_state(&self, state: NodeState) {
        let Some(board_reference) = &self.own_node_reference else { return };
        let running = matches!(state, NodeState::Running);
        let state = match state {
            NodeState::Running => "running",
            NodeState::Stopped => "stopped",
        };
        self.bus.emit(EventName::Daemon, json!({"board": board_reference, "state": state}));
        // The own node's stopped state is the hold's (§3c.4): every burst at
        // its board holds `stopped` without a dial, `probe` answers it, and
        // `Running` ends the hold, the resend run on the board's feed thread
        // where a session that may write stands.
        self.holds.set_node_stopped(board_reference, !running);
        if running {
            self.feed(board_reference).probe();
        }
    }

    /// Returns the signed mode's key at every board: the check before serving.
    ///
    /// It is the store's key for the principal at every board, its public
    /// facts. Under the bare mode it is `Ok` with no key: its sessions sign
    /// nothing.
    ///
    /// # Errors
    ///
    /// Returns `no_key` where the store is keyless for one, and
    /// `store_unreadable` where the store cannot be read.
    pub fn check_signed_key(&self) -> Result<Vec<KeyFacts>, Refusal> {
        let SessionMode::Signed { principal } = self.session_mode else { return Ok(Vec::new()) };
        let mut keys = Vec::new();
        for entry in &self.boards {
            let mode = || entry.board.health().map(|h| Mode::of(&h)).unwrap_or(Mode::Unclaimed);
            keys.push(sessions::signing_key(&self.store, entry.board.dialed(), principal, mode)?);
        }
        Ok(keys)
    }

    fn say(&self, line: impl AsRef<str>) {
        (self.talk)(line.as_ref());
    }

    /// Returns the feed handle of the board `board_reference` names.
    ///
    /// # Panics
    ///
    /// Panics where no board of this shell is under `board_reference`; every
    /// board of this shell has its feed, fixed at the open.
    fn feed(&self, board_reference: &str) -> &Feed {
        self.feeds.iter().find(|(r, _)| r == board_reference).map(|(_, feed)| feed).expect("every board of this shell has its feed, fixed at the open")
    }

    /// Returns the entry of the board a reference names.
    ///
    /// # Errors
    ///
    /// Returns `malformed_args` naming `board` where the reference is no
    /// string, and `unknown_board`, the pin's unknown-board refusal, where
    /// this shell issued none.
    fn board_entry(&self, board_reference: &Value) -> Result<Arc<BoardEntry>, Refusal> {
        let Some(board_reference) = board_reference.as_str() else { return Err(Refusal::malformed("board")) };
        self.boards.iter().find(|entry| entry.reference == board_reference).cloned().ok_or_else(|| Refusal::shell(Name::UNKNOWN_BOARD, json!({"board": board_reference})))
    }

    /// Returns the session a reference names.
    ///
    /// # Errors
    ///
    /// Returns `malformed_args` naming `session` where the reference is no
    /// string, and the pin's "session ended", `session_ended`, where this
    /// shell holds no session under it.
    fn session(&self, session_reference: &Value) -> Result<Arc<SessionEntry>, Refusal> {
        let Some(session_reference) = session_reference.as_str() else { return Err(Refusal::malformed("session")) };
        self.sessions.get(session_reference).ok_or_else(|| Refusal::shell(Name::SESSION_ENDED, json!({"session": session_reference})))
    }

    /// Ends `session`, whose token met the death signal at a call.
    ///
    /// The signal was met at one of the shell's calls; the session is ended
    /// by the one sequence the board's feed thread runs too, whichever caller
    /// came first, and the call's refusal, carrying the reason, is returned.
    fn died(&self, session: &SessionEntry) -> Refusal {
        let reason = self.sessions.end(session, &mut self.feed(&session.board_reference), &self.bus);
        Refusal::shell(Name::SESSION_DIED, json!({"session": session.reference, "reason": reason}))
    }

    // ── The calls ────────────────────────────────────────────────────────

    /// Answers one call by name, the log kept.
    ///
    /// The row's method is dispatched on the bridge's spelling, one arm per
    /// call.
    ///
    /// # Errors
    ///
    /// Returns the row's own refusals; `unknown_call` for a name the bridge
    /// does not spell, logged by its length alone; and `streamed_call` for
    /// `fetch`, which streams — a transport serves it on its own route, and a
    /// direct caller takes [`Shell::fetch`].
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
            Some(Call::Places) => self.places(args),
            Some(Call::Held) => self.held(args),
            Some(Call::Resolve) => self.resolve(args),
            Some(Call::Changes) => self.changes(args),
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

    /// Answers `boards()` with `[{board, name, origin}]`.
    ///
    /// `name` is the origin, v1's fallback: every board takes it while no
    /// board publishes a display name.
    fn boards(&self) -> Value {
        Value::Array(self.boards.iter().map(|entry| json!({"board": entry.reference, "name": entry.board.dialed().as_str(), "origin": entry.board.dialed().as_str()})).collect())
    }

    /// Answers `session(board, principal)`: the mode's opening as `principal`.
    ///
    /// It answers `{session, principal, account, writes}`: the reference
    /// issued in the token's place, and `writes` — whether a write may go out
    /// under it ([`SessionEntry::may_write`]): the signed mode's session
    /// writes, the bare mode's keyless one reads alone and has every write
    /// refused `write_in_bare_session`, which the page learns here, before it
    /// offers one.
    ///
    /// # Errors
    ///
    /// In this order: `malformed_args` naming `board`, then `unknown_board`;
    /// `malformed_args` naming `principal` where it is present in another
    /// form; then the mode's opening's refusals (`sessions::open_bare`,
    /// `sessions::open_signed`).
    fn session_call(&self, args: &Value) -> Result<Value, Refusal> {
        let entry = self.board_entry(&args["board"])?;
        let principal = optional(args, "principal", principal_arg)?.unwrap_or(self.session_mode.principal());
        let open = match self.session_mode {
            SessionMode::Bare { .. } => sessions::open_bare(&entry.board, principal)?,
            SessionMode::Signed { .. } => sessions::open_signed(&entry.board, &self.store, principal)?,
        };
        let session = self.sessions.register(&entry, open, &mut self.feed(&entry.reference));
        // The principal's held file read whole at its session's open (§3c.7),
        // so `held(session)` lists its lines at once. The resend is not run
        // here: the page reads `held(session)` right after opening, and a
        // synchronous resend would clear the lines before it; the feed's probe
        // and its daemon-running tick drive it once a session that may write
        // stands (§3c.5).
        self.holds.open_session(&session);
        Ok(json!({"session": session.reference, "principal": principal, "account": session.facts.account, "writes": session.may_write()}))
    }

    /// Answers `close(session)` with `{}`: the session out of the table.
    ///
    /// Then its drafts rows are read to the head under its token and its
    /// supplement released (`Feed::closing`, answered before the token
    /// closes), `POST /session/close` is sent (idempotent at the board), and
    /// its own arm goes out on `session-died`, after every `feed` row of the
    /// session. The close is the shell's act, whatever the board says —
    /// §4b.1's row arms no refusal at the board: a token the board did not
    /// close, or never answered for, is said on `Talk` and dies at the
    /// board's restart.
    ///
    /// # Errors
    ///
    /// Returns `malformed_args` naming `session` where it is no string, and
    /// "session ended", `session_ended`, for a reference this shell holds no
    /// session under — stale, or ended by a death met first.
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

    /// Answers `health(board)` with `{health, mode}`.
    ///
    /// They are the `/health` document verbatim and the derived mode.
    ///
    /// # Errors
    ///
    /// Returns `malformed_args` naming `board`, `unknown_board`, and the
    /// `/health` read's refusal: the board's, or `unreachable`.
    fn health(&self, args: &Value) -> Result<Value, Refusal> {
        let entry = self.board_entry(&args["board"])?;
        let health = entry.board.health()?;
        Ok(json!({"health": health.body, "mode": Mode::of(&health).name()}))
    }

    /// Answers `probe()` with `{daemon, dialed, signed}`.
    ///
    /// It is the own node's state where the shell runs one — `stopped` where
    /// its owner stopped it, `unreachable` where it does not answer, `running`
    /// else — and the first board's reachability where it runs none.
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

    /// Returns the guest form's target (§4b.1's `op` and `search` rows).
    ///
    /// The board a reference names is read first; else the canonical origin
    /// given, parsed by §1.6's grammar, read as this shell's own board where
    /// its list holds one at that origin.
    ///
    /// # Errors
    ///
    /// In this order: `malformed_args` naming `board` where it is present in
    /// another form, then `unknown_board` where this shell issued none; else
    /// `malformed_args` naming `origin` where it is present in another form,
    /// `malformed_args` naming `board or origin` where neither is given, and
    /// `not_canonical` where the origin given is no canonical origin.
    fn guest_target(&self, args: &Value) -> Result<GuestTarget, Refusal> {
        if optional(args, "board", Value::as_str)?.is_some() {
            return Ok(GuestTarget::Board(self.board_entry(&args["board"])?));
        }
        let origin = optional(args, "origin", Value::as_str)?.ok_or_else(|| Refusal::malformed("board or origin"))?;
        let origin = Origin::parse(origin).ok_or_else(|| Refusal::shell(Name::NOT_CANONICAL, json!({"origin": origin})))?;
        Ok(match self.boards.iter().find(|entry| *entry.board.dialed() == origin) {
            Some(entry) => GuestTarget::Board(Arc::clone(entry)),
            None => GuestTarget::Origin(origin),
        })
    }

    /// Returns the board the guest form dials, token-free.
    ///
    /// It is one of this shell's own, or a board at the origin its list holds
    /// none at, dialed through the shell's one dialer.
    ///
    /// # Errors
    ///
    /// Returns the target's refusals ([`Shell::guest_target`]).
    fn guest_board(&self, args: &Value) -> Result<Arc<Board>, Refusal> {
        Ok(match self.guest_target(args)? {
            GuestTarget::Board(entry) => Arc::clone(&entry.board),
            GuestTarget::Origin(origin) => Arc::new(Board::new(origin, self.dialer.clone())),
        })
    }

    /// Returns the frame, and its `at` where the page sent the `/op-at` form.
    ///
    /// # Errors
    ///
    /// Returns `malformed_args` naming `frame` where it is no object.
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

    /// Returns the board's response document as the call's answer, whole.
    ///
    /// # Errors
    ///
    /// Returns a `rejected` document as the board's refusal, verbatim.
    fn document_answer(v: Value) -> Result<Value, Refusal> {
        match Rejection::of(&v) {
            Some(r) => Err(Refusal::from(r.refused(&v))),
            None => Ok(v),
        }
    }

    /// Answers `op(session, frame)` and the guest forms: one frame to a board.
    ///
    /// Under a session the frame goes to the board the session stands at
    /// under its token, by the hold's one path ([`Holds::send`]) — the attest
    /// composed where the session holds a key and the kind has an entry
    /// frame, a burst held where the board cannot take it, a reissue-class
    /// answer reissued within the call, and an ack noted for the hold's
    /// `base` — an `/op-at` frame aside, its answer the board's own; or
    /// token-free at guest class, the board or origin named read first. Under
    /// a bare session — the keyless session, which reads alone (foundations
    /// §3.3 state 3) — a write is refused without a dial, the `/op-at` form's
    /// too ([`SessionEntry::may_write`]). An `/op-at` refusal is the board's
    /// verdict, as every other is; a death signal met at the dial or at a
    /// read the attest needed ends the session.
    ///
    /// # Errors
    ///
    /// In this order: `malformed_args` naming `frame` where it is no object,
    /// then the form's (`guest_form`). In the guest form, the target's
    /// (`unknown_board`, `not_canonical`, `malformed_args`), then a write
    /// refused without a dial (`write_in_guest_form`), then the board's
    /// verdict or `unreachable`. In the session form, `malformed_args` naming
    /// `session`, then `session_ended`; a write under a bare session refused
    /// `write_in_bare_session`; then the hold's answer ([`Holds::send`]), or
    /// for an `/op-at` frame the board's verdict or `unreachable`; and
    /// `session_died` where a death signal met at the dial or at a read the
    /// attest needed ends the session.
    fn op(&self, args: &Value) -> Result<Value, Refusal> {
        let (frame, at) = Self::frame_of(args)?;
        let op = frame["op"].as_str().unwrap_or("");
        if guest_form(args)? {
            let board = self.guest_board(args)?;
            if WRITE_KINDS.contains(&op) {
                return Err(Refusal::shell(Name::WRITE_IN_GUEST_FORM, json!({"op": op})));
            }
            return match at {
                Some(at) => match board.op_at(None, at, &frame)? {
                    AtAnswer::Document(v) => Self::document_answer(v),
                    other => Err(at_refusal(other)),
                },
                None => Self::document_answer(board.guest(&frame)?),
            };
        }
        let session = self.session(&args["session"])?;
        if WRITE_KINDS.contains(&op) && !session.may_write() {
            return Err(Refusal::shell(Name::WRITE_IN_BARE_SESSION, json!({"op": op})));
        }
        let Some(at) = at else {
            return match self.holds.send(&session, frame) {
                OpAnswer::Answered(answer) => answer,
                OpAnswer::Died => Err(self.died(&session)),
            };
        };
        match session.board.op_at(Some(&session.token), at, &frame)? {
            AtAnswer::Document(v) => Self::document_answer(v),
            AtAnswer::Closed => Err(self.died(&session)),
            other => Err(at_refusal(other)),
        }
    }

    /// Answers `upload(session, target)`: not reached at this pin.
    ///
    /// `skep-client` holds no media module for `media.md`'s walk (the PUT and
    /// its resume, the create, the cell's insert, the typing link); the
    /// provider would take a path.
    ///
    /// # Errors
    ///
    /// Returns `malformed_args` naming `session`, or `session_ended`, where
    /// the session does not stand, and `not_reached` where it does.
    fn upload(&self, args: &Value) -> Result<Value, Refusal> {
        self.session(&args["session"])?;
        Err(Refusal::shell(Name::NOT_REACHED, json!({"call": "upload", "detail": "the media walk — the PUT and its resume, the create, the cell's insert, the typing link — is not in skep-client at this pin; the provider would take a path in `args`"})))
    }

    /// Answers `restore(session, i)`: not reached at this pin, as `upload`.
    ///
    /// # Errors
    ///
    /// Returns `malformed_args` naming `session`, or `session_ended`, where
    /// the session does not stand, and `not_reached` where it does.
    fn restore(&self, args: &Value) -> Result<Value, Refusal> {
        self.session(&args["session"])?;
        Err(Refusal::shell(Name::NOT_REACHED, json!({"call": "restore", "detail": "the repair is a plain upload matched by hash (media.md), and the media walk is not in skep-client at this pin"})))
    }

    /// Answers `fetch(session, i)` and its guest forms: a `/blob` read.
    ///
    /// It is `GET /blob?i=<address>` on the dialer's streamed form, the bytes
    /// streamed back as the daemon checked them against the cell before its
    /// first byte — the client side of `media.md` §Recovery (the length held,
    /// the re-hash) is not run here. A non-200 is the board's refusal; the
    /// death signal on the head ends the session. It is logged as `call` logs
    /// every row — a refusal at once, a stream as its body is dropped,
    /// `bytes_out` the bytes read from it — so a transport serves the bytes
    /// and logs nothing; it reads the body to its end or drops it.
    ///
    /// # Errors
    ///
    /// In this order: `malformed_args` naming `i` where it is no address in
    /// its one spelling; the form's; in the guest form the target's
    /// (`unknown_board`, `not_canonical`, `malformed_args`), in the session
    /// form `malformed_args` naming `session`, then `session_ended`;
    /// `unreachable` where the dial fails; `session_died` where the head
    /// carries the death signal; and the board's refusal for a non-200.
    pub fn fetch(&self, args: &Value) -> Result<Fetched, Refusal> {
        let started = Instant::now();
        let bytes_in = json_len(args);
        match self.fetch_row(args) {
            Ok(Fetched { headers, body }) => Ok(Fetched { headers, body: Box::new(LoggedBody { body, log: Arc::clone(&self.log), bytes_in, bytes_out: 0, started }) }),
            Err(refusal) => {
                self.log.call(Call::Fetch.as_str(), bytes_in, json_len(&refusal.to_value()), started.elapsed(), CallOutcome::Refused);
                Err(refusal)
            }
        }
    }

    /// Does the `fetch` row's own work, unlogged.
    ///
    /// It is [`Shell::fetch`]'s answer before its call is logged.
    ///
    /// # Errors
    ///
    /// Returns the refusals [`Shell::fetch`] names.
    fn fetch_row(&self, args: &Value) -> Result<Fetched, Refusal> {
        let i = args["i"].as_str().ok_or_else(|| Refusal::malformed("i"))?;
        if !is_address_text(i) {
            return Err(Refusal::malformed("i"));
        }
        let (board, session) = if guest_form(args)? {
            (self.guest_board(args)?, None)
        } else {
            let session = self.session(&args["session"])?;
            (Arc::clone(&session.board), Some(session))
        };
        let headers = session.iter().map(|s| ("Skepd-Session".to_string(), s.token.as_str().to_string())).collect();
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

    /// Answers a `search` call off the board's consumer.
    ///
    /// `search(session|guest, board, query, opts)` → `{hits, places, state,
    /// …}` (`SearchAnswer`): the session form at the session's own board — a
    /// `board` given beside it naming that board, else `malformed_args` — and
    /// the guest form at the board its reference or its canonical origin
    /// names ([`Shell::guest_target`]), an origin this shell holds no board at
    /// answered with no index (`state: none`).
    ///
    /// # Errors
    ///
    /// Its refusals come in this order, the first that holds answering:
    /// `malformed_args` naming `query`; `query_too_long`, the shell's own
    /// bound on the call's text (§4b.1's `search` row: "length-bounded …
    /// then parsed"), asked before any other member is read and before any
    /// index is asked, at every target; `malformed_args` naming `opts` or one
    /// of its members; then the form's and the target's; then `feed_stopped`
    /// once the board's feed thread has stopped, and the search's own.
    fn search(&self, args: &Value) -> Result<Value, Refusal> {
        let query = args["query"].as_str().ok_or_else(|| Refusal::malformed("query"))?;
        if query.len() > QUERY_BOUND {
            return Err(query_too_long(QueryTooLong { bound: QUERY_BOUND, length: query.len() }));
        }
        let opts = search_opts(args)?;
        match self.index_reader(args)? {
            Some((feed, who)) => feed.search(who, query, opts),
            None => Ok(answer_without_index()),
        }
    }

    /// Lists the board's document index: `places(session|guest, board, opts)`.
    ///
    /// It answers `{docs, counts, state}` off the board's consumer: the
    /// document index read whole at the call's class (A-255; foundations §2),
    /// as `search` draws its `places` — the session form at the session's own
    /// board, the guest form at the board its reference or its canonical
    /// origin names, an origin this shell holds no board at answered with no
    /// index (`state: none`). `opts.under`, where given, narrows the
    /// documents and their counts to that prefix.
    ///
    /// # Errors
    ///
    /// In this order: `malformed_args` naming `opts`, then `opts.under`; the
    /// form's and the target's, as `search` meets them; `feed_stopped` once
    /// the board's feed thread has stopped.
    fn places(&self, args: &Value) -> Result<Value, Refusal> {
        let under = places_under(args)?;
        match self.index_reader(args)? {
            Some((feed, who)) => feed.places(who, under),
            None => Ok(places_without_index()),
        }
    }

    /// Returns the feed of the board whose index a call reads, and who reads.
    ///
    /// The session form reads at the session's own board, the guest form at
    /// the board its reference or its canonical origin names
    /// ([`Shell::guest_target`]); `None` for an origin this shell holds no
    /// board at — a followed link's — whose index it does not hold.
    ///
    /// # Errors
    ///
    /// In this order: the form's (`guest_form`); for the guest form, the
    /// target's (`guest_target`); for the session form, `malformed_args`
    /// naming `session` where it is no string, then `session_ended`, then
    /// `malformed_args` naming `board` where one given beside the session is
    /// no string or names another board.
    fn index_reader(&self, args: &Value) -> Result<Option<(&Feed, Searcher)>, Refusal> {
        if guest_form(args)? {
            return Ok(match self.guest_target(args)? {
                GuestTarget::Board(entry) => Some((self.feed(&entry.reference), Searcher::Guest)),
                GuestTarget::Origin(_) => None,
            });
        }
        let session = self.session(&args["session"])?;
        if optional(args, "board", Value::as_str)?.is_some_and(|board| board != session.board_reference) {
            return Err(Refusal::malformed("board"));
        }
        Ok(Some((self.feed(&session.board_reference), Searcher::Session(session))))
    }

    /// Answers `held(session)` with the acting principal's held bursts.
    ///
    /// They are the bursts at the session's board in resend order (§4b.1),
    /// from this principal's file and no other (P39).
    ///
    /// # Errors
    ///
    /// Returns `malformed_args` naming `session`, then `session_ended`; and
    /// `store_halted` where P38 halted the file, naming its `path` and its
    /// `why`: `newer` (a newer `v`), `unknown_member` (an unknown header
    /// member, or a header off its spelling) or `damaged` (a line not read
    /// whole, the header's or a body line's).
    fn held(&self, args: &Value) -> Result<Value, Refusal> {
        let session = self.session(&args["session"])?;
        self.holds.lines(&session)
    }

    /// Answers `resolve(session, {held, act})` with `{}` (§4b.1).
    ///
    /// `"drop"` on a `refused` or `moved` line marks it, and every line held
    /// after it on that document — a refused run's `behind` lines, a moved
    /// document's later lines — dropped. `"send"` re-enters the automatic
    /// machine for that document, the call answering "once the line is
    /// handed to the machine, never after its ack": the probe that resends
    /// it is handed to the board's feed thread (`Feed::probe`). Under a bare
    /// session, which reads alone ([`SessionEntry::may_write`]), `"drop"`
    /// stands, since it commits nothing to the board, and `"send"` does not,
    /// since no resend sends under it.
    ///
    /// # Errors
    ///
    /// In this order, the first that holds answering:
    ///
    /// 1. `malformed_args` naming `session`, then `session_ended` where this
    ///    shell holds no session under the reference;
    /// 2. `malformed_args` naming `held`, then `act` — an act the row does
    ///    not spell (`ResolveAct::named`) is the argument it is, refused
    ///    before any line is asked;
    /// 3. `write_in_bare_session` for `"send"` under a bare session;
    /// 4. `store_halted`, `no_such_held` and `not_resolvable`, as
    ///    `Holds::resolve` orders them.
    fn resolve(&self, args: &Value) -> Result<Value, Refusal> {
        let session = self.session(&args["session"])?;
        let k = args["held"].as_u64().ok_or_else(|| Refusal::malformed("held"))?;
        let act = args["act"].as_str().and_then(ResolveAct::named).ok_or_else(|| Refusal::malformed("act"))?;
        if act == ResolveAct::Send && !session.may_write() {
            return Err(Refusal::shell(Name::WRITE_IN_BARE_SESSION, json!({"act": "send"})));
        }
        match self.holds.resolve(&session, k, act)? {
            Resolved::Dropped => {}
            Resolved::HandedBack => self.feed(&session.board_reference).probe(),
        }
        Ok(json!({}))
    }

    /// Answers `changes(session, since, limit?)` with `{entries, next, head}`.
    ///
    /// It is the board's change feed from the position `since`, read at the
    /// session's class — the published feed token-free, the drafts
    /// supplement under its token (`feed::changes_since`) — what a client
    /// that comes back to a board missed: each entry in the `feed`
    /// event's update shape, `published` or `drafts` by the read that
    /// answered it, oldest first, bounded by `limit` and the wire's page
    /// budget; `next` the position to ask from next time, past every entry
    /// answered and never past one withheld; `head` the board's latest
    /// position, its own `/health` read, taken before the page. A draft the
    /// session may not read never appears: the gating is the board's, at the
    /// token's class. The read is one call's, on the caller's thread: the
    /// board's feed thread keeps its own cursors and is not asked.
    ///
    /// # Errors
    ///
    /// In this order: `malformed_args` naming `since` where it is no
    /// non-negative integer, then `limit` where one is given in another
    /// form; `malformed_args` naming `session`, then `session_ended`; the
    /// board's own — `history_reclaimed` with its floor where `since` lies
    /// below the feed's memory, `malformed_changes` for a `limit` off the
    /// route's range, `feed_rebuilding` — and `unreachable`; `session_died`
    /// where the read met the death signal, the session ended by the one
    /// sequence.
    fn changes(&self, args: &Value) -> Result<Value, Refusal> {
        let since = args["since"].as_u64().ok_or_else(|| Refusal::malformed("since"))?;
        let limit = optional(args, "limit", Value::as_u64)?;
        let session = self.session(&args["session"])?;
        match changes_since(&session, since, limit)? {
            ChangesRead::Page(page) => Ok(json!({"entries": page.entries, "next": page.next, "head": page.head})),
            ChangesRead::Died => Err(self.died(&session)),
        }
    }

    // ── The two answers ──────────────────────────────────────────────────

    /// Handles `answer(id, value)`: `value` handed to the walk that asked.
    ///
    /// The value is of the form its moment's kind takes (`MomentEvent.kind`).
    ///
    /// # Errors
    ///
    /// Returns `malformed_args` naming `value` where it is of another form,
    /// the moment still waiting; `no_such_moment` where no moment of that id
    /// waits.
    pub fn answer(&self, id: &str, value: Value) -> Result<(), Refusal> {
        self.pending.answer(id, value)
    }

    /// Handles `cancel(id)`: the walk that asked abandoned at that moment.
    ///
    /// # Errors
    ///
    /// Returns `no_such_moment` where no moment of that id waits.
    pub fn cancel(&self, id: &str) -> Result<(), Refusal> {
        self.pending.cancel(id)
    }

    // ── The stop ─────────────────────────────────────────────────────────

    /// Runs the clean stop.
    ///
    /// Every pending moment is cancelled and the moment table closed, so a
    /// walk that asks the page after the stop is abandoned at once; every
    /// session is out of the table and its close sent to its board — a board
    /// that does not answer keeps the token until its restart, said on `Talk`
    /// as `close` says it; the shell's dialer is stopped; every board's feed
    /// threads are stopped — each `/events` reader asked to stop, ending at
    /// its next read, each consumer saved and closed, each feed thread
    /// joined, so the `held/<chain>/` locks its holds kept are free once this
    /// returns. The dialer stops after the sessions' closes, which dial, and
    /// before the threads are asked to stop: from then on every dial is
    /// refused as one that made no connection (`ShellDialer::stop`), so a
    /// feed thread a board holds in a read without end — pages whose `more`
    /// never ends — is freed at its next exchange, and the stop waits on no
    /// board past one exchange's bound. A second stop finds nothing left to
    /// stop, and dropping the shell runs it. Nothing of the held-burst store
    /// is written here — every held line is already synced at its `op`
    /// (persist-first, §3c.6's step 3).
    ///
    /// **Unverified here** (the record §7 item 1): that the desktop
    /// framework's close hook runs this, and that the page's last `op`
    /// reaches the shell before the webview is destroyed, is the framework's
    /// to prove — no Tauri source is on this machine; a crash loses at most
    /// the open or in-flight burst (R14).
    ///
    /// # Panics
    ///
    /// Panics where the feed threads' lock is poisoned.
    pub fn shutdown(&self) {
        self.pending.cancel_all();
        for session in self.sessions.all() {
            if self.sessions.close(&session.reference).is_some() {
                if let Err(h) = session.board.session_close(&session.token) {
                    self.say(format!("stop: the board did not close {}'s token ({h}); it dies at the board's restart", session.reference));
                }
            }
        }
        self.dialer.stop();
        let threads = std::mem::take(&mut *self.threads.lock().expect("the feed threads' lock"));
        for board_threads in threads {
            board_threads.stop();
        }
    }
}

impl Drop for Shell {
    /// Runs the clean stop where its owner made none ([`Shell::shutdown`]).
    ///
    /// No feed thread, open session or `held/<chain>/` lock of the shell
    /// outlives it, and each board's `/events` reader, asked to stop, ends at
    /// its next read.
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Returns an `/op-at` refusal as the board's verdict.
///
/// It is the status and the error document the wire answers it with
/// (wire.md §Reading history), rebuilt from the variant `skep-client` read
/// them into — a member the variant holds rides the body, as "when known"
/// has it. The document and the death signal are the caller's to read
/// before this; an answer of any other kind halts naming it.
fn at_refusal(a: AtAnswer) -> Refusal {
    let error_document = |error: &str, member: &str, known: Option<u64>| {
        let mut body = json!({"error": error});
        if let Some(n) = known {
            body[member] = Value::from(n);
        }
        body
    };
    let (status, body) = match a {
        AtAnswer::HistoryReclaimed { floor } => (410, error_document("history_reclaimed", "floor", floor)),
        AtAnswer::BeyondHead { head } => (400, error_document("beyond_head", "head", head)),
        AtAnswer::NotAPosition { nearest } => (400, error_document("not_a_position", "nearest", nearest)),
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
