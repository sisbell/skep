//! [`Shell`] — THE CORE (the dev provider record §2.2 (B)): the boards the
//! shell is opened over, each dialed through the one logging dialer and
//! named to the page by an opaque reference; the sessions it holds, each
//! named by a reference in the token's place (t5: "the page never holds a
//! token"); the SESSION MODE the shell was started in — BARE as the
//! claimant on the permissive board, or SIGNED content-scoped with a dev
//! key in the store (both ruled selectable per run); and ONE METHOD PER
//! ROW of `client.md` §4b.1, each taking the row's input as a value and
//! answering the row's output or a [`Refusal`] under the row's armed name,
//! the board's own refusals carried verbatim. The row methods are private
//! behind ONE DOOR, [`Shell::call`], which dispatches on the bridge's
//! spelling and logs every call, so no call reaches a row past the log;
//! [`Shell::fetch`] alone is public beside it, because it streams and its
//! transport logs it. A ceremonial row runs the library's walk over the
//! person of `person` — its PUBLIC moments the page's, its SECRET and
//! CONSENT ones the dev arm's — and answers when the walk ends; a
//! transport runs each call on the connection's thread. The page's two
//! answers, [`Shell::answer`] and [`Shell::cancel`], route to the walk
//! that asked. A death signal a call meets ends the session by the one
//! sequence the board's feed thread runs too (`Sessions::end`), and the
//! call answers `session_died` with the arm that sequence derived.
//!
//! WHAT THE SHELL REFUSES WITHOUT ASKING (ps3-5): a WRITE frame in the
//! guest form (the board would answer `unauthenticated`; no dial is made),
//! and nothing else of a frame — `op` is a frame pipe, the frame's
//! semantics the wire's; a credential act from the page is refused by the
//! daemon's own `content_session` beneath the shell (ps3-7). What it
//! SIGNS: under the signed mode, every write of the ten kinds that have an
//! entry frame, the attest composed by `attest` from the shell's own reads
//! and never from a preimage the page supplies. Where the library does not
//! reach a row at this pin — `upload` and `restore`, whose media walk is
//! the shell's lane's and not in `skep-client` — the call answers
//! `not_reached` naming where it stops, never a silent stub; `fetch`
//! reaches the dialer's streamed form and no further (the §Recovery order
//! of the media design is not run here).

use std::io::Read;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde_json::{json, Map, Value};
use skep_client::address::is_address_text;
use skep_client::board::{Answer, AtAnswer, Board, Rejection, Scope};
use skep_client::ceremony::claim::{self, ClaimOutcome, NotebookOptions};
use skep_client::ceremony::first_session::{first_session, FirstSessionReads};
use skep_client::ceremony::handshake::{handshake, key_face, Site};
use skep_client::ceremony::{accept, enroll, handoff, recover, retire, rotate};
use skep_client::derive::{origin_arm, principal_of, walk_to_set, KeyDiagnosis, Mode};
use skep_client::dial::{Headers, Method, RequestHead};
use skep_client::halt::Halt;
use skep_client::person::{LabelBox, Person, Public};
use skep_client::search::SearchOpts;
use skep_client::sheet::{render_inert, Label};
use skep_client::store::{Binding, FileStore, KeyFacts, KeySelector, KeyStore, Purpose, StoreError};
use skep_client::Origin;
use skep_identity::{encode_enroll, Enrollment};

use crate::attest::{in_checked_set, Composer};
use crate::dev_arm::DevArm;
use crate::events::{Event, EventBus, SESSION_DIED};
use crate::feed::{BoardEntry, Feed, Searcher};
use crate::log::{Log, LoggingDialer};
use crate::person::{BridgePerson, Pending};
use crate::refs::board_name;
use crate::refusal::{Name, Refusal};
use crate::script;
use crate::sessions::{self, Kind, SessionEntry, Sessions, Supplements};
use crate::Talk;

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

/// The dev arm a run names: the auto-answer, or a script's answers.
#[derive(Debug, Clone)]
pub enum ArmConfig {
    Auto,
    Script(Vec<script::Answer>),
}

/// What a shell is opened over.
#[derive(Clone)]
pub struct ShellOptions {
    /// The boards, each a canonical origin dialed and signed at itself.
    pub boards: Vec<Origin>,
    /// The dev key store — a throwaway directory, never `~/.skep`.
    pub store_dir: PathBuf,
    pub mode: SessionMode,
    pub arm: ArmConfig,
    /// Where the TALK lines go.
    pub talk: Talk,
    /// The board that is the shell's OWN node, where the verb runs one:
    /// `probe()`'s subject.
    pub own_node: Option<Origin>,
}

/// The own node's state as the verb that owns it reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeState {
    Running,
    Stopped,
}

/// The write kinds of the wire (`docs/wire.md` §Operations): a frame of
/// one of these in the guest form is refused by the shell without a dial.
pub const WRITE_OPS: [&str; 17] = [
    "delegate",
    "register_node",
    "create_home",
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

/// The twenty calls of §4b.1, as the bridge spells them.
pub const CALLS: [&str; 20] = [
    "boards", "session", "close", "keygen", "fingerprint", "claim", "enroll", "bind", "recover", "rotate", "retire", "handoff", "accept",
    "health", "probe", "op", "upload", "fetch", "restore", "search",
];

/// AUTH-5.42's statements at the device-name box, the notebook's venue.
fn device_box_statements() -> Vec<String> {
    vec![
        "This name is permanent and cannot be edited: fixing a typo costs a keypair.".to_string(),
        "It is a byline: this name appears beside every write you make with this key, forever.".to_string(),
        "It holds the DEVICE's name — never your own and never your organisation's; a display name is a separate, changeable label.".to_string(),
        "at this notebook it is readable by anything on the machine".to_string(),
    ]
}

/// The outstanding act of a key enrolled nowhere (AUTH-5.32), the line
/// `keygen` answers and `fingerprint` carries beside every UNBOUND key.
pub const OUTSTANDING_ACT: &str = "Where it ADDS a device: take this payload to a device already signed in, run `enroll` there, and bring its three facts back to `bind` here. Where it REPLACES a machine: `rotate` with the payload there instead, then `bind` here.";

/// A fetched blob: the streamed answer's head and its body, read to close.
pub struct Fetched {
    pub status: u16,
    pub headers: Headers,
    pub body: Box<dyn Read + Send>,
}

/// THE SHELL.
pub struct Shell {
    boards: Vec<Arc<BoardEntry>>,
    feeds: Mutex<Vec<(String, Option<Feed>)>>,
    sessions: Arc<Sessions>,
    bus: Arc<EventBus>,
    pending: Arc<Pending>,
    arm: Arc<DevArm>,
    log: Arc<Log>,
    store: Arc<FileStore>,
    /// The store the restart arm re-opens a session under: the signed
    /// mode's, none under the bare mode (a bare session is never re-opened
    /// silently).
    reopen_store: Option<Arc<FileStore>>,
    anchors: PathBuf,
    mode: SessionMode,
    talk: Talk,
    own_node: Option<String>,
    node_state: AtomicU8,
    host_name: String,
    date: String,
}

impl std::fmt::Debug for Shell {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Shell({} boards, {} sessions, {})", self.boards.len(), self.sessions.len(), self.mode.name())
    }
}

/// A principal from a value: a non-negative integer no greater than
/// 2^53 − 1 (AUTH-6.36).
fn principal_of_value(v: &Value) -> Option<u64> {
    v.as_u64().filter(|n| *n <= (1u64 << 53) - 1)
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

/// The three facts as the bridge spells them.
fn facts_json(f: &skep_client::sheet::Facts) -> Value {
    json!({"principal": f.principal, "account": f.account, "origin": f.origin.as_str()})
}

impl Shell {
    /// THE OPEN: one entry per board, the feed threads started, the store
    /// opened (nothing written until a key is made); under the signed mode
    /// the key is checked at the first `session`, not here.
    pub fn open(opts: ShellOptions) -> Result<Shell, Halt> {
        let log = Arc::new(Log::new());
        let bus = Arc::new(EventBus::new());
        let sessions = Arc::new(Sessions::new());
        let store = Arc::new(FileStore::open(&opts.store_dir));
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
        let mut own_node = None;
        for origin in &opts.boards {
            let board = Board::new(origin.clone(), LoggingDialer::new(Arc::clone(&log)));
            let entry = Arc::new(BoardEntry { reference: board_name(), origin: origin.clone(), board });
            if opts.own_node.as_ref() == Some(origin) {
                own_node = Some(entry.reference.clone());
            }
            boards.push(entry);
        }
        let reopen_store = matches!(opts.mode, SessionMode::Signed { .. }).then(|| Arc::clone(&store));
        let feeds = boards
            .iter()
            .map(|entry| (entry.reference.clone(), Some(Feed::spawn(Arc::clone(entry), Arc::clone(&bus), Arc::clone(&sessions), reopen_store.clone(), opts.store_dir.clone(), Arc::clone(&opts.talk)))))
            .collect();
        let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        Ok(Shell {
            boards,
            feeds: Mutex::new(feeds),
            sessions,
            bus,
            pending: Arc::new(Pending::new()),
            arm,
            log,
            store,
            reopen_store,
            anchors,
            mode: opts.mode,
            talk: opts.talk,
            own_node,
            node_state: AtomicU8::new(0),
            host_name: host_name(),
            date: civil_date(secs),
        })
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
        self.boards.iter().map(|b| b.reference.clone()).collect()
    }

    /// The own node's state, as the verb that owns it reports it.
    pub fn set_node_state(&self, state: NodeState) {
        self.node_state.store(matches!(state, NodeState::Stopped) as u8, Ordering::SeqCst);
    }

    /// THE CHECK the signed mode makes before serving: the store's key for
    /// the principal at every board, its public facts — `no_key` where the
    /// store is keyless for one.
    pub fn check_signed_key(&self) -> Result<Vec<KeyFacts>, Refusal> {
        let SessionMode::Signed { principal } = self.mode else { return Ok(Vec::new()) };
        let mut keys = Vec::new();
        for entry in &self.boards {
            match self.store.select(&KeySelector::Board { origin: &entry.origin, principal: Some(principal) }, Purpose::Sign) {
                Ok(k) => keys.push(k),
                Err(StoreError::NoSelection { keys }) => {
                    let mode = entry.board.health().map(|h| Mode::of(&h)).unwrap_or(Mode::Unclaimed);
                    return Err(Refusal::of_named(Name::NO_KEY, skep_client::store::arm4_face(&self.store, &keys, mode)));
                }
                Err(e) => return Err(Refusal::of_named(Name::STORE_UNREADABLE, e.into())),
            }
        }
        Ok(keys)
    }

    fn say(&self, line: impl AsRef<str>) {
        (self.talk)(line.as_ref());
    }

    fn feed<R>(&self, board: &str, f: impl FnOnce(&Feed) -> R) -> Option<R> {
        let feeds = self.feeds.lock().expect("the feeds' lock");
        feeds.iter().find(|(r, _)| r == board).and_then(|(_, feed)| feed.as_ref()).map(f)
    }

    /// The board a reference names, or THE PIN's unknown-board refusal.
    fn board(&self, reference: &Value) -> Result<Arc<BoardEntry>, Refusal> {
        let Some(name) = reference.as_str() else { return Err(Refusal::malformed("board")) };
        self.boards.iter().find(|b| b.reference == name).cloned().ok_or_else(|| Refusal::shell(Name::UNKNOWN_BOARD, json!({"board": name})))
    }

    /// The session a reference names, or THE PIN's "session ended".
    fn session(&self, reference: &Value) -> Result<Arc<SessionEntry>, Refusal> {
        let Some(name) = reference.as_str() else { return Err(Refusal::malformed("session")) };
        self.sessions.get(name).ok_or_else(|| Refusal::shell(Name::SESSION_ENDED, json!({"session": name})))
    }

    /// The board a session stands at.
    fn board_of_session(&self, session: &SessionEntry) -> Arc<BoardEntry> {
        self.boards.iter().find(|b| b.reference == session.board).cloned().expect("a session stands at a board of this shell")
    }

    /// A person for `walk` at `board`.
    fn person(&self, walk: &'static str, board: &str) -> BridgePerson {
        BridgePerson::new(Arc::clone(&self.bus), Arc::clone(&self.pending), Arc::clone(&self.arm), walk, board.to_string())
    }

    /// A walk's halt as the call's refusal: the abandonment where the page
    /// cancelled or the arm left, else the family's member under `name`
    /// where the walk's one armed name is known.
    fn walk_refusal(&self, person: &BridgePerson, h: Halt) -> Refusal {
        if person.cancelled {
            return Refusal::shell(Name::ABANDONED, json!({"halt": h.to_string()}));
        }
        Refusal::of(h)
    }

    /// The principal a ceremonial row runs as: the row's own where it names
    /// one, else the mode's.
    fn principal_for(&self, args: &Value) -> u64 {
        principal_of_value(&args["principal"]).unwrap_or(self.mode.principal())
    }

    /// Two anchor destinations under the shell's own directory for `walk`.
    fn anchor_out(&self, walk: &str) -> Vec<PathBuf> {
        vec![self.anchors.join(format!("{walk}-a")), self.anchors.join(format!("{walk}-b"))]
    }

    /// A death signal met on `entry`'s token under the shell's hands: the
    /// session ended by the one sequence the board's feed thread runs too,
    /// whichever hand came first; the call's refusal, carrying the arm.
    fn died(&self, entry: &SessionEntry) -> Refusal {
        let board = self.board_of_session(entry);
        let mut supplements = BoardFeed { shell: self, board: &entry.board };
        let reason = self.sessions.end(entry, &board.board, self.reopen_store.as_deref(), &mut supplements, &self.bus);
        Refusal::shell(Name::SESSION_DIED, json!({"session": entry.reference, "reason": reason}))
    }

    // ── THE CALLS ────────────────────────────────────────────────────────

    /// ONE CALL by name, the log kept: the row's method dispatched on the
    /// bridge's spelling.
    pub fn call(&self, name: &str, args: &Value) -> Result<Value, Refusal> {
        let started = Instant::now();
        let bytes_in = args.to_string().len();
        let outcome = match name {
            "boards" => Ok(self.boards()),
            "session" => self.session_call(args),
            "close" => self.close(args),
            "keygen" => self.keygen(args),
            "fingerprint" => self.fingerprint(args),
            "claim" => self.claim(args),
            "enroll" => self.enroll(args),
            "bind" => self.bind(args),
            "recover" => self.recover(args),
            "rotate" => self.rotate(args),
            "retire" => self.retire(args),
            "handoff" => self.handoff(args),
            "accept" => self.accept(args),
            "health" => self.health(args),
            "probe" => Ok(self.probe()),
            "op" => self.op(args),
            "upload" => self.upload(args),
            "fetch" => Err(Refusal::shell(Name::STREAMED_CALL, json!({"call": "fetch", "detail": "fetch streams its bytes: a transport serves it on its own route, and a direct caller takes `Shell::fetch`"}))),
            "restore" => self.restore(args),
            "search" => self.search(args),
            _ => Err(Refusal::shell(Name::UNKNOWN_CALL, json!({"call": name}))),
        };
        let (bytes_out, kind) = match &outcome {
            Ok(v) => (v.to_string().len(), "result"),
            Err(r) => (r.to_value().to_string().len(), "refused"),
        };
        self.log.call(name, bytes_in, bytes_out, started.elapsed(), kind);
        outcome
    }

    /// `boards()` → `[{board, name, origin}]`: `name` the origin, v1's
    /// fallback (ps3-4: every board takes it while no board publishes a
    /// display name).
    fn boards(&self) -> Value {
        Value::Array(self.boards.iter().map(|b| json!({"board": b.reference, "name": b.origin.as_str(), "origin": b.origin.as_str()})).collect())
    }

    /// `session(board, principal)` → `{session, principal, account}`: the
    /// mode's opening as `principal`, the reference issued in the token's
    /// place.
    fn session_call(&self, args: &Value) -> Result<Value, Refusal> {
        let board = self.board(&args["board"])?;
        let principal = principal_of_value(&args["principal"]).unwrap_or(self.mode.principal());
        let open = match self.mode {
            SessionMode::Bare { .. } => sessions::open_bare(&board.board, principal)?,
            SessionMode::Signed { .. } => sessions::open_signed(&board.board, &self.store, principal)?,
        };
        let entry = self.sessions.register(&board.reference, open, &mut BoardFeed { shell: self, board: &board.reference });
        Ok(json!({"session": entry.reference, "principal": principal, "account": entry.facts.account}))
    }

    /// `close(session)` → `{}`: the session out of the table; its drafts
    /// rows read to the head under its token and its supplement narrowed
    /// (`Feed::closing`, answered before the token closes); `POST
    /// /session/close` (idempotent at the board); and its own arm on
    /// `session-died`, after every `feed` row of the session. A reference
    /// this shell holds no session under — stale, or ended by a death met
    /// first — answers "session ended".
    fn close(&self, args: &Value) -> Result<Value, Refusal> {
        let Some(name) = args["session"].as_str() else { return Err(Refusal::malformed("session")) };
        let entry = self.sessions.close(name).ok_or_else(|| Refusal::shell(Name::SESSION_ENDED, json!({"session": name})))?;
        self.feed(&entry.board, |f| f.closing(&entry));
        let board = self.board_of_session(&entry);
        let answer = board.board.session_close(&entry.token).map_err(Refusal::of);
        self.bus.emit(SESSION_DIED, json!({"session": entry.reference, "reason": sessions::closed()}));
        answer.map(|_| json!({}))
    }

    /// `keygen({label?})` → `{fingerprint, payload, outstanding}`: one
    /// device key into the store, its byline fixed at the box — a PUBLIC
    /// moment where no label is passed.
    fn keygen(&self, args: &Value) -> Result<Value, Refusal> {
        let empty_label = |f: skep_client::sheet::LabelFault| Refusal::shell(Name::EMPTY_LABEL, json!({"cause": f.to_string()}));
        let label = match args["label"].as_str() {
            Some(text) => Label::new(text).map_err(empty_label)?,
            None => {
                let mut person = self.person("keygen", "");
                let text = person
                    .label(Public(LabelBox { title: "name this device".into(), statements: device_box_statements(), default: None }))
                    .map_err(|_| Refusal::shell(Name::ABANDONED, json!({"moment": "the device-name box"})))?;
                Label::new(&text).map_err(empty_label)?
            }
        };
        let id = self.store.generate(Some(label.clone())).map_err(|e| Refusal::of_named(Name::STORE_UNWRITABLE, e.into()))?;
        let path = self.store.key_path(&id.0);
        let key = self.store.select(&KeySelector::Path(&path), Purpose::Read).map_err(|e| Refusal::of_named(Name::STORE_UNREADABLE, e.into()))?;
        let entry = Enrollment::new(key.public.clone(), false, Some(label.as_str().to_string())).map_err(|e| Refusal::shell(Name::EMPTY_LABEL, json!({"cause": e.to_string()})))?;
        self.say(format!("keygen: the key {} is written to the store under the byline `{}`", key.fingerprint, render_inert(label.as_str())));
        Ok(json!({"fingerprint": key.fingerprint.to_hex(), "payload": encode_enroll(&[entry]), "outstanding": OUTSTANDING_ACT}))
    }

    /// `fingerprint({select?, payload?})` → `[{fingerprint, label,
    /// bindings, unbound, payload}]`: the store's keys, or the one `select`
    /// names.
    fn fingerprint(&self, args: &Value) -> Result<Value, Refusal> {
        let unreadable = |e: StoreError| Refusal::of_named(Name::STORE_UNREADABLE, e.into());
        let keys: Vec<KeyFacts> = match args["select"].as_str() {
            Some(select) => match self.store.select(&KeySelector::select(select), Purpose::Read) {
                Ok(k) => vec![k],
                Err(StoreError::Ambiguous { keys }) => {
                    let matches: Vec<Value> = keys.iter().map(|k| json!({"fingerprint": k.fingerprint.to_hex(), "label": k.label.as_deref().map(render_inert)})).collect();
                    return Err(Refusal::shell(Name::AMBIGUOUS, json!({"select": select, "matches": matches})));
                }
                Err(StoreError::NotFound { select }) => return Err(Refusal::shell(Name::NOT_FOUND, json!({"select": select}))),
                Err(e) => return Err(unreadable(e)),
            },
            None => self.store.list().map_err(unreadable)?,
        };
        let bindings = self.store.all_bindings().map_err(unreadable)?;
        let with_payload = args["payload"].as_bool().unwrap_or(false);
        let mut rows = Vec::new();
        for key in &keys {
            let bound: Vec<String> = bindings
                .iter()
                .filter_map(|b| match b {
                    Binding::Enrollment { origin, principal, account, fingerprint } if *fingerprint == key.fingerprint => Some(format!("{origin} principal {principal} account {account}")),
                    _ => None,
                })
                .collect();
            let payload = if with_payload {
                let e = Enrollment::new(key.public.clone(), key.anchor, key.label.clone()).map_err(|e| Refusal::shell(Name::EMPTY_LABEL, json!({"cause": e.to_string()})))?;
                Value::from(encode_enroll(&[e]))
            } else {
                Value::Null
            };
            rows.push(json!({
                "fingerprint": key.fingerprint.to_hex(),
                "label": key.label.as_deref().map(render_inert),
                "bindings": bound,
                "unbound": bound.is_empty(),
                "payload": payload,
            }));
        }
        Ok(Value::Array(rows))
    }

    /// `claim(board, {principal?, name?, paper?})`: the notebook walk run
    /// by the shell against the board, the anchors under the shell's own
    /// directory; `already_claimed` where another store's claim stands.
    fn claim(&self, args: &Value) -> Result<Value, Refusal> {
        let board = self.board(&args["board"])?;
        let principal = principal_of_value(&args["principal"]);
        if let Err(StoreError::NoSelection { keys }) = self.store.select(&KeySelector::Board { origin: &board.origin, principal: Some(principal.unwrap_or(1)) }, Purpose::Sign) {
            if keys.is_empty() {
                let mode = board.board.health().map(|h| Mode::of(&h)).map_err(Refusal::of)?;
                return Err(Refusal::of_named(Name::NO_KEY, skep_client::store::arm4_face(&self.store, &keys, mode)));
            }
        }
        let opts = NotebookOptions {
            principal,
            display_name: args["name"].as_str().map(str::to_string),
            anchor_out: self.anchor_out("claim"),
            paper: args["paper"].as_bool().unwrap_or(false),
            host_name: self.host_name.clone(),
            date: self.date.clone(),
        };
        let mut person = self.person("claim", &board.reference);
        match claim::notebook(&board.board, &self.store, &mut person, &opts) {
            Ok(ClaimOutcome::Ours(c)) => Ok(json!({
                "account": c.account,
                "principal": c.principal,
                "fingerprint": c.fingerprint.to_hex(),
                "agent_space": c.agent_space,
                "display_name": c.display_name,
                "warnings": c.warnings,
            })),
            Ok(ClaimOutcome::Stranger { claimant }) => Err(Refusal::shell(Name::ALREADY_CLAIMED, json!({"claimant": claimant}))),
            Err(h) => Err(self.walk_refusal(&person, h)),
        }
    }

    /// `enroll(board, payload)` → the three facts: the hop's signed-in half
    /// run by the shell in its own full session as the mode's principal.
    fn enroll(&self, args: &Value) -> Result<Value, Refusal> {
        let board = self.board(&args["board"])?;
        let payload = args["payload"].as_str().ok_or_else(|| Refusal::malformed("payload"))?;
        let opts = enroll::EnrollOptions { principal: self.principal_for(args), payload: format!("{payload}\n").into_bytes() };
        let mut person = self.person("enroll", &board.reference);
        match enroll::enroll(&board.board, &self.store, &mut person, &opts) {
            Ok(e) => Ok(json!({
                "facts": facts_json(&e.facts),
                "fingerprints": e.fingerprints.iter().map(|f| f.to_hex()).collect::<Vec<_>>(),
                "reconciled": e.reconciled,
                "warnings": e.warnings,
            })),
            Err(h) => Err(self.walk_refusal(&person, h)),
        }
    }

    /// `bind(board, {principal, account, origin})` → `{}`: the three facts
    /// confirmed against the board, the key-set compare, the binding line
    /// appended, the first signed session run where one is owed. The
    /// whole-set compare against a genesis another hand wrote (the handoff
    /// landing's anchor files) is not reached here: the shell has no
    /// window for the files' pick, and the landing is taken as the hop's.
    fn bind(&self, args: &Value) -> Result<Value, Refusal> {
        let board = self.board(&args["board"])?;
        let principal = principal_of_value(&args["principal"]).ok_or_else(|| Refusal::malformed("principal"))?;
        let account = args["account"].as_str().ok_or_else(|| Refusal::malformed("account"))?.trim().to_string();
        let origin = args["origin"].as_str().ok_or_else(|| Refusal::malformed("origin"))?;
        if !is_address_text(&account) {
            return Err(Refusal::malformed("account"));
        }
        if origin != board.origin.as_str() {
            return Err(Refusal::shell(Name::ORIGIN_DISAGREES, json!({"pasted": origin, "dialed": board.origin.as_str()})));
        }
        let b = &board.board;
        let health = b.health().map_err(Refusal::of)?;
        origin_arm(b.signed(), &health).map_err(|h| Refusal::of_named(Name::ORIGIN_STATE, h))?;
        match principal_of(b, &account).map_err(Refusal::of)? {
            Some(p) if p == principal => {}
            other => return Err(Refusal::shell(Name::ACCOUNT_DISAGREES, json!({"pasted_principal": principal, "seated": other, "account": account}))),
        }
        match b.principal_prefix(principal).map_err(Refusal::of)? {
            Some(a) if a == account => {}
            other => return Err(Refusal::shell(Name::ACCOUNT_DISAGREES, json!({"pasted_account": account, "principal_prefix": other}))),
        }
        let key = match self.store.select(&KeySelector::Board { origin: &board.origin, principal: Some(principal) }, Purpose::Sign) {
            Ok(k) => k,
            Err(StoreError::NoSelection { keys }) => return Err(Refusal::of_named(Name::NO_KEY, skep_client::store::arm4_face(&self.store, &keys, Mode::of(&health)))),
            Err(e) => return Err(Refusal::of_named(Name::STORE_UNREADABLE, e.into())),
        };
        let walk = walk_to_set(b, &account).map_err(Refusal::of)?;
        let own = [(key.fingerprint, key.public.clone())];
        if let Err(h) = key_face(b, &walk, &key.fingerprint, &own, Site::Tail) {
            let name = match KeyDiagnosis::of(&walk.set, &key.fingerprint) {
                KeyDiagnosis::Retired { .. } => Name::RETIRED,
                _ => Name::NOT_ENROLLED,
            };
            return Err(Refusal::of_named(name, h));
        }
        let reads = FirstSessionReads::take(b, &account, &key.fingerprint, Some(&self.store)).map_err(Refusal::of)?;
        let mut warnings: Vec<String> = Vec::new();
        if reads.anything_owed() {
            let signer = self.store.signer(&KeySelector::Path(&key.path)).map_err(|e| Refusal::of_named(Name::STORE_UNREADABLE, e.into()))?;
            let session = handshake(b, Scope::Content, &*signer, principal, Site::Tail).map_err(Refusal::of)?;
            let done = first_session(b, &reads, &session, &*signer, Some(&self.store));
            let _ = session.close();
            warnings.extend(done.map_err(Refusal::of)?.warnings);
        }
        let line = Binding::Enrollment { origin: board.origin.clone(), principal, account: account.clone(), fingerprint: key.fingerprint };
        let mut out = Map::new();
        if let Err(w) = self.store.bind(&line) {
            out.insert("warning".into(), Value::from(w.to_string()));
        }
        if !warnings.is_empty() {
            out.insert("warnings".into(), json!(warnings));
        }
        Ok(Value::Object(out))
    }

    /// `recover(board, {principal, lost: [fp], stolen, anchorLost})` → the
    /// three facts: the device arm, or the loss arm; the import SECRET,
    /// the dev arm's.
    fn recover(&self, args: &Value) -> Result<Value, Refusal> {
        let board = self.board(&args["board"])?;
        let lost: Vec<String> = args["lost"].as_array().into_iter().flatten().filter_map(|v| v.as_str().map(str::to_string)).collect();
        let opts = recover::RecoverOptions {
            principal: self.principal_for(args),
            anchor: None,
            lost,
            stolen: args["stolen"].as_bool(),
            anchor_lost: args["anchorLost"].as_bool().unwrap_or(false),
            anchor_out: self.anchor_out("recover"),
            paper: false,
            host_name: self.host_name.clone(),
            date: self.date.clone(),
        };
        let mut person = self.person("recover", &board.reference);
        match recover::recover(&board.board, &self.store, &mut person, &opts) {
            Ok(r) => Ok(json!({
                "facts": facts_json(&r.facts),
                "enrolled": r.enrolled.iter().map(|f| f.to_hex()).collect::<Vec<_>>(),
                "retired": r.retired.iter().map(|f| f.to_hex()).collect::<Vec<_>>(),
                "containment": r.containment,
                "recovery_read": r.recovery_read,
                "warnings": r.warnings,
            })),
            Err(h) => Err(self.walk_refusal(&person, h)),
        }
    }

    /// `rotate(board, {principal, label?, payload?})` → the three facts.
    fn rotate(&self, args: &Value) -> Result<Value, Refusal> {
        let board = self.board(&args["board"])?;
        let opts = rotate::RotateOptions {
            principal: self.principal_for(args),
            label: args["label"].as_str().map(str::to_string),
            payload: args["payload"].as_str().map(|p| format!("{p}\n").into_bytes()),
        };
        let mut person = self.person("rotate", &board.reference);
        match rotate::rotate(&board.board, &self.store, &mut person, &opts) {
            Ok(r) => Ok(json!({
                "facts": facts_json(&r.facts),
                "old": r.old.to_hex(),
                "new": r.new.to_hex(),
                "trail": r.trail,
                "warnings": r.warnings,
            })),
            Err(h) => Err(self.walk_refusal(&person, h)),
        }
    }

    /// `retire(board, principal, fingerprint)` → `{}`: the preview and its
    /// typed confirmation the dev arm's.
    fn retire(&self, args: &Value) -> Result<Value, Refusal> {
        let board = self.board(&args["board"])?;
        let fingerprint = args["fingerprint"].as_str().ok_or_else(|| Refusal::malformed("fingerprint"))?;
        let opts = retire::RetireOptions { principal: self.principal_for(args), fingerprint_prefix: fingerprint.to_string() };
        let mut person = self.person("retire", &board.reference);
        match retire::retire(&board.board, &self.store, &mut person, &opts) {
            Ok(_) => Ok(json!({})),
            Err(h) => Err(self.walk_refusal(&person, h)),
        }
    }

    /// `handoff(board, {account, payload?})`: beat (a) alone without a
    /// payload, answering the address; the genesis with one, `{}`.
    fn handoff(&self, args: &Value) -> Result<Value, Refusal> {
        let board = self.board(&args["board"])?;
        let account = args["account"].as_str().ok_or_else(|| Refusal::malformed("account"))?;
        let opts = handoff::HandoffOptions {
            principal: self.principal_for(args),
            account: account.to_string(),
            payload: args["payload"].as_str().map(|p| format!("{p}\n").into_bytes()),
            anchor: None,
        };
        let mut person = self.person("handoff", &board.reference);
        match handoff::handoff(&board.board, &self.store, &mut person, &opts) {
            Ok(handoff::HandoffOutcome::Delegated { account, principal, already }) => Ok(json!({"address": account, "principal": principal, "already": already})),
            Ok(handoff::HandoffOutcome::Seeded { .. }) => Ok(json!({})),
            Err(h) => Err(self.walk_refusal(&person, h)),
        }
    }

    /// `accept(board, {address, label?, paper?, noAnchors?})` →
    /// `{payload}`: the recipient's beat; `no_address` where none is given.
    fn accept(&self, args: &Value) -> Result<Value, Refusal> {
        let board = self.board(&args["board"])?;
        let Some(address) = args["address"].as_str().filter(|a| !a.trim().is_empty()) else {
            return Err(Refusal::shell(Name::NO_ADDRESS, json!({})));
        };
        let opts = accept::AcceptOptions {
            account: address.to_string(),
            label: args["label"].as_str().map(str::to_string),
            anchor_out: self.anchor_out("accept"),
            paper: args["paper"].as_bool().unwrap_or(false),
            no_anchors: args["noAnchors"].as_bool().unwrap_or(false),
            hosted: None,
            host_name: self.host_name.clone(),
            date: self.date.clone(),
        };
        let mut person = self.person("accept", &board.reference);
        match accept::accept(&board.board, &self.store, &mut person, &opts) {
            Ok(a) => Ok(json!({"payload": a.record})),
            Err(h) => {
                let text = h.to_string();
                let name = if text.contains("already holds a key set") {
                    Some(Name::ALREADY_SEEDED)
                } else if text.contains("not yet delegated") {
                    Some(Name::NOT_DELEGATED)
                } else if text.contains("refused at the box") {
                    Some(Name::EMPTY_LABEL)
                } else {
                    None
                };
                match name {
                    Some(name) if !person.cancelled => Err(Refusal::of_named(name, h)),
                    _ => Err(self.walk_refusal(&person, h)),
                }
            }
        }
    }

    /// `health(board)` → `{health, mode}`: the `/health` document verbatim
    /// and the derived mode.
    fn health(&self, args: &Value) -> Result<Value, Refusal> {
        let board = self.board(&args["board"])?;
        let health = board.board.health().map_err(Refusal::of)?;
        Ok(json!({"health": health.body, "mode": Mode::of(&health).name()}))
    }

    /// `probe()` → `{daemon, dialed, signed}`: the own node's state where
    /// the shell runs one — `stopped` where its owner stopped it,
    /// `unreachable` where it does not answer, `running` else — and the
    /// first board's reachability where it runs none.
    fn probe(&self) -> Value {
        let entry = match &self.own_node {
            Some(reference) => self.boards.iter().find(|b| &b.reference == reference),
            None => self.boards.first(),
        };
        let Some(entry) = entry else { return json!({"daemon": "unreachable", "dialed": null, "signed": null}) };
        let state = if self.node_state.load(Ordering::SeqCst) == 1 {
            "stopped"
        } else if entry.board.health().is_ok() {
            "running"
        } else {
            "unreachable"
        };
        json!({"daemon": state, "dialed": entry.board.dialed().as_str(), "signed": entry.board.signed().as_str()})
    }

    /// The board the guest form names: a reference of this shell, or a
    /// canonical origin dialed token-free.
    fn guest_board(&self, args: &Value) -> Result<Board, Refusal> {
        if let Some(name) = args["board"].as_str() {
            let entry = self.board(&Value::from(name))?;
            return Ok(Board::new(entry.origin.clone(), LoggingDialer::new(Arc::clone(&self.log))));
        }
        let origin = args["origin"].as_str().ok_or_else(|| Refusal::malformed("board or origin"))?;
        let origin = Origin::parse(origin).ok_or_else(|| Refusal::shell(Name::NOT_CANONICAL, json!({"origin": origin})))?;
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
            Some(r) => Err(Refusal::of(r.refused(&v))),
            None => Ok(v),
        }
    }

    /// `op(session, frame)` and the guest forms: ONE frame to the board the
    /// session was opened at under its token — the attest composed under
    /// the signed mode where the kind has an entry frame — or token-free
    /// at guest class, a write refused without a dial.
    fn op(&self, args: &Value) -> Result<Value, Refusal> {
        let (mut frame, at) = Self::frame_of(args)?;
        let guest = args["guest"].as_bool().unwrap_or(false) || args.get("session").is_none();
        if guest {
            let board = self.guest_board(args)?;
            let op = frame["op"].as_str().unwrap_or("");
            if WRITE_OPS.contains(&op) {
                return Err(Refusal::shell(Name::WRITE_IN_GUEST_FORM, json!({"op": op})));
            }
            return match at {
                Some(at) => match board.op_at(None, at, &frame).map_err(Refusal::of)? {
                    AtAnswer::Document(v) => Self::document(v),
                    other => Ok(at_answer_json(other)),
                },
                None => Self::document(board.guest(&frame).map_err(Refusal::of)?),
            };
        }
        let entry = self.session(&args["session"])?;
        let board = self.board_of_session(&entry);
        if let (SessionMode::Signed { .. }, None, Kind::Content) = (self.mode, at, entry.facts.kind) {
            if frame["op"].as_str().is_some_and(in_checked_set) && frame.get("attest").is_none() {
                self.attach_attest(&board, &entry, &mut frame)?;
            }
        }
        let answer = match at {
            Some(at) => match board.board.op_at(Some(&entry.token), at, &frame).map_err(Refusal::of)? {
                AtAnswer::Document(v) => Answer::Document(v),
                AtAnswer::Closed => Answer::Closed,
                other => return Ok(at_answer_json(other)),
            },
            None => board.board.op(Some(&entry.token), &frame).map_err(Refusal::of)?,
        };
        match answer {
            Answer::Document(v) => Self::document(v),
            Answer::Closed => Err(self.died(&entry)),
        }
    }

    /// The attest for `frame` under `entry`'s key, composed by the shell.
    fn attach_attest(&self, board: &BoardEntry, entry: &SessionEntry, frame: &mut Value) -> Result<(), Refusal> {
        let term = board.board.board_term().map_err(Refusal::of)?;
        let Some(term) = term else {
            // No `H.1`: the board judges the write (`board_unavailable`, or a
            // draft's write outside the class); nothing to sign over.
            return Ok(());
        };
        let key = self.store.select(&KeySelector::Board { origin: &board.origin, principal: Some(entry.facts.principal) }, Purpose::Sign).map_err(|e| Refusal::of_named(Name::NO_KEY, e.into()))?;
        let signer = self.store.signer(&KeySelector::Path(&key.path)).map_err(|e| Refusal::of_named(Name::STORE_UNREADABLE, e.into()))?;
        let account = entry.facts.account.as_deref().ok_or_else(|| Refusal::shell(Name::NO_ACCOUNT, json!({})))?;
        let composer = Composer { board: &board.board, token: &entry.token, signer: &*signer, account, term };
        composer.attach(frame).map(|_| ()).map_err(|h| Refusal::of_named(Name::ATTEST_NOT_COMPOSED, h))
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
    /// head ends the session.
    pub fn fetch(&self, args: &Value) -> Result<Fetched, Refusal> {
        let i = args["i"].as_str().ok_or_else(|| Refusal::malformed("i"))?;
        if !is_address_text(i) {
            return Err(Refusal::malformed("i"));
        }
        let guest = args["guest"].as_bool().unwrap_or(false) || args.get("session").is_none();
        let (board, token, entry) = if guest {
            (self.guest_board(args)?, None, None)
        } else {
            let entry = self.session(&args["session"])?;
            let board = self.board_of_session(&entry);
            (Board::new(board.origin.clone(), LoggingDialer::new(Arc::clone(&self.log))), Some(entry.token.clone()), Some(entry))
        };
        let mut headers = Vec::new();
        if let Some(t) = &token {
            headers.push(("Skepd-Session".to_string(), t.as_str().to_string()));
        }
        let head = RequestHead { method: Method::Get, path: format!("/blob?i={i}"), headers, content_length: None };
        let mut empty = std::io::empty();
        let resp = board.dialer().stream(board.dialed(), &head, &mut empty, &mut |_| {}).map_err(|e| Refusal::of(Halt::Dial(e)))?;
        if resp.headers.get("Skepd-Session").is_some_and(|v| v.trim() == "closed") {
            if let Some(entry) = &entry {
                return Err(self.died(entry));
            }
        }
        if resp.status != 200 {
            let mut body = Vec::new();
            let reader = resp.body;
            let _ = reader.take(64 * 1024).read_to_end(&mut body);
            let v: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            return Err(Refusal::Board(skep_client::Refused {
                status: resp.status,
                code: v["error"].as_str().unwrap_or("http_error").to_string(),
                detail: v["detail"].as_str().map(str::to_string),
                op: None,
                body: v,
            }));
        }
        Ok(Fetched { status: resp.status, headers: resp.headers, body: resp.body })
    }

    /// `search(session|guest, board, query, opts)` → `{hits, places, state}`
    /// off the board's consumer; `query_too_long` the shell's own bound.
    fn search(&self, args: &Value) -> Result<Value, Refusal> {
        let query = args["query"].as_str().ok_or_else(|| Refusal::malformed("query"))?;
        let opts = SearchOpts {
            limit: args["opts"]["limit"].as_u64().map(|n| n as usize).unwrap_or(SearchOpts::default().limit),
            offset: args["opts"]["offset"].as_u64().map(|n| n as usize).unwrap_or(0),
        };
        let reindex = args["opts"]["reindex"].as_bool().unwrap_or(false);
        let guest = args["guest"].as_bool().unwrap_or(false) || args.get("session").is_none();
        let (board_ref, who) = if guest {
            if args["board"].is_null() {
                // A followed link's origin the shell holds no index for.
                return Ok(json!({"hits": [], "places": [], "state": {"arm": "none"}, "total": 0, "truncated": false, "more_terms": false, "fuzzy_bounded": false, "positions_bounded": false}));
            }
            (self.board(&args["board"])?.reference.clone(), Searcher::Guest)
        } else {
            let entry = self.session(&args["session"])?;
            let who = Searcher::Session { principal: entry.facts.principal, token: entry.token.clone(), account: entry.facts.account.clone().unwrap_or_default() };
            (entry.board.clone(), who)
        };
        self.feed(&board_ref, |f| f.search(who, query, opts, reindex)).unwrap_or_else(|| Err(Refusal::shell(Name::FEED_STOPPED, json!({}))))
    }

    // ── THE TWO ANSWERS ──────────────────────────────────────────────────

    /// `answer(id, value)`: `true` where a moment with that id waited.
    pub fn answer(&self, id: &str, value: Value) -> bool {
        self.pending.answer(id, value)
    }

    /// `cancel(id)`: `true` where a moment with that id waited.
    pub fn cancel(&self, id: &str) -> bool {
        self.pending.cancel(id)
    }

    // ── THE STOP ─────────────────────────────────────────────────────────

    /// THE CLEAN STOP: every pending moment cancelled, every session closed
    /// at its board, every consumer saved and closed.
    pub fn shutdown(&self) {
        self.pending.cancel_all();
        for entry in self.sessions.all() {
            if self.sessions.close(&entry.reference).is_some() {
                let board = self.board_of_session(&entry);
                let _ = board.board.session_close(&entry.token);
            }
        }
        let feeds: Vec<Feed> = self.feeds.lock().expect("the feeds' lock").iter_mut().filter_map(|(_, f)| f.take()).collect();
        for feed in feeds {
            feed.stop();
        }
    }
}

/// One board's drafts supplements as the shell reaches them: through the
/// board's feed handle, each widen and narrow a command its thread runs.
struct BoardFeed<'s> {
    shell: &'s Shell,
    board: &'s str,
}

impl Supplements for BoardFeed<'_> {
    fn widen(&mut self, entry: &Arc<SessionEntry>) {
        self.shell.feed(self.board, |f| f.widen(entry));
    }

    fn narrow(&mut self, principal: u64) {
        self.shell.feed(self.board, |f| f.narrow(principal));
    }
}

/// An `/op-at` answer that is no document, as a value the page renders.
fn at_answer_json(a: AtAnswer) -> Value {
    match a {
        AtAnswer::Document(v) => v,
        AtAnswer::Closed => json!({"resp": "rejected", "code": "session_closed"}),
        AtAnswer::HistoryReclaimed { floor } => json!({"resp": "rejected", "code": "history_reclaimed", "floor": floor}),
        AtAnswer::BeyondHead { head } => json!({"resp": "rejected", "code": "beyond_head", "head": head}),
        AtAnswer::NotAPosition { nearest } => json!({"resp": "rejected", "code": "not_a_position", "nearest": nearest}),
        AtAnswer::Busy => json!({"resp": "rejected", "code": "history_busy"}),
        _ => json!({"resp": "rejected", "code": "unknown"}),
    }
}

#[cfg(test)]
mod tests;
