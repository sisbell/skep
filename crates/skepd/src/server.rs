//! The process: one long-running server owning one `World`. The daemon is
//! transport, configuration, and lifetime — every handler is
//! parse/marshal/dispatch/configure; every decision lives in a store.
//!
//! Split for testability: [`Daemon`] holds the state and routes
//! `&HttpRequest → Routed` with no socket anywhere; [`serve`]/[`Skepd`]
//! wrap it in a synchronous accept loop over a plain `TcpListener`. The HTTP/1.1 subset this daemon speaks (GET/POST/OPTIONS,
//! `Content-Length` bodies, one request per connection, `Connection: close`
//! on every response) is written out here rather than taken from a server
//! library, because the commit stream needs two things a pull-based library
//! response cannot give: event bytes flushed to the socket at commit time,
//! and a server-initiated close at shutdown. Owning the socket makes both
//! one-line facts.
//!
//! **History is served from the journal** (wire v3): `POST /op-at` answers
//! any READ frame as of any committed position, and `GET /dump?at=N`
//! (observe builds) dumps that position's world. Both ask `history.rs`,
//! which owns the reconstruction (the engine's bounded replay), its
//! concurrency budget, and the `as_of` stamping; what this file adds is the
//! envelope, the read/write classification, and the one mapping from an
//! unavailable answer onto the wire's transport errors. Writes never reach
//! history — a write frame is refused at the transport
//! (`400 write_at_history`) before anything runs — and the live `/op` path
//! is untouched.
//!
//! **Durability is configuration, not code**: [`Daemon::open`] opens M2's
//! kernel on a real directory with `Durability::Fsync` (rollback burned-seq
//! policy), an every-1024-commits checkpoint cadence, and two retained
//! checkpoints — genesis on a fresh store, recovery on an existing one, both
//! inside `Engine::open`. Nothing here writes any file of its own.
//!
//! **Identity is local trust**: clients name their own principal at
//! `POST /session` and get an opaque token; the daemon maps token →
//! M10-minted `SessionId` in its own state, so a `SessionId` never rides the
//! wire (M10's non-forgeability precondition) and every write is attributed
//! to the named principal. Tokens die with the process — M10 session ids
//! reset on restart, and a stale token simply misses. A request with no (or
//! an unknown) token runs under a pre-retired guest session: reads are
//! principal-free and succeed; writes get M10's own `Unauthenticated`
//! rejection. The daemon binds 127.0.0.1 only — the trust model does not
//! survive a network.
//!
//! **Cross-origin posture (wire v4)**: every response carries
//! `Access-Control-Allow-Origin: *`, added at the one place responses are
//! written so no reply can miss it, and `OPTIONS` on any known path answers
//! a 204 preflight naming the allowed methods and headers. The `*` is a
//! scope decision, not an accident — but the session token is not what
//! bounds it: `POST /session` is itself unauthenticated and cross-origin
//! reachable, so a page that wants a token mints one, naming any principal
//! it likes. What `*` grants any page the browser loads is exactly what
//! this daemon already grants any local process: the whole surface, reads
//! and writes alike. That equivalence is the decision. Revisited when
//! authentication lands.
//!
//! **Writes go through one card** (`write_path.rs`): `POST /op` — the
//! daemon's only live write path — hands each write to `WritePath::commit`,
//! which commits it, records its change-feed entry, and announces its
//! position, in that order and under one lock. What this file adds is the
//! frame's parse and its classification; the ordering the two feeds below
//! rest on is not a thing a handler here can take apart. Reads execute
//! directly and take no lock.
//!
//! **The commit stream (wire v4)**: `GET /events` is a `text/event-stream`
//! of committed log positions — one event carrying the current head on
//! connect, then an event whenever the head advances. `write_path.rs` owns
//! the feed: what a subscriber is told next, and the coalescing that falls
//! out of asking "anything past what I last sent"; [`Subscribers`] below
//! owns the budget, the admission, and the join at shutdown. What this file
//! adds is the SSE framing (`serve_events`) and the hand-off that keeps an
//! open stream off the op pool — the accepting worker gives the socket to a
//! dedicated thread and returns to `accept`.
//!
//! **The change feed (wire v6)**: `GET /changes?since=N` answers the
//! committed positions in `(N, head]`, oldest first, each with its op kind,
//! affected document(s), and commit wall-clock time — so clients refresh
//! what they display instead of re-walking the world on every SSE tick.
//! `sidecar.rs` owns `commits.log`: its crash honesty, its retention, and
//! what a position whose record was lost answers; `write_path.rs` owns the
//! ordering that makes the sidecar's invariants true. What this file adds
//! is the query's parse, the marshal, and `/health`'s `head_time`.
//!
//! **The served client (wire v6, `client` feature, default OFF)**: `GET /`
//! answers the embedded authoring client (`skep/clients/board.html`,
//! `include_str!` at build — the binary is self-contained), `text/html`,
//! same CORS posture as everything else. One file by design; there is no
//! asset pipeline. The client ACTS — it generates keys and opens signed
//! sessions — so it is opted into rather than opted out of, and abstention
//! is the safe state; the feature's note in `Cargo.toml` carries the
//! ruling. A build without the feature has no `/` route (404).

use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use parking_lot::Mutex;
use serde_json::Value;
use skep_engine::{Engine, EngineError, GenesisConfig, HistoryError, World};
use skep_febe::{Codec, Operation, Response, SessionId};
use skep_kernel::{BurnedSeqPolicy, CheckpointPolicy, Durability, KernelConfig, Seq};
use skep_namespace::PrincipalId;

use crate::codec::{check_keys, obj, to_bytes, JsonCodec};
use crate::history::{History, ReconstructPermit, Unavailable};
use crate::sidecar::ChangesAnswer;
use crate::write_path::{op_is_read, write_meta, FeedStep, WritePath};

/// Auto-checkpoint cadence: every N commits (M2 evaluates on-commit; no
/// timer thread exists anywhere in this daemon). Together with
/// [`RETAINED_CHECKPOINTS`] this sets the sidecar's reconstruction ceiling
/// at open (see `Sidecar::open`): raising either lengthens startup on a
/// data dir whose commit metadata is missing.
const CHECKPOINT_EVERY_COMMITS: u64 = 1024;

/// Retained checkpoints: two, so `BadCheckpoint` recovery can fall back to
/// the older base instead of a full-journal replay from genesis. The other
/// factor of the sidecar's reconstruction ceiling — see
/// [`CHECKPOINT_EVERY_COMMITS`].
const RETAINED_CHECKPOINTS: usize = 2;

/// Socket read deadline for one request's head+body: a stalled local
/// client releases its worker instead of pinning it.
const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Socket write deadline (per write call, replies and events alike): a
/// subscriber that stops draining errors out instead of blocking a thread
/// forever — which is what keeps shutdown bounded even against a stalled
/// peer.
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// Preflight cache lifetime advertised on `OPTIONS` (wire v4).
const CORS_MAX_AGE_SECS: &str = "86400";

/// The one request header this daemon reads beyond HTTP's own framing: the
/// opaque session token. Named once because the CORS preflight must
/// advertise exactly the header the reader consults — a header the
/// preflight omits is one the browser will not send, so the two must agree
/// or every cross-origin write fails at a layer this crate's own suite,
/// which writes the header straight onto a socket, never reaches.
const SESSION_HEADER: &str = "Skepd-Session";

/// Request-head size cap. Tokens and headers are small; frames ride in the
/// body, capped separately by [`MAX_REQUEST_BODY`].
const MAX_REQUEST_HEAD: usize = 64 * 1024;

/// Request-body cap, enforced on the declared `Content-Length` before any
/// body byte is read or allocated. Pre-media value — wire frames are small.
///
/// This bounds the REQUEST, not the allocation it commands, and the ratio
/// between them is what anyone raising it must price: the per-byte write
/// discipline mints one `Val` per input byte, each its own allocation, so
/// an `insert` body buys roughly forty times its size in live heap. The
/// codec's own `MAX_INSERT_VALUES` is what bounds that multiplier; raising
/// this number alone raises the amplified cost with it.
///
/// REVISIT at the media round: blob upload will raise this for its route
/// only (a route-scoped cap, not a bigger global one).
const MAX_REQUEST_BODY: usize = 8 * 1024 * 1024;

/// `/changes` page size when `limit` is absent.
const CHANGES_LIMIT_DEFAULT: usize = 256;

/// `/changes` page-size ceiling; a larger request is refused, not clamped
/// (the never-silent posture applied to paging).
const CHANGES_LIMIT_MAX: usize = 4096;

/// The embedded authoring client (wire v6): one file, compiled in so the
/// binary is self-contained.
#[cfg(feature = "client")]
const BOARD_HTML: &str = include_str!("../../../clients/board.html");

/// `Daemon::open` failure — every variant is an operator-intervention
/// condition: report and stop, never retry.
#[derive(Debug)]
#[non_exhaustive]
pub enum DaemonError {
    /// The engine could not genesis/recover (corrupt journal, bad
    /// checkpoint, drifted genesis config).
    Engine(EngineError),
    /// `commits.log` (the commit-metadata sidecar) could not be opened,
    /// replayed, or extended. A torn tail is NOT an error (it truncates);
    /// this is the data dir refusing I/O the kernel just performed.
    Sidecar(std::io::Error),
}

impl std::fmt::Display for DaemonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DaemonError::Engine(e) => write!(f, "{e}"),
            DaemonError::Sidecar(e) => write!(f, "commits.log sidecar: {e}"),
        }
    }
}

/// `Display` states the whole condition on one line — that is what the
/// operator reads — and `source` additionally exposes the cause as a link,
/// so a generic reporter walking the chain finds one where there is one.
impl std::error::Error for DaemonError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DaemonError::Engine(e) => Some(e),
            DaemonError::Sidecar(e) => Some(e),
        }
    }
}

/// A response body and the media type naming it — one value, because a
/// reply may neither carry bytes it does not name nor name a type it has no
/// bytes for.
#[derive(Debug)]
pub struct Content {
    pub content_type: &'static str,
    pub bytes: Vec<u8>,
}

/// One handler result: a status, an optional body, and any extra headers.
/// `POST /op` is always `200` once a `Response` exists — rejections
/// included; the `Response` envelope, not the HTTP status, is the operation
/// protocol. Non-200 codes are transport-level only (`{"error": …}` bodies,
/// wire.md §Transport errors).
///
/// `content: None` is the bodiless answer, written with no content headers
/// at all (the 204 preflight). Making bodilessness the body's own absence
/// is what keeps the writer from inferring it from the status, where a 204
/// built with bytes would drop them in silence.
#[non_exhaustive]
pub struct Reply {
    pub status: u16,
    pub content: Option<Content>,
    /// Extra response headers beyond the universal set (`Content-Type`,
    /// `Content-Length`, `Access-Control-Allow-Origin`, `Connection`) —
    /// the preflight trio rides here.
    pub headers: Vec<(&'static str, &'static str)>,
}

/// The body's LENGTH, never its bytes: a `/dump` reply is a whole world and
/// an inlined body would make `dbg!` useless exactly where it is reached
/// for.
impl std::fmt::Debug for Reply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reply")
            .field("status", &self.status)
            .field("content_type", &self.content.as_ref().map(|c| c.content_type))
            .field("body_len", &self.body().len())
            .field("headers", &self.headers)
            .finish()
    }
}

impl Reply {
    /// The body bytes; empty for a bodiless reply.
    pub fn body(&self) -> &[u8] {
        self.content.as_ref().map_or(&[], |c| c.bytes.as_slice())
    }

    /// A reply carrying `bytes` under `content_type`.
    fn bodied(status: u16, content_type: &'static str, bytes: Vec<u8>) -> Reply {
        Reply {
            status,
            content: Some(Content { content_type, bytes }),
            headers: Vec::new(),
        }
    }

    /// A JSON reply at `status` — the success answers, which each name
    /// their own code. A refusal names a [`TransportError`] instead and
    /// takes its status from there.
    fn json(status: u16, v: Value) -> Reply {
        Reply::bodied(status, "application/json", to_bytes(v))
    }

    /// The CORS preflight answer (wire v4): 204, no body, the fixed method
    /// and header lists. `Access-Control-Allow-Origin: *` is universal and
    /// added where every response is written, so it is not repeated here.
    fn preflight() -> Reply {
        Reply {
            status: 204,
            content: None,
            headers: vec![
                ("Access-Control-Allow-Methods", "GET, POST, OPTIONS"),
                ("Access-Control-Allow-Headers", "Content-Type, Skepd-Session"),
                ("Access-Control-Max-Age", CORS_MAX_AGE_SECS),
            ],
        }
    }
}

/// One routing decision. Almost everything is a complete [`Reply`]; the
/// event stream is not request/response at all, so it never becomes one —
/// the accept path spawns a subscriber thread that owns the socket
/// (`serve_events`), and the type makes reaching it through the plain reply
/// path unrepresentable.
#[derive(Debug)]
pub enum Routed {
    Reply(Reply),
    /// `GET /events` — the server-sent commit stream (wire v4).
    EventStream,
}

/// One request, as [`Daemon::route`] receives it and as the socket reader
/// builds it — one value rather than a list of arguments, so the two
/// `Option<String>`s cannot be handed over in the wrong order.
pub struct HttpRequest {
    /// The method token, uppercase ASCII (`GET`, `POST`, `OPTIONS`).
    pub method: String,
    /// The request target with any query stripped — `/op`, `/changes`.
    pub path: String,
    /// The raw query string, if the target carried one. Meaningful on
    /// `/changes` and `/dump`; ignored elsewhere.
    pub query: Option<String>,
    /// The `Skepd-Session` header's value, if present: the opaque token a
    /// session was bound to. Absent or unknown resolves to the guest.
    pub session_token: Option<String>,
    /// The body, exactly `Content-Length` bytes (empty when absent).
    pub body: Vec<u8>,
}

/// The body's LENGTH and the token's PRESENCE: the body runs to the 8 MiB
/// cap, and the token names a live session, which is not a thing to leave
/// in a log line.
impl std::fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("query", &self.query)
            .field("session_token", &self.session_token.as_ref().map(|_| "<token>"))
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// The transport's whole error vocabulary — every `{"error": …}` name this
/// daemon can answer, and the only way one is written. EXHAUSTIVE over the
/// wire's transport-error table (wire.md §Transport errors, §Reading
/// history, §The change feed), so a new failure cannot ship without a
/// documented name, exactly as `code_name` guarantees for M10's rejections.
#[derive(Clone, Copy)]
enum TransportError {
    // The envelope and query parsers.
    MalformedSessionRequest,
    MalformedOpAt,
    MalformedChanges,
    #[cfg(feature = "observe")]
    MalformedAt,
    // Routing.
    NoSuchEndpoint,
    MethodNotAllowed,
    // The history surface.
    WriteAtHistory,
    BeyondHead,
    NotAPosition,
    HistoryReclaimed,
    HistoryBusy,
    NoJournal,
    HistoryIo,
    HistoryCorrupt,
    // The HTTP layer.
    MalformedHttp,
    PayloadTooLarge,
    InternalPanic,
}

impl TransportError {
    fn name(self) -> &'static str {
        match self {
            TransportError::MalformedSessionRequest => "malformed_session_request",
            TransportError::MalformedOpAt => "malformed_op_at",
            TransportError::MalformedChanges => "malformed_changes",
            #[cfg(feature = "observe")]
            TransportError::MalformedAt => "malformed_at",
            TransportError::NoSuchEndpoint => "no_such_endpoint",
            TransportError::MethodNotAllowed => "method_not_allowed",
            TransportError::WriteAtHistory => "write_at_history",
            TransportError::BeyondHead => "beyond_head",
            TransportError::NotAPosition => "not_a_position",
            TransportError::HistoryReclaimed => "history_reclaimed",
            TransportError::HistoryBusy => "history_busy",
            TransportError::NoJournal => "no_journal",
            TransportError::HistoryIo => "history_io",
            TransportError::HistoryCorrupt => "history_corrupt",
            TransportError::MalformedHttp => "malformed_http",
            TransportError::PayloadTooLarge => "payload_too_large",
            TransportError::InternalPanic => "internal_panic",
        }
    }

    /// The status this failure is answered with — the second column of the
    /// same table [`TransportError::name`] transcribes (wire.md §HTTP
    /// status codes). Clients dispatch on the status, so the pairing is
    /// contract; stating it here is what keeps one name from arriving under
    /// two statuses depending on which handler refused.
    fn status(self) -> u16 {
        match self {
            TransportError::MalformedSessionRequest
            | TransportError::MalformedOpAt
            | TransportError::MalformedChanges
            | TransportError::WriteAtHistory
            | TransportError::BeyondHead
            | TransportError::NotAPosition
            | TransportError::MalformedHttp => 400,
            #[cfg(feature = "observe")]
            TransportError::MalformedAt => 400,
            TransportError::NoSuchEndpoint => 404,
            TransportError::MethodNotAllowed => 405,
            TransportError::HistoryReclaimed => 410,
            TransportError::PayloadTooLarge => 413,
            TransportError::NoJournal
            | TransportError::HistoryIo
            | TransportError::HistoryCorrupt
            | TransportError::InternalPanic => 500,
            TransportError::HistoryBusy => 503,
        }
    }
}

/// A transport-level refusal, whole: the status and the `{"error": name}`
/// body wire.md pairs with `err`, plus an optional detail. Deliberately NOT
/// the `{"resp": "rejected"}` shape — no `Op` was involved. Every non-2xx
/// this daemon answers is built here or by [`refuse_with`], so no handler
/// chooses a status of its own.
fn refuse(err: TransportError, detail: Option<&str>) -> Reply {
    let fields = match detail {
        Some(d) => vec![("detail", Value::String(d.into()))],
        None => Vec::new(),
    };
    refuse_with(err, fields)
}

/// The same refusal carrying the diagnostic fields a few errors name —
/// `head`, `nearest`, `floor` — the coordinate a caller needs to ask a
/// better question. `error` is appended here, so a field list can never
/// omit it.
fn refuse_with(err: TransportError, fields: Vec<(&'static str, Value)>) -> Reply {
    let mut pairs = fields;
    pairs.push(("error", Value::String(err.name().into())));
    Reply::json(err.status(), obj(pairs))
}

/// The paths this daemon serves — the one place the route set is stated, so
/// preflight, method refusal and dispatch cannot disagree about what exists.
/// A known path answers `OPTIONS` with a preflight and a wrong method with
/// `405`; everything else is the ordinary `404`.
fn path_is_known(path: &str) -> bool {
    matches!(path, "/session" | "/op" | "/op-at" | "/health" | "/events" | "/changes")
        || (cfg!(feature = "observe") && path == "/dump")
        || (cfg!(feature = "client") && path == "/")
}

/// Live token bindings retained, oldest evicted first. `POST /session` is
/// unauthenticated and costs a client ~90 wire bytes, so an unbounded map
/// would let any local process (or any page the browser loads) retain
/// memory here and in M10 without limit and without ever writing —
/// unlike the CPU costs elsewhere on this surface, retention does not
/// clear when the caller stops.
///
/// Eviction is inside the documented session model rather than a
/// narrowing of it: wire.md already says a token may simply miss and
/// resolve to the guest, which is what an evicted one now does. The number
/// is M10's own idempotency capacity (1024), which is the commensurate
/// scale because [`Operation::close_session`] purges exactly one session's
/// idempotency entries — the two ephemeral tables are sized by the same
/// argument and are retired together.
const MAX_LIVE_SESSIONS: usize = 1024;

/// Identity as local trust: the token ↔ `SessionId` binding, and the one
/// policy over it. Clients name their own principal at `POST /session` and
/// get an opaque token back; a `SessionId` never rides the wire (M10's
/// non-forgeability precondition). Tokens die with the process — a token
/// from a previous run misses the map, and a miss is not an error: it
/// resolves to the guest, under which M10 itself serves reads and rejects
/// writes `Unauthenticated`, so the daemon holds no auth policy of its own.
///
/// The binding table is bounded at [`MAX_LIVE_SESSIONS`], so retention is
/// a function of the daemon's own budget rather than of how many sessions
/// a caller chose to open. Retiring a binding is this transport's to do —
/// nothing else in M10 retires one — and [`Sessions::bind`] hands back
/// what it evicted so `POST /session` can discharge that obligation
/// against M10 as well as against this map.
struct Sessions {
    /// The token table and its mint order, under one lock.
    bindings: Mutex<Bindings>,
    /// A session opened and immediately closed at startup: permanently
    /// unbound, never reissued (M10 §6) — what an absent or unknown token
    /// resolves to.
    guest: SessionId,
    /// Per-uptime random token prefix: a stale token from a previous run
    /// misses instead of silently aliasing onto a fresh session.
    seed: u64,
}

/// The bounded token table: the map, plus the mint order eviction reads.
/// One value under one lock, so the queue cannot describe a token the map
/// has lost or vice versa. Insertion order and not recency — a token's
/// worth to a client does not grow with use, and mint order needs no
/// bookkeeping on the read path, which is every request.
#[derive(Default)]
struct Bindings {
    map: HashMap<String, SessionId>,
    order: VecDeque<String>,
}

impl Sessions {
    fn new(guest: SessionId) -> Sessions {
        Sessions { bindings: Mutex::new(Bindings::default()), guest, seed: unpredictable_u64() }
    }

    /// Mint the opaque token naming `sid`, remember the binding, and hand
    /// back every session the insertion evicted — which the caller owes to
    /// [`Operation::close_session`], since a binding this map has dropped
    /// is one nothing can reach again.
    ///
    /// The suffix is drawn fresh per token rather than counted, so no
    /// issued token names any other: a counter would let one client that
    /// holds a token enumerate every live token of the same uptime, and
    /// the day `POST /session` gains a credential that enumeration is
    /// session hijacking. Today it is narrower — a guessed token replays
    /// another session's cached acks — and closing it now costs one draw
    /// per session.
    fn bind(&self, sid: SessionId) -> (String, Vec<SessionId>) {
        let token = format!("{:016x}.{:016x}", self.seed, unpredictable_u64());
        let mut bindings = self.bindings.lock();
        let mut evicted = Vec::new();
        match bindings.map.insert(token.clone(), sid) {
            // Fresh: the token takes its place in the mint order.
            None => bindings.order.push_back(token.clone()),
            // A repeated draw. The token keeps its ONE place in the order,
            // and the binding it displaced is unreachable, so it is retired
            // like any evicted one. This is what keeps map and order in
            // exact step without the invariant resting on the draw never
            // repeating — a queue naming one token twice would evict the
            // map entry belonging to the LIVE binding.
            Some(displaced) => evicted.push(displaced),
        }
        while bindings.order.len() > MAX_LIVE_SESSIONS {
            if let Some(old) = bindings.order.pop_front() {
                if let Some(sid) = bindings.map.remove(&old) {
                    evicted.push(sid);
                }
            }
        }
        (token, evicted)
    }

    /// The session a request runs under: its token's, or the guest for a
    /// token that is absent, unknown, or evicted.
    fn resolve(&self, token: Option<&str>) -> SessionId {
        token.and_then(|t| self.bindings.lock().map.get(t).copied()).unwrap_or(self.guest)
    }
}

/// One unpredictable `u64` from the standard library's own entropy — the
/// source both halves of a token draw from, and no new dependency.
fn unpredictable_u64() -> u64 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    RandomState::new().build_hasher().finish()
}

/// The daemon's state: the assembled engine, M10's front door, the codec,
/// and the token → session binding. Socket-free — [`Daemon::route`] is the
/// entire HTTP surface as a request→reply function over this state, with no
/// socket in its signature. Not a PURE one: see [`Daemon::route`].
pub struct Daemon {
    engine: Engine,
    /// M10's front door — the operation surface every frame executes
    /// against. `op` throughout this crate names an operation or its kind
    /// (`Op`, `OpKind`, `op_name`, the wire's own `"op"` field), so the
    /// boundary takes the boundary's name.
    febe: Operation<World>,
    codec: JsonCodec,
    /// The token ↔ session binding and the guest policy over it.
    sessions: Sessions,
    /// The write path: the serialization point, the commit-metadata sidecar
    /// behind `GET /changes` and `head_time` (wire v6), and the commit feed
    /// behind `GET /events` (wire v4). One field because the three are one
    /// ordering — commit, record, announce — that no handler may take apart.
    writes: WritePath,
    /// The history surface behind `/op-at` and `/dump?at`, holding its own
    /// reconstruction budget: neither route needs a session and replay is
    /// per-call uncached, so without that budget any local caller could pin
    /// every worker on reconstruction.
    history: History,
}

/// Deliberately opaque: reporting the log position would take the kernel's
/// lock, and a `Debug` that can block is one that turns `dbg!` into a
/// hazard. [`Daemon::log_position`] is how you ask.
impl std::fmt::Debug for Daemon {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Daemon").finish_non_exhaustive()
    }
}

impl Daemon {
    /// Open (genesis or recover) the one world at `data_dir`, replay the
    /// commit-metadata sidecar, and assemble the operation surface. Every
    /// [`DaemonError`] is an operator-intervention condition — surface it
    /// and exit, never retry.
    ///
    /// The sidecar replay is the one step here whose cost is not O(1) in
    /// the data dir: where commit metadata is missing it reconstructs the
    /// uncovered positions from the journal, one whole-world replay each,
    /// up to the retained window (`CHECKPOINT_EVERY_COMMITS` ×
    /// `RETAINED_CHECKPOINTS`). `Sidecar::open` states the bound.
    pub fn open(data_dir: &Path) -> Result<Daemon, DaemonError> {
        let cfg = KernelConfig {
            durability: Durability::Fsync {
                journal_path: data_dir.to_path_buf(),
                retain_checkpoints: RETAINED_CHECKPOINTS,
                burned_seq: BurnedSeqPolicy::Rollback,
            },
            checkpoint: CheckpointPolicy::EveryN(CHECKPOINT_EVERY_COMMITS),
        };
        let engine = Engine::open(cfg, GenesisConfig::standard()).map_err(DaemonError::Engine)?;
        let writes = WritePath::open(data_dir, &engine).map_err(DaemonError::Sidecar)?;
        let febe = Operation::new(Box::new(engine.stores()));
        // Mint-and-retire the guest binding; the principal value never
        // reaches a store (the binding is dropped before any request runs).
        let guest = febe.open_session(PrincipalId(u64::MAX));
        febe.close_session(guest);
        Ok(Daemon {
            engine,
            febe,
            codec: JsonCodec,
            sessions: Sessions::new(guest),
            writes,
            history: History::new(),
        })
    }

    /// The world as of a committed position — the same bounded replay
    /// `POST /op-at` answers from, for embedders that want the state rather
    /// than a wire answer. Unbudgeted: the reconstruction permit bounds
    /// concurrent HTTP callers, and an embedder calling this holds the
    /// daemon itself.
    pub fn world_at(&self, at: Seq) -> Result<World, HistoryError> {
        self.engine.world_at(at)
    }

    /// Current log position (M10's `log_position`; never regresses).
    pub fn log_position(&self) -> Seq {
        self.febe.log_position()
    }

    /// The router — the whole HTTP surface, still socket-free: the one
    /// route that cannot be a request/response `Reply` (`GET /events`, an
    /// unbounded response) is returned as its own [`Routed`] variant, and
    /// the accept path owns the socket from there.
    ///
    /// A COMMAND, not a query. `POST /op` commits to the journal, records
    /// the change-feed entry, and announces the commit; `POST /session`
    /// mints an M10 session and may retire an evicted one. So routing one
    /// write frame twice COMMITS TWICE unless the frame carries an
    /// idempotency `id` (wire.md §Correlation and idempotency) — a
    /// speculative retry after a timeout duplicates the insert or mints a
    /// second document. The remaining routes are queries.
    pub fn route(&self, req: &HttpRequest) -> Routed {
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/events") => Routed::EventStream,
            _ => Routed::Reply(self.reply(req)),
        }
    }

    /// The request/response routes — every method/path pair but the event
    /// stream, decided in one match.
    fn reply(&self, req: &HttpRequest) -> Reply {
        match (req.method.as_str(), req.path.as_str()) {
            // CORS preflight (wire v4): 204 on any known path; an unknown
            // path falls through to the ordinary 404 below.
            ("OPTIONS", p) if path_is_known(p) => Reply::preflight(),
            ("POST", "/session") => self.post_session(&req.body),
            ("POST", "/op") => self.post_op(req.session_token.as_deref(), &req.body),
            ("POST", "/op-at") => self.post_op_at(&req.body),
            ("GET", "/health") => self.get_health(),
            ("GET", "/changes") => self.get_changes(req.query.as_deref()),
            #[cfg(feature = "observe")]
            ("GET", "/dump") => self.get_dump(req.query.as_deref()),
            #[cfg(feature = "client")]
            ("GET", "/") => {
                Reply::bodied(200, "text/html; charset=utf-8", BOARD_HTML.as_bytes().to_vec())
            }
            (_, p) if path_is_known(p) => refuse(
                TransportError::MethodNotAllowed,
                Some("see wire.md for the endpoint list"),
            ),
            _ => refuse(TransportError::NoSuchEndpoint, Some(&req.path)),
        }
    }

    /// `POST /session` — bind a named principal (local trust: the client
    /// names it), return the opaque token and echo the principal so the
    /// client can name its own account in `principal_prefix`.
    fn post_session(&self, body: &[u8]) -> Reply {
        let principal = match session_principal(body) {
            Ok(p) => p,
            Err(detail) => {
                return refuse(TransportError::MalformedSessionRequest, Some(&detail))
            }
        };
        let sid = self.febe.open_session(PrincipalId(principal));
        let (token, evicted) = self.sessions.bind(sid);
        // The transport obligation M10 names: nothing else retires a
        // binding, and an evicted token can never be presented again, so
        // its session and its idempotency entries go with it.
        for dead in evicted {
            self.febe.close_session(dead);
        }
        Reply::json(
            200,
            obj(vec![
                ("principal", Value::Number(principal.into())),
                ("session", Value::String(token)),
            ]),
        )
    }

    /// `POST /op` — one frame in, one marshaled `Response` out; the HTTP
    /// exchange is the correlation envelope. Every inbound frame gets
    /// exactly one response: parsed → `execute`'s answer; unparseable → the
    /// `Unparseable` rejection, marshaled the same way.
    ///
    /// A write additionally goes through [`WritePath::commit`], which owns
    /// the ordering the change feed and the commit stream both rest on:
    /// commit, record, announce, under one lock. Reads execute directly and
    /// take no lock — a read has no position of its own to record or
    /// announce. `/op` is the daemon's only live write path, so this is
    /// complete: no head advance goes unannounced.
    fn post_op(&self, token: Option<&str>, body: &[u8]) -> Reply {
        let sid = self.sessions.resolve(token);
        let resp = match self.codec.parse(body) {
            Ok(req) => match write_meta(&req.op) {
                None => self.febe.execute(sid, req),
                Some((kind, docs)) => {
                    self.writes.commit(kind, docs, || self.febe.execute(sid, req))
                }
            },
            Err(e) => self.codec.unparseable(e),
        };
        self.op_reply(&resp)
    }

    /// One marshaled operation answer as its reply — always `200`, whatever
    /// the `Response` says: the envelope, not the HTTP status, is the
    /// operation protocol.
    fn op_reply(&self, resp: &Response) -> Reply {
        Reply::bodied(200, "application/json", self.codec.marshal(resp))
    }

    /// TEST HOOK (the `fuzz_support` standing: `#[doc(hidden)]`, not a
    /// stable API): hold one reconstruction permit exactly as an in-flight
    /// reconstruction does, or `None` when the whole budget is taken. Real
    /// reconstructions finish in milliseconds, so the integration tests pin
    /// the counter through this instead of racing the engine.
    #[doc(hidden)]
    pub fn try_hold_reconstruction_permit(&self) -> Option<ReconstructPermit<'_>> {
        self.history.try_hold_permit()
    }

    /// `POST /op-at` — answer one READ frame as of a committed position:
    /// envelope `{"at": <position>, "frame": {<op>}}`. The frame goes through
    /// the same codec as `/op`; the answer is the same response document with
    /// `as_of` reporting `at`. History is not a place you can act — a write
    /// frame is a transport-level 400 before anything runs; an unparseable
    /// frame gets the same `unparseable` rejection `/op` gives it.
    fn post_op_at(&self, body: &[u8]) -> Reply {
        let (at, frame) = match op_at_envelope(body) {
            Ok(x) => x,
            Err(detail) => return refuse(TransportError::MalformedOpAt, Some(&detail)),
        };
        let req = match self.codec.parse_frame(frame) {
            Ok(r) => r,
            Err(e) => return self.op_reply(&self.codec.unparseable(e)),
        };
        if !op_is_read(&req.op) {
            // The ruling-fixed body, exactly: {"error": "write_at_history"}.
            return refuse(TransportError::WriteAtHistory, None);
        }
        match self.history.read_at(&self.engine, at, req) {
            Ok(resp) => self.op_reply(&resp),
            Err(e) => unavailable_reply(e),
        }
    }

    fn get_health(&self) -> Reply {
        // The head position's recorded wall-clock time (wire v6) — null
        // when the head's own record is bare or nothing is recorded at all
        // (a fresh world): transport metadata, never invented, and never
        // an older position's time standing in for the head's.
        let head_time =
            self.writes.head_time().map(|t| Value::Number(t.into())).unwrap_or(Value::Null);
        Reply::json(
            200,
            obj(vec![
                ("head_time", head_time),
                ("log_position", Value::Number(self.febe.log_position().0.into())),
                ("ok", Value::Bool(true)),
            ]),
        )
    }

    /// `GET /changes?since=N[&limit=K]` (wire v6) — the delta read: the
    /// committed positions in `(N, head]`, oldest first, from the sidecar.
    /// Pure parse/marshal over [`Sidecar::changes`]; determinism is the
    /// map's (same journal + sidecar ⇒ byte-equal pages, across restarts).
    fn get_changes(&self, query: Option<&str>) -> Reply {
        let (since, limit) = match changes_params(query) {
            Ok(x) => x,
            Err(detail) => return refuse(TransportError::MalformedChanges, Some(&detail)),
        };
        match self.writes.changes(since, limit) {
            ChangesAnswer::Reclaimed { floor } => reclaimed_reply(floor),
            ChangesAnswer::Page { entries, last, more } => Reply::json(
                200,
                obj(vec![
                    (
                        "changes",
                        Value::Array(entries.iter().map(|(at, meta)| meta.entry(*at)).collect()),
                    ),
                    ("last", Value::Number(last.into())),
                    ("more", Value::Bool(more)),
                ]),
            ),
        }
    }

    /// `GET /dump` — the engine's deterministic `WorldDump` of the committed
    /// world; `GET /dump?at=N` the dump of the world as of position `N`
    /// (bounded replay — same determinism, two equal `N`s are byte-equal and
    /// `N` = head equals the plain dump). Exists only in `observe` builds.
    #[cfg(feature = "observe")]
    fn get_dump(&self, query: Option<&str>) -> Reply {
        let at = match dump_at_param(query) {
            Ok(x) => x,
            Err(detail) => return refuse(TransportError::MalformedAt, Some(&detail)),
        };
        let dump = match at {
            None => self.engine.world_dump(),
            Some(at) => match self.history.dump_at(&self.engine, at) {
                Ok(d) => d,
                Err(e) => return unavailable_reply(e),
            },
        };
        Reply::bodied(200, "text/plain; charset=utf-8", dump.into_string().into_bytes())
    }
}

/// Strictly `{"principal": <non-negative integer>}`.
fn session_principal(body: &[u8]) -> Result<u64, String> {
    let v: Value =
        serde_json::from_slice(body).map_err(|e| format!("invalid JSON: {e}"))?;
    let Value::Object(m) = v else {
        return Err("session request must be a JSON object".into());
    };
    check_keys(&m, &["principal"])?;
    m.get("principal")
        .and_then(Value::as_u64)
        .ok_or_else(|| "missing or non-integer field 'principal'".into())
}

// ── the change feed (wire v6) ────────────────────────────────────────────

/// A query string as its parameter list — `k=v` pairs split on `&`, shape
/// checked and nothing else. Every query this daemon reads walks this, so
/// one discipline covers them all and each parser adds only its own
/// vocabulary: an unknown or repeated parameter is a named refusal, which
/// is the wire's never-silent posture applied to queries.
fn query_pairs(q: &str) -> Result<Vec<(&str, &str)>, String> {
    q.split('&')
        .map(|pair| pair.split_once('=').ok_or_else(|| format!("malformed parameter '{pair}'")))
        .collect()
}

/// The `/changes` query: `since=<position>` (required) plus optional
/// `limit=<1..=4096>`.
fn changes_params(query: Option<&str>) -> Result<(u64, usize), String> {
    let q = match query {
        None | Some("") => {
            return Err("the required parameter is since=<position>".into());
        }
        Some(q) => q,
    };
    let mut since: Option<u64> = None;
    let mut limit: Option<usize> = None;
    for (k, v) in query_pairs(q)? {
        match k {
            "since" => {
                if since.is_some() {
                    return Err("duplicate parameter 'since'".into());
                }
                since = Some(v.parse().map_err(|_| {
                    format!("since: '{v}' is not a position (a non-negative integer)")
                })?);
            }
            "limit" => {
                if limit.is_some() {
                    return Err("duplicate parameter 'limit'".into());
                }
                let n: usize = v
                    .parse()
                    .map_err(|_| format!("limit: '{v}' is not a count"))?;
                if n == 0 || n > CHANGES_LIMIT_MAX {
                    return Err(format!("limit: must be 1..={CHANGES_LIMIT_MAX}"));
                }
                limit = Some(n);
            }
            other => return Err(format!("unknown parameter '{other}'")),
        }
    }
    let since = since.ok_or_else(|| String::from("the required parameter is since=<position>"))?;
    Ok((since, limit.unwrap_or(CHANGES_LIMIT_DEFAULT)))
}

// ── the history surface (wire v3) ────────────────────────────────────────

/// Strictly `{"at": <non-negative integer>, "frame": <object>}`; returns the
/// position and the frame, which the codec parses from here. The
/// object-ness check is a decision, not duplicated validation: a non-object
/// `frame` is a malformed ENVELOPE (a transport fault), where the same
/// value reaching the codec would be an operation-channel rejection.
fn op_at_envelope(body: &[u8]) -> Result<(Seq, Value), String> {
    let v: Value =
        serde_json::from_slice(body).map_err(|e| format!("invalid JSON: {e}"))?;
    let Value::Object(mut m) = v else {
        return Err("op-at envelope must be a JSON object".into());
    };
    check_keys(&m, &["at", "frame"])?;
    let at = m
        .get("at")
        .and_then(Value::as_u64)
        .ok_or_else(|| String::from("missing or non-integer field 'at'"))?;
    let frame = m.remove("frame").ok_or_else(|| String::from("missing field 'frame'"))?;
    if !frame.is_object() {
        return Err("field 'frame' must be a JSON object (an /op frame)".into());
    }
    Ok((Seq(at), frame))
}

/// The `/dump` query: nothing, or exactly `at=<decimal position>`.
#[cfg(feature = "observe")]
fn dump_at_param(query: Option<&str>) -> Result<Option<Seq>, String> {
    let q = match query {
        None | Some("") => return Ok(None),
        Some(q) => q,
    };
    let mut at: Option<Seq> = None;
    for (k, v) in query_pairs(q)? {
        match k {
            "at" => {
                if at.is_some() {
                    return Err("duplicate parameter 'at'".into());
                }
                at = Some(Seq(v.parse().map_err(|_| {
                    format!("at: '{v}' is not a position (a non-negative integer)")
                })?));
            }
            other => {
                return Err(format!(
                    "unknown parameter '{other}'; the one /dump parameter is at=<position>"
                ))
            }
        }
    }
    Ok(at)
}

/// The `410 history_reclaimed` refusal: the position asked for is older
/// than what can still be answered, and `floor` — when one exists — names
/// the oldest that can. One construction, shared by the history surface and
/// the change feed, so the two cannot describe the same condition
/// differently.
fn reclaimed_reply(floor: Option<u64>) -> Reply {
    let fields = match floor {
        Some(f) => vec![("floor", Value::Number(f.into()))],
        None => Vec::new(),
    };
    refuse_with(TransportError::HistoryReclaimed, fields)
}

/// Map an unavailable historical answer onto the wire's transport errors —
/// the one place the history surface's `Unavailable` becomes HTTP. The
/// ruling-fixed `beyond_head` body is emitted exactly as specified; the
/// rest are this daemon's own wire decisions, documented in wire.md
/// §Reading history. `history_busy` is the one retry-class error: the
/// position may be perfectly good and the daemon momentarily saturated.
///
/// It is also the FIRST refusal: the reconstruction permit is taken before
/// the journal sees `at`, so under saturation a position beyond the head,
/// between commits, or long reclaimed is answered `history_busy` — retry
/// advice for a fault that is permanent. The retry is what learns
/// otherwise; nothing here can say so sooner without re-deriving a bound
/// the engine owns.
fn unavailable_reply(e: Unavailable) -> Reply {
    let journal = match e {
        Unavailable::Busy => {
            return refuse(
                TransportError::HistoryBusy,
                Some("all reconstruction permits are in use; retry shortly"),
            )
        }
        Unavailable::Journal(e) => e,
    };
    match journal {
        HistoryError::BeyondHead { head } => refuse_with(
            TransportError::BeyondHead,
            vec![("head", Value::Number(head.0.into()))],
        ),
        HistoryError::NotABoundary { nearest } => refuse_with(
            TransportError::NotAPosition,
            vec![("nearest", Value::Number(nearest.0.into()))],
        ),
        HistoryError::Reclaimed { floor } => reclaimed_reply(floor.map(|f| f.0)),
        // Unreachable under this daemon's Fsync configuration; mapped so the
        // surface stays total over the engine's error type.
        HistoryError::Unjournaled => refuse(
            TransportError::NoJournal,
            Some("this daemon holds no journal; history is unavailable"),
        ),
        HistoryError::Io(err) => refuse(TransportError::HistoryIo, Some(&err.to_string())),
        HistoryError::Corruption { at, .. } => refuse(
            TransportError::HistoryCorrupt,
            Some(&format!("journal corrupt at rest; next intact frame at {}", at.0)),
        ),
    }
}

// ── the wire loop ────────────────────────────────────────────────────────

/// The running server: the listener, the op workers, the daemon, and the
/// event-stream subscriber threads.
pub struct Skepd {
    daemon: Arc<Daemon>,
    /// Held, never read: the workers own clones, so this handle is what
    /// keeps [`Skepd::port`] bound for exactly as long as the server value
    /// exists rather than only while a worker survives.
    _listener: Arc<TcpListener>,
    workers: Vec<JoinHandle<()>>,
    subscribers: Arc<Subscribers>,
    stop: Arc<AtomicBool>,
    port: u16,
}

/// The bound port and the worker count — no lock is taken, so this is safe
/// to reach for from anywhere, including a thread that already holds one.
impl std::fmt::Debug for Skepd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Skepd")
            .field("port", &self.port)
            .field("workers", &self.workers.len())
            .finish_non_exhaustive()
    }
}

/// Bind `127.0.0.1:port` (`0` = ephemeral) and serve with `workers`
/// threads. Concurrency policy in full: each worker blocks in `accept`,
/// serves the one request on that connection, closes it — one request per
/// connection, `Connection: close` on every response (`Operation::execute`
/// is `Sync` and M2's single applier serializes writes, so the worker count
/// is the whole op-concurrency story). `GET /events` is the one exception
/// to request/response: the worker hands the socket to a dedicated
/// subscriber thread and returns to `accept` at once, so open streams never
/// occupy the op pool.
///
/// PRECONDITION: `workers >= 1`. A count of zero asks for a server that
/// serves nothing, which is a caller's bug rather than an outcome, so it
/// stops here loudly instead of being repaired into a one-worker server —
/// the same posture `CHANGES_LIMIT_MAX` takes on the wire, where an
/// out-of-range page size is refused and never clamped. `main.rs`
/// establishes it by refusing a zero count where the flag is read, which is
/// also what makes its startup line's worker count honest.
///
/// Failure is exactly the socket's: binding the address, or reading back
/// the port it bound. Naming `io::Error` rather than boxing it is what lets
/// a caller dispatch on `ErrorKind` — `AddrInUse` to try the next port,
/// `PermissionDenied` for a privileged one — without a downcast.
pub fn serve(daemon: Daemon, port: u16, workers: usize) -> io::Result<Skepd> {
    assert!(workers >= 1, "serve requires at least one worker thread (workers = 0)");
    let daemon = Arc::new(daemon);
    let listener = Arc::new(TcpListener::bind(("127.0.0.1", port))?);
    let port = listener.local_addr()?.port();
    let stop = Arc::new(AtomicBool::new(false));
    let subscribers = Arc::new(Subscribers::new());
    let handles = (0..workers)
        .map(|_| {
            let daemon = Arc::clone(&daemon);
            let listener = Arc::clone(&listener);
            let stop = Arc::clone(&stop);
            let subscribers = Arc::clone(&subscribers);
            thread::spawn(move || loop {
                if stop.load(Ordering::Acquire) {
                    break;
                }
                let stream = match listener.accept() {
                    Ok((s, _)) => s,
                    Err(_) => {
                        // Transient accept failure (EMFILE and kin): brief
                        // pause instead of a spin, then re-check stop.
                        thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                };
                // Shutdown's wake connect lands here: the flag, not the
                // connection, is the signal.
                if stop.load(Ordering::Acquire) {
                    break;
                }
                serve_connection(&daemon, &subscribers, stream);
            })
        })
        .collect();
    Ok(Skepd { daemon, _listener: listener, workers: handles, subscribers, stop, port })
}

impl Skepd {
    /// The bound port (useful under `port = 0`).
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The served daemon, borrowed for the server's lifetime — long enough
    /// to ask it anything, and not long enough to outlive [`Skepd::shutdown`],
    /// whose last act releases the kernel's journal-directory lock.
    pub fn daemon(&self) -> &Daemon {
        &self.daemon
    }

    /// Block until the workers exit — the binary's foreground call, which
    /// returns when something else stops the server. Crash-stop is the
    /// shutdown story: M2's WAL makes recovery the clean path, so no signal
    /// machinery. Returning ends every event stream too, since the server
    /// is dropped here.
    pub fn wait(mut self) {
        for h in self.workers.drain(..) {
            let _ = h.join();
        }
    }

    /// Orderly stop for embedders and tests: release and join the op
    /// workers, then end every event stream — the feed broadcast wakes each
    /// subscriber, which drops its socket (the client sees a clean close)
    /// and exits — and join those threads too. Returning releases the
    /// kernel's journal-directory lock, so the same data dir can be
    /// reopened. Bounded: nothing here waits on a client.
    ///
    /// Calling it is how a caller learns the stop *finished*; a server that
    /// is merely dropped stops the same way, so a panic between [`serve`]
    /// and here cannot leak the threads or strand the lock.
    pub fn shutdown(mut self) {
        self.stop_and_join();
    }

    /// The whole stop, against `&mut self` so both [`Skepd::shutdown`] and
    /// `Drop` run it. Idempotent through the flag it already owns: a
    /// dropped-after-shutdown server takes the early return, and the joins
    /// have already happened.
    fn stop_and_join(&mut self) {
        if self.stop.swap(true, Ordering::AcqRel) {
            return;
        }
        // One wake connect per worker: a worker blocked in `accept` returns
        // and the flag breaks its loop. A worker mid-request exits at its
        // next loop check instead, leaving its wake connect unclaimed in
        // the backlog — harmless; the listener drops with the struct.
        for _ in 0..self.workers.len() {
            let _ = TcpStream::connect(("127.0.0.1", self.port));
        }
        for h in self.workers.drain(..) {
            let _ = h.join();
        }
        // The workers are gone, so no new subscriber can appear past here.
        self.daemon.writes.shutdown();
        self.subscribers.join_all();
    }
}

/// The threads, the listener and the journal-directory lock are released by
/// dropping the server, not by remembering to ask — so an unwinding test or
/// an early return leaves nothing running and nothing locked. Panic-free by
/// construction (the locks do not poison, and every join and connect is
/// discarded), so it is safe during an unwind.
impl Drop for Skepd {
    fn drop(&mut self) {
        self.stop_and_join();
    }
}

/// Serve one connection: read the one request, route it, write the one
/// reply, close — or, for `GET /events`, hand the socket to a dedicated
/// subscriber thread and return at once. A handler panic is contained to a
/// 500 so one bad request cannot take a worker down; the panic still prints
/// to stderr for the operator.
fn serve_connection(daemon: &Arc<Daemon>, subscribers: &Subscribers, mut stream: TcpStream) {
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(REQUEST_READ_TIMEOUT));
    let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));
    let req = match read_request(&mut stream) {
        Ok(Some(r)) => r,
        // Clean close before any byte (a port probe, shutdown's wake
        // connect): no request, so no reply owed.
        Ok(None) => return,
        Err(refusal) => {
            let reply = match refusal {
                ReadError::Malformed(detail) => {
                    refuse(TransportError::MalformedHttp, Some(&detail))
                }
                ReadError::BodyTooLarge(declared) => {
                    let detail = format!(
                        "Content-Length {declared} exceeds the {MAX_REQUEST_BODY}-byte body cap"
                    );
                    refuse(TransportError::PayloadTooLarge, Some(&detail))
                }
            };
            let _ = write_reply(&mut stream, &reply);
            return;
        }
    };
    let routed = match catch_unwind(AssertUnwindSafe(|| daemon.route(&req))) {
        Ok(r) => r,
        Err(_) => Routed::Reply(refuse(TransportError::InternalPanic, None)),
    };
    match routed {
        Routed::Reply(reply) => {
            let _ = write_reply(&mut stream, &reply);
        }
        Routed::EventStream => subscribers.admit(Arc::clone(daemon), stream),
    }
}

/// Live `GET /events` streams served at once. Each costs one OS thread and
/// holds one descriptor for as long as its client keeps reading, so without
/// a bound a caller opening streams consumes both until one runs out — and
/// the two run out differently. At the descriptor wall `accept` degrades
/// gracefully (the worker loop pauses and retries); a refused thread does
/// not degrade at all, which is why the spawn in [`Subscribers::admit`] is
/// fallible and why this cap sits above it.
///
/// The number reserves the rest of the process's descriptors for the work
/// the daemon exists to do: against the 256 soft limit still common on the
/// platforms this ships to, 64 streams leave the listener and the op pool
/// three quarters of the table. It is an order of magnitude above what a
/// browser will hold against one origin (~6 connections) and above any
/// plausible fleet of local subscribers, so a client reaches it only by
/// trying to.
const MAX_SUBSCRIBERS: usize = 64;

/// The live event streams: the budget, the admission, and the retirement.
/// One card, because a stream admitted here is one shutdown must join, and
/// a slot is free only once the thread that held it has finished — two
/// facts about one set that a bare handle vector states neither of.
struct Subscribers {
    live: Mutex<Vec<JoinHandle<()>>>,
}

impl Subscribers {
    fn new() -> Subscribers {
        Subscribers { live: Mutex::new(Vec::new()) }
    }

    /// Admit one stream and give it its own thread, or refuse it by dropping
    /// the socket — a clean close before any stream head, which is the same
    /// end a subscriber meets at shutdown and the one a reconnecting client
    /// already handles.
    fn admit(&self, daemon: Arc<Daemon>, stream: TcpStream) {
        let mut live = self.live.lock();
        // Reap finished threads so the registry tracks live streams, not
        // history — which is also what returns a departed subscriber's slot.
        live.retain(|h| !h.is_finished());
        if live.len() >= MAX_SUBSCRIBERS {
            return;
        }
        // Spawn FALLIBLY. `thread::spawn` panics when the OS refuses a
        // thread, and this call sits outside the handler's `catch_unwind` —
        // a panic here would unwind the worker's accept loop and retire the
        // worker for the life of the process, so a transient resource
        // condition would become a permanent, silent loss of capacity with
        // the listener still bound. A refusal must cost one stream, never a
        // worker; the failed spawn drops the closure and with it the socket,
        // which is the clean close above.
        if let Ok(h) = thread::Builder::new().spawn(move || serve_events(&daemon, stream)) {
            live.push(h);
        }
    }

    /// Join every live subscriber. Called after the feed has broadcast its
    /// shutdown, so each is already awake and on its way out — which is what
    /// keeps this bounded rather than a wait on a client.
    fn join_all(&self) {
        for h in std::mem::take(&mut *self.live.lock()) {
            let _ = h.join();
        }
    }
}

/// A refused request read: which transport-error reply the connection is
/// owed. Everything malformed is one bucket; the body cap gets its own
/// honest disposition (`413 payload_too_large`), not a generic parse error.
enum ReadError {
    /// Not the HTTP subset this daemon speaks → `400 malformed_http`.
    Malformed(String),
    /// The declared `Content-Length` exceeds [`MAX_REQUEST_BODY`] →
    /// `413 payload_too_large`. Raised before any body byte is read.
    BodyTooLarge(usize),
}

impl From<String> for ReadError {
    fn from(detail: String) -> ReadError {
        ReadError::Malformed(detail)
    }
}

impl From<&str> for ReadError {
    fn from(detail: &str) -> ReadError {
        ReadError::Malformed(detail.into())
    }
}

/// Read one request off the socket. `Ok(None)` = clean close before any
/// byte; `Err(_)` = the request is refused (the caller answers the
/// [`ReadError`]'s reply and closes). The subset: one request per
/// connection, HTTP/1.0 or 1.1, bodies by `Content-Length` (absent =
/// empty, capped at [`MAX_REQUEST_BODY`]), `Expect: 100-continue`
/// honored, `Transfer-Encoding` refused.
///
/// Each header this daemon READS — `Content-Length`, `Skepd-Session`,
/// `Expect` — may appear at most once; a repeat is `malformed_http`, the
/// same never-silent treatment a duplicate query parameter and an unknown
/// frame field already get. Headers this daemon does not read pass unread
/// however often they appear.
fn read_request(stream: &mut TcpStream) -> Result<Option<HttpRequest>, ReadError> {
    // The head, plus whatever early body bytes arrived with it.
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let head_end = loop {
        if let Some(i) = find_head_end(&buf) {
            break i;
        }
        if buf.len() > MAX_REQUEST_HEAD {
            return Err(format!("request head exceeds the {MAX_REQUEST_HEAD}-byte cap").into());
        }
        let mut chunk = [0u8; 4096];
        match stream.read(&mut chunk) {
            Ok(0) if buf.is_empty() => return Ok(None),
            Ok(0) => return Err("connection closed inside the request head".into()),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) if buf.is_empty() => return Ok(None),
            Err(e) => return Err(format!("read: {e}").into()),
        }
    };
    let head = std::str::from_utf8(&buf[..head_end])
        .map_err(|_| String::from("request head is not UTF-8"))?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or("").to_string();
    let target = parts
        .next()
        .ok_or_else(|| String::from("request line lacks a target"))?
        .to_string();
    let version = parts
        .next()
        .ok_or_else(|| String::from("request line lacks an HTTP version"))?;
    if parts.next().is_some() {
        return Err("malformed request line".into());
    }
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(format!("unsupported protocol '{version}'").into());
    }
    if method.is_empty() || !method.bytes().all(|b| b.is_ascii_uppercase()) {
        return Err("malformed method token".into());
    }
    // The headers this daemon acts on; everything else passes unread, as
    // HTTP requires. Each of the three is read through `once`, so a repeat
    // is a named refusal rather than a silent last-wins — two conflicting
    // `Content-Length`s otherwise pick between a stalled read and a
    // truncated frame by which line came last, and answer the same
    // malformed head with two different diagnoses.
    let mut content_length: Option<usize> = None;
    let mut session_token: Option<String> = None;
    let mut expects_continue: Option<bool> = None;
    fn once<T>(slot: &Option<T>, name: &str) -> Result<(), ReadError> {
        match slot {
            Some(_) => Err(format!("duplicate header '{name}'").into()),
            None => Ok(()),
        }
    }
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| format!("malformed header line '{line}'"))?;
        let (name, value) = (name.trim(), value.trim());
        if name.eq_ignore_ascii_case("Content-Length") {
            once(&content_length, name)?;
            content_length =
                Some(value.parse().map_err(|_| format!("bad Content-Length '{value}'"))?);
        } else if name.eq_ignore_ascii_case(SESSION_HEADER) {
            once(&session_token, name)?;
            session_token = Some(value.to_string());
        } else if name.eq_ignore_ascii_case("Expect") {
            once(&expects_continue, name)?;
            expects_continue = Some(value.eq_ignore_ascii_case("100-continue"));
        } else if name.eq_ignore_ascii_case("Transfer-Encoding") {
            return Err("chunked request bodies are unsupported; send Content-Length".into());
        }
    }
    let expects_continue = expects_continue.unwrap_or(false);
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), Some(q.to_string())),
        None => (target, None),
    };
    let mut body = buf[head_end + 4..].to_vec();
    let declared = content_length.unwrap_or(0);
    // The one unbounded-allocation vector: refuse on the declared length
    // alone, before 100-continue invites the body and before the loop reads
    // (and allocates) a single byte of it. The media round's blob upload
    // will raise this for its route only.
    if declared > MAX_REQUEST_BODY {
        return Err(ReadError::BodyTooLarge(declared));
    }
    if expects_continue && body.len() < declared {
        // The client is holding the body until told to send it (curl does
        // this for large payloads).
        if stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").is_err() {
            return Err("client went away at 100-continue".into());
        }
    }
    while body.len() < declared {
        let mut chunk = [0u8; 8192];
        match stream.read(&mut chunk) {
            Ok(0) => return Err("connection closed inside the request body".into()),
            Ok(n) => body.extend_from_slice(&chunk[..n]),
            Err(e) => return Err(format!("read: {e}").into()),
        }
    }
    // A byte past Content-Length would be a pipelined second request; this
    // connection answers one and closes, so it is dropped unread.
    body.truncate(declared);
    Ok(Some(HttpRequest { method, path, query, session_token, body }))
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Write one complete reply; the connection closes behind it. Every
/// response carries `Access-Control-Allow-Origin: *` — wire v4's CORS
/// posture, enforced at this one choke point so no reply can miss it — and
/// `Connection: close` (one request per connection). A bodiless reply
/// carries no content headers (RFC 7230's 204).
fn write_reply(stream: &mut TcpStream, reply: &Reply) -> io::Result<()> {
    let mut head = Vec::with_capacity(256);
    head.extend_from_slice(
        format!("HTTP/1.1 {} {}\r\n", reply.status, reason(reply.status)).as_bytes(),
    );
    head.extend_from_slice(b"Access-Control-Allow-Origin: *\r\n");
    for (name, value) in &reply.headers {
        head.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    // The body and the headers describing it come from one value, so the
    // two cannot disagree about whether there is one.
    if let Some(c) = &reply.content {
        head.extend_from_slice(
            format!("Content-Type: {}\r\nContent-Length: {}\r\n", c.content_type, c.bytes.len())
                .as_bytes(),
        );
        head.extend_from_slice(b"Connection: close\r\n\r\n");
        // The body is written FROM the reply rather than copied into this
        // buffer first. The largest answer this daemon serves is a whole
        // world dump, and assembling one buffer would hold two copies of
        // it at once — per in-flight request, on a route that needs no
        // session. `set_nodelay` is on, so the cost is the second write
        // call and nothing else.
        stream.write_all(&head)?;
        stream.write_all(&c.bytes)
    } else {
        head.extend_from_slice(b"Connection: close\r\n\r\n");
        stream.write_all(&head)
    }
}

/// The subset's reason phrases — informational only; clients dispatch on
/// the code.
fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        410 => "Gone",
        413 => "Payload Too Large",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

/// One subscriber (wire v4): write the stream head and the initial event
/// carrying the current head, then follow the feed — a `commit` event when
/// the head advances, a `:ka` comment on silence — until shutdown or the
/// first failed write (a gone subscriber). Exiting drops the socket, which
/// is the client's end-of-stream. Coalescing is inherent: the feed answers
/// "anything past what I last sent", so a burst of commits is one event.
fn serve_events(daemon: &Daemon, mut stream: TcpStream) {
    let head = "HTTP/1.1 200 OK\r\n\
                Access-Control-Allow-Origin: *\r\n\
                Content-Type: text/event-stream\r\n\
                Cache-Control: no-cache\r\n\
                Connection: close\r\n\r\n";
    if stream.write_all(head.as_bytes()).is_err() {
        return;
    }
    let mut last = daemon.log_position();
    if write_commit_event(&mut stream, last).is_err() {
        return;
    }
    loop {
        match daemon.writes.next(last) {
            FeedStep::Shutdown => return,
            FeedStep::Commit(at) => {
                last = at;
                if write_commit_event(&mut stream, at).is_err() {
                    return;
                }
            }
            FeedStep::Keepalive => {
                if stream.write_all(b":ka\n\n").is_err() {
                    return;
                }
            }
        }
    }
}

/// `event: commit` / `data: {"log_position":N}` / blank — the wire v4
/// event framing, byte-for-byte what wire.md documents (compact JSON, the
/// position alone).
fn write_commit_event(stream: &mut TcpStream, at: Seq) -> std::io::Result<()> {
    stream.write_all(format!("event: commit\ndata: {{\"log_position\":{}}}\n\n", at.0).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every path the router serves. The list is the test's own — an
    /// independent restatement, so a route added to [`path_is_known`] alone
    /// (with no dispatch arm) is caught here rather than answering 405 for
    /// every method.
    const ROUTES: &[&str] = &[
        "/session",
        "/op",
        "/op-at",
        "/health",
        "/events",
        "/changes",
        #[cfg(feature = "observe")]
        "/dump",
        #[cfg(feature = "client")]
        "/",
    ];

    /// One route set, three consequences: a known path preflights, refuses
    /// an unsupported method with `405`, and dispatches at least one real
    /// method; an unknown path is `404` for every method including
    /// `OPTIONS`. This is the invariant [`path_is_known`] exists to keep — a
    /// route stated in one table and forgotten in another breaks exactly
    /// one of these.
    #[test]
    fn the_route_set_agrees_across_preflight_dispatch_and_refusal() {
        let dir = tempfile::tempdir().expect("tempdir");
        let daemon = Daemon::open(dir.path()).expect("genesis open");
        let bare = |method: &str, path: &str| HttpRequest {
            method: method.to_string(),
            path: path.to_string(),
            query: None,
            session_token: None,
            body: Vec::new(),
        };
        let status = |method: &str, path: &str| match daemon.route(&bare(method, path)) {
            Routed::Reply(r) => r.status,
            // The one non-reply route; reached only by GET /events, which
            // this test never asks for.
            Routed::EventStream => 200,
        };
        for path in ROUTES {
            assert!(path_is_known(path), "{path} is served but not known");
            assert_eq!(status("OPTIONS", path), 204, "{path} must answer the CORS preflight");
            assert_eq!(status("PUT", path), 405, "{path} must refuse an unsupported method");
            let served = ["GET", "POST"].iter().any(|m| {
                let s = status(m, path);
                s != 404 && s != 405
            });
            assert!(served, "{path} is known but no method dispatches");
        }
        for unknown in ["/nope", "/op/", "/Health"] {
            assert!(!path_is_known(unknown), "{unknown} must not be known");
            assert_eq!(status("GET", unknown), 404, "{unknown}");
            assert_eq!(status("OPTIONS", unknown), 404, "an unknown path preflights nothing");
        }
    }

    /// The guest policy in one place: an absent or unrecognized token is
    /// the guest (M10 then serves reads and refuses writes), a bound token
    /// is its own session, and two binds never collide.
    #[test]
    fn sessions_resolve_unknown_tokens_to_the_guest() {
        let dir = tempfile::tempdir().expect("tempdir");
        let daemon = Daemon::open(dir.path()).expect("genesis open");
        let guest = daemon.sessions.resolve(None);
        assert_eq!(
            daemon.sessions.resolve(Some("no-such-token")),
            guest,
            "an unknown token is the guest, not an error"
        );
        let sid = daemon.febe.open_session(PrincipalId(7));
        let (token, evicted) = daemon.sessions.bind(sid);
        assert!(evicted.is_empty(), "an unfilled table evicts nothing");
        assert_eq!(daemon.sessions.resolve(Some(&token)), sid, "a bound token is its session");
        let (other, _) = daemon.sessions.bind(daemon.febe.open_session(PrincipalId(8)));
        assert_ne!(token, other, "each binding gets its own token");
    }

    /// The binding table is bounded, and what falls out of it is retired
    /// rather than merely forgotten: `POST /session` is unauthenticated, so
    /// an unbounded map is memory any caller can retain — here and in M10 —
    /// without ever writing. The evicted token resolves to the guest, which
    /// is a state wire.md already documents (an unknown token is not an
    /// error), so the bound narrows retention without narrowing the wire.
    #[test]
    fn the_session_table_is_bounded_and_evicts_oldest_first() {
        let dir = tempfile::tempdir().expect("tempdir");
        let daemon = Daemon::open(dir.path()).expect("genesis open");
        let guest = daemon.sessions.resolve(None);

        let mut tokens = Vec::new();
        for _ in 0..MAX_LIVE_SESSIONS {
            let (t, evicted) = daemon.sessions.bind(daemon.febe.open_session(PrincipalId(1)));
            assert!(evicted.is_empty(), "nothing is evicted up to the bound");
            tokens.push(t);
        }
        assert_eq!(daemon.sessions.bindings.lock().map.len(), MAX_LIVE_SESSIONS);
        assert_ne!(daemon.sessions.resolve(Some(&tokens[0])), guest, "all still live");

        // One past the bound evicts exactly the oldest, and hands it back
        // so the caller can retire it in M10 too.
        let (newest, evicted) = daemon.sessions.bind(daemon.febe.open_session(PrincipalId(2)));
        assert_eq!(evicted.len(), 1, "one in, one out");
        assert_eq!(
            daemon.sessions.resolve(Some(&tokens[0])),
            guest,
            "the oldest token now resolves to the guest, as an unknown token does"
        );
        assert_ne!(
            daemon.sessions.resolve(Some(&tokens[1])),
            guest,
            "and only the oldest went"
        );
        assert_ne!(daemon.sessions.resolve(Some(&newest)), guest, "the newest is live");
        assert_eq!(
            daemon.sessions.bindings.lock().map.len(),
            MAX_LIVE_SESSIONS,
            "the table stays at its bound however many sessions are opened"
        );
    }

    /// A token names no other token: the suffix is drawn fresh per binding,
    /// not counted, so holding one gives a client no way to enumerate the
    /// rest. Nothing on the wire reveals the draw, which is what keeps the
    /// property true when `POST /session` gains a credential.
    #[test]
    fn one_token_does_not_name_the_next() {
        let dir = tempfile::tempdir().expect("tempdir");
        let daemon = Daemon::open(dir.path()).expect("genesis open");
        let mint = || daemon.sessions.bind(daemon.febe.open_session(PrincipalId(1))).0;
        let first = mint();
        let rest: Vec<String> = (0..64).map(|_| mint()).collect();
        let (prefix, suffix) =
            first.split_once('.').expect("a token is <uptime prefix>.<per-token draw>");
        assert!(
            rest.iter().all(|t| t.starts_with(&format!("{prefix}."))),
            "the uptime prefix is shared, so a stale token still misses"
        );
        let next = u64::from_str_radix(suffix, 16).expect("hex suffix").wrapping_add(1);
        let guessed = format!("{prefix}.{next:016x}");
        assert!(
            !rest.contains(&guessed),
            "the token after one you hold is not the one adjacent to it"
        );
        let uniq: std::collections::HashSet<&String> = rest.iter().collect();
        assert_eq!(uniq.len(), rest.len(), "and no two bindings collide");
        // The invariant `Bindings` claims, checked rather than argued: the
        // queue describes exactly the tokens the map holds. Insertion, not
        // the draw, is what keeps the two in step.
        let bindings = daemon.sessions.bindings.lock();
        assert_eq!(
            bindings.map.len(),
            bindings.order.len(),
            "the mint order names each live token exactly once"
        );
    }

    /// A refusal is a status AND a name together: the body is built through
    /// the codec's sorting device (byte-deterministic whatever backs
    /// serde_json's map) and the status comes from the same table the name
    /// does, so the wire.md pairing is checked rather than repeated.
    #[test]
    fn refusals_pair_their_status_with_their_name() {
        let r = refuse(TransportError::PayloadTooLarge, Some("too big"));
        assert_eq!(r.status, 413);
        assert_eq!(
            String::from_utf8(r.body().to_vec()).expect("json"),
            r#"{"detail":"too big","error":"payload_too_large"}"#
        );
        let r = refuse_with(
            TransportError::BeyondHead,
            vec![("head", Value::Number(12u64.into()))],
        );
        assert_eq!(r.status, 400);
        assert_eq!(
            String::from_utf8(r.body().to_vec()).expect("json"),
            r#"{"error":"beyond_head","head":12}"#
        );
    }

    /// The body and the type naming it travel together: a bodiless reply
    /// writes no content headers at all, and a bodied one writes both —
    /// which is what makes "a 204 that silently drops its bytes" and
    /// "`Content-Type:` with nothing after it" unconstructible rather than
    /// merely unwritten.
    #[test]
    fn a_bodiless_reply_writes_no_content_headers() {
        let pre = Reply::preflight();
        assert!(pre.content.is_none(), "the preflight names no body");
        assert!(pre.body().is_empty());
        let json = Reply::json(200, obj(vec![("ok", Value::Bool(true))]));
        let c = json.content.as_ref().expect("a JSON reply names its body");
        assert_eq!(c.content_type, "application/json");
        assert_eq!(c.bytes, br#"{"ok":true}"#);
    }

    /// The preflight advertises exactly the header [`read_request`] reads.
    /// The allow-list is one joined `&'static str`, so the header's name
    /// necessarily appears in it as text rather than as the constant; this
    /// is what keeps the two one decision. A header the preflight omits is
    /// one a browser will not send, and that failure appears only
    /// cross-origin, where this suite's own TCP clients never look.
    #[test]
    fn the_preflight_advertises_the_session_header_the_reader_reads() {
        let pre = Reply::preflight();
        let allow = pre
            .headers
            .iter()
            .find(|(k, _)| *k == "Access-Control-Allow-Headers")
            .map(|&(_, v)| v)
            .expect("the preflight names its allowed headers");
        assert!(allow.contains(SESSION_HEADER), "{allow} must name {SESSION_HEADER}");
    }

    /// A server with no workers serves nothing, so asking for one is the
    /// caller's bug and stops here — never a silent repair into a
    /// one-worker server, which would teach callers that the stated
    /// precondition is not the real one.
    #[test]
    #[should_panic(expected = "at least one worker")]
    fn zero_workers_is_a_callers_bug() {
        let dir = tempfile::tempdir().expect("tempdir");
        let daemon = Daemon::open(dir.path()).expect("genesis open");
        let _ = serve(daemon, 0, 0);
    }

    /// The commit feed announces a position only from the section that
    /// recorded it: a committing write publishes ITS OWN position, and
    /// nothing else publishes at all.
    ///
    /// The read is the load-bearing half, and the head is deliberately
    /// pushed ahead of the feed first — through `febe` directly, the one
    /// path that commits without announcing — because a daemon that
    /// announced the CURRENT HEAD from any `/op` request would look
    /// correct on a quiet socket and wrong under concurrency, leaking a
    /// write another thread had committed but not yet recorded. Here that
    /// gap is opened deliberately instead of raced for.
    #[test]
    fn only_a_committing_write_announces_and_only_its_own_position() {
        let dir = tempfile::tempdir().expect("tempdir");
        let daemon = Daemon::open(dir.path()).expect("genesis open");
        let (token, _) = daemon.sessions.bind(daemon.febe.open_session(PrincipalId(0)));
        let announced = || daemon.writes.announced();
        let post = |body: &str| match daemon.route(&HttpRequest {
            method: "POST".to_string(),
            path: "/op".to_string(),
            query: None,
            session_token: Some(token.clone()),
            body: body.as_bytes().to_vec(),
        }) {
            Routed::Reply(r) => serde_json::from_slice::<Value>(r.body()).expect("json"),
            Routed::EventStream => panic!("POST /op is not the event stream"),
        };

        // Commit past the feed without announcing: this is the state a
        // concurrent write leaves behind between its commit and its record.
        let frame = br#"{"op":"register_node","addr":"1.9001"}"#;
        let req = daemon.codec.parse(frame).unwrap_or_else(|_| panic!("test frame parses"));
        let sid = daemon.sessions.resolve(Some(&token));
        let ahead = match daemon.febe.execute(sid, req) {
            Response::AckAddr { at, .. } => at,
            // `Response` derives no Debug upstream; marshal to say what came back.
            other => panic!(
                "register_node acks an address: {}",
                String::from_utf8_lossy(&daemon.codec.marshal(&other))
            ),
        };
        assert!(ahead.0 > announced().0, "the head is now ahead of the feed");

        let read = post(r#"{"op":"next_account_prefix","parent":"1"}"#);
        assert_eq!(read["resp"].as_str(), Some("maybe_addr"), "a read was served: {read}");
        assert!(
            announced().0 < ahead.0,
            "a read commits nothing and must announce nothing — announcing the current \
             head would name a commit whose change-feed entry may not exist yet"
        );

        let bad = post(r#"{"op":"frobnicate"}"#);
        assert_eq!(bad["op"].as_str(), Some("unparseable"));
        assert!(announced().0 < ahead.0, "an unparseable frame announces nothing either");

        let write = post(r#"{"op":"register_node","addr":"1.9002"}"#);
        let at = write["at"].as_u64().expect("register_node commits: {write}");
        assert_eq!(
            announced().0,
            at,
            "a committing write announces the position it committed, not the head"
        );
    }
}
