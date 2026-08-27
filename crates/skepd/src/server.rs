//! The process: one long-running server owning one `World`. The daemon is
//! transport, configuration, and lifetime — every handler is
//! parse/marshal/dispatch/configure; every decision lives in a store.
//!
//! Split for testability: [`Daemon`] holds the state and routes
//! `(method, path, query, session, body) → Routed` with no socket anywhere;
//! [`serve`]/[`Skepd`] wrap it in a synchronous accept loop over a plain
//! `TcpListener`. The HTTP/1.1 subset this daemon speaks (GET/POST/OPTIONS,
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
//! scope decision, not an accident: the daemon is loopback-only local
//! trust, so any local page may read what any local process may read;
//! writes still require the session token, which is not a browser
//! credential. Revisited when authentication lands.
//!
//! **The commit stream (wire v4)**: `GET /events` is a `text/event-stream`
//! of committed log positions — one event carrying the current head on
//! connect, then an event whenever the head advances (coalescing under
//! load: a subscriber sees a strictly increasing sequence converging on the
//! true head). The mechanism is write-path notification: `/op` — the
//! daemon's only live write path — publishes its post-execute position into
//! the condvar-backed `EventFeed`, and each subscriber thread blocks there;
//! no polling anywhere, so a commit reaches subscribers at thread-wake
//! speed. Subscribers are dedicated spawned threads, never workers: the
//! accepting worker hands the socket off and returns to `accept`, so open
//! streams cannot starve `/op`. A `:ka` keepalive comment flows after each
//! silent interval so both sides can detect a dead peer; shutdown
//! broadcasts on the same condvar and joins every subscriber, so open
//! streams end in bounded time with a clean close the client sees.
//!
//! **The change feed (wire v6)**: `GET /changes?since=N` answers the
//! committed positions in `(N, head]`, oldest first, each with its op kind,
//! affected document(s), and commit wall-clock time — so clients refresh
//! what they display instead of re-walking the world on every SSE tick.
//! The source is the commit-metadata sidecar (`commits.log`, see
//! `sidecar.rs`): the daemon observing its own write path — `/op` is the
//! only live write path — under the write-serialization lock, so sidecar
//! order is commit order. Writes only; reads never appear. Timestamps are
//! transport metadata, never substrate state: two daemons replaying one
//! journal still converge on byte-identical worlds, and a position whose
//! record was lost (or predates the feature) answers `null` fields —
//! reconstructed as a bare position, never an invented value. `/health`
//! additionally reports `head_time`, the newest recorded commit's time.
//!
//! **The served client (wire v6, `client` feature, default on)**: `GET /`
//! answers the embedded authoring client (`skep/clients/board.html`,
//! `include_str!` at build — the binary is self-contained), `text/html`,
//! same CORS posture as everything else. One file by design; there is no
//! asset pipeline. A build without the feature has no `/` route (404).

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use parking_lot::{Condvar, Mutex};
use serde_json::Value;
use skep_address::Address;
use skep_engine::{Engine, EngineError, GenesisConfig, HistoryError, World};
use skep_febe::{Codec, Op, OpKind, Operation, Request, Response, SessionId};
use skep_kernel::{BurnedSeqPolicy, CheckpointPolicy, Durability, KernelConfig, Seq};
use skep_namespace::PrincipalId;

use crate::codec::{check_keys, obj, op_name, tumbler_string, JsonCodec};
use crate::history::{History, Unavailable};
use crate::sidecar::{ChangesAnswer, Sidecar};

/// Auto-checkpoint cadence: every N commits (M2 evaluates on-commit; no
/// timer thread exists anywhere in this daemon).
const CHECKPOINT_EVERY_COMMITS: u64 = 1024;

/// Retained checkpoints: two, so `BadCheckpoint` recovery can fall back to
/// the older base instead of a full-journal replay from genesis.
const RETAINED_CHECKPOINTS: usize = 2;

/// SSE keepalive cadence: a `:ka` comment after each interval of silence,
/// so proxies and clients can detect liveness — and the daemon detects a
/// dead subscriber by the failed write within one interval.
const SSE_KEEPALIVE: Duration = Duration::from_secs(15);

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

/// Request-head size cap. Tokens and headers are small; frames ride in the
/// body, capped separately by [`MAX_REQUEST_BODY`].
const HEAD_MAX: usize = 64 * 1024;

/// Request-body cap, enforced on the declared `Content-Length` before any
/// body byte is read or allocated. Pre-media value — wire frames are small.
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

impl std::error::Error for DaemonError {}

/// One handler result: status, content type, body. `POST /op` is always
/// `200` once a `Response` exists — rejections included; the `Response`
/// envelope, not the HTTP status, is the operation protocol. Non-200 codes
/// are transport-level only (`{"error": …}` bodies, wire.md §Transport
/// errors).
pub struct Reply {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
    /// Extra response headers beyond the universal set (`Content-Type`,
    /// `Content-Length`, `Access-Control-Allow-Origin`, `Connection`) —
    /// the preflight trio rides here.
    pub headers: Vec<(&'static str, &'static str)>,
}

impl Reply {
    fn json(status: u16, v: Value) -> Reply {
        Reply {
            status,
            content_type: "application/json",
            body: serde_json::to_vec(&v).expect("serializing a serde_json::Value cannot fail"),
            headers: Vec::new(),
        }
    }

    /// The CORS preflight answer (wire v4): 204, no body, the fixed method
    /// and header lists. `Access-Control-Allow-Origin: *` is universal and
    /// added where every response is written, so it is not repeated here.
    fn preflight() -> Reply {
        Reply {
            status: 204,
            content_type: "",
            body: Vec::new(),
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
pub enum Routed {
    Reply(Reply),
    /// `GET /events` — the server-sent commit stream (wire v4).
    EventStream,
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
}

/// A transport-level error body: `{"error": name}` plus an optional detail.
/// Deliberately NOT the `{"resp": "rejected"}` shape — no `Op` was involved.
fn err_body(err: TransportError, detail: Option<&str>) -> Value {
    let mut pairs = vec![("error", Value::String(err.name().into()))];
    if let Some(d) = detail {
        pairs.push(("detail", Value::String(d.into())));
    }
    obj(pairs)
}

/// The paths this daemon serves — the one place the route set is stated, so
/// preflight, method refusal and dispatch cannot disagree about what exists.
/// A known path answers `OPTIONS` with a preflight and a wrong method with
/// `405`; everything else is the ordinary `404`.
fn known_path(path: &str) -> bool {
    matches!(path, "/session" | "/op" | "/op-at" | "/health" | "/events" | "/changes")
        || (cfg!(feature = "observe") && path == "/dump")
        || (cfg!(feature = "client") && path == "/")
}

/// Identity as local trust: the token ↔ `SessionId` binding, and the one
/// policy over it. Clients name their own principal at `POST /session` and
/// get an opaque token back; a `SessionId` never rides the wire (M10's
/// non-forgeability precondition). Tokens die with the process — a token
/// from a previous run misses the map, and a miss is not an error: it
/// resolves to the guest, under which M10 itself serves reads and rejects
/// writes `Unauthenticated`, so the daemon holds no auth policy of its own.
struct Sessions {
    map: Mutex<HashMap<String, SessionId>>,
    /// A session opened and immediately closed at startup: permanently
    /// unbound, never reissued (M10 §6) — what an absent or unknown token
    /// resolves to.
    guest: SessionId,
    /// Per-uptime random token prefix: a stale token from a previous run
    /// misses instead of silently aliasing onto a fresh session.
    seed: u64,
    counter: AtomicU64,
}

impl Sessions {
    fn new(guest: SessionId) -> Sessions {
        let seed = {
            use std::collections::hash_map::RandomState;
            use std::hash::{BuildHasher, Hasher};
            RandomState::new().build_hasher().finish()
        };
        Sessions { map: Mutex::new(HashMap::new()), guest, seed, counter: AtomicU64::new(1) }
    }

    /// Mint the opaque token naming `sid`, and remember the binding.
    fn bind(&self, sid: SessionId) -> String {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        let token = format!("{:016x}.{:x}", self.seed, n);
        self.map.lock().insert(token.clone(), sid);
        token
    }

    /// The session a request runs under: its token's, or the guest for a
    /// token that is absent or unknown.
    fn resolve(&self, token: Option<&str>) -> SessionId {
        token.and_then(|t| self.map.lock().get(t).copied()).unwrap_or(self.guest)
    }
}

/// The daemon's state: the assembled engine, M10's front door, the codec,
/// and the token → session binding. Socket-free — [`Daemon::handle`] is the
/// entire HTTP surface as a pure request→reply function over this state.
pub struct Daemon {
    engine: Engine,
    op: Operation<World>,
    codec: JsonCodec,
    /// The token ↔ session binding and the guest policy over it.
    sessions: Sessions,
    /// The commit feed behind `GET /events` (wire v4): `/op` publishes its
    /// post-execute log position, subscriber threads block on the condvar.
    feed: EventFeed,
    /// The commit-metadata sidecar behind `GET /changes` and `head_time`
    /// (wire v6) — the daemon's testimony about its own write path.
    sidecar: Sidecar,
    /// Serializes the daemon's write path (M2's applier serializes commits
    /// anyway; this only moves the serialization point up) so the sidecar
    /// append rides atomically behind its own commit: file order is
    /// position order and recorded times are monotone. A process crash can
    /// lose at most the one in-flight record (the append is flushed before
    /// the lock releases); an OS crash can lose more of the un-fsynced
    /// tail — either way the reopen walk re-covers the gap as bare
    /// entries. Reads never take this lock.
    write_serial: Mutex<()>,
    /// The history surface behind `/op-at` and `/dump?at`, holding its own
    /// reconstruction budget: neither route needs a session and replay is
    /// per-call uncached, so without that budget any local caller could pin
    /// every worker on reconstruction.
    history: History,
}

impl Daemon {
    /// Open (genesis or recover) the one world at `data_dir`, replay the
    /// commit-metadata sidecar, and assemble the operation surface. Every
    /// [`DaemonError`] is an operator-intervention condition — surface it
    /// and exit, never retry.
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
        let sidecar = Sidecar::open(data_dir, &engine).map_err(DaemonError::Sidecar)?;
        let op = Operation::new(Box::new(engine.stores()));
        // Mint-and-retire the guest binding; the principal value never
        // reaches a store (the binding is dropped before any request runs).
        let guest = op.open_session(PrincipalId(u64::MAX));
        op.close_session(guest);
        let feed = EventFeed::at(op.log_position());
        Ok(Daemon {
            engine,
            op,
            codec: JsonCodec,
            sessions: Sessions::new(guest),
            feed,
            sidecar,
            write_serial: Mutex::new(()),
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
        self.op.log_position()
    }

    /// The router — the whole HTTP surface, still socket-free: the one
    /// route that cannot be a request/response `Reply` (`GET /events`, an
    /// unbounded response) is returned as its own [`Routed`] variant, and
    /// the accept path owns the socket from there. `query` is the raw query
    /// string (meaningful on `/changes` and `/dump`, ignored elsewhere);
    /// `session` is the value of the `Skepd-Session` header, if any.
    pub fn handle(
        &self,
        method: &str,
        path: &str,
        query: Option<&str>,
        session: Option<&str>,
        body: &[u8],
    ) -> Routed {
        match (method, path) {
            ("GET", "/events") => Routed::EventStream,
            // CORS preflight (wire v4): 204 on any known path; an unknown
            // path falls through to the ordinary 404.
            ("OPTIONS", p) if known_path(p) => Routed::Reply(Reply::preflight()),
            _ => Routed::Reply(self.reply(method, path, query, session, body)),
        }
    }

    /// The request/response routes.
    fn reply(
        &self,
        method: &str,
        path: &str,
        query: Option<&str>,
        session: Option<&str>,
        body: &[u8],
    ) -> Reply {
        match (method, path) {
            ("POST", "/session") => self.post_session(body),
            ("POST", "/op") => self.post_op(session, body),
            ("POST", "/op-at") => self.post_op_at(body),
            ("GET", "/health") => self.get_health(),
            ("GET", "/changes") => self.get_changes(query),
            #[cfg(feature = "observe")]
            ("GET", "/dump") => self.get_dump(query),
            #[cfg(feature = "client")]
            ("GET", "/") => Reply {
                status: 200,
                content_type: "text/html; charset=utf-8",
                body: BOARD_HTML.as_bytes().to_vec(),
                headers: Vec::new(),
            },
            (_, p) if known_path(p) => Reply::json(
                405,
                err_body(
                    TransportError::MethodNotAllowed,
                    Some("see wire.md for the endpoint list"),
                ),
            ),
            _ => Reply::json(404, err_body(TransportError::NoSuchEndpoint, Some(path))),
        }
    }

    /// `POST /session` — bind a named principal (local trust: the client
    /// names it), return the opaque token and echo the principal so the
    /// client can name its own account in `principal_prefix`.
    fn post_session(&self, body: &[u8]) -> Reply {
        let principal = match session_principal(body) {
            Ok(p) => p,
            Err(detail) => {
                return Reply::json(
                    400,
                    err_body(TransportError::MalformedSessionRequest, Some(&detail)),
                )
            }
        };
        let sid = self.op.open_session(PrincipalId(principal));
        let token = self.sessions.bind(sid);
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
    /// Writes additionally serialize through `write_serial` (wire v6) so
    /// the sidecar append is atomic with its own commit — M2's applier
    /// already serializes the commits themselves, so this costs nothing it
    /// wasn't already paying. Reads bypass the lock entirely.
    fn post_op(&self, session: Option<&str>, body: &[u8]) -> Reply {
        let sid = self.sessions.resolve(session);
        let resp = match self.codec.parse(body) {
            Ok(req) => match write_meta(&req.op) {
                None => self.execute(sid, req),
                Some((kind, docs)) => {
                    let _serial = self.write_serial.lock();
                    let resp = self.execute(sid, req);
                    self.observe_commit(kind, docs, &resp);
                    resp
                }
            },
            Err(e) => self.codec.unparseable(e),
        };
        // Write-path notification (wire v4): `/op` is the daemon's only
        // live write path, so publishing the post-execute head here is
        // complete. Reads publish a no-op; concurrent writes coalesce; the
        // feed keeps the sequence monotone. Published after the sidecar
        // append (above), so a subscriber waking on the event already finds
        // the position in `/changes`.
        self.feed.publish(self.op.log_position());
        self.op_reply(&resp)
    }

    /// One marshaled operation answer as its reply — always `200`, whatever
    /// the `Response` says: the envelope, not the HTTP status, is the
    /// operation protocol.
    fn op_reply(&self, resp: &Response) -> Reply {
        Reply {
            status: 200,
            content_type: "application/json",
            body: self.codec.marshal(resp),
            headers: Vec::new(),
        }
    }

    /// Feed the sidecar from a write's answer: an ack carries the committed
    /// position; a rejection committed nothing and records nothing. Runs
    /// under `write_serial`. EXHAUSTIVE with no `_` arm, like the other
    /// `Response` walks here: a new answer shape carrying a committed
    /// position must decide whether the change feed reports it, and fails
    /// to compile until it does.
    fn observe_commit(&self, kind: OpKind, docs: DocsSrc, resp: &Response) {
        let (at, minted) = match resp {
            Response::Ack { at } => (*at, None),
            Response::AckAddr { addr, at } => (*at, Some(addr)),
            Response::AckEdit { at, .. } => (*at, None),
            Response::Delivery { .. }
            | Response::SpanSet { .. }
            | Response::Addrs { .. }
            | Response::MaybeAddr { .. }
            | Response::Count { .. }
            | Response::Page { .. }
            | Response::Endsets { .. }
            | Response::Runs { .. }
            | Response::Bool { .. }
            | Response::LinkValue { .. }
            | Response::Follow { .. }
            | Response::Deletions { .. }
            | Response::Compare { .. }
            | Response::Orphans { .. }
            | Response::Claims { .. }
            | Response::Rejected(_) => return,
        };
        let docs = match docs {
            DocsSrc::These(v) => v.iter().map(|a| tumbler_string(a.tumbler())).collect(),
            DocsSrc::Minted => match minted {
                Some(a) => vec![tumbler_string(a.tumbler())],
                None => Vec::new(),
            },
        };
        self.sidecar.record(at.0, op_name(kind), docs);
    }

    fn execute(&self, sid: SessionId, req: Request) -> skep_febe::Response {
        self.op.execute(sid, req)
    }

    /// TEST HOOK (the `fuzz_support` standing: `#[doc(hidden)]`, not a
    /// stable API): hold one reconstruction permit exactly as an in-flight
    /// reconstruction does, or `None` when the whole budget is taken. Real
    /// reconstructions finish in milliseconds, so the integration tests pin
    /// the counter through this instead of racing the engine.
    #[doc(hidden)]
    pub fn try_hold_reconstruction_permit(&self) -> Option<impl Drop + '_> {
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
            Err(detail) => {
                return Reply::json(400, err_body(TransportError::MalformedOpAt, Some(&detail)))
            }
        };
        let req = match self.codec.parse(&frame) {
            Ok(r) => r,
            Err(e) => return self.op_reply(&self.codec.unparseable(e)),
        };
        if !op_is_read(&req.op) {
            // The ruling-fixed body, exactly: {"error": "write_at_history"}.
            return Reply::json(400, err_body(TransportError::WriteAtHistory, None));
        }
        match self.history.read_at(&self.engine, at, req) {
            Ok(resp) => self.op_reply(&resp),
            Err(e) => unavailable_reply(e),
        }
    }

    fn get_health(&self) -> Reply {
        // The newest recorded commit's wall-clock time (wire v6) — null
        // when unrecorded (fresh world, bare head): transport metadata,
        // never invented.
        let head_time =
            self.sidecar.head_time().map(|t| Value::Number(t.into())).unwrap_or(Value::Null);
        Reply::json(
            200,
            obj(vec![
                ("head_time", head_time),
                ("log_position", Value::Number(self.op.log_position().0.into())),
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
            Err(detail) => {
                return Reply::json(
                    400,
                    err_body(TransportError::MalformedChanges, Some(&detail)),
                )
            }
        };
        match self.sidecar.changes(since, limit) {
            ChangesAnswer::Reclaimed { floor } => reclaimed_reply(floor),
            ChangesAnswer::Page { entries, last, more } => {
                let list: Vec<Value> = entries
                    .iter()
                    .map(|(at, meta)| {
                        obj(vec![
                            ("at", Value::Number((*at).into())),
                            (
                                "docs",
                                meta.docs
                                    .as_ref()
                                    .map(|d| {
                                        Value::Array(
                                            d.iter().map(|s| Value::String(s.clone())).collect(),
                                        )
                                    })
                                    .unwrap_or(Value::Null),
                            ),
                            (
                                "op",
                                meta.op
                                    .as_ref()
                                    .map(|s| Value::String(s.clone()))
                                    .unwrap_or(Value::Null),
                            ),
                            (
                                "time",
                                meta.time.map(|t| Value::Number(t.into())).unwrap_or(Value::Null),
                            ),
                        ])
                    })
                    .collect();
                Reply::json(
                    200,
                    obj(vec![
                        ("changes", Value::Array(list)),
                        ("last", Value::Number(last.into())),
                        ("more", Value::Bool(more)),
                    ]),
                )
            }
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
            Err(detail) => {
                return Reply::json(400, err_body(TransportError::MalformedAt, Some(&detail)))
            }
        };
        let dump = match at {
            None => self.engine.world_dump(),
            Some(at) => match self.history.world_at(&self.engine, at) {
                Ok(w) => skep_engine::observe::dump(&w, self.engine.genesis_config()),
                Err(e) => return unavailable_reply(e),
            },
        };
        Reply {
            status: 200,
            content_type: "text/plain; charset=utf-8",
            body: dump.into_string().into_bytes(),
            headers: Vec::new(),
        }
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

/// The `/changes` query: `since=<position>` (required) plus optional
/// `limit=<1..=4096>`. Unknown or repeated parameters are refused — the
/// wire's never-silent posture applied to queries.
fn changes_params(query: Option<&str>) -> Result<(u64, usize), String> {
    let q = match query {
        None | Some("") => {
            return Err("the required parameter is since=<position>".into());
        }
        Some(q) => q,
    };
    let mut since: Option<u64> = None;
    let mut limit: Option<usize> = None;
    for pair in q.split('&') {
        let Some((k, v)) = pair.split_once('=') else {
            return Err(format!("malformed parameter '{pair}'"));
        };
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

/// A write's affected document(s) for the sidecar (ruling §0): the write's
/// target doc; a link write names its home (`edit_link` both homes); the
/// MINTED document for create/fork/version (known only from the ack);
/// delegate/register_node touch no document.
enum DocsSrc {
    These(Vec<Address>),
    Minted,
}

/// The sidecar metadata of a write `Op` — `None` for reads, which is also
/// THE read/write partition: [`op_is_read`] is defined as this answer's
/// absence, so the two cannot disagree about a variant. EXHAUSTIVE with no
/// `_` arm: a new `Op` fails to compile here until its feed entry is
/// decided, and that one decision classifies it for the history surface
/// too.
fn write_meta(op: &Op) -> Option<(OpKind, DocsSrc)> {
    let one = |a: &Address| DocsSrc::These(vec![a.clone()]);
    match op {
        Op::CreateNewDocument { .. } => Some((OpKind::CreateNewDocument, DocsSrc::Minted)),
        Op::Delegate { .. } => Some((OpKind::Delegate, DocsSrc::These(Vec::new()))),
        Op::RegisterNode { .. } => Some((OpKind::RegisterNode, DocsSrc::These(Vec::new()))),
        Op::Fork => Some((OpKind::Fork, DocsSrc::Minted)),
        Op::Insert { doc, .. } => Some((OpKind::Insert, one(doc))),
        Op::Delete { doc, .. } => Some((OpKind::Delete, one(doc))),
        Op::Copy { doc, .. } => Some((OpKind::Copy, one(doc))),
        Op::Rearrange { doc, .. } => Some((OpKind::Rearrange, one(doc))),
        Op::Version { .. } => Some((OpKind::Version, DocsSrc::Minted)),
        Op::MakeLink { home, .. } => Some((OpKind::MakeLink, one(home))),
        Op::Emit { home, .. } => Some((OpKind::Emit, one(home))),
        Op::Nullify { home, .. } => Some((OpKind::Nullify, one(home))),
        Op::AssertSup { home, .. } => Some((OpKind::AssertSup, one(home))),
        Op::EditLink { d_s, d_a, .. } => {
            let mut docs = vec![d_s.clone()];
            if d_a != d_s {
                docs.push(d_a.clone());
            }
            Some((OpKind::EditLink, DocsSrc::These(docs)))
        }
        Op::NextAccountPrefix { .. }
        | Op::PrincipalPrefix { .. }
        | Op::ReadLink { .. }
        | Op::FollowLink { .. }
        | Op::RetrieveV { .. }
        | Op::RetrieveDocVSpan { .. }
        | Op::RetrieveDocVSpanSet { .. }
        | Op::ShowOrigin { .. }
        | Op::ShowDeletions { .. }
        | Op::Compare { .. }
        | Op::FindDocsContaining { .. }
        | Op::Image { .. }
        | Op::FindLinksV { .. }
        | Op::FindLinksFtt { .. }
        | Op::CountV { .. }
        | Op::CountFtt { .. }
        | Op::WindowV { .. }
        | Op::WindowFtt { .. }
        | Op::RetrieveEndsets { .. }
        | Op::Project { .. }
        | Op::DiscoverableFrom { .. }
        | Op::DeleteOrphans { .. }
        | Op::InClaims { .. }
        | Op::OutClaims { .. } => None,
    }
}

// ── the history surface (wire v3) ────────────────────────────────────────

/// Strictly `{"at": <non-negative integer>, "frame": <object>}`; returns the
/// position and the frame re-serialized for the codec.
fn op_at_envelope(body: &[u8]) -> Result<(Seq, Vec<u8>), String> {
    let v: Value =
        serde_json::from_slice(body).map_err(|e| format!("invalid JSON: {e}"))?;
    let Value::Object(m) = v else {
        return Err("op-at envelope must be a JSON object".into());
    };
    check_keys(&m, &["at", "frame"])?;
    let at = m
        .get("at")
        .and_then(Value::as_u64)
        .ok_or_else(|| String::from("missing or non-integer field 'at'"))?;
    let frame = m.get("frame").ok_or_else(|| String::from("missing field 'frame'"))?;
    if !frame.is_object() {
        return Err("field 'frame' must be a JSON object (an /op frame)".into());
    }
    let bytes =
        serde_json::to_vec(frame).expect("re-serializing a serde_json::Value cannot fail");
    Ok((Seq(at), bytes))
}

/// The `/dump` query: nothing, or exactly `at=<decimal position>`.
#[cfg(feature = "observe")]
fn dump_at_param(query: Option<&str>) -> Result<Option<Seq>, String> {
    let q = match query {
        None | Some("") => return Ok(None),
        Some(q) => q,
    };
    let Some(v) = q.strip_prefix("at=") else {
        return Err(format!("unknown query '{q}'; the one /dump parameter is at=<position>"));
    };
    v.parse::<u64>()
        .map(|n| Some(Seq(n)))
        .map_err(|_| format!("at: '{v}' is not a position (a non-negative integer)"))
}

/// The `410 history_reclaimed` refusal: the position asked for is older
/// than what can still be answered, and `floor` — when one exists — names
/// the oldest that can. One construction, shared by the history surface and
/// the change feed, so the two cannot describe the same condition
/// differently.
fn reclaimed_reply(floor: Option<u64>) -> Reply {
    let mut pairs =
        vec![("error", Value::String(TransportError::HistoryReclaimed.name().into()))];
    if let Some(f) = floor {
        pairs.push(("floor", Value::Number(f.into())));
    }
    Reply::json(410, obj(pairs))
}

/// Map an unavailable historical answer onto the wire's transport errors —
/// the one place the history surface's `Unavailable` becomes HTTP. The
/// ruling-fixed `beyond_head` body is emitted exactly as specified; the
/// rest are this daemon's own wire decisions, documented in wire.md
/// §Reading history. `history_busy` is the one retry-class error: the
/// position may be perfectly good and the daemon momentarily saturated.
fn unavailable_reply(e: Unavailable) -> Reply {
    let journal = match e {
        Unavailable::Busy => {
            return Reply::json(
                503,
                err_body(
                    TransportError::HistoryBusy,
                    Some("all reconstruction permits are in use; retry shortly"),
                ),
            )
        }
        Unavailable::Journal(e) => e,
    };
    let mut pairs: Vec<(&'static str, Value)> = Vec::new();
    let (status, err) = match journal {
        HistoryError::BeyondHead { head } => {
            pairs.push(("head", Value::Number(head.0.into())));
            (400, TransportError::BeyondHead)
        }
        HistoryError::NotABoundary { nearest } => {
            pairs.push(("nearest", Value::Number(nearest.0.into())));
            (400, TransportError::NotAPosition)
        }
        HistoryError::Reclaimed { floor } => return reclaimed_reply(floor.map(|f| f.0)),
        // Unreachable under this daemon's Fsync configuration; mapped so the
        // surface stays total over the engine's error type.
        HistoryError::Unjournaled => {
            pairs.push((
                "detail",
                Value::String("this daemon holds no journal; history is unavailable".into()),
            ));
            (500, TransportError::NoJournal)
        }
        HistoryError::Io(err) => {
            pairs.push(("detail", Value::String(err.to_string())));
            (500, TransportError::HistoryIo)
        }
        HistoryError::Corruption { at, .. } => {
            pairs.push((
                "detail",
                Value::String(format!(
                    "journal corrupt at rest; next intact frame at {}",
                    at.0
                )),
            ));
            (500, TransportError::HistoryCorrupt)
        }
    };
    pairs.push(("error", Value::String(err.name().into())));
    Reply::json(status, obj(pairs))
}

/// The wire's read/write partition, mirroring M10's own `Op::is_read`
/// (crate-private there, so restated here — the one classification the
/// history surface needs before dispatch). A read is exactly an `Op` the
/// change feed has nothing to record: one table decides both, so an `Op`
/// admitted to history can never be one that commits.
fn op_is_read(op: &Op) -> bool {
    write_meta(op).is_none()
}

// ── the commit feed (wire v4) ────────────────────────────────────────────

/// One head + shutdown flag under a mutex, one condvar. `/op` publishes
/// after execute (write-path notification — the only live write path, so
/// no head advance can be missed); each subscriber blocks in
/// [`EventFeed::next`] with the keepalive interval as its wait bound.
/// Shutdown broadcasts on the same condvar, which is what makes closing
/// open streams immediate rather than a poll away.
struct EventFeed {
    state: Mutex<FeedState>,
    cond: Condvar,
}

struct FeedState {
    head: Seq,
    shutdown: bool,
}

/// What a subscriber does next.
enum FeedStep {
    /// The head advanced past the subscriber's last-sent position.
    Commit(Seq),
    /// Nothing moved for one keepalive interval.
    Keepalive,
    /// The daemon is stopping; end the stream.
    Shutdown,
}

impl EventFeed {
    fn at(head: Seq) -> EventFeed {
        EventFeed {
            state: Mutex::new(FeedState { head, shutdown: false }),
            cond: Condvar::new(),
        }
    }

    fn publish(&self, seq: Seq) {
        let mut st = self.state.lock();
        if seq.0 > st.head.0 {
            st.head = seq;
            self.cond.notify_all();
        }
    }

    fn shutdown(&self) {
        self.state.lock().shutdown = true;
        self.cond.notify_all();
    }

    /// Block until the head passes `last`, the daemon stops, or the
    /// keepalive interval elapses — whichever comes first. Returning the
    /// current head (not a queue of commits) is the coalescing: a burst of
    /// commits between wakes is one step.
    fn next(&self, last: Seq) -> FeedStep {
        let deadline = Instant::now() + SSE_KEEPALIVE;
        let mut st = self.state.lock();
        loop {
            if st.shutdown {
                return FeedStep::Shutdown;
            }
            if st.head.0 > last.0 {
                return FeedStep::Commit(st.head);
            }
            if self.cond.wait_until(&mut st, deadline).timed_out() {
                return FeedStep::Keepalive;
            }
        }
    }
}

// ── the wire loop ────────────────────────────────────────────────────────

/// The running server: the listener, the op workers, the daemon, and the
/// event-stream subscriber threads.
pub struct Skepd {
    daemon: Arc<Daemon>,
    listener: Arc<TcpListener>,
    workers: Vec<JoinHandle<()>>,
    subscribers: Arc<Mutex<Vec<JoinHandle<()>>>>,
    stop: Arc<AtomicBool>,
    port: u16,
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
pub fn serve(
    daemon: Daemon,
    port: u16,
    workers: usize,
) -> Result<Skepd, Box<dyn std::error::Error + Send + Sync>> {
    let daemon = Arc::new(daemon);
    let listener = Arc::new(TcpListener::bind(("127.0.0.1", port))?);
    let port = listener.local_addr()?.port();
    let stop = Arc::new(AtomicBool::new(false));
    let subscribers: Arc<Mutex<Vec<JoinHandle<()>>>> = Arc::new(Mutex::new(Vec::new()));
    let workers = workers.max(1);
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
    Ok(Skepd { daemon, listener, workers: handles, subscribers, stop, port })
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

    /// Block until the workers exit (they don't, absent [`Skepd::shutdown`])
    /// — the binary's foreground call. Crash-stop is the shutdown story:
    /// M2's WAL makes recovery the clean path, so no signal machinery.
    pub fn wait(self) {
        for h in self.workers {
            let _ = h.join();
        }
    }

    /// Orderly stop for embedders and tests: release and join the op
    /// workers, then end every event stream — the feed broadcast wakes each
    /// subscriber, which drops its socket (the client sees a clean close)
    /// and exits — and join those threads too. Dropping the daemon last
    /// releases the kernel's journal-directory lock so the same data dir
    /// can be reopened. Bounded: nothing here waits on a client.
    pub fn shutdown(self) {
        let Skepd { daemon, listener, workers, subscribers, stop, port } = self;
        stop.store(true, Ordering::Release);
        // One wake connect per worker: a worker blocked in `accept` returns
        // and the flag breaks its loop. A worker mid-request exits at its
        // next loop check instead, leaving its wake connect unclaimed in
        // the backlog — harmless; the listener drops below.
        for _ in 0..workers.len() {
            let _ = TcpStream::connect(("127.0.0.1", port));
        }
        for h in workers {
            let _ = h.join();
        }
        // The workers are gone, so no new subscriber can appear past here.
        daemon.feed.shutdown();
        let subs = std::mem::take(&mut *subscribers.lock());
        for h in subs {
            let _ = h.join();
        }
        drop(listener);
        drop(daemon);
    }
}

/// Serve one connection: read the one request, route it, write the one
/// reply, close — or, for `GET /events`, hand the socket to a dedicated
/// subscriber thread and return at once. A handler panic is contained to a
/// 500 so one bad request cannot take a worker down; the panic still prints
/// to stderr for the operator.
fn serve_connection(
    daemon: &Arc<Daemon>,
    subscribers: &Mutex<Vec<JoinHandle<()>>>,
    mut stream: TcpStream,
) {
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
                    Reply::json(400, err_body(TransportError::MalformedHttp, Some(&detail)))
                }
                ReadError::BodyTooLarge(declared) => {
                    let detail = format!(
                        "Content-Length {declared} exceeds the {MAX_REQUEST_BODY}-byte body cap"
                    );
                    Reply::json(413, err_body(TransportError::PayloadTooLarge, Some(&detail)))
                }
            };
            let _ = write_reply(&mut stream, &reply);
            return;
        }
    };
    let routed = match catch_unwind(AssertUnwindSafe(|| {
        daemon.handle(
            &req.method,
            &req.path,
            req.query.as_deref(),
            req.session.as_deref(),
            &req.body,
        )
    })) {
        Ok(r) => r,
        Err(_) => Routed::Reply(Reply::json(500, err_body(TransportError::InternalPanic, None))),
    };
    match routed {
        Routed::Reply(reply) => {
            let _ = write_reply(&mut stream, &reply);
        }
        Routed::EventStream => {
            let daemon = Arc::clone(daemon);
            let mut subs = subscribers.lock();
            // Reap finished subscriber threads so the registry tracks live
            // streams, not history.
            subs.retain(|h| !h.is_finished());
            subs.push(thread::spawn(move || serve_events(&daemon, stream)));
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

/// One parsed request. `body` is exactly `Content-Length` bytes.
struct HttpRequest {
    method: String,
    path: String,
    query: Option<String>,
    session: Option<String>,
    body: Vec<u8>,
}

/// Read one request off the socket. `Ok(None)` = clean close before any
/// byte; `Err(_)` = the request is refused (the caller answers the
/// [`ReadError`]'s reply and closes). The subset: one request per
/// connection, HTTP/1.0 or 1.1, bodies by `Content-Length` (absent =
/// empty, capped at [`MAX_REQUEST_BODY`]), `Expect: 100-continue`
/// honored, `Transfer-Encoding` refused.
fn read_request(stream: &mut TcpStream) -> Result<Option<HttpRequest>, ReadError> {
    // The head, plus whatever early body bytes arrived with it.
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let head_end = loop {
        if let Some(i) = find_head_end(&buf) {
            break i;
        }
        if buf.len() > HEAD_MAX {
            return Err("request head exceeds 64 KiB".into());
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
    // The headers this daemon acts on; everything else passes unread.
    let mut content_length: Option<usize> = None;
    let mut session: Option<String> = None;
    let mut expects_continue = false;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| format!("malformed header line '{line}'"))?;
        let (name, value) = (name.trim(), value.trim());
        if name.eq_ignore_ascii_case("Content-Length") {
            content_length =
                Some(value.parse().map_err(|_| format!("bad Content-Length '{value}'"))?);
        } else if name.eq_ignore_ascii_case("Skepd-Session") {
            session = Some(value.to_string());
        } else if name.eq_ignore_ascii_case("Expect") {
            expects_continue = value.eq_ignore_ascii_case("100-continue");
        } else if name.eq_ignore_ascii_case("Transfer-Encoding") {
            return Err("chunked request bodies are unsupported; send Content-Length".into());
        }
    }
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), Some(q.to_string())),
        None => (target, None),
    };
    let mut body = buf[head_end + 4..].to_vec();
    let want = content_length.unwrap_or(0);
    // The one unbounded-allocation vector: refuse on the declared length
    // alone, before 100-continue invites the body and before the loop reads
    // (and allocates) a single byte of it. The media round's blob upload
    // will raise this for its route only.
    if want > MAX_REQUEST_BODY {
        return Err(ReadError::BodyTooLarge(want));
    }
    if expects_continue && body.len() < want {
        // The client is holding the body until told to send it (curl does
        // this for large payloads).
        if stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").is_err() {
            return Err("client went away at 100-continue".into());
        }
    }
    while body.len() < want {
        let mut chunk = [0u8; 8192];
        match stream.read(&mut chunk) {
            Ok(0) => return Err("connection closed inside the request body".into()),
            Ok(n) => body.extend_from_slice(&chunk[..n]),
            Err(e) => return Err(format!("read: {e}").into()),
        }
    }
    // A byte past Content-Length would be a pipelined second request; this
    // connection answers one and closes, so it is dropped unread.
    body.truncate(want);
    Ok(Some(HttpRequest { method, path, query, session, body }))
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Write one complete reply; the connection closes behind it. Every
/// response carries `Access-Control-Allow-Origin: *` — wire v4's CORS
/// posture, enforced at this one choke point so no reply can miss it — and
/// `Connection: close` (one request per connection). A 204 carries no body
/// and no content headers (RFC 7230).
fn write_reply(stream: &mut TcpStream, reply: &Reply) -> std::io::Result<()> {
    let mut out = Vec::with_capacity(reply.body.len() + 256);
    out.extend_from_slice(
        format!("HTTP/1.1 {} {}\r\n", reply.status, reason(reply.status)).as_bytes(),
    );
    out.extend_from_slice(b"Access-Control-Allow-Origin: *\r\n");
    for (name, value) in &reply.headers {
        out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    if reply.status != 204 {
        out.extend_from_slice(
            format!(
                "Content-Type: {}\r\nContent-Length: {}\r\n",
                reply.content_type,
                reply.body.len()
            )
            .as_bytes(),
        );
    }
    out.extend_from_slice(b"Connection: close\r\n\r\n");
    if reply.status != 204 {
        out.extend_from_slice(&reply.body);
    }
    stream.write_all(&out)
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
        match daemon.feed.next(last) {
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
    /// independent restatement, so a route added to [`known_path`] alone
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
    /// `OPTIONS`. This is the invariant [`known_path`] exists to keep — a
    /// route stated in one table and forgotten in another breaks exactly
    /// one of these.
    #[test]
    fn the_route_set_agrees_across_preflight_dispatch_and_refusal() {
        let dir = tempfile::tempdir().expect("tempdir");
        let daemon = Daemon::open(dir.path()).expect("genesis open");
        let status = |method: &str, path: &str| match daemon.handle(method, path, None, None, b"")
        {
            Routed::Reply(r) => r.status,
            // The one non-reply route; reached only by GET /events, which
            // this test never asks for.
            Routed::EventStream => 200,
        };
        for path in ROUTES {
            assert!(known_path(path), "{path} is served but not known");
            assert_eq!(status("OPTIONS", path), 204, "{path} must answer the CORS preflight");
            assert_eq!(status("PUT", path), 405, "{path} must refuse an unsupported method");
            let served = ["GET", "POST"].iter().any(|m| {
                let s = status(m, path);
                s != 404 && s != 405
            });
            assert!(served, "{path} is known but no method dispatches");
        }
        for unknown in ["/nope", "/op/", "/Health"] {
            assert!(!known_path(unknown), "{unknown} must not be known");
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
        let sid = daemon.op.open_session(PrincipalId(7));
        let token = daemon.sessions.bind(sid);
        assert_eq!(daemon.sessions.resolve(Some(&token)), sid, "a bound token is its session");
        let other = daemon.sessions.bind(daemon.op.open_session(PrincipalId(8)));
        assert_ne!(token, other, "each binding gets its own token");
    }

    /// The partition is one table's two faces: reads are exactly the ops
    /// the change feed records nothing for.
    #[test]
    fn reads_are_exactly_the_ops_with_no_feed_entry() {
        let read = Op::Fork;
        assert!(!op_is_read(&read), "fork commits");
        assert!(write_meta(&read).is_some());
        let query = Op::PrincipalPrefix { id: PrincipalId(1) };
        assert!(op_is_read(&query), "principal_prefix reads");
        assert!(write_meta(&query).is_none());
    }

    /// Transport-error bodies are built through the codec's sorting device,
    /// so they are byte-deterministic whatever backs serde_json's map.
    #[test]
    fn error_bodies_are_key_sorted() {
        let v = err_body(TransportError::PayloadTooLarge, Some("too big"));
        assert_eq!(
            serde_json::to_string(&v).expect("json"),
            r#"{"detail":"too big","error":"payload_too_large"}"#
        );
    }
}
