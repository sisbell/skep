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
//! (observe builds) dumps that position's world. The mechanism is the
//! engine's bounded replay (`Engine::world_at` — checkpoint-or-genesis base
//! plus journal fold, per request, uncached); the daemon then runs the frame
//! through a throwaway in-memory M10 over the historical world and stamps
//! the requested position as `as_of`. Writes never reach history — a write
//! frame is refused at the transport (`400 write_at_history`) before
//! anything runs — and the live `/op` path is untouched.
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
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use parking_lot::{Condvar, Mutex};
use serde_json::{Map, Value};
use skep_address::Address;
use skep_arrangement::Vstream;
use skep_engine::{Engine, EngineError, GenesisConfig, HistoryError, World};
use skep_febe::{Codec, Op, OpKind, Operation, Request, Response, SessionId, Stores};
use skep_kernel::{BurnedSeqPolicy, CheckpointPolicy, Durability, Kernel, KernelConfig, Seq};
use skep_links::LinkStore;
use skep_namespace::{Namespace, PrincipalId};

use crate::codec::{op_name, tumbler_string, JsonCodec};
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

/// Concurrent historical reconstructions (`Engine::world_at` behind
/// `/op-at` and `/dump?at`) allowed at once: each is a whole-checkpoint
/// deserialize plus journal fold, per call, uncached — two keeps history
/// panes serviceable without letting core-bound replay occupy the whole
/// worker pool. Surplus callers get `503 history_busy`, never a queue.
const OPAT_MAX_CONCURRENT: usize = 2;

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

/// A transport-level error body: `{"error": name}` plus an optional detail.
/// Deliberately NOT the `{"resp": "rejected"}` shape — no `Op` was involved.
fn err_body(name: &str, detail: Option<&str>) -> Value {
    let mut m = Map::new();
    m.insert("error".into(), Value::String(name.into()));
    if let Some(d) = detail {
        m.insert("detail".into(), Value::String(d.into()));
    }
    Value::Object(m)
}

/// The daemon's state: the assembled engine, M10's front door, the codec,
/// and the token → session binding. Socket-free — [`Daemon::handle`] is the
/// entire HTTP surface as a pure request→reply function over this state.
pub struct Daemon {
    engine: Engine,
    op: Operation<World>,
    codec: JsonCodec,
    sessions: Mutex<HashMap<String, SessionId>>,
    /// A session opened and immediately closed at startup: permanently
    /// unbound, never reissued (M10 §6). Requests carrying no usable token
    /// execute under it — M10 itself then serves reads and rejects writes
    /// `Unauthenticated`, so the daemon holds no auth policy of its own.
    guest: SessionId,
    /// Per-uptime random token prefix: a stale token from a previous run
    /// misses instead of silently aliasing onto a fresh session.
    token_seed: u64,
    token_counter: AtomicU64,
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
    /// Bounds concurrent `world_at` reconstructions ([`OPAT_MAX_CONCURRENT`]);
    /// `/op-at` needs no session and reconstruction is per-call uncached, so
    /// without this any local caller could pin every worker on replay.
    reconstruct_permits: ReconstructPermits,
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
        let token_seed = {
            use std::collections::hash_map::RandomState;
            use std::hash::{BuildHasher, Hasher};
            RandomState::new().build_hasher().finish()
        };
        let feed = EventFeed::at(op.log_position());
        Ok(Daemon {
            engine,
            op,
            codec: JsonCodec,
            sessions: Mutex::new(HashMap::new()),
            guest,
            token_seed,
            token_counter: AtomicU64::new(1),
            feed,
            sidecar,
            write_serial: Mutex::new(()),
            reconstruct_permits: ReconstructPermits::new(OPAT_MAX_CONCURRENT),
        })
    }

    /// The assembled engine (kernel, registry, genesis config).
    pub fn engine(&self) -> &Engine {
        &self.engine
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
            ("OPTIONS", "/session" | "/op" | "/op-at" | "/health" | "/events" | "/changes") => {
                Routed::Reply(Reply::preflight())
            }
            #[cfg(feature = "observe")]
            ("OPTIONS", "/dump") => Routed::Reply(Reply::preflight()),
            #[cfg(feature = "client")]
            ("OPTIONS", "/") => Routed::Reply(Reply::preflight()),
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
            (_, "/session") | (_, "/op") | (_, "/op-at") | (_, "/health") | (_, "/events")
            | (_, "/changes") => Reply::json(
                405,
                err_body("method_not_allowed", Some("see wire.md for the endpoint list")),
            ),
            #[cfg(feature = "observe")]
            (_, "/dump") => Reply::json(
                405,
                err_body("method_not_allowed", Some("see wire.md for the endpoint list")),
            ),
            #[cfg(feature = "client")]
            (_, "/") => Reply::json(
                405,
                err_body("method_not_allowed", Some("see wire.md for the endpoint list")),
            ),
            _ => Reply::json(404, err_body("no_such_endpoint", Some(path))),
        }
    }

    /// `POST /session` — bind a named principal (local trust: the client
    /// names it), return the opaque token and echo the principal so the
    /// client can name its own account in `principal_prefix`.
    fn post_session(&self, body: &[u8]) -> Reply {
        let principal = match session_principal(body) {
            Ok(p) => p,
            Err(detail) => {
                return Reply::json(400, err_body("malformed_session_request", Some(&detail)))
            }
        };
        let sid = self.op.open_session(PrincipalId(principal));
        let n = self.token_counter.fetch_add(1, Ordering::Relaxed);
        let token = format!("{:016x}.{:x}", self.token_seed, n);
        self.sessions.lock().insert(token.clone(), sid);
        let mut m = Map::new();
        m.insert("principal".into(), Value::Number(principal.into()));
        m.insert("session".into(), Value::String(token));
        Reply::json(200, Value::Object(m))
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
        let sid = session
            .and_then(|t| self.sessions.lock().get(t).copied())
            .unwrap_or(self.guest);
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
        Reply {
            status: 200,
            content_type: "application/json",
            body: self.codec.marshal(&resp),
            headers: Vec::new(),
        }
    }

    /// Feed the sidecar from a write's answer: an ack carries the committed
    /// position; a rejection committed nothing and records nothing. Runs
    /// under `write_serial`.
    fn observe_commit(&self, kind: OpKind, docs: DocsSrc, resp: &Response) {
        let (at, minted) = match resp {
            Response::Ack { at } => (*at, None),
            Response::AckAddr { addr, at } => (*at, Some(addr)),
            Response::AckEdit { at, .. } => (*at, None),
            _ => return,
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

    /// `Engine::world_at` under a reconstruction permit
    /// ([`OPAT_MAX_CONCURRENT`]). The permit spans the engine call alone,
    /// never the surrounding request, and exhaustion answers `Err` with the
    /// wire's `503 history_busy` — no queueing: a worker parked behind a
    /// core-bound replay is a worker lost to live traffic.
    fn world_at_permitted(&self, at: Seq) -> Result<World, Reply> {
        let Some(_permit) = self.reconstruct_permits.try_acquire() else {
            return Err(busy_reply());
        };
        self.engine.world_at(at).map_err(history_error_reply)
    }

    /// TEST HOOK (the `fuzz_support` standing: `#[doc(hidden)]`, not a
    /// stable API): hold one reconstruction permit exactly as an in-flight
    /// `world_at` does, or `None` when all [`OPAT_MAX_CONCURRENT`] are
    /// taken. Real reconstructions finish in milliseconds, so the
    /// integration tests pin the counter through this instead of racing
    /// the engine.
    #[doc(hidden)]
    pub fn try_hold_reconstruction_permit(&self) -> Option<impl Drop + '_> {
        self.reconstruct_permits.try_acquire()
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
            Err(detail) => return Reply::json(400, err_body("malformed_op_at", Some(&detail))),
        };
        let req = match self.codec.parse(&frame) {
            Ok(r) => r,
            Err(e) => {
                let resp = self.codec.unparseable(e);
                return Reply {
                    status: 200,
                    content_type: "application/json",
                    body: self.codec.marshal(&resp),
                    headers: Vec::new(),
                };
            }
        };
        if !op_is_read(&req.op) {
            // The ruling-fixed body, exactly: {"error": "write_at_history"}.
            let mut m = Map::new();
            m.insert("error".into(), Value::String("write_at_history".into()));
            return Reply::json(400, Value::Object(m));
        }
        let world = match self.world_at_permitted(at) {
            Ok(w) => w,
            Err(reply) => return reply,
        };
        let mut resp = execute_read_on(world, req);
        stamp_as_of(&mut resp, at);
        Reply {
            status: 200,
            content_type: "application/json",
            body: self.codec.marshal(&resp),
            headers: Vec::new(),
        }
    }

    fn get_health(&self) -> Reply {
        let mut m = Map::new();
        // The newest recorded commit's wall-clock time (wire v6) — null
        // when unrecorded (fresh world, bare head): transport metadata,
        // never invented.
        m.insert(
            "head_time".into(),
            self.sidecar.head_time().map(|t| Value::Number(t.into())).unwrap_or(Value::Null),
        );
        m.insert("log_position".into(), Value::Number(self.op.log_position().0.into()));
        m.insert("ok".into(), Value::Bool(true));
        Reply::json(200, Value::Object(m))
    }

    /// `GET /changes?since=N[&limit=K]` (wire v6) — the delta read: the
    /// committed positions in `(N, head]`, oldest first, from the sidecar.
    /// Pure parse/marshal over [`Sidecar::changes`]; determinism is the
    /// map's (same journal + sidecar ⇒ byte-equal pages, across restarts).
    fn get_changes(&self, query: Option<&str>) -> Reply {
        let (since, limit) = match changes_params(query) {
            Ok(x) => x,
            Err(detail) => {
                return Reply::json(400, err_body("malformed_changes", Some(&detail)))
            }
        };
        match self.sidecar.changes(since, limit) {
            ChangesAnswer::Reclaimed { floor } => {
                let mut m = Map::new();
                m.insert("error".into(), Value::String("history_reclaimed".into()));
                if let Some(f) = floor {
                    m.insert("floor".into(), Value::Number(f.into()));
                }
                Reply::json(410, Value::Object(m))
            }
            ChangesAnswer::Page { entries, last, more } => {
                let list: Vec<Value> = entries
                    .iter()
                    .map(|(at, meta)| {
                        let mut e = Map::new();
                        e.insert("at".into(), Value::Number((*at).into()));
                        e.insert(
                            "docs".into(),
                            meta.docs
                                .as_ref()
                                .map(|d| {
                                    Value::Array(
                                        d.iter().map(|s| Value::String(s.clone())).collect(),
                                    )
                                })
                                .unwrap_or(Value::Null),
                        );
                        e.insert(
                            "op".into(),
                            meta.op
                                .as_ref()
                                .map(|s| Value::String(s.clone()))
                                .unwrap_or(Value::Null),
                        );
                        e.insert(
                            "time".into(),
                            meta.time.map(|t| Value::Number(t.into())).unwrap_or(Value::Null),
                        );
                        Value::Object(e)
                    })
                    .collect();
                let mut m = Map::new();
                m.insert("changes".into(), Value::Array(list));
                m.insert("last".into(), Value::Number(last.into()));
                m.insert("more".into(), Value::Bool(more));
                Reply::json(200, Value::Object(m))
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
            Err(detail) => return Reply::json(400, err_body("malformed_at", Some(&detail))),
        };
        let dump = match at {
            None => self.engine.world_dump(),
            Some(at) => match self.world_at_permitted(at) {
                Ok(w) => skep_engine::observe::dump(&w, self.engine.genesis_config()),
                Err(reply) => return reply,
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
    for k in m.keys() {
        if k != "principal" {
            return Err(format!("unknown field '{k}'"));
        }
    }
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

/// The sidecar metadata of a write `Op` — `None` for reads. EXHAUSTIVE
/// with no `_` arm, like [`op_is_read`]: a new `Op` variant fails to
/// compile here until its feed entry is decided.
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
    for k in m.keys() {
        if k != "at" && k != "frame" {
            return Err(format!("unknown field '{k}'"));
        }
    }
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

/// The reconstruction bound behind [`OPAT_MAX_CONCURRENT`]: a counting
/// try-acquire with no queue and no blocking — plain atomics, no new
/// dependency. The guard returns its permit on drop, early returns and
/// panics included.
struct ReconstructPermits {
    available: AtomicUsize,
}

/// One held permit; dropping it releases the slot.
struct ReconstructPermit<'a> {
    permits: &'a ReconstructPermits,
}

impl ReconstructPermits {
    fn new(n: usize) -> ReconstructPermits {
        ReconstructPermits { available: AtomicUsize::new(n) }
    }

    /// One permit, or `None` right now — never blocks.
    fn try_acquire(&self) -> Option<ReconstructPermit<'_>> {
        self.available
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1))
            .ok()
            .map(|_| ReconstructPermit { permits: self })
    }
}

impl Drop for ReconstructPermit<'_> {
    fn drop(&mut self) {
        self.permits.available.fetch_add(1, Ordering::Release);
    }
}

/// The permit-exhausted refusal: `503 history_busy`, the wire's one
/// retry-class transport error (wire.md §Reading history). Distinct from
/// every position error — the position may be fine; the daemon is
/// momentarily saturated with reconstructions, so try again shortly.
fn busy_reply() -> Reply {
    Reply::json(
        503,
        err_body("history_busy", Some("all reconstruction permits are in use; retry shortly")),
    )
}

/// Map a bounded-replay failure onto the wire's transport errors. The two
/// ruling-fixed bodies (`write_at_history` lives at its check site;
/// `beyond_head` here) are emitted exactly as specified; the rest are this
/// daemon's own wire decisions, documented in wire.md §Reading history.
fn history_error_reply(e: HistoryError) -> Reply {
    let mut m = Map::new();
    let (status, name) = match e {
        HistoryError::BeyondHead { head } => {
            m.insert("head".into(), Value::Number(head.0.into()));
            (400, "beyond_head")
        }
        HistoryError::NotABoundary { nearest } => {
            m.insert("nearest".into(), Value::Number(nearest.0.into()));
            (400, "not_a_position")
        }
        HistoryError::Reclaimed { floor } => {
            if let Some(fl) = floor {
                m.insert("floor".into(), Value::Number(fl.0.into()));
            }
            (410, "history_reclaimed")
        }
        // Unreachable under this daemon's Fsync configuration; mapped so the
        // surface stays total over the engine's error type.
        HistoryError::Unjournaled => {
            m.insert(
                "detail".into(),
                Value::String("this daemon holds no journal; history is unavailable".into()),
            );
            (500, "no_journal")
        }
        HistoryError::Io(err) => {
            m.insert("detail".into(), Value::String(err.to_string()));
            (500, "history_io")
        }
        HistoryError::Corruption { at } => {
            m.insert(
                "detail".into(),
                Value::String(format!("journal corrupt at rest; next intact frame at {}", at.0)),
            );
            (500, "history_corrupt")
        }
    };
    m.insert("error".into(), Value::String(name.into()));
    Reply::json(status, Value::Object(m))
}

/// Run one already-classified READ frame against a historical world: a
/// throwaway in-memory M2 kernel rooted at that world, a throwaway M10 over
/// it, one `execute`. All the read semantics stay M10's and the stores' —
/// the daemon only assembles. The session is minted and retired up front
/// (the guest pattern): reads are principal-free, and even a misclassified
/// write would meet M10's own `Unauthenticated` wall rather than a store.
fn execute_read_on(world: World, req: Request) -> Response {
    let cfg = KernelConfig {
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::Manual,
    };
    let kernel =
        Arc::new(Kernel::open(cfg, world).expect("in-memory open runs no recovery and cannot fail"));
    let op = Operation::new(Box::new(HistStores { kernel }));
    let sid = op.open_session(PrincipalId(u64::MAX));
    op.close_session(sid);
    op.execute(sid, req)
}

/// `Stores<World>` over the throwaway historical kernel — the same shape as
/// the engine's `EngineStores`, which is constructible only over the live
/// recovered kernel and so cannot serve here.
struct HistStores {
    kernel: Arc<Kernel<World>>,
}

impl Stores<World> for HistStores {
    fn kernel(&self) -> &Kernel<World> {
        &self.kernel
    }

    fn namespace(&self) -> Namespace<World> {
        Namespace::new(Arc::clone(&self.kernel))
    }

    fn vstream(&self) -> Vstream<'_, World> {
        Vstream::new(&self.kernel)
    }

    fn linkstore(&self) -> LinkStore<'_, World> {
        LinkStore::new(&self.kernel)
    }
}

/// Stamp the requested position as `as_of`: the throwaway kernel is rooted
/// at the historical world with its own seq at 0, so M10's snapshot-seq
/// stamping — correct live — must be overwritten with the position the
/// answer is OF. Purely mechanical; every read shape is listed, writes
/// cannot reach here, and rejections carry no `as_of` at history exactly as
/// they carry none live.
fn stamp_as_of(resp: &mut Response, at: Seq) {
    match resp {
        Response::Delivery { as_of, .. }
        | Response::SpanSet { as_of, .. }
        | Response::Addrs { as_of, .. }
        | Response::MaybeAddr { as_of, .. }
        | Response::Count { as_of, .. }
        | Response::Page { as_of, .. }
        | Response::Endsets { as_of, .. }
        | Response::Runs { as_of, .. }
        | Response::Bool { as_of, .. }
        | Response::LinkValue { as_of, .. }
        | Response::Follow { as_of, .. }
        | Response::Deletions { as_of, .. }
        | Response::Compare { as_of, .. }
        | Response::Orphans { as_of, .. }
        | Response::Claims { as_of, .. } => *as_of = at,
        Response::Ack { .. }
        | Response::AckAddr { .. }
        | Response::AckEdit { .. }
        | Response::Rejected(_) => {}
    }
}

/// The wire's read/write partition, mirroring M10's own `Op::is_read`
/// (crate-private there, so restated here — the one classification the
/// history surface needs before dispatch). EXHAUSTIVE with no `_` arm: a
/// new `Op` variant fails to compile here until classified, the same
/// guarantee M10 gives its dispatch tables.
//
// The two-arm shape is load-bearing (compile-time non-exhaustiveness on a
// new variant), so the `matches!` rewrite clippy suggests is refused.
#[allow(clippy::match_like_matches_macro)]
fn op_is_read(op: &Op) -> bool {
    match op {
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
        | Op::OutClaims { .. } => true,
        Op::CreateNewDocument { .. }
        | Op::Delegate { .. }
        | Op::RegisterNode { .. }
        | Op::Fork
        | Op::Insert { .. }
        | Op::Delete { .. }
        | Op::Copy { .. }
        | Op::Rearrange { .. }
        | Op::Version { .. }
        | Op::MakeLink { .. }
        | Op::Emit { .. }
        | Op::Nullify { .. }
        | Op::AssertSup { .. }
        | Op::EditLink { .. } => false,
    }
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

    pub fn daemon(&self) -> &Arc<Daemon> {
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
                    Reply::json(400, err_body("malformed_http", Some(&detail)))
                }
                ReadError::BodyTooLarge(declared) => {
                    let detail = format!(
                        "Content-Length {declared} exceeds the {MAX_REQUEST_BODY}-byte body cap"
                    );
                    Reply::json(413, err_body("payload_too_large", Some(&detail)))
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
        Err(_) => Routed::Reply(Reply::json(500, err_body("internal_panic", None))),
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

    /// The counter is exact: [`OPAT_MAX_CONCURRENT`] acquires succeed, the
    /// next fails, and a drop returns exactly one slot.
    #[test]
    fn reconstruct_permits_account_exactly() {
        let permits = ReconstructPermits::new(OPAT_MAX_CONCURRENT);
        let first = permits.try_acquire().expect("permit 1 of 2");
        let second = permits.try_acquire().expect("permit 2 of 2");
        assert!(permits.try_acquire().is_none(), "the cap is exactly {OPAT_MAX_CONCURRENT}");
        drop(first);
        let third = permits.try_acquire().expect("a dropped permit reopens its slot");
        assert!(permits.try_acquire().is_none(), "still exactly one slot came back");
        drop(second);
        drop(third);
        let a = permits.try_acquire().expect("all slots return");
        let b = permits.try_acquire().expect("all slots return");
        drop((a, b));
    }

    /// Under real threads, at most [`OPAT_MAX_CONCURRENT`] holders exist at
    /// any instant — the invariant is asserted inside the hold, so any
    /// overshoot fails loudly regardless of scheduling.
    #[test]
    fn reconstruct_permits_bound_concurrent_holders() {
        let permits = ReconstructPermits::new(OPAT_MAX_CONCURRENT);
        let holding = AtomicUsize::new(0);
        let granted = AtomicUsize::new(0);
        thread::scope(|s| {
            for _ in 0..8 {
                s.spawn(|| {
                    for _ in 0..200 {
                        let Some(permit) = permits.try_acquire() else { continue };
                        let now = holding.fetch_add(1, Ordering::AcqRel) + 1;
                        assert!(
                            now <= OPAT_MAX_CONCURRENT,
                            "{now} concurrent holders exceeds the permit of {OPAT_MAX_CONCURRENT}"
                        );
                        granted.fetch_add(1, Ordering::Relaxed);
                        std::hint::spin_loop();
                        holding.fetch_sub(1, Ordering::AcqRel);
                        drop(permit);
                    }
                });
            }
        });
        assert!(granted.load(Ordering::Relaxed) > 0, "some acquires must have succeeded");
    }
}
