//! The process: one long-running server owning one `World`. The daemon is
//! transport, configuration, and lifetime — every handler is
//! parse/marshal/dispatch/configure; every decision lives in a store.
//!
//! Split for testability: [`Daemon`] holds the state and routes
//! `(method, path, query, session, body) → Reply` with no socket anywhere;
//! [`serve`]/[`Skepd`] wrap it in a synchronous `tiny_http` accept loop.
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

use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use parking_lot::Mutex;
use serde_json::{Map, Value};
use skep_arrangement::Vstream;
use skep_engine::{Engine, EngineError, GenesisConfig, HistoryError, World};
use skep_febe::{Codec, Op, Operation, Request, Response, SessionId, Stores};
use skep_kernel::{BurnedSeqPolicy, CheckpointPolicy, Durability, Kernel, KernelCfg, Seq};
use skep_links::LinkStore;
use skep_namespace::{Namespace, PrincipalId};

use crate::codec::JsonCodec;

/// Auto-checkpoint cadence: every N commits (M2 evaluates on-commit; no
/// timer thread exists anywhere in this daemon).
const CHECKPOINT_EVERY_COMMITS: u64 = 1024;

/// Retained checkpoints: two, so `BadCheckpoint` recovery can fall back to
/// the older base instead of a full-journal replay from genesis.
const RETAINED_CHECKPOINTS: usize = 2;

/// One handler result: status, content type, body. `POST /op` is always
/// `200` once a `Response` exists — rejections included; the `Response`
/// envelope, not the HTTP status, is the operation protocol. Non-200 codes
/// are transport-level only (`{"error": …}` bodies, wire.md §Transport
/// errors).
pub struct Reply {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
}

impl Reply {
    fn json(status: u16, v: Value) -> Reply {
        Reply {
            status,
            content_type: "application/json",
            body: serde_json::to_vec(&v).expect("serializing a serde_json::Value cannot fail"),
        }
    }
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
}

impl Daemon {
    /// Open (genesis or recover) the one world at `data_dir` and assemble
    /// the operation surface over it. Every [`EngineError`] is an
    /// operator-intervention condition — surface it and exit, never retry.
    pub fn open(data_dir: &Path) -> Result<Daemon, EngineError> {
        let cfg = KernelCfg {
            journal_path: data_dir.to_path_buf(),
            durability: Durability::Fsync { burned_seq: BurnedSeqPolicy::Rollback },
            checkpoint: CheckpointPolicy::EveryN(CHECKPOINT_EVERY_COMMITS),
            retain_checkpoints: RETAINED_CHECKPOINTS,
        };
        let engine = Engine::open(cfg, GenesisConfig::standard())?;
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
        Ok(Daemon {
            engine,
            op,
            codec: JsonCodec,
            sessions: Mutex::new(HashMap::new()),
            guest,
            token_seed,
            token_counter: AtomicU64::new(1),
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

    /// The router — the whole HTTP surface. `query` is the raw query string
    /// (meaningful only on `/dump`, ignored elsewhere); `session` is the
    /// value of the `Skepd-Session` header, if any.
    #[cfg_attr(not(feature = "observe"), allow(unused_variables))]
    pub fn handle(
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
            #[cfg(feature = "observe")]
            ("GET", "/dump") => self.get_dump(query),
            (_, "/session") | (_, "/op") | (_, "/op-at") | (_, "/health") => Reply::json(
                405,
                err_body("method_not_allowed", Some("see wire.md for the endpoint list")),
            ),
            #[cfg(feature = "observe")]
            (_, "/dump") => Reply::json(
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
    fn post_op(&self, session: Option<&str>, body: &[u8]) -> Reply {
        let sid = session
            .and_then(|t| self.sessions.lock().get(t).copied())
            .unwrap_or(self.guest);
        let resp = match self.codec.parse(body) {
            Ok(req) => self.execute(sid, req),
            Err(e) => self.codec.unparseable(e),
        };
        Reply {
            status: 200,
            content_type: "application/json",
            body: self.codec.marshal(&resp),
        }
    }

    fn execute(&self, sid: SessionId, req: Request) -> skep_febe::Response {
        self.op.execute(sid, req)
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
                };
            }
        };
        if !op_is_read(&req.op) {
            // The ruling-fixed body, exactly: {"error": "write_at_history"}.
            let mut m = Map::new();
            m.insert("error".into(), Value::String("write_at_history".into()));
            return Reply::json(400, Value::Object(m));
        }
        let world = match self.engine.world_at(at) {
            Ok(w) => w,
            Err(e) => return history_error_reply(e),
        };
        let mut resp = execute_read_on(world, req);
        stamp_as_of(&mut resp, at);
        Reply {
            status: 200,
            content_type: "application/json",
            body: self.codec.marshal(&resp),
        }
    }

    fn get_health(&self) -> Reply {
        let mut m = Map::new();
        m.insert("log_position".into(), Value::Number(self.op.log_position().0.into()));
        m.insert("ok".into(), Value::Bool(true));
        Reply::json(200, Value::Object(m))
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
            Some(at) => match self.engine.world_at(at) {
                Ok(w) => skep_engine::observe::dump(&w, self.engine.genesis_config()),
                Err(e) => return history_error_reply(e),
            },
        };
        Reply {
            status: 200,
            content_type: "text/plain; charset=utf-8",
            body: dump.into_string().into_bytes(),
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
    let cfg = KernelCfg {
        journal_path: PathBuf::new(),
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::Manual,
        retain_checkpoints: 1,
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

/// The running server: the shared listener, the worker threads, the daemon.
pub struct Skepd {
    server: Arc<tiny_http::Server>,
    workers: Vec<JoinHandle<()>>,
    daemon: Arc<Daemon>,
    port: u16,
}

/// Bind `127.0.0.1:port` (`0` = ephemeral) and serve with `workers`
/// threads. Concurrency policy in full: each worker blocks in `recv`,
/// handles one request, responds — `Operation::execute` is `Sync` and M2's
/// single applier serializes writes, so no further machinery exists here.
pub fn serve(
    daemon: Daemon,
    port: u16,
    workers: usize,
) -> Result<Skepd, Box<dyn std::error::Error + Send + Sync>> {
    let daemon = Arc::new(daemon);
    let server = Arc::new(tiny_http::Server::http(("127.0.0.1", port))?);
    let port = server
        .server_addr()
        .to_ip()
        .ok_or("tcp listener must have an ip address")?
        .port();
    let workers = workers.max(1);
    let handles = (0..workers)
        .map(|_| {
            let server = Arc::clone(&server);
            let daemon = Arc::clone(&daemon);
            thread::spawn(move || {
                while let Ok(rq) = server.recv() {
                    serve_one(&daemon, rq);
                }
            })
        })
        .collect();
    Ok(Skepd { server, workers: handles, daemon, port })
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

    /// Orderly stop for embedders and tests: unblock and join every worker,
    /// then drop the daemon — releasing the kernel's journal-directory lock
    /// so the same data dir can be reopened.
    pub fn shutdown(self) {
        let Skepd { server, workers, daemon, port: _ } = self;
        for _ in 0..workers.len() {
            server.unblock();
        }
        for h in workers {
            let _ = h.join();
        }
        drop(server);
        drop(daemon);
    }
}

/// Adapt one `tiny_http` request onto [`Daemon::handle`]. A handler panic is
/// contained to a 500 so one bad request cannot take a worker down; the
/// panic still prints to stderr for the operator.
fn serve_one(daemon: &Daemon, mut rq: tiny_http::Request) {
    let method = match rq.method() {
        tiny_http::Method::Get => "GET",
        tiny_http::Method::Post => "POST",
        _ => "OTHER",
    };
    let url = rq.url().to_string();
    let (path, query) = match url.split_once('?') {
        Some((p, q)) => (p.to_string(), Some(q.to_string())),
        None => (url, None),
    };
    let session = rq
        .headers()
        .iter()
        .find(|h| h.field.equiv("Skepd-Session"))
        .map(|h| h.value.as_str().to_string());
    let mut body = Vec::new();
    let reply = if rq.as_reader().read_to_end(&mut body).is_err() {
        Reply::json(400, err_body("unreadable_body", None))
    } else {
        match catch_unwind(AssertUnwindSafe(|| {
            daemon.handle(method, &path, query.as_deref(), session.as_deref(), &body)
        })) {
            Ok(r) => r,
            Err(_) => Reply::json(500, err_body("internal_panic", None)),
        }
    };
    let response = tiny_http::Response::from_data(reply.body)
        .with_status_code(reply.status)
        .with_header(
            tiny_http::Header::from_bytes(&b"Content-Type"[..], reply.content_type.as_bytes())
                .expect("a static content type is a valid header"),
        );
    let _ = rq.respond(response);
}
