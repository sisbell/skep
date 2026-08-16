//! The process: one long-running server owning one `World`. The daemon is
//! transport, configuration, and lifetime — every handler is
//! parse/marshal/dispatch/configure; every decision lives in a store.
//!
//! Split for testability: [`Daemon`] holds the state and routes
//! `(method, path, session, body) → Reply` with no socket anywhere;
//! [`serve`]/[`Skepd`] wrap it in a synchronous `tiny_http` accept loop.
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
use std::io::Read;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use parking_lot::Mutex;
use serde_json::{Map, Value};
use skep_engine::{Engine, EngineError, GenesisConfig, World};
use skep_febe::{Codec, Operation, Request, SessionId};
use skep_kernel::{BurnedSeqPolicy, CheckpointPolicy, Durability, KernelCfg, Seq};
use skep_namespace::PrincipalId;

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

    /// The router — the whole HTTP surface. `session` is the value of the
    /// `Skepd-Session` header, if any.
    pub fn handle(&self, method: &str, path: &str, session: Option<&str>, body: &[u8]) -> Reply {
        match (method, path) {
            ("POST", "/session") => self.post_session(body),
            ("POST", "/op") => self.post_op(session, body),
            ("GET", "/health") => self.get_health(),
            #[cfg(feature = "observe")]
            ("GET", "/dump") => self.get_dump(),
            (_, "/session") | (_, "/op") | (_, "/health") => Reply::json(
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

    fn get_health(&self) -> Reply {
        let mut m = Map::new();
        m.insert("log_position".into(), Value::Number(self.op.log_position().0.into()));
        m.insert("ok".into(), Value::Bool(true));
        Reply::json(200, Value::Object(m))
    }

    /// `GET /dump` — the engine's deterministic `WorldDump` of the committed
    /// world, for run reconstruction. Exists only in `observe` builds.
    #[cfg(feature = "observe")]
    fn get_dump(&self) -> Reply {
        Reply {
            status: 200,
            content_type: "text/plain; charset=utf-8",
            body: self.engine.world_dump().into_string().into_bytes(),
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
    let path = rq.url().split('?').next().unwrap_or("").to_string();
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
            daemon.handle(method, &path, session.as_deref(), &body)
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
